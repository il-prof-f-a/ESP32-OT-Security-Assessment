#include "file_reporter.h"
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <errno.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include "cJSON.h"
#include "../core/async_storage_engine.h"
#include "../core/logging_system.h"
#include "../core/filesystem_task_delegate.h"
#include "../core/psram_allocator.h"

extern "C" {
    #include "esp_psram.h"
    #include "esp_heap_caps.h"
}

// Utility function to check if current task is running on PSRAM stack
static bool isCurrentTaskOnPSRAMStack() {
    char stack_var = 0;  // Initialize to suppress warning
    return esp_ptr_external_ram(&stack_var);
}

// Helper: extract TAG from a plain log line like
// "[HH:MM:SS.mmm] LEVEL TAG: message".
// Returns empty string if pattern not matched.
static psram_string extractTagFromLogLine(const psram_string& line) {
    // Find "] " after timestamp
    size_t rb = line.find("] ");
    if (rb == psram_string::npos) return psram_string();
    size_t pos = rb + 2; // after "] "
    // Skip LEVEL token
    size_t sp = line.find(' ', pos);
    if (sp == psram_string::npos) return psram_string();
    // TAG ends at ':'
    size_t colon = line.find(':', sp + 1);
    if (colon == psram_string::npos || colon <= sp + 1) return psram_string();
    psram_string tag = line.substr(sp + 1, colon - (sp + 1));
    // Trim trailing spaces
    while (!tag.empty() && (unsigned char)tag.back() <= ' ') tag.pop_back();
    return tag;
}

static inline bool equalsIgnoreCase(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i) {
        unsigned char a = static_cast<unsigned char>(lhs[i]);
        unsigned char b = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(a) != std::tolower(b)) {
            return false;
        }
    }
    return true;
}

static inline bool containsIgnoreCase(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    const size_t limit = haystack.size() - needle.size();
    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            unsigned char h = static_cast<unsigned char>(haystack[i + j]);
            unsigned char n = static_cast<unsigned char>(needle[j]);
            if (std::tolower(h) != std::tolower(n)) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

std::string FileReporter::determineLogFile(const psram_string& payload) {
    if (multi_mode_) {
        return determineLogFileMulti(payload);
    }

    // Legacy single-file mode fallback
    if (cfg_.path == "/data/app.log") {
        return "/data/logs/app.log";
    }
    return cfg_.path.empty() ? "/data/logs/app.log" : cfg_.path;
}

std::string FileReporter::determineLogFileMulti(const psram_string& payload) {
    // If payload starts like JSON, try JSON-based routing first
    if (!payload.empty() && payload.front() == '{') {
        cJSON* json = cJSON_Parse(payload.c_str());

        if (json) {
            cJSON* channel = cJSON_GetObjectItem(json, "channel");
            std::string channel_str = (channel && cJSON_IsString(channel)) ? channel->valuestring : "";

            cJSON_Delete(json);

            // Use configured multi-file map for routing
            std::string target_file = getFileForChannel(channel_str);

            if (!target_file.empty()) return target_file;

            // Fallback JSON to app.log
            return "/data/logs/app.log";
        }
    }

    // Non-JSON payload: route plain logs by TAG using configuration
    psram_string tag_ps = extractTagFromLogLine(payload);
    if (!tag_ps.empty()) {
        std::string tag = PSRAMUtils::fromPSRAMString(tag_ps);
        // Try to find configured file for this TAG (treated as channel)
        std::string target_file = getFileForChannel(tag);
        if (!target_file.empty()) return target_file;
    }

    // Fallback to app.log
    return "/data/logs/app.log";
}

bool FileReporter::rotateIfNeeded(const std::string& file_path, const FileConfig& config) {
    // CRITICAL: Check memory pressure first to prevent crashes during rotation
    if (PSRAMUtils::isCriticalMemory()) {
        // Skip rotation silently to avoid recursion via LOG_WARNING
        return false;
    }

    // CRITICAL: Check available stack space - delegate rotation if stack is getting low
    UBaseType_t stack_remaining = uxTaskGetStackHighWaterMark(nullptr);
    //LOG_DEBUGF("FileReporter", "rotate check path=%s stack_rem=%u rotate_bytes=%u max=%u", file_path.c_str(), (unsigned)stack_remaining, (unsigned)config.rotate_bytes, (unsigned)config.max_files);

    // If less than 2KB stack remaining, delegate to avoid overflow
    if (stack_remaining < 2048) {
        auto result = FilesystemTaskDelegate::getInstance().rotateFileSync(
            file_path, config.rotate_bytes, config.max_files, 3000);
        //LOG_DEBUGF("FileReporter", "rotate delegated sync path=%s stack_rem=%u result=%s",file_path.c_str(), (unsigned)stack_remaining,(result == FilesystemTaskDelegate::OperationResult::SUCCESS) ? "SUCCESS" : "FAIL");
        return (result == FilesystemTaskDelegate::OperationResult::SUCCESS);
    }

    // Sufficient stack space - direct filesystem access
    struct stat st{};
    if (stat(file_path.c_str(), &st) == 0) {
        if (st.st_size >= (off_t)config.rotate_bytes) {
            //LOG_DEBUGF("FileReporter", "rotate direct path=%s size=%ld threshold=%u",file_path.c_str(), (long)st.st_size, (unsigned)config.rotate_bytes);
            // rotate: path -> path.1 ... path.max_files-1
            for (int i = (int)config.max_files - 1; i >= 1; i--) {
                char oldp[256], newp[256];
                snprintf(oldp, sizeof(oldp), "%s.%d", file_path.c_str(), i);
                snprintf(newp, sizeof(newp), "%s.%d", file_path.c_str(), i + 1);
                rename(oldp, newp);
            }
            char p1[256];
            snprintf(p1, sizeof(p1), "%s.1", file_path.c_str());
            // Avoid LOG calls here to prevent recursion via reportLogMessage -> FileReporter
            rename(file_path.c_str(), p1);
        } else {
            ///LOG_DEBUGF("FileReporter", "rotate skip path=%s size=%ld threshold=%u",file_path.c_str(), (long)st.st_size, (unsigned)config.rotate_bytes);
        }
    } else {
        //LOG_DEBUGF("FileReporter", "rotate stat failed path=%s errno=%d", file_path.c_str(), errno);
    }
    return true;
}

bool FileReporter::init(const FileConfig& c){ cfg_ = c; return true; }

bool FileReporter::rotate_if_needed(){
    struct stat st{};
    if (stat(cfg_.path.c_str(), &st)==0 && st.st_size >= (off_t)cfg_.rotate_bytes) {
        // rotate: path -> path.1 ... path.max_files-1
        for (int i=(int)cfg_.max_files-1;i>=1;i--){
            char oldp[256], newp[256];
            snprintf(oldp,sizeof(oldp), "%s.%d", cfg_.path.c_str(), i);
            snprintf(newp,sizeof(newp), "%s.%d", cfg_.path.c_str(), i+1);
            rename(oldp, newp);
        }
        char p1[256]; snprintf(p1,sizeof(p1), "%s.1", cfg_.path.c_str());
        rename(cfg_.path.c_str(), p1);
    }
    return true;
}

bool FileReporter::append(const psram_string& payload){
    std::lock_guard<std::mutex> lk(mtx_);

    // Determine target file based on event content
    std::string target_file = determineLogFile(payload);

    bool is_statistics = (payload.find("\"type\":\"statistics\"") != psram_string::npos);
    if (is_statistics) {
        size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t min_internal  = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        printf("[FILE_MEM] append_begin file=%s len=%u free=%uB min=%uB\n",
               target_file.c_str(),
               (unsigned)payload.size(),
               (unsigned)free_internal,
               (unsigned)min_internal);
    }

    // Check if file is enabled in multi-mode
    if (multi_mode_) {
        auto it = multi_configs_.find(target_file);
        if (it != multi_configs_.end() && !it->second.enabled) {
            return true; // Silently ignore disabled files
        }
    }

    // Use appropriate config for the determined file
    FileConfig target_config = cfg_; // fallback
    if (multi_mode_) {
        auto it = multi_configs_.find(target_file);
        if (it != multi_configs_.end()) {
            target_config = it->second;
        }
    } else {
        target_config.path = target_file;
    }

    // Rotate if needed for this specific file
    if (!isCurrentTaskOnPSRAMStack()) {
        // Direct rotation - safe from INTERNAL_RAM stack
        rotateIfNeeded(target_file, target_config);
    } else {
        // Delegate rotation to INTERNAL_RAM task for PSRAM stack safety
        // Avoid LOG calls here to prevent recursion via reportLogMessage -> FileReporter
        FilesystemTaskDelegate::getInstance().rotateFileAsync(
            target_file, target_config.rotate_bytes, target_config.max_files);
    }

    const size_t payload_len = payload.size();
    const size_t total_len = payload_len + 1; // include newline

    PSRAMUtils::ScopedBuffer payload_buf(total_len);
    char* ps_buf = payload_buf.get();
    if (!ps_buf) {
        LOG_ERROR("FileReporter", "Failed to allocate PSRAM buffer for log append");
        return false;
    }

    if (payload_len > 0) {
        std::memcpy(ps_buf, payload.data(), payload_len);
    }
    ps_buf[payload_len] = '\n';

    esp_err_t err = AsyncStorage::Global::appendFileRaw(target_file, ps_buf, total_len);

    // Special case: duplicate SESSION tag into network.log as well (only for plain logs)
    if (err == ESP_OK && (payload.empty() || payload.front() != '{')) {
        psram_string tag_ps = extractTagFromLogLine(payload);
        if (!tag_ps.empty() && tag_ps == "SESSION") {
            const std::string dup_path = "/data/logs/network.log";
            if (dup_path != target_file) {
                // Rotate for duplicate target if needed
                FileConfig dup_cfg = cfg_;
                if (multi_mode_) {
                    auto it2 = multi_configs_.find(dup_path);
                    if (it2 != multi_configs_.end()) dup_cfg = it2->second;
                } else {
                    dup_cfg.path = dup_path;
                }

                if (!isCurrentTaskOnPSRAMStack()) {
                    // Direct rotation - safe from INTERNAL_RAM stack
                    rotateIfNeeded(dup_path, dup_cfg);
                } else {
                    // Delegate rotation to INTERNAL_RAM task for PSRAM stack safety
                    // Avoid LOG calls here to prevent recursion
                    FilesystemTaskDelegate::getInstance().rotateFileAsync(
                        dup_path, dup_cfg.rotate_bytes, dup_cfg.max_files);
                }
                (void)AsyncStorage::Global::appendFileRaw(dup_path, ps_buf, total_len);
            }
        }
    }

    if (is_statistics) {
        size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t min_internal  = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        printf("[FILE_MEM] append_end file=%s len=%u free=%uB min=%uB err=%d\n",
               target_file.c_str(),
               (unsigned)payload.size(),
               (unsigned)free_internal,
               (unsigned)min_internal,
               (int)err);
    }

    return (err == ESP_OK);
}


bool FileReporter::ensureDirectoryExists(const std::string& dir_path) const {
    if (dir_path.empty()) {
        return true;
    }

    bool ok = true;
    std::string accumulator;
    size_t start = 0;

    if (!dir_path.empty() && dir_path[0] == '/') {
        accumulator = "/";
        start = 1;
    }

    while (start < dir_path.size()) {
        size_t next = dir_path.find('/', start);
        size_t segment_len = (next == std::string::npos) ? (dir_path.size() - start) : (next - start);

        if (segment_len == 0) {
            if (next == std::string::npos) {
                break;
            }
            start = next + 1;
            continue;
        }

        const std::string segment = dir_path.substr(start, segment_len);
        if (accumulator.empty()) {
            accumulator = segment;
        } else if (accumulator == "/") {
            accumulator += segment;
        } else {
            accumulator.push_back('/');
            accumulator += segment;
        }

        esp_err_t res = AsyncStorage::Global::createDir(accumulator);
        if (res != ESP_OK) {
            LOG_WARNINGF("FileReporter", "Failed to ensure directory %s (err=%s)", accumulator.c_str(), esp_err_to_name(res));
            ok = false;
        }

        if (next == std::string::npos) {
            break;
        }
        start = next + 1;
    }

    return ok;
}

bool FileReporter::ensurePathReady(const std::string& file_path) const {
    if (file_path.empty()) {
        LOG_ERRORF("FileReporter", "ensurePathReady: empty file_path");
        return false;
    }

    //LOG_INFOF("FileReporter", "ensurePathReady: checking path %s", file_path.c_str());

    size_t slash = file_path.find_last_of('/');
    if (slash != std::string::npos) {
        std::string dir = file_path.substr(0, slash);
        if (!dir.empty() && !ensureDirectoryExists(dir)) {
            LOG_ERRORF("FileReporter", "ensurePathReady: failed to ensure directory %s", dir.c_str());
            return false;
        } else {
            //LOG_INFOF("FileReporter", "ensurePathReady: directory %s is ready", dir.c_str());
        }
    }

    bool exists = false;
    esp_err_t exists_res = AsyncStorage::Global::fileExists(file_path, exists);
    if (exists_res != ESP_OK) {
        LOG_WARNINGF("FileReporter", "fileExists(%s) failed: %s", file_path.c_str(), esp_err_to_name(exists_res));
        return false;
    }

    //LOG_INFOF("FileReporter", "ensurePathReady: file %s exists=%s", file_path.c_str(), exists ? "true" : "false");

    if (!exists) {
        //LOG_INFOF("FileReporter", "ensurePathReady: creating empty file %s", file_path.c_str());
        esp_err_t create_res = AsyncStorage::Global::writeFile(file_path, std::string());
        if (create_res != ESP_OK) {
            LOG_ERRORF("FileReporter", "writeFile(%s) failed: %s", file_path.c_str(), esp_err_to_name(create_res));
            return false;
        }
        //LOG_INFOF("FileReporter", "ensurePathReady: successfully created file %s", file_path.c_str());
    }

    return true;
}

bool FileReporter::prepareStorageForConfigs(const FileConfigMap& configs) {
    bool ok = true;

    for (const auto& pair : configs) {
        const FileConfig& cfg = pair.second;
        const std::string& path = cfg.path.empty() ? pair.first : cfg.path;
        if (path.empty()) {
            continue;
        }

        if (!ensurePathReady(path)) {
            ok = false;
        }
    }

    return ok;
}


// Multi-file initialization (PSRAM-safe)
bool FileReporter::initMultiFile(const FileConfigMap& configs) {
    std::lock_guard<std::mutex> lk(mtx_);

    if (!prepareStorageForConfigs(configs)) {
        LOG_ERROR("FileReporter", "Unable to prepare storage paths for multi-file logging");
        return false;
    }

    multi_configs_ = configs;
    multi_mode_ = true;

    return true;
}

// File management methods (PSRAM-safe)
bool FileReporter::enableFile(const std::string& filename, bool enabled) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!multi_mode_) return false;

    auto it = multi_configs_.find(filename);
    if (it != multi_configs_.end()) {
        it->second.enabled = enabled;
        return true;
    }
    return false;
}

bool FileReporter::getFileStatus(const std::string& filename, bool& enabled, size_t& current_size) {
    std::lock_guard<std::mutex> lk(mtx_);

    // Get enabled status
    if (multi_mode_) {
        auto it = multi_configs_.find(filename);
        if (it != multi_configs_.end()) {
            enabled = it->second.enabled;
        } else {
            enabled = false;
        }
    } else {
        enabled = true; // legacy mode
    }

    // Get file size using AsyncStorage (PSRAM-safe)
    esp_err_t err = AsyncStorage::Global::fileSize(filename, current_size);
    return (err == ESP_OK);
}

std::vector<std::string> FileReporter::getConfiguredFiles() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<std::string> files;

    if (multi_mode_) {
        files.reserve(multi_configs_.size());
        for (const auto& pair : multi_configs_) {
            files.push_back(pair.first);
        }
    } else {
        // Legacy mode - return known files
        files = {
            "/data/logs/app.log",
            "/data/logs/access.log",
            "/data/logs/security.log",
            "/data/logs/network.log",
            "/data/fuzzing_events.log",
            "/data/ids_events.log",
            "/data/vulnerability_scanner.log",
            "/data/scanner_events.log"
        };
    }

    return files;
}

bool FileReporter::updateFileConfig(const std::string& filename, const FileConfig& config) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!multi_mode_) return false;

    multi_configs_[filename] = config;
    return true;
}

// Channel mapping helpers (PSRAM-safe)
bool FileReporter::isChannelMappedToFile(const std::string& channel, const std::string& filename) const {
    if (!multi_mode_) return false;

    auto it = multi_configs_.find(filename);
    if (it == multi_configs_.end()) return false;

    const auto& channels = it->second.channels;
    return std::find(channels.begin(), channels.end(), channel) != channels.end();
}

std::string FileReporter::getFileForChannel(const std::string& channel) const {
    if (!multi_mode_) {
        return "";
    }

    // First try exact match (case-insensitive) without creating temporary strings
    for (const auto& pair : multi_configs_) {
        const auto& channels = pair.second.channels;
        for (const auto& configured_channel : channels) {
            if (equalsIgnoreCase(channel, configured_channel)) {
                return pair.first;
            }
        }
    }

    // Then try substring match, prioritizing longer configured channels
    const std::string* best_match = nullptr;
    size_t best_match_len = 0;

    for (const auto& pair : multi_configs_) {
        const auto& channels = pair.second.channels;
        for (const auto& configured_channel : channels) {
            if (configured_channel.empty()) {
                continue;
            }
            if (containsIgnoreCase(channel, configured_channel) && configured_channel.length() > best_match_len) {
                best_match_len = configured_channel.length();
                best_match = &pair.first;
            }
        }
    }

    if (best_match) {
        return *best_match;
    }

    return "";
}
