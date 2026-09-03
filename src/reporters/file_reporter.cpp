#include "file_reporter.h"
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <cstring>
#include "cJSON.h"
#include "../core/async_storage_engine.h"
#include "../core/logging_system.h"
#include "../core/psram_allocator.h"

extern "C" {
    #include "esp_heap_caps.h"
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

// Keep diagnostics cheap and bounded: report the first failures, powers of two,
// and every 64th failure thereafter.  The payload itself is never logged.
static inline bool should_log_append_failure(uint32_t count) {
    return count <= 4 || (count != 0 && (count & (count - 1U)) == 0U) || (count % 64U) == 0U;
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
            cJSON* type = cJSON_GetObjectItem(json, "type");
            std::string channel_str = (channel && cJSON_IsString(channel)) ? channel->valuestring : "";
            std::string type_str = (type && cJSON_IsString(type)) ? type->valuestring : "";

            cJSON_Delete(json);

            // Event type is authoritative.  This prevents a broad substring
            // channel (for example "scanner") from stealing a discovery,
            // signature, or presence event when the channel map evolves.
            std::string target_file = getFileForChannel(type_str);
            if (!target_file.empty()) return target_file;

            // Fall back to the explicit channel for legacy payloads.
            target_file = getFileForChannel(channel_str);

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
    if (PSRAMUtils::isCriticalMemory()) {
        return false;
    }

    // FileReporter serializes calls with mtx_; keeping all filesystem operations
    // on AsyncStorageWorker prevents a delegate rename from racing an append.
    size_t current_size = 0;
    if (AsyncStorage::Global::fileSize(file_path, current_size) != ESP_OK ||
        current_size < config.rotate_bytes) {
        return true;
    }

    const uint32_t max_files = std::max<uint32_t>(1, config.max_files);
    for (uint32_t index = max_files; index > 1; --index) {
        const std::string destination = file_path + "." + std::to_string(index);
        const std::string source = file_path + "." + std::to_string(index - 1);
        if (index == max_files) {
            (void)AsyncStorage::Global::deleteFile(destination);
        }
        (void)AsyncStorage::Global::fileRename(source, destination);
    }

    const std::string first_backup = file_path + ".1";
    if (max_files == 1) {
        (void)AsyncStorage::Global::deleteFile(first_backup);
    }
    return AsyncStorage::Global::fileRename(file_path, first_backup) == ESP_OK;
}

bool FileReporter::init(const FileConfig& c){ cfg_ = c; return true; }

bool FileReporter::rotate_if_needed(){
    return rotateIfNeeded(cfg_.path, cfg_);
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

    // Rotation and the append below are both executed by AsyncStorageWorker.
    // Keep appending after a transient rotation failure so reports are not lost.
    (void)rotateIfNeeded(target_file, target_config);

    const size_t payload_len = payload.size();
    const size_t total_len = payload_len + 1; // include newline

    PSRAMUtils::ScopedBuffer payload_buf(total_len);
    char* ps_buf = payload_buf.get();
    if (!ps_buf) {
        const uint32_t failure_count = ++append_failure_count_;
        if (should_log_append_failure(failure_count)) {
            LOG_ERRORF("FileReporter",
                       "File append failed: path=%s stage=psram_alloc payload_bytes=%u failure_count=%u free_psram=%u largest_psram=%u",
                       target_file.c_str(),
                       (unsigned)payload.size(),
                       (unsigned)failure_count,
                       (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                       (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
        }
        return false;
    }

    if (payload_len > 0) {
        std::memcpy(ps_buf, payload.data(), payload_len);
    }
    ps_buf[payload_len] = '\n';

    esp_err_t err = AsyncStorage::Global::appendFileRaw(target_file, ps_buf, total_len);

    if (err != ESP_OK) {
        const uint32_t failure_count = ++append_failure_count_;
        if (should_log_append_failure(failure_count)) {
            LOG_ERRORF("FileReporter",
                       "File append failed: path=%s stage=appendFileRaw payload_bytes=%u failure_count=%u err=%d(%s) free_psram=%u largest_psram=%u",
                       target_file.c_str(),
                       (unsigned)payload.size(),
                       (unsigned)failure_count,
                       (int)err,
                       esp_err_to_name(err),
                       (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                       (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
        }
    }

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

                (void)rotateIfNeeded(dup_path, dup_cfg);
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
