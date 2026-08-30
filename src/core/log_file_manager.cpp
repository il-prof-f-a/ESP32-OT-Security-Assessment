#include "log_file_manager.h"
#include "async_storage_engine.h"
#include "logging_system.h"
#include "filesystem_task_delegate.h"
#include "task_config.h"
#include <ctime>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

extern "C" {
    #include "esp_timer.h"
    #include "esp_log.h"
}

LogFileManager::LogFileManager() : file_reporter_(nullptr) {
}

LogFileManager::~LogFileManager() {
    stopFileSizeMonitor();
}

bool LogFileManager::initialize(FileReporter* file_reporter) {

    if (!file_reporter) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mtx_);
    file_reporter_ = file_reporter;

    // Setup default configuration
    setupDefaultFiles();
    setupDefaultChannelMappings();

    // Apply configuration to FileReporter
    FileConfigMap reporter_config = convertToFileReporterConfig();

    //for (const auto& pair : reporter_config) {
    //}

    bool result = file_reporter_->initMultiFile(reporter_config);


    LOG_INFOF("LOG_FILE_MANAGER", "FileReporter initialization result: %s (%zu files configured)",
              result ? "SUCCESS" : "FAILED", reporter_config.size());

    return result;
}

void LogFileManager::setupDefaultFiles() {
    // System log files
    file_configs_["/data/logs/app.log"] = {
        "/data/logs/app.log", true, 1024, 5,
        {"app", "general", "system"}, 0, ""
    };

    file_configs_["/data/logs/access.log"] = {
        "/data/logs/access.log", true, 512, 3,
        {"access", "http", "web"}, 0, ""
    };

    file_configs_["/data/logs/security.log"] = {
        "/data/logs/security.log", true, 512, 3,
        {"security", "auth", "session", "login"}, 0, ""
    };

    file_configs_["/data/logs/network.log"] = {
        "/data/logs/network.log", true, 1024, 3,
        {"network", "wifi", "ethernet", "connection"}, 0, ""
    };

    // Feature-specific log files
    file_configs_["/data/fuzzing_events.log"] = {
        "/data/fuzzing_events.log", true, 2048, 3,
        {"fuzzing", "fuzz"}, 0, ""
    };

    file_configs_["/data/ids_events.log"] = {
        "/data/ids_events.log", true, 1024, 3,
        {"intrusion_detected", "ids_detection_detailed", "intrusion_detection", "ids", "intrusion", "detection"}, 0, ""
    };

    file_configs_["/data/vulnerability_scanner.log"] = {
        "/data/vulnerability_scanner.log", true, 1024, 3,
        {"vulnerability_scanner", "vuln", "scanner", "vuln_scanner_job_lifecycle", "vuln_scanner_job_execution", "scanner_scan_result"}, 0, ""
    };

    file_configs_["/data/scanner_events.log"] = {
        "/data/scanner_events.log", true, 512, 3,
        {"legacy_scan_events"}, 0, ""
    };

    // Dedicated action logs. Keep the legacy scanner_events.log readable, but
    // never route new discovery or vulnerability records into it.
    file_configs_["/data/discovery_events.log"] = {
        "/data/discovery_events.log", true, 1024, 3,
        {"discovery", "general_discovery_result", "discovery_result"}, 0, ""
    };
    file_configs_["/data/signature_events.log"] = {
        "/data/signature_events.log", true, 2048, 3,
        {"signature", "threat_detected", "signature_match"}, 0, ""
    };
    file_configs_["/data/network_presence_events.log"] = {
        "/data/network_presence_events.log", true, 1024, 3,
        {"network_presence", "presence", "device_observed", "trust_changed"}, 0, ""
    };

    file_configs_["/data/audit_events.log"] = {
        "/data/audit_events.log", true, 1024, 3,
        {"audit", "AUDIT", "audit_event", "security_audit", "security_event", "SECURITY", "config_change"}, 0, ""
    };
    file_configs_["/data/gpio_events.log"] = {
        "/data/gpio_events.log", true, 512, 3,
        {"gpio", "gpio_event", "gpio_input", "gpio_output"}, 0, ""
    };
}

void LogFileManager::setupDefaultChannelMappings() {
    // Channel mappings are already included in setupDefaultFiles()
    // This method can be used for additional complex mappings if needed
}

FileConfigMap LogFileManager::convertToFileReporterConfig() const {
    FileConfigMap reporter_config;

    for (const auto& pair : file_configs_) {
        const std::string& filename = pair.first;
        const LogFileInfo& info = pair.second;

        FileConfig config;
        config.path = info.path;
        config.enabled = info.enabled;
        config.rotate_bytes = info.max_size_kb * 1024;
        config.max_files = info.max_files;
        config.channels = info.channels;

        reporter_config[filename] = config;
    }

    return reporter_config;
}

bool LogFileManager::enableFile(const std::string& filename, bool enabled) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = file_configs_.find(filename);
    if (it == file_configs_.end()) return false;

    it->second.enabled = enabled;

    // Update FileReporter configuration
    if (file_reporter_) {
        return file_reporter_->enableFile(filename, enabled);
    }

    return true;
}

bool LogFileManager::isFileEnabled(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = file_configs_.find(filename);
    return (it != file_configs_.end()) ? it->second.enabled : false;
}

bool LogFileManager::getFileInfo(const std::string& filename, LogFileInfo& info) const {
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = file_configs_.find(filename);
    if (it == file_configs_.end()) return false;

    info = it->second;
    return true;
}

std::vector<std::string> LogFileManager::getConfiguredFiles() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::string> files;

    files.reserve(file_configs_.size());
    for (const auto& pair : file_configs_) {
        files.push_back(pair.first);
    }

    return files;
}

bool LogFileManager::updateFileConfig(const std::string& filename, const LogFileInfo& info) {
    std::lock_guard<std::mutex> lock(mtx_);

    file_configs_[filename] = info;

    // Update FileReporter configuration
    if (file_reporter_) {
        FileConfig config;
        config.path = info.path;
        config.enabled = info.enabled;
        config.rotate_bytes = info.max_size_kb * 1024;
        config.max_files = info.max_files;
        config.channels = info.channels;

        return file_reporter_->updateFileConfig(filename, config);
    }

    return true;
}

bool LogFileManager::addChannelToFile(const std::string& filename, const std::string& channel) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = file_configs_.find(filename);
    if (it == file_configs_.end()) return false;

    auto& channels = it->second.channels;
    if (std::find(channels.begin(), channels.end(), channel) == channels.end()) {
        channels.push_back(channel);

        // Update FileReporter
        if (file_reporter_) {
            FileConfig config;
            config.path = it->second.path;
            config.enabled = it->second.enabled;
            config.rotate_bytes = it->second.max_size_kb * 1024;
            config.max_files = it->second.max_files;
            config.channels = it->second.channels;

            file_reporter_->updateFileConfig(filename, config);
        }
    }

    return true;
}

bool LogFileManager::removeChannelFromFile(const std::string& filename, const std::string& channel) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = file_configs_.find(filename);
    if (it == file_configs_.end()) return false;

    auto& channels = it->second.channels;
    auto channel_it = std::find(channels.begin(), channels.end(), channel);
    if (channel_it != channels.end()) {
        channels.erase(channel_it);

        // Update FileReporter
        if (file_reporter_) {
            FileConfig config;
            config.path = it->second.path;
            config.enabled = it->second.enabled;
            config.rotate_bytes = it->second.max_size_kb * 1024;
            config.max_files = it->second.max_files;
            config.channels = it->second.channels;

            file_reporter_->updateFileConfig(filename, config);
        }
    }

    return true;
}

bool LogFileManager::refreshFileStatuses() {
    std::lock_guard<std::mutex> lock(mtx_);

    for (auto& pair : file_configs_) {
        updateFileStatusFromFS(pair.first, pair.second);
    }

    return true;
}

bool LogFileManager::updateFileStatusFromFS(const std::string& filename, LogFileInfo& info) {
    // Update file size using AsyncStorage (PSRAM-safe)
    size_t file_size = 0;
    esp_err_t err = AsyncStorage::Global::fileSize(filename, file_size);
    if (err == ESP_OK) {
        info.current_size = file_size;
    }

    // Update last write time
    info.last_write_time = getCurrentTimeString();

    return true;
}

std::string LogFileManager::getCurrentTimeString() const {
    uint64_t time_us = esp_timer_get_time();
    uint64_t time_ms = time_us / 1000;

    // Simple time formatting (could be improved with RTC if available)
    char time_buf[32];
    snprintf(time_buf, sizeof(time_buf), "%llu", time_ms);
    return std::string(time_buf);
}

psram_string LogFileManager::formatFileSize(size_t bytes) const {
    char size_buf[32];
    if (bytes < 1024) {
        snprintf(size_buf, sizeof(size_buf), "%zu B", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(size_buf, sizeof(size_buf), "%.1f KB", bytes / 1024.0);
    } else {
        snprintf(size_buf, sizeof(size_buf), "%.1f MB", bytes / (1024.0 * 1024.0));
    }
    return PSRAMUtils::createPSRAMString(size_buf);
}

psram_string LogFileManager::getStatusJSON() const {
    std::lock_guard<std::mutex> lock(mtx_);

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return PSRAMUtils::createPSRAMString("{}");
    }

    cJSON* files_array = cJSON_CreateArray();
    if (!files_array) {
        cJSON_Delete(root);
        return PSRAMUtils::createPSRAMString("[]");
    }
    cJSON_AddItemToObject(root, "files", files_array);

    for (const auto& pair : file_configs_) {
        const std::string& filename = pair.first;
        const LogFileInfo& info = pair.second;

        cJSON* file_obj = cJSON_CreateObject();
        if (!file_obj) {
            continue;
        }
        const size_t slash = filename.find_last_of("/\\");
        const std::string display_name = slash == std::string::npos
            ? filename : filename.substr(slash + 1);
        cJSON_AddStringToObject(file_obj, "filename", display_name.c_str());
        cJSON_AddStringToObject(file_obj, "path", info.path.c_str());
        cJSON_AddBoolToObject(file_obj, "enabled", info.enabled);
        cJSON_AddNumberToObject(file_obj, "max_size_kb", info.max_size_kb);
        cJSON_AddNumberToObject(file_obj, "max_files", info.max_files);
        cJSON_AddNumberToObject(file_obj, "current_size", info.current_size);

        psram_string formatted_size = formatFileSize(info.current_size);
        cJSON_AddStringToObject(file_obj, "current_size_formatted", formatted_size.c_str());
        cJSON_AddStringToObject(file_obj, "last_write_time", info.last_write_time.c_str());

        cJSON* channels_array = cJSON_CreateArray();
        if (channels_array) {
            for (const auto& channel : info.channels) {
                cJSON_AddItemToArray(channels_array, cJSON_CreateString(channel.c_str()));
            }
            cJSON_AddItemToObject(file_obj, "channels", channels_array);
        }

        cJSON_AddItemToArray(files_array, file_obj);
    }

    char* json_string = cJSON_PrintUnformatted(root);
    psram_string result = json_string ? PSRAMUtils::createPSRAMString(json_string)
                                      : PSRAMUtils::createPSRAMString("[]");
    if (json_string) {
        free(json_string);
    }
    cJSON_Delete(root);
    return result;
}


bool LogFileManager::loadDefaultConfiguration() {

    // Default configuration is already set up in initialize()
    // This method can be used to reset to defaults if needed
    setupDefaultFiles();
    setupDefaultChannelMappings();

    return true;
}

bool LogFileManager::loadFromConfiguration(const cJSON* config_json) {
    if (!config_json) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mtx_);

    // Parse logging configuration from config.json
    cJSON* reporting = cJSON_GetObjectItem(config_json, "reporting");
    if (!reporting) {
        return loadDefaultConfiguration();
    }
    cJSON* file = cJSON_GetObjectItem(reporting, "file");
    if (!file) {
        return loadDefaultConfiguration();
    }
    cJSON* files = cJSON_GetObjectItem(file, "files");
    if (!files || !cJSON_IsObject(files)) {
        return loadDefaultConfiguration();
    }

    // Parse each file configuration
    int file_count = 0;
    cJSON* file_item = files->child;
    while (file_item) {
        LogFileInfo info;
        if (parseFileConfigFromJSON(file_item, info)) {
            std::string filename = std::string(file_item->string);
            file_configs_[filename] = info;
            file_count++;
        }
        file_item = file_item->next;
    }

    return true;
}

bool LogFileManager::parseFileConfigFromJSON(const cJSON* file_json, LogFileInfo& info) {
    if (!file_json || !cJSON_IsObject(file_json)) return false;

    // Parse basic settings
    cJSON* enabled = cJSON_GetObjectItem(file_json, "enabled");
    info.enabled = enabled ? cJSON_IsTrue(enabled) : true;

    cJSON* max_size = cJSON_GetObjectItem(file_json, "max_size_kb");
    info.max_size_kb = (max_size && cJSON_IsNumber(max_size)) ? (size_t)max_size->valueint : 1024;

    cJSON* max_files = cJSON_GetObjectItem(file_json, "max_files");
    info.max_files = (max_files && cJSON_IsNumber(max_files)) ? (uint32_t)max_files->valueint : 3;

    // Parse channels
    cJSON* channels = cJSON_GetObjectItem(file_json, "channels");
    if (channels && cJSON_IsArray(channels)) {
        info.channels.clear();
        cJSON* channel_item = channels->child;
        while (channel_item) {
            if (cJSON_IsString(channel_item)) {
                info.channels.push_back(std::string(channel_item->valuestring));
            }
            channel_item = channel_item->next;
        }
    }

    return true;
}

// ======================= FILE SIZE MONITORING =======================

static const char* FS_MONITOR_TAG = "LOG_FS_MONITOR";

bool LogFileManager::startFileSizeMonitor() {
    std::lock_guard<std::mutex> lock(mtx_);

    if (monitoring_task_handle_) {
        LOG_WARNING(FS_MONITOR_TAG, "File size monitor already running");
        return true;
    }

    monitoring_active_.store(true);

    // Create monitoring task - use regular xTaskCreate for simplicity
    BaseType_t result = xTaskCreate(
        monitoringTaskThunk,
        "file_monitor",
        MONITORING_TASK_STACK_SIZE / sizeof(StackType_t),
        this,
        MONITORING_TASK_PRIORITY,
        &monitoring_task_handle_
    );

    if (result != pdPASS || !monitoring_task_handle_) {
        LOG_ERROR(FS_MONITOR_TAG, "Failed to create file size monitoring task");
        monitoring_active_.store(false);
        monitoring_task_handle_ = nullptr;
        return false;
    }

    LOG_INFO(FS_MONITOR_TAG, "✅ File size monitor started (30s interval)");
    return true;
}

void LogFileManager::stopFileSizeMonitor() {
    std::lock_guard<std::mutex> lock(mtx_);

    if (!monitoring_task_handle_) {
        return;
    }

    LOG_INFO(FS_MONITOR_TAG, "Stopping file size monitor...");

    monitoring_active_.store(false);

    // Give task time to exit gracefully
    vTaskDelay(pdMS_TO_TICKS(100));

    vTaskDelete(monitoring_task_handle_);
    monitoring_task_handle_ = nullptr;

    LOG_INFO(FS_MONITOR_TAG, "✅ File size monitor stopped");
}

void LogFileManager::monitoringTaskThunk(void* param) {
    static_cast<LogFileManager*>(param)->monitoringTaskLoop();
}

void LogFileManager::monitoringTaskLoop() {
    LOG_INFO(FS_MONITOR_TAG, "File size monitoring loop started");

    while (monitoring_active_.load()) {
        // Check and trim files - no exception handling needed in ESP32
        checkAndTrimFiles();

        // Wait for 30 seconds, checking if we should stop every second
        for (int i = 0; i < MONITORING_INTERVAL_MS / 1000 && monitoring_active_.load(); ++i) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    LOG_INFO(FS_MONITOR_TAG, "File size monitoring loop exited");
}

void LogFileManager::checkAndTrimFiles() {
    std::lock_guard<std::mutex> lock(mtx_);

    // Get reference to filesystem delegate
    FilesystemTaskDelegate& fs_delegate = FilesystemTaskDelegate::getInstance();

    if (!fs_delegate.isReady()) {
        LOG_DEBUG(FS_MONITOR_TAG, "Filesystem delegate not ready, skipping size check");
        return;
    }

    size_t files_checked = 0;
    size_t files_trimmed = 0;

    for (const auto& [file_path, config] : file_configs_) {
        if (!config.enabled) {
            continue; // Skip disabled files
        }

        files_checked++;

        // Check current file size
        struct stat st{};
        if (stat(file_path.c_str(), &st) != 0) {
            continue; // File doesn't exist, skip
        }

        size_t current_size_bytes = (size_t)st.st_size;
        size_t max_size_bytes = config.max_size_kb * 1024;

        if (current_size_bytes > max_size_bytes) {
            LOG_INFOF(FS_MONITOR_TAG, "File %s exceeds limit: %zu > %zu bytes - trimming...",
                     file_path.c_str(), current_size_bytes, max_size_bytes);

            // Use async trimming to avoid blocking the monitoring task
            bool trim_success = fs_delegate.trimFileAsync(file_path, max_size_bytes);

            if (trim_success) {
                files_trimmed++;
                LOG_INFOF(FS_MONITOR_TAG, "Queued trim operation for %s", file_path.c_str());
            } else {
                LOG_WARNINGF(FS_MONITOR_TAG, "Failed to queue trim operation for %s", file_path.c_str());
            }
        }
    }

    if (files_trimmed > 0) {
        LOG_INFOF(FS_MONITOR_TAG, "Size check complete: %zu files checked, %zu trimmed",
                 files_checked, files_trimmed);
    } else {
        LOG_DEBUGF(FS_MONITOR_TAG, "Size check complete: %zu files checked, all within limits",
                  files_checked);
    }
}
