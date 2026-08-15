#pragma once
#include <string>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <atomic>
#include "psram_allocator.h"
#include "../reporters/file_reporter.h"

extern "C" {
    #include "cJSON.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
}

/**
 * LogFileManager - Centralized management of log file configurations
 *
 * PSRAM-safe implementation for managing multiple log files with
 * individual configurations, channel routing, and runtime control.
 *
 * Features:
 * - Per-file enable/disable control
 * - Individual rotation settings
 * - Channel-to-file mapping
 * - Runtime configuration updates
 * - PSRAM-optimized operations
 */
class LogFileManager {
public:
    struct LogFileInfo {
        std::string path;
        bool enabled;
        size_t max_size_kb;
        uint32_t max_files;
        std::vector<std::string> channels;
        size_t current_size;
        std::string last_write_time;
    };

    using LogFileInfoMap = std::unordered_map<std::string, LogFileInfo>;

    LogFileManager();
    ~LogFileManager();

    // Initialization
    bool initialize(FileReporter* file_reporter);
    bool loadDefaultConfiguration();
    bool loadFromConfiguration(const cJSON* config_json);

    // File management
    bool enableFile(const std::string& filename, bool enabled);
    bool isFileEnabled(const std::string& filename) const;
    bool getFileInfo(const std::string& filename, LogFileInfo& info) const;
    std::vector<std::string> getConfiguredFiles() const;

    // Configuration management (PSRAM-safe)
    bool updateFileConfig(const std::string& filename, const LogFileInfo& info);
    bool addChannelToFile(const std::string& filename, const std::string& channel);
    bool removeChannelFromFile(const std::string& filename, const std::string& channel);

    // Status and monitoring
    bool refreshFileStatuses(); // Update current sizes, last write times
    psram_string getStatusJSON() const; // PSRAM-safe JSON generation

    // Configuration persistence
    bool saveConfiguration();
    cJSON* generateConfigJSON() const; // For saving to config.json

    // File size monitoring and trimming
    bool startFileSizeMonitor(); // Start 30-second cyclic monitoring task
    void stopFileSizeMonitor();  // Stop monitoring task
    bool isMonitoringActive() const { return monitoring_task_handle_ != nullptr; }

private:
    FileReporter* file_reporter_;
    LogFileInfoMap file_configs_;
    mutable std::mutex mtx_;

    // File size monitoring task
    TaskHandle_t monitoring_task_handle_ = nullptr;
    std::atomic<bool> monitoring_active_{false};

    // Default configurations
    void setupDefaultFiles();
    void setupDefaultChannelMappings();

    // PSRAM-safe helpers
    bool updateFileStatusFromFS(const std::string& filename, LogFileInfo& info);
    psram_string formatFileSize(size_t bytes) const;
    std::string getCurrentTimeString() const;

    // Configuration conversion
    FileConfigMap convertToFileReporterConfig() const;
    bool parseFileConfigFromJSON(const cJSON* file_json, LogFileInfo& info);

    // File size monitoring helpers
    static void monitoringTaskThunk(void* param);
    void monitoringTaskLoop();
    void checkAndTrimFiles();

    // Configuration
    static constexpr uint32_t MONITORING_INTERVAL_MS = 30000; // 30 seconds
    static constexpr size_t MONITORING_TASK_STACK_SIZE = 4096;
    static constexpr UBaseType_t MONITORING_TASK_PRIORITY = tskIDLE_PRIORITY + 2;
};
