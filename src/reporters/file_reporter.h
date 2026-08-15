#pragma once
#include <string>
#include <mutex>
#include <unordered_map>
#include <vector>
#include "../core/psram_allocator.h"

struct FileConfig {
    std::string path = "/data/events.log";
    uint32_t rotate_bytes = 512*1024;
    uint32_t max_files = 3;
    bool enabled = true;
    std::vector<std::string> channels; // Channels routed to this file
};

// PSRAM-safe file configurations map
using FileConfigMap = std::unordered_map<std::string, FileConfig>;

class FileReporter {
public:
    bool init(const FileConfig& c);
    bool initMultiFile(const FileConfigMap& configs);
    bool append(const psram_string& payload);

    // File management
    bool enableFile(const std::string& filename, bool enabled);
    bool getFileStatus(const std::string& filename, bool& enabled, size_t& current_size);
    std::vector<std::string> getConfiguredFiles() const;

    // Configuration update (PSRAM-safe)
    bool updateFileConfig(const std::string& filename, const FileConfig& config);

private:
    FileConfig cfg_;  // Legacy single file config
    FileConfigMap multi_configs_;  // Multi-file configurations
    mutable std::mutex mtx_;
    bool multi_mode_ = false;

    bool rotate_if_needed();

    // Smart routing methods
    std::string determineLogFile(const psram_string& payload);
    std::string determineLogFileMulti(const psram_string& payload);
    bool rotateIfNeeded(const std::string& file_path, const FileConfig& config);
    bool prepareStorageForConfigs(const FileConfigMap& configs);
    bool ensurePathReady(const std::string& file_path) const;
    bool ensureDirectoryExists(const std::string& dir_path) const;

    // Channel mapping helpers (PSRAM-safe)
    bool isChannelMappedToFile(const std::string& channel, const std::string& filename) const;
    std::string getFileForChannel(const std::string& channel) const;
};
