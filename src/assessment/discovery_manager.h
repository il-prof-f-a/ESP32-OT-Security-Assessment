#pragma once

#include <map>
#include <string>
#include <chrono>
#include <memory>
#include <mutex>
#include "../core/psram_allocator.h"
#include "../protocols/base_plugin.h"
#include "../core/types.h"

extern "C" {
    #include "cJSON.h"
}

// Forward declarations
class PluginManager;
class ReportingEngine;
class ConfigurationManager;

enum class DiscoveryStatus {
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
};

struct DiscoveryJob {
    psram_string id;
    ProtocolType protocol;
    bool is_general = false;
    psram_string custom_protocol_name;
    psram_string mode_label;
    BasePlugin::GeneralDiscoveryConfig general_config;
    psram_string target;
    uint32_t timeout_ms;
    DiscoveryStatus status;
    uint64_t start_time_ms;
    uint64_t end_time_ms;
    psram_string partial_results;
    psram_string final_results;
    psram_string error_message;
    float progress_percent;
    // Live metrics (for web UI progress)
    uint32_t hosts_enumerated = 0;
    uint32_t hosts_scanned = 0;
    uint32_t hosts_connected = 0;
    uint32_t responses_mei = 0;
    uint32_t responses_probe = 0;
    psram_string last_ip;

    DiscoveryJob() : status(DiscoveryStatus::RUNNING), start_time_ms(0), end_time_ms(0), progress_percent(0.0f) {}
};

class DiscoveryManager {
public:
    static DiscoveryManager& getInstance() {
        static DiscoveryManager instance;
        return instance;
    }

    // Start a new discovery job
    psram_string startDiscovery(ProtocolType protocol, const char* target, uint32_t timeout_ms);
    psram_string startGeneralDiscovery(const BasePlugin::GeneralDiscoveryConfig& cfg);

    // Get discovery status and results
    cJSON* getDiscoveryStatus(const char* discovery_id);

    // Get all active and recent discoveries
    cJSON* getAllDiscoveries();

    // Cancel a running discovery
    bool cancelDiscovery(const char* discovery_id);

    // Cleanup old completed discoveries (older than 10 minutes)
    void cleanupOldDiscoveries();

    // Progress helpers (usable from discovery task thread)
    void initTotalsTLS(uint32_t total_hosts);
    void updateProgressTLS(const char* ip,
                           uint32_t scanned,
                           uint32_t connected,
                           uint32_t mei,
                           uint32_t probe);

private:
    DiscoveryManager() = default;
    ~DiscoveryManager() = default;
    DiscoveryManager(const DiscoveryManager&) = delete;
    DiscoveryManager& operator=(const DiscoveryManager&) = delete;

    std::mutex discoveries_mutex_;
    psram_map<psram_string, std::unique_ptr<DiscoveryJob>> discoveries_;

    // Background task function
    static void discoveryTask(void* pvParameters);
    static void generalDiscoveryTask(void* pvParameters);

    // Helper methods
    psram_string generateDiscoveryId();
    uint64_t getCurrentTimeMs();
    const char* getProtocolName(ProtocolType protocol);
    cJSON* jobToJson(const DiscoveryJob& job);

    // Reference to plugins for actual discovery
    PluginManager* plugins_ = nullptr;

public:
    void setPluginManager(PluginManager* plugins) { plugins_ = plugins; }
    void setReporter(ReportingEngine* reporter) { reporter_ = reporter; }
    void setConfig(ConfigurationManager* cfg) { cfg_ = cfg; }

private:
    ReportingEngine* reporter_ = nullptr;
    ConfigurationManager* cfg_ = nullptr;
};
