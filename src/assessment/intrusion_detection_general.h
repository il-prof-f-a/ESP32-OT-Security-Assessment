#pragma once
#include <vector>
#include <mutex>
#include <map>
#include <string>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "../core/types.h"
#include "../core/whitelist_manager.h"
#include "../core/psram_allocator.h"
#include "network_presence_tracker.h"
#include "anomaly_detection_engine.h"
#include "correlation_engine.h"
#include "protocol_baseline.h"

// Minimal IDS rule structure used by the general IDS engine
struct IDSRule {
    psram_string rule_id;
    psram_string name;
    psram_string description;
    bool enabled = true;
    ProtocolType protocol = ProtocolType::CUSTOM;
    LogLevel severity = LogLevel::WARNING;
    psram_string pattern; // simple payload substring match
};

class ReportingEngine;
class ConfigurationManager;
class PluginManager;


struct TrafficBaseline {
    psram_string src_ip, dst_ip;
    uint16_t port = 0;
    ProtocolType protocol = ProtocolType::CUSTOM;
    uint32_t avg_packets_per_minute = 0;
    uint32_t avg_bytes_per_minute = 0;
    uint32_t typical_packet_size = 0;
    psram_vector<int> active_hours;
};

class IntrusionDetectionGeneral {
public:
    IntrusionDetectionGeneral();
    ~IntrusionDetectionGeneral();

    bool initialize(ConfigurationManager* cfg, ReportingEngine* reporting_engine, PluginManager* plugins);
    void shutdown();

    bool startIDS();
    void stopIDS();

    void startBaselineLearning();
    void stopBaselineLearning();
    void saveBaselines();
    void loadBaselines();

    // Rule management
    void disableRule(const psram_string& rule_id);
    // Compatibility overloads
    void disableRule(const std::string& rule_id) {
        disableRule(PSRAMUtils::createPSRAMString(rule_id.c_str()));
    }
    void disableRule(const char* rule_id) {
        disableRule(PSRAMUtils::createPSRAMString(rule_id));
    }

    psram_vector<TrafficBaseline> getTrafficBaselines() const;
    uint64_t getTotalPacketsAnalyzed() const;
    uint64_t getAlertsGenerated() const;
    psram_map<psram_string, uint64_t> getProtocolStatistics() const;

    // IP Whitelist management
    WhitelistManager& getWhitelistManager() { return whitelist_manager_; }
    const WhitelistManager& getWhitelistManager() const { return whitelist_manager_; }
    void reloadWhitelistFromConfig();
    void reportWhitelistViolation(const NetworkPacket& p);
    bool onPacket(const NetworkPacket& packet); //return bypassAuth

    NetworkPresenceTracker& getNetworkPresenceTracker() { return network_presence_; }
    const NetworkPresenceTracker& getNetworkPresenceTracker() const { return network_presence_; }

protected:
    ConfigurationManager* cfg_ = nullptr;
    PluginManager* plugins_ = nullptr;

private:
    void idsWorker();
    static void idsTaskThunk(void* pvParameters);
    bool onPacketScan(const NetworkPacket& packet);
    bool matchesRule(const NetworkPacket& packet, const IDSRule& rule);
    void checkAnomaliesOnSinglePacket(const NetworkPacket& packet);
    void updateBaseline(const NetworkPacket& packet);
    bool checkAnomalousTrafficOnFlow(const NetworkPacket& packet);
    void updateStatistics(const NetworkPacket& packet);
    void emitAnomalyEvent(const NetworkPacket& packet,
                          const AnomalyDetection& anomaly,
                          const char* scope);
    void recordCorrelationEvent(const NetworkPacket& packet,
                                const char* attack_type,
                                float severity);
    void processCorrelatedAttacks();
    void reportCorrelatedAttack(const CorrelatedAttack& attack);

    // Members (subset; full impl in cpp as per provided code)
    ReportingEngine* reporting_engine_ = nullptr;

    NetworkPresenceTracker network_presence_;

    TaskHandle_t ids_task_handle_ = nullptr;
    bool ids_active_ = true;
    bool baseline_learning_enabled_ = false;
    uint32_t learning_period_hours_ = 1;
    uint32_t baseline_start_time_ = 0;

    psram_vector<TrafficBaseline> baselines_;
    mutable std::mutex stats_mutex_, baselines_mutex_;
    psram_map<psram_string, uint64_t> protocol_stats_;
    uint64_t total_packets_analyzed_ = 0;
    uint64_t alerts_generated_ = 0;
    psram_map<psram_string, uint32_t> packet_counts_, byte_counts_, connection_counts_;

    // IP Whitelist manager
    WhitelistManager whitelist_manager_;

    // Protocol baseline managers (one per protocol for anomaly detection)
    psram_map<ProtocolType, ProtocolBaselineManager> protocol_baselines_;
    CorrelationEngine correlation_engine_;
    uint64_t last_correlation_analysis_ms_ = 0;
    uint64_t last_memory_report_ms_ = 0;
    bool psram_low_alert_sent_ = false;
    bool dram_low_alert_sent_ = false;

    // Motore centralizzato di anomaly detection
    AnomalyDetectionEngine anomaly_engine_;
    uint64_t last_baseline_save_ms_ = 0;

    // Simple rule engine
    psram_vector<IDSRule> rules_{};
    std::mutex rules_mutex_;

};
