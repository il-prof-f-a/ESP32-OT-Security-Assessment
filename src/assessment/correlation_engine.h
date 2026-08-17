#pragma once

#include "../core/types.h"
#include "../core/psram_allocator.h"
#include "flow_data.h"
#include <cstdint>

/**
 * @brief Anomalous event for correlation
 */
struct CorrelationEvent {
    uint64_t timestamp_ms = 0;
    psram_string source_ip;
    psram_string dest_ip;
    psram_string attack_type;      // e.g.: "port_scan", "brute_force", "flooding"
    ProtocolType protocol = ProtocolType::UNKNOWN;
    float severity = 0.0f;

    CorrelationEvent()
        : source_ip(PSRAMAllocator<char>()),
          dest_ip(PSRAMAllocator<char>()),
          attack_type(PSRAMAllocator<char>()) {}
};

/**
 * @brief Detected correlated attack pattern
 */
struct CorrelatedAttack {
    psram_string attack_pattern;   // e.g.: "distributed_scan", "coordinated_flood"
    psram_vector<psram_string> involved_sources;
    psram_vector<psram_string> involved_targets;
    uint32_t event_count = 0;
    uint64_t first_seen_ms = 0;
    uint64_t last_seen_ms = 0;
    float combined_severity = 0.0f;

    CorrelatedAttack()
        : attack_pattern(PSRAMAllocator<char>()),
          involved_sources(PSRAMAllocator<psram_string>()),
          involved_targets(PSRAMAllocator<psram_string>()) {}
};

/**
 * @brief Correlation engine configuration
 */
struct CorrelationConfig {
    bool enabled = true;
    uint32_t time_window_ms = 60000;          // Correlation time window (default: 60s)
    uint32_t min_events_for_correlation = 3;   // Minimum events for correlation
    uint32_t max_events_tracked = 1000;        // Maximum events in memory
    float severity_threshold = 0.5f;           // Severity threshold for considering an event
    uint32_t event_retention_ms = 300000;      // Event retention (default: 5 min)
};

/**
 * @brief Correlation Engine for detecting distributed attacks
 *
 * Correlates anomalous events from different sessions/flows to detect:
 * - Distributed port scanning
 * - Coordinated brute-force attacks
 * - Flooding attacks from multiple sources
 * - Distributed reconnaissance
 */
class CorrelationEngine {
public:
    CorrelationEngine();
    ~CorrelationEngine() = default;

    void setConfig(const CorrelationConfig& cfg);
    const CorrelationConfig& getConfig() const { return config_; }

    /**
     * @brief Records a new anomalous event for correlation
     */
    void recordEvent(const CorrelationEvent& event);

    /**
     * @brief Performs correlation analysis and detects patterns
     * @param out_attacks Detected correlated attacks
     * @return Number of correlated attacks found
     */
    uint32_t analyzeCorrelations(psram_vector<CorrelatedAttack>& out_attacks);

    /**
     * @brief Cleans up old events beyond the retention period
     */
    void cleanupOldEvents();

    /**
     * @brief Full reset of the correlation state
     */
    void reset();

    /**
     * @brief Get correlation engine statistics
     */
    uint32_t getTrackedEventCount() const { return events_.size(); }
    uint32_t getTotalEventsProcessed() const { return total_events_processed_; }
    uint32_t getTotalCorrelatedAttacks() const { return total_correlated_attacks_; }

private:
    // Pattern detection helpers
    bool detectDistributedScan(const psram_vector<CorrelationEvent>& events,
                              CorrelatedAttack& out_attack) const;
    bool detectCoordinatedFlood(const psram_vector<CorrelationEvent>& events,
                               CorrelatedAttack& out_attack) const;
    bool detectBruteForceDistributed(const psram_vector<CorrelationEvent>& events,
                                    CorrelatedAttack& out_attack) const;

    // Event grouping helpers
    void groupEventsByTarget(const psram_vector<CorrelationEvent>& events,
                            psram_map<psram_string, psram_vector<CorrelationEvent>>& out_groups) const;
    void groupEventsBySource(const psram_vector<CorrelationEvent>& events,
                            psram_map<psram_string, psram_vector<CorrelationEvent>>& out_groups) const;

    CorrelationConfig config_;
    psram_vector<CorrelationEvent> events_;
    uint32_t total_events_processed_ = 0;
    uint32_t total_correlated_attacks_ = 0;
    uint64_t last_cleanup_ms_ = 0;
};
