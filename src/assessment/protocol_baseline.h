/**
 * @file protocol_baseline.h
 * @brief Baseline system for anomaly detection in industrial protocols
 *
 * This module maintains a baseline of normal behavior for each protocol,
 * learning from legitimate traffic and detecting anomalous deviations.
 *
 * ALLOCATION: PSRAM (all data structures)
 *
 * @date 2025-10-25
 * @version 1.0
 */

#pragma once

#include <cstdint>
#include <map>
#include "../core/psram_allocator.h"
#include "../core/types.h"
#include "flow_state.h"
#include "flow_label.h"

/**
 * @brief Baseline statistics for a single endpoint
 *
 * Tracks the normal behavior of a device on the industrial network
 */
struct EndpointBaseline {
    // Endpoint identification
    psram_string ip_address;
    psram_string mac_address;

    // Normal traffic counters
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;

    // Operation distribution (READ/WRITE/CONTROL)
    uint32_t read_operations = 0;
    uint32_t write_operations = 0;
    uint32_t control_operations = 0;
    uint32_t diagnostic_operations = 0;

    // Normal error rate
    uint32_t error_responses = 0;
    float normal_error_rate = 0.0f;  // Expected error percentage

    // Normally visited states (bitmap)
    uint16_t normal_states_bitmap = 0;  // Bit for each FlowState

    // Normal traffic intensity (packets per second)
    float avg_pps = 0.0f;
    float max_pps = 0.0f;

    // Normal peers (devices it communicates with)
    psram_vector<psram_string> known_peers;

    // Statistics timestamps
    uint64_t first_seen_ms = 0;
    uint64_t last_updated_ms = 0;
    uint32_t learning_samples = 0;  // Number of samples used for learning

    // Flag
    bool is_writer = false;        // Device authorized to write
    bool learning_complete = false;  // Stabilized baseline

    EndpointBaseline() {
        PSRAMAllocator<char> alloc;
        ip_address = psram_string(alloc);
        mac_address = psram_string(alloc);
        known_peers = psram_vector<psram_string>(alloc);
    }
};

/**
 * @brief Global baseline for a protocol
 *
 * Contains aggregate statistics and normal patterns for the entire protocol
 */
struct ProtocolBaseline {
    ProtocolType protocol;

    // Tracked endpoints (IP -> baseline)
    psram_map<psram_string, EndpointBaseline> endpoints;

    // Normal state transitions (state_from << 8 | state_to) -> count
    psram_map<uint16_t, uint32_t> normal_state_transitions;

    // Common operation sequences (hash -> count)
    // Hash computed from a sequence like: "READ,READ,WRITE"
    psram_map<uint32_t, uint32_t> operation_sequences;

    // Global statistics
    uint64_t total_flows = 0;
    uint64_t total_packets = 0;

    // Anomaly thresholds (standard deviations)
    float pps_threshold_factor = 3.0f;       // Threshold for anomalous rate (mean + N*stddev)
    float error_rate_threshold = 0.1f;       // Error percentage threshold
    float peer_change_threshold = 0.3f;      // Peer change threshold (30% new peers)

    // Learning
    uint32_t min_learning_samples = 100;     // Minimum samples for baseline
    uint64_t learning_window_ms = 3600000;   // Learning window (1 hour)
    bool learning_enabled = true;

    // Persistence
    uint64_t last_saved_ms = 0;
    uint32_t save_interval_ms = 300000;      // Save every 5 minutes

    ProtocolBaseline() {
        PSRAMAllocator<char> alloc;
        endpoints = psram_map<psram_string, EndpointBaseline>(alloc);
        normal_state_transitions = psram_map<uint16_t, uint32_t>(alloc);
        operation_sequences = psram_map<uint32_t, uint32_t>(alloc);
    }
};

/**
 * @brief Type of detected anomaly
 */
enum class AnomalyType : uint8_t {
    NONE = 0,

    // Traffic anomalies
    UNUSUAL_TRAFFIC_RATE,      // Anomalous packet rate (too high/low)
    EXCESSIVE_ERRORS,          // Too many errors
    FLOODING,                  // Flooding detected

    // Behavioral anomalies
    UNEXPECTED_WRITER,         // Unauthorized device writes
    UNUSUAL_PEER,              // Communication with unknown peer
    STATE_VIOLATION,           // Invalid state transition
    OPERATION_SEQUENCE_ANOMALY, // Anomalous operation sequence

    // Temporal anomalies
    TRAFFIC_AT_UNUSUAL_TIME,   // Traffic at unusual times
    SUDDEN_TRAFFIC_SPIKE,      // Sudden spike

    // Protocol anomalies
    MALFORMED_PATTERN,         // Malformed pattern
    PROTOCOL_DOWNGRADE,        // Security downgrade attempt

    // Security anomalies
    RECONNAISSANCE,            // Scanning/enumeration
    PRIVILEGE_ESCALATION,      // Privilege escalation attempt
    DATA_EXFILTRATION          // Possible data exfiltration
};

/**
 * @brief Detected anomaly details
 */
struct AnomalyDetection {
    AnomalyType type;
    float severity;            // 0.0-1.0 (0=info, 1=critical)
    float confidence;          // 0.0-1.0 (confidence in the detection)

    psram_string endpoint_ip;
    psram_string description;
    psram_string evidence;     // Evidence data (e.g.: "rate=1000pps, baseline=10pps")

    uint64_t timestamp_ms;

    AnomalyDetection() {
        PSRAMAllocator<char> alloc;
        endpoint_ip = psram_string(alloc);
        description = psram_string(alloc);
        evidence = psram_string(alloc);
    }
};

/**
 * @brief Baseline and anomaly detection manager for industrial protocols
 */
class ProtocolBaselineManager {
public:
    ProtocolBaselineManager();
    ~ProtocolBaselineManager() = default;

    /**
     * @brief Initializes the baseline manager for a protocol
     */
    bool initialize(ProtocolType protocol);

    /**
     * @brief Loads baseline from persistent storage
     */
    bool loadBaseline(const char* filepath);

    /**
     * @brief Saves baseline to persistent storage
     */
    bool saveBaseline(const char* filepath);

    /**
     * @brief Updates baseline with new data (learning)
     *
     * @param endpoint_ip Endpoint IP
     * @param mac_address Endpoint MAC
     * @param packet_size Packet size
     * @param operation_type Operation type (READ/WRITE/etc)
     * @param is_error true if error response
     * @param current_state Current flow state
     * @param peer_ip Communication peer IP
     */
    bool updateBaseline(const psram_string& endpoint_ip,
                        const psram_string& mac_address,
                        uint32_t packet_size,
                        const psram_string& operation_type,
                        bool is_error,
                        FlowState current_state,
                        const psram_string& peer_ip);

    /**
     * @brief Detects anomalies by comparing against baseline
     *
     * @param endpoint_ip IP to analyze
     * @param current_pps Current packet rate
     * @param error_rate Current error rate
     * @param operation_type Operation type
     * @param current_state Flow state
     * @param peer_ip Peer IP
     * @param anomalies [out] Detected anomalies
     * @return Number of detected anomalies
     */
    uint32_t detectAnomalies(const psram_string& endpoint_ip,
                            float current_pps,
                            float error_rate,
                            const psram_string& operation_type,
                            FlowState current_state,
                            const psram_string& peer_ip,
                            psram_vector<AnomalyDetection>& anomalies);

    /**
     * @brief Checks whether the endpoint is in the learning phase
     */
    bool isLearning(const psram_string& endpoint_ip) const;

    /**
     * @brief Forces learning completion for the endpoint
     */
    void completeLearning(const psram_string& endpoint_ip);

    /**
     * @brief Resets baseline (for testing or after an incident)
     */
    void resetBaseline();

    /**
     * @brief Gets the current baseline (read-only)
     */
    const ProtocolBaseline& getBaseline() const { return baseline_; }

    /**
     * @brief Enables/disables automatic learning
     */
    void setLearningEnabled(bool enabled) { baseline_.learning_enabled = enabled; }

    /**
     * @brief Sets detection thresholds
     */
    void setThresholds(float pps_factor, float error_rate, float peer_change) {
        baseline_.pps_threshold_factor = pps_factor;
        baseline_.error_rate_threshold = error_rate;
        baseline_.peer_change_threshold = peer_change;
    }

    /**
     * @brief Automatic threshold tuning based on the learned baseline
     * @param endpoint_ip Endpoint to calibrate (empty = all)
     * @return true if at least one endpoint was calibrated
     */
    bool autoTuneThresholds(const psram_string& endpoint_ip = psram_string(PSRAMAllocator<char>()));

    /**
     * @brief Gets learning statistics for the endpoint
     */
    bool getLearningStats(const psram_string& endpoint_ip,
                         float& out_avg_pps,
                         float& out_stddev_pps,
                         float& out_error_rate,
                         uint32_t& out_samples) const;

private:
    ProtocolBaseline baseline_;

    // Helper for computing the operation sequence hash
    uint32_t hashOperationSequence(const psram_vector<psram_string>& ops) const;

    // Helper for checking state transitions
    bool isNormalStateTransition(FlowState from, FlowState to) const;

    // Helper for computing statistics
    float calculateMean(const psram_vector<float>& values) const;
    float calculateStdDev(const psram_vector<float>& values, float mean) const;
};
