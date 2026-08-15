#pragma once

#include "../core/types.h"
#include "../core/psram_allocator.h"
#include "flow_data.h"
#include "protocol_baseline.h"

/**
 * @brief Feature set per analisi anomalie su singolo pacchetto
 */
struct PacketAnomalyFeatures {
    ProtocolType protocol = ProtocolType::UNKNOWN;
    psram_string endpoint_ip;
    psram_string peer_ip;
    psram_string operation_type;
    float packets_per_second = 0.0f;
    float error_rate = 0.0f;
    FlowState state = FlowState::INIT;
    bool is_error = false;
    uint32_t packet_size = 0;
    bool baseline_learning_enabled = false;

    PacketAnomalyFeatures()
        : endpoint_ip(PSRAMAllocator<char>()),
          peer_ip(PSRAMAllocator<char>()),
          operation_type(PSRAMAllocator<char>()) {}
};

/**
 * @brief Feature set per analisi anomalie su flusso aggregato
 */
struct FlowAnomalyFeatures {
    ProtocolType protocol = ProtocolType::UNKNOWN;
    psram_string endpoint_ip;
    psram_string peer_ip;
    psram_string last_operation;
    FlowState state = FlowState::INIT;
    FlowMetrics metrics{};
    float packets_per_second = 0.0f;
    float error_rate = 0.0f;
    bool last_operation_error = false;
    bool baseline_learning_enabled = false;

    FlowAnomalyFeatures()
        : endpoint_ip(PSRAMAllocator<char>()),
          peer_ip(PSRAMAllocator<char>()),
          last_operation(PSRAMAllocator<char>()) {}
};

struct AnomalyThresholdConfig {
    float flooding_pps_threshold = 750.0f;
    float requests_per_second_threshold = 250.0f;
    float request_response_high_ratio = 1.6f;
    float request_response_low_ratio = 0.45f;
    float malformed_packets_normalizer = 5.0f;
};

class AnomalyDetectionEngine {
public:
    AnomalyDetectionEngine() = default;
    ~AnomalyDetectionEngine() = default;

    void setThresholds(const AnomalyThresholdConfig& cfg);

    /**
     * @brief Analizza un singolo pacchetto e genera anomalie
     */
    void analyzePacket(const PacketAnomalyFeatures& features,
                       ProtocolBaselineManager& baseline,
                       psram_vector<AnomalyDetection>& out) const;

    /**
     * @brief Analizza uno snapshot di flusso aggregato
     */
    void analyzeFlow(const FlowAnomalyFeatures& features,
                     ProtocolBaselineManager& baseline,
                     psram_vector<AnomalyDetection>& out) const;

private:
    void appendStateViolation(const PacketAnomalyFeatures& features,
                              psram_vector<AnomalyDetection>& out) const;
    void appendStateViolation(const FlowAnomalyFeatures& features,
                              psram_vector<AnomalyDetection>& out) const;
    void appendMalformedFlowAnomaly(const FlowAnomalyFeatures& features,
                                    psram_vector<AnomalyDetection>& out) const;
    void appendFloodingIndicators(const FlowAnomalyFeatures& features,
                                  psram_vector<AnomalyDetection>& out) const;
    void appendSequenceAnomaly(const FlowAnomalyFeatures& features,
                               psram_vector<AnomalyDetection>& out) const;

    AnomalyThresholdConfig thresholds_;
};
