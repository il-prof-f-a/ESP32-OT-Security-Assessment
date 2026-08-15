#include "anomaly_detection_engine.h"
#include "../core/logging_system.h"
#include "../core/task_config.h"
#include "../core/psram_allocator.h"
#include <algorithm>
#include <cmath>

namespace {
constexpr float kDefaultFloodingPpsThreshold = 750.0f;
constexpr float kDefaultRequestsPerSecondThreshold = 250.0f;
constexpr float kDefaultRequestResponseImbalanceHigh = 1.6f;
constexpr float kDefaultRequestResponseImbalanceLow = 0.45f;
constexpr float kDefaultMalformedNormalizer = 5.0f;

inline psram_string make_ps_string(const char* value) {
    return PSRAMUtils::createPSRAMString(value ? value : "");
}
}  // namespace

void AnomalyDetectionEngine::setThresholds(const AnomalyThresholdConfig& cfg) {
    thresholds_.flooding_pps_threshold =
        (cfg.flooding_pps_threshold > 0.0f) ? cfg.flooding_pps_threshold : kDefaultFloodingPpsThreshold;
    thresholds_.requests_per_second_threshold =
        (cfg.requests_per_second_threshold > 0.0f) ? cfg.requests_per_second_threshold : kDefaultRequestsPerSecondThreshold;
    thresholds_.request_response_high_ratio =
        (cfg.request_response_high_ratio > 0.0f) ? cfg.request_response_high_ratio : kDefaultRequestResponseImbalanceHigh;
    thresholds_.request_response_low_ratio =
        (cfg.request_response_low_ratio > 0.0f) ? cfg.request_response_low_ratio : kDefaultRequestResponseImbalanceLow;
    thresholds_.malformed_packets_normalizer =
        (cfg.malformed_packets_normalizer > 0.0f) ? cfg.malformed_packets_normalizer : kDefaultMalformedNormalizer;
}

void AnomalyDetectionEngine::analyzePacket(const PacketAnomalyFeatures& features,
                                           ProtocolBaselineManager& baseline,
                                           psram_vector<AnomalyDetection>& out) const {
    if (features.endpoint_ip.empty()) {
        return;
    }

    // Baseline-driven anomalies
    psram_vector<AnomalyDetection> baseline_findings;
    baseline.detectAnomalies(features.endpoint_ip,
                             features.packets_per_second,
                             features.error_rate,
                             features.operation_type,
                             features.state,
                             features.peer_ip,
                             baseline_findings);
    for (auto& finding : baseline_findings) {
        out.push_back(finding);
    }

    // State machine violations independent from baseline
    appendStateViolation(features, out);
}

void AnomalyDetectionEngine::analyzeFlow(const FlowAnomalyFeatures& features,
                                         ProtocolBaselineManager& baseline,
                                         psram_vector<AnomalyDetection>& out) const {
    if (features.endpoint_ip.empty()) {
        return;
    }

    // Baseline detection
    psram_vector<AnomalyDetection> baseline_findings;
    baseline.detectAnomalies(features.endpoint_ip,
                             features.packets_per_second,
                             features.error_rate,
                             features.last_operation,
                             features.state,
                             features.peer_ip,
                             baseline_findings);
    for (auto& finding : baseline_findings) {
        out.push_back(finding);
    }

    appendStateViolation(features, out);
    appendMalformedFlowAnomaly(features, out);
    appendFloodingIndicators(features, out);
    appendSequenceAnomaly(features, out);
}

void AnomalyDetectionEngine::appendStateViolation(const PacketAnomalyFeatures& features,
                                                  psram_vector<AnomalyDetection>& out) const {
    if (features.state != FlowState::ERROR &&
        features.state != FlowState::TIMEOUT) {
        return;
    }

    PSRAMAllocator<char> alloc;
    AnomalyDetection anomaly;
    anomaly.type = AnomalyType::STATE_VIOLATION;
    anomaly.severity = features.state == FlowState::ERROR ? 0.85f : 0.65f;
    anomaly.confidence = features.is_error ? 0.9f : 0.6f;
    anomaly.endpoint_ip = features.endpoint_ip;
    anomaly.description = PSRAMUtils::createPSRAMString("Session transitioned to unstable state");

    char evidence[192];
    snprintf(evidence, sizeof(evidence),
             "state=%d pps=%.2f error_rate=%.3f",
             static_cast<int>(features.state),
             features.packets_per_second,
             features.error_rate);
    anomaly.evidence = psram_string(evidence, alloc);
    anomaly.timestamp_ms = esp_timer_get_time() / 1000ULL;

    out.push_back(anomaly);
}

void AnomalyDetectionEngine::appendStateViolation(const FlowAnomalyFeatures& features,
                                                  psram_vector<AnomalyDetection>& out) const {
    if (features.state != FlowState::ERROR &&
        features.state != FlowState::TIMEOUT) {
        return;
    }

    PSRAMAllocator<char> alloc;
    AnomalyDetection anomaly;
    anomaly.type = AnomalyType::STATE_VIOLATION;
    anomaly.severity = features.state == FlowState::ERROR ? 0.9f : 0.7f;
    anomaly.confidence = 0.85f;
    anomaly.endpoint_ip = features.endpoint_ip;
    anomaly.description = PSRAMUtils::createPSRAMString("Flow in terminal error state");

    char evidence[192];
    snprintf(evidence, sizeof(evidence),
             "state=%d packets=%lu errors=%lu duration_ms=%lu",
             static_cast<int>(features.state),
             static_cast<unsigned long>(features.metrics.packet_count),
             static_cast<unsigned long>(features.metrics.error_responses),
             static_cast<unsigned long>(features.metrics.duration_ms()));
    anomaly.evidence = psram_string(evidence, alloc);
    anomaly.timestamp_ms = esp_timer_get_time() / 1000ULL;

    out.push_back(anomaly);
}

void AnomalyDetectionEngine::appendMalformedFlowAnomaly(const FlowAnomalyFeatures& features,
                                                        psram_vector<AnomalyDetection>& out) const {
    if (features.metrics.malformed_packets == 0) {
        return;
    }

    PSRAMAllocator<char> alloc;
    AnomalyDetection anomaly;
    anomaly.type = AnomalyType::MALFORMED_PATTERN;
    anomaly.severity = std::min(1.0f, thresholds_.malformed_packets_normalizer > 0.0f
                                          ? features.metrics.malformed_packets / thresholds_.malformed_packets_normalizer
                                          : features.metrics.malformed_packets);
    anomaly.confidence = 0.75f;
    anomaly.endpoint_ip = features.endpoint_ip;
    anomaly.description = PSRAMUtils::createPSRAMString("Malformed packets detected in flow");

    char evidence[160];
    snprintf(evidence, sizeof(evidence),
             "malformed=%lu total_packets=%lu last_op=%s",
             static_cast<unsigned long>(features.metrics.malformed_packets),
             static_cast<unsigned long>(features.metrics.packet_count),
             PSRAMUtils::fromPSRAMString(features.last_operation).c_str());

    anomaly.evidence = psram_string(evidence, alloc);
    anomaly.timestamp_ms = esp_timer_get_time() / 1000ULL;

    out.push_back(anomaly);
}

void AnomalyDetectionEngine::appendFloodingIndicators(const FlowAnomalyFeatures& features,
                                                      psram_vector<AnomalyDetection>& out) const {
    float pps = features.packets_per_second;
    if (pps <= 0.0f && features.metrics.duration_sec() > 0.0f) {
        pps = static_cast<float>(features.metrics.packet_count) / features.metrics.duration_sec();
    }

    if (pps < thresholds_.flooding_pps_threshold &&
        features.metrics.requests_per_second < thresholds_.requests_per_second_threshold) {
        return;
    }

    PSRAMAllocator<char> alloc;
    AnomalyDetection anomaly;
    anomaly.type = AnomalyType::FLOODING;
    const float reference = thresholds_.flooding_pps_threshold > 0.0f
                                ? thresholds_.flooding_pps_threshold
                                : kDefaultFloodingPpsThreshold;
    anomaly.severity = std::min(1.0f, (pps / reference));
    anomaly.confidence = 0.7f;
    anomaly.endpoint_ip = features.endpoint_ip;
    anomaly.description = PSRAMUtils::createPSRAMString("Sustained high traffic rate detected");

    char evidence[160];
    snprintf(evidence, sizeof(evidence),
             "pps=%.2f requests_per_sec=%.2f bytes_per_sec=%.2f",
             pps,
             features.metrics.requests_per_second,
             features.metrics.bytes_per_second);
    anomaly.evidence = psram_string(evidence, alloc);
    anomaly.timestamp_ms = esp_timer_get_time() / 1000ULL;

    out.push_back(anomaly);
}

void AnomalyDetectionEngine::appendSequenceAnomaly(const FlowAnomalyFeatures& features,
                                                   psram_vector<AnomalyDetection>& out) const {
    if (features.metrics.packet_count < 6) {
        return;
    }

    const float ratio = features.metrics.request_response_ratio;
    const float low_limit = thresholds_.request_response_low_ratio;
    const float high_limit = thresholds_.request_response_high_ratio;
    if (ratio >= low_limit &&
        ratio <= high_limit) {
        return;
    }

    PSRAMAllocator<char> alloc;
    AnomalyDetection anomaly;
    anomaly.type = AnomalyType::OPERATION_SEQUENCE_ANOMALY;
    anomaly.severity = 0.6f;
    anomaly.confidence = 0.6f;
    anomaly.endpoint_ip = features.endpoint_ip;
    anomaly.description = PSRAMUtils::createPSRAMString("Request/response balance significantly deviates from baseline");

    char evidence[160];
    snprintf(evidence, sizeof(evidence),
             "rr_ratio=%.2f read_ops=%lu write_ops=%lu control_ops=%lu",
             ratio,
             static_cast<unsigned long>(features.metrics.read_operations),
             static_cast<unsigned long>(features.metrics.write_operations),
             static_cast<unsigned long>(features.metrics.control_operations));
    anomaly.evidence = psram_string(evidence, alloc);
    anomaly.timestamp_ms = esp_timer_get_time() / 1000ULL;

    out.push_back(anomaly);
}
