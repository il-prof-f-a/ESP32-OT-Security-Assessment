/**
 * @file flow_metrics.h
 * @brief Common metrics for network flows
 *
 * Data structure that collects all the quantitative metrics of a flow:
 * - Temporal counters (first/last packet, duration)
 * - Packet and byte counters
 * - Operation counters (read/write/control/error)
 * - Calculated rates (pps, bps, rps)
 * - Statistics (avg packet size, request/response ratio)
 * - Classification (intensity, labels)
 *
 * ALLOCATION: Stack or PSRAM (no strings, only numeric data)
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_METRICS_H
#define FLOW_METRICS_H

#include "flow_label.h"
#include "flow_intensity.h"
#include <cstdint>
#include <cstring>
#include "esp_timer.h"

/**
 * @brief Common metrics for all network flows
 *
 * Structure that contains all the counters and calculated metrics
 * for a flow. Used by all protocols.
 *
 * ALLOCATION: This structure is POD (Plain Old Data) and can be
 * allocated either on stack or in PSRAM. It contains no pointers or strings.
 */
struct FlowMetrics {
    // ==================== TEMPORAL ====================

    /**
     * First packet timestamp (milliseconds since boot)
     */
    uint64_t first_packet_ms;

    /**
     * Last packet timestamp (milliseconds since boot)
     */
    uint64_t last_packet_ms;

    /**
     * Calculate flow duration in milliseconds
     * @return Duration in ms
     */
    uint32_t duration_ms() const {
        if (last_packet_ms < first_packet_ms) return 0;
        return static_cast<uint32_t>(last_packet_ms - first_packet_ms);
    }

    /**
     * Calculate flow duration in seconds
     * @return Duration in seconds
     */
    float duration_sec() const {
        return duration_ms() / 1000.0f;
    }

    // ==================== PACKET COUNTERS ====================

    /**
     * Total number of received packets
     */
    uint32_t packet_count;

    /**
     * Total number of received bytes
     */
    uint64_t byte_count;

    // ==================== OPERATION COUNTERS ====================

    /**
     * Number of detected read operations
     * (e.g.: Modbus Read, S7 Read Variable, OPC UA Read)
     */
    uint32_t read_operations;

    /**
     * Number of detected write operations
     * (e.g.: Modbus Write, S7 Write Variable, OPC UA Write)
     */
    uint32_t write_operations;

    /**
     * Number of detected control operations
     * (e.g.: S7 STOP/RESTART, OPC UA Call, ENIP Reset)
     */
    uint32_t control_operations;

    /**
     * Number of error responses received
     * (e.g.: Modbus Exception, S7 Error, OPC UA Bad StatusCode)
     */
    uint32_t error_responses;

    /**
     * Number of detected malformed packets
     */
    uint32_t malformed_packets;

    // ==================== RATES (calculated) ====================

    /**
     * Packets per second (calculated over a time window)
     */
    float packets_per_second;

    /**
     * Bytes per second (calculated over a time window)
     */
    float bytes_per_second;

    /**
     * Requests per second (read + write + control)
     */
    float requests_per_second;

    // ==================== STATISTICS ====================

    /**
     * Average packet size in bytes
     */
    float avg_packet_size;

    /**
     * Request/response ratio for request-response protocols
     * Expected value ~1.0 for balanced traffic
     * > 1.0 indicates more requests than responses (possible timeout/loss)
     * < 1.0 indicates more responses than requests (anomalous)
     */
    float request_response_ratio;

    // ==================== CLASSIFICATION ====================

    /**
     * Traffic intensity (calculated from pps)
     */
    FlowIntensity intensity;

    /**
     * Primary label assigned by the plugin
     */
    FlowLabel primary_label;

    /**
     * Secondary label (optional, for multiple classification)
     * Default: NORMAL_OPERATION if unused
     */
    FlowLabel secondary_label;

    // ==================== CONSTRUCTORS ====================

    /**
     * Default constructor: zeroes all metrics
     */
    FlowMetrics() {
        memset(this, 0, sizeof(FlowMetrics));
        intensity = FlowIntensity::IDLE;
        primary_label = FlowLabel::NORMAL_OPERATION;
        secondary_label = FlowLabel::NORMAL_OPERATION;
        request_response_ratio = 1.0f;
    }

    // ==================== METHODS ====================

    /**
     * @brief Update calculated rates
     *
     * Recalculates pps, bps, rps based on the specified time window.
     * Typically called periodically (e.g.: every 60 seconds).
     *
     * @param window_ms Time window in milliseconds (default: 60000 = 1 min)
     */
    void updateRates(uint32_t window_ms = 60000) {
        if (window_ms == 0) {
            // Avoid division by zero
            packets_per_second = 0.0f;
            bytes_per_second = 0.0f;
            requests_per_second = 0.0f;
            return;
        }

        float window_sec = window_ms / 1000.0f;

        // Calculate rates
        packets_per_second = static_cast<float>(packet_count) / window_sec;
        bytes_per_second = static_cast<float>(byte_count) / window_sec;

        uint32_t total_requests = read_operations + write_operations + control_operations;
        requests_per_second = static_cast<float>(total_requests) / window_sec;

        // Calculate avg packet size
        if (packet_count > 0) {
            avg_packet_size = static_cast<float>(byte_count) / static_cast<float>(packet_count);
        } else {
            avg_packet_size = 0.0f;
        }

        // Update intensity
        intensity = calculateIntensity(packets_per_second);
    }

    /**
     * @brief Update rates on a rolling window
     *
     * Calculates rates considering only the actual duration of the flow,
     * not a fixed window. More accurate for young flows.
     */
    void updateRatesRolling() {
        uint32_t duration = duration_ms();
        if (duration < 1000) {
            // Flow too young, use at least 1 second
            duration = 1000;
        }
        updateRates(duration);
    }

    /**
     * @brief Increment counters for a received packet
     *
     * @param packet_size Packet size in bytes
     */
    void onPacketReceived(uint16_t packet_size) {
        packet_count++;
        byte_count += packet_size;
        last_packet_ms = esp_timer_get_time() / 1000;
    }

    /**
     * @brief Increment read operations counter
     */
    void onReadOperation() {
        read_operations++;
    }

    /**
     * @brief Increment write operations counter
     */
    void onWriteOperation() {
        write_operations++;
    }

    /**
     * @brief Increment control operations counter
     */
    void onControlOperation() {
        control_operations++;
    }

    /**
     * @brief Increment error responses counter
     */
    void onErrorResponse() {
        error_responses++;
    }

    /**
     * @brief Increment malformed packets counter
     */
    void onMalformedPacket() {
        malformed_packets++;
    }

    /**
     * @brief Calculate error rate (% of errors over total operations)
     *
     * @return Error rate [0.0-1.0], 0.0 = no errors, 1.0 = all errors
     */
    float getErrorRate() const {
        uint32_t total_ops = read_operations + write_operations + control_operations;
        if (total_ops == 0) return 0.0f;
        return static_cast<float>(error_responses) / static_cast<float>(total_ops);
    }

    /**
     * @brief Calculate write ratio (% of writes over total r/w)
     *
     * @return Write ratio [0.0-1.0], 0.0 = read only, 1.0 = write only
     */
    float getWriteRatio() const {
        uint32_t total_rw = read_operations + write_operations;
        if (total_rw == 0) return 0.0f;
        return static_cast<float>(write_operations) / static_cast<float>(total_rw);
    }

    /**
     * @brief Check whether the flow is mainly a reader
     *
     * @return true if > 90% read operations, false otherwise
     */
    bool isReader() const {
        return write_operations == 0 && read_operations > 0;
    }

    /**
     * @brief Check whether the flow is mainly a writer
     *
     * @return true if it contains at least one write, false otherwise
     */
    bool isWriter() const {
        return write_operations > 0;
    }

    /**
     * @brief Check whether the flow has too many errors
     *
     * @param threshold Error rate threshold (default: 0.1 = 10%)
     * @return true if error rate > threshold
     */
    bool hasTooManyErrors(float threshold = 0.1f) const {
        return getErrorRate() > threshold;
    }

    /**
     * @brief Check whether the flow is flooding
     *
     * @return true if intensity == FLOODING
     */
    bool isFlooding() const {
        return intensity == FlowIntensity::FLOODING;
    }

    /**
     * @brief Check whether the flow is idle
     *
     * @return true if intensity == IDLE
     */
    bool isIdle() const {
        return intensity == FlowIntensity::IDLE;
    }

    /**
     * @brief Check whether the flow is active (has recent traffic)
     *
     * @param timeout_ms Timeout in ms (default: 60000 = 1 min)
     * @return true if last packet < timeout_ms ago
     */
    bool isActive(uint32_t timeout_ms = 60000) const {
        uint64_t now_ms = esp_timer_get_time() / 1000;
        return (now_ms - last_packet_ms) < timeout_ms;
    }

    /**
     * @brief Get flow age (time since the last packet)
     *
     * @return Milliseconds since the last packet
     */
    uint64_t getAge() const {
        uint64_t now_ms = esp_timer_get_time() / 1000;
        if (now_ms < last_packet_ms) return 0;
        return now_ms - last_packet_ms;
    }

    /**
     * @brief Reset metrics (for testing or reuse)
     */
    void reset() {
        memset(this, 0, sizeof(FlowMetrics));
        intensity = FlowIntensity::IDLE;
        primary_label = FlowLabel::NORMAL_OPERATION;
        secondary_label = FlowLabel::NORMAL_OPERATION;
        request_response_ratio = 1.0f;
    }

    /**
     * @brief Merge with other metrics (for aggregation)
     *
     * Useful for summing metrics from multiple flows (e.g.: all flows of an IP).
     *
     * @param other Metrics to sum
     */
    void merge(const FlowMetrics& other) {
        // Temporal: take min/max
        if (other.first_packet_ms < first_packet_ms || first_packet_ms == 0) {
            first_packet_ms = other.first_packet_ms;
        }
        if (other.last_packet_ms > last_packet_ms) {
            last_packet_ms = other.last_packet_ms;
        }

        // Counters: sum
        packet_count += other.packet_count;
        byte_count += other.byte_count;
        read_operations += other.read_operations;
        write_operations += other.write_operations;
        control_operations += other.control_operations;
        error_responses += other.error_responses;
        malformed_packets += other.malformed_packets;

        // Recalculate rates
        updateRatesRolling();
    }
};

#endif // FLOW_METRICS_H
