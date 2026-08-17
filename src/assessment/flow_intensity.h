/**
 * @file flow_intensity.h
 * @brief Network traffic intensity classification
 *
 * System for classifying the intensity of a flow based on
 * packets per second (pps). Used to identify traffic
 * that is normal, intense, or flooding.
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_INTENSITY_H
#define FLOW_INTENSITY_H

#include <cstdint>

/**
 * @brief Traffic intensity levels
 *
 * Classification based on packets per second (pps).
 * The thresholds are configurable and can vary by protocol,
 * but these are the typical default values for industrial networks.
 */
enum class FlowIntensity : uint8_t {
    /**
     * No traffic or sporadic traffic
     * < 1 pps
     *
     * Typical for:
     * - Inactive connections
     * - Very slow polling
     */
    IDLE = 0,

    /**
     * Low/normal traffic
     * 1-10 pps
     *
     * Typical for:
     * - Standard SCADA polling (1-5 sec)
     * - Normal periodic reads
     */
    LOW = 1,

    /**
     * Medium traffic
     * 10-50 pps
     *
     * Typical for:
     * - Fast polling (< 1 sec)
     * - Multiple operations per second
     * - Active HMI
     */
    MEDIUM = 2,

    /**
     * High traffic
     * 50-200 pps
     *
     * Typical for:
     * - Real-time control loops
     * - Fast polling multiple devices
     * - Burst of operations
     */
    HIGH = 3,

    /**
     * Very high traffic
     * 200-1000 pps
     *
     * Typical for:
     * - Motion control
     * - Multiple concurrent clients
     * - Potential intensive scanning
     */
    VERY_HIGH = 4,

    /**
     * Flooding: excessive anomalous traffic
     * > 1000 pps
     *
     * Indicates:
     * - Possible DoS attack
     * - Client malfunction
     * - Network loop
     * - Aggressive scanning
     */
    FLOODING = 5
};

/**
 * @brief Default thresholds for intensity classification (pps)
 */
struct FlowIntensityThresholds {
    float idle_max;         ///< Max pps per IDLE (default: 1.0)
    float low_max;          ///< Max pps per LOW (default: 10.0)
    float medium_max;       ///< Max pps per MEDIUM (default: 50.0)
    float high_max;         ///< Max pps per HIGH (default: 200.0)
    float very_high_max;    ///< Max pps per VERY_HIGH (default: 1000.0)
    // > very_high_max = FLOODING

    /**
     * Constructor with default values
     */
    FlowIntensityThresholds()
        : idle_max(1.0f),
          low_max(10.0f),
          medium_max(50.0f),
          high_max(200.0f),
          very_high_max(1000.0f) {}
};

/**
 * @brief Calculate intensity from packets per second with custom thresholds
 *
 * @param pps Flow rate in pps
 * @param thresholds Custom thresholds
 * @return Classified FlowIntensity
 */
inline FlowIntensity calculateIntensity(float pps, const FlowIntensityThresholds& thresholds) {
    if (pps < thresholds.idle_max) {
        return FlowIntensity::IDLE;
    } else if (pps < thresholds.low_max) {
        return FlowIntensity::LOW;
    } else if (pps < thresholds.medium_max) {
        return FlowIntensity::MEDIUM;
    } else if (pps < thresholds.high_max) {
        return FlowIntensity::HIGH;
    } else if (pps < thresholds.very_high_max) {
        return FlowIntensity::VERY_HIGH;
    } else {
        return FlowIntensity::FLOODING;
    }
}

/**
 * @brief Calculate intensity from packets per second
 *
 * Uses default thresholds for classification.
 *
 * @param packets_per_second Flow rate in pps
 * @return Classified FlowIntensity
 */
inline FlowIntensity calculateIntensity(float packets_per_second) {
    FlowIntensityThresholds thresholds;
    return calculateIntensity(packets_per_second, thresholds);
}

/**
 * @brief Convert FlowIntensity to string
 *
 * @param intensity Intensity to convert
 * @return Intensity name as a string
 */
inline const char* flowIntensityToString(FlowIntensity intensity) {
    switch (intensity) {
        case FlowIntensity::IDLE:       return "IDLE";
        case FlowIntensity::LOW:        return "LOW";
        case FlowIntensity::MEDIUM:     return "MEDIUM";
        case FlowIntensity::HIGH:       return "HIGH";
        case FlowIntensity::VERY_HIGH:  return "VERY_HIGH";
        case FlowIntensity::FLOODING:   return "FLOODING";
        default:                        return "UNKNOWN";
    }
}

/**
 * @brief Get the pps range for an intensity
 *
 * @param intensity Intensity
 * @return Descriptive string of the range (e.g.: "1-10 pps")
 */
inline const char* flowIntensityRange(FlowIntensity intensity) {
    switch (intensity) {
        case FlowIntensity::IDLE:       return "< 1 pps";
        case FlowIntensity::LOW:        return "1-10 pps";
        case FlowIntensity::MEDIUM:     return "10-50 pps";
        case FlowIntensity::HIGH:       return "50-200 pps";
        case FlowIntensity::VERY_HIGH:  return "200-1000 pps";
        case FlowIntensity::FLOODING:   return "> 1000 pps";
        default:                        return "unknown";
    }
}

/**
 * @brief Check whether the intensity indicates a possible anomaly
 *
 * VERY_HIGH and FLOODING are considered anomalous for typical OT networks.
 *
 * @param intensity Intensity to check
 * @return true if anomalous, false if normal
 */
inline bool isFlowIntensityAnomalous(FlowIntensity intensity) {
    return intensity == FlowIntensity::VERY_HIGH ||
           intensity == FlowIntensity::FLOODING;
}

/**
 * @brief Check whether the intensity indicates flooding
 *
 * @param intensity Intensity to check
 * @return true if flooding, false otherwise
 */
inline bool isFlowIntensityFlooding(FlowIntensity intensity) {
    return intensity == FlowIntensity::FLOODING;
}

/**
 * @brief Get the suggested color for UI (CSS class)
 *
 * @param intensity Intensity
 * @return Suggested CSS class name
 */
inline const char* flowIntensityColorClass(FlowIntensity intensity) {
    switch (intensity) {
        case FlowIntensity::IDLE:       return "intensity-idle";       // gray
        case FlowIntensity::LOW:        return "intensity-low";        // green
        case FlowIntensity::MEDIUM:     return "intensity-medium";     // yellow
        case FlowIntensity::HIGH:       return "intensity-high";       // orange
        case FlowIntensity::VERY_HIGH:  return "intensity-very-high";  // light red
        case FlowIntensity::FLOODING:   return "intensity-flooding";   // dark red
        default:                        return "intensity-unknown";
    }
}

/**
 * @brief Protocol-specific thresholds for industrial protocols
 *
 * Each protocol can have different traffic characteristics.
 * These are suggested thresholds based on OT best practices.
 */
namespace ProtocolIntensityThresholds {
    /**
     * Modbus TCP
     * Typically slow polling (1-5 sec), rarely > 10 pps
     */
    inline FlowIntensityThresholds modbusDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 0.5f;
        t.low_max = 5.0f;
        t.medium_max = 20.0f;
        t.high_max = 50.0f;
        t.very_high_max = 200.0f;
        return t;
    }

    /**
     * S7 Communication
     * Faster polling possible, but < 100 pps typical
     */
    inline FlowIntensityThresholds s7Defaults() {
        FlowIntensityThresholds t;
        t.idle_max = 1.0f;
        t.low_max = 10.0f;
        t.medium_max = 50.0f;
        t.high_max = 100.0f;
        t.very_high_max = 500.0f;
        return t;
    }

    /**
     * PROFINET DCP
     * Discovery burst-based, normal < 10 pps, > 50 anomalous
     */
    inline FlowIntensityThresholds profinetDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 0.1f;
        t.low_max = 5.0f;
        t.medium_max = 20.0f;
        t.high_max = 50.0f;
        t.very_high_max = 100.0f;
        return t;
    }

    /**
     * EtherNet/IP
     * Can have fast real-time I/O, > 200 pps possible
     */
    inline FlowIntensityThresholds ethernetipDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 1.0f;
        t.low_max = 10.0f;
        t.medium_max = 50.0f;
        t.high_max = 200.0f;
        t.very_high_max = 1000.0f;
        return t;
    }

    /**
     * OPC UA
     * Subscriptions can generate sustained traffic
     */
    inline FlowIntensityThresholds opcuaDefaults() {
        FlowIntensityThresholds t;
        t.idle_max = 1.0f;
        t.low_max = 10.0f;
        t.medium_max = 50.0f;
        t.high_max = 200.0f;
        t.very_high_max = 1000.0f;
        return t;
    }
}

#endif // FLOW_INTENSITY_H
