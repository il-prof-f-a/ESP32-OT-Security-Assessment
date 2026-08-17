/**
 * @file flow_label.h
 * @brief Classification labels for network flows
 *
 * Universal classification system for flow behavior.
 * Used by all protocols to identify traffic patterns,
 * anomalies and potential threats.
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_LABEL_H
#define FLOW_LABEL_H

#include <cstdint>
#include "core/logging_system.h"

/**
 * @brief Classification labels for network flows
 *
 * Enum that identifies the behavior/type of a flow.
 * Each plugin can assign one or more labels based on the analysis
 * of traffic and detected operations.
 *
 * The labels are organized into categories:
 * - 0-9:   Normal base states
 * - 10-19: Normal operation types
 * - 20-29: Detected patterns (not necessarily malicious)
 * - 30-39: Anomalies and suspicious behaviors
 * - 40-49: Vulnerabilities or weak configurations
 * - 50-59: Critical operations or confirmed attacks
 */
enum class FlowLabel : uint8_t {
    // ==================== BASE STATES (0-9) ====================

    /**
     * Normal operation, no anomalies detected
     */
    NORMAL_OPERATION = 0,

    /**
     * Inactive flow (no recent traffic)
     */
    IDLE = 1,

    /**
     * Flow in initialization phase (handshake)
     */
    INITIALIZING = 2,

    /**
     * Flow in closing
     */
    CLOSING = 3,

    // ==================== OPERATION TYPES (10-19) ====================

    /**
     * Flow that performs only read operations
     * (e.g.: Modbus Read Coils/Registers, S7 Read Variable, OPC UA Read)
     */
    READER = 10,

    /**
     * Flow that performs write operations
     * (e.g.: Modbus Write, S7 Write Variable, OPC UA Write)
     */
    WRITER = 11,

    /**
     * Flow with a mix of reads and writes
     */
    MIXED_RW = 12,

    /**
     * Broadcast operations (Modbus unit_id=255)
     */
    BROADCASTER = 13,

    /**
     * Legitimate diagnostic/discovery operations
     * (e.g.: Modbus Device ID, PROFINET DCP Identify, ENIP ListIdentity)
     */
    DIAGNOSTIC = 14,

    // ==================== DETECTED PATTERNS (20-29) ====================

    /**
     * Systematic scanning of addresses/registers
     * (many sequential reads in a short time)
     */
    SCANNER = 20,

    /**
     * Active reconnaissance (discovery services)
     * (e.g.: PROFINET DCP Get, OPC UA Browse, ENIP ListServices)
     */
    RECONNAISSANCE = 21,

    /**
     * High but regular traffic (normal intensive user)
     */
    HEAVY_USER = 22,

    /**
     * Regular polling pattern (e.g.: SCADA reading cyclically)
     */
    POLLING = 23,

    // ==================== ANOMALIES (30-39) ====================

    /**
     * Suspicious behavior detected (unusual pattern)
     */
    SUSPICIOUS = 30,

    /**
     * Potential attack in progress (to be confirmed)
     */
    POTENTIAL_ATTACK = 31,

    /**
     * Multiple failed authentication attempts
     * (e.g.: repeated OPC UA CreateSession, S7 Setup Communication storm)
     */
    BRUTE_FORCE_ATTEMPT = 32,

    /**
     * Flooding: excessive anomalous traffic
     * (pps beyond threshold, possible DoS)
     */
    FLOODING = 33,

    /**
     * Protocol violation: malformed packets or wrong sequence
     */
    PROTOCOL_VIOLATION = 34,

    /**
     * Reception of many malformed packets
     */
    MALFORMED_PACKETS = 35,

    /**
     * Anomalous temporal pattern (e.g.: activity outside working hours)
     */
    TEMPORAL_ANOMALY = 36,

    /**
     * Access to unexpected or unauthorized resources
     */
    UNAUTHORIZED_ACCESS = 37,

    // ==================== VULNERABILITIES (40-49) ====================

    /**
     * Use of detected default credentials
     */
    DEFAULT_CREDENTIALS = 40,

    /**
     * Weak security configuration
     * (e.g.: PROFINET Security Class 0, OPC UA Policy#None)
     */
    WEAK_SECURITY = 41,

    /**
     * Unencrypted communication where it should be encrypted
     * (e.g.: OPC UA without encryption, S7 non-TLS)
     */
    NO_ENCRYPTION = 42,

    /**
     * Anonymous authentication allowed
     * (e.g.: OPC UA anonymous login allowed)
     */
    ANONYMOUS_ALLOWED = 43,

    /**
     * Default device name not changed
     * (e.g.: PROFINET "station_1")
     */
    DEFAULT_DEVICE_NAME = 44,

    /**
     * Exposed port/service should not be accessible
     */
    EXPOSED_SERVICE = 45,

    // ==================== CRITICAL (50-59) ====================

    /**
     * Dangerous operation detected
     * (e.g.: S7 STOP CPU, OPC UA DeleteNodes, ENIP Reset)
     */
    DANGEROUS_OPERATION = 50,

    /**
     * Critical write: broadcast write, write on critical area
     * (e.g.: Modbus write broadcast, S7 write safety area)
     */
    CRITICAL_WRITE = 51,

    /**
     * Confirmed attack in progress
     */
    ATTACK_CONFIRMED = 52,

    /**
     * Configuration manipulation attempt
     * (e.g.: PROFINET DCP Set storm, IP/device name change)
     */
    CONFIGURATION_TAMPERING = 53,

    /**
     * Session hijacking attempt
     * (e.g.: OPC UA session token reuse, ENIP session handle spoofing)
     */
    SESSION_HIJACKING = 54,

    /**
     * Replay attack detected
     * (e.g.: PROFINET XID reuse, identical duplicate packets)
     */
    REPLAY_ATTACK = 55
};

/**
 * @brief Convert FlowLabel to a readable string
 *
 * @param label Label to convert
 * @return Name of the label as a constant string
 */
inline const char* flowLabelToString(FlowLabel label) {
    switch (label) {
        // Base states
        case FlowLabel::NORMAL_OPERATION:       return "NORMAL_OPERATION";
        case FlowLabel::IDLE:                   return "IDLE";
        case FlowLabel::INITIALIZING:           return "INITIALIZING";
        case FlowLabel::CLOSING:                return "CLOSING";

        // Operation types
        case FlowLabel::READER:                 return "READER";
        case FlowLabel::WRITER:                 return "WRITER";
        case FlowLabel::MIXED_RW:               return "MIXED_RW";
        case FlowLabel::BROADCASTER:            return "BROADCASTER";
        case FlowLabel::DIAGNOSTIC:             return "DIAGNOSTIC";

        // Detected patterns
        case FlowLabel::SCANNER:                return "SCANNER";
        case FlowLabel::RECONNAISSANCE:         return "RECONNAISSANCE";
        case FlowLabel::HEAVY_USER:             return "HEAVY_USER";
        case FlowLabel::POLLING:                return "POLLING";

        // Anomalies
        case FlowLabel::SUSPICIOUS:             return "SUSPICIOUS";
        case FlowLabel::POTENTIAL_ATTACK:       return "POTENTIAL_ATTACK";
        case FlowLabel::BRUTE_FORCE_ATTEMPT:    return "BRUTE_FORCE_ATTEMPT";
        case FlowLabel::FLOODING:               return "FLOODING";
        case FlowLabel::PROTOCOL_VIOLATION:     return "PROTOCOL_VIOLATION";
        case FlowLabel::MALFORMED_PACKETS:      return "MALFORMED_PACKETS";
        case FlowLabel::TEMPORAL_ANOMALY:       return "TEMPORAL_ANOMALY";
        case FlowLabel::UNAUTHORIZED_ACCESS:    return "UNAUTHORIZED_ACCESS";

        // Vulnerabilities
        case FlowLabel::DEFAULT_CREDENTIALS:    return "DEFAULT_CREDENTIALS";
        case FlowLabel::WEAK_SECURITY:          return "WEAK_SECURITY";
        case FlowLabel::NO_ENCRYPTION:          return "NO_ENCRYPTION";
        case FlowLabel::ANONYMOUS_ALLOWED:      return "ANONYMOUS_ALLOWED";
        case FlowLabel::DEFAULT_DEVICE_NAME:    return "DEFAULT_DEVICE_NAME";
        case FlowLabel::EXPOSED_SERVICE:        return "EXPOSED_SERVICE";

        // Critical
        case FlowLabel::DANGEROUS_OPERATION:    return "DANGEROUS_OPERATION";
        case FlowLabel::CRITICAL_WRITE:         return "CRITICAL_WRITE";
        case FlowLabel::ATTACK_CONFIRMED:       return "ATTACK_CONFIRMED";
        case FlowLabel::CONFIGURATION_TAMPERING: return "CONFIGURATION_TAMPERING";
        case FlowLabel::SESSION_HIJACKING:      return "SESSION_HIJACKING";
        case FlowLabel::REPLAY_ATTACK:          return "REPLAY_ATTACK";

        default:                                return "UNKNOWN";
    }
}

/**
 * @brief Convert FlowLabel to the appropriate LogLevel
 *
 * Determines the logging level based on the severity of the label.
 *
 * Mapping:
 * - NORMAL, IDLE, READER, WRITER, etc. -> INFO
 * - SUSPICIOUS, SCANNER -> WARNING
 * - POTENTIAL_ATTACK, vulnerability -> WARNING
 * - DANGEROUS_OPERATION, ATTACK_CONFIRMED -> ERROR
 *
 * @param label Label to convert
 * @return Appropriate LogLevel
 */
inline LogLevel flowLabelToLogLevel(FlowLabel label) {
    uint8_t val = static_cast<uint8_t>(label);

    // Base states and normal operation types (0-19)
    if (val < 20) {
        return LogLevel::INFO;
    }

    // Detected patterns (20-29) -> INFO/WARNING
    if (val >= 20 && val < 30) {
        // SCANNER and RECONNAISSANCE are WARNING
        if (label == FlowLabel::SCANNER || label == FlowLabel::RECONNAISSANCE) {
            return LogLevel::WARNING;
        }
        return LogLevel::INFO;
    }

    // Anomalies (30-39) -> WARNING
    if (val >= 30 && val < 40) {
        return LogLevel::WARNING;
    }

    // Vulnerabilities (40-49) -> WARNING
    if (val >= 40 && val < 50) {
        return LogLevel::WARNING;
    }

    // Critical (50-59) -> ERROR
    if (val >= 50) {
        return LogLevel::ERROR;
    }

    return LogLevel::INFO;
}

/**
 * @brief Check whether a label indicates malicious behavior
 *
 * @param label Label to check
 * @return true if potentially malicious, false otherwise
 */
inline bool isFlowLabelMalicious(FlowLabel label) {
    uint8_t val = static_cast<uint8_t>(label);

    // Anomalies (30-39), Critical (50-59)
    return (val >= 30 && val < 40) || (val >= 50);
}

/**
 * @brief Check whether a label indicates a vulnerability
 *
 * @param label Label to check
 * @return true if it is a vulnerability, false otherwise
 */
inline bool isFlowLabelVulnerability(FlowLabel label) {
    uint8_t val = static_cast<uint8_t>(label);

    // Vulnerabilities (40-49)
    return (val >= 40 && val < 50);
}

/**
 * @brief Check whether a label indicates a critical operation
 *
 * @param label Label to check
 * @return true if it is critical, false otherwise
 */
inline bool isFlowLabelCritical(FlowLabel label) {
    uint8_t val = static_cast<uint8_t>(label);

    // Critical (50-59)
    return (val >= 50);
}

/**
 * @brief Get the category of the label
 *
 * @param label Label to classify
 * @return Category name as a string
 */
inline const char* getFlowLabelCategory(FlowLabel label) {
    uint8_t val = static_cast<uint8_t>(label);

    if (val < 10)       return "BASE_STATE";
    if (val < 20)       return "OPERATION_TYPE";
    if (val < 30)       return "PATTERN_DETECTED";
    if (val < 40)       return "ANOMALY";
    if (val < 50)       return "VULNERABILITY";
    if (val < 60)       return "CRITICAL";

    return "UNKNOWN";
}

/**
 * @brief Check whether a label indicates suspicious behavior
 *
 * Includes anomalies (30-39) and critical (50-59), excludes vulnerabilities (40-49)
 * because vulnerabilities are weak configurations, not active behaviors.
 *
 * @param label Label to check
 * @return true if suspicious, false otherwise
 */
inline bool isFlowLabelSuspicious(FlowLabel label) {
    uint8_t val = static_cast<uint8_t>(label);
    // Anomalies (30-39) or Critical (50-59)
    return (val >= 30 && val < 40) || (val >= 50);
}

/**
 * @brief Get the detailed description of the label
 *
 * @param label Label to describe
 * @return Textual description
 */
inline const char* flowLabelDescription(FlowLabel label) {
    switch (label) {
        case FlowLabel::NORMAL_OPERATION:
            return "Normal operation, no anomalies detected";
        case FlowLabel::IDLE:
            return "Flow inactive (no recent traffic)";
        case FlowLabel::INITIALIZING:
            return "Flow initializing (handshake in progress)";
        case FlowLabel::CLOSING:
            return "Flow closing";
        case FlowLabel::READER:
            return "Read-only operations (polling, monitoring)";
        case FlowLabel::WRITER:
            return "Write operations detected";
        case FlowLabel::MIXED_RW:
            return "Mixed read/write operations";
        case FlowLabel::BROADCASTER:
            return "Broadcast operations";
        case FlowLabel::DIAGNOSTIC:
            return "Legitimate diagnostic/discovery operations";
        case FlowLabel::SCANNER:
            return "Systematic scanning of addresses/registers";
        case FlowLabel::RECONNAISSANCE:
            return "Active reconnaissance (discovery services)";
        case FlowLabel::HEAVY_USER:
            return "High traffic but regular pattern";
        case FlowLabel::POLLING:
            return "Regular polling pattern (SCADA-like)";
        case FlowLabel::SUSPICIOUS:
            return "Suspicious behavior detected (unusual pattern)";
        case FlowLabel::POTENTIAL_ATTACK:
            return "Potential attack in progress (to be confirmed)";
        case FlowLabel::BRUTE_FORCE_ATTEMPT:
            return "Multiple authentication failures";
        case FlowLabel::FLOODING:
            return "Excessive anomalous traffic (possible DoS)";
        case FlowLabel::PROTOCOL_VIOLATION:
            return "Protocol violation: malformed packets or wrong sequence";
        case FlowLabel::MALFORMED_PACKETS:
            return "Multiple malformed packets received";
        case FlowLabel::TEMPORAL_ANOMALY:
            return "Anomalous temporal pattern (e.g., off-hours activity)";
        case FlowLabel::UNAUTHORIZED_ACCESS:
            return "Access to unexpected or unauthorized resources";
        case FlowLabel::DEFAULT_CREDENTIALS:
            return "Default credentials detected";
        case FlowLabel::WEAK_SECURITY:
            return "Weak security configuration";
        case FlowLabel::NO_ENCRYPTION:
            return "Unencrypted communication where encryption expected";
        case FlowLabel::ANONYMOUS_ALLOWED:
            return "Anonymous authentication allowed";
        case FlowLabel::DEFAULT_DEVICE_NAME:
            return "Default device name not changed";
        case FlowLabel::EXPOSED_SERVICE:
            return "Port/service exposed (should not be accessible)";
        case FlowLabel::DANGEROUS_OPERATION:
            return "Dangerous operation detected (CPU STOP, DeleteNodes, Reset)";
        case FlowLabel::CRITICAL_WRITE:
            return "Critical write: broadcast or safety area";
        case FlowLabel::ATTACK_CONFIRMED:
            return "Attack confirmed in progress";
        case FlowLabel::CONFIGURATION_TAMPERING:
            return "Attempt to manipulate configuration";
        case FlowLabel::SESSION_HIJACKING:
            return "Session hijacking attempt";
        case FlowLabel::REPLAY_ATTACK:
            return "Replay attack detected";
        default:
            return "Unknown label";
    }
}

#endif // FLOW_LABEL_H
