#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include "psram_allocator.h"
extern "C" {
    #include "cJSON.h"
    #include "esp_timer.h"
}

// Forward declarations
class ReportingEngine;

// Common structures for detailed reporting
struct PacketData {
    psram_string hex;
    size_t size = 0;
    uint64_t timestamp = 0;
    cJSON* structure = nullptr; // Protocol-specific parsed structure

    PacketData() = default;
    ~PacketData() {
        if (structure) {
            cJSON_Delete(structure);
            structure = nullptr;
        }
    }

    // Move constructor
    PacketData(PacketData&& other) noexcept
        : hex(std::move(other.hex)), size(other.size), timestamp(other.timestamp), structure(other.structure) {
        other.structure = nullptr;
        other.size = 0;
        other.timestamp = 0;
    }

    // Move assignment
    PacketData& operator=(PacketData&& other) noexcept {
        if (this != &other) {
            if (structure) cJSON_Delete(structure);
            hex = std::move(other.hex);
            size = other.size;
            timestamp = other.timestamp;
            structure = other.structure;
            other.structure = nullptr;
            other.size = 0;
            other.timestamp = 0;
        }
        return *this;
    }

    // Delete copy operations to prevent issues with cJSON*
    PacketData(const PacketData&) = delete;
    PacketData& operator=(const PacketData&) = delete;
};

struct TestResult {
    psram_string status;           // "success", "failure", "timeout", "exception", "error"
    bool vulnerability_found = false;
    psram_string vulnerability_type;
    psram_string severity;         // "critical", "high", "medium", "low"
    int result_code = 0;
    psram_string description;
    float cvss_score = 0.0f;
    psram_string recommendation;
    uint32_t execution_time_ms = 0;
    uint32_t retries = 0;
};

// Base class for all detailed report builders
class DetailedReportBuilderBase {
public:
    DetailedReportBuilderBase();
    virtual ~DetailedReportBuilderBase();

    // Common fields
    void setDeviceId(const psram_string& device_id);
    void setSessionId(const psram_string& session_id);
    void setModuleInfo(const psram_string& module, const psram_string& version);
    void setTimestamp(uint64_t timestamp_ms = 0); // 0 = current time

    // Build the final JSON report
    virtual psram_string build() = 0;

protected:
    // Common JSON building helpers
    cJSON* createBaseStructure();
    void addPacketToJSON(cJSON* parent, const char* key, const PacketData& packet);
    void addTestResultToJSON(cJSON* parent, const TestResult& result);

    // Convert cJSON to PSRAM string
    psram_string jsonToString(cJSON* root);

    // Common fields
    psram_string schema_version_;
    psram_string event_type_;
    uint64_t timestamp_;
    psram_string device_id_;
    psram_string session_id_;
    psram_string module_name_;
    psram_string module_version_;

private:
    static psram_string getDeviceId();
};

// Fuzzing test report builder
class FuzzTestReportBuilder : public DetailedReportBuilderBase {
public:
    FuzzTestReportBuilder();
    ~FuzzTestReportBuilder() override = default;

    // Test information
    void setTestInfo(uint32_t job_id, uint32_t test_case_id, uint32_t mutation_id, uint32_t seed_id);
    void setTestType(const psram_string& test_type);
    void setProtocol(const psram_string& protocol);
    void setTarget(const psram_string& host, uint16_t port, uint32_t unit_id = 0, const psram_string& endpoint = PSRAMUtils::createPSRAMString(""));

    // Packet data
    void setSentPacket(const psram_string& hex, size_t size, cJSON* structure = nullptr);
    void setReceivedPacket(const psram_string& hex, size_t size, cJSON* structure = nullptr, uint32_t delay_ms = 0);

    // Test result
    void setResult(const TestResult& result);

    // Metrics
    void setMetrics(uint32_t execution_time_ms, uint32_t retries, float success_rate);

    psram_string build() override;

private:
    uint32_t job_id_ = 0;
    uint32_t test_case_id_ = 0;
    uint32_t mutation_id_ = 0;
    uint32_t seed_id_ = 0;
    psram_string test_type_;
    psram_string protocol_;
    psram_string target_host_;
    uint16_t target_port_ = 0;
    uint32_t target_unit_id_ = 0;
    psram_string target_endpoint_;

    PacketData sent_packet_;
    PacketData received_packet_;
    uint32_t packet_delay_ms_ = 0;

    TestResult result_;

    uint32_t execution_time_ms_ = 0;
    uint32_t retries_ = 0;
    float success_rate_ = 0.0f;
};

// Vulnerability scan report builder
class VulnScanReportBuilder : public DetailedReportBuilderBase {
public:
    struct VulnTest {
        psram_string test_id;
        psram_string test_name;
        psram_string test_description;
        PacketData sent_packet;
        PacketData received_packet;
        TestResult result;

        VulnTest() = default;
        VulnTest(VulnTest&&) = default;
        VulnTest& operator=(VulnTest&&) = default;
        VulnTest(const VulnTest&) = delete;
        VulnTest& operator=(const VulnTest&) = delete;
    };

    struct ScanSummary {
        uint32_t tests_run = 0;
        uint32_t vulnerabilities_found = 0;
        uint32_t critical = 0;
        uint32_t high = 0;
        uint32_t medium = 0;
        uint32_t low = 0;
        uint32_t scan_duration_ms = 0;
        psram_string overall_risk;
    };

    VulnScanReportBuilder();
    ~VulnScanReportBuilder() override = default;

    // Scan information
    void setScanInfo(uint32_t job_id, const psram_string& scan_name, const psram_string& scan_type);
    void setProtocol(const psram_string& protocol);
    void setTarget(const psram_string& host, uint16_t port, const psram_string& description = PSRAMUtils::createPSRAMString(""));

    // Add individual test results
    void addTest(VulnTest&& test);

    // Summary
    void setSummary(const ScanSummary& summary);

    psram_string build() override;

private:
    uint32_t job_id_ = 0;
    psram_string scan_name_;
    psram_string scan_type_;
    psram_string protocol_;
    psram_string target_host_;
    uint16_t target_port_ = 0;
    psram_string target_description_;

    psram_vector<VulnTest> tests_;
    ScanSummary summary_;
};

// IDS detection report builder
class IDSDetectionReportBuilder : public DetailedReportBuilderBase {
public:
    struct DetectionInfo {
        psram_string alert_id;
        psram_string detection_type;  // "signature_based", "anomaly_based", "behavioral", "statistical"
        psram_string rule_id;
        psram_string rule_name;
        psram_string rule_description;
        psram_string severity;        // "critical", "high", "medium", "low", "info"
        float confidence = 0.0f;
    };

    struct PacketInfo {
        psram_string direction;       // "inbound", "outbound", "internal"
        psram_string src_ip;
        uint16_t src_port = 0;
        psram_string src_mac;
        psram_string src_hostname;
        psram_string dst_ip;
        uint16_t dst_port = 0;
        psram_string dst_mac;
        psram_string dst_hostname;
        psram_string protocol;
        PacketData raw_data;
        cJSON* parsed_data = nullptr;

        ~PacketInfo() {
            if (parsed_data) {
                cJSON_Delete(parsed_data);
                parsed_data = nullptr;
            }
        }

        PacketInfo() = default;
        PacketInfo(PacketInfo&& other) noexcept
            : direction(std::move(other.direction)), src_ip(std::move(other.src_ip)),
              src_port(other.src_port), src_mac(std::move(other.src_mac)), src_hostname(std::move(other.src_hostname)),
              dst_ip(std::move(other.dst_ip)), dst_port(other.dst_port), dst_mac(std::move(other.dst_mac)),
              dst_hostname(std::move(other.dst_hostname)), protocol(std::move(other.protocol)),
              raw_data(std::move(other.raw_data)), parsed_data(other.parsed_data) {
            other.parsed_data = nullptr;
            other.src_port = 0;
            other.dst_port = 0;
        }

        PacketInfo& operator=(PacketInfo&& other) noexcept {
            if (this != &other) {
                if (parsed_data) cJSON_Delete(parsed_data);
                direction = std::move(other.direction);
                src_ip = std::move(other.src_ip);
                src_port = other.src_port;
                src_mac = std::move(other.src_mac);
                src_hostname = std::move(other.src_hostname);
                dst_ip = std::move(other.dst_ip);
                dst_port = other.dst_port;
                dst_mac = std::move(other.dst_mac);
                dst_hostname = std::move(other.dst_hostname);
                protocol = std::move(other.protocol);
                raw_data = std::move(other.raw_data);
                parsed_data = other.parsed_data;
                other.parsed_data = nullptr;
                other.src_port = 0;
                other.dst_port = 0;
            }
            return *this;
        }

        PacketInfo(const PacketInfo&) = delete;
        PacketInfo& operator=(const PacketInfo&) = delete;
    };

    struct DetectionContext {
        float baseline_deviation = 0.0f;
        uint32_t requests_per_second = 0;
        uint32_t typical_rate = 0;
        float deviation_factor = 0.0f;
        psram_string_vector related_events;
        psram_string attack_pattern;  // "data_exfiltration", "dos_attempt", "reconnaissance", "exploitation"
    };

    IDSDetectionReportBuilder();
    ~IDSDetectionReportBuilder() override = default;

    // Detection information
    void setDetectionInfo(const DetectionInfo& detection);
    void setPacketInfo(const PacketInfo& packet);
    void setContext(const DetectionContext& context);
    void setActionTaken(const psram_string& action);

    psram_string build() override;

private:
    DetectionInfo detection_;
    PacketInfo packet_;
    DetectionContext context_;
    psram_string action_taken_;
};

// Whitelist violation report builder
class WhitelistViolationReportBuilder : public DetailedReportBuilderBase {
public:
    struct ViolationInfo {
        psram_string violation_id;
        psram_string violation_type;  // "ip_not_allowed", "mac_not_allowed", "protocol_not_allowed", "port_not_allowed", "function_not_allowed"
        psram_string whitelist_name;
        psram_string severity;        // "critical", "high", "medium", "low"
    };

    struct WhitelistCheck {
        bool ip_allowed = false;
        bool mac_allowed = false;
        bool protocol_allowed = false;
        bool port_allowed = false;
        bool function_allowed = false;
        psram_string failed_check;
        psram_string_vector expected_ips;
        psram_string_vector expected_macs;
        psram_string_vector expected_protocols;
    };

    WhitelistViolationReportBuilder();
    ~WhitelistViolationReportBuilder() override = default;

    // Violation information
    void setViolationInfo(const ViolationInfo& violation);
    void setPacketInfo(const IDSDetectionReportBuilder::PacketInfo& packet);
    void setWhitelistCheck(const WhitelistCheck& check);
    void setActionTaken(const psram_string& action);

    psram_string build() override;

private:
    ViolationInfo violation_;
    IDSDetectionReportBuilder::PacketInfo packet_;
    WhitelistCheck whitelist_check_;
    psram_string action_taken_;
};

// Global helper functions
void registerDetailedReportBuilders(ReportingEngine* reporting_engine);
psram_string formatPacketHex(const uint8_t* data, size_t size);
cJSON* parseModbusPacket(const uint8_t* data, size_t size);
cJSON* parseS7Packet(const uint8_t* data, size_t size);
cJSON* parseOPCUAPacket(const uint8_t* data, size_t size);
cJSON* parseEtherNetIPPacket(const uint8_t* data, size_t size);