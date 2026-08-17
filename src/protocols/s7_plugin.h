
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>

#include "base_plugin.h"
#include "../network/ethernet_tx_if.h"
#include "../assessment/network_presence_tracker.h"
#include "../core/psram_allocator.h"

class SecurityManager;

// S7 Protocol Constants
namespace S7 {
    // PDU Types (ROSCTR)
    constexpr uint8_t PDU_TYPE_JOB = 0x01;         // Request
    constexpr uint8_t PDU_TYPE_ACK = 0x02;         // Acknowledgement (no data)
    constexpr uint8_t PDU_TYPE_ACK_DATA = 0x03;    // Response with data
    constexpr uint8_t PDU_TYPE_USERDATA = 0x07;    // Userdata (SZL, programming, etc.)

    // Function Codes
    constexpr uint8_t FUNC_READ_VAR = 0x04;
    constexpr uint8_t FUNC_WRITE_VAR = 0x05;
    constexpr uint8_t FUNC_SETUP_COMM = 0xF0;
    constexpr uint8_t FUNC_STOP_CPU = 0x29;
    constexpr uint8_t FUNC_HOT_RESTART = 0x28;
    constexpr uint8_t FUNC_COLD_RESTART = 0x28;    // Same as hot restart, parameter differs

    // SZL IDs (System Status List)
    constexpr uint16_t SZL_MODULE_IDENTIFICATION = 0x0011;
    constexpr uint16_t SZL_CPU_CHARACTERISTICS = 0x0131;
    constexpr uint16_t SZL_CPU_PROTECTION = 0x0232;
    constexpr uint16_t SZL_COMPONENT_IDENTIFICATION = 0x001C;

    // Protection Levels
    constexpr uint8_t PROTECTION_NONE = 0;
    constexpr uint8_t PROTECTION_WRITE = 1;
    constexpr uint8_t PROTECTION_READ_WRITE = 2;
    constexpr uint8_t PROTECTION_FULL = 3;
}

// S7 Device Information Structure (NO std::string - only fixed char arrays!)
struct S7DeviceInfo {
    char module_type[32];        // "S7-300", "S7-1200", "S7-1500"
    char order_code[32];         // "6ES7 212-1AE40-0XB0"
    char firmware_version[16];   // "V4.5.2"
    char serial_number[24];      // "S C-X4U421302009"
    char plant_id[32];           // Plant/location identifier
    char copyright_info[64];     // Copyright string from SZL

    uint16_t asdu_length;        // Max PDU size negotiated
    uint16_t max_jobs_calling;   // Max parallel jobs (calling)
    uint16_t max_jobs_called;    // Max parallel jobs (called)

    uint8_t protection_level;    // 0-3 (see S7::PROTECTION_*)
    bool supports_password;
    bool supports_encryption;
    bool is_online;

    // Additional flags
    bool szl_read_success;
    bool setup_comm_success;

    S7DeviceInfo() : asdu_length(0), max_jobs_calling(0), max_jobs_called(0),
                     protection_level(S7::PROTECTION_NONE),
                     supports_password(false), supports_encryption(false),
                     is_online(false), szl_read_success(false),
                     setup_comm_success(false) {
        module_type[0] = '\0';
        order_code[0] = '\0';
        firmware_version[0] = '\0';
        serial_number[0] = '\0';
        plant_id[0] = '\0';
        copyright_info[0] = '\0';
    }
};

class S7Plugin : public BasePlugin {
public:
    S7Plugin(EthernetTxIf* tx = nullptr, SecurityManager* sec = nullptr);

    bool initialize(ConfigurationManager* cfg, ReportingEngine* rep) override;
    void shutdown() override;

    // Active scan entry point (used by VulnerabilityScanner and REST) - now returns string report
    std::string doVulnerabilityScan(const std::string& target) override;
    bool doVulnerabilityScanPSRAM(const psram_string& target, psram_string& out_report) override;
    std::string doNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms = 5000) override;
    bool doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                 uint32_t timeout_ms,
                                 psram_string& out_report) override;

    // Network presence tracking API implementation
    NetworkPresenceTracker& getNetworkPresenceTracker() override { return network_presence_tracker_; }
    const NetworkPresenceTracker& getNetworkPresenceTracker() const override { return network_presence_tracker_; }

    // Protocol-specific packet analysis
    bool isPacketWriter(const NetworkPacket& pkt) const override;

    // IDS passive hooks
    bool doPacketAnalysis(const NetworkPacket& pkt) override;
    bool isTargetPacket(const NetworkPacket& pkt) override;
    void loadIDSRules(const std::string& rules_json) override;

    // Flow Management API (BasePlugin overrides)
    bool buildFlowKey(const NetworkPacket& packet, FlowKey& key) override;
    bool classifyPacketOperation(const NetworkPacket& packet,
                                 psram_string& operation_type,
                                 psram_string& operation_details,
                                 bool& is_error) override;
    void updateProtocolState(const NetworkPacket& packet, FlowData& flow) override;
    void assignFlowLabel(FlowData& flow) override;

    // Fuzzing API (move to cpp)
    bool generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) override;
    bool fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) override;
    FuzzResult execute(const FuzzJob& job, const FuzzTestCase& tc,
                      std::string& sent_hex, std::string& received_hex,
                      std::string& status_details) override;

    // Advanced fuzzing
    bool generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out);

    // Port monitoring
    std::vector<uint16_t> getMonitoredPorts() const override { return {102}; }

    // Extra API for REST
    bool activeScanJSON(const std::string& target,
                        std::string& out_json,
                        uint32_t timeout_ms = 3000,
                        bool lightweight = false);

    // Snap7-style client operations (read-only by default; state-changing ops are gated by SecurityManager).
    // Request JSON example:
    // {"op":"read_db","target":"192.168.1.1:102","db":1,"start":0,"size":1,"timeout_ms":3000}
    bool clientOpsPSRAM(const psram_string& request_json, psram_string& out_json);

    struct RuntimeStats {
        uint64_t handshake_started = 0;
        uint64_t handshake_confirmed = 0;
        uint64_t handshake_failed = 0;
        uint64_t setup_comm_completed = 0;
        uint64_t tls_sessions = 0;
        uint64_t stop_cpu_detected = 0;
        uint64_t stop_cpu_blocked = 0;
        uint64_t restart_detected = 0;
        uint64_t reconnaissance_alerts = 0;
        uint64_t write_alerts = 0;
        uint64_t brute_force_alerts = 0;
        uint64_t flooding_alerts = 0;
    };
    void getRuntimeStats(RuntimeStats& out) const;

    // wiring
    void setEthernetTx(EthernetTxIf* tx) { tx_ = tx; }
    void setSecurity(SecurityManager* s) { sec_ = s; }

private:
    struct S7FlowContext {
        bool handshake_started = false;
        bool handshake_confirmed = false;
        bool setup_complete = false;
        bool handshake_alerted = false;
    };

    // --- Helpers ---
    static bool isTLSClientHello(const uint8_t* buf, size_t len);
    static const uint8_t* locateS7Pdu(const uint8_t* buf, size_t len, size_t& out_len);
    static bool parseS7Function(const uint8_t* s7, size_t s7_len, uint8_t& rosctr, uint8_t& func_code);
    static bool splitTarget(const std::string& t, std::string& ip, uint16_t& port);
    bool doHandshake(const std::string& ip, uint16_t port, uint16_t& negotiated_pdu, std::string& note);

    // --- Enhanced Discovery Methods (Phase 1) ---
    bool sendS7SetupComm(int sock, S7DeviceInfo& dev_info);
    bool readSZL(int sock, uint16_t szl_id, uint16_t szl_index, S7DeviceInfo& dev_info);
    bool parseSZLResponse(const uint8_t* data, size_t len, uint16_t szl_id, S7DeviceInfo& dev_info);
    bool buildDeviceInfoJSON(const S7DeviceInfo& dev_info, const char* target_ip, uint16_t port, psram_string& out_json);

    // --- Vulnerability Check Methods (Phase 2) ---
    bool checkAuthentication(int sock, psram_string& finding);
    bool checkProtectionLevel(int sock, S7DeviceInfo& dev_info);
    bool testAnonymousStop(int sock, psram_string& finding);

    // --- Helper functions ---
    static void wr16be(uint8_t* p, uint16_t v) { p[0] = (v >> 8) & 0xFF; p[1] = v & 0xFF; }
    static void wr32be(uint8_t* p, uint32_t v) {
        p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF;
        p[2] = (v >> 8) & 0xFF; p[3] = v & 0xFF;
    }
    static uint16_t rd16be(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
    static uint32_t rd32be(const uint8_t* p) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    static void cleanupFlowContext(void* ctx_ptr);
    void raiseHandshakeAlert(const NetworkPacket& packet, S7FlowContext* ctx, const char* reason);

    EthernetTxIf* tx_ = nullptr;
    SecurityManager* sec_ = nullptr;

    std::atomic<uint64_t> ids_events_{0}, scans_ok_{0}, scans_fail_{0};
    std::atomic<uint64_t> handshake_started_{0};
    std::atomic<uint64_t> handshake_confirmed_{0};
    std::atomic<uint64_t> handshake_failed_{0};
    std::atomic<uint64_t> setup_comm_success_{0};
    std::atomic<uint64_t> tls_sessions_{0};
    std::atomic<uint64_t> stop_cpu_detected_{0};
    std::atomic<uint64_t> stop_cpu_blocked_{0};
    std::atomic<uint64_t> restart_detected_{0};
    std::atomic<uint64_t> reconnaissance_alerts_{0};
    std::atomic<uint64_t> write_alerts_{0};
    std::atomic<uint64_t> brute_force_alerts_{0};
    std::atomic<uint64_t> flooding_alerts_{0};

    // Writers tracking for this protocol
    NetworkPresenceTracker network_presence_tracker_;

    std::string legacyDoVulnerabilityScan(const std::string& target);
    std::string legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms);
};
