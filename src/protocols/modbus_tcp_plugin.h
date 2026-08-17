#pragma once
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <memory>

#include "base_plugin.h"
#include "../assessment/network_presence_tracker.h"

// Forward declarations for Modbus Attack Types
enum class ModbusAttackType {
    BASIC_FUZZING = 0,           // Standard fuzzing already implemented
    UNAUTHORIZED_WRITES,         // Advanced unauthorized writes
    DOS_LISTEN_ONLY,            // DoS via Diagnostics Listen-Only Mode
    BROADCAST_ATTACKS,          // RTU broadcast attacks
    DEVICE_DISCOVERY,           // In-depth enumeration and discovery
    VULNERABILITY_EXPLOITS      // Specific exploits for buffer overflow/malformed
};

// Advanced configuration for Modbus attacks
struct ModbusAttackConfig {
    ModbusAttackType attack_type = ModbusAttackType::BASIC_FUZZING;
    std::vector<uint16_t> critical_registers;    // Critical registers to target
    std::vector<uint8_t> unit_id_range;         // Unit ID range for discovery
    bool stealth_mode = false;                  // Stealth mode (broadcast, no response)
    std::string discovery_depth = "basic";      // "basic", "regular", "extended"
    uint32_t timing_delay_ms = 100;             // Delay between attacks for timing attacks
    bool force_broadcast = false;               // Force use of Unit ID 0 (broadcast)
};

// Structure for discovery results
struct ModbusDeviceInfo {
    std::string ip_address;
    uint16_t port = 502;
    std::vector<uint8_t> active_unit_ids;
    std::string vendor;
    std::string product_name;
    std::string version;
    std::vector<uint8_t> supported_functions;
    bool vulnerable_to_dos = false;
    bool supports_broadcast = false;
};

// Base class for specialized attack profiles (integrated into the plugin)
class ModbusAttackProfile {
public:
    virtual ~ModbusAttackProfile() = default;
    virtual ModbusAttackType getType() const = 0;
    virtual bool generateSeeds(const ModbusAttackConfig& config, std::vector<std::vector<uint8_t>>& seeds) = 0;
    virtual std::string executeAttack(const std::string& target, const std::vector<uint8_t>& payload) = 0;
    virtual void parseAttackResponse(const std::vector<uint8_t>& response, const std::vector<uint8_t>& request, std::string& result_json) = 0;

protected:
    // Base implementation for network execution (implemented inline for ESP32 compatibility)
    std::string executeNetworkAttack(const std::string& target, const std::vector<uint8_t>& payload) {
        // Simple implementation for now - just return success
        return "{\"attack_executed\":true,\"target\":\"" + target + "\",\"payload_size\":" + std::to_string(payload.size()) + "}";
    }
};

// Modbus TCP plugin with advanced fuzzing capabilities.
class ModbusTCPPlugin : public BasePlugin {
public:
    ModbusTCPPlugin();

    bool initialize(ConfigurationManager* cfg, ReportingEngine* rep) override;
    void shutdown() override;

    // Active scanning - now returns string report
    std::string doVulnerabilityScan(const std::string& target) override;
    bool doVulnerabilityScanPSRAM(const psram_string& target, psram_string& out_report) override;

    // Network discovery API
    std::string doNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms = 5000) override;
    bool doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                 uint32_t timeout_ms,
                                 psram_string& out_report) override;

    // Network presence tracking API implementation
    NetworkPresenceTracker& getNetworkPresenceTracker() override { return network_presence_tracker_; }
    const NetworkPresenceTracker& getNetworkPresenceTracker() const override { return network_presence_tracker_; }

    // Protocol-specific packet analysis
    bool isPacketWriter(const NetworkPacket& pkt) const override;

    // Passive IDS
    bool doPacketAnalysis(const NetworkPacket& pkt) override;
    bool isTargetPacket(const NetworkPacket& pkt) override { return pkt.src_port==502 || pkt.dst_port==502; }
    void loadIDSRules(const std::string& rules_json) override;

    // Flow Management API (BasePlugin overrides)
    bool buildFlowKey(const NetworkPacket& packet, FlowKey& key) override;
    bool classifyPacketOperation(const NetworkPacket& packet,
                                 psram_string& operation_type,
                                 psram_string& operation_details,
                                 bool& is_error) override;
    void updateProtocolState(const NetworkPacket& packet, FlowData& flow) override;
    void assignFlowLabel(FlowData& flow) override;

    // Fuzzing API (consolidated from ModbusFuzzTarget with advanced attack profiles)
    bool generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) override;
    bool fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) override;
    FuzzResult execute(const FuzzJob& job, const FuzzTestCase& tc,
                      std::string& sent_hex, std::string& received_hex,
                      std::string& status_details) override;

    // Advanced attack profile support (from ModbusFuzzTarget)
    bool generateAttackSeeds(const FuzzJob& job, ModbusAttackType attack_type, std::vector<FuzzTestCase>& out);
    ModbusAttackConfig parseAttackConfig(const FuzzJob& job);

    // Factory method for creating attack profiles
    std::unique_ptr<ModbusAttackProfile> createAttackProfile(ModbusAttackType type);

    // Port monitoring
    std::vector<uint16_t> getMonitoredPorts() const override { return {502}; }

private:
    // Forward declarations for specialized attack profiles
    class UnauthorizedWritesProfile;
    class DoSListenOnlyProfile;
    class BroadcastAttacksProfile;
    class DeviceDiscoveryProfile;
    class VulnerabilityExploitsProfile;

private:
    // Configuration derived from JSON
    struct Config {
        int default_unit_id = 1;
        int connect_timeout_ms = 1500;
        int io_timeout_ms = 1500;
        bool enable_test_write = false;     // dangerous on OT, default false
        int  test_write_register = 0;       // holding register address to test
        std::vector<std::string> allowed_writers; // list of IPs allowed to send write FC
        int discovery_connect_timeout_ms = 3000;
        int discovery_io_timeout_ms = 3000;
        int discovery_request_retries = 3;
        int discovery_connect_retries = 2;
        bool discovery_prescan_enabled = true;
        int discovery_prescan_timeout_ms = 400;
        int discovery_probe_coils_max = 16;
        std::vector<uint8_t> discovery_unit_ids = {1,2,3,4,5,6,7,8,9,10,16,17,32,64,255};
    } cfg_;

    // Helpers
    static bool parseTarget(const std::string& target, std::string& host, uint16_t& port, int& unit_id);
    bool modbusConnect(const std::string& host, uint16_t port, int& sock);
    bool modbusSendRecv(int sock, const std::vector<uint8_t>& pdu, std::vector<uint8_t>& out,
                        int unit_id, uint16_t& txid);
    bool modbusSendRecv(int sock, const std::vector<uint8_t>& pdu, psram_vector<uint8_t>& out,
                        int unit_id, uint16_t& txid);
    void buildUnitScanList(psram_vector<uint8_t>& out) const;

    // PDU builders
    static std::vector<uint8_t> pduReadCoils(uint16_t addr, uint16_t qty);
    static std::vector<uint8_t> pduReadDiscrete(uint16_t addr, uint16_t qty);
    static std::vector<uint8_t> pduReadHolding(uint16_t addr, uint16_t qty);
    static std::vector<uint8_t> pduReadInput(uint16_t addr, uint16_t qty);
    static std::vector<uint8_t> pduReportSlaveID();
    static std::vector<uint8_t> pduDeviceIdentificationBasic(); // FC 0x2B/0x0E basic
    static std::vector<uint8_t> pduWriteSingleRegister(uint16_t addr, uint16_t value);

    // Interpreters
    static bool isException(const std::vector<uint8_t>& pdu);
    static bool isException(const psram_vector<uint8_t>& pdu);
    static uint8_t getFunctionCode(const std::vector<uint8_t>& pdu);
    static uint8_t getFunctionCode(const psram_vector<uint8_t>& pdu);

    // IDS helper methods (consolidated from ModbusIntrusionDetection)
    bool checkModbus(uint32_t now_ms, uint32_t src, uint32_t dst, uint8_t unit_id, uint8_t func,
                     uint16_t start, uint16_t qty, uint16_t trans_id, const uint8_t* pdu, size_t pdu_len);
    bool checkBroadcastWrite(uint8_t unit_id, uint8_t func);
    bool isWriteFunction(uint8_t func) const;

    // Fuzzing helper methods (consolidated from ModbusFuzzTarget)
    void generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out);

    // State
    std::atomic<uint64_t> scans_ok_{0}, scans_fail_{0};
    bool alert_broadcast_write_ = true;

    // Writers tracking for this protocol
    NetworkPresenceTracker network_presence_tracker_;

    std::string legacyDoVulnerabilityScan(const std::string& target);
    std::string legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms);
};
