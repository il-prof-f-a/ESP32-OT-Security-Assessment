#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

#include "base_plugin.h"
#include "../network/ethernet_tx_if.h"
#include "../assessment/network_presence_tracker.h"
#include "../core/psram_allocator.h"

// PROFINET Protocol Constants
namespace PROFINET {
    // EtherType
    constexpr uint16_t ETHERTYPE_PN_DCP = 0x8892;  // PROFINET DCP (Discovery and Configuration Protocol)
    constexpr uint16_t ETHERTYPE_PN_RT = 0x8892;   // PROFINET Real-Time (cyclic data)

    // DCP Service IDs
    constexpr uint8_t DCP_SERVICE_GET = 0x03;
    constexpr uint8_t DCP_SERVICE_SET = 0x04;
    constexpr uint8_t DCP_SERVICE_IDENTIFY = 0x05;
    constexpr uint8_t DCP_SERVICE_HELLO = 0x06;

    // DCP Service Types
    constexpr uint8_t DCP_REQUEST = 0x00;
    constexpr uint8_t DCP_RESPONSE_SUCCESS = 0x01;
    constexpr uint8_t DCP_RESPONSE_UNSUPPORTED = 0x05;

    // DCP Options
    constexpr uint8_t DCP_OPT_IP = 0x01;
    constexpr uint8_t DCP_OPT_DEVICE = 0x02;
    constexpr uint8_t DCP_OPT_DHCP = 0x03;
    constexpr uint8_t DCP_OPT_CONTROL = 0x05;
    constexpr uint8_t DCP_OPT_DEVICEINITIATIVE = 0x06;

    // DCP Suboptions (Device)
    constexpr uint8_t DCP_SUB_DEV_TYPEOFSTATION = 0x01;  // TypeOfStation
    constexpr uint8_t DCP_SUB_DEV_NAMEOFSTATION = 0x02;
    constexpr uint8_t DCP_SUB_DEV_ID = 0x03;             // VendorID + DeviceID
    constexpr uint8_t DCP_SUB_DEV_ROLE = 0x04;
    constexpr uint8_t DCP_SUB_DEV_OPTIONS = 0x05;
    constexpr uint8_t DCP_SUB_DEV_SIGNATURE = 0x06;       // Vendor specific / signature blob

    // DCP Suboptions (IP)
    constexpr uint8_t DCP_SUB_IP_MAC = 0x01;
    constexpr uint8_t DCP_SUB_IP_PARAMETER = 0x02;       // IP, Netmask, Gateway
    constexpr uint8_t DCP_SUB_IP_FULLIP = 0x03;

    // DCP Suboptions (Control)
    constexpr uint8_t DCP_SUB_CONTROL_ALIAS = 0x01;
    constexpr uint8_t DCP_SUB_CONTROL_DEVICEINIT = 0x03;
    constexpr uint8_t DCP_SUB_CONTROL_SIGNATURE = 0x05;

    // Multicast MAC for Identify-All
    constexpr uint8_t DCP_MULTICAST_MAC[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};

    // Security Classes
    constexpr uint8_t SECURITY_CLASS_NONE = 0;
    constexpr uint8_t SECURITY_CLASS_1 = 1;              // Basic integrity
    constexpr uint8_t SECURITY_CLASS_2 = 2;              // Integrity + confidentiality
}

// PROFINET Device Information (NO std::string - only fixed char arrays!)
struct PROFINETDeviceInfo {
    char name_of_station[128];    // Device name (e.g., "plc-01")
    char type_of_station[64];     // Device type (e.g., "SIMATIC S7-1500")
    char vendor_name[64];         // Vendor name
    char order_id[32];            // Order/Article number
    char serial_number[32];       // Serial number
    char alias_name[128];         // AliasName (DCP Control/AliasName)

    uint8_t mac_address[6];       // MAC address
    uint32_t ip_address;          // IP address (network byte order)
    uint32_t netmask;             // Netmask
    uint32_t gateway;             // Gateway

    uint16_t vendor_id;           // Vendor ID (e.g., 0x002A for Siemens)
    uint16_t device_id;           // Device ID

    uint8_t device_role;          // 0=IO-Device, 1=IO-Controller, 2=IO-Supervisor
    uint8_t security_class;       // Security class (0, 1, 2)

    bool ip_is_dhcp;              // IP assigned via DHCP
    bool supports_legacy;         // Supports legacy protocols (insecure)
    bool is_configured;           // Device is configured
    bool is_default_name;         // Uses default/generic name
    uint16_t device_options;      // Raw device options bitmask
    bool has_signature;           // Signature block advertised
    bool signature_valid;         // Signature status from qualifier/hash
    uint32_t signature_hash;      // Hash of signature payload for consistency checks
    uint16_t signature_length;    // Length of signature payload
    bool has_sync_status;         // PTCP/Sync status reported
    bool sync_locked;             // Device reports synchronized
    bool supports_profidrive;
    bool supports_profisafe;

    // Minimal raw DCP block summary (helps map vendor-specific/unknown blocks without log spam).
    // Stored only for the last Identify response we parsed for this device.
    struct DcpBlockMini {
        uint8_t option = 0;
        uint8_t suboption = 0;
        uint16_t qualifier = 0;
        uint16_t payload_len = 0;
        uint32_t payload_hash = 0;
        uint8_t preview[8] = {0};
    };
    uint8_t dcp_blocks_count = 0;
    DcpBlockMini dcp_blocks[8];

    PROFINETDeviceInfo() : ip_address(0), netmask(0), gateway(0),
                           vendor_id(0), device_id(0), device_role(0),
                           security_class(PROFINET::SECURITY_CLASS_NONE),
                           ip_is_dhcp(false), supports_legacy(false),
                           is_configured(false), is_default_name(false),
                           device_options(0), has_signature(false),
                           signature_valid(false), signature_hash(0),
                           signature_length(0), has_sync_status(false),
                           sync_locked(false), supports_profidrive(false),
                           supports_profisafe(false) {
        name_of_station[0] = '\0';
        type_of_station[0] = '\0';
        vendor_name[0] = '\0';
        order_id[0] = '\0';
        serial_number[0] = '\0';
        alias_name[0] = '\0';
        memset(mac_address, 0, 6);
        dcp_blocks_count = 0;
    }
};

// PROFINETPlugin: DCP Identify (active) + passive parser for PN-DCP (EtherType 0x8892)
// Active discovery uses raw Ethernet to send a multicast DCP Identify-All request to 01:0E:CF:00:00:00
// Requires an Ethernet raw-tx helper provided by the platform layer.
// Forward declaration - actual interface defined in network/ethernet_tx_if.h
class EthernetTxIf;

class PROFINETPlugin : public BasePlugin {
public:
    explicit PROFINETPlugin(EthernetTxIf* eth = nullptr);

    bool initialize(ConfigurationManager* cfg, ReportingEngine* rep) override;
    void shutdown() override;

    // Active network-wide discovery (Identify-All). Returns a JSON array with devices found.
    bool identifyAll(std::string& out_json, uint32_t timeout_ms = 1500);

    // BasePlugin implementation
    std::string doVulnerabilityScan(const std::string& target) override;
    bool doVulnerabilityScanPSRAM(const psram_string& target, psram_string& out_report) override;
    std::string doNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms = 5000) override;
    bool doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                 uint32_t timeout_ms,
                                 psram_string& out_report) override;

    // Network presence tracking API implementation
    NetworkPresenceTracker& getNetworkPresenceTracker() override { return network_presence_tracker_; }
    const NetworkPresenceTracker& getNetworkPresenceTracker() const override { return network_presence_tracker_; }
    bool isTargetPacket(const NetworkPacket& packet) override;

    // Protocol-specific packet analysis
    bool isPacketWriter(const NetworkPacket& pkt) const override;

    // Passive analysis from capture engine
    bool doPacketAnalysis(const NetworkPacket& pkt) override;
    void loadIDSRules(const std::string& rules_json) override;

    // Flow Management API (BasePlugin overrides)
    bool buildFlowKey(const NetworkPacket& packet, FlowKey& key) override;
    bool classifyPacketOperation(const NetworkPacket& packet,
                                 psram_string& operation_type,
                                 psram_string& operation_details,
                                 bool& is_error) override;
    void updateProtocolState(const NetworkPacket& packet, FlowData& flow) override;
    void assignFlowLabel(FlowData& flow) override;

    // Fuzzing API
    bool generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) override;
    bool fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) override;
    FuzzResult execute(const FuzzJob& job, const FuzzTestCase& tc,
                      std::string& sent_hex, std::string& received_hex,
                      std::string& status_details) override;

    // Advanced fuzzing
    bool generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out);

    // Port monitoring (PROFINET uses direct Ethernet, no specific TCP/UDP ports)
    std::vector<uint16_t> getMonitoredPorts() const override { return {}; }

    ProtocolType protocol() const override { return ProtocolType::PROFINET; }
    const char* name()  const override { return "PROFINETPlugin"; }
    const char* version() const override { return "0.1"; }

    struct RtChannelSnapshot {
        uint16_t frame_id = 0;
        bool is_irt = false;
        uint32_t samples = 0;
        uint32_t missed_cycles = 0;
        bool jitter_alerted = false;
        uint64_t last_ts_ms = 0;
        uint8_t last_cycle = 0;
        psram_string mac;
    };

    struct SyncDeviceSnapshot {
        psram_string mac;
        bool locked = false;
        uint8_t valid_streak = 0;
        uint8_t invalid_streak = 0;
    };

    struct RealtimeSummary {
        uint32_t total_channels = 0;
        uint32_t irt_channels = 0;
        uint32_t jitter_alerts = 0;
        uint32_t total_missed_cycles = 0;
        uint32_t sync_locked_devices = 0;
        uint32_t sync_unlocked_devices = 0;
        psram_vector<RtChannelSnapshot> channels;
        psram_vector<SyncDeviceSnapshot> sync_devices;
    };

    void getRealtimeSummary(RealtimeSummary& out) const;

private:
    // Configuration structure
    struct Config {
        bool enabled = true;
        psram_string dcp_multicast = PSRAMUtils::createPSRAMString("01:0e:cf:00:00:00");
        bool enable_topology_discovery = true;
        uint32_t discovery_timeout_ms = 3000;

        // Security assessment flags
        bool check_default_names = true;
        bool check_security_class = true;
        bool check_unencrypted_comm = true;
        psram_string_vector default_name_patterns; // filled in initialize()

        // IDS settings
        bool detect_dcp_spoofing = true;
    bool detect_config_changes = true;
        bool detect_topology_changes = true;
        uint32_t max_devices_per_sec = 10;
    } config_;

    EthernetTxIf* eth_ = nullptr;
    std::atomic<uint64_t> ids_events_{0}, scans_{0};

    // Active DCP discovery window: identifyAll() sends the request and collects Identify responses
    // observed by doPacketAnalysis() during the timeout.
    mutable std::mutex discovery_mutex_;
    std::atomic<bool> discovery_active_{false};
    psram_set<uint64_t> discovery_keys_;
    psram_vector<PROFINETDeviceInfo> discovery_devices_;

    // Diagnostics for active discovery window (to debug empty results).
    std::atomic<uint32_t> discovery_rx_frames_{0};
    std::atomic<uint32_t> discovery_rx_identify_{0};
    std::atomic<uint32_t> discovery_parse_ok_{0};
    std::atomic<uint32_t> discovery_parse_fail_{0};
    std::atomic<uint16_t> discovery_last_frame_id_{0};
    psram_string discovery_last_detail_json_{PSRAMAllocator<char>{}};

    struct LldpInfo {
        char chassis_id[64] {0};
        char port_id[64] {0};
        char port_desc[64] {0};
        char system_name[64] {0};
        char system_desc[128] {0};
        char mgmt_addr[64] {0};
        uint16_t ttl = 0;
        bool has_profinet_org = false;
        uint8_t profinet_subtype = 0;
        uint32_t profinet_payload_hash = 0;
        uint64_t last_seen_ms = 0;
    };
    mutable std::mutex topo_mutex_;
    psram_map<uint64_t, LldpInfo> lldp_by_mac_;

    // Security assessment helpers
    bool isDefaultDeviceName(const std::string& name) const;
    bool hasSecurityClass(const std::string& device_info) const;

    // Builders & parsers
    bool buildDcpIdentifyAll(psram_vector<uint8_t>& out_frame);
    static bool parseDcpResponse(const uint8_t* eth, size_t len, psram_string& out_json_one);

    // --- Enhanced DCP Discovery Methods (Phase 4) ---
    bool sendDcpIdentifyAll(uint32_t timeout_ms, std::vector<PROFINETDeviceInfo>& devices);
    bool parseDcpIdentifyResponse(const uint8_t* dcp_data, size_t len, PROFINETDeviceInfo& dev_info);
    bool buildDeviceInfoJSON(const PROFINETDeviceInfo& dev_info, psram_string& out_json);
    void handleLldpFrame(const NetworkPacket& pkt);

    // --- Vulnerability Check Methods (Phase 5) ---
    bool checkDefaultDeviceName(const PROFINETDeviceInfo& dev_info, psram_string& finding);
    bool checkSecurityClass(const PROFINETDeviceInfo& dev_info, psram_string& finding);
    bool checkUnencryptedComm(const PROFINETDeviceInfo& dev_info, psram_string& finding);
    bool checkDigitalSignature(const PROFINETDeviceInfo& dev_info, psram_string& finding);

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
    static const char* vendorIdToName(uint16_t vendor_id);
    static const char* deviceRoleToString(uint8_t role);

    // Writers tracking for this protocol
    NetworkPresenceTracker network_presence_tracker_;

    std::string legacyDoVulnerabilityScan(const std::string& target);
    std::string legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms);

    // --- Real-Time monitoring helpers ---
    struct RtChannelState {
        uint64_t last_ts_ms = 0;
        uint8_t last_cycle = 0;
        uint32_t samples = 0;
        uint32_t missed_cycles = 0;
        bool is_irt = false;
        bool jitter_alerted = false;
    };

    struct SyncState {
        uint8_t valid_streak = 0;
        uint8_t invalid_streak = 0;
        bool locked = false;
        uint64_t last_alert_ms = 0;
    };

    static uint64_t macToKey(const uint8_t mac[6]);
    bool evaluateDeviceSignature(const PROFINETDeviceInfo& dev_info, const uint8_t responder_mac[6], const NetworkPacket& pkt);
    bool updateSyncStateFromIdentify(const PROFINETDeviceInfo& dev_info, const uint8_t responder_mac[6], const NetworkPacket& pkt);
    bool processRtFrame(const NetworkPacket& pkt, uint16_t frame_id, bool is_irt);
    bool trackSyncFromRt(uint64_t mac_key, bool data_valid, const NetworkPacket& pkt, bool is_irt);
    static psram_string macKeyToString(uint64_t mac_key);

    std::unordered_map<uint64_t, RtChannelState> rt_channels_;
    std::unordered_map<uint64_t, SyncState> sync_states_;
    std::unordered_map<uint64_t, uint32_t> signature_hash_cache_;
    std::unordered_set<uint64_t> signature_missing_alerted_;
    std::unordered_set<uint64_t> signature_mismatch_alerted_;
    std::unordered_set<uint64_t> signature_invalid_alerted_;
    std::unordered_set<uint64_t> sync_loss_alerted_;
    std::unordered_set<uint64_t> default_name_reported_;
    std::unordered_set<uint64_t> security_class_reported_;
    std::unordered_set<uint64_t> unencrypted_reported_;
    std::unordered_set<uint64_t> profidrive_reported_;
    std::unordered_set<uint64_t> profisafe_reported_;
    mutable std::mutex rt_mutex_;
    mutable std::mutex sync_mutex_;
};
