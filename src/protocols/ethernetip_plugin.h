#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

#include "base_plugin.h"
#include "../assessment/network_presence_tracker.h"
#include "../core/psram_allocator.h"

// EtherNet/IP (CIP over TCP/UDP) plugin:
// - Passive IDS on TCP/44818 and UDP/44818, UDP/2222
// - Active safe scan (ListIdentity over TCP) to fingerprint device (vendor, product, revision, serial, name)
// - No writes, no ForwardOpen (fuzzing left for later)
class EtherNetIPPlugin : public BasePlugin {
public:
    EtherNetIPPlugin();

    bool initialize(ConfigurationManager* cfg, ReportingEngine* rep) override;
    void shutdown() override;

    // Vulnerability scanner entrypoint (safe): ListIdentity over TCP to a specific target - now returns string report
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

    // IDS/packet path
    bool doPacketIDSAnalysisOfProtocol(const NetworkPacket& pkt) override;
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

    // Fuzzing API
    bool generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) override;
    bool fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) override;
    FuzzResult execute(const FuzzJob& job, const FuzzTestCase& tc,
                      std::string& sent_hex, std::string& received_hex,
                      std::string& status_details) override;

    // Advanced fuzzing
    bool generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out);

    // Port monitoring
    std::vector<uint16_t> getMonitoredPorts() const override { return {44818, 2222}; }


    // Optional: explicit call to run ListIdentity and get raw JSON
    bool activeListIdentity(const std::string& target, std::string& out_json);

    // UDP broadcast ListIdentity discovery across subnet; returns JSON array of identities
    bool activeBroadcastDiscovery(uint32_t timeout_ms, std::string& out_json);

private:
    // --- Encapsulation helpers (little-endian) ---
    static inline uint16_t le16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1]<<8)); }
    static inline uint32_t le32(const uint8_t* p) { return (uint32_t)(p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24)); }
    static inline void wr16le(uint8_t* p, uint16_t v) { p[0]=(uint8_t)(v&0xFF); p[1]=(uint8_t)(v>>8); }
    static inline void wr32le(uint8_t* p, uint32_t v) { p[0]=(uint8_t)(v&0xFF); p[1]=(uint8_t)((v>>8)&0xFF); p[2]=(uint8_t)((v>>16)&0xFF); p[3]=(uint8_t)((v>>24)&0xFF); }

    // Encapsulation
    // Build a bare Encapsulation header in buf: command, length, session, status=0, context=0, options=0
    static void buildEncapHeader(uint8_t* buf, uint16_t command, uint16_t length, uint32_t session);

    // Parse a ListIdentity response payload (encapsulation-specific data) into JSON (single item best-effort)
    static bool parseListIdentityPayload(const uint8_t* p, size_t len, std::string& out_json);
    static bool parseListIdentityPayloadPSRAM(const uint8_t* p, size_t len, psram_string& out_json);

    // Parse SendRRData -> CPF -> CIP service (best-effort, for IDS only)
    static bool parseSendRRDataForCIP(const uint8_t* encap_data, size_t encap_len,
                                      uint8_t& out_service_code, bool& out_is_response,
                                      uint16_t& cls, uint16_t& inst, uint16_t& attr);

    bool parseListServicesForSecurity(const uint8_t* payload, size_t length,
                                      bool& cip_security_found,
                                      psram_vector<psram_string>* descriptions = nullptr);
    bool analyzeIoDatagram(const NetworkPacket& pkt);

    // Writers tracking for this protocol
    NetworkPresenceTracker network_presence_tracker_;

    std::unordered_map<uint32_t, bool, std::hash<uint32_t>, std::equal_to<uint32_t>, PSRAMAllocator<std::pair<const uint32_t, bool>>> cip_security_status_;
    std::unordered_set<uint32_t, std::hash<uint32_t>, std::equal_to<uint32_t>, PSRAMAllocator<uint32_t>> io_without_security_reported_;
    std::unordered_map<uint64_t, uint16_t, std::hash<uint64_t>, std::equal_to<uint64_t>, PSRAMAllocator<std::pair<const uint64_t, uint16_t>>> io_run_idle_state_;
    std::unordered_map<uint32_t, uint32_t, std::hash<uint32_t>, std::equal_to<uint32_t>, PSRAMAllocator<std::pair<const uint32_t, uint32_t>>> session_handle_devices_;
    std::unordered_set<uint64_t, std::hash<uint64_t>, std::equal_to<uint64_t>, PSRAMAllocator<uint64_t>> session_register_nonzero_alerted_;
    std::unordered_set<uint64_t, std::hash<uint64_t>, std::equal_to<uint64_t>, PSRAMAllocator<uint64_t>> session_zero_response_alerted_;
    std::unordered_set<uint64_t, std::hash<uint64_t>, std::equal_to<uint64_t>, PSRAMAllocator<uint64_t>> session_unknown_usage_alerted_;

    std::string legacyDoVulnerabilityScan(const std::string& target);
    psram_string legacyDoVulnerabilityScan(const psram_string& target);
    bool activeListIdentityPSRAM(const psram_string& target, psram_string& out_json);
    std::string legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms);
};
