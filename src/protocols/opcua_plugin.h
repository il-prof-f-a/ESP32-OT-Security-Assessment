#pragma once
#include <set>
#include <mutex>
#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include "base_plugin.h"
#include "../core/configuration_manager.h"
#include "../assessment/network_presence_tracker.h"

struct OPCUAServer {
    std::string endpoint_url;
    std::string server_name;
    std::vector<std::string> security_policies;
    std::vector<std::string> security_modes;
    std::string server_certificate;
    std::string certificate_subject;
    std::string certificate_issuer;
    std::vector<std::string> certificate_issues;
    uint64_t certificate_not_before = 0;
    uint64_t certificate_not_after = 0;
    bool anonymous_login_allowed = false;
    bool encryption_available = false;
    bool certificate_present = false;
    bool certificate_valid = false;
    bool certificate_self_signed = false;
    bool certificate_expired = false;
    bool certificate_is_ca = false;
    std::vector<std::string> vulnerabilities;
};

class ConfigurationManager;
class ReportingEngine;
struct UA_Client {
    int socket_fd = -1;
    std::string endpoint_url;
    bool connected = false;
};

class OPCUAPlugin : public BasePlugin {
public:
    static constexpr uint16_t OPCUA_PORT = 4840;

    OPCUAPlugin();
    ~OPCUAPlugin() override;

    bool initialize(ConfigurationManager* config, ReportingEngine* reporting) override;
    void shutdown() override;

    std::string doVulnerabilityScan(const std::string& target) override;
    bool doVulnerabilityScanPSRAM(const psram_string& target, psram_string& out_report) override;
    std::string doNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms = 5000) override;
    bool doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                 uint32_t timeout_ms,
                                 psram_string& out_report) override;
    bool doPacketAnalysis(const NetworkPacket& packet) override;
    bool isTargetPacket(const NetworkPacket& packet) override;
    void loadIDSRules(const std::string& rules_json) override;
    bool isPacketWriter(const NetworkPacket& pkt) const override;

    // Flow Management API (BasePlugin overrides)
    bool buildFlowKey(const NetworkPacket& packet, FlowKey& key) override;
    bool classifyPacketOperation(const NetworkPacket& packet,
                                 psram_string& operation_type,
                                 psram_string& operation_details,
                                 bool& is_error) override;
    void updateProtocolState(const NetworkPacket& packet, FlowData& flow) override;
    void assignFlowLabel(FlowData& flow) override;

    // Network presence tracking API implementation
    NetworkPresenceTracker& getNetworkPresenceTracker() override { return network_presence_tracker_; }
    const NetworkPresenceTracker& getNetworkPresenceTracker() const override { return network_presence_tracker_; }


    // Fuzzing API
    bool generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) override;
    bool fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) override;
    FuzzResult execute(const FuzzJob& job, const FuzzTestCase& tc,
                      std::string& sent_hex, std::string& received_hex,
                      std::string& status_details) override;

    // Advanced fuzzing
    bool generateAttackSeeds(const FuzzJob& job, const std::string& attack_type, std::vector<FuzzTestCase>& out);

    // Port monitoring
    std::vector<uint16_t> getMonitoredPorts() const override { return {4840}; }

    // Active discovery for web API
    bool activeDiscover(const std::string& ip, uint16_t port, uint32_t timeout_ms);

private:
    bool initializeOPCUAClient();
    void shutdownOPCUAClient();
    bool connectToServer(const std::string& endpoint_url);
    void disconnectFromServer();

    bool discoverEndpoints(const std::string& server_url, OPCUAServer& server);
    bool testAnonymousConnection(const std::string& server_url);
    bool validateServerCertificate(const OPCUAServer& server);
    bool checkSecurityConfiguration(const OPCUAServer& server);
    void assessServerSecurity(OPCUAServer& server);
    void checkForDefaultConfiguration(OPCUAServer& server);

    bool parseOPCUAPacket(const NetworkPacket& packet, std::string& message_type,
                          uint32_t& secure_channel_id, uint32_t& sequence_number);
    void analyzeOPCUATraffic(const NetworkPacket& packet);
    bool isOPCUAHandshake(const NetworkPacket& packet);
    bool isBruteForceAttempt(uint32_t src_ipv4);
    void configureScan(const std::map<std::string,std::string>&) {}

    UA_Client* ua_client_ = nullptr;
    bool client_initialized_ = false;

    std::vector<OPCUAServer> discovered_servers_;
    std::mutex servers_mutex_;
    std::set<std::string> suspicious_endpoints_;
    uint32_t max_failed_connections_ = 10;
    uint64_t packets_analyzed_ = 0;
    uint64_t vulnerabilities_found_ = 0;
    bool enforce_secure_endpoints_ = true;
    bool require_certificate_validation_ = true;

    // Writers tracking for this protocol
    NetworkPresenceTracker network_presence_tracker_;

    std::string legacyDoVulnerabilityScan(const std::string& target);
    std::string legacyDoNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms);
};
