#pragma once
#include <string>
#include <cstdint>
#include <atomic>
#include <vector>
#include <mutex>
#include <condition_variable>

#include "../core/types.h"
#include "../core/psram_allocator.h"
#include "../assessment/flow_table.h"
#include "../assessment/flow_key.h"
#include "../assessment/flow_data.h"
#include "session_state_machine.h"

class ConfigurationManager;
class ReportingEngine;
class WritersTracker;
class NetworkPresenceTracker;
class SecurityManager;
class SandboxedPlugin;

// Forward declarations for fuzzing structures
struct FuzzTestCase;
struct FuzzJob;

// Fuzzing execution result codes
enum class FuzzResult {
    SUCCESS = 0,              // Test executed successfully and received valid response
    CONNECTION_FAILED = 1,    // Cannot connect to target
    TIMEOUT = 2,             // Connected but no response received
    EXCEPTION_RESPONSE = 3,   // Received protocol-level exception/error
    INVALID_RESPONSE = 4,     // Received malformed or unexpected response
    SOCKET_ERROR = 5,        // Socket creation or configuration failed
    SEND_FAILED = 6          // Failed to send test payload
};

class BasePlugin {
public:
    BasePlugin(const std::string& name, const std::string& version, ProtocolType type)
    : name_(name), version_(version), type_(type) {}
    virtual ~BasePlugin() = default;

    virtual bool initialize(ConfigurationManager* cfg, ReportingEngine* rep) {
        cfg_ = cfg; rep_ = rep;
        loadAllowedWritersFromConfig();
        return true;
    }
    virtual void shutdown() {}

    void setSecurityManager(SecurityManager* sec) { sec_ = sec; }

    // Network packet callback for real-time analysis (implemented at base level)
    virtual void onPacket(const NetworkPacket& pkt, bool bypassAuthorization = false) final;

    // Protocol-specific packet analysis is handled via doPacketAnalysis()
    // Base class enforces writers authorization via enforceWritersAuthorization()

    // Plugin-specific determination: is this packet a WRITE operation for this protocol?
    // Default false; plugins should override.
    virtual bool isPacketWriter(const NetworkPacket& pkt) const { (void)pkt; return false; }

    // Active scan API (legacy std::string, to be phased out)
    virtual std::string doVulnerabilityScan(const std::string& target) = 0;

    // Network discovery API - returns JSON with discovered devices/services (legacy)
    virtual std::string doNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms = 300000) = 0;

    // PSRAM-native active scan APIs (new). Default implementation bridges to legacy methods.
    virtual bool doVulnerabilityScanPSRAM(const psram_string& target, psram_string& out_report);
    virtual bool doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                         uint32_t timeout_ms,
                                         psram_string& out_report);
    bool doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                 psram_string& out_report) {
        return doNetworkDiscoveryPSRAM(target_network, 300000U, out_report);
    }

    // Writers tracking API - each protocol manages its own writers
    // Network presence tracking interface
    virtual NetworkPresenceTracker& getNetworkPresenceTracker() = 0;
    virtual const NetworkPresenceTracker& getNetworkPresenceTracker() const = 0;

    // Passive IDS API. The template method is final so every plugin, including
    // future plugins and sandbox wrappers, receives the same policy gates.
    virtual bool doPacketAnalysis(const NetworkPacket& packet) final;
    virtual bool isTargetPacket(const NetworkPacket& packet) = 0;

    // A discovery scope is per plugin instance/protocol. It is independent of
    // the IDS configuration and remains active while at least one scope lives.
    class DiscoveryScope {
    public:
        DiscoveryScope() = default;
        DiscoveryScope(const DiscoveryScope&) = delete;
        DiscoveryScope& operator=(const DiscoveryScope&) = delete;
        DiscoveryScope(DiscoveryScope&& other) noexcept;
        DiscoveryScope& operator=(DiscoveryScope&& other) noexcept;
        ~DiscoveryScope();
        explicit operator bool() const { return owner_ != nullptr; }
    private:
        friend class BasePlugin;
        explicit DiscoveryScope(BasePlugin* owner) : owner_(owner) {}
        BasePlugin* owner_ = nullptr;
    };

    DiscoveryScope beginDiscovery();
    bool isDiscoveryActive() const { return discovery_active_.load(std::memory_order_acquire); }

protected:
    // Template-method hooks. Protocols implement behavior only; policy stays
    // centralized in BasePlugin::doPacketAnalysis().
    virtual bool doPacketIDSAnalysisOfProtocol(const NetworkPacket& packet) = 0;
    virtual void processDiscoveryOfProtocol(const NetworkPacket& packet) {
        (void)packet;
    }
    virtual bool acceptsDiscoveryPacket(const NetworkPacket& packet) {
        return isTargetPacket(packet);
    }

public:
    virtual void loadIDSRules(const std::string& rules_json) { (void)rules_json; }
    virtual void loadIDSRulesPSRAM(const psram_string& rules_json);

    // ==================== FLOW MANAGEMENT API ====================

    /**
     * @brief Builds the protocol-specific flow key
     *
     * Each protocol implements this function to extract the identifiers
     * relevant to the packet (e.g., Modbus unit_id, S7 rack/slot, OPC UA channel_id)
     *
     * @param packet Network packet
     * @param key [out] Flow key to populate
     * @return true if the key was created successfully, false otherwise
     */
    virtual bool buildFlowKey(const NetworkPacket& packet, FlowKey& key) = 0;

    /**
     * @brief Classify the operation type from the packet
     *
     * Determine whether the packet contains READ, WRITE, CONTROL, ERROR, etc.
     *
     * @param packet Network packet
     * @param operation_type [out] Operation type (e.g., "READ", "WRITE")
     * @param operation_details [out] Details (e.g., "FC=0x03 addr=100")
     * @param is_error [out] true if it is an error response
     * @return true if classification succeeded, false if the packet cannot be analyzed
     */
    virtual bool classifyPacketOperation(const NetworkPacket& packet,
                                         psram_string& operation_type,
                                         psram_string& operation_details,
                                         bool& is_error) = 0;

    /**
     * @brief Update the flow's protocol state
     *
     * Called to update the flow's state machine based on the packet.
     * (es: INIT -> CONNECTING -> ESTABLISHED -> DATA_EXCHANGE)
     *
     * @param packet Network packet
     * @param flow Flow to update
     */
    virtual void updateProtocolState(const NetworkPacket& packet, FlowData& flow) = 0;

    /**
     * @brief Assign a label to the flow based on detected patterns
     *
     * Analyze the flow's metrics and history to assign appropriate labels
     * (es: READER, WRITER, SCANNER, FLOODING, SUSPICIOUS, etc.)
     *
     * @param flow Flow to classify
     */
    virtual void assignFlowLabel(FlowData& flow) = 0;

    /**
     * @brief Get a reference to the plugin's flow table
     *
     * @return Reference to the FlowTable
     */
    FlowTable& getFlowTable() { return flow_table_; }
    const FlowTable& getFlowTable() const { return flow_table_; }

    // Fuzzing API
    virtual bool generateSeedCorpus(const FuzzJob& job, std::vector<FuzzTestCase>& out) = 0;
    virtual bool fixup(const FuzzJob& job, const FuzzTestCase& in, FuzzTestCase& out) = 0;
    virtual FuzzResult execute(const FuzzJob& job, const FuzzTestCase& tc,
                              std::string& sent_hex, std::string& received_hex,
                              std::string& status_details) = 0;

    // Port monitoring for dynamic raw taps
    virtual std::vector<uint16_t> getMonitoredPorts() const = 0;

    // Plugin metadata (for compatibility with existing code)
    virtual ProtocolType protocol() const { return type_; }
    virtual const char* name() const { return name_.c_str(); }
    virtual const char* version() const { return version_.c_str(); }

    // Introspection
    const std::string& getName() const { return name_; }
    const std::string& getVersion() const { return version_; }
    ProtocolType getProtocolType() const { return type_; }
    uint64_t getEventsGenerated() const { return events_generated_.load(); }

    // Centralized target parsing: splits "ip:port" or "ip" format and uses protocol default port if not specified
    bool parseTarget(const std::string& target, std::string& ip, uint16_t& port) const;
    bool parseTarget(const psram_string& target, psram_string& ip, uint16_t& port) const;

    struct GeneralDiscoveryConfig {
        psram_string target;
        psram_string mode_label;
        // Compatibility field. Assessment sockets are always bound to ETH_DEF;
        // any other value is ignored to preserve the IT/OT boundary.
        psram_string bind_ifkey;
        bool ping_scan = true;
        bool port_scan = false;
        bool emit_progress_events = true;
        uint32_t per_host_timeout_ms = 500;
        uint32_t connect_timeout_ms = 400;
        uint32_t batch_size = 4;
        uint32_t batch_delay_ms = 250;
        uint32_t max_hosts = 512;
        uint32_t total_timeout_ms = 0;
        psram_vector<uint16_t> ports;
    };

    static std::string runGeneralDiscovery(const GeneralDiscoveryConfig& cfg,
                                           ReportingEngine* rep,
                                           ConfigurationManager* cfg_mgr);

protected:
    // ==================== FLOW TRACKING HELPERS ====================

    /**
     * @brief Track the packet in the flow management system
     *
     * Common method implemented in BasePlugin that:
     * 1. Builds the FlowKey by calling buildFlowKey()
     * 2. Gets or creates the flow in the FlowTable
     * 3. Updates the flow's metrics
     * 4. Classifies the operation by calling classifyPacketOperation()
     * 5. Adds the operation to the history
     * 6. Updates the state by calling updateProtocolState()
     * 7. Assigns a label by calling assignFlowLabel()
     *
     * Protocol IDS hooks may call this method for every packet they want to
     * track; the template method invokes those hooks only after policy gates.
     *
     * @param packet Network packet to track
     * @return true if tracking succeeded, false on error
     */
    bool trackPacketInFlow(const NetworkPacket& packet);

    /**
     * @brief Periodic cleanup of expired flows
     *
     * Called periodically (e.g., every minute) to remove
     * inactive flows from the table. Plugins can call it from a dedicated task
     * or from the protocol IDS hook itself.
     */
    void cleanupExpiredFlows();

    /**
     * @brief Access to the centralized state machine
     *
     * Plugins can use this method to register
     * protocol-specific callbacks for state management.
     *
     * @return Reference to the SessionStateMachine
     */
    SessionStateMachine& getSessionStateMachine() { return session_state_machine_; }

    // Helpers for reporting
    void reportVulnerability(const std::string& target,
                             const std::string& payload_json,
                             const std::string& extra = "",
                             LogLevel level = LogLevel::WARNING);
    void reportVulnerabilityPSRAM(const psram_string& target,
                                  const psram_string& payload_json,
                                  const psram_string& extra,
                                  LogLevel level = LogLevel::WARNING);
    inline void reportVulnerabilityPSRAM(const psram_string& target,
                                         const psram_string& payload_json,
                                         LogLevel level = LogLevel::WARNING) {
        reportVulnerabilityPSRAM(target, payload_json, psram_string{}, level);
    }

    void reportIntrusion(const NetworkPacket& pkt,
                         const std::string& payload_json,
                         LogLevel level = LogLevel::WARNING);
    void reportIntrusionPSRAM(const NetworkPacket& pkt,
                              const psram_string& payload_json,
                              LogLevel level = LogLevel::WARNING);

    ConfigurationManager* cfg_ = nullptr;
    ReportingEngine* rep_ = nullptr;
    SecurityManager* sec_ = nullptr;
    std::atomic<uint64_t> events_generated_{0};

    /**
     * Flow table for tracking sessions/flows (allocated in PSRAM)
     */
    FlowTable flow_table_;

    /**
     * Centralized session state machine (shared across all protocols)
     * Plugins can register protocol-specific callbacks for custom state transitions
     */
    SessionStateMachine session_state_machine_;

private:
    std::string name_;
    std::string version_;
    ProtocolType type_;

protected:
    // Allowed writers parsed from config for this plugin (stored in PSRAM)
    psram_vector<psram_string> allowed_writer_ips_;
    psram_vector<psram_string> allowed_writer_macs_;

    void loadAllowedWritersFromConfig();
    bool isWriterAuthorized(const std::string& src_ip, const std::string& src_mac) const;
    void enforceWritersAuthorization(const NetworkPacket& pkt, bool bypassAuthorization);

private:
    friend class SandboxedPlugin;
    bool isIdsAnalysisEnabled() const;
    bool beginDiscoveryPacket();
    void endDiscoveryPacket();
    void releaseDiscoveryScope();

    mutable std::mutex discovery_state_mutex_;
    mutable std::condition_variable discovery_state_cv_;
    uint32_t discovery_scope_count_ = 0;
    uint32_t discovery_inflight_ = 0;
    std::atomic<bool> discovery_active_{false};
};
