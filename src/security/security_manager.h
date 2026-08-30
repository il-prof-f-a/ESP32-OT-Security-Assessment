#pragma once
#include <string>
#include <vector>
#include <atomic>

#include "../core/configuration_manager.h"
#include "../core/psram_allocator.h"
#include "../core/types.h"
#include "security_policy.h"
#include <optional>
#include <cstdint>
#include <mutex>
#include <string>

extern "C" {
    #include "esp_system.h"
    #include "esp_efuse.h"
    #include "esp_efuse_table.h"
    #include "esp_mac.h"
    #include "esp_ota_ops.h"
    #include "mbedtls/sha256.h"
    #include "mbedtls/aes.h"
}

// API key structure in PSRAM
struct ApiKeyEntry {
    psram_string id;           // UUID of the key
    psram_string label;        // Descriptive label
    psram_string hash;         // SHA-256 hash of the token
    uint64_t created_ms;       // Creation timestamp
    uint64_t last_used_ms;     // Timestamp of last use
    bool enabled;              // Activation flag
    bool rotation_alert_sent;
    bool disable_alert_sent;

    ApiKeyEntry() {
        PSRAMAllocator<char> alloc;
        id = psram_string(alloc);
        label = psram_string(alloc);
        hash = psram_string(alloc);
        created_ms = 0;
        last_used_ms = 0;
        enabled = true;
        rotation_alert_sent = false;
        disable_alert_sent = false;
    }
};

struct SecurityEventLog {
    psram_string id;
    psram_string type;
    psram_string severity;
    psram_string summary;
    psram_string detail_json;
    psram_string acked_by;
    uint64_t timestamp_ms;
    uint64_t ack_timestamp_ms;
    bool acknowledged;

    SecurityEventLog()
        : timestamp_ms(0)
        , ack_timestamp_ms(0)
        , acknowledged(false) {}
};

struct ApiKeyMetrics {
    uint32_t total = 0;
    uint32_t enabled = 0;
    uint32_t rotation_required = 0;
    uint32_t disabled_pending_rotation = 0;
    uint64_t newest_created_ms = 0;
    uint64_t oldest_created_ms = 0;
};

struct OffensiveTestingDecision {
    bool allowed = false;
    bool software_enabled = false;
    bool gpio_asserted = false;
    bool gpio_required = false;
    const char* reason = "disabled_in_security_config";
    const char* source = "default";
};

class SecurityManager {
public:
    // Software toggle persisted via /api/security/config (NVS key: security:fuzzing_allowed).
    bool isFuzzingAllowedConfig() const { return fuzzing_allowed_; }
    void setFuzzingAllowed(bool v) { fuzzing_allowed_ = v; }

    // Effective permission used by runtime components (e.g. FuzzingEngine).
    // This is config AND (optional) GPIO physical switch gate.
    bool isFuzzingAllowed() const;
    const char* getFuzzingBlockReason() const;
    OffensiveTestingDecision evaluateOffensiveTesting() const;
    // True only for an explicitly authorized development build. Public/release
    // firmware keeps the physical interlock mandatory regardless of NVS/config.
    bool isOffensiveInterlockBypassAuthorized() const;
    const char* getOffensiveTestingPolicySource() const { return offensive_policy_source_.c_str(); }
    bool loadOffensiveTestingPolicyFromStorage();
    bool persistOffensiveTestingPolicy();
    void getOffensiveTestingConfigSnapshot(OffensiveTestingConfig& out) const;

    // Optional physical interlock for unsafe fuzzing.
    // pull_mode: 0=none, 1=pullup, 2=pulldown
    bool configureFuzzingGpioGate(bool enabled,
                                  int gpio_num,
                                  bool active_high,
                                  int pull_mode,
                                  bool require_gate);
    bool isFuzzingGpioGateEnabled() const { return fuzzing_gpio_gate_enabled_; }
    bool isFuzzingGpioGateRequired() const { return fuzzing_gpio_gate_required_; }
    int getFuzzingGpioNum() const { return fuzzing_gpio_num_; }
    bool isFuzzingGpioActiveHigh() const { return fuzzing_gpio_active_high_; }
    int getFuzzingGpioPullMode() const { return fuzzing_gpio_pull_mode_; }
    bool readFuzzingGpioGateState() const;
    SecurityManager() = default;
    ~SecurityManager() = default;

    bool initialize(const SecurityConfig& cfg);
    void shutdown();

    // Status checks
    bool isSecureBootEnabled() const;
    bool isFlashEncryptionEnabled() const;

    // Firmware integrity helpers
    std::string getRunningAppSHA256() const;
    bool setExpectedFirmwareHash(const std::string& hex); // store in NVS for comparison
    bool verifyFirmwareHash() const; // compare running hash vs expected

    // Certificates (CA / client)
    bool loadDefaultCA(std::string& out_pem) const; // /data/certs/ca_bundle.pem
    bool readFile(const std::string& path, std::string& out) const;

    // Additional methods
    const SecurityPolicy& getPolicy() const { return policy_; }
    void setPolicy(const SecurityPolicy& p) { policy_ = p; }
    bool loadPolicyFromConfig(const std::string& json);

    // mitigation: craft TCP RST on observed packet (requires raw Ethernet frame)
    bool mitigateTcpByRst(const uint8_t* eth_frame, size_t len, class EthernetTxIf* tx) const;
    bool mitigateTcpByRst(const NetworkPacket& packet, class EthernetTxIf* tx) const;

    // API Authentication methods (stub implementations)
    bool verifyApiKey(const psram_string& token) const;
    bool verifyApiKey(const char* token) const;
    bool verifyApiKey(const std::string& token) const;
    bool verifyAdminPassword(const psram_string& password) const;
    bool verifyAdminPassword(const char* password) const;
    bool verifyAdminPassword(const std::string& password) const;
    std::vector<std::pair<std::string, std::string>> listApiKeysMasked() const;
    std::string createApiKey(const psram_string& label);
    std::string createApiKey(const char* label);
    std::string createApiKey(const std::string& label);
    bool revokeApiKey(const psram_string& id);
    bool revokeApiKey(const char* id);
    bool revokeApiKey(const std::string& id);
    bool saveToConfig(class ConfigurationManager* cfg);
    void getApiKeyMetrics(ApiKeyMetrics& out_metrics) const;
    void getSecurityEvents(psram_vector<SecurityEventLog>& out_events) const;
    bool acknowledgeSecurityEvent(const psram_string& event_id,
                                  const psram_string& actor,
                                  bool acknowledged);
    bool isTemporaryAdminCredentialActive() const { return false; }
    void setAlertPolicy(const SecurityAlertPolicy& policy);
    void getAlertPolicy(SecurityAlertPolicy& out_policy) const;
    void getSecurityConfigSnapshot(SecurityConfig& out_cfg) const;

private:
    // Helper methods
    psram_string generateSecureToken() const;
    psram_string computeSHA256(const psram_string& data) const;
    bool constantTimeCompare(const psram_string& a, const psram_string& b) const;
    bool loadApiKeysFromNVS();
    bool saveApiKeysToNVS();
    psram_string generateUUID() const;
    bool loadAdminPasswordHash(psram_string& hash_out);
    bool storeAdminPasswordHash(const psram_string& hash);
    void raiseSecurityFault(const char* feature, const char* recommendation);
    void emitApiKeySecurityEvent(const ApiKeyEntry& entry,
                                 const char* event_type,
                                 uint64_t age_ms,
                                 bool disabled) const;
    bool updateApiKeyAgeState(ApiKeyEntry& entry, uint64_t age_ms) const;
    void auditApiKeysForRotation();
    void scheduleRotationForKey(const ApiKeyEntry& entry) const;
    void cancelRotationForKey(const psram_string& key_id) const;
    void enforceMandatoryInterlockForBuild();
    void recordSecurityEvent(const char* type,
                             const char* severity,
                             const psram_string& summary,
                             const psram_string& detail_json);
    void dispatchSecurityEvent(const psram_string& type,
                               const psram_string& payload,
                               const char* severity,
                               uint64_t timestamp_ms,
                               const SecurityAlertPolicy& policy);

    bool fuzzing_allowed_ = false;

    // Physical gate defaults to disabled. When enabled+required, fuzzing is only allowed if the GPIO is "ON".
    bool fuzzing_gpio_gate_enabled_ = false;
    bool fuzzing_gpio_gate_required_ = false;
    int fuzzing_gpio_num_ = -1;
    bool fuzzing_gpio_active_high_ = false; // default active-low (typical switch to GND with pull-up)
    int fuzzing_gpio_pull_mode_ = 1;        // default pull-up
    std::string offensive_policy_source_ = "default";

    SecurityConfig cfg_{};
    SecurityPolicy policy_{};
    SecurityAlertPolicy alert_policy_{};

    // API Keys storage in PSRAM
    psram_vector<ApiKeyEntry> api_keys_;
    mutable std::mutex api_keys_mutex_;
    psram_string master_key_;  // Master key for encryption (derived from chip ID)
    psram_string admin_password_hash_;
    bool admin_hash_dirty_ = false;
    bool security_gap_detected_ = false;
    static constexpr size_t kMaxSecurityEvents = 16;
    psram_vector<SecurityEventLog> security_events_;
    mutable std::mutex security_events_mutex_;
    mutable std::mutex alert_policy_mutex_;
    uint64_t last_email_alert_ms_ = 0;
    uint64_t last_webhook_alert_ms_ = 0;
};
