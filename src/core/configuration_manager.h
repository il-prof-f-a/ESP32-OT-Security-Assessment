#pragma once
#include <string>
#include <map>
#include <vector>
#include "types.h"
#include "logging_system.h"
#include "async_storage_engine.h"
#include "psram_allocator.h"
extern "C" {
    #include "nvs_flash.h"
    #include "nvs.h"
    #include "cJSON.h"
}
#include <cstring>

// No forward declaration needed - using AsyncStorage::Global

struct SecurityAlertPolicy {
    struct EmailPolicy {
        bool enabled = false;
        psram_string_vector recipients;
        psram_string subject = PSRAMUtils::createPSRAMString("Security Alert");
        uint32_t throttle_minutes = 5;

        EmailPolicy() : recipients(PSRAMAllocator<psram_string>()) {}
    } email;

    struct WebhookPolicy {
        bool enabled = false;
        psram_string url = PSRAMUtils::createPSRAMString("");
        psram_string token = PSRAMUtils::createPSRAMString("");
    } webhook;

    struct GpioPolicy {
        bool enabled = false;
        uint8_t critical_pin = 15;
        uint8_t warning_pin = 4;
        uint8_t buzzer_pin = 14;
    } gpio;
};

struct SecurityConfig {
    psram_string admin_password = PSRAMUtils::createPSRAMString("");
    psram_string_map api_keys;
    bool secure_boot = false;
    bool flash_encryption = false;
    bool certificate_validation = true;
    bool opcua_enforce_security = true;
    SecurityAlertPolicy alert_policy{};
};

struct NetworkConfig {
    bool eth_promiscuous = true;
    bool wifi_enabled = false;
    psram_string wifi_ssid;
    psram_string wifi_password;
    // Ethernet config
    bool eth_enabled = true;
    bool eth_dhcp = true;
    psram_string eth_ip;
    psram_string eth_gateway;
    psram_string eth_netmask;
    // WiFi config
    bool wifi_dhcp = true;
    psram_string wifi_ip;
    psram_string wifi_gateway;
    psram_string wifi_netmask;
    // DNS configuration (for both WiFi and Ethernet)
    psram_string dns_primary;     // Primary DNS server (e.g., "8.8.8.8")
    psram_string dns_secondary;   // Secondary DNS server (e.g., "8.8.4.4")
    // Time synchronization configuration
    psram_string time_sync = PSRAMUtils::createPSRAMString("ntp");    // "ntp" or "http"
    psram_string http_time_sync;  // HTTP time API URL (e.g., worldtimeapi.org)
    // NTP configuration (legacy, used when time_sync = "ntp")
    psram_string ntp_primary;     // Primary NTP server (e.g., "pool.ntp.org")
    psram_string ntp_secondary;   // Secondary NTP server (e.g., "time.nist.gov")
    psram_string ntp_tertiary;    // Tertiary NTP server (e.g., local server)
};

struct IDSConfig {
    bool enabled = true;
    uint32_t max_per_sec_modbus = 50;
    uint32_t max_per_sec_s7 = 40;
    uint32_t max_per_sec_enip = 60;
    uint32_t max_per_sec_pn = 40;
    uint32_t max_per_sec_opcua = 30;
    uint32_t replay_window_ms = 5000;
};

struct IDSAnomalyConfig {
    float flooding_pps_threshold = 750.0f;
    float requests_per_second_threshold = 250.0f;
    float request_response_high_ratio = 1.6f;
    float request_response_low_ratio = 0.45f;
    float malformed_packets_normalizer = 5.0f;
    uint32_t reactive_fuzzing_cooldown_ms = 15U * 60U * 1000U;   // 15 minutes
    uint32_t reactive_fuzzing_retention_ms = 60U * 60U * 1000U;  // 60 minutes
};

// Legacy WritersConfig - keep for backward compatibility
struct WritersConfig {
    bool enabled = true;
    bool alert_unauthorized_writes = true;
    bool track_all_senders = true;
    uint32_t cleanup_interval_ms = 300000;
    uint32_t inactive_sender_timeout_ms = 3600000;
    psram_string_vector allowed_writers; // Format: ip1;ip2;mac1;ip3
    // New IDS consolidated fields
    psram_string_vector allowed_ips;
    psram_string_vector allowed_macs;
};

// Advanced NetworkPresence configuration with learning system
struct NetworkPresenceConfig {
    bool enabled = true;
    bool learning_mode = true;                    // Enable automatic device learning
    bool alert_unauthorized_writes = true;
    bool track_all_traffic = true;              // Track reads + writes

    // Cleanup and maintenance timing
    uint32_t cleanup_interval_ms = 300000;       // 5 minutes
    uint32_t inactive_device_timeout_ms = 3600000; // 1 hour inactive timeout

    // Learning system parameters
    uint32_t activation_delay_minutes = 1;       // Wait 3 min before considering device continuously present
    uint32_t retention_days = 30;                // Remove learned devices after 30 days of inactivity
    double trust_threshold_score = 0.75;         // Minimum score for auto-promotion to trusted
    double min_observation_period_hours = 0.067; // Observe device for ~4 minutes before auto-trust

    // Scoring weights
    double continuity_weight = 0.4;              // Weight for continuous presence
    double diversity_weight = 0.3;               // Weight for protocol/port diversity
    double frequency_weight = 0.3;               // Weight for communication frequency

    // Persistent storage
    bool enable_persistent_learning = true;      // Save learned devices to NVS
    uint32_t storage_sync_interval_ms = 900000;  // Sync to NVS every 15 minutes

    // Static whitelist (backward compatibility)
    psram_string_vector whitelisted_devices; // Format: ip1;ip2;mac1;ip3
};

struct WatchdogConfig {
    bool enabled = true;
    uint32_t timeout_seconds = 120;
    bool panic_on_timeout = true;
    bool monitor_idle_cores = false;
};

// GPIO Reporter Configuration (now inside reporting section)
struct GpioReportingConfig {
    bool enabled = true;                     // Enable/disable entire GPIO reporter
    psram_string format = PSRAMUtils::createPSRAMString("JSON");
    psram_string verbosity = PSRAMUtils::createPSRAMString("REPORTS_ONLY");

    // GPIO Pin Configuration
    struct {
        uint8_t led_critical = 2;    // Red LED - GPIO2
        uint8_t led_warning = 4;     // Yellow LED - GPIO4
        uint8_t led_info = 5;        // Green LED - GPIO5
        uint8_t led_success = 18;    // Blue LED - GPIO18
        uint8_t buzzer = 19;         // Buzzer - GPIO19
        uint8_t btn_acknowledge = 0;     // Boot button - GPIO0
        uint8_t btn_reset = 35;          // Reset button - GPIO35
        uint8_t btn_learning = 34;       // Learning enable button - GPIO34
        uint8_t btn_maintenance = 39;    // Maintenance mode button - GPIO39
    } pins;

    // Behavior Configuration
    struct {
        bool buzzer_enabled = true;              // Enable/disable buzzer
        uint32_t alert_duration_ms = 5000;       // How long to keep alert active
        uint32_t blink_interval_ms = 500;        // LED blink interval for active alerts
        uint32_t debounce_ms = 50;               // Button debounce time
    } behavior;

    // Filters
    struct {
        bool enabled = true;
        bool case_sensitive = false;
        psram_string_vector include;
        psram_string_vector exclude;
    } filters;
};

// Audit Manager Configuration (standalone section)
struct AuditManagerConfig {
    bool enabled = true;                     // Enable/disable audit manager

    // Logging Configuration
    struct {
        bool log_denied = true;                 // Log denied operations
        bool log_timeouts = true;               // Log timeout events
        bool log_ratelimits = true;             // Log rate limit events
        bool log_system_events = true;          // Log system audit events
        bool log_security_events = true;        // Log security events
        bool log_config_changes = true;         // Log configuration changes
    } logging;

    // Rate Limiting Configuration
    struct {
        uint32_t max_events_per_second = 50;    // Rate limiting for audit events
    } rate_limiting;

    // Filters
    struct {
        bool enabled = true;
        bool case_sensitive = false;
        psram_string_vector include;
        psram_string_vector exclude;
    } filters;
};


class ConfigurationManager {
public:
    // Configuration source tracking
    enum class ConfigSource {
        DEFAULT = 0,
        EMBEDDED = 1,
        FILESYSTEM = 2,
        WEB_INTERFACE = 3
    };

    explicit ConfigurationManager();
    ~ConfigurationManager();

    bool begin() { return load(); }
    bool initialize();
    bool loadDevConfigFromSource();

    // Memory-safe version that allocates JSON buffer in PSRAM
    char* getRawConfigInPSRAM(size_t* size_out) const {
        if (!size_out) return nullptr;

        const size_t json_size = raw_.size();
        *size_out = json_size;

        if (json_size == 0) return nullptr;

        // Allocate in PSRAM with DRAM fallback
        char* psram_buffer = (char*)heap_caps_malloc(json_size + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!psram_buffer) {
            // Fallback to DRAM only for small configs
            if (json_size < 4096) {
                psram_buffer = (char*)heap_caps_malloc(json_size + 1, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
            }
        }

        if (psram_buffer) {
            memcpy(psram_buffer, raw_.c_str(), json_size);
            psram_buffer[json_size] = '\0';
        }

        return psram_buffer;
    }

    bool saveConfigJSON(const psram_string& json);
    bool saveConfigJSON(const std::string& json) { return saveConfigJSON(PSRAMUtils::createPSRAMString(json.c_str())); }
    bool saveConfigJSON(const char* json) { return json ? saveConfigJSON(PSRAMUtils::createPSRAMString(json)) : false; }

    // Configuration metadata
    ConfigSource getConfigSource() const { return config_source_; }
    std::string getConfigSourceName() const;
    bool resetToEmbeddedConfig();

    // Config accessors
    DebugConfig getDebugConfig() const;
    SecurityConfig getSecurityConfig() const;
    NetworkConfig getNetworkConfig() const;
    IDSConfig getIDSConfig() const;
    IDSAnomalyConfig getIDSAnomalyConfig() const;
    WritersConfig getWritersConfig() const;
    NetworkPresenceConfig getNetworkPresenceConfig() const;
    WatchdogConfig getWatchdogConfig() const;
    AuditManagerConfig getAuditManagerConfig() const;
    GpioReportingConfig getGpioReportingConfig() const;
    psram_string_map getProtocolConfig(ProtocolType p) const;

    // PSRAM helpers: read simple paths without std::string
    bool getBoolAtPath(const char* path, bool* out) const;
    bool getStringAtPath(const char* path, char* out, size_t out_sz) const;

    // Optional feature flags read from JSON (features.<name> : bool)
    bool isFeatureEnabled(const char* name, bool default_value = false) const;

    // Config setters

    // Validation
    bool isValid() const { return validateConfig(); }

    // Configuration state
    bool isUserModified() const { return config_source_ == ConfigSource::WEB_INTERFACE; }

    // Static constants
    static const char* kNVS_NAMESPACE;
    static const char* kNVS_CRC_KEY;
    static const char* kCONFIG_PATH;
    static const char* kCONFIG_BAK;

private:
    // Using AsyncStorage::Global instead of StorageManager
    psram_string raw_ = PSRAMUtils::createPSRAMString("{}");
    cJSON* root_ = nullptr;
    DebugConfig debug_;
    SecurityConfig sec_;
    NetworkConfig net_;
    IDSConfig ids_;
    IDSAnomalyConfig ids_anomaly_;
    WritersConfig writers_;
    NetworkPresenceConfig network_presence_;
    WatchdogConfig watchdog_;
    GpioReportingConfig gpio_;

    bool load(){
        LOG_INFO("Config", "Attempting to load configuration from NVS");

        esp_err_t e = AsyncStorage::Global::nvsGet("cfg", "config_json", raw_);
        if (e == ESP_OK && !raw_.empty() && raw_.size() < (32*1024)) {
            LOG_INFOF("Config", "Found configuration in NVS, size: %u bytes", (unsigned)raw_.size());
            LOG_INFO("Config", "✅ Configuration loaded from NVS successfully");
        } else {
            LOG_WARNINGF("Config", "No valid configuration in NVS (error: %s, len: %u)",
                        esp_err_to_name(e), (unsigned)raw_.size());
        }

        bool success = (e == ESP_OK);
        LOG_INFOF("Config", "NVS load result: %s", success ? "SUCCESS" : "FAILED");
        return success;
    }
    bool save() {
        LOG_INFO("Config", "Attempting to save configuration to NVS");
        const size_t sz = raw_.length();
        LOG_INFOF("Config", "Configuration size: %u bytes", (unsigned)sz);

        // (Advice) Avoid putting very large JSON in NVS: it is a KV store, not a filesystem.
        // If it exceeds ~3-4 KB, consider keeping it on the filesystem and saving only CRC/version in NVS.
        if (sz > 4096) {
            LOG_WARNINGF("Config",
                "Config JSON is large (%u bytes). NVS is not ideal for big blobs; "
                "prefer filesystem + CRC/version in NVS.", (unsigned)sz);
        }

        esp_err_t e = AsyncStorage::Global::nvsSet("cfg", "config_json", raw_);
        if (e == ESP_OK) {
            LOG_INFO("Config", "✅ Configuration saved to NVS successfully");
        } else {
            LOG_ERRORF("Config", "Failed to save configuration to NVS: %s", esp_err_to_name(e));
        }

        const bool success = (e == ESP_OK);
        LOG_INFOF("Config", "NVS save result: %s", success ? "SUCCESS" : "FAILED");
        return success;
    }

    // Internal methods
    bool loadJSONFromFS();
    bool tryRecoveryFromBackup();
    bool loadOrCreateDefault();
    bool validateConfig() const;
    bool parseAndCache(cJSON* root);
    void mergeDefaultProtocolFields();
    uint32_t crc32(const uint8_t* data, size_t len) const;
    bool beginProvisionedConfigUpdate(bool& transaction_active);
    bool finishProvisionedConfigUpdate(uint32_t crc, bool transaction_active);


    bool saveConfigSourceToNVS(ConfigSource source);
    ConfigSource loadConfigSourceFromNVS();

    ConfigSource config_source_ = ConfigSource::DEFAULT;
};
