#pragma once
#include <cstdint>
#include <string>
#include <map>
#include <mutex>
#include <atomic>

extern "C" {
    #include "esp_http_server.h"
    #include "esp_https_server.h"  // For HTTPS support
    #include "esp_event.h"
    #include "esp_system.h"
    #include "esp_timer.h"
    #include "esp_netif.h"
}


#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "../core/psram_allocator.h"
#include "../provisioning/runtime_tls_credentials.h"

class ConfigurationManager;
class ReportingEngine;
class Logger;
class PluginManager;
class SecurityManager;
class EthernetManager;
class WiFiManager;
class VulnerabilityScanner;
class NetworkEngine;
class IntrusionDetectionGeneral;
class LogFileManager;
class DiscoveryManager;
class CronScheduler;
struct StaticJsonBuffer;

class WebServer {
public:
    WebServer() = default;
    ~WebServer();

    bool initialize(ConfigurationManager* cfg,
                           ReportingEngine* rep,
                           Logger* logger,
                           PluginManager* plugins,
                           IntrusionDetectionGeneral* ids,
                           EthernetManager* eth,
                           WiFiManager* wifi,
                           VulnerabilityScanner* scanner,
                           SecurityManager* sec,
                           NetworkEngine* net,
                           LogFileManager* log_mgr = nullptr);

    bool start(uint16_t port = 80);
    bool startOnInterface(uint16_t port, esp_netif_t* netif);
    void shutdown();

    static WebServer* instance() { return self_; }
    static const WebServer* instanceConst() { return self_; }

    EthernetManager* ethernet() const { return eth_; }
    WiFiManager* wifi() const { return wifi_; }
    PluginManager* plugins() const { return plugins_; }
    IntrusionDetectionGeneral* ids() const { return ids_; }
    LogFileManager* logFileManager() const { return log_file_manager_; }

    // New members for managing the WiFi connection
    std::string new_ssid_;
    std::string new_password_;
    esp_timer_handle_t wifi_connect_timer_ = nullptr;

    // Declaration of the method for the connection logic
    bool connectToWiFi();

    // IRAM defragmentation timer (triggered 2s after last dashboard API call)
    esp_timer_handle_t defrag_timer_ = nullptr;
    static void defrag_timer_callback(void* arg);
    void scheduleDefragmentation();
    void performDefragmentation();

    // New method to start the WebServer with a separate task
    bool startWithTask(uint16_t port, esp_netif_t* netif);

    // Declaration of the timer callback method as static
    static void wifi_connect_timer_callback(void* arg);

    // HTTPS support
    bool startHTTPS(uint16_t port = 443);
    void stopHTTPS();
    bool isHTTPSEnabled() const;

    // Internal setup
    void attach(ConfigurationManager* cfg, SecurityManager* sec, ReportingEngine* rep);
    // Late attachment for remaining dependencies when starting early
    void attachFull(PluginManager* plugins,
                    IntrusionDetectionGeneral* ids,
                    EthernetManager* eth,
                    WiFiManager* wifi,
                    VulnerabilityScanner* scanner,
                    NetworkEngine* net);

    // Helper methods for network transitions
    void disconnectAPClientsAsync();
    void stopAPAsync();
    void stopHTTPServer();
    void restartHTTPServer();
    bool persistWiFiConfig(const char* ssid, const char* password);

private:
    friend void webserver_httpd_monitor_note_request(httpd_req_t* req);
    friend void webserver_httpd_monitor_note_response(httpd_req_t* req, int status_code, const char* auth_status);

    static esp_err_t h_root(httpd_req_t* req);
    static esp_err_t h_status(httpd_req_t* req);
    static esp_err_t h_telemetry(httpd_req_t* req);
    static esp_err_t h_config_get(httpd_req_t* req);
    static esp_err_t h_config_post(httpd_req_t* req);
    static esp_err_t h_config_update(httpd_req_t* req);
    static esp_err_t h_config_reset_defaults(httpd_req_t* req);
    static esp_err_t h_reboot(httpd_req_t* req);
    static esp_err_t h_audit_status(httpd_req_t* req);
    static esp_err_t h_audit_metrics_get(httpd_req_t* req);
    static esp_err_t h_audit_events_get(httpd_req_t* req);
    static esp_err_t h_audit_events_delete(httpd_req_t* req);
    static esp_err_t h_audit_export_get(httpd_req_t* req);
    static esp_err_t h_audit_analytics_get(httpd_req_t* req);
    static esp_err_t h_redirect(httpd_req_t* req); // captive-like

    // Reporting queue REST
    static esp_err_t h_report_queue_status(httpd_req_t* req);
    static esp_err_t h_report_flush(httpd_req_t* req);
    static esp_err_t h_report_channels_get(httpd_req_t* req);
    static esp_err_t h_report_channels_post(httpd_req_t* req);
    static esp_err_t h_report_endpoints_get(httpd_req_t* req);
    static esp_err_t h_report_endpoints_post(httpd_req_t* req);
    static esp_err_t h_report_format_get(httpd_req_t* req);
    static esp_err_t h_report_format_post(httpd_req_t* req);
    static esp_err_t h_report_filters_get(httpd_req_t* req);
    static esp_err_t h_report_filters_post(httpd_req_t* req);
    static esp_err_t h_report_filter_add(httpd_req_t* req);
    static esp_err_t h_report_filter_remove(httpd_req_t* req);

    // GPIO Reporter API
    static esp_err_t h_gpio_status(httpd_req_t* req);
    static esp_err_t h_gpio_config_get(httpd_req_t* req);
    static esp_err_t h_gpio_config_post(httpd_req_t* req);
    static esp_err_t h_gpio_alert(httpd_req_t* req);
    static esp_err_t h_gpio_reset(httpd_req_t* req);
    static esp_err_t h_gpio_test(httpd_req_t* req);
    static esp_err_t h_gpio_buttons(httpd_req_t* req);

    // Sandbox Reporter API
    static esp_err_t h_sandbox_status(httpd_req_t* req);
    static esp_err_t h_sandbox_config_get(httpd_req_t* req);
    static esp_err_t h_sandbox_config_post(httpd_req_t* req);
    static esp_err_t h_sandbox_audit_get(httpd_req_t* req);

    // Auth & API keys
    static esp_err_t h_login_get(httpd_req_t* req);
    static esp_err_t h_login_post(httpd_req_t* req);
    static esp_err_t h_logout(httpd_req_t* req);
    static esp_err_t h_keys_list(httpd_req_t* req);
    static esp_err_t h_keys_create(httpd_req_t* req);
    static esp_err_t h_keys_revoke(httpd_req_t* req);
    static esp_err_t h_logs_retention_get(httpd_req_t* req);
    static esp_err_t h_logs_retention_post(httpd_req_t* req);
    static esp_err_t h_logs_retention_run(httpd_req_t* req);
    static esp_err_t h_logs_access_get(httpd_req_t* req);
    static esp_err_t h_logs_access_metrics(httpd_req_t* req);
    static esp_err_t h_wifi_connect(httpd_req_t* req);
    static esp_err_t h_wifi_status(httpd_req_t* req);
    static esp_err_t h_wifi_disconnect(httpd_req_t* req);
    static esp_err_t h_wifi_scan_start(httpd_req_t* req);
    static esp_err_t h_wifi_scan_status(httpd_req_t* req);
    static esp_err_t h_wifi_connect_result(httpd_req_t* req);
    static esp_err_t h_logs_get(httpd_req_t* req);
    static esp_err_t h_logs_download(httpd_req_t* req);

    // IP Whitelist endpoints
    static esp_err_t h_whitelist_get(httpd_req_t* req);
    static esp_err_t h_whitelist_post(httpd_req_t* req);

    // Incremental logs endpoints
    static esp_err_t h_logs_incremental_session(httpd_req_t* req);
    static esp_err_t h_logs_incremental_read(httpd_req_t* req);
    static esp_err_t h_logs_sse(httpd_req_t* req);

    // Protocol list
    static esp_err_t h_protocols_get_details(httpd_req_t* req);
    static esp_err_t h_protocols_get(httpd_req_t* req);

    static esp_err_t h_config_export(httpd_req_t* req);
    static esp_err_t h_config_import(httpd_req_t* req);
    static esp_err_t h_config_metadata_get(httpd_req_t* req);
    static esp_err_t h_config_reset_post(httpd_req_t* req);
    static bool check_api_auth(httpd_req_t* req);
    static bool check_session(httpd_req_t* req);

    // DEPRECATED: extractClientIP returns std::string in Internal RAM - causes leak!
    // Use extractClientIPToBuffer() instead (48 bytes thread_local - acceptable)
    static std::string extractClientIP(httpd_req_t* req);

    // Payload already uses PSRAM - keep using this (returns std::string but from PSRAM buffer)
    static psram_string extractPayload(httpd_req_t* req);

    // NEW: Zero-allocation IP address extraction (48 bytes Internal RAM - acceptable)
    static const char* extractClientIPToBuffer(httpd_req_t* req);

    static void logConfigChange(httpd_req_t* req, const char* config_type, const char* details = nullptr);
    static esp_err_t h_ids_adv_cfg_get(httpd_req_t* req);
    static esp_err_t h_ids_adv_cfg_post(httpd_req_t* req);
    static esp_err_t h_api_selftest(httpd_req_t* req);
    static esp_err_t h_api_httpd_stats(httpd_req_t* req);
    static esp_err_t h_ids_adv_stats(httpd_req_t* req);

    // Debug configuration endpoints
    static esp_err_t h_debug_config_get(httpd_req_t* req);
    static esp_err_t h_debug_config_post(httpd_req_t* req);

    // Network Presence tracking endpoints
    static esp_err_t h_presence_stats_get(httpd_req_t* req);
    static esp_err_t h_presence_devices_get(httpd_req_t* req);
    static esp_err_t h_presence_learned_get(httpd_req_t* req);
    static esp_err_t h_presence_config_get(httpd_req_t* req);
    static esp_err_t h_presence_config_post(httpd_req_t* req);
    static esp_err_t h_presence_clear_post(httpd_req_t* req);
    static esp_err_t h_presence_promote_post(httpd_req_t* req);
    static esp_err_t h_presence_demote_post(httpd_req_t* req);

    // Security configuration endpoints
    static esp_err_t h_security_config_get(httpd_req_t* req);
    static esp_err_t h_security_config_post(httpd_req_t* req);
    static esp_err_t h_security_event_ack(httpd_req_t* req);

    // Rate limiter endpoints
    static esp_err_t h_ratelimit_get(httpd_req_t* req);
    static esp_err_t h_ratelimit_post(httpd_req_t* req);
    static esp_err_t h_unblock_client(httpd_req_t* req);

    // API Key Rotation endpoints
    static esp_err_t h_rotation_policy_get(httpd_req_t* req);
    static esp_err_t h_rotation_policy_post(httpd_req_t* req);
    static esp_err_t h_rotation_scheduled_get(httpd_req_t* req);
    static esp_err_t h_rotation_schedule_post(httpd_req_t* req);
    static esp_err_t h_rotation_cancel_post(httpd_req_t* req);
    static esp_err_t h_rotation_trigger_post(httpd_req_t* req);

    // Watchdog configuration endpoints
    static esp_err_t h_watchdog_config_get(httpd_req_t* req);
    static esp_err_t h_watchdog_config_post(httpd_req_t* req);

    // Serial reporting endpoints
    static esp_err_t h_serial_config_get(httpd_req_t* req);
    static esp_err_t h_serial_config_post(httpd_req_t* req);
    static esp_err_t h_serial_stats_get(httpd_req_t* req);

    // Scanner REST
    static esp_err_t h_scan_jobs_get(httpd_req_t* req);
    static esp_err_t h_scan_jobs_post(httpd_req_t* req);
    static esp_err_t h_scan_jobs_delete(httpd_req_t* req);
    static esp_err_t h_scan_run(httpd_req_t* req);
    static esp_err_t h_scan_result_get(httpd_req_t* req);
    static esp_err_t h_scan_cfg_get(httpd_req_t* req);
    static esp_err_t h_scan_cfg_post(httpd_req_t* req);

    // IDS endpoints
    static esp_err_t h_ids_signatures_get(httpd_req_t* req);
    static esp_err_t h_ids_signatures_post(httpd_req_t* req);
    static esp_err_t h_ids_stats_get(httpd_req_t* req);
    static esp_err_t h_ids_config_get(httpd_req_t* req);
    static esp_err_t h_ids_config_post(httpd_req_t* req);
    static esp_err_t h_network_presence_learned_get(httpd_req_t* req);

    // CVE Signature detection endpoints
    static esp_err_t h_signatures_reload(httpd_req_t* req);
    static esp_err_t h_signatures_stats(httpd_req_t* req);
    static esp_err_t h_signatures_list(httpd_req_t* req);
    static esp_err_t h_signatures_upload(httpd_req_t* req);
    static esp_err_t h_signatures_download(httpd_req_t* req);
    static esp_err_t h_signatures_clear(httpd_req_t* req);
    static esp_err_t h_signatures_save(httpd_req_t* req);

    // Page handlers
    static esp_err_t h_page_signatures(httpd_req_t* req);
    static esp_err_t h_page_security(httpd_req_t* req);

    // Discovery endpoints
    // Fuzzing endpoints
    static esp_err_t h_fuzz_jobs_get(httpd_req_t* req);
    static esp_err_t h_fuzz_jobs_post(httpd_req_t* req);
    static esp_err_t h_fuzz_jobs_delete(httpd_req_t* req);
    static esp_err_t h_fuzz_run(httpd_req_t* req);
    static esp_err_t h_fuzz_stop(httpd_req_t* req);
    static esp_err_t h_fuzz_profiles_get(httpd_req_t* req);
    static esp_err_t h_fuzz_result_get(httpd_req_t* req);

    // Discovery endpoints (legacy sync)
    static esp_err_t h_discovery_modbus(httpd_req_t* req);
    static esp_err_t h_discovery_s7(httpd_req_t* req);
    static esp_err_t h_discovery_profinet(httpd_req_t* req);
    static esp_err_t h_discovery_enip(httpd_req_t* req);
    static esp_err_t h_discovery_opcua(httpd_req_t* req);

    // S7 client operations (Snap7-style)
    static esp_err_t h_s7_ops(httpd_req_t* req);

    // Async Discovery endpoints
    static esp_err_t h_discovery_start(httpd_req_t* req);
    static esp_err_t h_discovery_status(httpd_req_t* req);
    static esp_err_t h_discovery_list(httpd_req_t* req);
    static esp_err_t h_discovery_cancel(httpd_req_t* req);
    static esp_err_t h_discovery_general_start(httpd_req_t* req);
    static esp_err_t h_discovery_general_status(httpd_req_t* req);
    static esp_err_t h_discovery_general_defaults(httpd_req_t* req);

    // Schedule endpoints
    static esp_err_t h_schedule_list(httpd_req_t* req);
    static esp_err_t h_schedule_create(httpd_req_t* req);
    static esp_err_t h_schedule_update(httpd_req_t* req);
    static esp_err_t h_schedule_delete(httpd_req_t* req);
    static esp_err_t h_schedule_toggle(httpd_req_t* req);
    static esp_err_t h_schedule_trigger(httpd_req_t* req);

    // Protocol configuration endpoints
    static esp_err_t h_protocol_modbus_config_get(httpd_req_t* req);
    static esp_err_t h_protocol_modbus_config_post(httpd_req_t* req);
    static esp_err_t h_protocol_s7_config_get(httpd_req_t* req);
    static esp_err_t h_protocol_s7_config_post(httpd_req_t* req);
    static esp_err_t h_protocol_profinet_config_get(httpd_req_t* req);
    static esp_err_t h_protocol_profinet_config_post(httpd_req_t* req);
    static esp_err_t h_protocol_ethernetip_config_get(httpd_req_t* req);
    static esp_err_t h_protocol_ethernetip_config_post(httpd_req_t* req);
    static esp_err_t h_protocol_opcua_config_get(httpd_req_t* req);
    static esp_err_t h_protocol_opcua_config_post(httpd_req_t* req);

    // Network diagnostics endpoints
    static esp_err_t h_network_ping(httpd_req_t* req);
    static esp_err_t h_network_status(httpd_req_t* req);
    static esp_err_t h_network_interfaces(httpd_req_t* req);

    // Ethernet configuration endpoints
    static esp_err_t h_ethernet_config_get(httpd_req_t* req);
    static esp_err_t h_ethernet_config_post(httpd_req_t* req);
    static esp_err_t h_ethernet_diagnostics(httpd_req_t* req);
    static esp_err_t h_ip_stack_diagnostics(httpd_req_t* req);
    static esp_err_t h_network_layer_analysis(httpd_req_t* req);
    static esp_err_t h_network_scan(httpd_req_t* req);

    // Features toggle endpoints
    static esp_err_t h_features_get(httpd_req_t* req);
    static esp_err_t h_features_post(httpd_req_t* req);
    static esp_err_t h_driver_level_diagnostics(httpd_req_t* req);

    // Page bootstrap (reduce API fan-out for UI)
    static esp_err_t h_page_bootstrap_get(httpd_req_t* req);
    bool build_page_bootstrap_json(StaticJsonBuffer& cache, const char* page_name) const;

    // Log file management endpoints
    static esp_err_t h_logging_files_get(httpd_req_t* req);
    static esp_err_t h_logging_files_post(httpd_req_t* req);
    static esp_err_t h_logging_file_config_get(httpd_req_t* req);
    static esp_err_t h_logging_file_config_post(httpd_req_t* req);

    // Web pages
    static esp_err_t h_page_protocols(httpd_req_t* req);
    static esp_err_t h_page_scanner(httpd_req_t* req);
    static esp_err_t h_page_ids(httpd_req_t* req);
    static esp_err_t h_page_network_presence(httpd_req_t* req);
    static esp_err_t h_page_reporting(httpd_req_t* req);
    static esp_err_t h_page_serial_monitor(httpd_req_t* req);
    static esp_err_t h_page_network(httpd_req_t* req);
    static esp_err_t h_page_diagnostics(httpd_req_t* req);
    static esp_err_t h_page_logging(httpd_req_t* req);
    static esp_err_t h_page_gpio(httpd_req_t* req);
    static esp_err_t h_page_audit(httpd_req_t* req);
    static esp_err_t h_page_style(httpd_req_t* req);

    static bool read_body(httpd_req_t* req, psram_string& out, size_t max_len = 65536);

    static WebServer* self_;   // singleton-like pointer for handlers

    static void invalidateReportingCache();
    static void ensureReportingCacheLoaded();
    static void loadReportingCacheLocked();
    static void updateReportingCache(const char* data, size_t len);
    static void invalidateReportingChannelsCache();
    static void ensureReportingChannelsCacheLoaded();

    void initCronSchedulerIfReady();

    static psram_string reporting_cache_;
    static std::mutex reporting_cache_mutex_;
    static bool reporting_cache_valid_;
    static psram_string reporting_channels_cache_;
    static std::mutex reporting_channels_mutex_;
    static bool reporting_channels_valid_;

    ConfigurationManager* cfg_ = nullptr;
    SecurityManager* sec_ = nullptr;
    ReportingEngine* rep_ = nullptr;
    Logger* logger_ = nullptr;
    PluginManager* plugins_ = nullptr;
    EthernetManager* eth_ = nullptr;
    WiFiManager* wifi_ = nullptr;
    VulnerabilityScanner* scanner_ = nullptr;
    CronScheduler* cron_scheduler_ = nullptr;
    bool cron_scheduler_initialized_ = false;
    IntrusionDetectionGeneral* ids_ = nullptr;
    NetworkEngine* net_ = nullptr;
    LogFileManager* log_file_manager_ = nullptr;

    httpd_handle_t http_ = nullptr;

    // WiFi connection transition state
    SemaphoreHandle_t wifi_transition_mutex_ = nullptr;
    bool wifi_transition_in_progress_ = false;
    bool wifi_transition_result_ready_ = false;
    bool wifi_transition_success_ = false;
    bool wifi_transition_ap_shutdown_pending_ = false;
    bool wifi_transition_ap_shutdown_done_ = false;
    uint64_t wifi_transition_ready_us_ = 0;
    char wifi_transition_ip_[16] = {0};
    char wifi_transition_ssid_[33] = {0};
    char wifi_transition_error_[64] = {0};
    int wifi_transition_timeout_sec_ = 20;

    httpd_handle_t https_server_ = nullptr;  // HTTPS server handle
    httpd_handle_t active_server_ = nullptr; // Active HTTP or HTTPS route target
    RuntimeTlsCredentials tls_credentials_;

    // HTTPS helper methods
    void registerHTTPSHandlers();

    struct HttpdMonitorData {
        std::atomic<uint64_t> total_requests{0};
        std::atomic<uint64_t> total_responses{0};
        std::atomic<int32_t> inflight_requests{0};
        std::atomic<uint64_t> max_concurrent{0};
        std::atomic<uint32_t> method_get{0};
        std::atomic<uint32_t> method_post{0};
        std::atomic<uint32_t> method_put{0};
        std::atomic<uint32_t> method_delete{0};
        std::atomic<uint32_t> method_other{0};
        std::atomic<uint32_t> status_2xx{0};
        std::atomic<uint32_t> status_3xx{0};
        std::atomic<uint32_t> status_4xx{0};
        std::atomic<uint32_t> status_5xx{0};
        std::atomic<uint32_t> auth_failures{0};
        std::atomic<uint64_t> last_request_ms{0};
        std::atomic<uint64_t> last_response_ms{0};
        std::atomic<uint64_t> last_stall_ms{0};
        std::atomic<uint32_t> stall_count{0};
        std::atomic<uint8_t> watchdog_triggered{0};
        std::atomic<int32_t> last_status_code{0};
        char last_request_uri[96];
        char last_error_uri[96];
        std::mutex uri_mutex;

        HttpdMonitorData() {
            last_request_uri[0] = '\0';
            last_error_uri[0] = '\0';
        }
    };

    static void httpdMonitorReset();
    static void httpdMonitorNoteRequest(httpd_req_t* req);
    static void httpdMonitorNoteResponse(httpd_req_t* req, int status_code, const char* auth_status);
    static void httpdMonitorStart();
    static void httpdMonitorStop();
    static void httpdMonitorTimerCallback(void* arg);

    static HttpdMonitorData httpd_monitor_;
    static esp_timer_handle_t httpd_monitor_timer_;

    // Fallback debug handlers (kept as class static methods)
    static esp_err_t h_api_fallback(httpd_req_t* req);
    static esp_err_t h_any_fallback(httpd_req_t* req);
};
