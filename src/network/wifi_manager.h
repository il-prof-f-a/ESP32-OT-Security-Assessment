
#pragma once
#include <string>
extern "C" {
  #include "esp_wifi.h"
  #include "esp_netif.h"
  #include "esp_event.h"
}

// Forward declaration
class ConfigurationManager;


struct WiFiScanEntry {
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    wifi_auth_mode_t auth_mode;
    bool secure;
};

struct WiFiScanSnapshot {
    bool scanning;
    bool completed;
    uint16_t total_found;
    uint16_t cached;
    uint32_t elapsed_ms;
    uint16_t last_status;
};

class WiFiManager {
public:
    static constexpr uint16_t kMaxScanEntries = 24;
    // Constructor with ConfigurationManager dependency injection
    explicit WiFiManager(ConfigurationManager* cfg = nullptr);
    ~WiFiManager();

    // High-level method to initialize WiFi based on configuration
    bool initializeFromConfig();

    bool startSTA(const std::string& ssid, const std::string& pw, bool dhcp=true);
    bool connectSTA(const std::string& ssid, const std::string& pw, int timeout_sec=20);
    bool connectSTAKeepingAP(const std::string& ssid, const std::string& pw, int timeout_sec=20);
    bool disconnect();
    void startAP(const std::string& ssid, const std::string& pw);
    bool startAsyncScan();
    bool getAsyncScanResults(WiFiScanSnapshot* snapshot, WiFiScanEntry* entries, uint16_t max_entries);
    bool isScanInProgress() const;

    void stop();
    void stopAP();  // Stop only AP, keep STA active
    void disconnectAllAPClients();  // Disconnect all clients from AP

    // Load runtime options (e.g., timeouts, scan_on_fail) from configuration
    void loadRuntimeOptionsFromConfig();

    // Connection status
    bool isSTAConnected() const;
    bool isAPActive() const;

    esp_netif_t* ap() const { return ap_; }
    esp_netif_t* sta() const { return sta_; }

    bool configureSTAStaticIP(const char* ip, const char* gw, const char* mask);

    // Network info
    std::string getIP() const;
    bool getIP(char* out, size_t out_sz) const; // C-friendly variant

    // Status methods for checking current state
    bool isConfiguredFromConfig() const { return cfg_ != nullptr; }

    // Event callbacks (used by WiFi event logger)
    void handleStaConnected() { sta_connected_ = true; }
    void handleStaDisconnected() { sta_connected_ = false; }
    void handleGotIP() { got_ip_ = true; }

private:
    ConfigurationManager* cfg_ = nullptr;
    esp_netif_t* ap_  = nullptr;
    esp_netif_t* sta_ = nullptr;
    volatile bool sta_connected_ = false;
    volatile bool got_ip_ = false;

    // Last applied IP configuration (for diagnostics)
    bool last_use_dhcp_ = true;
    char last_static_ip_[16] = {0};
    char last_static_gw_[16] = {0};
    char last_static_mask_[16] = {0};

    // Internal helper methods
    bool parseWiFiConfig(std::string& ssid, std::string& pass, bool& enabled);
    bool parseWiFiConfig(char* out_ssid, size_t ssid_sz, char* out_pass, size_t pass_sz, bool* enabled);
    void saveWiFiCredentialsToConfig(const std::string& ssid, const std::string& pass);
    bool configureSTANetworkSettings();

public:
    // C-friendly overloads to avoid std::string on hot paths
    bool startSTA(const char* ssid, const char* pw, bool dhcp=true);
    bool connectSTA(const char* ssid, const char* pw, int timeout_sec=20);
    bool connectSTA(const char* ssid, const char* pw, int timeout_sec, bool keep_ap);
    bool connectSTAKeepingAP(const char* ssid, const char* pw, int timeout_sec=20);
    void startAP(const char* ssid, const char* pw);

private:

    // WiFi scan state
    WiFiScanEntry* scan_entries_ = nullptr;
    uint16_t scan_cached_ = 0;
    uint16_t scan_total_found_ = 0;
    uint16_t scan_last_status_ = 0;
    bool scan_running_ = false;
    bool scan_completed_ = false;
    uint64_t scan_start_us_ = 0;
    uint64_t scan_end_us_ = 0;
    SemaphoreHandle_t scan_mutex_ = nullptr;
    esp_event_handler_instance_t scan_handler_ = nullptr;
    esp_event_handler_instance_t ap_conn_handler_ = nullptr;
    esp_event_handler_instance_t ap_dis_handler_ = nullptr;

    static void handleScanDone(void* arg, esp_event_base_t base, int32_t id, void* data);
    // Runtime options (tunable via JSON)
    bool scan_on_fail_ = false;      // Avoid DRAM pressure on failure path
    int  connect_timeout_sec_ = 20;  // Default connection timeout
};
