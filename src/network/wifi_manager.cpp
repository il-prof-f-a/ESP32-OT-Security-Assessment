
#include "wifi_manager.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include <cstring>
extern "C" {
#include "lwip/inet.h"
#include "cJSON.h"
#include "esp_wifi.h"
#include "esp_event.h"
}
// Use PSRAM-backed cJSON hooks
#include "../core/psram_json_parser.h"
#include "soc/soc_caps.h"

#if SOC_WIFI_SUPPORTED

static const char* TAG = "WiFiManager";

// Map disconnect reason to human-readable string
static const char* wifi_reason_to_str(uint8_t r) {
    switch (r) {
        case WIFI_REASON_UNSPECIFIED: return "UNSPECIFIED";
        case WIFI_REASON_AUTH_EXPIRE: return "AUTH_EXPIRE";
        case WIFI_REASON_AUTH_LEAVE: return "AUTH_LEAVE";
        case WIFI_REASON_ASSOC_EXPIRE: return "ASSOC_EXPIRE";
        case WIFI_REASON_ASSOC_TOOMANY: return "ASSOC_TOOMANY";
        case WIFI_REASON_NOT_AUTHED: return "NOT_AUTHED";
        case WIFI_REASON_NOT_ASSOCED: return "NOT_ASSOCED";
        case WIFI_REASON_ASSOC_LEAVE: return "ASSOC_LEAVE";
        case WIFI_REASON_ASSOC_NOT_AUTHED: return "ASSOC_NOT_AUTHED";
        case WIFI_REASON_DISASSOC_PWRCAP_BAD: return "PWRCAP_BAD";
        case WIFI_REASON_DISASSOC_SUPCHAN_BAD: return "SUPCHAN_BAD";
        case WIFI_REASON_IE_INVALID: return "IE_INVALID";
        case WIFI_REASON_MIC_FAILURE: return "MIC_FAILURE";
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT: return "4WAY_TIMEOUT";
        case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT: return "GTK_TIMEOUT";
        case WIFI_REASON_IE_IN_4WAY_DIFFERS: return "4WAY_IE_DIFFERS";
        case WIFI_REASON_GROUP_CIPHER_INVALID: return "GROUP_CIPHER_INVALID";
        case WIFI_REASON_PAIRWISE_CIPHER_INVALID: return "PAIRWISE_CIPHER_INVALID";
        case WIFI_REASON_AKMP_INVALID: return "AKMP_INVALID";
        case WIFI_REASON_UNSUPP_RSN_IE_VERSION: return "UNSUPP_RSN_VER";
        case WIFI_REASON_INVALID_RSN_IE_CAP: return "INVALID_RSN_CAP";
        case WIFI_REASON_802_1X_AUTH_FAILED: return "8021X_AUTH_FAILED";
        case WIFI_REASON_CIPHER_SUITE_REJECTED: return "CIPHER_REJECTED";
        case WIFI_REASON_BEACON_TIMEOUT: return "BEACON_TIMEOUT";
        case WIFI_REASON_NO_AP_FOUND: return "NO_AP_FOUND";
        case WIFI_REASON_AUTH_FAIL: return "AUTH_FAIL";
        case WIFI_REASON_ASSOC_FAIL: return "ASSOC_FAIL";
        case WIFI_REASON_HANDSHAKE_TIMEOUT: return "HS_TIMEOUT";
        default: return "UNKNOWN";
    }
}

static void wifi_event_logger(void* arg, esp_event_base_t base, int32_t id, void* data) {
    WiFiManager* self = reinterpret_cast<WiFiManager*>(arg);
    if (base == WIFI_EVENT) {
        switch (id) {
            case WIFI_EVENT_STA_START:
                LOG_INFO("WiFi", "STA_START");
                break;
            case WIFI_EVENT_STA_CONNECTED:
                LOG_INFO("WiFi", "STA_CONNECTED");
                if (self) self->handleStaConnected();
                break;
            case WIFI_EVENT_STA_DISCONNECTED: {
                auto* d = (wifi_event_sta_disconnected_t*)data;
                LOG_WARNINGF("WiFi", "STA_DISCONNECTED: reason=%u (%s), ssid='%.*s', bssid=%02x:%02x:%02x:%02x:%02x:%02x, rssi=%d",
                             d->reason, wifi_reason_to_str(d->reason), d->ssid_len, d->ssid,
                             d->bssid[0], d->bssid[1], d->bssid[2], d->bssid[3], d->bssid[4], d->bssid[5], d->rssi);
                if (self) self->handleStaDisconnected();
                break;
            }
            case WIFI_EVENT_AP_STACONNECTED: {
                auto* ev = (wifi_event_ap_staconnected_t*)data;
                LOG_INFOF("WiFi", "AP_CLIENT_CONNECTED: aid=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x",
                          ev->aid,
                          ev->mac[0], ev->mac[1], ev->mac[2], ev->mac[3], ev->mac[4], ev->mac[5]);
                break;
            }
            case WIFI_EVENT_AP_STADISCONNECTED: {
                auto* ev = (wifi_event_ap_stadisconnected_t*)data;
                LOG_INFOF("WiFi", "AP_CLIENT_DISCONNECTED: aid=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x, reason=%u",
                          ev->aid,
                          ev->mac[0], ev->mac[1], ev->mac[2], ev->mac[3], ev->mac[4], ev->mac[5],
                          ev->reason);
                break;
            }
            default:
                LOG_INFOF("WiFi", "EVENT %ld", (long)id);
                break;
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        auto* e = (ip_event_got_ip_t*)data;
        char ip[16]; snprintf(ip, sizeof(ip), IPSTR, IP2STR(&e->ip_info.ip));
        LOG_INFOF("WiFi", "STA_GOT_IP: %s", ip);
        if (self) self->handleGotIP();
    }
}

WiFiManager::WiFiManager(ConfigurationManager* cfg) : cfg_(cfg) {
    LOG_INFO(TAG, "WiFiManager initialized with ConfigurationManager");
    scan_mutex_ = xSemaphoreCreateMutex();
    if (!scan_mutex_) {
        LOG_WARNING(TAG, "Failed to create WiFi scan mutex");
    }
}

WiFiManager::~WiFiManager() {
    stop();
    if (scan_handler_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, scan_handler_);
        scan_handler_ = nullptr;
    }
    if (scan_entries_) {
        heap_caps_free(scan_entries_);
        scan_entries_ = nullptr;
    }
    if (scan_mutex_) {
        vSemaphoreDelete(scan_mutex_);
        scan_mutex_ = nullptr;
    }
}

bool WiFiManager::initializeFromConfig() {
    if (!cfg_) {
        LOG_WARNING(TAG, "No ConfigurationManager provided, using manual configuration");
        return false;
    }

    LOG_INFO(TAG, "Initializing WiFi from configuration...");

    std::string ssid, pass;
    bool enabled = false;

    if (!parseWiFiConfig(ssid, pass, enabled)) {
        LOG_ERROR(TAG, "Failed to parse WiFi configuration");
        return false;
    }

    LOG_INFOF(TAG, "WiFi configuration: enabled=%s, ssid='%s'",
              enabled ? "true" : "false", ssid.c_str());

    if (!enabled || ssid.empty()) {
        LOG_INFO(TAG, "WiFi STA is disabled or not configured");
        return true;
    }

    // Load runtime options from configuration (timeouts, scan behavior)
    loadRuntimeOptionsFromConfig();

    // Mask password for logging (no std::string building)
    char masked[64];
    size_t plen = pass.size();
    if (plen <= 2) {
        snprintf(masked, sizeof(masked), "****");
    } else if (plen <= 6) {
        snprintf(masked, sizeof(masked), "%c****%c", pass[0], pass[plen-1]);
    } else {
        char head[4] = {0}, tail[4] = {0};
        memcpy(head, pass.c_str(), 3);
        memcpy(tail, pass.c_str() + plen - 3, 3);
        snprintf(masked, sizeof(masked), "%s****%s", head, tail);
    }
    LOG_INFOF(TAG, "Connecting to WiFi: SSID='%s', Password='%s'", ssid.c_str(), masked);

    // Try to connect with configured timeout
    if (connectSTA(ssid, pass, connect_timeout_sec_)) {
        LOG_INFO(TAG, "WiFi STA connected successfully!");

        // Save credentials to network.wifi section if needed
        //saveWiFiCredentialsToConfig(ssid, pass);

        // Configure network settings (DHCP/static IP)
        //configureSTANetworkSettings();

        return true;
    } else {
        LOG_WARNING(TAG, "WiFi STA connection failed");
        return false;
    }
}

void WiFiManager::loadRuntimeOptionsFromConfig() {
    // Defaults
    scan_on_fail_ = false;
    connect_timeout_sec_ = 20;
    if (!cfg_) return;

    size_t json_size = 0;
    char* json_buf = cfg_->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) return;
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) return;

    do {
        cJSON* netw = cJSON_GetObjectItem(root, "network");
        if (!netw || !cJSON_IsObject(netw)) break;
        cJSON* wf = cJSON_GetObjectItem(netw, "wifi");
        if (!wf || !cJSON_IsObject(wf)) break;

        cJSON* sscan = cJSON_GetObjectItem(wf, "scan_on_fail");
        if (sscan && cJSON_IsBool(sscan)) {
            scan_on_fail_ = (sscan->valueint != 0);
        }
        cJSON* cto = cJSON_GetObjectItem(wf, "connect_timeout_sec");
        if (cto && cJSON_IsNumber(cto)) {
            int v = (int)cto->valuedouble;
            if (v >= 5 && v <= 120) connect_timeout_sec_ = v;
        }
    } while(0);

    cJSON_Delete(root);
}
bool WiFiManager::startAsyncScan() {
    if (!scan_mutex_) {
        scan_mutex_ = xSemaphoreCreateMutex();
        if (!scan_mutex_) {
            LOG_WARNING(TAG, "Unable to create scan mutex");
            return false;
        }
    }
    if (xSemaphoreTake(scan_mutex_, pdMS_TO_TICKS(200)) != pdTRUE) {
        LOG_WARNING(TAG, "Scan mutex busy");
        return false;
    }
    if (!scan_entries_) {
        size_t buf_sz = sizeof(WiFiScanEntry) * kMaxScanEntries;
        scan_entries_ = (WiFiScanEntry*)heap_caps_malloc(buf_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!scan_entries_) {
            LOG_ERROR(TAG, "Failed to allocate WiFi scan buffer");
            xSemaphoreGive(scan_mutex_);
            return false;
        }
    }
    if (scan_running_) {
        xSemaphoreGive(scan_mutex_);
        return true;
    }

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t init_res = esp_wifi_init(&wcfg);
    if (init_res != ESP_OK && init_res != ESP_ERR_WIFI_INIT_STATE) {
        LOG_ERRORF(TAG, "esp_wifi_init failed for scan: %s", esp_err_to_name(init_res));
        xSemaphoreGive(scan_mutex_);
        return false;
    }

    if (!sta_) {
        sta_ = esp_netif_create_default_wifi_sta();
    }

    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_NULL) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
    } else if (mode == WIFI_MODE_AP) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
    }

    esp_err_t start_err = esp_wifi_start();
    if (start_err != ESP_OK && start_err != ESP_ERR_WIFI_CONN) {
        LOG_WARNINGF(TAG, "esp_wifi_start (scan) returned %s", esp_err_to_name(start_err));
    }

    if (!scan_handler_) {
        esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &WiFiManager::handleScanDone, this, &scan_handler_);
    }

    wifi_scan_config_t cfg{};
    cfg.ssid = nullptr;
    cfg.bssid = nullptr;
    cfg.channel = 0;
    cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    cfg.show_hidden = true;

    scan_running_ = true;
    scan_completed_ = false;
    scan_total_found_ = 0;
    scan_cached_ = 0;
    scan_last_status_ = 0;
    scan_start_us_ = esp_timer_get_time();
    scan_end_us_ = 0;

    esp_err_t err = esp_wifi_scan_start(&cfg, false);
    if (err != ESP_OK) {
        scan_running_ = false;
        scan_last_status_ = (uint16_t)(err & 0xFFFFu);
        LOG_ERRORF(TAG, "esp_wifi_scan_start failed: %s", esp_err_to_name(err));
        xSemaphoreGive(scan_mutex_);
        return false;
    }

    LOG_INFO(TAG, "WiFi scan started (async)");
    xSemaphoreGive(scan_mutex_);
    return true;
}

bool WiFiManager::getAsyncScanResults(WiFiScanSnapshot* snapshot, WiFiScanEntry* entries, uint16_t max_entries) {
    if (!scan_mutex_) {
        if (snapshot) {
            snapshot->scanning = false;
            snapshot->completed = false;
            snapshot->total_found = 0;
            snapshot->cached = 0;
            snapshot->elapsed_ms = 0;
            snapshot->last_status = 0;
        }
        return false;
    }
    if (xSemaphoreTake(scan_mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
        return false;
    }

    if (snapshot) {
        snapshot->scanning = scan_running_;
        snapshot->completed = scan_completed_;
        snapshot->total_found = scan_total_found_;
        snapshot->cached = scan_cached_;
        snapshot->last_status = scan_last_status_;
        uint64_t now_us = esp_timer_get_time();
        uint64_t start_us = scan_start_us_ ? scan_start_us_ : now_us;
        uint64_t end_us = scan_running_ ? now_us : (scan_end_us_ ? scan_end_us_ : now_us);
        snapshot->elapsed_ms = (uint32_t)((end_us > start_us) ? ((end_us - start_us) / 1000ULL) : 0);
    }

    if (entries && scan_entries_ && max_entries) {
        uint16_t to_copy = scan_cached_;
        if (to_copy > max_entries) {
            to_copy = max_entries;
        }
        for (uint16_t i = 0; i < to_copy; ++i) {
            entries[i] = scan_entries_[i];
        }
        for (uint16_t i = to_copy; i < max_entries; ++i) {
            entries[i].ssid[0] = 0;
            entries[i].rssi = 0;
            entries[i].channel = 0;
            entries[i].auth_mode = WIFI_AUTH_OPEN;
            entries[i].secure = false;
        }
    }

    xSemaphoreGive(scan_mutex_);
    return true;
}

void WiFiManager::handleScanDone(void* arg, esp_event_base_t base, int32_t id, void* data) {
    WiFiManager* self = reinterpret_cast<WiFiManager*>(arg);
    if (!self) {
        return;
    }
    if (!self->scan_mutex_) {
        return;
    }
    if (xSemaphoreTake(self->scan_mutex_, pdMS_TO_TICKS(100)) != pdTRUE) {
        return;
    }

    wifi_event_sta_scan_done_t* evt = (wifi_event_sta_scan_done_t*)data;
    if (evt) {
        self->scan_last_status_ = evt->status;
    } else {
        self->scan_last_status_ = 0xFFFFu;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    uint16_t to_fetch = ap_num;
    if (to_fetch > kMaxScanEntries) {
        to_fetch = kMaxScanEntries;
    }

    uint16_t stored = 0;
    if (to_fetch > 0) {
        size_t buf_sz = to_fetch * sizeof(wifi_ap_record_t);
        wifi_ap_record_t* recs = (wifi_ap_record_t*)heap_caps_malloc(buf_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (recs) {
            uint16_t n = to_fetch;
            if (esp_wifi_scan_get_ap_records(&n, recs) == ESP_OK) {
                if (!self->scan_entries_) {
                    size_t entry_sz = sizeof(WiFiScanEntry) * kMaxScanEntries;
                    self->scan_entries_ = (WiFiScanEntry*)heap_caps_malloc(entry_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                }
                if (self->scan_entries_) {
                    if (n > kMaxScanEntries) {
                        n = kMaxScanEntries;
                    }
                    for (uint16_t i = 0; i < n; ++i) {
                        memcpy(self->scan_entries_[i].ssid, recs[i].ssid, sizeof(recs[i].ssid));
                        self->scan_entries_[i].ssid[32] = 0;
                        self->scan_entries_[i].rssi = recs[i].rssi;
                        self->scan_entries_[i].channel = recs[i].primary;
                        self->scan_entries_[i].auth_mode = recs[i].authmode;
                        self->scan_entries_[i].secure = (recs[i].authmode != WIFI_AUTH_OPEN);
                    }
                    stored = n;
                }
            }
            heap_caps_free(recs);
        }
    }

    self->scan_cached_ = stored;
    self->scan_total_found_ = ap_num;
    self->scan_running_ = false;
    self->scan_completed_ = true;
    self->scan_end_us_ = esp_timer_get_time();

    LOG_INFOF(TAG, "WiFi scan completed: %u APs, cached %u", (unsigned)ap_num, (unsigned)stored);

    xSemaphoreGive(self->scan_mutex_);
}

bool WiFiManager::parseWiFiConfig(std::string& ssid, std::string& pass, bool& enabled) {
    if (!cfg_) return false;

    enabled = false;
    ssid.clear();
    pass.clear();

    // PRIORITY 1: Read from NVS (separate keys saved by /api/wifi/connect)
    psram_string nvs_ssid, nvs_pass;
    uint8_t nvs_enabled = 0;

    esp_err_t err_ssid = AsyncStorage::Global::nvsGet("wifi", "ssid", nvs_ssid);
    esp_err_t err_pass = AsyncStorage::Global::nvsGet("wifi", "password", nvs_pass);
    esp_err_t err_enabled = AsyncStorage::Global::nvsGet("wifi", "enabled", nvs_enabled);

    if (err_ssid == ESP_OK && !nvs_ssid.empty()) {
        ssid = nvs_ssid.c_str();
        if (err_pass == ESP_OK) {
            pass = nvs_pass.c_str();
        }
        enabled = (err_enabled == ESP_OK) ? (nvs_enabled != 0) : true;
        LOG_INFO(TAG, "✅ Using WiFi credentials from NVS (saved via web interface)");
        return true;
    }

    // PRIORITY 2: Read from the JSON configuration file
    size_t json_size = 0;
    char* json_buf = cfg_->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) return false;
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) return false;

    // First: try to read from network.wifi.*
    cJSON* netw = cJSON_GetObjectItem(root, "network");
    cJSON* network_wifi = nullptr;
    if (netw && cJSON_IsObject(netw)) {
        network_wifi = cJSON_GetObjectItem(netw, "wifi");
    }

    // If network.wifi exists and has credentials, use them
    if (network_wifi && cJSON_IsObject(network_wifi)) {
        cJSON* s = cJSON_GetObjectItem(network_wifi, "ssid");
        cJSON* p = cJSON_GetObjectItem(network_wifi, "password");
        cJSON* en = cJSON_GetObjectItem(network_wifi, "enabled");

        if (s && cJSON_IsString(s) && strlen(s->valuestring) > 0) {
            ssid = s->valuestring;
            if (p && cJSON_IsString(p)) pass = p->valuestring;
            enabled = (en && cJSON_IsBool(en)) ? (en->valueint != 0) : true; // assume enabled if ssid present
            LOG_INFO(TAG, "Using WiFi credentials from network.wifi section in JSON config");
            cJSON_Delete(root);
            return true;
        }
    }

    // Fallback: read from wifi.* (original behavior)
    cJSON* w = cJSON_GetObjectItem(root, "wifi");
    if (w && cJSON_IsObject(w)) {
        cJSON* en = cJSON_GetObjectItem(w, "enabled");
        enabled = (en && cJSON_IsBool(en)) ? (en->valueint != 0) : false;
        cJSON* s = cJSON_GetObjectItem(w, "ssid");
        cJSON* p = cJSON_GetObjectItem(w, "password");
        if (s && cJSON_IsString(s)) ssid = s->valuestring;
        if (p && cJSON_IsString(p)) pass = p->valuestring;
        LOG_INFO(TAG, "Using WiFi credentials from wifi section in JSON config (fallback)");
    }

    cJSON_Delete(root);
    return true;
}

bool WiFiManager::parseWiFiConfig(char* out_ssid, size_t ssid_sz, char* out_pass, size_t pass_sz, bool* enabled) {
    if (!cfg_ || !out_ssid || !out_pass || !enabled) return false;
    std::string ssid, pass;
    bool en = false;
    if (!parseWiFiConfig(ssid, pass, en)) return false;
    // Copy to C buffers
    if (ssid_sz) { strncpy(out_ssid, ssid.c_str(), ssid_sz-1); out_ssid[ssid_sz-1] = '\0'; }
    if (pass_sz) { strncpy(out_pass, pass.c_str(), pass_sz-1); out_pass[pass_sz-1] = '\0'; }
    *enabled = en;
    return true;
}

void WiFiManager::saveWiFiCredentialsToConfig(const std::string& ssid, const std::string& pass) {
    if (!cfg_) return;

    size_t jsz = 0; char* jbuf = cfg_->getRawConfigInPSRAM(&jsz);
    PSRAMJsonParser::PSRAMContext ctx2;
    cJSON* check_root = (jbuf && jsz) ? PSRAMJsonParser::parseInPSRAM(jbuf, jsz) : nullptr;
    bool should_save_to_network = false;
    if (check_root) {
        cJSON* check_netw = cJSON_GetObjectItem(check_root, "network");
        cJSON* check_wifi = nullptr;
        if (check_netw && cJSON_IsObject(check_netw)) {
            check_wifi = cJSON_GetObjectItem(check_netw, "wifi");
        }

        // If network.wifi doesn't exist or doesn't have ssid, we need to save
        if (!check_wifi || !cJSON_IsObject(check_wifi)) {
            should_save_to_network = true;
        } else {
            cJSON* existing_ssid = cJSON_GetObjectItem(check_wifi, "ssid");
            if (!existing_ssid || !cJSON_IsString(existing_ssid) || strlen(existing_ssid->valuestring) == 0) {
                should_save_to_network = true;
            }
        }
        cJSON_Delete(check_root);
    }

    if (should_save_to_network) {
        LOG_INFO(TAG, "Saving WiFi credentials to network.wifi section for future use");
        size_t jsz2 = 0; char* jbuf2 = cfg_->getRawConfigInPSRAM(&jsz2);
        PSRAMJsonParser::PSRAMContext ctx3;
        cJSON* save_root = (jbuf2 && jsz2) ? PSRAMJsonParser::parseInPSRAM(jbuf2, jsz2) : nullptr;
        if (!save_root) save_root = cJSON_CreateObject();

        // Create/get network section
        cJSON* netw = cJSON_GetObjectItem(save_root, "network");
        if (!netw) {
            netw = cJSON_CreateObject();
            cJSON_AddItemToObject(save_root, "network", netw);
        }

        // Create/get wifi section
        cJSON* wf = cJSON_GetObjectItem(netw, "wifi");
        if (!wf) {
            wf = cJSON_CreateObject();
            cJSON_AddItemToObject(netw, "wifi", wf);
        }

        // Save credentials
        cJSON_DeleteItemFromObject(wf, "enabled");
        cJSON_DeleteItemFromObject(wf, "ssid");
        cJSON_DeleteItemFromObject(wf, "password");
        cJSON_DeleteItemFromObject(wf, "dhcp");

        cJSON_AddBoolToObject(wf, "enabled", true);
        cJSON_AddStringToObject(wf, "ssid", ssid.c_str());
        cJSON_AddStringToObject(wf, "password", pass.c_str());
        cJSON_AddBoolToObject(wf, "dhcp", true); // default DHCP

        // Save updated configuration
        char* json_string = cJSON_PrintUnformatted(save_root);
        if (json_string) {
            if (cfg_->saveConfigJSON(json_string)) {
                LOG_INFO(TAG, "WiFi credentials saved to network.wifi section");
            } else {
                LOG_WARNING(TAG, "Failed to save WiFi credentials to network.wifi");
            }
            free(json_string);
        }
        cJSON_Delete(save_root);
    }
}

bool WiFiManager::configureSTANetworkSettings() {
    if (!cfg_ || !sta_) return false;

    // Get JSON buffer in PSRAM and parse with PSRAM-only hooks to avoid DRAM pressure
    size_t json_size = 0;
    char* json_buf = cfg_->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) return false;

    PSRAMJsonParser::PSRAMContext ctx;
    if (!ctx.isValid()) { heap_caps_free(json_buf); return false; }
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) return false;

    bool result = false;

    do {
        cJSON* netw = cJSON_GetObjectItem(root, "network");
        if (!netw || !cJSON_IsObject(netw)) break;
        cJSON* wf = cJSON_GetObjectItem(netw, "wifi");
        if (!wf || !cJSON_IsObject(wf)) break;

        cJSON* dhcp = cJSON_GetObjectItem(wf, "dhcp");
        cJSON* ip   = cJSON_GetObjectItem(wf, "ip");
        cJSON* gw   = cJSON_GetObjectItem(wf, "gateway");
        cJSON* mask = cJSON_GetObjectItem(wf, "netmask");

        bool use_dhcp = (!dhcp || (cJSON_IsBool(dhcp) && dhcp->valueint != 0));

        if (use_dhcp) {
            esp_netif_dhcpc_start(sta_);
            last_use_dhcp_ = true;
            last_static_ip_[0] = last_static_gw_[0] = last_static_mask_[0] = '\0';
            LOG_INFO(TAG, "WiFi STA IP config: DHCP");
            result = true;
        } else if (ip && gw && mask && cJSON_IsString(ip) && cJSON_IsString(gw) && cJSON_IsString(mask)) {
            esp_netif_dhcpc_stop(sta_);
            esp_netif_ip_info_t ipi{};
            uint32_t a = esp_ip4addr_aton(ip->valuestring);
            uint32_t b = esp_ip4addr_aton(gw->valuestring);
            uint32_t c = esp_ip4addr_aton(mask->valuestring);
            if (a != IPADDR_NONE && b != IPADDR_NONE && c != IPADDR_NONE) {
                ipi.ip.addr = a;
                ipi.gw.addr = b;
                ipi.netmask.addr = c;
                esp_netif_set_ip_info(sta_, &ipi);
                last_use_dhcp_ = false;
                strncpy(last_static_ip_, ip->valuestring, sizeof(last_static_ip_)-1);
                strncpy(last_static_gw_, gw->valuestring, sizeof(last_static_gw_)-1);
                strncpy(last_static_mask_, mask->valuestring, sizeof(last_static_mask_)-1);
                LOG_INFOF(TAG, "WiFi STA IP config: STATIC ip=%s gw=%s mask=%s",
                         ip->valuestring, gw->valuestring, mask->valuestring);
                result = true;
            } else {
                LOG_WARNING(TAG, "Invalid static IP configuration, falling back to DHCP");
                esp_netif_dhcpc_start(sta_);
                last_use_dhcp_ = true;
                last_static_ip_[0] = last_static_gw_[0] = last_static_mask_[0] = '\0';
                result = true;
            }
        }

        // Configure DNS servers from network.wifi.dns (current config.json format)
        cJSON* wifi_dns = cJSON_GetObjectItem(wf, "dns");
        if (wifi_dns && cJSON_IsString(wifi_dns) && strlen(wifi_dns->valuestring) > 0) {
            esp_netif_dns_info_t dns_info = {};
            uint32_t dns_addr = esp_ip4addr_aton(wifi_dns->valuestring);
            if (dns_addr != IPADDR_NONE) {
                dns_info.ip.u_addr.ip4.addr = dns_addr;
                dns_info.ip.type = IPADDR_TYPE_V4;
                esp_netif_set_dns_info(sta_, ESP_NETIF_DNS_MAIN, &dns_info);
                LOG_INFOF(TAG, "WiFi STA DNS Primary: %s", wifi_dns->valuestring);

                // Set default secondary DNS
                dns_info.ip.u_addr.ip4.addr = esp_ip4addr_aton("8.8.4.4");
                esp_netif_set_dns_info(sta_, ESP_NETIF_DNS_BACKUP, &dns_info);
                LOG_INFO(TAG, "WiFi STA DNS Secondary: 8.8.4.4 (default)");
            }
        } else {
            // Fallback: Try to read from separate network.dns section
            cJSON* dns = cJSON_GetObjectItem(netw, "dns");
            if (dns && cJSON_IsObject(dns)) {
                esp_netif_dns_info_t dns_info = {};

                // Primary DNS
                cJSON* primary = cJSON_GetObjectItem(dns, "primary");
                if (primary && cJSON_IsString(primary) && strlen(primary->valuestring) > 0) {
                    uint32_t dns_addr = esp_ip4addr_aton(primary->valuestring);
                    if (dns_addr != IPADDR_NONE) {
                        dns_info.ip.u_addr.ip4.addr = dns_addr;
                        dns_info.ip.type = IPADDR_TYPE_V4;
                        esp_netif_set_dns_info(sta_, ESP_NETIF_DNS_MAIN, &dns_info);
                        LOG_INFOF(TAG, "WiFi STA DNS Primary: %s", primary->valuestring);
                    }
                }

                // Secondary DNS
                cJSON* secondary = cJSON_GetObjectItem(dns, "secondary");
                if (secondary && cJSON_IsString(secondary) && strlen(secondary->valuestring) > 0) {
                    uint32_t dns_addr = esp_ip4addr_aton(secondary->valuestring);
                    if (dns_addr != IPADDR_NONE) {
                        dns_info.ip.u_addr.ip4.addr = dns_addr;
                        dns_info.ip.type = IPADDR_TYPE_V4;
                        esp_netif_set_dns_info(sta_, ESP_NETIF_DNS_BACKUP, &dns_info);
                        LOG_INFOF(TAG, "WiFi STA DNS Secondary: %s", secondary->valuestring);
                    }
                }
            }
        }
    } while(0);

    cJSON_Delete(root);
    return result;
}

bool WiFiManager::startSTA(const char* ssid, const char* pw, bool dhcp){
    if (!sta_) sta_ = esp_netif_create_default_wifi_sta();
    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&wcfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    // TEST SETTINGS: disable power-save and enable 11b/g/n for broader AP compatibility
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
    wifi_config_t cfg{};
    strncpy((char*)cfg.sta.ssid, ssid ? ssid : "", sizeof(cfg.sta.ssid)-1);
    strncpy((char*)cfg.sta.password, pw ? pw : "", sizeof(cfg.sta.password)-1);
    // Compatibility settings to reduce auth mismatches
    cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    cfg.sta.pmf_cfg.required = false; // avoid PMF-required AP incompatibility
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK; // accept WPA2/WPA3 mixed
    esp_wifi_set_config(WIFI_IF_STA, &cfg);
    esp_wifi_start();
    // Register detailed event logs
    esp_event_handler_instance_t ih1, ih2, ih3;
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &wifi_event_logger, this, &ih1);
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &wifi_event_logger, this, &ih2);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_logger, this, &ih3);
    esp_wifi_connect();
    LOG_INFOF(TAG, "STA connecting to %s", ssid ? ssid : "");
    return true;
}

bool WiFiManager::startSTA(const std::string& ssid, const std::string& pw, bool dhcp){
    return startSTA(ssid.c_str(), pw.c_str(), dhcp);
}


bool WiFiManager::connectSTA(const char* ssid, const char* pw, int timeout_sec, bool keep_ap) {
    LOG_INFOF(TAG, "Attempting WiFi connection to \"%s\" with %d second timeout...", ssid ? ssid : "", timeout_sec);
    if (!ssid || !ssid[0]) {
        LOG_WARNING(TAG, "Empty SSID - aborting WiFi connection");
        return false;
    }

    if (timeout_sec < 5) {
        timeout_sec = 5;
    } else if (timeout_sec > 120) {
        timeout_sec = 120;
    }

    if (!keep_ap) {
        stop();
    }

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t init_res = esp_wifi_init(&wcfg);
    if (init_res != ESP_OK && init_res != ESP_ERR_WIFI_INIT_STATE) {
        LOG_ERRORF(TAG, "esp_wifi_init failed: %s", esp_err_to_name(init_res));
        return false;
    }

    if (!sta_) {
        sta_ = esp_netif_create_default_wifi_sta();
    }

    wifi_mode_t current_mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&current_mode);
    if (keep_ap) {
        if (current_mode == WIFI_MODE_NULL || current_mode == WIFI_MODE_AP || current_mode == WIFI_MODE_STA) {
            esp_err_t mode_err = esp_wifi_set_mode(WIFI_MODE_APSTA);
            if (mode_err != ESP_OK && mode_err != ESP_ERR_WIFI_MODE) {
                LOG_WARNINGF(TAG, "esp_wifi_set_mode(APSTA) returned %s", esp_err_to_name(mode_err));
            }
        }
    } else {
        esp_err_t mode_err = esp_wifi_set_mode(WIFI_MODE_STA);
        if (mode_err != ESP_OK && mode_err != ESP_ERR_WIFI_MODE) {
            LOG_WARNINGF(TAG, "esp_wifi_set_mode(STA) returned %s", esp_err_to_name(mode_err));
        }
    }

    esp_wifi_set_ps(WIFI_PS_NONE);

    wifi_config_t cfg{};
    memset(&cfg, 0, sizeof(cfg));
    strncpy((char*)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);
    if (pw) {
        strncpy((char*)cfg.sta.password, pw, sizeof(cfg.sta.password) - 1);
    }
    cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    cfg.sta.pmf_cfg.required = false;
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    esp_wifi_set_config(WIFI_IF_STA, &cfg);

    esp_err_t start_err = esp_wifi_start();
    if (start_err != ESP_OK && start_err != ESP_ERR_WIFI_CONN) {
        LOG_WARNINGF(TAG, "esp_wifi_start returned %s", esp_err_to_name(start_err));
    }

    (void)configureSTANetworkSettings();

    esp_event_handler_instance_t ih_dis = nullptr;
    esp_event_handler_instance_t ih_conn = nullptr;
    esp_event_handler_instance_t ih_ip = nullptr;
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &wifi_event_logger, this, &ih_dis);
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &wifi_event_logger, this, &ih_conn);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_logger, this, &ih_ip);

    sta_connected_ = false;
    got_ip_ = false;

    esp_wifi_disconnect();
    esp_err_t conn_err = esp_wifi_connect();
    if (conn_err != ESP_OK) {
        LOG_WARNINGF(TAG, "esp_wifi_connect returned %s", esp_err_to_name(conn_err));
    }

    for (int attempt = 0; attempt < timeout_sec; ++attempt) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_netif_ip_info_t ipi{};
        bool ip_ready = (sta_ && esp_netif_get_ip_info(sta_, &ipi) == ESP_OK && ipi.ip.addr != 0);
        if (got_ip_ || (sta_connected_ && ip_ready)) {
            if (ip_ready) {
                char ipbuf[16];
                snprintf(ipbuf, sizeof(ipbuf), IPSTR, IP2STR(&ipi.ip));
                LOG_INFOF(TAG, "WiFi STA connected successfully! IP: %s", ipbuf);
            } else {
                LOG_INFO(TAG, "WiFi STA connected successfully!");
            }
            esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, ih_dis);
            esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, ih_conn);
            esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, ih_ip);
            return true;
        }
        LOG_INFOF(TAG, "WiFi connection attempt %d/%d...", attempt + 1, timeout_sec);
    }

    esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, ih_dis);
    esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, ih_conn);
    esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, ih_ip);

    if (!keep_ap && scan_on_fail_) {
        wifi_scan_config_t sc{};
        sc.show_hidden = true;
        LOG_INFO(TAG, "WiFi STA connection failed - scanning for networks (1s)...");
        esp_wifi_scan_start(&sc, true);
    } else if (!keep_ap) {
        LOG_INFO(TAG, "WiFi STA connection failed - scan disabled by config");
    }

    if (!keep_ap) {
        LOG_WARNINGF(TAG, "WiFi connection failed after %d seconds", timeout_sec);
    } else {
        LOG_WARNINGF(TAG, "WiFi connection failed after %d seconds (AP kept active)", timeout_sec);
    }

    return false;
}

bool WiFiManager::connectSTA(const char* ssid, const char* pw, int timeout_sec) {
    return connectSTA(ssid, pw, timeout_sec, false);
}

bool WiFiManager::connectSTAKeepingAP(const char* ssid, const char* pw, int timeout_sec) {
    return connectSTA(ssid, pw, timeout_sec, true);
}

bool WiFiManager::connectSTA(const std::string& ssid, const std::string& pw, int timeout_sec) {
    return connectSTA(ssid.c_str(), pw.c_str(), timeout_sec, false);
}

bool WiFiManager::connectSTAKeepingAP(const std::string& ssid, const std::string& pw, int timeout_sec) {
    return connectSTA(ssid.c_str(), pw.c_str(), timeout_sec, true);
}bool WiFiManager::disconnect() {
    static const char* TAG = "WiFiManager";
    LOG_INFO(TAG, "Disconnecting from WiFi STA");

    if (!sta_) {
        LOG_WARNING(TAG, "No STA interface to disconnect");
        return true; // Already disconnected
    }

    // Disconnect from current network
    esp_err_t err = esp_wifi_disconnect();
    if (err != ESP_OK) {
        LOG_ERRORF(TAG, "esp_wifi_disconnect failed: %s", esp_err_to_name(err));
        return false;
    }

    // Stop WiFi if in STA mode
    esp_wifi_stop();

    LOG_INFO(TAG, "WiFi STA disconnected successfully");
    return true;
}

bool WiFiManager::isSTAConnected() const {
    // Prefer WiFi driver status over IP info as IP may persist after disconnect
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) return true;
    return false;
}

bool WiFiManager::isAPActive() const {
    return (ap_ != nullptr);
}

void WiFiManager::startAP(const char* ssid, const char* pw){
    // Safe fallback: ensure STA is disconnected and WiFi is stopped before switching mode
    // 1) Register temp handler to observe DISCONNECTED event and update state
    esp_event_handler_instance_t ih_dis = nullptr;
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &wifi_event_logger, this, &ih_dis);
    // 2) Try graceful disconnect
    (void)esp_wifi_disconnect();
    // Wait up to 1500 ms for DISCONNECTED state
    for (int i = 0; i < 30; ++i) { // ~1500 ms
        vTaskDelay(pdMS_TO_TICKS(50));
        if (!sta_connected_) break;
    }
    // 2) Stop WiFi if running
    (void)esp_wifi_stop();
    // Unregister temporary handler
    if (ih_dis) esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, ih_dis);

    // 3) Ensure AP netif exists
    if (!ap_) ap_ = esp_netif_create_default_wifi_ap();

    // 4) Initialize WiFi if needed, then set AP mode
    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t einit = esp_wifi_init(&wcfg);
    if (einit != ESP_OK && einit != ESP_ERR_WIFI_INIT_STATE) {
        LOG_ERRORF(TAG, "esp_wifi_init failed: %s", esp_err_to_name(einit));
    }
    esp_err_t emode = esp_wifi_set_mode(WIFI_MODE_AP);
    if (emode != ESP_OK) {
        LOG_WARNINGF(TAG, "esp_wifi_set_mode(AP) returned %s, retrying after stop", esp_err_to_name(emode));
        (void)esp_wifi_stop();
        emode = esp_wifi_set_mode(WIFI_MODE_AP);
        if (emode != ESP_OK) {
            LOG_ERRORF(TAG, "Failed to set AP mode: %s", esp_err_to_name(emode));
        }
    }
    wifi_config_t apcfg{};
    strncpy((char*)apcfg.ap.ssid, ssid ? ssid : "", sizeof(apcfg.ap.ssid)-1);
    strncpy((char*)apcfg.ap.password, pw ? pw : "", sizeof(apcfg.ap.password)-1);
    apcfg.ap.ssid_len = ssid ? strlen(ssid) : 0;
    apcfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    apcfg.ap.max_connection = 1;
    esp_wifi_set_config(WIFI_IF_AP, &apcfg);
    esp_wifi_start();

    if (ap_conn_handler_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_AP_STACONNECTED, ap_conn_handler_);
        ap_conn_handler_ = nullptr;
    }
    if (ap_dis_handler_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_AP_STADISCONNECTED, ap_dis_handler_);
        ap_dis_handler_ = nullptr;
    }
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_AP_STACONNECTED, &wifi_event_logger, this, &ap_conn_handler_);
    esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_AP_STADISCONNECTED, &wifi_event_logger, this, &ap_dis_handler_);
    LOG_INFOF(TAG, "AP started SSID=%s", ssid ? ssid : "");
}

void WiFiManager::startAP(const std::string& ssid, const std::string& pw){
    startAP(ssid.c_str(), pw.c_str());
}

void WiFiManager::stop(){
    esp_wifi_stop();
    esp_wifi_deinit();
    sta_connected_ = false;
    got_ip_ = false;
    if (ap_)  { esp_netif_destroy(ap_); ap_=nullptr; }
    if (sta_) { esp_netif_destroy(sta_); sta_=nullptr; }

    if (ap_conn_handler_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_AP_STACONNECTED, ap_conn_handler_);
        ap_conn_handler_ = nullptr;
    }
    if (ap_dis_handler_) {
        esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_AP_STADISCONNECTED, ap_dis_handler_);
        ap_dis_handler_ = nullptr;
    }
}

void WiFiManager::disconnectAllAPClients() {
    LOG_INFO(TAG, "Disconnecting all AP clients...");

    // Get list of connected stations and disconnect them
    wifi_sta_list_t sta_list;
    esp_wifi_ap_get_sta_list(&sta_list);

    LOG_INFOF(TAG, "Found %d connected clients to disconnect", sta_list.num);

    for (int i = 0; i < sta_list.num; i++) {
        // In ESP-IDF 5.5.0, we use AID derived from list position + 1 (AID starts from 1)
        uint16_t aid = i + 1;  // AIDs typically start from 1
        esp_wifi_deauth_sta(aid);
        LOG_INFOF(TAG, "Disconnected client AID: %d, MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                 aid,
                 sta_list.sta[i].mac[0], sta_list.sta[i].mac[1], sta_list.sta[i].mac[2],
                 sta_list.sta[i].mac[3], sta_list.sta[i].mac[4], sta_list.sta[i].mac[5]);
    }

    // Wait for disconnections to complete
    vTaskDelay(pdMS_TO_TICKS(200));
}

void WiFiManager::stopAP() {
    LOG_INFO(TAG, "Stopping Access Point...");

    if (isSTAConnected()) {
        // If STA is connected, switch to STA-only mode
        esp_wifi_set_mode(WIFI_MODE_STA);
        LOG_INFO(TAG, "Switched to STA-only mode, AP stopped");
    } else {
        // If no STA connection, stop WiFi completely
        esp_wifi_stop();
        LOG_INFO(TAG, "No STA connection, stopped WiFi completely");
    }

    // Clean up AP netif
    if (ap_) {
        esp_netif_destroy(ap_);
        ap_ = nullptr;
    }
}


bool WiFiManager::configureSTAStaticIP(const char* ip, const char* gw, const char* mask){
    if (!sta_) return false;
    esp_netif_dhcpc_stop(sta_);
    esp_netif_ip_info_t ipi{};
    uint32_t a = esp_ip4addr_aton(ip);
    uint32_t b = esp_ip4addr_aton(gw);
    uint32_t c = esp_ip4addr_aton(mask);
    if (a == IPADDR_NONE || b == IPADDR_NONE || c == IPADDR_NONE){
        esp_netif_dhcpc_start(sta_);
        return false;
    }
    ipi.ip.addr = a; ipi.gw.addr = b; ipi.netmask.addr = c;
    esp_netif_set_ip_info(sta_, &ipi);
    return true;
}

std::string WiFiManager::getIP() const {
    // Try STA first, then AP
    esp_netif_t* netif = sta_ ? sta_ : ap_;
    if (!netif) return "";
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) return "";
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
    return std::string(ip_str);
}

bool WiFiManager::getIP(char* out, size_t out_sz) const {
    if (!out || out_sz < 16) return false;
    esp_netif_t* netif = sta_ ? sta_ : ap_;
    if (!netif) { out[0] = '\0'; return false; }
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) { out[0] = '\0'; return false; }
    snprintf(out, out_sz, IPSTR, IP2STR(&ip_info.ip));
    return true;
}

#else

static const char* TAG = "WiFiManager";

WiFiManager::WiFiManager(ConfigurationManager* cfg) : cfg_(cfg) {
    LOG_INFO(TAG, "Wi-Fi is unavailable on this target");
}

WiFiManager::~WiFiManager() = default;

bool WiFiManager::initializeFromConfig() { return false; }
void WiFiManager::loadRuntimeOptionsFromConfig() {}
bool WiFiManager::startAsyncScan() { return false; }

bool WiFiManager::getAsyncScanResults(WiFiScanSnapshot* snapshot,
                                      WiFiScanEntry*,
                                      uint16_t) {
    if (snapshot) {
        *snapshot = WiFiScanSnapshot{};
    }
    return false;
}

bool WiFiManager::isScanInProgress() const { return false; }
void WiFiManager::handleScanDone(void*, esp_event_base_t, int32_t, void*) {}

bool WiFiManager::parseWiFiConfig(std::string&, std::string&, bool& enabled) {
    enabled = false;
    return false;
}

bool WiFiManager::parseWiFiConfig(char*, size_t, char*, size_t, bool* enabled) {
    if (enabled) {
        *enabled = false;
    }
    return false;
}

void WiFiManager::saveWiFiCredentialsToConfig(const std::string&, const std::string&) {}
bool WiFiManager::configureSTANetworkSettings() { return false; }
bool WiFiManager::startSTA(const char*, const char*, bool) { return false; }

bool WiFiManager::startSTA(const std::string&, const std::string&, bool) {
    return false;
}

bool WiFiManager::connectSTA(const char*, const char*, int, bool) { return false; }
bool WiFiManager::connectSTA(const char*, const char*, int) { return false; }
bool WiFiManager::connectSTAKeepingAP(const char*, const char*, int) { return false; }

bool WiFiManager::connectSTA(const std::string&, const std::string&, int) {
    return false;
}

bool WiFiManager::connectSTAKeepingAP(const std::string&, const std::string&, int) {
    return false;
}

bool WiFiManager::disconnect() { return true; }
bool WiFiManager::isSTAConnected() const { return false; }
bool WiFiManager::isAPActive() const { return false; }
void WiFiManager::startAP(const char*, const char*) {}
void WiFiManager::startAP(const std::string&, const std::string&) {}
void WiFiManager::stop() {}
void WiFiManager::disconnectAllAPClients() {}
void WiFiManager::stopAP() {}
bool WiFiManager::configureSTAStaticIP(const char*, const char*, const char*) { return false; }
std::string WiFiManager::getIP() const { return std::string(); }

bool WiFiManager::getIP(char* out, size_t out_sz) const {
    if (out && out_sz > 0) {
        out[0] = '\0';
    }
    return false;
}

#endif
