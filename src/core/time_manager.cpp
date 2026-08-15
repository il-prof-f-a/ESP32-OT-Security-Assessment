#include "time_manager.h"
#include "logging_system.h"
#include "network/wifi_manager.h"

#include <cstring>
#include <cstdlib>

extern "C" {
    #include "freertos/task.h"
    #include "esp_err.h"
    #include "esp_netif.h"
    #include <sys/time.h>
    #include "cJSON.h"
}

// Static member definitions
time_t TimeManager::base_time_ = 0;
uint64_t TimeManager::base_millis_ = 0;
bool TimeManager::synchronized_ = false;
bool TimeManager::last_sync_success_ = false;
TimeManager::SyncMethod TimeManager::sync_method_ = SyncMethod::NTP;
psram_string TimeManager::ntp_primary_;
psram_string TimeManager::ntp_secondary_;
psram_string TimeManager::ntp_tertiary_;
psram_string TimeManager::http_time_url_;
TimerHandle_t TimeManager::sync_timer_ = nullptr;
volatile bool TimeManager::ntp_sync_done_ = false;
psram_string TimeManager::http_response_buffer_;
ConfigurationManager* TimeManager::config_ctx_ = nullptr;
WiFiManager* TimeManager::wifi_ctx_ = nullptr;
esp_event_handler_instance_t TimeManager::wifi_handler_ = nullptr;
bool TimeManager::periodic_timer_started_ = false;
portMUX_TYPE TimeManager::sync_spinlock_ = portMUX_INITIALIZER_UNLOCKED;
volatile uint8_t TimeManager::pending_triggers_ = 0;
esp_netif_t* TimeManager::last_synced_netif_ = nullptr;

void TimeManager::markSyncPending(uint8_t trigger_mask) {
    portENTER_CRITICAL(&sync_spinlock_);
    pending_triggers_ |= trigger_mask;
    portEXIT_CRITICAL(&sync_spinlock_);
}

bool TimeManager::netifHasIPv4(esp_netif_t* netif) {
    if (!netif) {
        return false;
    }

    esp_netif_ip_info_t ip_info{};
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
        return false;
    }

    return ip_info.ip.addr != 0;
}

void TimeManager::handleWiFiEvent(void* arg, esp_event_base_t base, int32_t id, void* event_data) {
    (void)arg;
    (void)event_data;

    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        markSyncPending(SYNC_TRIGGER_WIFI_EVENT);
    }
}

void TimeManager::configureWiFiAutoSync(ConfigurationManager* cfg, WiFiManager* wifi) {
    config_ctx_ = cfg;
    wifi_ctx_ = wifi;

    portENTER_CRITICAL(&sync_spinlock_);
    pending_triggers_ = 0;
    portEXIT_CRITICAL(&sync_spinlock_);

    if (wifi_ctx_ && !wifi_handler_) {
        esp_err_t res = esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &TimeManager::handleWiFiEvent, nullptr, &wifi_handler_);
        if (res != ESP_OK && res != ESP_ERR_INVALID_STATE) {
            LOG_WARNINGF("TimeManager", "Failed to register WiFi IP handler: %s", esp_err_to_name(res));
            wifi_handler_ = nullptr;
        }
    }

    if (wifi_ctx_) {
        esp_netif_t* wifi_netif = wifi_ctx_->sta();
        if (netifHasIPv4(wifi_netif)) {
            markSyncPending(SYNC_TRIGGER_WIFI_IMMEDIATE);
        }
    }
}

void TimeManager::notifyWiFiHasIP() {
    markSyncPending(SYNC_TRIGGER_WIFI_IMMEDIATE);
}

void TimeManager::processPendingSync() {
    uint8_t triggers;
    portENTER_CRITICAL(&sync_spinlock_);
    triggers = pending_triggers_;
    pending_triggers_ = 0;
    portEXIT_CRITICAL(&sync_spinlock_);

    if (!triggers) {
        return;
    }

    if (triggers & (SYNC_TRIGGER_WIFI_EVENT | SYNC_TRIGGER_WIFI_IMMEDIATE)) {
        const char* origin = (triggers & SYNC_TRIGGER_WIFI_EVENT) ? "WiFi STA event" : "WiFi STA immediate";
        esp_netif_t* wifi_netif = (wifi_ctx_) ? wifi_ctx_->sta() : nullptr;
        runTimeSyncOnNetif(wifi_netif, origin);
    }

    if (triggers & SYNC_TRIGGER_PERIODIC) {
        esp_netif_t* target = last_synced_netif_;
        if (!netifHasIPv4(target) && wifi_ctx_) {
            target = wifi_ctx_->sta();
        }

        bool success = runTimeSyncOnNetif(target, "Periodic timer");
        if (!success && config_ctx_) {
            if (!synchronized_) {
                success = TimeManager::initialize(config_ctx_->getNetworkConfig());
            } else {
                success = TimeManager::syncTime();
            }

            if (!success) {
                LOG_WARNING("TimeManager", "Periodic timer sync fallback failed");
            }
        }
    }
}

void TimeManager::requestSyncForNetif(esp_netif_t* netif, const char* origin) {
    if (!runTimeSyncOnNetif(netif, origin)) {
        LOG_WARNINGF("TimeManager", "Unable to synchronize time for interface (%s)", origin ? origin : "manual");
    }
}

bool TimeManager::initialize(const NetworkConfig& config) {
    LOG_INFO("TimeManager", "Initializing time synchronization system");

    applyTimezone(config);

    if (config.time_sync.empty() || strcmp(config.time_sync.c_str(), "ntp") == 0) {
        sync_method_ = SyncMethod::NTP;
        ntp_primary_ = config.ntp_primary.empty() ? PSRAMUtils::createPSRAMString("pool.ntp.org") : config.ntp_primary;
        ntp_secondary_ = config.ntp_secondary.empty() ? PSRAMUtils::createPSRAMString("time.nist.gov") : config.ntp_secondary;
        ntp_tertiary_ = config.ntp_tertiary.empty() ? PSRAMUtils::createPSRAMString("time.google.com") : config.ntp_tertiary;
        LOG_INFOF("TimeManager", "Using NTP sync with primary: %s", ntp_primary_.c_str());
    } else if (strcmp(config.time_sync.c_str(), "http") == 0) {
        sync_method_ = SyncMethod::HTTP;
        http_time_url_ = config.http_time_sync.empty() ? PSRAMUtils::createPSRAMString("http://worldtimeapi.org/api/timezone/Europe/Rome") : config.http_time_sync;
        LOG_INFOF("TimeManager", "Using HTTP sync with URL: %s", http_time_url_.c_str());
    } else {
        LOG_ERRORF("TimeManager", "Invalid time_sync method: %s", config.time_sync.c_str());
        return false;
    }

    if (!syncTime()) {
        LOG_WARNING("TimeManager", "Initial time synchronization failed");
        return false;
    }

    if (!periodic_timer_started_) {
        startPeriodicSync();
    }

    LOG_INFO("TimeManager", "Time synchronization initialized successfully");
    return true;
}

void TimeManager::applyTimezone(const NetworkConfig& config) {
    (void)config;
    setenv("TZ", "CET-1CEST,M3.5.0/2,M10.5.0/3", 1);
    tzset();
}

time_t TimeManager::getCurrentTime() {
    if (!synchronized_) {
        return time(nullptr);
    }

    uint64_t current_millis = esp_timer_get_time() / 1000ULL;
    uint64_t elapsed_millis = current_millis - base_millis_;
    return base_time_ + static_cast<time_t>(elapsed_millis / 1000ULL);
}

uint64_t TimeManager::getCurrentTimeMs() {
    if (!synchronized_) {
        return esp_timer_get_time() / 1000ULL;
    }

    uint64_t current_millis = esp_timer_get_time() / 1000ULL;
    uint64_t elapsed_millis = current_millis - base_millis_;
    return (static_cast<uint64_t>(base_time_) * 1000ULL) + elapsed_millis;
}

bool TimeManager::syncTime() {
    LOG_INFO("TimeManager", "Starting time synchronization");

    bool success = false;
    if (sync_method_ == SyncMethod::HTTP) {
        success = syncViaHTTP(http_time_url_);
    } else {
        success = syncViaNTP(ntp_primary_, ntp_secondary_, ntp_tertiary_);
    }

    last_sync_success_ = success;
    if (success) {
        synchronized_ = true;
        LOG_INFOF("TimeManager", "Time synchronized successfully via %s", (sync_method_ == SyncMethod::HTTP) ? "HTTP" : "NTP");
    } else {
        LOG_ERRORF("TimeManager", "Time synchronization failed via %s", (sync_method_ == SyncMethod::HTTP) ? "HTTP" : "NTP");
    }

    return success;
}

void TimeManager::startPeriodicSync() {
    if (sync_timer_ != nullptr) {
        periodic_timer_started_ = true;
        return;
    }

    sync_timer_ = xTimerCreate(
        "time_sync_timer",
        pdMS_TO_TICKS(30UL * 60UL * 1000UL),
        pdTRUE,
        nullptr,
        periodicSyncCallback
    );

    if (sync_timer_ != nullptr && xTimerStart(sync_timer_, 0) == pdPASS) {
        periodic_timer_started_ = true;
        LOG_INFO("TimeManager", "Periodic sync timer started (30 minutes interval)");
    } else {
        LOG_ERROR("TimeManager", "Failed to start periodic sync timer");
    }
}

void TimeManager::stopPeriodicSync() {
    if (sync_timer_ != nullptr) {
        xTimerStop(sync_timer_, 0);
        xTimerDelete(sync_timer_, 0);
        sync_timer_ = nullptr;
        periodic_timer_started_ = false;
        LOG_INFO("TimeManager", "Periodic sync timer stopped");
    }
}

bool TimeManager::isSynchronized() {
    return synchronized_;
}

bool TimeManager::getLastSyncSuccess() {
    return last_sync_success_;
}

bool TimeManager::runTimeSyncOnNetif(esp_netif_t* netif, const char* origin) {
    const char* label = origin ? origin : "unknown";

    if (!config_ctx_) {
        LOG_WARNING("TimeManager", "No configuration context available for time synchronization");
        return false;
    }

    if (!netifHasIPv4(netif)) {
        LOG_WARNINGF("TimeManager", "Network interface not ready for time sync (%s)", label);
        return false;
    }

    esp_err_t set_res = esp_netif_set_default_netif(netif);
    if (set_res == ESP_OK) {
        LOG_INFOF("TimeManager", "Interface set as default for SNTP (%s)", label);
    } else if (set_res != ESP_ERR_INVALID_STATE) {
        LOG_WARNINGF("TimeManager", "Failed to set default netif (%s): %s", label, esp_err_to_name(set_res));
    }

    bool success = false;
    if (!synchronized_) {
        success = TimeManager::initialize(config_ctx_->getNetworkConfig());
    } else {
        success = TimeManager::syncTime();
    }

    if (success) {
        last_synced_netif_ = netif;
        time_t current_time = TimeManager::getCurrentTime();
        LOG_INFOF("TimeManager", "Time sync completed (%s): %s", label, ctime(&current_time));
    } else {
        LOG_WARNINGF("TimeManager", "Time synchronization attempt failed (%s)", label);
    }

    return success;
}

bool TimeManager::syncViaHTTP(const psram_string& url) {
    LOG_INFOF("TimeManager", "Attempting HTTP time sync from: %s", url.c_str());

    const int max_retries = 20;
    const int timeout_ms = 3000;

    for (int attempt = 1; attempt <= max_retries; attempt++) {
        LOG_INFOF("TimeManager", "HTTP sync attempt %d/%d", attempt, max_retries);

        http_response_buffer_.clear();

        esp_http_client_config_t config = {};
        config.url = url.c_str();
        config.event_handler = httpEventHandler;
        config.timeout_ms = timeout_ms;
        config.buffer_size = 1024;
        config.buffer_size_tx = 512;

        esp_http_client_handle_t client = esp_http_client_init(&config);
        if (client == nullptr) {
            LOG_ERRORF("TimeManager", "Failed to initialize HTTP client (attempt %d)", attempt);
            if (attempt < max_retries) {
                LOG_INFO("TimeManager", "Retrying in 2 seconds...");
                vTaskDelay(pdMS_TO_TICKS(2000));
                continue;
            }
            return false;
        }

        esp_err_t err = esp_http_client_perform(client);
        int status_code = esp_http_client_get_status_code(client);
        esp_http_client_cleanup(client);

        if (err != ESP_OK) {
            LOG_ERRORF("TimeManager", "HTTP request failed (attempt %d): %s", attempt, esp_err_to_name(err));
            if (attempt < max_retries) {
                LOG_INFO("TimeManager", "Retrying in 3 seconds...");
                vTaskDelay(pdMS_TO_TICKS(3000));
                continue;
            }
            return false;
        }

        if (status_code != 200) {
            LOG_ERRORF("TimeManager", "HTTP request returned status %d (attempt %d)", status_code, attempt);
            if (attempt < max_retries) {
                LOG_INFO("TimeManager", "Retrying in 3 seconds...");
                vTaskDelay(pdMS_TO_TICKS(3000));
                continue;
            }
            return false;
        }

        if (http_response_buffer_.empty()) {
            LOG_ERRORF("TimeManager", "Empty HTTP response (attempt %d)", attempt);
            if (attempt < max_retries) {
                LOG_INFO("TimeManager", "Retrying in 2 seconds...");
                vTaskDelay(pdMS_TO_TICKS(2000));
                continue;
            }
            return false;
        }

        time_t timestamp = parseHttpTimeResponse(http_response_buffer_.c_str());
        if (timestamp <= 0) {
            LOG_ERRORF("TimeManager", "Invalid timestamp in HTTP response (attempt %d)", attempt);
            if (attempt < max_retries) {
                LOG_INFO("TimeManager", "Retrying in 2 seconds...");
                vTaskDelay(pdMS_TO_TICKS(2000));
                continue;
            }
            return false;
        }

        return setSystemTime(timestamp);
    }

    LOG_ERROR("TimeManager", "HTTP time sync failed after all retries");
    return false;
}

bool TimeManager::syncViaNTP(const psram_string& primary, const psram_string& secondary, const psram_string& tertiary) {
    LOG_INFOF("TimeManager", "Attempting NTP sync with servers: %s, %s, %s", primary.c_str(), secondary.c_str(), tertiary.c_str());

    esp_sntp_stop();
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_set_sync_mode(SNTP_SYNC_MODE_IMMED);
    esp_sntp_set_sync_interval(30UL * 60UL * 1000UL);
    esp_sntp_set_time_sync_notification_cb(ntpSyncCallback);

    esp_sntp_setservername(0, primary.c_str());
    if (!secondary.empty()) {
        esp_sntp_setservername(1, secondary.c_str());
    }
    if (!tertiary.empty()) {
        esp_sntp_setservername(2, tertiary.c_str());
    }

    ntp_sync_done_ = false;
    esp_sntp_init();

    const int max_wait_ms = 30000;
    const int check_interval_ms = 1000;
    int elapsed = 0;

    while (!ntp_sync_done_ && elapsed < max_wait_ms) {
        vTaskDelay(pdMS_TO_TICKS(check_interval_ms));
        elapsed += check_interval_ms;

        sntp_sync_status_t status = esp_sntp_get_sync_status();
        LOG_INFOF("TimeManager", "NTP sync progress: %d seconds, status: %d", elapsed / 1000, (int)status);
    }

    if (!ntp_sync_done_) {
        LOG_ERRORF("TimeManager", "NTP synchronization timeout after %d seconds", max_wait_ms / 1000);
        return false;
    }

    time_t now = time(nullptr);
    return setSystemTime(now);
}

esp_err_t TimeManager::httpEventHandler(esp_http_client_event_t *evt) {
    if (evt->event_id == HTTP_EVENT_ON_DATA && evt->data_len > 0) {
        http_response_buffer_.append(static_cast<const char*>(evt->data), evt->data_len);
    } else if (evt->event_id == HTTP_EVENT_ERROR) {
        LOG_ERROR("TimeManager", "HTTP event error during time sync");
    }

    return ESP_OK;
}

void TimeManager::ntpSyncCallback(struct timeval *tv) {
    (void)tv;
    ntp_sync_done_ = true;
}

void TimeManager::periodicSyncCallback(TimerHandle_t) {
    markSyncPending(SYNC_TRIGGER_PERIODIC);
}

bool TimeManager::setSystemTime(time_t timestamp) {
    if (timestamp <= 0) {
        LOG_ERRORF("TimeManager", "Invalid timestamp: %ld", timestamp);
        return false;
    }

    struct timeval tv;
    tv.tv_sec = timestamp;
    tv.tv_usec = 0;

    if (settimeofday(&tv, nullptr) != 0) {
        LOG_ERROR("TimeManager", "Failed to set system time");
        return false;
    }

    base_time_ = timestamp;
    base_millis_ = esp_timer_get_time() / 1000ULL;

    struct tm timeinfo;
    localtime_r(&timestamp, &timeinfo);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);

    LOG_INFOF("TimeManager", "System time set to: %s (timestamp: %ld)", time_str, timestamp);
    return true;
}

time_t TimeManager::parseHttpTimeResponse(const char* response_data) {
    if (response_data == nullptr) {
        LOG_ERROR("TimeManager", "Null response data");
        return 0;
    }

    if (response_data[0] == '{') {
        cJSON* root = cJSON_Parse(response_data);
        if (root == nullptr) {
            LOG_ERROR("TimeManager", "Failed to parse JSON response");
            return 0;
        }

        time_t timestamp = 0;
        cJSON* unixtime = cJSON_GetObjectItem(root, "unixtime");
        if (unixtime && cJSON_IsNumber(unixtime)) {
            timestamp = static_cast<time_t>(cJSON_GetNumberValue(unixtime));
        } else {
            cJSON* ts_field = cJSON_GetObjectItem(root, "timestamp");
            if (ts_field && cJSON_IsNumber(ts_field)) {
                timestamp = static_cast<time_t>(cJSON_GetNumberValue(ts_field));
            }
        }

        cJSON_Delete(root);
        return timestamp;
    }

    const char* line = response_data;
    while (line && *line) {
        const char* line_end = strchr(line, '\n');
        size_t line_len = line_end ? static_cast<size_t>(line_end - line) : strlen(line);

        if (line_len >= 9 && strncmp(line, "unixtime:", 9) == 0) {
            const char* value_start = line + 9;
            while (*value_start == ' ' || *value_start == '\t') {
                ++value_start;
            }
            return static_cast<time_t>(atol(value_start));
        }

        if (!line_end) {
            break;
        }
        line = line_end + 1;
    }

    LOG_ERROR("TimeManager", "No unixtime found in text response");
    return 0;
}
