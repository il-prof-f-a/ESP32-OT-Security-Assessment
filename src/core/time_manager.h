#pragma once
#include <ctime>
#include <cstdint>

#include "psram_allocator.h"
#include "types.h"
#include "configuration_manager.h"

class WiFiManager;

extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/timers.h"
    #include "freertos/portmacro.h"
    #include "esp_timer.h"
    #include "esp_sntp.h"
    #include "esp_event.h"
    #include "esp_http_client.h"
    #include "esp_netif.h"
}

class TimeManager {
public:
    enum class SyncMethod {
        NTP,
        HTTP
    };

    static bool initialize(const NetworkConfig& config);
    static void configureWiFiAutoSync(ConfigurationManager* cfg, WiFiManager* wifi);
    // Drop startup-time references before app_main returns on a failed boot.
    // This unregisters the event callback and prevents a later event from
    // dereferencing automatic ConfigurationManager/WiFiManager objects.
    static void clearWiFiAutoSync();
    static void notifyWiFiHasIP();
    static void processPendingSync();
    static void requestSyncForNetif(esp_netif_t* netif, const char* origin);

    static time_t getCurrentTime();
    static uint64_t getCurrentTimeMs();
    static bool syncTime();
    static void startPeriodicSync();
    static void stopPeriodicSync();
    static bool isSynchronized();
    static bool getLastSyncSuccess();

private:
    static void applyTimezone(const NetworkConfig& config);
    static bool configureSntpOnce();
    static bool triggerNtpSync();
    static bool triggerHttpSync();
    static void httpSyncTask(void* arg);
    static bool syncViaHTTP(const psram_string& url);
    static esp_err_t httpEventHandler(esp_http_client_event_t *evt);
    static void ntpSyncCallback(struct timeval *tv);
    static void periodicSyncCallback(TimerHandle_t xTimer);
    static bool setSystemTime(time_t timestamp);
    static time_t parseHttpTimeResponse(const char* json_data);

    enum SyncTrigger : uint8_t {
        SYNC_TRIGGER_WIFI_EVENT     = 1u << 0,
        SYNC_TRIGGER_WIFI_IMMEDIATE = 1u << 1,
        SYNC_TRIGGER_PERIODIC       = 1u << 2
    };

    static void markSyncPending(uint8_t trigger_mask);
    static bool runTimeSyncOnNetif(esp_netif_t* netif, const char* origin);
    static bool netifHasIPv4(esp_netif_t* netif);
    static void handleWiFiEvent(void* arg, esp_event_base_t base, int32_t id, void* event_data);

    static volatile time_t base_time_;
    static volatile uint64_t base_millis_;
    static volatile bool synchronized_;
    static volatile bool last_sync_success_;
    static SyncMethod sync_method_;
    static psram_string ntp_primary_;
    static psram_string ntp_secondary_;
    static psram_string ntp_tertiary_;
    static psram_string http_time_url_;
    static TimerHandle_t sync_timer_;
    static bool sntp_initialized_;
    static volatile bool http_sync_in_progress_;
    static psram_string http_response_buffer_;

    static ConfigurationManager* config_ctx_;
    static WiFiManager* wifi_ctx_;
    static esp_event_handler_instance_t wifi_handler_;
    static bool periodic_timer_started_;
    static portMUX_TYPE sync_spinlock_;
    static volatile uint8_t pending_triggers_;
    static esp_netif_t* last_synced_netif_;
};
