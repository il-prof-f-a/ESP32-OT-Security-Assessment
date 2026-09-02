#pragma once

#include <cstdint>
#include <atomic>
#include "esp_task_wdt.h"

// Owned and called only by app_main. Configuration is applied at boot, while
// feeding follows the actual subscription, never a subsequently edited config.
// This class does not own/deinitialize the shared SDK TWDT or other tasks.
class MainTaskWatchdog {
public:
    static constexpr uint32_t normalizeTimeoutSeconds(uint32_t seconds) {
        // ESP-IDF's MWDT stage 1 multiplies timeout_ms by four (500 us ticks,
        // second stage at twice the timeout). Bound that conversion as well.
        constexpr uint32_t maximum = UINT32_MAX / 4000U;
        return seconds < 60U ? 60U : (seconds > maximum ? maximum : seconds);
    }

    // The configuration editor can save a new value while the device is
    // running.  The SDK watchdog deliberately keeps using its boot-time
    // configuration until restart, so expose an immutable runtime snapshot.
    static void recordBootConfiguration(bool enabled,
                                        uint32_t requested_timeout_seconds,
                                        uint32_t effective_timeout_seconds,
                                        bool panic_on_timeout,
                                        bool monitor_idle_cores) {
        boot_enabled_.store(enabled, std::memory_order_relaxed);
        boot_requested_timeout_seconds_.store(requested_timeout_seconds,
                                              std::memory_order_relaxed);
        boot_effective_timeout_seconds_.store(effective_timeout_seconds,
                                              std::memory_order_relaxed);
        boot_panic_on_timeout_.store(panic_on_timeout, std::memory_order_relaxed);
        boot_monitor_idle_cores_.store(monitor_idle_cores, std::memory_order_relaxed);
        boot_configuration_recorded_.store(true, std::memory_order_release);
    }

    static bool hasBootConfiguration() {
        return boot_configuration_recorded_.load(std::memory_order_acquire);
    }

    static bool bootEnabled() {
        return boot_enabled_.load(std::memory_order_relaxed);
    }

    static uint32_t bootRequestedTimeoutSeconds() {
        return boot_requested_timeout_seconds_.load(std::memory_order_relaxed);
    }

    static uint32_t bootEffectiveTimeoutSeconds() {
        return boot_effective_timeout_seconds_.load(std::memory_order_relaxed);
    }

    static bool bootPanicOnTimeout() {
        return boot_panic_on_timeout_.load(std::memory_order_relaxed);
    }

    static bool bootMonitorIdleCores() {
        return boot_monitor_idle_cores_.load(std::memory_order_relaxed);
    }

    esp_err_t configure(const esp_task_wdt_config_t& config) {
        esp_err_t result = esp_task_wdt_reconfigure(&config);
        if (result == ESP_ERR_INVALID_STATE) {
            // Some SDK builds do not auto-initialize the TWDT. Do not call
            // init for unrelated errors or tear down an existing watchdog.
            result = esp_task_wdt_init(&config);
        }
        configured_ = result == ESP_OK;
        return result;
    }

    esp_err_t start(bool enabled, uint32_t now_seconds) {
        last_feed_attempt_ = now_seconds;
        const esp_err_t status = esp_task_wdt_status(nullptr);
        subscribed_ = status == ESP_OK;
        if (status != ESP_OK && status != ESP_ERR_NOT_FOUND &&
            status != ESP_ERR_INVALID_STATE) {
            return status;
        }
        if (!enabled) {
            if (!subscribed_) return ESP_OK;
            const esp_err_t result = esp_task_wdt_delete(nullptr);
            if (result == ESP_OK) {
                subscribed_ = false;
            } else {
                reconcileSubscription();
            }
            return result;
        }
        if (subscribed_) return ESP_OK; // Do not double-register the task.
        if (!configured_) return ESP_ERR_INVALID_STATE;
        const esp_err_t result = esp_task_wdt_add(nullptr);
        if (result == ESP_OK) {
            subscribed_ = true;
        } else {
            reconcileSubscription();
        }
        return result;
    }

    bool subscribed() const { return subscribed_; }

    // Remove this task from the shared watchdog during startup rollback.  The
    // watchdog itself remains owned by ESP-IDF and is not deinitialized here.
    esp_err_t stop() {
        if (!subscribed_) return ESP_OK;
        const esp_err_t result = esp_task_wdt_delete(nullptr);
        if (result == ESP_OK || result == ESP_ERR_NOT_FOUND || result == ESP_ERR_INVALID_STATE) {
            subscribed_ = false;
        }
        return result;
    }

    // Returns false without modifying result when no feed was attempted.
    bool feedIfDue(uint32_t now_seconds, esp_err_t& result) {
        // If configuration/removal failed with an existing subscription, its
        // timeout may be the SDK default: keep feeding once per main-loop tick.
        const uint32_t interval = configured_ ? 10U : 1U;
        if (!subscribed_ || uint32_t(now_seconds - last_feed_attempt_) < interval) {
            return false;
        }
        last_feed_attempt_ = now_seconds;
        result = esp_task_wdt_reset();
        if (result != ESP_OK) reconcileSubscription();
        return true;
    }

private:
    void reconcileSubscription() {
        const esp_err_t status = esp_task_wdt_status(nullptr);
        if (status == ESP_OK) subscribed_ = true;
        else if (status == ESP_ERR_NOT_FOUND || status == ESP_ERR_INVALID_STATE) subscribed_ = false;
        // An unknown query error must not abandon a known subscription.
    }

    bool configured_ = false;
    bool subscribed_ = false;
    uint32_t last_feed_attempt_ = 0;

    inline static std::atomic<bool> boot_configuration_recorded_{false};
    inline static std::atomic<bool> boot_enabled_{false};
    inline static std::atomic<uint32_t> boot_requested_timeout_seconds_{0};
    inline static std::atomic<uint32_t> boot_effective_timeout_seconds_{0};
    inline static std::atomic<bool> boot_panic_on_timeout_{false};
    inline static std::atomic<bool> boot_monitor_idle_cores_{false};
};
