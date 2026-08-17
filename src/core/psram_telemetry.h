/**
 * @file psram_telemetry.h
 * @brief Advanced PSRAM/DRAM telemetry and monitoring system
 *
 * Provides detailed metrics on PSRAM and Internal RAM memory usage:
 * - Real-time monitoring with periodic updates
 * - Automatic watchdog for low-memory conditions
 * - Aggregate statistics (min/max/avg)
 * - API for the Web UI dashboard
 *
 * @date 2025-10-29
 * @version 1.0
 */

#pragma once

#include <cstdint>
#include <atomic>
#include "psram_allocator.h"

extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "esp_heap_caps.h"
    #include "esp_timer.h"
}

/**
 * @brief Instantaneous PSRAM/DRAM memory metrics
 */
struct PSRAMMetrics {
    // PSRAM
    size_t psram_total;
    size_t psram_free;
    size_t psram_used;
    uint8_t psram_used_percent;
    size_t psram_largest_block;

    // Internal DRAM
    size_t dram_total;
    size_t dram_free;
    size_t dram_used;
    uint8_t dram_used_percent;
    size_t dram_largest_block;
    uint8_t dram_fragmentation_percent;

    // Allocation counters (approximate)
    uint32_t alloc_count_estimate;
    uint32_t dealloc_count_estimate;

    // State flags
    bool critical_dram;  // < 10KB free
    bool warning_dram;   // < 30KB free
    bool psram_available;

    // Timestamp
    uint64_t timestamp_ms;

    PSRAMMetrics() : psram_total(0), psram_free(0), psram_used(0), psram_used_percent(0),
                     psram_largest_block(0), dram_total(0), dram_free(0), dram_used(0),
                     dram_used_percent(0), dram_largest_block(0), dram_fragmentation_percent(0),
                     alloc_count_estimate(0), dealloc_count_estimate(0),
                     critical_dram(false), warning_dram(false), psram_available(false),
                     timestamp_ms(0) {}
};

/**
 * @brief Aggregate memory statistics (min/max/avg)
 */
struct PSRAMStats {
    // DRAM stats
    size_t dram_free_min;
    size_t dram_free_max;
    size_t dram_free_avg;
    uint8_t dram_frag_min;
    uint8_t dram_frag_max;
    uint8_t dram_frag_avg;

    // PSRAM stats
    size_t psram_free_min;
    size_t psram_free_max;
    size_t psram_free_avg;

    // Event counters
    uint32_t updates_count;
    uint32_t critical_events;
    uint32_t warning_events;

    PSRAMStats() : dram_free_min(SIZE_MAX), dram_free_max(0), dram_free_avg(0),
                   dram_frag_min(100), dram_frag_max(0), dram_frag_avg(0),
                   psram_free_min(SIZE_MAX), psram_free_max(0), psram_free_avg(0),
                   updates_count(0), critical_events(0), warning_events(0) {}
};

/**
 * @brief Singleton class for advanced PSRAM telemetry
 *
 * Provides periodic memory monitoring with aggregate statistics,
 * automatic watchdog, and API for exporting metrics.
 *
 * Utilizzo:
 * ```cpp
 * // Initialization (once only)
 * PSRAMTelemetry::getInstance().initialize(60000); // Update every 60s
 *
 * // Enable watchdog
 * PSRAMTelemetry::getInstance().enableWatchdog(15000); // Alert se DRAM < 15KB
 *
 * // Get current metrics
 * PSRAMMetrics metrics = PSRAMTelemetry::getInstance().getMetrics();
 * ESP_LOGI("APP", "DRAM free: %u KB", metrics.dram_free / 1024);
 *
 * // Get aggregate statistics
 * PSRAMStats stats = PSRAMTelemetry::getInstance().getStats();
 * ESP_LOGI("APP", "DRAM free min: %u bytes", stats.dram_free_min);
 * ```
 */
class PSRAMTelemetry {
public:
    /**
     * @brief Get the singleton instance
     */
    static PSRAMTelemetry& getInstance() {
        static PSRAMTelemetry instance;
        return instance;
    }

    // Delete copy/move
    PSRAMTelemetry(const PSRAMTelemetry&) = delete;
    PSRAMTelemetry& operator=(const PSRAMTelemetry&) = delete;
    PSRAMTelemetry(PSRAMTelemetry&&) = delete;
    PSRAMTelemetry& operator=(PSRAMTelemetry&&) = delete;

    /**
     * @brief Initialize telemetry with periodic updates
     *
     * @param update_interval_ms Metrics update interval (default: 60000 = 60s)
     * @return true if initialization succeeded
     */
    bool initialize(uint32_t update_interval_ms = 60000);

    /**
     * @brief Shutdown telemetry
     */
    void shutdown();

    /**
     * @brief Manual metrics update (without waiting for the interval)
     */
    void updateNow();

    /**
     * @brief Get current metrics
     *
     * @return Snapshot of instantaneous metrics
     */
    PSRAMMetrics getMetrics() const;

    /**
     * @brief Get aggregate statistics
     *
     * @return Min/max/avg statistics since initialization
     */
    PSRAMStats getStats() const;

    /**
     * @brief Reset aggregate statistics
     */
    void resetStats();

    /**
     * @brief Log current metrics
     *
     * @param context Context string to identify the log
     */
    void logMetrics(const char* context = "PSRAMTelemetry") const;

    /**
     * @brief Enable automatic watchdog
     *
     * When enabled, logs WARNING/ERROR automatically
     * if DRAM free drops below the threshold.
     *
     * @param threshold_bytes DRAM threshold in bytes (default: 15000)
     */
    void enableWatchdog(size_t threshold_bytes = 15000);

    /**
     * @brief Disable watchdog
     */
    void disableWatchdog();

    /**
     * @brief Check whether the watchdog is enabled
     */
    bool isWatchdogEnabled() const { return watchdog_enabled_; }

    /**
     * @brief Get the current watchdog threshold
     */
    size_t getWatchdogThreshold() const { return watchdog_threshold_; }

private:
    PSRAMTelemetry();
    ~PSRAMTelemetry();

    // Worker task for periodic updates
    static void telemetryTask(void* pvParameters);

    // Internal metrics update
    void updateMetrics();

    // Check watchdog
    void checkWatchdog();

    // Members
    PSRAMMetrics current_metrics_;
    PSRAMStats stats_;

    TaskHandle_t task_handle_;
    uint32_t update_interval_ms_;
    bool initialized_;

    std::atomic<bool> watchdog_enabled_;
    size_t watchdog_threshold_;
    uint64_t last_watchdog_alert_ms_;

    mutable portMUX_TYPE metrics_mutex_;
};
