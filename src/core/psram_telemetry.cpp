/**
 * @file psram_telemetry.cpp
 * @brief Implementazione sistema telemetria PSRAM/DRAM
 * @date 2025-10-29
 */

#include "psram_telemetry.h"
#include "esp_log.h"
#include <cstring>
#include <algorithm>

static const char* TAG = "PSRAMTelemetry";

// Soglie di warning/critical (configurabili via watchdog)
#define DEFAULT_CRITICAL_THRESHOLD 10240   // 10KB
#define DEFAULT_WARNING_THRESHOLD  30720   // 30KB
#define WATCHDOG_ALERT_COOLDOWN_MS 30000   // 30s tra alert consecutivi

PSRAMTelemetry::PSRAMTelemetry()
    : task_handle_(nullptr)
    , update_interval_ms_(60000)
    , initialized_(false)
    , watchdog_enabled_(false)
    , watchdog_threshold_(15000)
    , last_watchdog_alert_ms_(0)
{
    metrics_mutex_ = portMUX_INITIALIZER_UNLOCKED;
}

PSRAMTelemetry::~PSRAMTelemetry() {
    shutdown();
}

bool PSRAMTelemetry::initialize(uint32_t update_interval_ms) {
    if (initialized_) {
        ESP_LOGW(TAG, "Already initialized");
        return true;
    }

    update_interval_ms_ = update_interval_ms;

    // Update iniziale metriche
    updateMetrics();

    // Spawn telemetry task
    BaseType_t ret = xTaskCreate(
        telemetryTask,
        "psram_telem",
        4096,
        this,
        5,  // Priority
        &task_handle_
    );

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create telemetry task");
        return false;
    }

    initialized_ = true;
    ESP_LOGI(TAG, "Initialized (update interval: %u ms)", update_interval_ms_);
    logMetrics("Initial");

    return true;
}

void PSRAMTelemetry::shutdown() {
    if (!initialized_) return;

    if (task_handle_) {
        vTaskDelete(task_handle_);
        task_handle_ = nullptr;
    }

    initialized_ = false;
    ESP_LOGI(TAG, "Shutdown complete");
}

void PSRAMTelemetry::telemetryTask(void* pvParameters) {
    PSRAMTelemetry* self = static_cast<PSRAMTelemetry*>(pvParameters);
    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xPeriod = pdMS_TO_TICKS(self->update_interval_ms_);

    ESP_LOGI(TAG, "Telemetry task started");

    while (true) {
        vTaskDelayUntil(&xLastWakeTime, xPeriod);

        // Update metriche
        self->updateMetrics();

        // Check watchdog se abilitato
        if (self->watchdog_enabled_.load()) {
            self->checkWatchdog();
        }
    }
}

void PSRAMTelemetry::updateMetrics() {
    portENTER_CRITICAL(&metrics_mutex_);

    // PSRAM
    current_metrics_.psram_total = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    current_metrics_.psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    current_metrics_.psram_used = current_metrics_.psram_total - current_metrics_.psram_free;
    current_metrics_.psram_largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    current_metrics_.psram_available = (current_metrics_.psram_total > 0);

    if (current_metrics_.psram_total > 0) {
        current_metrics_.psram_used_percent =
            (uint8_t)((current_metrics_.psram_used * 100) / current_metrics_.psram_total);
    } else {
        current_metrics_.psram_used_percent = 0;
    }

    // Internal DRAM
    current_metrics_.dram_total = heap_caps_get_total_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    current_metrics_.dram_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    current_metrics_.dram_used = current_metrics_.dram_total - current_metrics_.dram_free;
    current_metrics_.dram_largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);

    if (current_metrics_.dram_total > 0) {
        current_metrics_.dram_used_percent =
            (uint8_t)((current_metrics_.dram_used * 100) / current_metrics_.dram_total);
    } else {
        current_metrics_.dram_used_percent = 0;
    }

    // Frammentazione DRAM: (free - largest_block) / free * 100
    if (current_metrics_.dram_free > 0) {
        size_t fragmented = current_metrics_.dram_free - current_metrics_.dram_largest_block;
        current_metrics_.dram_fragmentation_percent =
            (uint8_t)((fragmented * 100) / current_metrics_.dram_free);
    } else {
        current_metrics_.dram_fragmentation_percent = 100;
    }

    // Flags stato
    current_metrics_.critical_dram = (current_metrics_.dram_free < DEFAULT_CRITICAL_THRESHOLD);
    current_metrics_.warning_dram = (current_metrics_.dram_free < DEFAULT_WARNING_THRESHOLD);

    // Timestamp
    current_metrics_.timestamp_ms = esp_timer_get_time() / 1000;

    // Stima allocazioni (non preciso, ma approssimativo)
    current_metrics_.alloc_count_estimate = 0;  // TODO: hook malloc se necessario
    current_metrics_.dealloc_count_estimate = 0;

    portEXIT_CRITICAL(&metrics_mutex_);

    // Update statistiche aggregate
    portENTER_CRITICAL(&metrics_mutex_);

    stats_.updates_count++;

    // DRAM stats
    stats_.dram_free_min = std::min(stats_.dram_free_min, current_metrics_.dram_free);
    stats_.dram_free_max = std::max(stats_.dram_free_max, current_metrics_.dram_free);
    stats_.dram_frag_min = std::min(stats_.dram_frag_min, current_metrics_.dram_fragmentation_percent);
    stats_.dram_frag_max = std::max(stats_.dram_frag_max, current_metrics_.dram_fragmentation_percent);

    // Calcolo running average per DRAM free
    if (stats_.updates_count == 1) {
        stats_.dram_free_avg = current_metrics_.dram_free;
        stats_.dram_frag_avg = current_metrics_.dram_fragmentation_percent;
    } else {
        // Exponential moving average (alpha = 0.1)
        stats_.dram_free_avg = (size_t)(0.9 * stats_.dram_free_avg + 0.1 * current_metrics_.dram_free);
        stats_.dram_frag_avg = (uint8_t)(0.9 * stats_.dram_frag_avg + 0.1 * current_metrics_.dram_fragmentation_percent);
    }

    // PSRAM stats
    if (current_metrics_.psram_available) {
        stats_.psram_free_min = std::min(stats_.psram_free_min, current_metrics_.psram_free);
        stats_.psram_free_max = std::max(stats_.psram_free_max, current_metrics_.psram_free);

        if (stats_.updates_count == 1) {
            stats_.psram_free_avg = current_metrics_.psram_free;
        } else {
            stats_.psram_free_avg = (size_t)(0.9 * stats_.psram_free_avg + 0.1 * current_metrics_.psram_free);
        }
    }

    // Contatori eventi
    if (current_metrics_.critical_dram) {
        stats_.critical_events++;
    }
    if (current_metrics_.warning_dram) {
        stats_.warning_events++;
    }

    portEXIT_CRITICAL(&metrics_mutex_);
}

void PSRAMTelemetry::updateNow() {
    updateMetrics();
    ESP_LOGI(TAG, "Manual update triggered");
}

PSRAMMetrics PSRAMTelemetry::getMetrics() const {
    PSRAMMetrics copy;
    portENTER_CRITICAL(&metrics_mutex_);
    copy = current_metrics_;
    portEXIT_CRITICAL(&metrics_mutex_);
    return copy;
}

PSRAMStats PSRAMTelemetry::getStats() const {
    PSRAMStats copy;
    portENTER_CRITICAL(&metrics_mutex_);
    copy = stats_;
    portEXIT_CRITICAL(&metrics_mutex_);
    return copy;
}

void PSRAMTelemetry::resetStats() {
    portENTER_CRITICAL(&metrics_mutex_);
    stats_ = PSRAMStats();
    portEXIT_CRITICAL(&metrics_mutex_);
    ESP_LOGI(TAG, "Statistics reset");
}

void PSRAMTelemetry::logMetrics(const char* context) const {
    PSRAMMetrics m = getMetrics();

    ESP_LOGI(TAG, "[%s] === Memory Telemetry ===", context);

    if (m.psram_available) {
        ESP_LOGI(TAG, "  PSRAM: %u KB free / %u KB total (%u%% used)",
                 m.psram_free / 1024, m.psram_total / 1024, m.psram_used_percent);
        ESP_LOGI(TAG, "  PSRAM largest block: %u KB", m.psram_largest_block / 1024);
    } else {
        ESP_LOGI(TAG, "  PSRAM: Not available");
    }

    ESP_LOGI(TAG, "  DRAM: %u KB free / %u KB total (%u%% used)",
             m.dram_free / 1024, m.dram_total / 1024, m.dram_used_percent);
    ESP_LOGI(TAG, "  DRAM largest block: %u KB", m.dram_largest_block / 1024);
    ESP_LOGI(TAG, "  DRAM fragmentation: %u%%", m.dram_fragmentation_percent);

    if (m.critical_dram) {
        ESP_LOGE(TAG, "  ⚠️  CRITICAL: DRAM < %u KB!", DEFAULT_CRITICAL_THRESHOLD / 1024);
    } else if (m.warning_dram) {
        ESP_LOGW(TAG, "  ⚠️  WARNING: DRAM < %u KB", DEFAULT_WARNING_THRESHOLD / 1024);
    }
}

void PSRAMTelemetry::enableWatchdog(size_t threshold_bytes) {
    watchdog_threshold_ = threshold_bytes;
    watchdog_enabled_.store(true);
    last_watchdog_alert_ms_ = 0;
    ESP_LOGI(TAG, "Watchdog enabled (threshold: %u bytes)", threshold_bytes);
}

void PSRAMTelemetry::disableWatchdog() {
    watchdog_enabled_.store(false);
    ESP_LOGI(TAG, "Watchdog disabled");
}

void PSRAMTelemetry::checkWatchdog() {
    PSRAMMetrics m = getMetrics();

    if (m.dram_free < watchdog_threshold_) {
        uint64_t now_ms = esp_timer_get_time() / 1000;

        // Rate limit: 1 alert ogni 30s
        if (now_ms - last_watchdog_alert_ms_ < WATCHDOG_ALERT_COOLDOWN_MS) {
            return;
        }

        last_watchdog_alert_ms_ = now_ms;

        if (m.dram_free < DEFAULT_CRITICAL_THRESHOLD) {
            ESP_LOGE(TAG, "🚨 WATCHDOG ALERT: CRITICAL DRAM free (%u bytes < %u threshold)",
                     m.dram_free, watchdog_threshold_);
            ESP_LOGE(TAG, "   Fragmentation: %u%%, Largest block: %u bytes",
                     m.dram_fragmentation_percent, m.dram_largest_block);
        } else {
            ESP_LOGW(TAG, "⚠️  WATCHDOG ALERT: Low DRAM free (%u bytes < %u threshold)",
                     m.dram_free, watchdog_threshold_);
            ESP_LOGW(TAG, "   Fragmentation: %u%%, Largest block: %u bytes",
                     m.dram_fragmentation_percent, m.dram_largest_block);
        }
    }
}
