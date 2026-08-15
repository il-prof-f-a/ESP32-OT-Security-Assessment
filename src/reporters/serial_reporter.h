#pragma once

#include <string>
#include <queue>
#include <mutex>
#include <atomic>

// Forward declaration
struct cJSON;

extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "freertos/queue.h"
    #include "esp_log.h"
}

/**
 * SerialReporter - Simple output sink for serial console
 *
 * This reporter provides basic formatted output to the ESP32 serial console.
 * It serves as a simple sink for data formatted by the ReportingEngine.
 * All filtering and processing logic is handled by the ReportingEngine.
 *
 * Features:
 * - Non-blocking asynchronous output
 * - Rate limiting to prevent serial flooding
 * - Thread-safe queued output
 */
class SerialReporter {
public:
    struct Config {
        bool enabled = true;
        uint32_t max_rate_per_sec = 50;  // Rate limiting
        uint32_t buffer_size = 512;      // Output buffer size
    };

    SerialReporter();
    virtual ~SerialReporter();

    // Simple output interface
    bool initialize();
    void shutdown();
    bool writeToSerial(const std::string& formatted_data);
    bool isHealthy() const;

    // Configuration management
    void setConfig(const Config& config);
    Config getConfig() const;

    // Statistics for monitoring
    struct Stats {
        uint64_t messages_processed = 0;
        uint64_t messages_rate_limited = 0;
        uint64_t output_lines = 0;
        uint32_t current_rate_per_sec = 0;
        bool is_enabled = false;
        uint32_t queue_size = 0;
    };
    Stats getStats() const;

private:
    // outputTaskThunk e outputTask rimossi - modalità sincrona

    bool checkRateLimit();

    // Configuration and state
    Config config_;
    mutable std::mutex config_mutex_;

    // Synchronous output - nessuna coda né task asincroni
    std::atomic<bool> shutdown_requested_{false};

    // Statistics and rate limiting
    mutable std::mutex stats_mutex_;
    Stats stats_;
    uint64_t last_rate_check_ms_ = 0;
    uint32_t current_second_count_ = 0;

    static constexpr const char* TAG = "SerialReporter";
    static constexpr size_t OUTPUT_TASK_STACK_SIZE = 3072;
    static constexpr UBaseType_t OUTPUT_TASK_PRIORITY = 4;
    static constexpr TickType_t QUEUE_TIMEOUT_MS = 100;
};