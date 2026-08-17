#include "serial_reporter.h"
#include "../core/event_formatter.h"
#include "../core/logging_system.h"
#include "cJSON.h"

extern "C" {
    #include "esp_timer.h"
    #include <time.h>
    #include <sys/time.h>
}

#include <sstream>
#include <iomanip>
#include <algorithm>

static const char* TAG __attribute__((unused)) = "SerialReporter";

SerialReporter::SerialReporter() {
    // Initialize with default configuration
    config_ = Config();

    // Initialize statistics
    stats_ = {};
    stats_.is_enabled = config_.enabled;
}

SerialReporter::~SerialReporter() {
    shutdown();
}

bool SerialReporter::initialize() {
    LOG_INFO(TAG, "Initializing SerialReporter (synchronous mode)");

    // Synchronous mode - no queue or task needed
    // Initialization simply completed

    LOG_INFO(TAG, "SerialReporter initialized successfully (synchronous)");
    return true;
}

void SerialReporter::shutdown() {
    LOG_INFO(TAG, "Shutting down SerialReporter");

    // Synchronous mode - there is nothing to stop
    shutdown_requested_ = true;

    LOG_INFO(TAG, "SerialReporter shutdown complete (synchronous)");
}

bool SerialReporter::writeToSerial(const std::string& formatted_data) {
    // Direct synchronous write with thread-safety
    std::lock_guard<std::mutex> lock(stats_mutex_);

    stats_.messages_processed++;

    if (!config_.enabled) {
        return true;  // Not an error, just disabled
    }

    if (!checkRateLimit()) {
        stats_.messages_rate_limited++;
        return true;  // Not an error, just rate limited
    }

    // Direct synchronous write to serial
    Logger::write_raw(formatted_data.c_str(), formatted_data.size());
    Logger::write_raw("\n", 1);

    // Update statistics
    stats_.output_lines++;

    return true;
}

bool SerialReporter::isHealthy() const {
    return !shutdown_requested_;
}

void SerialReporter::setConfig(const Config& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;

    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.is_enabled = config_.enabled;

    LOG_INFOF(TAG, "Configuration updated - enabled: %s, max_rate: %lu, buffer_size: %lu",
             config_.enabled ? "true" : "false",
             (unsigned long)config_.max_rate_per_sec,
             (unsigned long)config_.buffer_size);
}

SerialReporter::Config SerialReporter::getConfig() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

SerialReporter::Stats SerialReporter::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    Stats current_stats = stats_;

    // Synchronous mode - queue_size always 0
    current_stats.queue_size = 0;

    return current_stats;
}

// outputTaskThunk and outputTask removed - no longer needed in synchronous mode


bool SerialReporter::checkRateLimit() {
    uint64_t now_ms = esp_timer_get_time() / 1000ULL;
    uint64_t current_second = now_ms / 1000ULL;

    if (current_second != last_rate_check_ms_ / 1000ULL) {
        // New second, reset counter
        current_second_count_ = 0;
        last_rate_check_ms_ = now_ms;
    }

    current_second_count_++;
    stats_.current_rate_per_sec = current_second_count_;

    return current_second_count_ <= config_.max_rate_per_sec;
}