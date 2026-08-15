#pragma once
#include <string>
#include <functional>
#include <vector>
#include <cstdint>
#include "psram_allocator.h"
#include "queue_common.h"

extern "C" {
  #include "freertos/FreeRTOS.h"
  #include "freertos/semphr.h"
}

struct QueueConfig {
    std::string base_dir = "/data/reportq"; // LittleFS mountpoint
    uint32_t max_items = 512;  // Reduced from 2048 for LittleFS space
    uint32_t backoff_base_ms = 1000;
    uint32_t backoff_max_ms  = 60000;
};

class ReliableQueue {
public:
    bool scrub();
    static uint32_t crc32(const uint8_t* data, size_t n);
    explicit ReliableQueue(const QueueConfig& cfg);
    ~ReliableQueue();

    bool enqueue(const std::string& channel, const std::string& payload);
    // PSRAM-safe enqueue: avoids large std::string allocations by chunked appends
    bool enqueue_psram(const psram_string& channel, const psram_string& payload);
    // flush iterates files; send_fn should return true on success
    uint32_t flush(uint64_t now_ms, const std::function<bool(const QueuedEvent&)>& send_fn);
    uint32_t size() const;

    // Cleanup orphan temporary files
    void cleanup_orphan_files();

private:
    QueueConfig cfg_;
    mutable SemaphoreHandle_t mtx_;
    mutable uint64_t last_cleanup_ms_ = 0;  // Throttling for cleanup operations
    mutable uint64_t last_list_ms_ = 0;     // Throttling for list operations
    mutable psram_vector<psram_string> cached_files_;  // Cached file list in PSRAM

    // DEBUG FLAG: Set to false to disable throttling and get real-time behavior
    // Set to true only when you want to reduce delegate spam in logs during debugging
    static constexpr bool ENABLE_LIST_THROTTLING = false;

    bool write_atomic(const std::string& path, const std::string& data);
    bool read_event(const std::string& path, QueuedEvent& out);
    bool update_event(const std::string& path, const QueuedEvent& ev);
    bool remove_file(const std::string& path);
    psram_vector<psram_string> list_files() const;
    static psram_string rand_id();
};
