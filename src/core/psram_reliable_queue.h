#pragma once
#include <string>
#include <functional>
#include <vector>
#include <cstdint>
#include <atomic>
#include <mutex>
#include "psram_allocator.h"
#include "queue_common.h"

extern "C" {
  #include "freertos/FreeRTOS.h"
  #include "freertos/semphr.h"
}

// Forward declaration
class FilesystemTaskDelegate;

struct PSRAMQueueConfig {
    std::string backup_file = "/data/reportq/psram_queue.bin"; // Backup file path
    uint32_t max_items = 512;  // Maximum items in queue
    uint32_t backoff_base_ms = 1000;
    uint32_t backoff_max_ms  = 60000;
    uint32_t sync_threshold = 10;    // Sync to file every N events
    uint32_t sync_interval_ms = 30000; // Force sync every 30 seconds
};

// File format structures
struct PSRAMQueueFileHeader {
    uint32_t magic;           // 'PSRQ' (PSRAMReliableQueue)
    uint32_t version;         // Format version (1)
    uint32_t event_count;     // Number of events in file
    uint32_t checksum;        // CRC32 of event data
    uint64_t last_updated_ms; // Last save timestamp
    uint64_t reserved[3];     // Future expansion
};

struct PSRAMQueueStats {
    uint32_t queued = 0;
    uint32_t max_items = 0;
    uint32_t events_since_sync = 0;
    uint64_t last_sync_ms = 0;
    bool dirty = false;
    bool initialized = false;
    uint32_t sync_threshold = 0;
    uint32_t sync_interval_ms = 0;
    uint32_t backoff_base_ms = 0;
    uint32_t backoff_max_ms = 0;
    uint32_t payload_bytes = 0;
    psram_string backup_file;
    uint32_t flush_interval_ms = 0; // populated by ReportingEngine
};

class PSRAMReliableQueue {
public:
    explicit PSRAMReliableQueue(const PSRAMQueueConfig& cfg);
    ~PSRAMReliableQueue();

    // Initialize with filesystem delegate
    bool initialize(FilesystemTaskDelegate* fs_delegate);
    void shutdown();

    // Queue operations (same interface as ReliableQueue)
    bool enqueue(const std::string& channel, const std::string& payload);
    bool enqueue_psram(const psram_string& channel, const psram_string& payload);

    // Process queue and execute send function for ready events
    uint32_t flush(uint64_t now_ms, const std::function<bool(const QueuedEvent&)>& send_fn);

    // Get current queue size
    uint32_t size() const;

    // Snapshot current queue statistics
    void getStats(PSRAMQueueStats& out_stats) const;

    // Manual sync operations
    bool sync_to_file();
    bool load_from_file();

    // Utility
    void clear();
    bool scrub(); // Maintain compatibility
    void cleanup_orphan_files(); // Compatibility with ReliableQueue (no-op in PSRAM implementation)
    static uint32_t crc32(const uint8_t* data, size_t n);

private:
    PSRAMQueueConfig cfg_;
    mutable std::mutex queue_mutex_;

    // In-memory queue in PSRAM
    psram_vector<QueuedEvent> events_;

    // Sync management
    std::atomic<bool> dirty_flag_;
    uint64_t last_sync_ms_;
    uint32_t events_since_sync_;

    // FilesystemTaskDelegate for async file operations
    FilesystemTaskDelegate* fs_delegate_;
    bool initialized_;

    // Constants
    static constexpr uint32_t QUEUE_MAGIC = 0x50535251; // 'PSRQ'
    static constexpr uint32_t QUEUE_VERSION = 1;

    // Helper methods
    void mark_dirty();
    bool should_sync(uint64_t now_ms) const;
    uint64_t get_current_time_ms() const;
    static psram_string generate_id();
    uint32_t calculate_checksum(const psram_vector<QueuedEvent>& events) const;

    // File operations (executed via FilesystemTaskDelegate)
    bool sync_to_file_impl();
    bool load_from_file_impl();

    // Serialization helpers
    psram_string serialize_events() const;
    bool deserialize_events(const psram_string& data);
};
