#include "psram_reliable_queue.h"
#include "filesystem_task_delegate.h"
#include "logging_system.h"
#include <algorithm>
#include <random>
#include <cstring>
#include <memory>
#include <limits>

extern "C" {
    #include "esp_timer.h"
    #include "esp_crc.h"
}

static const char* TAG = "PSRAMQueue";

PSRAMReliableQueue::PSRAMReliableQueue(const PSRAMQueueConfig& cfg)
    : cfg_(cfg)
    , dirty_flag_(false)
    , last_sync_ms_(0)
    , events_since_sync_(0)
    , fs_delegate_(nullptr)
    , initialized_(false) {

    LOG_INFOF(TAG, "PSRAMReliableQueue created, max_items=%u", cfg_.max_items);
}

PSRAMReliableQueue::~PSRAMReliableQueue() {
    shutdown();
}

bool PSRAMReliableQueue::initialize(FilesystemTaskDelegate* fs_delegate) {
    if (initialized_) {
        LOG_WARNING(TAG, "Already initialized");
        return true;
    }

    if (!fs_delegate) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate is null");
        return false;
    }

    fs_delegate_ = fs_delegate;

    // Try to load existing queue from file
    if (!load_from_file()) {
        LOG_INFO(TAG, "No existing queue file found, starting with empty queue");
    }

    initialized_ = true;
    LOG_INFO(TAG, "PSRAMReliableQueue initialized successfully");
    return true;
}

void PSRAMReliableQueue::shutdown() {
    if (!initialized_) return;

    // Force sync before shutdown
    if (dirty_flag_.load()) {
        sync_to_file();
    }

    std::lock_guard<std::mutex> lock(queue_mutex_);
    events_.clear();
    initialized_ = false;
    LOG_INFO(TAG, "PSRAMReliableQueue shutdown complete");
}

bool PSRAMReliableQueue::enqueue(const std::string& channel, const std::string& payload) {
    // Convert to PSRAM strings to avoid memory fragmentation
    psram_string psram_channel = PSRAMUtils::createPSRAMString(channel.c_str());
    psram_string psram_payload = PSRAMUtils::createPSRAMString(payload.c_str());

    return enqueue_psram(psram_channel, psram_payload);
}

bool PSRAMReliableQueue::enqueue_psram(const psram_string& channel, const psram_string& payload) {
    if (!initialized_) {
        LOG_ERROR(TAG, "Queue not initialized");
        return false;
    }

    std::lock_guard<std::mutex> lock(queue_mutex_);

    // Check queue size limit
    if (events_.size() >= cfg_.max_items) {
        LOG_WARNINGF(TAG, "Queue full (%u items), dropping event", cfg_.max_items);
        return false;
    }

    // Create new event
    QueuedEvent event;
    event.id = generate_id();
    event.channel = channel;
    event.payload = payload;
    event.attempts = 0;
    event.next_attempt_ms = get_current_time_ms(); // Ready immediately

    events_.push_back(event);
    mark_dirty();

    // Check if we should sync to file
    uint64_t now_ms = get_current_time_ms();
    if (should_sync(now_ms)) {
        // CRITICAL FIX: Reset counter BEFORE calling sync to prevent infinite loop
        // if response queue is full and callback never gets called
        events_since_sync_ = 0;
        last_sync_ms_ = now_ms;

        // Schedule async sync (fire-and-forget)
        sync_to_file();
    }

    return true;
}

uint32_t PSRAMReliableQueue::flush(uint64_t now_ms, const std::function<bool(const QueuedEvent&)>& send_fn) {
    if (!initialized_) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(queue_mutex_);
    uint32_t processed = 0;
    bool queue_changed = false;

    // Process events that are ready to be sent
    auto it = events_.begin();
    while (it != events_.end()) {
        if (it->next_attempt_ms <= now_ms) {
            bool success = send_fn(*it);
            processed++;

            if (success) {
                it = events_.erase(it);
                queue_changed = true;
            } else {
                // Increment attempts and schedule retry with exponential backoff
                it->attempts++;
                uint32_t shift_amount = std::min(static_cast<uint32_t>(it->attempts - 1), static_cast<uint32_t>(10));
                uint32_t backoff_ms = std::min(
                    cfg_.backoff_base_ms * (1U << shift_amount),
                    cfg_.backoff_max_ms
                );
                it->next_attempt_ms = now_ms + backoff_ms;

                LOG_DEBUGF(TAG, "Event failed, retry in %ums (attempt %u) id=%s",
                           backoff_ms, it->attempts, it->id.c_str());
                ++it;
            }
        } else {
            ++it;
        }
    }

    if (queue_changed) {
        mark_dirty();

        // Check if we should sync after processing
        if (should_sync(now_ms)) {
            // CRITICAL FIX: Reset counter BEFORE calling sync
            events_since_sync_ = 0;
            last_sync_ms_ = now_ms;

            sync_to_file();
        }
    }

    return processed;
}

uint32_t PSRAMReliableQueue::size() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return events_.size();
}

void PSRAMReliableQueue::getStats(PSRAMQueueStats& out_stats) const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    out_stats.queued = static_cast<uint32_t>(events_.size());
    out_stats.max_items = cfg_.max_items;
    out_stats.events_since_sync = events_since_sync_;
    out_stats.last_sync_ms = last_sync_ms_;
    out_stats.dirty = dirty_flag_.load(std::memory_order_relaxed);
    out_stats.initialized = initialized_;
    out_stats.sync_threshold = cfg_.sync_threshold;
    out_stats.sync_interval_ms = cfg_.sync_interval_ms;
    out_stats.backoff_base_ms = cfg_.backoff_base_ms;
    out_stats.backoff_max_ms = cfg_.backoff_max_ms;
    out_stats.backup_file = PSRAMUtils::createPSRAMString(cfg_.backup_file.c_str());

    size_t payload_total = 0;
    for (const auto& ev : events_) {
        payload_total += ev.payload.length();
        payload_total += ev.channel.length();
        payload_total += ev.id.length();
    }
    if (payload_total > std::numeric_limits<uint32_t>::max()) {
        payload_total = std::numeric_limits<uint32_t>::max();
    }
    out_stats.payload_bytes = static_cast<uint32_t>(payload_total);
}

bool PSRAMReliableQueue::sync_to_file() {
    if (!fs_delegate_) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not available");
        return false;
    }

    // Serialize events to PSRAM buffer
    psram_string serialized_data = serialize_events();

    if (serialized_data.empty() && !events_.empty()) {
        LOG_ERROR(TAG, "Failed to serialize events");
        return false;
    }

    auto data_ptr = std::make_shared<psram_string>(std::move(serialized_data));

    // Schedule file write via FilesystemTaskDelegate
    auto completion_callback = [this, data_ptr](bool success) {
        if (success) {
            dirty_flag_.store(false);
            last_sync_ms_ = get_current_time_ms();
            events_since_sync_ = 0;
        } else {
            LOG_WARNING(TAG, "Queue sync to file failed");
        }
    };

    bool result = fs_delegate_->writeFileAsync(cfg_.backup_file, *data_ptr, completion_callback);
    if (!result) {
        LOG_ERROR(TAG, "Failed to enqueue queue backup write request");
    }
    return result;
}

bool PSRAMReliableQueue::load_from_file() {
    if (!fs_delegate_) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate not available");
        return false;
    }

    // Read file synchronously during initialization
    psram_string file_data;
    if (!fs_delegate_->readFileSync(cfg_.backup_file, file_data)) {
        LOG_INFO(TAG, "Queue backup file not found or unreadable");
        return false;
    }

    if (!deserialize_events(file_data)) {
        LOG_WARNING(TAG, "Failed to deserialize queue data");
        return false;
    }

    LOG_INFOF(TAG, "Loaded %zu events from backup file", events_.size());
    dirty_flag_.store(false);
    return true;
}

void PSRAMReliableQueue::clear() {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    events_.clear();
    mark_dirty();
    LOG_INFO(TAG, "Queue cleared");
}

bool PSRAMReliableQueue::scrub() {
    // Compatibility function - in PSRAM implementation, no orphan files to clean
    return true;
}

void PSRAMReliableQueue::cleanup_orphan_files() {
    // Compatibility function - in PSRAM implementation, no orphan files to clean
    // This is a no-op since we don't have individual files that can become orphaned
}

uint32_t PSRAMReliableQueue::crc32(const uint8_t* data, size_t n) {
    return esp_crc32_le(0, data, n);
}

// Private helper methods

void PSRAMReliableQueue::mark_dirty() {
    dirty_flag_.store(true);
    events_since_sync_++;
}

bool PSRAMReliableQueue::should_sync(uint64_t now_ms) const {
    if (!dirty_flag_.load()) {
        return false;
    }

    // Sync if we have enough events since last sync
    if (events_since_sync_ >= cfg_.sync_threshold) {
        return true;
    }

    // Sync if enough time has passed
    if (now_ms - last_sync_ms_ >= cfg_.sync_interval_ms) {
        return true;
    }

    return false;
}

uint64_t PSRAMReliableQueue::get_current_time_ms() const {
    return esp_timer_get_time() / 1000;
}

psram_string PSRAMReliableQueue::generate_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);

    uint64_t timestamp = esp_timer_get_time() / 1000; // Use static function directly
    uint32_t random = dis(gen);

    char id_buffer[32];
    snprintf(id_buffer, sizeof(id_buffer), "%08lx_%08lx", (unsigned long)timestamp, (unsigned long)random);

    return PSRAMUtils::createPSRAMString(id_buffer);
}

uint32_t PSRAMReliableQueue::calculate_checksum(const psram_vector<QueuedEvent>& events) const {
    // Simple checksum of all event data
    uint32_t checksum = 0;

    for (const auto& event : events) {
        checksum ^= crc32(reinterpret_cast<const uint8_t*>(event.id.c_str()), event.id.length());
        checksum ^= crc32(reinterpret_cast<const uint8_t*>(event.channel.c_str()), event.channel.length());
        checksum ^= crc32(reinterpret_cast<const uint8_t*>(event.payload.c_str()), event.payload.length());
        checksum ^= event.attempts;
        checksum ^= static_cast<uint32_t>(event.next_attempt_ms);
    }

    return checksum;
}

psram_string PSRAMReliableQueue::serialize_events() const {
    // NOTE: This function assumes queue_mutex_ is already held by the caller!
    // Do NOT acquire the mutex here to avoid deadlock when called from enqueue_psram()

    if (events_.empty()) {
        // Create empty file with just header
        PSRAMQueueFileHeader header = {};
        header.magic = QUEUE_MAGIC;
        header.version = QUEUE_VERSION;
        header.event_count = 0;
        header.checksum = 0;
        header.last_updated_ms = get_current_time_ms();

        psram_string result;
        result.resize(sizeof(header));
        memcpy(&result[0], &header, sizeof(header));
        return result;
    }

    // Calculate total size needed
    size_t total_size = sizeof(PSRAMQueueFileHeader);
    for (const auto& event : events_) {
        total_size += sizeof(uint32_t) * 4; // id_len, channel_len, payload_len, attempts
        total_size += sizeof(uint64_t);     // next_attempt_ms
        total_size += event.id.length();
        total_size += event.channel.length();
        total_size += event.payload.length();
    }

    psram_string result;
    result.reserve(total_size);

    // Create header
    PSRAMQueueFileHeader header = {};
    header.magic = QUEUE_MAGIC;
    header.version = QUEUE_VERSION;
    header.event_count = events_.size();
    header.checksum = calculate_checksum(events_);
    header.last_updated_ms = get_current_time_ms();

    // Append header
    result.resize(sizeof(header));
    memcpy(&result[0], &header, sizeof(header));

    // Append events
    for (const auto& event : events_) {
        size_t pos = result.size();

        // Lengths
        uint32_t id_len = event.id.length();
        uint32_t channel_len = event.channel.length();
        uint32_t payload_len = event.payload.length();

        // Resize and append data
        result.resize(pos + sizeof(uint32_t) * 4 + sizeof(uint64_t) + id_len + channel_len + payload_len);

        char* data_ptr = &result[pos];
        memcpy(data_ptr, &id_len, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(data_ptr, &channel_len, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(data_ptr, &payload_len, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(data_ptr, &event.attempts, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(data_ptr, &event.next_attempt_ms, sizeof(uint64_t)); data_ptr += sizeof(uint64_t);
        memcpy(data_ptr, event.id.c_str(), id_len); data_ptr += id_len;
        memcpy(data_ptr, event.channel.c_str(), channel_len); data_ptr += channel_len;
        memcpy(data_ptr, event.payload.c_str(), payload_len);
    }

    return result;
}

bool PSRAMReliableQueue::deserialize_events(const psram_string& data) {
    if (data.size() < sizeof(PSRAMQueueFileHeader)) {
        LOG_WARNING(TAG, "Queue file too small");
        return false;
    }

    // Parse header
    PSRAMQueueFileHeader header;
    memcpy(&header, data.c_str(), sizeof(header));

    if (header.magic != QUEUE_MAGIC) {
        LOG_WARNING(TAG, "Invalid queue file magic");
        return false;
    }

    if (header.version != QUEUE_VERSION) {
        LOG_WARNING(TAG, "Unsupported queue file version");
        return false;
    }

    std::lock_guard<std::mutex> lock(queue_mutex_);
    events_.clear();

    if (header.event_count == 0) {
        return true; // Empty queue is valid
    }

    // Parse events
    const char* data_ptr = data.c_str() + sizeof(header);
    const char* data_end = data.c_str() + data.size();

    for (uint32_t i = 0; i < header.event_count; ++i) {
        if (data_ptr + sizeof(uint32_t) * 4 + sizeof(uint64_t) > data_end) {
            LOG_WARNING(TAG, "Queue file truncated");
            events_.clear();
            return false;
        }

        QueuedEvent event;

        // Read lengths
        uint32_t id_len, channel_len, payload_len;
        memcpy(&id_len, data_ptr, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(&channel_len, data_ptr, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(&payload_len, data_ptr, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(&event.attempts, data_ptr, sizeof(uint32_t)); data_ptr += sizeof(uint32_t);
        memcpy(&event.next_attempt_ms, data_ptr, sizeof(uint64_t)); data_ptr += sizeof(uint64_t);

        // Check bounds
        if (data_ptr + id_len + channel_len + payload_len > data_end) {
            LOG_WARNING(TAG, "Queue file corrupted");
            events_.clear();
            return false;
        }

        // Read strings
        std::string temp_id(data_ptr, id_len); data_ptr += id_len;
        std::string temp_channel(data_ptr, channel_len); data_ptr += channel_len;
        std::string temp_payload(data_ptr, payload_len); data_ptr += payload_len;

        event.id = PSRAMUtils::createPSRAMString(temp_id.c_str());
        event.channel = PSRAMUtils::createPSRAMString(temp_channel.c_str());
        event.payload = PSRAMUtils::createPSRAMString(temp_payload.c_str());

        events_.push_back(event);
    }

    // Verify checksum
    uint32_t calculated_checksum = calculate_checksum(events_);
    if (calculated_checksum != header.checksum) {
        LOG_WARNING(TAG, "Queue file checksum mismatch");
        events_.clear();
        return false;
    }

    LOG_INFOF(TAG, "Successfully deserialized %u events", header.event_count);
    return true;
}
