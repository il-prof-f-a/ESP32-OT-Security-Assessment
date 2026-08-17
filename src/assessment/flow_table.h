/**
 * @file flow_table.h
 * @brief Hash table of network flows in PSRAM
 *
 * Manages a thread-safe hashtable of flows (FlowData) allocated in PSRAM.
 * Provides:
 * - Get/Create flows by key
 * - Automatic cleanup of expired flows
 * - Thread-safe iteration
 * - Usage statistics
 *
 * ALLOCATION: PSRAM (hashtable + all flows)
 * THREAD-SAFETY: Mutex-protected for concurrent access
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "flow_data.h"
#include "core/psram_allocator.h"
#include "esp_log.h"
#include <unordered_map>
#include <mutex>
#include <functional>

static const char* FLOW_TABLE_TAG = "FlowTable";

/**
 * @brief Hash table of flows allocated in PSRAM
 *
 * Manages a collection of network flows with:
 * - Key: psram_string (FlowKey.toString())
 * - Value: FlowData (complete flow structure)
 * - Allocator: PSRAMAllocator (whole hashtable in PSRAM)
 * - Thread-safety: std::mutex for concurrent access protection
 *
 * Configuration:
 * - max_flows: Maximum number of simultaneous flows (default: 1000)
 * - flow_timeout_ms: Inactivity timeout before removal (default: 5 min)
 * - cleanup_interval_ms: Automatic cleanup interval (default: 1 min)
 *
 * Usage:
 * ```cpp
 * FlowTable table(1000, 300000, 60000);
 *
 * // Get or create flow
 * FlowKey key(...);
 * FlowData* flow = table.getOrCreateFlow(key);
 * if (flow) {
 *     flow->metrics.onPacketReceived(packet_size);
 *     // ...
 * }
 *
 * // Periodic cleanup (from a dedicated task)
 * table.periodicCleanup();
 *
 * // Iteration (e.g.: for export/report)
 * table.forEach([](const FlowData& flow) {
 *     ESP_LOGI("", "Flow: %s", flow.key.toString().c_str());
 * });
 * ```
 */
class FlowTable {
private:
    /**
     * Hashtable type with PSRAM allocator
     *
     * std::unordered_map with:
     * - Key: psram_string
     * - Value: FlowData
     * - Allocator: PSRAMAllocator per pair<const psram_string, FlowData>
     */
    using FlowMap = std::unordered_map<
        psram_string,
        FlowData,
        std::hash<psram_string>,
        std::equal_to<psram_string>,
        PSRAMAllocator<std::pair<const psram_string, FlowData>>
    >;

    /**
     * Hashtable of flows (PSRAM)
     */
    FlowMap flows_;

    /**
     * Mutex for concurrent access protection
     */
    mutable std::mutex mutex_;

    // ==================== CONFIGURATION ====================

    /**
     * Maximum number of simultaneous flows
     * When reached, forced cleanup to free space
     */
    uint32_t max_flows_;

    /**
     * Automatic cleanup interval (milliseconds)
     * Default: 60000 (1 minute)
     */
    uint32_t cleanup_interval_ms_;

    /**
     * Flow timeout for inactivity (milliseconds)
     * Inactive flows > timeout are removed
     * Default: 300000 (5 minutes)
     */
    uint32_t flow_timeout_ms_;

    /**
     * Last cleanup timestamp (milliseconds since boot)
     */
    uint64_t last_cleanup_ms_;

    // ==================== STATISTICS ====================

    /**
     * Total number of created flows (since startup)
     */
    uint32_t total_flows_created_;

    /**
     * Total number of expired/removed flows (since startup)
     */
    uint32_t total_flows_expired_;

    /**
     * Number of forced cleanups for reaching max_flows
     */
    uint32_t forced_cleanups_;

public:
    // ==================== CONSTRUCTOR ====================

    /**
     * @brief FlowTable constructor
     *
     * @param max_flows Maximum number of flows (default: 1000)
     * @param flow_timeout_ms Inactivity timeout ms (default: 300000 = 5 min)
     * @param cleanup_interval_ms Cleanup interval ms (default: 60000 = 1 min)
     */
    FlowTable(uint32_t max_flows = 1000,
              uint32_t flow_timeout_ms = 300000,
              uint32_t cleanup_interval_ms = 60000)
        : flows_(PSRAMAllocator<std::pair<const psram_string, FlowData>>()),
          max_flows_(max_flows),
          cleanup_interval_ms_(cleanup_interval_ms),
          flow_timeout_ms_(flow_timeout_ms),
          last_cleanup_ms_(0),
          total_flows_created_(0),
          total_flows_expired_(0),
          forced_cleanups_(0) {

        ESP_LOGI(FLOW_TABLE_TAG, "FlowTable created: max_flows=%u, timeout=%ums, cleanup_interval=%ums",
                 max_flows_, flow_timeout_ms_, cleanup_interval_ms_);
    }

    /**
     * @brief Destructor
     *
     * Cleanup of all flows (calls cleanup_func for protocol_specific_data)
     */
    ~FlowTable() {
        std::lock_guard<std::mutex> lock(mutex_);
        flows_.clear();  // Calls FlowData destructors that perform cleanup
        ESP_LOGI(FLOW_TABLE_TAG, "FlowTable destroyed: total_created=%u, total_expired=%u",
                 total_flows_created_, total_flows_expired_);
    }

    // Disable copy and move (singleton-like)
    FlowTable(const FlowTable&) = delete;
    FlowTable& operator=(const FlowTable&) = delete;
    FlowTable(FlowTable&&) = delete;
    FlowTable& operator=(FlowTable&&) = delete;

    // ==================== FLOW ACCESS ====================

    /**
     * @brief Get or create flow (thread-safe)
     *
     * If the flow exists, updates last_packet_ms.
     * If it does not exist, creates and initializes it.
     * If max_flows is reached, forces cleanup before creating.
     *
     * @param key Flow key
     * @return Pointer to the flow, nullptr on error
     */
    FlowData* getOrCreateFlow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check valid key
        if (!key.isValid()) {
            ESP_LOGW(FLOW_TABLE_TAG, "getOrCreateFlow: invalid key");
            return nullptr;
        }

        psram_string key_str = key.toString();

        // Look for existing flow
        auto it = flows_.find(key_str);
        if (it != flows_.end()) {
            // Update last_packet_ms
            it->second.metrics.last_packet_ms = esp_timer_get_time() / 1000;
            return &it->second;
        }

        // Check limit
        if (flows_.size() >= max_flows_) {
            ESP_LOGW(FLOW_TABLE_TAG, "Max flows reached (%u), forcing cleanup", max_flows_);
            cleanupExpiredFlows_NoLock(true);  // Force cleanup
            forced_cleanups_++;
        }

        // Create new flow
        PSRAMAllocator<char> alloc;
        FlowData new_flow(alloc);
        new_flow.key = key;

        uint64_t now_ms = esp_timer_get_time() / 1000;
        new_flow.metrics.first_packet_ms = now_ms;
        new_flow.metrics.last_packet_ms = now_ms;
        new_flow.state = FlowState::INIT;

        // Insert into map (move)
        auto insert_result = flows_.emplace(std::move(key_str), std::move(new_flow));
        total_flows_created_++;

        if (!insert_result.second) {
            ESP_LOGE(FLOW_TABLE_TAG, "Failed to insert flow");
            return nullptr;
        }

        ESP_LOGD(FLOW_TABLE_TAG, "Flow created: %s (total active: %u)",
                 key.toDirectionString().c_str(), flows_.size());

        return &insert_result.first->second;
    }

    /**
     * @brief Periodic cleanup of expired flows
     *
     * Call periodically from a dedicated task or from the main loop.
     * Removes flows:
     * - Inactive > flow_timeout_ms
     * - In terminal state (CLOSED, ERROR, TIMEOUT)
     *
     * Thread-safe.
     */
    void periodicCleanup() {
        uint64_t now_ms = esp_timer_get_time() / 1000;

        // Check cleanup interval
        if ((now_ms - last_cleanup_ms_) < cleanup_interval_ms_) {
            return;  // Too soon
        }

        std::lock_guard<std::mutex> lock(mutex_);
        cleanupExpiredFlows_NoLock(false);
        last_cleanup_ms_ = now_ms;
    }

    /**
     * @brief Thread-safe iteration over flows
     *
     * Calls the callback for each flow in the table.
     * The lock is held during the entire iteration.
     *
     * WARNING: Do not call getOrCreateFlow() from the callback
     * (deadlock due to recursive lock).
     *
     * @param callback Function to call for each flow
     */
    template<typename Func>
    void forEach(Func callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : flows_) {
            callback(pair.first, pair.second);
        }
    }

    /**
     * @brief Thread-safe iteration (const)
     *
     * @param callback Function to call for each flow (const ref)
     */
    template<typename Func>
    void forEach(Func callback) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& pair : flows_) {
            callback(pair.first, pair.second);
        }
    }

    /**
     * @brief Look up flow by key (thread-safe)
     *
     * @param key Flow key
     * @return Pointer to the flow, nullptr if not found
     */
    FlowData* findFlow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        psram_string key_str = key.toString();
        auto it = flows_.find(key_str);
        return (it != flows_.end()) ? &it->second : nullptr;
    }

    /**
     * @brief Look up flow by key (const)
     *
     * @param key Flow key
     * @return Const pointer to the flow, nullptr if not found
     */
    const FlowData* findFlow(const FlowKey& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        psram_string key_str = key.toString();
        auto it = flows_.find(key_str);
        return (it != flows_.end()) ? &it->second : nullptr;
    }

    /**
     * @brief Remove flow by key (thread-safe)
     *
     * @param key Flow key
     * @return true if removed, false if not found
     */
    bool removeFlow(const FlowKey& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        psram_string key_str = key.toString();
        size_t removed = flows_.erase(key_str);
        if (removed > 0) {
            total_flows_expired_++;
            ESP_LOGD(FLOW_TABLE_TAG, "Flow removed: %s", key.toDirectionString().c_str());
        }
        return removed > 0;
    }

    // ==================== STATISTICS ====================

    /**
     * @brief Number of active flows
     *
     * @return Number of flows in the table
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flows_.size();
    }

    /**
     * @brief Check whether the table is empty
     *
     * @return true if empty, false otherwise
     */
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return flows_.empty();
    }

    /**
     * @brief Total created flows (since startup)
     *
     * @return Total number of created flows
     */
    uint32_t getTotalCreated() const { return total_flows_created_; }

    /**
     * @brief Total expired/removed flows (since startup)
     *
     * @return Total number of removed flows
     */
    uint32_t getTotalExpired() const { return total_flows_expired_; }

    /**
     * @brief Number of forced cleanups
     *
     * @return Number of times cleanup was forced for max_flows
     */
    uint32_t getForcedCleanups() const { return forced_cleanups_; }

    /**
     * @brief Percentage usage of the table
     *
     * @return Usage percentage [0.0-1.0]
     */
    float getUsagePercent() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (max_flows_ == 0) return 0.0f;
        return static_cast<float>(flows_.size()) / static_cast<float>(max_flows_);
    }

    // ==================== RUNTIME CONFIGURATION ====================

    /**
     * @brief Set maximum number of flows
     *
     * @param max New maximum
     */
    void setMaxFlows(uint32_t max) {
        std::lock_guard<std::mutex> lock(mutex_);
        max_flows_ = max;
        ESP_LOGI(FLOW_TABLE_TAG, "Max flows updated: %u", max_flows_);
    }

    /**
     * @brief Set flow timeout
     *
     * @param timeout_ms New timeout in milliseconds
     */
    void setFlowTimeout(uint32_t timeout_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        flow_timeout_ms_ = timeout_ms;
        ESP_LOGI(FLOW_TABLE_TAG, "Flow timeout updated: %ums", flow_timeout_ms_);
    }

    /**
     * @brief Set cleanup interval
     *
     * @param interval_ms New interval in milliseconds
     */
    void setCleanupInterval(uint32_t interval_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup_interval_ms_ = interval_ms;
        ESP_LOGI(FLOW_TABLE_TAG, "Cleanup interval updated: %ums", cleanup_interval_ms_);
    }

    /**
     * @brief Get current configuration
     *
     * @param max_flows Output: maximum number of flows
     * @param timeout_ms Output: flow timeout
     * @param cleanup_interval_ms Output: cleanup interval
     */
    void getConfig(uint32_t& max_flows, uint32_t& timeout_ms, uint32_t& cleanup_interval_ms) const {
        std::lock_guard<std::mutex> lock(mutex_);
        max_flows = max_flows_;
        timeout_ms = flow_timeout_ms_;
        cleanup_interval_ms = cleanup_interval_ms_;
    }

    /**
     * @brief Full clear of the table (for testing/reset)
     */
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = flows_.size();
        flows_.clear();
        total_flows_expired_ += count;
        ESP_LOGI(FLOW_TABLE_TAG, "Table cleared: %u flows removed", count);
    }

private:
    /**
     * @brief Cleanup expired flows (NO LOCK - internal use)
     *
     * Removes flows:
     * 1. Terminal states (CLOSED, ERROR, TIMEOUT)
     * 2. Inactive > flow_timeout_ms
     * 3. If force=true, also removes flows > timeout/2 to free space
     *
     * IMPORTANT: The lock MUST already be acquired before calling.
     *
     * @param force If true, aggressive cleanup to free space
     */
    void cleanupExpiredFlows_NoLock(bool force) {
        uint64_t now_ms = esp_timer_get_time() / 1000;
        auto it = flows_.begin();
        uint32_t removed = 0;

        while (it != flows_.end()) {
            bool should_remove = false;
            FlowData& flow = it->second;

            // Criterion 1: Terminal state
            if (flow.isTerminal()) {
                should_remove = true;
            }

            // Criterion 2: Normal timeout
            else if (flow.isExpired(flow_timeout_ms_)) {
                should_remove = true;
                // Update state before removal
                if (flow.state != FlowState::TIMEOUT) {
                    flow.state = FlowState::TIMEOUT;
                }
            }

            // Criterion 3: Forced cleanup (if close to max_flows)
            else if (force && flows_.size() > max_flows_ * 0.9) {
                // Remove oldest flows (timeout reduced to half)
                if (flow.isExpired(flow_timeout_ms_ / 2)) {
                    should_remove = true;
                }
            }

            if (should_remove) {
                ESP_LOGD(FLOW_TABLE_TAG, "Removing flow: %s (state=%s, age=%llums)",
                         flow.key.toDirectionString().c_str(),
                         flowStateToString(flow.state),
                         flow.metrics.getAge());

                it = flows_.erase(it);
                removed++;
                total_flows_expired_++;
            } else {
                ++it;
            }
        }

        if (removed > 0) {
            ESP_LOGI(FLOW_TABLE_TAG, "Cleanup: removed %u flows (active: %u, created: %u, expired: %u)",
                     removed, flows_.size(), total_flows_created_, total_flows_expired_);
        }
    }
};

#endif // FLOW_TABLE_H
