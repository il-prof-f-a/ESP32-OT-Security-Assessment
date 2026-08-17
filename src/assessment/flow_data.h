/**
 * @file flow_data.h
 * @brief Unified data structure for network flows
 *
 * Combines all the elements of a flow:
 * - Identifying key (FlowKey)
 * - Machine state (FlowState)
 * - Metrics (FlowMetrics)
 * - Circular buffer of recent operations (PSRAM)
 * - Protocol-specific data (opaque pointer)
 *
 * ALLOCATION: PSRAM (all strings and buffers)
 *
 * @date 2025-10-21
 * @version 1.0
 */

#ifndef FLOW_DATA_H
#define FLOW_DATA_H

#include "flow_key.h"
#include "flow_metrics.h"
#include "flow_label.h"
#include "flow_state.h"
#include "core/psram_allocator.h"
#include <deque>
#include <cstdint>

/**
 * @brief Single operation tracked in the flow
 *
 * Represents a significant action detected in the flow
 * (e.g.: READ, WRITE, CONTROL, ERROR).
 *
 * ALLOCATION: PSRAM (strings use PSRAMAllocator)
 */
struct FlowOperation {
    /**
     * Operation type (e.g.: "READ", "WRITE", "CONTROL", "ERROR", "DIAGNOSTIC")
     */
    psram_string type;

    /**
     * Protocol-specific details (e.g.: "FC=0x03 addr=100", "Browse /Root")
     */
    psram_string details;

    /**
     * Operation timestamp (milliseconds since boot)
     */
    uint32_t timestamp_ms;

    /**
     * Success flag
     */
    bool success;

    /**
     * PSRAM-safe default constructor
     */
    FlowOperation(PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : type(alloc),
          details(alloc),
          timestamp_ms(0),
          success(true) {}

    /**
     * Constructor with parameters
     */
    FlowOperation(const char* op_type, const char* op_details,
                 uint32_t timestamp, bool op_success = true,
                 PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : type(op_type, alloc),
          details(op_details, alloc),
          timestamp_ms(timestamp),
          success(op_success) {}
};

/**
 * @brief Complete data structure for a network flow
 *
 * Contiene:
 * - Identification (FlowKey)
 * - Current state (FlowState)
 * - Accumulated metrics (FlowMetrics)
 * - Circular buffer of recent operations (std::deque in PSRAM)
 * - Opaque pointer to protocol-specific data
 *
 * ALLOCATION: PSRAM for all dynamic allocations
 */
struct FlowData {
    // ==================== IDENTIFICATION ====================

    /**
     * Identifying key of the flow
     */
    FlowKey key;

    // ==================== STATE ====================

    /**
     * Current state of the state machine
     */
    FlowState state;

    // ==================== METRICS ====================

    /**
     * Accumulated metrics of the flow
     */
    FlowMetrics metrics;

    // ==================== RECENT OPERATIONS ====================

    /**
     * Circular buffer of recent operations
     * Uses std::deque with PSRAMAllocator for PSRAM allocation
     * FIFO: when it reaches max_operations, it removes the oldest ones
     */
    std::deque<FlowOperation, PSRAMAllocator<FlowOperation>> recent_operations;

    /**
     * Maximum number of operations to keep in the buffer
     * Configurable (default: 50)
     */
    uint16_t max_operations;

    // ==================== PROTOCOL-SPECIFIC DATA ====================

    /**
     * Opaque pointer to protocol-specific data
     *
     * Each plugin can allocate its own data structure in PSRAM
     * and store the pointer here.
     *
     * Examples:
     * - Modbus: ModbusSessionData* (unit address, accessed registers, etc.)
     * - S7: S7SessionData* (rack/slot, PDU ref, SZL reads, etc.)
     * - OPC UA: OPCUASessionData* (channel_id, token_id, endpoints, etc.)
     *
     * IMPORTANT: The plugin is responsible for allocating and deallocating
     * this data using heap_caps_malloc(MALLOC_CAP_SPIRAM).
     */
    void* protocol_specific_data;

    /**
     * Cleanup function for protocol_specific_data
     *
     * The plugin provides this function to deallocate its own data.
     * Called automatically in the FlowData destructor.
     *
     * Example:
     * void cleanupModbusData(void* data) {
     *     if (data) {
     *         ModbusSessionData* mdata = static_cast<ModbusSessionData*>(data);
     *         heap_caps_free(data);
     *     }
     * }
     */
    typedef void (*CleanupFunc)(void*);
    CleanupFunc cleanup_func;

    // ==================== CONSTRUCTORS AND DESTRUCTOR ====================

    /**
     * PSRAM-safe default constructor
     */
    FlowData(PSRAMAllocator<char> alloc = PSRAMAllocator<char>())
        : key(alloc),
          state(FlowState::INIT),
          metrics(),
          recent_operations(PSRAMAllocator<FlowOperation>()),
          max_operations(50),
          protocol_specific_data(nullptr),
          cleanup_func(nullptr) {}

    /**
     * Destructor: calls the cleanup function if present
     */
    ~FlowData() {
        if (protocol_specific_data && cleanup_func) {
            cleanup_func(protocol_specific_data);
            protocol_specific_data = nullptr;
        }
    }

    // Disable copy (it has an opaque pointer)
    FlowData(const FlowData&) = delete;
    FlowData& operator=(const FlowData&) = delete;

    // Enable move
    FlowData(FlowData&& other) noexcept
        : key(std::move(other.key)),
          state(other.state),
          metrics(other.metrics),
          recent_operations(std::move(other.recent_operations)),
          max_operations(other.max_operations),
          protocol_specific_data(other.protocol_specific_data),
          cleanup_func(other.cleanup_func) {
        // Prevent double-free
        other.protocol_specific_data = nullptr;
        other.cleanup_func = nullptr;
    }

    FlowData& operator=(FlowData&& other) noexcept {
        if (this != &other) {
            // Clean up existing data
            if (protocol_specific_data && cleanup_func) {
                cleanup_func(protocol_specific_data);
            }

            // Move
            key = std::move(other.key);
            state = other.state;
            metrics = other.metrics;
            recent_operations = std::move(other.recent_operations);
            max_operations = other.max_operations;
            protocol_specific_data = other.protocol_specific_data;
            cleanup_func = other.cleanup_func;

            // Prevent double-free
            other.protocol_specific_data = nullptr;
            other.cleanup_func = nullptr;
        }
        return *this;
    }

    // ==================== METHODS ====================

    /**
     * @brief Add operation to the buffer (FIFO)
     *
     * If the buffer is full, it removes the oldest operation.
     *
     * @param type Operation type (e.g.: "READ", "WRITE")
     * @param details Operation details (e.g.: "FC=0x03 addr=100")
     * @param timestamp Timestamp in milliseconds
     * @param success Success flag
     */
    void addOperation(const psram_string& type, const psram_string& details,
                     uint32_t timestamp, bool success = true) {
        PSRAMAllocator<char> alloc;
        FlowOperation op(alloc);
        op.type = type;
        op.details = details;
        op.timestamp_ms = timestamp;
        op.success = success;

        recent_operations.push_back(std::move(op));

        // Keep maximum size (FIFO)
        while (recent_operations.size() > max_operations) {
            recent_operations.pop_front();
        }
    }

    /**
     * @brief Add operation (const char* version)
     *
     * @param type Operation type
     * @param details Operation details
     * @param timestamp Timestamp in milliseconds
     * @param success Success flag
     */
    void addOperation(const char* type, const char* details,
                     uint32_t timestamp, bool success = true) {
        PSRAMAllocator<char> alloc;
        psram_string type_str(type, alloc);
        psram_string details_str(details, alloc);
        addOperation(type_str, details_str, timestamp, success);
    }

    /**
     * @brief Cleanup old operations (> age_ms)
     *
     * Removes operations older than age_ms from the buffer.
     *
     * @param age_ms Maximum age in milliseconds
     */
    void cleanupOldOperations(uint32_t age_ms) {
        uint32_t now_ms = esp_timer_get_time() / 1000;

        while (!recent_operations.empty()) {
            const FlowOperation& oldest = recent_operations.front();
            if ((now_ms - oldest.timestamp_ms) > age_ms) {
                recent_operations.pop_front();
            } else {
                break;  // Sorted by timestamp; if the first one is not expired, stop
            }
        }
    }

    /**
     * @brief Get the number of operations in the buffer
     *
     * @return Number of operations present
     */
    size_t getOperationCount() const {
        return recent_operations.size();
    }

    /**
     * @brief Check whether the operation buffer is full
     *
     * @return true if full, false otherwise
     */
    bool isOperationBufferFull() const {
        return recent_operations.size() >= max_operations;
    }

    /**
     * @brief Get the last operation
     *
     * @return Pointer to the last operation, nullptr if the buffer is empty
     */
    const FlowOperation* getLastOperation() const {
        if (recent_operations.empty()) return nullptr;
        return &recent_operations.back();
    }

    /**
     * @brief Count operations by type
     *
     * @param type Operation type to count (e.g.: "READ", "WRITE")
     * @return Number of occurrences
     */
    uint32_t countOperations(const char* type) const {
        uint32_t count = 0;
        for (const auto& op : recent_operations) {
            if (op.type == type) {
                count++;
            }
        }
        return count;
    }

    /**
     * @brief Count failed operations
     *
     * @return Number of operations with success=false
     */
    uint32_t countFailedOperations() const {
        uint32_t count = 0;
        for (const auto& op : recent_operations) {
            if (!op.success) {
                count++;
            }
        }
        return count;
    }

    /**
     * @brief Allocate protocol-specific data
     *
     * Helper to allocate data in PSRAM.
     *
     * Example:
     * ModbusSessionData* data = flow.allocateProtocolData<ModbusSessionData>(cleanupModbusData);
     *
     * @tparam T Data structure type
     * @param cleanup Cleanup function
     * @return Pointer to the structure allocated in PSRAM
     */
    template<typename T>
    T* allocateProtocolData(CleanupFunc cleanup) {
        // Clean up old data if present
        if (protocol_specific_data && cleanup_func) {
            cleanup_func(protocol_specific_data);
        }

        // Allocate in PSRAM
        T* data = static_cast<T*>(heap_caps_malloc(sizeof(T), MALLOC_CAP_SPIRAM));
        if (data) {
            new (data) T();  // Placement new
            protocol_specific_data = data;
            cleanup_func = cleanup;
        }

        return data;
    }

    /**
     * @brief Get protocol-specific data
     *
     * @tparam T Data structure type
     * @return Pointer to the data, nullptr if not allocated
     */
    template<typename T>
    T* getProtocolData() {
        return static_cast<T*>(protocol_specific_data);
    }

    /**
     * @brief Get protocol-specific data (const)
     *
     * @tparam T Data structure type
     * @return Const pointer to the data, nullptr if not allocated
     */
    template<typename T>
    const T* getProtocolData() const {
        return static_cast<const T*>(protocol_specific_data);
    }

    /**
     * @brief Check whether the flow has expired
     *
     * @param timeout_ms Timeout in milliseconds
     * @return true if expired, false otherwise
     */
    bool isExpired(uint32_t timeout_ms) const {
        return metrics.getAge() > timeout_ms;
    }

    /**
     * @brief Check whether the flow is in a terminal state
     *
     * @return true if terminal state (CLOSED, ERROR, TIMEOUT)
     */
    bool isTerminal() const {
        return isFlowStateTerminal(state);
    }

    /**
     * @brief Clear the operation buffer (keeps max_operations)
     */
    void clearOperations() {
        recent_operations.clear();
    }

    /**
     * @brief Full flow reset (for reuse)
     */
    void reset() {
        state = FlowState::INIT;
        metrics.reset();
        recent_operations.clear();

        if (protocol_specific_data && cleanup_func) {
            cleanup_func(protocol_specific_data);
            protocol_specific_data = nullptr;
            cleanup_func = nullptr;
        }
    }
};

#endif // FLOW_DATA_H
