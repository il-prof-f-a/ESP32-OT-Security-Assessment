#pragma once

#include <string>
#include <functional>
#include <variant>
#include <vector>
#include <memory>
#include <atomic>
#include <cstring>  // For memcpy
#include "task_config.h"
#include "psram_allocator.h"

extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "freertos/queue.h"
    #include "esp_log.h"
    #include "freertos/semphr.h"
    #include "esp_err.h"
    #include "nvs.h"
}

/**
 * Async Storage Engine - Centralized storage operations for ESP32 with PSRAM support
 *
 * Provides asynchronous and synchronous access to NVS and filesystem operations
 * from tasks with stacks in PSRAM. Uses a dedicated worker thread in INTERNAL_RAM
 * to handle all flash operations safely.
 */

namespace AsyncStorage {

namespace detail {
    uint32_t nextDebugId();
}

// Forward declarations
class Engine;

// ========================= OPERATION TYPES =========================

enum class OpType {
    // NVS Operations
    NVS_SET_STR,
    NVS_GET_STR,
    NVS_SET_U8,
    NVS_GET_U8,
    NVS_SET_U16,
    NVS_GET_U16,
    NVS_SET_U32,
    NVS_GET_U32,
    NVS_SET_I8,
    NVS_GET_I8,
    NVS_SET_I16,
    NVS_GET_I16,
    NVS_SET_I32,
    NVS_GET_I32,
    NVS_SET_I64,
    NVS_GET_I64,
    NVS_SET_BLOB,
    NVS_GET_BLOB,
    NVS_ERASE_KEY,
    NVS_ERASE_ALL,
    NVS_OPEN,
    NVS_CLOSE,
    NVS_COMMIT,

    // Filesystem Operations
    FS_WRITE_FILE,
    FS_READ_FILE,
    FS_APPEND_FILE,
    FS_DELETE_FILE,
    FS_EXISTS,
    FS_FILE_SIZE,
    FS_MKDIR,
    FS_RENAME,
    FS_LIST_DIR,
    // RAW buffer FS operations (no std::string/vector allocations in caller)
    FS_WRITE_RAW,
    FS_APPEND_RAW
};

// ========================= DATA STRUCTURES =========================

// Variant for operation data
using OperationData = std::variant<
    psram_string,                   // String data in PSRAM
    psram_vector<uint8_t>,         // Binary data in PSRAM
    uint8_t, uint16_t, uint32_t,   // Unsigned types
    int8_t, int16_t, int32_t, int64_t,  // Signed types
    std::monostate                  // No data
>;

// Result structure
struct Result {
    esp_err_t error = ESP_FAIL;
    OperationData data;
    char* error_message = nullptr;  // Changed from psram_string to prevent heap corruption

    bool isSuccess() const { return error == ESP_OK; }
    bool isNotFound() const { return error == ESP_ERR_NOT_FOUND; }
};

// Completion callback type
using CompletionCallback = std::function<void(const Result&)>;

/**
 * CALLBACK SAFETY GUIDELINES - CRITICAL TO PREVENT UAF CRASHES
 *
 * When using completion_callback in async operations:
 *
 * ✅ SAFE - Capture by value:
 * op->completion_callback = [path](const Result& r) {
 *     LOG_INFOF("AsyncStorage", "Operation on '%s' completed", path.c_str());
 * };
 *
 * ✅ SAFE - Weak pointer for object references:
 * op->completion_callback = [w = std::weak_ptr<MyClass>(shared_this)](const Result& r) {
 *     if (auto obj = w.lock()) {
 *         obj->onOperationComplete(r);
 *     }
 * };
 *
 * ❌ UNSAFE - Capture by reference to stack objects:
 * std::string temp_path = "/some/path";
 * op->completion_callback = [&temp_path](const Result& r) {  // ← UAF if temp_path destroyed
 *     LOG_INFO("AsyncStorage", temp_path.c_str());
 * };
 *
 * ❌ UNSAFE - Raw this pointer capture:
 * op->completion_callback = [this](const Result& r) {  // ← UAF if object destroyed
 *     this->handleResult(r);
 * };
 */

// Operation structure for queue
struct Operation {
    OpType type;
    // CRITICAL FIX: Replace psram_string with raw char* to prevent std::string corruption
    char* namespace_or_path_raw = nullptr;  // NVS namespace or filesystem path (PSRAM allocated)
    char* key_or_subpath_raw = nullptr;     // NVS key or filesystem subpath (PSRAM allocated)
    OperationData input_data;
    // For RAW operations: PSRAM-backed buffer and size
    void* raw_buf = nullptr;
    size_t raw_size = 0;
    // For RAW operations: PSRAM copy of path to avoid std::string allocations
    char* raw_path = nullptr;

    uint32_t debug_id = 0;                  // Monotonic identifier for tracing
    const char* debug_source = nullptr;     // Literal describing the creator

    // Completion signaling
    volatile bool caller_timed_out = false;   // Set by executeSyncOperation() if timeout occurs
    bool is_async = false;                    // True for async operations (cleanup by worker)
    bool allocated_in_psram = false;           // Tracks allocation strategy for safe cleanup

    // Task notification system (replaces semaphores to eliminate race conditions)
    TaskHandle_t waiting_task = nullptr;      // Task waiting for completion
    bool use_task_notify = false;             // True to use task notifications instead of semaphore

    CompletionCallback completion_callback = nullptr;  // For async operations
    // Store result inline to avoid heap allocation and atomic reference counting issues
    Result result_storage __attribute__((aligned(4)));  // Force 4-byte alignment
    Result* result;                                      // Points to result_storage (no heap, no atomic ops)

    // NVS specific
    nvs_open_mode_t nvs_mode = NVS_READONLY;
    uint32_t nvs_handle = 0;  // For operations that need existing handle

    // Constructor - CRITICAL FIX: Allocate raw char* buffers in PSRAM
    Operation(OpType op_type, const std::string& ns_path, const std::string& key_subpath = "")
        : type(op_type), namespace_or_path_raw(nullptr), key_or_subpath_raw(nullptr) {
        // Point directly to aligned inline storage - no atomic operations
        result = &result_storage;

        // Verify memory alignment to prevent LoadStoreAlignment exceptions
        uintptr_t addr = reinterpret_cast<uintptr_t>(&result_storage);
        if (addr % 4 != 0) {
            // Force alignment by pointing to next aligned address
            result = reinterpret_cast<Result*>((addr + 3) & ~3);
        }

        debug_id = detail::nextDebugId();
        debug_source = "unset";

        // CRITICAL: Allocate PSRAM char* buffers instead of psram_string to prevent corruption
        if (!ns_path.empty()) {
            size_t ns_len = ns_path.length() + 1;
            namespace_or_path_raw = (char*)heap_caps_malloc(ns_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (namespace_or_path_raw) {
                memcpy(namespace_or_path_raw, ns_path.c_str(), ns_len);
            }
        }

        if (!key_subpath.empty()) {
            size_t key_len = key_subpath.length() + 1;
            key_or_subpath_raw = (char*)heap_caps_malloc(key_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (key_or_subpath_raw) {
                memcpy(key_or_subpath_raw, key_subpath.c_str(), key_len);
            }
        }
    }

    void setDebugSource(const char* source_literal) {
        if (source_literal) {
            debug_source = source_literal;
        }
    }

    const char* getDebugSource() const {
        return (debug_source && debug_source[0] != '\0') ? debug_source : "unknown";
    }

    ~Operation() {
        // CRITICAL: Destructor intentionally does NOTHING to prevent heap corruption
        // All cleanup is handled manually in destroy_operation()
        // This prevents double-free and mixed-heap allocation issues where:
        // - Operation object allocated in DRAM via new Operation()
        // - Internal pointers allocated in PSRAM via heap_caps_malloc()
        // When delete op is called, the destructor would try to call heap_caps_free()
        // on PSRAM pointers, causing "pointer is outside heap areas" assertion
    }
};

// POD message structure for FreeRTOS queue (avoids std::shared_ptr issues)
struct OpMsg {
    Operation* op;
    bool is_sync;                 // true = caller waiting
};

// ========================= MAIN ENGINE CLASS =========================

class Engine {
public:
    // Singleton pattern
    static Engine& getInstance();

    // Lifecycle
    bool initialize();
    void shutdown();
    bool isInitialized() const { return initialized_; }

    // ==================== SYNCHRONOUS API ====================

    // NVS Operations - Synchronous
    esp_err_t nvsSetString(const std::string& ns, const std::string& key, const std::string& value);
    esp_err_t nvsGetString(const std::string& ns, const std::string& key, std::string& out_value);

    // PSRAM-compatible NVS operations (needed for Configuration Manager compatibility)
    esp_err_t nvsSetString(const std::string& ns, const std::string& key, const psram_string& value);
    esp_err_t nvsGetString(const std::string& ns, const std::string& key, psram_string& out_value);
    esp_err_t nvsSetU8(const std::string& ns, const std::string& key, uint8_t value);
    esp_err_t nvsGetU8(const std::string& ns, const std::string& key, uint8_t& out_value);
    esp_err_t nvsSetU16(const std::string& ns, const std::string& key, uint16_t value);
    esp_err_t nvsGetU16(const std::string& ns, const std::string& key, uint16_t& out_value);
    esp_err_t nvsSetU32(const std::string& ns, const std::string& key, uint32_t value);
    esp_err_t nvsGetU32(const std::string& ns, const std::string& key, uint32_t& out_value);
    esp_err_t nvsSetI8(const std::string& ns, const std::string& key, int8_t value);
    esp_err_t nvsGetI8(const std::string& ns, const std::string& key, int8_t& out_value);
    esp_err_t nvsSetI16(const std::string& ns, const std::string& key, int16_t value);
    esp_err_t nvsGetI16(const std::string& ns, const std::string& key, int16_t& out_value);
    esp_err_t nvsSetI32(const std::string& ns, const std::string& key, int32_t value);
    esp_err_t nvsGetI32(const std::string& ns, const std::string& key, int32_t& out_value);
    esp_err_t nvsSetI64(const std::string& ns, const std::string& key, int64_t value);
    esp_err_t nvsGetI64(const std::string& ns, const std::string& key, int64_t& out_value);
    esp_err_t nvsSetBlob(const std::string& ns, const std::string& key, const void* data, size_t size);
    esp_err_t nvsGetBlob(const std::string& ns, const std::string& key, std::vector<uint8_t>& out_data);
    esp_err_t nvsEraseKey(const std::string& ns, const std::string& key);
    esp_err_t nvsEraseAll(const std::string& ns);

    // Filesystem Operations - Synchronous
    esp_err_t fileWrite(const std::string& path, const std::string& data);
    esp_err_t fileWrite(const std::string& path, const std::vector<uint8_t>& data);
    esp_err_t fileWrite(const std::string& path, const psram_string& data);
    esp_err_t fileRead(const std::string& path, std::string& out_data);
    esp_err_t fileRead(const std::string& path, std::vector<uint8_t>& out_data);
    esp_err_t fileRead(const std::string& path, psram_string& out_data);
    esp_err_t fileAppend(const std::string& path, const std::string& data);
    esp_err_t fileAppend(const std::string& path, const std::vector<uint8_t>& data);
    esp_err_t fileAppend(const std::string& path, const psram_string& data);
    esp_err_t fileDelete(const std::string& path);
    esp_err_t fileExists(const std::string& path, bool& exists);
    esp_err_t fileSize(const std::string& path, size_t& size);
    void ensureDataDirectories();
    esp_err_t createDirectory(const std::string& path);
    esp_err_t fileRename(const std::string& old_path, const std::string& new_path);
    esp_err_t listDirectory(const std::string& path, std::vector<std::string>& files);
    // Raw buffer FS operations (buffer is copied to PSRAM internally)
    esp_err_t fileWriteRaw(const std::string& path, const void* data, size_t size);
    esp_err_t fileAppendRaw(const std::string& path, const void* data, size_t size);
    // Overloads avoiding std::string construction (low-DRAM safe)
    esp_err_t fileWriteRaw(const char* path, const void* data, size_t size);
    esp_err_t fileAppendRaw(const char* path, const void* data, size_t size);

    // ==================== ASYNCHRONOUS API ====================

    // NVS Operations - Asynchronous
    void nvsSetStringAsync(const std::string& ns, const std::string& key,
                          const std::string& value, CompletionCallback callback);
    void nvsGetStringAsync(const std::string& ns, const std::string& key, CompletionCallback callback);
    void nvsSetU32Async(const std::string& ns, const std::string& key, uint32_t value, CompletionCallback callback);
    void nvsGetU32Async(const std::string& ns, const std::string& key, CompletionCallback callback);

    // Filesystem Operations - Asynchronous
    void fileWriteAsync(const std::string& path, const std::string& data, CompletionCallback callback);
    void fileReadAsync(const std::string& path, CompletionCallback callback);
    void fileAppendAsync(const std::string& path, const std::string& data, CompletionCallback callback);
    void fileDeleteAsync(const std::string& path, CompletionCallback callback);

    // ==================== UTILITY METHODS ====================

    // Queue status
    size_t getPendingOperations() const;
    bool isQueueFull() const;

    // Statistics
    size_t getTotalOperations() const { return total_operations_; }
    size_t getFailedOperations() const { return failed_operations_; }

private:
    // Constructor/Destructor (singleton)
    Engine() = default;
    ~Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    // Configuration (must be defined before usage)
    static constexpr size_t QUEUE_SIZE = 64;
    static constexpr size_t WORKER_STACK_SIZE = TaskConfig::SystemTasks::ASYNC_STORAGE_STACK_SIZE;  // 8KB in INTERNAL_RAM
    static constexpr UBaseType_t WORKER_PRIORITY = TaskConfig::SystemTasks::ASYNC_STORAGE_PRIORITY;   // High priority
    static constexpr TickType_t SYNC_TIMEOUT_MS = 30000; // 30 second timeout for sync ops

    // Internal state
    bool initialized_ = false;
    TaskHandle_t worker_task_handle_ = nullptr;
    QueueHandle_t operation_queue_ = nullptr;

    // Static buffers for worker task (INTERNAL_RAM allocation)
    static constexpr size_t WORKER_STACK_WORDS = WORKER_STACK_SIZE / sizeof(StackType_t);
    StackType_t worker_stack_[WORKER_STACK_WORDS];
    StaticTask_t worker_tcb_;

    // Statistics
    std::atomic<size_t> total_operations_{0};
    std::atomic<size_t> failed_operations_{0};

    // Helper functions for PSRAM-safe operation allocation
    Operation* createOperationInPSRAM(OpType type, const std::string& ns_or_path, const std::string& key_or_subpath = "");
    Operation* createOperationInPSRAM(OpType type, const std::string& ns_or_path);

    // Internal methods
    static void workerTaskFunction(void* param);
    void processOperations();
    void processNVSOperation(Operation* op);
    void processFilesystemOperation(Operation* op);

    // Synchronous operation helper
    esp_err_t executeSyncOperation(Operation* op);

    // Asynchronous operation helper
    void executeAsyncOperation(Operation* op);
};

// ========================= CONVENIENCE FUNCTIONS =========================

// Global access functions (shortcuts to singleton)
namespace Global {
    // Initialize the global storage engine
    bool initialize();
    void shutdown();

    // NVS shortcuts
    esp_err_t nvsSet(const std::string& ns, const std::string& key, const std::string& value);
    esp_err_t nvsGet(const std::string& ns, const std::string& key, std::string& value);

    // PSRAM-compatible NVS shortcuts (needed for Configuration Manager compatibility)
    esp_err_t nvsSet(const std::string& ns, const std::string& key, const psram_string& value);
    esp_err_t nvsGet(const std::string& ns, const std::string& key, psram_string& value);
    esp_err_t nvsSet(const std::string& ns, const std::string& key, uint32_t value);
    esp_err_t nvsGet(const std::string& ns, const std::string& key, uint32_t& value);
    esp_err_t nvsSet(const std::string& ns, const std::string& key, uint8_t value);
    esp_err_t nvsGet(const std::string& ns, const std::string& key, uint8_t& value);

    // NVS blob operations
    esp_err_t nvsSetBlob(const std::string& ns, const std::string& key, const void* data, size_t size);
    esp_err_t nvsGetBlob(const std::string& ns, const std::string& key, std::vector<uint8_t>& out_data);
    esp_err_t nvsEraseKey(const std::string& ns, const std::string& key);
    esp_err_t nvsEraseAll(const std::string& ns);

    // Filesystem shortcuts
    esp_err_t writeFile(const std::string& path, const std::string& data);
    esp_err_t writeFile(const std::string& path, const psram_string& data);
    esp_err_t readFile(const std::string& path, std::string& data);
    esp_err_t readFile(const std::string& path, psram_string& data);
    esp_err_t appendFile(const std::string& path, const std::string& data);
    esp_err_t appendFile(const std::string& path, const psram_string& data);
    // Raw buffer helpers to avoid large std::string allocations; caller can chunk
    esp_err_t writeFileRaw(const std::string& path, const void* data, size_t size);
    esp_err_t appendFileRaw(const std::string& path, const void* data, size_t size);
    esp_err_t deleteFile(const std::string& path);
    esp_err_t createDir(const std::string& path);
    esp_err_t fileExists(const std::string& path, bool& exists);
    esp_err_t fileSize(const std::string& path, size_t& size);
    void ensureDataDirectories();
}

} // namespace AsyncStorage
