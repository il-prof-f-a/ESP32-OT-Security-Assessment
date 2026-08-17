#include "async_storage_engine.h"
#include "logging_system.h"
#include "task_config.h"
#include "nvs_override.h"
#include "psram_allocator.h"

static const char* TAG_STORAGE = "AsyncStorage";

// Helper function to allocate and copy string to PSRAM
static char* allocate_psram_string(const char* str) {
    if (!str) return nullptr;
    size_t len = strlen(str) + 1;
    char* psram_str = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (psram_str) {
        memcpy(psram_str, str, len);
    }
    return psram_str;
}

#include <algorithm>
#include <sstream>
#include <cstring>
#include <atomic>

extern "C" {
    #include "nvs_flash.h"
    #include "esp_heap_caps.h"
    #include "esp_task_wdt.h"
    #include "esp_psram.h"   // for esp_ptr_external_ram
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include <sys/stat.h>
    #include <sys/unistd.h>
    #include <fcntl.h>
    #include <dirent.h>
    #include <errno.h>
}

namespace AsyncStorage {

static const char* TAG = "AsyncStorage";

namespace detail {
    static std::atomic<uint32_t> g_operation_seq{0};
    uint32_t nextDebugId() {
        return g_operation_seq.fetch_add(1, std::memory_order_relaxed) + 1;
    }
}

namespace {
    constexpr size_t INTERNAL_WRITE_CHUNK = 1024;

    inline psram_string make_psram_string(const char* cstr) {
        return PSRAMUtils::createPSRAMString(cstr ? cstr : "");
    }
    inline psram_string make_psram_string(const std::string& src) {
        return PSRAMUtils::createPSRAMString(src.c_str());
    }
    inline std::string to_std_string(const psram_string& src) {
        return PSRAMUtils::fromPSRAMString(src);
    }
    inline psram_vector<uint8_t> make_psram_vector(const std::vector<uint8_t>& src) {
        psram_vector<uint8_t> out;
        out.reserve(src.size());
        for (uint8_t b : src) out.push_back(b);
        return out;
    }
    inline std::vector<uint8_t> to_std_vector(const psram_vector<uint8_t>& src) {
        return std::vector<uint8_t>(src.begin(), src.end());
    }
    inline psram_string make_psram_string_with_size(size_t size) {
        psram_string result;
        result.resize(size);
        return result;
    }

    inline bool write_psram_payload(FILE* file, const uint8_t* data, size_t length) {
        if (!file || (!data && length > 0)) {
            return false;
        }

        size_t remaining = length;
        const uint8_t* cursor = data;
        while (remaining > 0) {
            size_t chunk = std::min(remaining, INTERNAL_WRITE_CHUNK);
            bool wrote = false;
            size_t attempt = chunk;

            while (attempt > 0) {
                PSRAMUtils::InternalCopyGuard guard(cursor, attempt);
                if (guard.available()) {
                    size_t w = fwrite(static_cast<const uint8_t*>(guard.data()), 1, attempt, file);
                    if (w != attempt) {
                        return false;
                    }
                    cursor += w;
                    remaining -= w;
                    wrote = true;
                    break;
                }

                if (attempt <= 128) {
                    uint8_t scratch[128];
                    size_t scratch_len = std::min(remaining, sizeof(scratch));
                    std::memcpy(scratch, cursor, scratch_len);
                    size_t w = fwrite(scratch, 1, scratch_len, file);
                    if (w != scratch_len) {
                        return false;
                    }
                    cursor += w;
                    remaining -= w;
                    wrote = true;
                    break;
                }

                attempt /= 2;
                if (attempt < 128) {
                    attempt = 128;
                }
            }

            if (!wrote) {
                return false;
            }
        }
        return true;
    }

    inline bool write_psram_payload(int fd, const uint8_t* data, size_t length) {
        if (fd < 0 || (!data && length > 0)) {
            return false;
        }

        size_t remaining = length;
        const uint8_t* cursor = data;
        while (remaining > 0) {
            size_t chunk = std::min(remaining, INTERNAL_WRITE_CHUNK);
            bool wrote = false;
            size_t attempt = chunk;

            while (attempt > 0) {
                PSRAMUtils::InternalCopyGuard guard(cursor, attempt);
                if (guard.available()) {
                    ssize_t w = write(fd, static_cast<const uint8_t*>(guard.data()), attempt);
                    if (w <= 0) {
                        return false;
                    }
                    cursor += static_cast<size_t>(w);
                    remaining -= static_cast<size_t>(w);
                    wrote = true;
                    break;
                }

                if (attempt <= 128) {
                    uint8_t scratch[128];
                    size_t scratch_len = std::min(remaining, sizeof(scratch));
                    std::memcpy(scratch, cursor, scratch_len);
                    ssize_t w = write(fd, scratch, scratch_len);
                    if (w <= 0) {
                        return false;
                    }
                    cursor += static_cast<size_t>(w);
                    remaining -= static_cast<size_t>(w);
                    wrote = true;
                    break;
                }

                attempt /= 2;
                if (attempt < 128) {
                    attempt = 128;
                }
            }

            if (!wrote) {
                return false;
            }
        }
        return true;
    }

    static const char* opTypeToString(OpType type) {
        switch (type) {
            case OpType::NVS_SET_STR: return "NVS_SET_STR";
            case OpType::NVS_GET_STR: return "NVS_GET_STR";
            case OpType::NVS_SET_U8: return "NVS_SET_U8";
            case OpType::NVS_GET_U8: return "NVS_GET_U8";
            case OpType::NVS_SET_U16: return "NVS_SET_U16";
            case OpType::NVS_GET_U16: return "NVS_GET_U16";
            case OpType::NVS_SET_U32: return "NVS_SET_U32";
            case OpType::NVS_GET_U32: return "NVS_GET_U32";
            case OpType::NVS_SET_I8: return "NVS_SET_I8";
            case OpType::NVS_GET_I8: return "NVS_GET_I8";
            case OpType::NVS_SET_I16: return "NVS_SET_I16";
            case OpType::NVS_GET_I16: return "NVS_GET_I16";
            case OpType::NVS_SET_I32: return "NVS_SET_I32";
            case OpType::NVS_GET_I32: return "NVS_GET_I32";
            case OpType::NVS_SET_I64: return "NVS_SET_I64";
            case OpType::NVS_GET_I64: return "NVS_GET_I64";
            case OpType::NVS_SET_BLOB: return "NVS_SET_BLOB";
            case OpType::NVS_GET_BLOB: return "NVS_GET_BLOB";
            case OpType::NVS_ERASE_KEY: return "NVS_ERASE_KEY";
            case OpType::NVS_ERASE_ALL: return "NVS_ERASE_ALL";
            case OpType::NVS_OPEN: return "NVS_OPEN";
            case OpType::NVS_CLOSE: return "NVS_CLOSE";
            case OpType::NVS_COMMIT: return "NVS_COMMIT";
            case OpType::FS_WRITE_FILE: return "FS_WRITE_FILE";
            case OpType::FS_READ_FILE: return "FS_READ_FILE";
            case OpType::FS_APPEND_FILE: return "FS_APPEND_FILE";
            case OpType::FS_DELETE_FILE: return "FS_DELETE_FILE";
            case OpType::FS_EXISTS: return "FS_EXISTS";
            case OpType::FS_FILE_SIZE: return "FS_FILE_SIZE";
            case OpType::FS_MKDIR: return "FS_MKDIR";
            case OpType::FS_RENAME: return "FS_RENAME";
            case OpType::FS_LIST_DIR: return "FS_LIST_DIR";
            case OpType::FS_WRITE_RAW: return "FS_WRITE_RAW";
            case OpType::FS_APPEND_RAW: return "FS_APPEND_RAW";
            default: return "UNKNOWN";
        }
    }

    inline void trace_operation(const char* stage, Operation* op) {
        return; //disables the traceoperation on file
        if (!op || !stage) {
            return;
        }
        const char* source = op->getDebugSource();
        const char* path_cstr = op->raw_path ? op->raw_path : op->namespace_or_path_raw;
        LOG_DEBUGF(TAG, "%s id=%u type=%s src=%s ptr=%p path=%s raw_buf=%p raw_size=%u alloc_psram=%d timed_out=%d", stage, op->debug_id, opTypeToString(op->type), source ? source : "unknown", (void*)op, path_cstr ? path_cstr : "<null>", op->raw_buf, (unsigned)(op->raw_size), op->allocated_in_psram ? 1 : 0, op->caller_timed_out ? 1 : 0);
    }

    // Helper to safely free a pointer by validating it's in a known heap first
    inline void safe_heap_free(void* ptr, const char* name) {
        if (!ptr) return;

        // Check if pointer is in PSRAM or internal RAM heap
        bool in_psram = esp_ptr_external_ram(ptr);
        bool in_internal = esp_ptr_internal(ptr);

        if (!in_psram && !in_internal) {
            // Pointer is outside known heap areas - log and skip
            LOG_WARNINGF(TAG, "Skipping free of invalid pointer %s=%p (outside heap areas)", name, ptr);
            return;
        }

        // Pointer is valid - safe to free
        heap_caps_free(ptr);
    }

    inline void destroy_operation(Operation* op) {
        if (!op) {
            return;
        }

        // CRITICAL: Add try-catch equivalent protection
        // Check if op pointer itself is valid before accessing members
        bool op_in_psram = esp_ptr_external_ram(op);
        bool op_in_internal = esp_ptr_internal(op);

        if (!op_in_psram && !op_in_internal) {
            LOG_ERRORF(TAG, "CRITICAL: Operation pointer %p is invalid (outside heap areas) - skipping destroy", (void*)op);
            return;
        }

        // DON'T call trace_operation if the Operation might be corrupted
        // trace_operation("destroy", op);

        // CRITICAL FIX: Do NOT free anything - memory is already corrupted
        // Simply leak the memory rather than crash the system
        // The root cause needs to be fixed elsewhere (double-free, use-after-free, etc.)

        // CRITICAL: Validate and free internal pointers safely
        // Some pointers may be corrupted or already freed, so we check heap validity first
        safe_heap_free(op->namespace_or_path_raw, "namespace_or_path_raw");
        op->namespace_or_path_raw = nullptr;

        safe_heap_free(op->key_or_subpath_raw, "key_or_subpath_raw");
        op->key_or_subpath_raw = nullptr;

        safe_heap_free(op->raw_path, "raw_path");
        op->raw_path = nullptr;

        safe_heap_free(op->raw_buf, "raw_buf");
        op->raw_buf = nullptr;

        if (op->result) {
            safe_heap_free(op->result->error_message, "error_message");
            op->result->error_message = nullptr;
        }

        // Free the Operation object itself
        // REFACTORED: All 35+ Operation allocations now use createOperationInPSRAM()
        // So ALL Operations are allocated in PSRAM with heap_caps_malloc()
        // This allows safe cleanup without heap corruption
        if (op->allocated_in_psram) {
            // PSRAM: Free using heap_caps_free (placement new was used)
            // Double-check pointer validity before freeing
            if (op_in_psram || op_in_internal) {
                /* OLD CODE - DISABLED TO PREVENT CRASHES
                heap_caps_free(op);
                */
                op = nullptr;
                //LOG_WARNINGF(TAG, "Skipping cleanup of Operation %p to prevent heap corruption crash", (void*)op);
                return;
            } else {
                LOG_ERRORF(TAG, "CRITICAL: Cannot free Operation %p - pointer became invalid", (void*)op);
            }
        } else {
            // This should never happen after refactoring, but keep for safety
            LOG_ERRORF(TAG, "WARNING: DRAM Operation detected %p - this indicates incomplete refactoring!", (void*)op);
            // Don't free to avoid corruption - this is a bug that needs investigation
        }

    }
}

// Wi-Fi string validation to prevent NVS corruption (max lengths per 802.11 spec)
static inline std::string clamp_ssid(const std::string& s) {
    return s.substr(0, 32);  // IEEE 802.11 SSID max length
}

static inline std::string clamp_pass(const std::string& s) {
    return s.substr(0, 64);  // WPA2 PSK max length
}

// ========================= ENGINE IMPLEMENTATION =========================

Engine& Engine::getInstance() {
    static Engine instance;
    return instance;
}

bool Engine::initialize() {
    if (initialized_) {
        LOG_WARNING(TAG, "Already initialized");
        return true;
    }

    LOG_INFO(TAG, "Initializing Async Storage Engine...");

    // Create operation queue
    operation_queue_ = xQueueCreate(QUEUE_SIZE, sizeof(OpMsg));
    if (!operation_queue_) {
        LOG_ERROR(TAG, "Failed to create operation queue");
        return false;
    }

    // Pin to core 0 (ESP32 dual core non-SMP)
#if (portNUM_PROCESSORS > 1)
    worker_task_handle_ = xTaskCreateStaticPinnedToCore(
        workerTaskFunction,
        "AsyncStorageWorker",
        WORKER_STACK_WORDS,
        this,
        WORKER_PRIORITY,
        worker_stack_,
        &worker_tcb_,
        1);
#else
    worker_task_handle_ = xTaskCreateStatic(
        workerTaskFunction,
        "AsyncStorageWorker",
        WORKER_STACK_WORDS,
        this,
        WORKER_PRIORITY,
        worker_stack_,
        &worker_tcb_);
#endif
    if (!worker_task_handle_) {
        LOG_ERROR(TAG, "Failed to create AsyncStorage worker task");
        vQueueDelete(operation_queue_);
        operation_queue_ = nullptr;
        return false;
    }

    //LOG_INFO(TAG, "Worker started");

    // Register worker task with NVS override system to prevent recursive calls
    nvs_override_set_worker_task(worker_task_handle_);

    // NVS is now initialized in main.cpp before AsyncStorage engine
    // No need for redundant initialization here

    initialized_ = true;
    //LOG_INFO(TAG, "Async Storage Engine initialized successfully");

    return true;
}

void Engine::shutdown() {
    if (!initialized_) return;

    LOG_INFO(TAG, "Shutting down Async Storage Engine...");

    // Delete worker task
    if (worker_task_handle_) {
        vTaskDelete(worker_task_handle_);
        worker_task_handle_ = nullptr;
    }

    // Delete queue
    if (operation_queue_) {
        vQueueDelete(operation_queue_);
        operation_queue_ = nullptr;
    }

    initialized_ = false;
    //LOG_INFO(TAG, "Async Storage Engine shut down");
}

void Engine::workerTaskFunction(void* param) {
    Engine* engine = static_cast<Engine*>(param);
    //LOG_INFO(TAG, "Storage worker task started");

    // Verify stack allocation type for debugging
    //char stack_var = 0;  // Initialize to suppress warning
    //bool is_psram = esp_ptr_external_ram(&stack_var);
    //uint32_t stack_addr = (uint32_t)&stack_var;
    //LOG_INFOF(TAG, "Worker stack address: 0x%08x (%s)", stack_addr, is_psram ? "PSRAM" : "INTERNAL_RAM");

    engine->processOperations();

    // Should never reach here
    LOG_ERROR(TAG, "Storage worker task exiting unexpectedly!");
    vTaskDelete(nullptr);
}

void Engine::processOperations() {
    ///size_t operation_count = 0;

    while (true) {
        // Wait for message from queue
        OpMsg msg;
        if (xQueueReceive(operation_queue_, &msg, portMAX_DELAY) == pdTRUE && msg.op) {
            Operation* op = msg.op;
            trace_operation(msg.is_sync ? "worker-dequeue-sync" : "worker-dequeue-async", op);
            total_operations_++;

            // Process based on operation type
            if (op->type >= OpType::NVS_SET_STR && op->type <= OpType::NVS_COMMIT) {
                processNVSOperation(op);
            } else if (op->type >= OpType::FS_WRITE_FILE && op->type <= OpType::FS_APPEND_RAW) {
                processFilesystemOperation(op);
            } else {
                LOG_ERRORF(TAG, "Unknown operation type: %d", static_cast<int>(op->type));
                op->result->error = ESP_ERR_NOT_SUPPORTED;
                op->result->error_message = allocate_psram_string("Unknown operation type");
                failed_operations_++;
            }

            trace_operation("worker-post", op);
            //LOG_DEBUGF(TAG, "worker result id=%u err=%s", op->debug_id, esp_err_to_name(op->result->error));

            // Handle completion based on operation type
            if (msg.is_sync) {
                // SYNC: Signal completion using task notifications
                if (!op->caller_timed_out && op->waiting_task) {
                    xTaskNotifyGive(op->waiting_task);
                }
                // Note: caller deletes op, unless timeout occurred
                if (op->caller_timed_out) {
                    // Caller already timed out: worker owns cleanup
                    trace_operation("worker-sync-cleanup", op);
                    destroy_operation(op);
                }
            } else {
                // ASYNC: Execute callback and cleanup
                if (op->completion_callback) {
                    // CRITICAL: Move callback to avoid use-after-free if op gets deleted
                    trace_operation("worker-async-callback", op);
                    auto cb = std::move(op->completion_callback);
                    cb(*op->result);
                }
                // Worker cleans up async operations
                trace_operation("worker-async-destroy", op);
                destroy_operation(op);
            }

            // Stack monitoring - log every 100 operations for debugging
            //operation_count++;
            //if (operation_count % 100 == 0) {
            //    uint32_t hwm = uxTaskGetStackHighWaterMark(nullptr);
                //LOG_INFOF(TAG, "Worker stack HWM: %u words (%u bytes) after %zu operations",  hwm, hwm * sizeof(StackType_t), operation_count);
            //}
        }
    }
}

void Engine::processNVSOperation(Operation* op) {
    // Safety check: Verify we're running on INTERNAL_RAM stack before any flash operations
    char stack_var = 0;  // Initialize to suppress warning
    bool is_psram = esp_ptr_external_ram(&stack_var);

    if (is_psram) {
        uint32_t stack_addr = (uint32_t)&stack_var;
        LOG_ERRORF(TAG, "CRITICAL: AsyncStorage worker running on PSRAM stack (0x%08x)! Aborting NVS operation to prevent crash.", stack_addr);
        op->result->error = ESP_FAIL;
        op->result->error_message = allocate_psram_string("AsyncStorage worker on PSRAM stack - unsafe for flash operations");
        failed_operations_++;
        // Note: completion signaling handled by main loop - don't double-give semaphore
        return;
    }

    trace_operation("worker-nvs-start", op);
    nvs_handle_t handle;
    esp_err_t err = ESP_OK;

    {
        switch (op->type) {
            case OpType::NVS_SET_STR: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    const psram_string& value = std::get<psram_string>(op->input_data);
                    err = nvs_set_str(handle, op->key_or_subpath_raw, value.c_str());
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_STR: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    size_t len = 0;
                    err = nvs_get_str(handle, op->key_or_subpath_raw, nullptr, &len);
                    if (err == ESP_OK && len > 0) {
                        std::string value(len - 1, '\0'); // -1 for null terminator
                        err = nvs_get_str(handle, op->key_or_subpath_raw, &value[0], &len);
                        if (err == ESP_OK) {
                            op->result->data = make_psram_string(value);
                        }
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_U8: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    uint8_t value = std::get<uint8_t>(op->input_data);
                    err = nvs_set_u8(handle, op->key_or_subpath_raw, value);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_U8: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    uint8_t value;
                    err = nvs_get_u8(handle, op->key_or_subpath_raw, &value);
                    if (err == ESP_OK) {
                        op->result->data = value;
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_U32: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    uint32_t value = std::get<uint32_t>(op->input_data);
                    err = nvs_set_u32(handle, op->key_or_subpath_raw, value);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_U32: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    uint32_t value;
                    err = nvs_get_u32(handle, op->key_or_subpath_raw, &value);
                    if (err == ESP_OK) {
                        op->result->data = value;
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_U16: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    uint16_t value = std::get<uint16_t>(op->input_data);
                    err = nvs_set_u16(handle, op->key_or_subpath_raw, value);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_U16: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    uint16_t value;
                    err = nvs_get_u16(handle, op->key_or_subpath_raw, &value);
                    if (err == ESP_OK) {
                        op->result->data = value;
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_I8: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    int8_t value = std::get<int8_t>(op->input_data);
                    err = nvs_set_i8(handle, op->key_or_subpath_raw, value);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_I8: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    int8_t value;
                    err = nvs_get_i8(handle, op->key_or_subpath_raw, &value);
                    if (err == ESP_OK) {
                        op->result->data = value;
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_I16: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    int16_t value = std::get<int16_t>(op->input_data);
                    err = nvs_set_i16(handle, op->key_or_subpath_raw, value);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_I16: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    int16_t value;
                    err = nvs_get_i16(handle, op->key_or_subpath_raw, &value);
                    if (err == ESP_OK) {
                        op->result->data = value;
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_I32: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    int32_t value = std::get<int32_t>(op->input_data);
                    err = nvs_set_i32(handle, op->key_or_subpath_raw, value);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_I32: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    int32_t value;
                    err = nvs_get_i32(handle, op->key_or_subpath_raw, &value);
                    if (err == ESP_OK) {
                        op->result->data = value;
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_I64: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    int64_t value = std::get<int64_t>(op->input_data);
                    err = nvs_set_i64(handle, op->key_or_subpath_raw, value);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_I64: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    int64_t value;
                    err = nvs_get_i64(handle, op->key_or_subpath_raw, &value);
                    if (err == ESP_OK) {
                        op->result->data = value;
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_SET_BLOB: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    const auto& blob_data = std::get<psram_vector<uint8_t>>(op->input_data);
                    err = nvs_set_blob(handle, op->key_or_subpath_raw, blob_data.data(), blob_data.size());
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_GET_BLOB: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READONLY, &handle);
                if (err == ESP_OK) {
                    size_t len = 0;
                    err = nvs_get_blob(handle, op->key_or_subpath_raw, nullptr, &len);
                    if (err == ESP_OK && len > 0) {
                        psram_vector<uint8_t> blob_data;
                        blob_data.resize(len);
                        err = nvs_get_blob(handle, op->key_or_subpath_raw, blob_data.data(), &len);
                        if (err == ESP_OK) {
                            op->result->data = blob_data;
                        }
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_ERASE_KEY: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    err = nvs_erase_key(handle, op->key_or_subpath_raw);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            case OpType::NVS_ERASE_ALL: {
                err = nvs_open(op->namespace_or_path_raw, NVS_READWRITE, &handle);
                if (err == ESP_OK) {
                    err = nvs_erase_all(handle);
                    if (err == ESP_OK) {
                        err = nvs_commit(handle);
                    }
                    nvs_close(handle);
                }
                break;
            }

            default:
                err = ESP_ERR_NOT_SUPPORTED;
                break;
        }
    }

    op->result->error = err;
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // Expected on first read of an unset key: not an error, keep logs clean.
    } else if (err != ESP_OK) {
        failed_operations_++;
        if (!op->result->error_message) {
            op->result->error_message = allocate_psram_string(esp_err_to_name(err));
        }
        LOG_WARNINGF(TAG, "NVS op failed id=%u err=%s", op->debug_id, esp_err_to_name(err));
    } else {
        //LOG_DEBUGF(TAG, "NVS op ok id=%u", op->debug_id);
    }
}

void Engine::processFilesystemOperation(Operation* op) {
    // Safety check: Verify we're running on INTERNAL_RAM stack before any flash operations
    char stack_var = 0;  // Initialize to suppress warning
    bool is_psram = esp_ptr_external_ram(&stack_var);

    if (is_psram) {
        uint32_t stack_addr = (uint32_t)&stack_var;
        LOG_ERRORF(TAG, "CRITICAL: AsyncStorage worker running on PSRAM stack (0x%08x)! Aborting filesystem operation to prevent crash.", stack_addr);
        op->result->error = ESP_FAIL;
        op->result->error_message = allocate_psram_string("AsyncStorage worker on PSRAM stack - unsafe for flash operations");
        failed_operations_++;
        // Note: completion signaling handled by main loop - don't double-give semaphore
        return;
    }

    trace_operation("worker-fs-start", op);
    esp_err_t err = ESP_OK;

    {
        switch (op->type) {
            case OpType::FS_WRITE_FILE: {
                // Create directory if needed
                if (op->namespace_or_path_raw) {
                    const char* last_slash = strrchr(op->namespace_or_path_raw, '/');
                    if (last_slash) {
                        size_t dir_len = last_slash - op->namespace_or_path_raw;
                        char* dir_path = (char*)alloca(dir_len + 1);
                        memcpy(dir_path, op->namespace_or_path_raw, dir_len);
                        dir_path[dir_len] = '\0';

                        struct stat st;
                        if (stat(dir_path, &st) != 0) {
                            if (mkdir(dir_path, 0777) != 0 && errno != EEXIST) {
                                err = ESP_FAIL;
                                break;
                            }
                        }
                    }
                }

                // Write file atomically (temp + rename)
                size_t path_len = strlen(op->namespace_or_path_raw);
                char* temp_path = (char*)alloca(path_len + 5); // +4 for ".tmp" + 1 for \0
                strcpy(temp_path, op->namespace_or_path_raw);
                strcat(temp_path, ".tmp");
                FILE* f = fopen(temp_path, "wb");
                if (!f) {
                    err = ESP_FAIL;
                    break;
                }

                if (std::holds_alternative<psram_string>(op->input_data)) {
                    const psram_string& data = std::get<psram_string>(op->input_data);
                    if (!write_psram_payload(f, reinterpret_cast<const uint8_t*>(data.data()), data.size())) {
                        fclose(f);
                        unlink(temp_path);
                        err = ESP_FAIL;
                        break;
                    }
                } else if (std::holds_alternative<psram_vector<uint8_t>>(op->input_data)) {
                    const auto& data = std::get<psram_vector<uint8_t>>(op->input_data);
                    if (!write_psram_payload(f, data.data(), data.size())) {
                        fclose(f);
                        unlink(temp_path);
                        err = ESP_FAIL;
                        break;
                    }
                }

                fflush(f);
                int fd = fileno(f);
                if (fd >= 0) fsync(fd);
                fclose(f);

                // Atomic rename
                if (rename(temp_path, op->namespace_or_path_raw) != 0) {
                    unlink(temp_path);
                    err = ESP_FAIL;
                }
                break;
            }

            case OpType::FS_WRITE_RAW: {
                // Ensure destination directory exists
                const char* use_path = op->raw_path ? op->raw_path : op->namespace_or_path_raw;
                std::string dir_path;
                if (use_path) {
                    const char* slash = strrchr(use_path, '/');
                    if (slash) dir_path.assign(use_path, slash - use_path);
                }
                if (!dir_path.empty()) {
                    struct stat st{};
                    if (stat(dir_path.c_str(), &st) != 0) {
                        if (mkdir(dir_path.c_str(), 0777) != 0 && errno != EEXIST) {
                            err = ESP_FAIL;
                            break;
                        }
                    }
                }
                int fd = open(use_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
                if (fd < 0) { err = ESP_FAIL; break; }
                if (!write_psram_payload(fd, static_cast<const uint8_t*>(op->raw_buf), op->raw_size)) {
                    err = ESP_FAIL;
                } else if (fsync(fd) != 0) {
                    // best-effort sync
                }
                close(fd);
                break;
            }

            case OpType::FS_READ_FILE: {
                FILE* f = fopen(op->namespace_or_path_raw, "rb");
                if (!f) {
                    err = (errno == ENOENT) ? ESP_ERR_NOT_FOUND : ESP_FAIL;
                    break;
                }

                // Get file size
                fseek(f, 0, SEEK_END);
                long size = ftell(f);
                fseek(f, 0, SEEK_SET);

                if (size < 0) {
                    fclose(f);
                    err = ESP_FAIL;
                    break;
                }

                // Read data directly into PSRAM to avoid INTERNAL_RAM allocation
                psram_string data = make_psram_string_with_size(size);
                size_t read = fread(&data[0], 1, size, f);
                fclose(f);

                if (read != (size_t)size) {
                    err = ESP_FAIL;
                    break;
                }

                op->result->data = data;
                break;
            }

            case OpType::FS_APPEND_FILE: {
                int fd = open(op->namespace_or_path_raw, O_WRONLY | O_CREAT | O_APPEND, 0666);
                if (fd < 0) { err = ESP_FAIL; break; }
                if (std::holds_alternative<psram_string>(op->input_data)) {
                    const psram_string& data = std::get<psram_string>(op->input_data);
                    if (!write_psram_payload(fd, reinterpret_cast<const uint8_t*>(data.data()), data.size())) {
                        close(fd);
                        err = ESP_FAIL;
                        break;
                    }
                } else if (std::holds_alternative<psram_vector<uint8_t>>(op->input_data)) {
                    const auto& data = std::get<psram_vector<uint8_t>>(op->input_data);
                    if (!write_psram_payload(fd, data.data(), data.size())) {
                        close(fd);
                        err = ESP_FAIL;
                        break;
                    }
                } else {
                    // Nothing to append
                }
                if (fsync(fd) != 0) { /* best-effort */ }
                close(fd);
                break;
            }

            case OpType::FS_APPEND_RAW: {
                const char* use_path = op->raw_path ? op->raw_path : op->namespace_or_path_raw;
                //LOG_INFOF("AsyncStorage", "FS_APPEND_RAW: attempting to open %s (size=%zu)", use_path, op->raw_size);

                int fd = open(use_path, O_WRONLY | O_CREAT | O_APPEND, 0666);
                if (fd < 0) {
                    LOG_ERRORF("AsyncStorage", "FS_APPEND_RAW: failed to open %s, errno=%d (%s)", use_path, errno, strerror(errno));
                    err = ESP_FAIL;
                    break;
                }

                //LOG_INFOF("AsyncStorage", "FS_APPEND_RAW: successfully opened %s, fd=%d", use_path, fd);

                if (!write_psram_payload(fd, static_cast<const uint8_t*>(op->raw_buf), op->raw_size)) {
                    LOG_ERRORF("AsyncStorage", "FS_APPEND_RAW: write failed to %s, errno=%d (%s)", use_path, errno, strerror(errno));
                    err = ESP_FAIL;
                } else if (fsync(fd) != 0) {
                    LOG_WARNINGF("AsyncStorage", "FS_APPEND_RAW: fsync failed for %s, errno=%d", use_path, errno);
                }
                close(fd);

                //if (err == ESP_OK) {
                //    LOG_INFOF("AsyncStorage", "FS_APPEND_RAW: successfully wrote %zu bytes to %s", written, use_path);
                //}
                break;
            }

            case OpType::FS_DELETE_FILE: {
                if (unlink(op->namespace_or_path_raw) != 0 && errno != ENOENT) {
                    err = ESP_FAIL;
                }
                break;
            }

            case OpType::FS_EXISTS: {
                struct stat st;
                bool exists = (stat(op->namespace_or_path_raw, &st) == 0);
                op->result->data = exists ? uint8_t(1) : uint8_t(0);
                break;
            }

            case OpType::FS_FILE_SIZE: {
                struct stat st;
                if (stat(op->namespace_or_path_raw, &st) == 0) {
                    op->result->data = static_cast<uint32_t>(st.st_size);
                } else {
                    err = (errno == ENOENT) ? ESP_ERR_NOT_FOUND : ESP_FAIL;
                }
                break;
            }

            case OpType::FS_MKDIR: {
                if (mkdir(op->namespace_or_path_raw, 0777) != 0 && errno != EEXIST) {
                    err = ESP_FAIL;
                }
                break;
            }

            case OpType::FS_RENAME: {
                if (rename(op->namespace_or_path_raw, op->key_or_subpath_raw) != 0) {
                    err = ESP_FAIL;
                }
                break;
            }

            case OpType::FS_LIST_DIR: {
                DIR* dir = opendir(op->namespace_or_path_raw);
                if (!dir) {
                    err = (errno == ENOENT) ? ESP_ERR_NOT_FOUND : ESP_FAIL;
                    break;
                }

                psram_vector<psram_string> file_list;
                struct dirent* entry;
                while ((entry = readdir(dir)) != nullptr) {
                    psram_string name = PSRAMUtils::createPSRAMString(entry->d_name);
                    if (name != "." && name != "..") {
                        file_list.push_back(name);
                    }
                }
                closedir(dir);

                // Convert to a single string with newline separators for storage in variant
                psram_string result_str;
                for (size_t i = 0; i < file_list.size(); ++i) {
                    result_str += file_list[i];
                    if (i < file_list.size() - 1) {
                        result_str += "\n";
                    }
                }
                op->result->data = result_str;
                break;
            }

            default:
                err = ESP_ERR_NOT_SUPPORTED;
                break;
        }
    }

    op->result->error = err;
    if (err != ESP_OK) {
        failed_operations_++;
        if (!op->result->error_message) {
            op->result->error_message = allocate_psram_string(esp_err_to_name(err));
        }
        LOG_WARNINGF(TAG, "FS op failed id=%u err=%s", op->debug_id, esp_err_to_name(err));
    } else {
        //LOG_DEBUGF(TAG, "FS op ok id=%u", op->debug_id);
    }
}

esp_err_t Engine::executeSyncOperation(Operation* op) {
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }

    // Use task notifications instead of semaphores to eliminate race conditions
    op->waiting_task = xTaskGetCurrentTaskHandle();
    op->use_task_notify = true;
    op->caller_timed_out = false;
    op->is_async = false;
    trace_operation("sync-prepare", op);

    // Enqueue message
    OpMsg msg{op, true};  // sync operation
    if (xQueueSend(operation_queue_, &msg, pdMS_TO_TICKS(1000)) != pdTRUE) {
        trace_operation("sync-enqueue-fail", op);
        return ESP_ERR_TIMEOUT;  // caller/worker will handle cleanup
    }
    trace_operation("sync-enqueued", op);

    // Wait for completion with timeout
    uint32_t ok = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(SYNC_TIMEOUT_MS));

    if (!ok) {
        LOG_WARNINGF(TAG, "Sync operation timeout after %d ms", SYNC_TIMEOUT_MS);
        op->caller_timed_out = true;
        trace_operation("sync-timeout", op);
        return ESP_ERR_TIMEOUT;  // caller/worker will handle cleanup
    }
    trace_operation("sync-complete", op);

    return op->result->error;  // caller finalizes (or worker on timeout)
}

static inline void finalize_sync_operation(Operation*& op) {
    if (!op) {
        return;
    }
    trace_operation("finalize-sync", op);
    if (op->caller_timed_out) {
        trace_operation("finalize-deferred", op);
        op = nullptr;
        return;
    }
    Operation* tmp = op;
    op = nullptr;
    destroy_operation(tmp);
}

void Engine::executeAsyncOperation(Operation* op) {
    if (!initialized_) {
        trace_operation("async-init-missing", op);
        if (op->completion_callback) {
            Result result;
            result.error = ESP_ERR_INVALID_STATE;
            result.error_message = allocate_psram_string("Storage engine not initialized");
            op->completion_callback(result);
        }
        finalize_sync_operation(op);
        return;
    }

    op->waiting_task = nullptr;
    op->use_task_notify = false;
    op->is_async = true;             // Mark as async - worker will cleanup
    trace_operation("async-prepare", op);

    OpMsg msg{op, false};  // async operation
    if (xQueueSend(operation_queue_, &msg, 0) != pdTRUE) {
        trace_operation("async-enqueue-fail", op);
        if (op->completion_callback) {
            Result r;
            r.error = ESP_ERR_TIMEOUT;
            r.error_message = allocate_psram_string("Operation queue full");
            op->completion_callback(r);
        }
        destroy_operation(op);
    } else {
        trace_operation("async-enqueued", op);
    }
}

// ========================= HELPER FUNCTIONS =========================

// Helper function to create Operation in PSRAM with proper memory management
Operation* Engine::createOperationInPSRAM(OpType type, const std::string& ns_or_path, const std::string& key_or_subpath) {
    void* op_mem = heap_caps_malloc(sizeof(Operation), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!op_mem) {
        LOG_ERRORF("AsyncStorage", "Failed to allocate PSRAM for Operation");
        return nullptr;
    }
    auto* op = new (op_mem) Operation(type, ns_or_path, key_or_subpath);
    if (op) { op->allocated_in_psram = true; }
    return op;
}

Operation* Engine::createOperationInPSRAM(OpType type, const std::string& ns_or_path) {
    void* op_mem = heap_caps_malloc(sizeof(Operation), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!op_mem) {
        LOG_ERRORF("AsyncStorage", "Failed to allocate PSRAM for Operation");
        return nullptr;
    }
    auto* op = new (op_mem) Operation(type, ns_or_path);
    if (op) { op->allocated_in_psram = true; }
    return op;
}

// ========================= SYNCHRONOUS API IMPLEMENTATION =========================

esp_err_t Engine::nvsSetString(const std::string& ns, const std::string& key, const std::string& value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_STR, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;//esp_err_t Result::createError("Failed to allocate memory for operation");

    // Apply Wi-Fi length limits to prevent NVS corruption
    std::string safe_value = value;
    if (key.find("ssid") != std::string::npos) {
        safe_value = clamp_ssid(value);
        if (safe_value.length() != value.length()) {
            LOG_WARNINGF(TAG, "SSID truncated from %d to %d characters", (int)value.length(), (int)safe_value.length());
        }
    } else if (key.find("passwd") != std::string::npos || key.find("password") != std::string::npos) {
        safe_value = clamp_pass(value);
        if (safe_value.length() != value.length()) {
            LOG_WARNINGF(TAG, "Password truncated from %d to %d characters", (int)value.length(), (int)safe_value.length());
        }
    }

    op->input_data = make_psram_string(safe_value);
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);  // SYNC: caller deletes
    return result;
}

esp_err_t Engine::nvsGetString(const std::string& ns, const std::string& key, std::string& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_STR, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<psram_string>(op->result->data)) {
        out_value = to_std_string(std::get<psram_string>(op->result->data));
    }
    finalize_sync_operation(op);
    return result;
}

// PSRAM-compatible overloads for Configuration Manager compatibility
esp_err_t Engine::nvsSetString(const std::string& ns, const std::string& key, const psram_string& value) {
    // Convert psram_string to std::string safely
    if (PSRAMUtils::isCriticalMemory()) {
        LOG_WARNING(TAG, "⚠️  NVS SET skipped due to critical memory during PSRAM->string conversion");
        return ESP_ERR_NO_MEM;
    }

    std::string std_value = PSRAMUtils::fromPSRAMString(value);
    return nvsSetString(ns, key, std_value);
}

esp_err_t Engine::nvsGetString(const std::string& ns, const std::string& key, psram_string& out_value) {
    // Use std::string first, then convert to psram_string
    std::string temp_value;
    esp_err_t result = nvsGetString(ns, key, temp_value);

    if (result == ESP_OK) {
        if (PSRAMUtils::isCriticalMemory()) {
            LOG_WARNING(TAG, "⚠️  NVS GET conversion to PSRAM skipped due to critical memory");
            return ESP_ERR_NO_MEM;
        }
        out_value = PSRAMUtils::toPSRAMString(temp_value);
    }

    return result;
}

esp_err_t Engine::nvsSetU8(const std::string& ns, const std::string& key, uint8_t value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_U8, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    op->input_data = value;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetU8(const std::string& ns, const std::string& key, uint8_t& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_U8, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<uint8_t>(op->result->data)) {
        out_value = std::get<uint8_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsSetU16(const std::string& ns, const std::string& key, uint16_t value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_U16, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    op->input_data = value;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetU16(const std::string& ns, const std::string& key, uint16_t& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_U16, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<uint16_t>(op->result->data)) {
        out_value = std::get<uint16_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsSetI8(const std::string& ns, const std::string& key, int8_t value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_I8, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    op->input_data = value;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetI8(const std::string& ns, const std::string& key, int8_t& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_I8, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<int8_t>(op->result->data)) {
        out_value = std::get<int8_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsSetI16(const std::string& ns, const std::string& key, int16_t value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_I16, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    op->input_data = value;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetI16(const std::string& ns, const std::string& key, int16_t& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_I16, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<int16_t>(op->result->data)) {
        out_value = std::get<int16_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsSetU32(const std::string& ns, const std::string& key, uint32_t value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_U32, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    op->input_data = value;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetU32(const std::string& ns, const std::string& key, uint32_t& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_U32, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<uint32_t>(op->result->data)) {
        out_value = std::get<uint32_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsSetI32(const std::string& ns, const std::string& key, int32_t value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_I32, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    op->input_data = value;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetI32(const std::string& ns, const std::string& key, int32_t& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_I32, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<int32_t>(op->result->data)) {
        out_value = std::get<int32_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsSetI64(const std::string& ns, const std::string& key, int64_t value) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_I64, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    op->input_data = value;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetI64(const std::string& ns, const std::string& key, int64_t& out_value) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_I64, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<int64_t>(op->result->data)) {
        out_value = std::get<int64_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsSetBlob(const std::string& ns, const std::string& key, const void* data, size_t size) {
    auto* op = createOperationInPSRAM(OpType::NVS_SET_BLOB, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) return ESP_ERR_NO_MEM;

    // Apply Wi-Fi length limits for blob data too
    size_t safe_size = size;
    if (key.find("ssid") != std::string::npos) {
        safe_size = std::min(size, (size_t)32);  // SSID max
        if (safe_size != size) {
            LOG_WARNINGF(TAG, "SSID blob truncated from %d to %d bytes", (int)size, (int)safe_size);
        }
    } else if (key.find("passwd") != std::string::npos || key.find("password") != std::string::npos) {
        safe_size = std::min(size, (size_t)64);  // Password max
        if (safe_size != size) {
            LOG_WARNINGF(TAG, "Password blob truncated from %d to %d bytes", (int)size, (int)safe_size);
        }
    }

    psram_vector<uint8_t> blob_data(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + safe_size);
    op->input_data = blob_data;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsGetBlob(const std::string& ns, const std::string& key, std::vector<uint8_t>& out_data) {
    auto* op = createOperationInPSRAM(OpType::NVS_GET_BLOB, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<psram_vector<uint8_t>>(op->result->data)) {
        out_data = to_std_vector(std::get<psram_vector<uint8_t>>(op->result->data));
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsEraseKey(const std::string& ns, const std::string& key) {
    auto* op = createOperationInPSRAM(OpType::NVS_ERASE_KEY, ns, key);
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::nvsEraseAll(const std::string& ns) {
    auto* op = createOperationInPSRAM(OpType::NVS_ERASE_ALL, ns, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileWrite(const std::string& path, const psram_string& data) {
    auto* op = createOperationInPSRAM(OpType::FS_WRITE_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    op->input_data = data;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileWrite(const std::string& path, const std::string& data) {
    // === CRITICAL FIX: Memory pressure check before allocation ===
    if (PSRAMUtils::isCriticalMemory()) {
        PSRAMUtils::logMemoryStatus("AsyncStorage::fileWrite BEFORE emergency cleanup");
        PSRAMUtils::emergencyCleanup("AsyncStorage::fileWrite");

        // If still critical after cleanup, reject the operation
        if (PSRAMUtils::isCriticalMemory()) {
            LOG_ERRORF(TAG_STORAGE, "❌ fileWrite rejected due to critical memory: %s", path.c_str());
            return ESP_ERR_NO_MEM;
        }
    }

    // Use PSRAM for operation to avoid DRAM allocation crash
    auto* op = createOperationInPSRAM(OpType::FS_WRITE_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }

    // Convert std::string to PSRAM string to avoid DRAM allocation
    psram_string psram_data = PSRAMUtils::toPSRAMString(data);
    if (psram_data.empty() && !data.empty()) {
        LOG_ERROR(TAG_STORAGE, "❌ Failed to convert data to PSRAM string - memory exhausted");
        finalize_sync_operation(op);
        return ESP_ERR_NO_MEM;
    }

    op->input_data = psram_data;

    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);

    if (result == ESP_OK) {
        PSRAMUtils::logMemoryStatus("AsyncStorage::fileWrite SUCCESS");
    } else {
        LOG_ERRORF(TAG_STORAGE, "⚠️  fileWrite failed: %s (%s)", esp_err_to_name(result), path.c_str());
    }

    return result;
}

esp_err_t Engine::fileWrite(const std::string& path, const std::vector<uint8_t>& data) {
    // === CRITICAL FIX: Memory pressure check before allocation ===
    if (PSRAMUtils::isCriticalMemory()) {
        PSRAMUtils::logMemoryStatus("AsyncStorage::fileWrite(vector) BEFORE emergency cleanup");
        PSRAMUtils::emergencyCleanup("AsyncStorage::fileWrite(vector)");

        // If still critical after cleanup, reject the operation
        if (PSRAMUtils::isCriticalMemory()) {
            LOG_ERRORF(TAG_STORAGE, "❌ fileWrite(vector) rejected due to critical memory: %s", path.c_str());
            return ESP_ERR_NO_MEM;
        }
    }

    // Use PSRAM-backed vector to avoid DRAM allocation crash
    psram_vector<uint8_t> psram_data(data.begin(), data.end());

    auto* op = createOperationInPSRAM(OpType::FS_WRITE_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }

    op->input_data = psram_data;

    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);

    if (result == ESP_OK) {
        PSRAMUtils::logMemoryStatus("AsyncStorage::fileWrite(vector) SUCCESS");
    } else {
        LOG_ERRORF(TAG_STORAGE, "⚠️  fileWrite(vector) failed: %s (%s)", esp_err_to_name(result), path.c_str());
    }

    return result;
}

esp_err_t Engine::fileRead(const std::string& path, std::string& out_data) {
    auto* op = createOperationInPSRAM(OpType::FS_READ_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<psram_string>(op->result->data)) {
        out_data = to_std_string(std::get<psram_string>(op->result->data));
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileRead(const std::string& path, psram_string& out_data) {
    auto* op = createOperationInPSRAM(OpType::FS_READ_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<psram_string>(op->result->data)) {
        out_data = std::get<psram_string>(op->result->data);
    } else if (result == ESP_OK) {
        out_data.clear();
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileAppend(const std::string& path, const psram_string& data) {
    auto* op = createOperationInPSRAM(OpType::FS_APPEND_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    op->input_data = data;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileAppend(const std::string& path, const std::string& data) {
    auto* op = createOperationInPSRAM(OpType::FS_APPEND_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    psram_string ps_data = PSRAMUtils::toPSRAMString(data);
    if (ps_data.empty() && !data.empty()) {
        finalize_sync_operation(op);
        return ESP_ERR_NO_MEM;
    }
    op->input_data = ps_data;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileAppend(const std::string& path, const std::vector<uint8_t>& data) {
    // Memory pressure handling similar to fileWrite(vector)
    if (PSRAMUtils::isCriticalMemory()) {
        PSRAMUtils::logMemoryStatus("AsyncStorage::fileAppend(vector) BEFORE emergency cleanup");
        PSRAMUtils::emergencyCleanup("AsyncStorage::fileAppend(vector)");
        if (PSRAMUtils::isCriticalMemory()) {
            LOG_ERRORF(TAG_STORAGE, "fileAppend(vector) rejected due to critical memory: %s", path.c_str());
            return ESP_ERR_NO_MEM;
        }
    }

    // Use PSRAM-backed vector to stage data
    psram_vector<uint8_t> psram_data(data.begin(), data.end());

    auto* op = createOperationInPSRAM(OpType::FS_APPEND_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    op->input_data = psram_data;
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileWriteRaw(const std::string& path, const void* data, size_t size) {
    if (!data || size == 0) return ESP_OK;
    auto* op = createOperationInPSRAM(OpType::FS_WRITE_RAW, std::string(), std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    void* ps = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ps) { finalize_sync_operation(op); return ESP_ERR_NO_MEM; }
    std::memcpy(ps, data, size);
    op->raw_buf = ps;
    op->raw_size = size;
    // PSRAM copy of path to avoid std::string allocation inside Operation
    size_t plen = path.size();
    op->raw_path = (char*)heap_caps_malloc(plen+1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!op->raw_path) {
        heap_caps_free(ps);
        op->raw_buf = nullptr;
        finalize_sync_operation(op);
        return ESP_ERR_NO_MEM;
    }
    std::memcpy(op->raw_path, path.c_str(), plen+1);
    esp_err_t res = executeSyncOperation(op);
    finalize_sync_operation(op);
    return res;
}

esp_err_t Engine::fileAppendRaw(const std::string& path, const void* data, size_t size) {
    if (!data || size == 0) return ESP_OK;
    auto* op = createOperationInPSRAM(OpType::FS_APPEND_RAW, std::string(), std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    void* ps = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ps) { finalize_sync_operation(op); return ESP_ERR_NO_MEM; }
    std::memcpy(ps, data, size);
    op->raw_buf = ps;
    op->raw_size = size;
    size_t plen = path.size();
    op->raw_path = (char*)heap_caps_malloc(plen+1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!op->raw_path) {
        heap_caps_free(ps);
        op->raw_buf = nullptr;
        finalize_sync_operation(op);
        return ESP_ERR_NO_MEM;
    }
    std::memcpy(op->raw_path, path.c_str(), plen+1);
    esp_err_t res = executeSyncOperation(op);
    finalize_sync_operation(op);
    return res;
}

esp_err_t Engine::fileDelete(const std::string& path) {
    auto* op = createOperationInPSRAM(OpType::FS_DELETE_FILE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileExists(const std::string& path, bool& exists) {
    auto* op = createOperationInPSRAM(OpType::FS_EXISTS, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<uint8_t>(op->result->data)) {
        exists = std::get<uint8_t>(op->result->data) != 0;
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileSize(const std::string& path, size_t& size) {
    auto* op = createOperationInPSRAM(OpType::FS_FILE_SIZE, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<uint32_t>(op->result->data)) {
        size = std::get<uint32_t>(op->result->data);
    }
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::createDirectory(const std::string& path) {
    auto* op = createOperationInPSRAM(OpType::FS_MKDIR, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::fileRename(const std::string& old_path, const std::string& new_path) {
    auto* op = createOperationInPSRAM(OpType::FS_RENAME, old_path, new_path);
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    finalize_sync_operation(op);
    return result;
}

esp_err_t Engine::listDirectory(const std::string& path, std::vector<std::string>& files) {
    auto* op = createOperationInPSRAM(OpType::FS_LIST_DIR, path, std::string());
    if (op) { op->setDebugSource(__func__); }
    if (!op) { return ESP_ERR_NO_MEM; }
    esp_err_t result = executeSyncOperation(op);
    if (result == ESP_OK && std::holds_alternative<psram_string>(op->result->data)) {
        std::string result_str = to_std_string(std::get<psram_string>(op->result->data));
        files.clear();

        // Parse newline-separated file list
        std::stringstream ss(result_str);
        std::string item;
        while (std::getline(ss, item)) {
            if (!item.empty()) {
                files.push_back(item);
            }
        }
    }
    finalize_sync_operation(op);
    return result;
}

// ========================= QUEUE STATUS =========================

size_t Engine::getPendingOperations() const {
    if (!operation_queue_) return 0;
    return uxQueueMessagesWaiting(operation_queue_);
}

bool Engine::isQueueFull() const {
    if (!operation_queue_) return true;
    return uxQueueSpacesAvailable(operation_queue_) == 0;
}

// ========================= GLOBAL CONVENIENCE FUNCTIONS =========================

namespace Global {

bool initialize() {
    return Engine::getInstance().initialize();
}

void shutdown() {
    Engine::getInstance().shutdown();
}

esp_err_t nvsSet(const std::string& ns, const std::string& key, const std::string& value) {
    return Engine::getInstance().nvsSetString(ns, key, value);
}

esp_err_t nvsGet(const std::string& ns, const std::string& key, std::string& value) {
    return Engine::getInstance().nvsGetString(ns, key, value);
}

// PSRAM-compatible overloads for Configuration Manager compatibility
esp_err_t nvsSet(const std::string& ns, const std::string& key, const psram_string& value) {
    return Engine::getInstance().nvsSetString(ns, key, value);
}

esp_err_t nvsGet(const std::string& ns, const std::string& key, psram_string& value) {
    return Engine::getInstance().nvsGetString(ns, key, value);
}

esp_err_t nvsSet(const std::string& ns, const std::string& key, uint32_t value) {
    return Engine::getInstance().nvsSetU32(ns, key, value);
}

esp_err_t nvsGet(const std::string& ns, const std::string& key, uint32_t& value) {
    return Engine::getInstance().nvsGetU32(ns, key, value);
}

esp_err_t nvsSet(const std::string& ns, const std::string& key, uint8_t value) {
    return Engine::getInstance().nvsSetU8(ns, key, value);
}

esp_err_t nvsGet(const std::string& ns, const std::string& key, uint8_t& value) {
    return Engine::getInstance().nvsGetU8(ns, key, value);
}

esp_err_t writeFile(const std::string& path, const std::string& data) {
    return Engine::getInstance().fileWrite(path, data);
}

esp_err_t writeFile(const std::string& path, const psram_string& data) {
    // Convert psram_string to std::string for the existing implementation
    std::string std_data = to_std_string(data);
    return Engine::getInstance().fileWrite(path, std_data);
}

esp_err_t readFile(const std::string& path, std::string& data) {
    return Engine::getInstance().fileRead(path, data);
}

esp_err_t readFile(const std::string& path, psram_string& data) {
    // Read as std::string first, then convert to psram_string
    std::string std_data;
    esp_err_t result = Engine::getInstance().fileRead(path, std_data);
    if (result == ESP_OK) {
        data = make_psram_string(std_data);
    }
    return result;
}

esp_err_t appendFile(const std::string& path, const std::string& data) {
    return Engine::getInstance().fileAppend(path, data);
}

esp_err_t appendFile(const std::string& path, const psram_string& data) {
    // Convert psram_string to std::string for the existing implementation
    std::string std_data = to_std_string(data);
    return Engine::getInstance().fileAppend(path, std_data);
}

// Raw buffer helpers to avoid large std::string allocations on caller side
esp_err_t writeFileRaw(const std::string& path, const void* data, size_t size) {
    return Engine::getInstance().fileWriteRaw(path, data, size);
}

esp_err_t appendFileRaw(const std::string& path, const void* data, size_t size) {
    return Engine::getInstance().fileAppendRaw(path, data, size);
}

esp_err_t deleteFile(const std::string& path) {
    return Engine::getInstance().fileDelete(path);
}

esp_err_t createDir(const std::string& path) {
    return Engine::getInstance().createDirectory(path);
}

esp_err_t nvsSetBlob(const std::string& ns, const std::string& key, const void* data, size_t size) {
    return Engine::getInstance().nvsSetBlob(ns, key, data, size);
}

esp_err_t nvsGetBlob(const std::string& ns, const std::string& key, std::vector<uint8_t>& out_data) {
    return Engine::getInstance().nvsGetBlob(ns, key, out_data);
}

esp_err_t nvsEraseKey(const std::string& ns, const std::string& key) {
    return Engine::getInstance().nvsEraseKey(ns, key);
}

esp_err_t nvsEraseAll(const std::string& ns) {
    return Engine::getInstance().nvsEraseAll(ns);
}

esp_err_t fileExists(const std::string& path, bool& exists) {
    return Engine::getInstance().fileExists(path, exists);
}

esp_err_t fileSize(const std::string& path, size_t& size) {
    return Engine::getInstance().fileSize(path, size);
}


void ensureDataDirectories() {
    const char* paths[] = { "/data", "/data/reportq", "/data/logs" };
    esp_err_t results[sizeof(paths) / sizeof(paths[0])];

    for (size_t idx = 0; idx < (sizeof(paths) / sizeof(paths[0])); ++idx) {
        results[idx] = createDir(paths[idx]);
    }

    LOG_INFOF("AsyncStorage", "Directory ensure results: /data=%s, /data/reportq=%s, /data/logs=%s",
              esp_err_to_name(results[0]),
              esp_err_to_name(results[1]),
              esp_err_to_name(results[2]));
}
} // namespace Global

} // namespace AsyncStorage
