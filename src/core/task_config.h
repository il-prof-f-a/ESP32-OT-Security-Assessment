#pragma once

#include <cstdint>
#include "task_alloc_helpers.h"
#include "psram_allocator.h"
#include "sdkconfig.h"

extern "C" {
    #include "esp_heap_caps.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
}

// ==== GLOBAL TASK CONFIGURATION ====
// Centralizes all stack size and memory allocation configurations for every system task

namespace TaskConfig {

    // ==== ALLOCATION TYPES ====
    enum class AllocType {
        INTERNAL_RAM,   // Force internal RAM (critical performance, cache disabled)
        PSRAM,          // Use PSRAM (asynchronous, non-critical tasks)
        AUTO            // Let the system decide (deprecated)
    };

    // ==== SYSTEM TASK CONFIGURATIONS ====
    struct SystemTasks {
        // Main task - IMPORTANT: Must match CONFIG_ESP_MAIN_TASK_STACK_SIZE in sdkconfig.defaults
        static constexpr uint32_t MAIN_STACK_SIZE = CONFIG_ESP_MAIN_TASK_STACK_SIZE; //6144;
        static constexpr AllocType MAIN_ALLOC = AllocType::INTERNAL_RAM;
        static constexpr UBaseType_t MAIN_PRIORITY = 1;  // Default ESP-IDF priority

        // AsyncStorage Engine - CRITICAL: Must be in INTERNAL_RAM for flash operations
        static constexpr uint32_t ASYNC_STORAGE_STACK_SIZE = 32768; // 8KB stack in INTERNAL_RAM
        static constexpr AllocType ASYNC_STORAGE_ALLOC = AllocType::INTERNAL_RAM;
        static constexpr UBaseType_t ASYNC_STORAGE_PRIORITY = 6;  // High priority for storage operations

        // Logger - Now can use PSRAM (AsyncStorage engine handles flash operations)
        static constexpr uint32_t LOG_WRITER_STACK_SIZE = 8192; // ULTRA-AGGRESSIVE: 12KB → 8KB for memory crisis
        static constexpr AllocType LOG_WRITER_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t LOG_WRITER_PRIORITY = 3;  // tskIDLE_PRIORITY + 3

        // Reporting - Now can use PSRAM (AsyncStorage engine handles flash operations)
        static constexpr uint32_t REPORT_FLUSH_STACK_SIZE = 8192; // ULTRA-AGGRESSIVE: 12KB → 8KB for memory crisis
        static constexpr AllocType REPORT_FLUSH_ALLOC = AllocType::PSRAM; // HYBRID: PSRAM with runtime filesystem protection
        static constexpr UBaseType_t REPORT_FLUSH_PRIORITY = 5;  // Medium priority

        // Filesystem delegate - INTERNAL_RAM for VFS operations with cache disabled
        static constexpr uint32_t FILESYSTEM_DELEGATE_STACK_SIZE = 8192;
        static constexpr AllocType FILESYSTEM_DELEGATE_ALLOC = AllocType::INTERNAL_RAM;
        static constexpr UBaseType_t FILESYSTEM_DELEGATE_PRIORITY = 7;

    };

    // ==== NETWORK CONFIGURATIONS ====
    struct NetworkTasks {
        // NetworkEngine - Now can use PSRAM (AsyncStorage engine handles flash operations)
        static constexpr uint32_t NET_CAP_STACK_SIZE = 8192; // ULTRA-AGGRESSIVE: 12KB → 8KB for memory crisis
        static constexpr AllocType NET_CAP_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t NET_CAP_PRIORITY = 9;  // High priority for capture

        static constexpr uint32_t NET_ANA_STACK_SIZE = 12288; // Crash fix: 8KB insufficient for the IDS+anomaly chain (see docs/net_ana_stack_overflow.md)
        static constexpr AllocType NET_ANA_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t NET_ANA_PRIORITY = 8;  // High priority for analysis

        // WebServer - Used by web_server_task wrapper
        static constexpr uint32_t WEB_SERVER_STACK_SIZE = 32 * 1024;
        static constexpr AllocType WEB_SERVER_ALLOC = AllocType::PSRAM;  // HYBRID: PSRAM with runtime filesystem protection
        static constexpr UBaseType_t WEB_SERVER_PRIORITY = 8;  // High priority for efficient streaming (priority higher than filesystem delegate=8)
    };

    // ==== SECURITY/ASSESSMENT CONFIGURATIONS ====
    struct SecurityTasks {
        // VulnerabilityScanner - Now can use PSRAM (AsyncStorage engine handles flash operations)
        static constexpr uint32_t VULN_SCANNER_STACK_SIZE = 12288;  // ULTRA-AGGRESSIVE: 8KB → 6KB for memory crisis
        static constexpr AllocType VULN_SCANNER_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t VULN_SCANNER_PRIORITY = 6;  // Medium-high priority

        // FuzzingEngine - Now can use PSRAM (AsyncStorage engine handles flash operations)
        static constexpr uint32_t FUZZING_ENGINE_STACK_SIZE = 12288;  // ULTRA-AGGRESSIVE: 9KB → 6KB for memory crisis
        static constexpr AllocType FUZZING_ENGINE_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t FUZZING_ENGINE_PRIORITY = 7;  // High priority for fuzzing

        // IntrusionDetection - Now can use PSRAM (AsyncStorage engine handles flash operations)
        static constexpr uint32_t IDS_WORKER_STACK_SIZE = 12288; // ULTRA-AGGRESSIVE: 16KB → 12KB for memory crisis
        static constexpr AllocType IDS_WORKER_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t IDS_WORKER_PRIORITY = 5;  // Medium priority

        // LogRetention - Now can use PSRAM (AsyncStorage engine handles flash operations)
        static constexpr uint32_t LOG_RETENTION_STACK_SIZE = 12288; // ULTRA-AGGRESSIVE: 16KB → 12KB for memory crisis
        static constexpr AllocType LOG_RETENTION_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t LOG_RETENTION_PRIORITY = 3;  // Low priority
    };

    // ==== DISCOVERY CONFIGURATIONS ====
    struct DiscoveryTasks {
        static constexpr uint32_t PROTOCOL_STACK_SIZE = 12288;  // Requires stable socket/TLS
        static constexpr AllocType PROTOCOL_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t PROTOCOL_PRIORITY = tskIDLE_PRIORITY + 2;

        static constexpr uint32_t GENERAL_STACK_SIZE = 12288;  // Increased from 4KB to 12KB for reporting chain depth
        static constexpr AllocType GENERAL_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t GENERAL_PRIORITY = tskIDLE_PRIORITY + 2;
    };

    // ==== SANDBOX CONFIGURATIONS ====
    struct SandboxTasks {
        static constexpr uint32_t WORKER_STACK_SIZE = 8192;
        static constexpr AllocType WORKER_ALLOC = AllocType::INTERNAL_RAM;
        static constexpr UBaseType_t WORKER_PRIORITY = 6;
    };


    // ==== REPORTING CONFIGURATIONS ====
    struct ReportingTasks {
        // EmailSender - Worker task for sending emails with SMTP/TLS operations
        static constexpr uint32_t EMAIL_SENDER_STACK_SIZE = 16384;  // 16KB for SMTP/TLS operations
        static constexpr AllocType EMAIL_SENDER_ALLOC = AllocType::PSRAM;
        static constexpr UBaseType_t EMAIL_SENDER_PRIORITY = 2;  // Low priority, non-critical
    };

    // NOTE: ProtocolTasks removed - protocol plugins don't create separate tasks.
    // They run within the calling engine tasks (IDS, VulnScanner, FuzzingEngine).

    // ==== HELPER FUNCTIONS ====

    // Struct for the complete task configuration
    struct TaskParams {
        uint32_t stackSize;
        AllocType allocType;
        UBaseType_t priority;
    };

    // Create a task with complete configuration (stack, allocation, priority)
    inline TaskHandle_t createTask(TaskFunction_t taskFunc, const char* name,
                                 uint32_t stackSize, AllocType allocType,
                                 void* params, UBaseType_t priority,
                                 BaseType_t core = tskNO_AFFINITY) {
        switch (allocType) {
            case AllocType::PSRAM:
                if (core == 0) {
                    return create_task_core0_psram(taskFunc, name,
                                                 STACK_WORDS_FROM_BYTES(stackSize),
                                                 params, priority);
                } else if (core == 1) {
                    return create_task_core1_psram(taskFunc, name,
                                                 STACK_WORDS_FROM_BYTES(stackSize),
                                                 params, priority);
                } else {
                    // Default to core 1 for PSRAM
                    return create_task_core1_psram(taskFunc, name,
                                                 STACK_WORDS_FROM_BYTES(stackSize),
                                                 params, priority);
                }

            case AllocType::INTERNAL_RAM: {
                // For INTERNAL_RAM allocation, we need to temporarily disable PSRAM allocation
                // This forces FreeRTOS to allocate from INTERNAL_RAM heap
                TaskHandle_t handle = nullptr;
                BaseType_t result;

                // Standard task creation (may use PSRAM if available)

                if (core == tskNO_AFFINITY) {
                    result = xTaskCreate(taskFunc, name,
                                       STACK_WORDS_FROM_BYTES(stackSize),
                                       params, priority, &handle);
                } else {
                    result = xTaskCreatePinnedToCore(taskFunc, name,
                                                   STACK_WORDS_FROM_BYTES(stackSize),
                                                   params, priority, &handle, core);
                }

                return (result == pdPASS) ? handle : nullptr;
            }

            case AllocType::AUTO:
            default: {
                TaskHandle_t handle = nullptr;
                BaseType_t result;

                if (core == tskNO_AFFINITY) {
                    result = xTaskCreate(taskFunc, name,
                                       STACK_WORDS_FROM_BYTES(stackSize),
                                       params, priority, &handle);
                } else {
                    result = xTaskCreatePinnedToCore(taskFunc, name,
                                                   STACK_WORDS_FROM_BYTES(stackSize),
                                                   params, priority, &handle, core);
                }

                return (result == pdPASS) ? handle : nullptr;
            }
        }
    }

    // Simplified overload with TaskParams
    inline TaskHandle_t createTask(TaskFunction_t taskFunc, const char* name,
                                 const TaskParams& params, void* taskParams,
                                 BaseType_t core = tskNO_AFFINITY) {
        return createTask(taskFunc, name, params.stackSize, params.allocType,
                        taskParams, params.priority, core);
    }

    // ==== PREDEFINED CONFIGURATIONS FOR EASY USE ====

    // Defines complete parameters for each common task
    namespace Presets {
        constexpr TaskParams LOG_WRITER = {
            SystemTasks::LOG_WRITER_STACK_SIZE,
            SystemTasks::LOG_WRITER_ALLOC,
            SystemTasks::LOG_WRITER_PRIORITY
        };

        constexpr TaskParams REPORT_FLUSH = {
            SystemTasks::REPORT_FLUSH_STACK_SIZE,
            SystemTasks::REPORT_FLUSH_ALLOC,
            SystemTasks::REPORT_FLUSH_PRIORITY
        };

        constexpr TaskParams VULN_SCANNER = {
            SecurityTasks::VULN_SCANNER_STACK_SIZE,
            SecurityTasks::VULN_SCANNER_ALLOC,
            SecurityTasks::VULN_SCANNER_PRIORITY
        };

        constexpr TaskParams FUZZING_ENGINE = {
            SecurityTasks::FUZZING_ENGINE_STACK_SIZE,
            SecurityTasks::FUZZING_ENGINE_ALLOC,
            SecurityTasks::FUZZING_ENGINE_PRIORITY
        };

        constexpr TaskParams NET_CAP = {
            NetworkTasks::NET_CAP_STACK_SIZE,
            NetworkTasks::NET_CAP_ALLOC,
            NetworkTasks::NET_CAP_PRIORITY
        };

        constexpr TaskParams NET_ANA = {
            NetworkTasks::NET_ANA_STACK_SIZE,
            NetworkTasks::NET_ANA_ALLOC,
            NetworkTasks::NET_ANA_PRIORITY
        };

        constexpr TaskParams EMAIL_SENDER = {
            ReportingTasks::EMAIL_SENDER_STACK_SIZE,
            ReportingTasks::EMAIL_SENDER_ALLOC,
            ReportingTasks::EMAIL_SENDER_PRIORITY
        };

        constexpr TaskParams IDS_WORKER = {
            SecurityTasks::IDS_WORKER_STACK_SIZE,
            SecurityTasks::IDS_WORKER_ALLOC,
            SecurityTasks::IDS_WORKER_PRIORITY
        };

        constexpr TaskParams LOG_RETENTION = {
            SecurityTasks::LOG_RETENTION_STACK_SIZE,
            SecurityTasks::LOG_RETENTION_ALLOC,
            SecurityTasks::LOG_RETENTION_PRIORITY
        };

        constexpr TaskParams WEB_SERVER = {
            NetworkTasks::WEB_SERVER_STACK_SIZE,
            NetworkTasks::WEB_SERVER_ALLOC,
            NetworkTasks::WEB_SERVER_PRIORITY
        };

        constexpr TaskParams DISCOVERY_PROTOCOL = {
            DiscoveryTasks::PROTOCOL_STACK_SIZE,
            DiscoveryTasks::PROTOCOL_ALLOC,
            DiscoveryTasks::PROTOCOL_PRIORITY
        };

        constexpr TaskParams DISCOVERY_GENERAL = {
            DiscoveryTasks::GENERAL_STACK_SIZE,
            DiscoveryTasks::GENERAL_ALLOC,
            DiscoveryTasks::GENERAL_PRIORITY
        };

        constexpr TaskParams FILESYSTEM_DELEGATE = {
            SystemTasks::FILESYSTEM_DELEGATE_STACK_SIZE,
            SystemTasks::FILESYSTEM_DELEGATE_ALLOC,
            SystemTasks::FILESYSTEM_DELEGATE_PRIORITY
        };

        constexpr TaskParams SANDBOX_WORKER = {
            SandboxTasks::WORKER_STACK_SIZE,
            SandboxTasks::WORKER_ALLOC,
            SandboxTasks::WORKER_PRIORITY
        };

    }

    // ==== DEBUG/MONITORING ====

    // Print the full configuration
    void printTaskConfiguration();

    // Get real memory usage from FreeRTOS
    uint32_t getRealInternalRAMFree();
    uint32_t getRealPSRAMFree();
    uint32_t getRealInternalRAMUsed();
    uint32_t getRealPSRAMUsed();

    // Calculate theoretical memory for task stacks (deprecated, use real values above)
    uint32_t calculateInternalRAMUsage();
    uint32_t calculatePSRAMUsage();

    // ==== EMERGENCY MEMORY MANAGEMENT ====

    // Emergency memory cleanup for critical allocation failures
    bool emergencyMemoryCleanup();

    // Emergency PSRAM cleanup for critical allocation failures
    bool emergencyPSRAMCleanup();

    // Check if memory is in critical state (returns true if emergency action needed)
    bool isMemoryInCriticalState();

    // Check if PSRAM is in critical state
    bool isPSRAMInCriticalState();

    // Force heap defragmentation and integrity check
    void forceHeapDefragmentation();

    // Force PSRAM defragmentation and integrity check
    void forcePSRAMDefragmentation();

    // Clean up PSRAM-based task data structures
    void cleanupPSRAMTaskDataStructures();

    // Get detailed memory fragmentation report
    struct MemoryFragmentationReport {
        uint32_t total_free;
        uint32_t largest_block;
        uint32_t fragmentation_percent;
        uint32_t total_blocks;
        bool critical_fragmentation;
    };
    MemoryFragmentationReport getMemoryFragmentationReport();

    // ==== STRUCTURED DATA FOR TASK COMMUNICATION ====
    // All data structures use PSRAMAllocator to reduce DRAM pressure

    // Inter-task message queue structures
    struct TaskMessage {
        uint32_t message_id;
        uint32_t sender_task_id;
        uint32_t priority;
        psram_string message_type;
        psram_string payload;
        uint32_t timestamp;
    };
    using task_message_queue = psram_vector<TaskMessage>;

    // Task performance monitoring
    struct TaskPerformance {
        psram_string task_name;
        uint32_t stack_high_water_mark;
        uint32_t cpu_usage_percent;
        uint32_t run_time_counter;
        uint32_t last_measurement;
        uint32_t heap_usage_bytes;
    };
    using task_performance_registry = psram_vector<TaskPerformance>;

    // Error reporting structure for tasks
    struct TaskError {
        psram_string task_name;
        uint32_t error_code;
        psram_string error_message;
        psram_string stack_trace;
        uint32_t timestamp;
        uint32_t severity_level;
    };
    using task_error_log = psram_vector<TaskError>;

    // Task synchronization data
    struct TaskSyncState {
        psram_string task_name;
        uint32_t state;
        uint32_t sync_counter;
        psram_string last_action;
        uint32_t last_update;
    };
    using task_sync_registry = psram_vector<TaskSyncState>;

    // ==== HELPER FUNCTIONS FOR PSRAM DATA ====

    // Initialize PSRAM-based data structures for task communication
    void initializeTaskDataStructures();

    // Cleanup PSRAM-based data structures
    void cleanupTaskDataStructures();

    // Get memory usage statistics for task data structures
    struct TaskDataMemoryStats {
        uint32_t total_psram_used;
        uint32_t total_dram_saved;
        uint32_t active_containers;
        uint32_t total_elements;
    };
    TaskDataMemoryStats getTaskDataMemoryStats();

} // namespace TaskConfig
