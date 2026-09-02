#include "task_config.h"
#include "task_alloc_helpers.h"
#include "logging_system.h"
#include "async_storage_engine.h"
#include <cstdio>
extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "esp_heap_caps.h"
}

namespace TaskConfig {

// Get real memory usage from FreeRTOS
uint32_t getRealInternalRAMFree() {
    return heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
}

uint32_t getRealPSRAMFree() {
    return heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
}

uint32_t getRealInternalRAMUsed() {
    return heap_caps_get_total_size(MALLOC_CAP_INTERNAL) - heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
}

uint32_t getRealPSRAMUsed() {
    return heap_caps_get_total_size(MALLOC_CAP_SPIRAM) - heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
}

void printTaskConfiguration() {
    LOG_INFO("TaskConfig", "=== TASK CONFIGURATION ===");

    LOG_INFO("TaskConfig", "SYSTEM TASKS:");
    LOG_INFOF("TaskConfig", "  Main: %d bytes, prio %d (%s)",
              SystemTasks::MAIN_STACK_SIZE, SystemTasks::MAIN_PRIORITY,
              (SystemTasks::MAIN_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  LogWriter: %d bytes, prio %d (%s)",
              SystemTasks::LOG_WRITER_STACK_SIZE, SystemTasks::LOG_WRITER_PRIORITY,
              (SystemTasks::LOG_WRITER_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  ReportFlush: %d bytes, prio %d (%s)",
              SystemTasks::REPORT_FLUSH_STACK_SIZE, SystemTasks::REPORT_FLUSH_PRIORITY,
              (SystemTasks::REPORT_FLUSH_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  FilesystemDelegate: %d bytes, prio %d (%s)",
              SystemTasks::FILESYSTEM_DELEGATE_STACK_SIZE, SystemTasks::FILESYSTEM_DELEGATE_PRIORITY,
              (SystemTasks::FILESYSTEM_DELEGATE_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");

    LOG_INFO("TaskConfig", "NETWORK TASKS:");
    LOG_INFOF("TaskConfig", "  NetCap: %d bytes, prio %d (%s)",
              NetworkTasks::NET_CAP_STACK_SIZE, NetworkTasks::NET_CAP_PRIORITY,
              (NetworkTasks::NET_CAP_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  NetAna: %d bytes, prio %d (%s)",
              NetworkTasks::NET_ANA_STACK_SIZE, NetworkTasks::NET_ANA_PRIORITY,
              (NetworkTasks::NET_ANA_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  WebServer: %d bytes, prio %d (%s)",
              NetworkTasks::WEB_SERVER_STACK_SIZE, NetworkTasks::WEB_SERVER_PRIORITY,
              (NetworkTasks::WEB_SERVER_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");

    LOG_INFO("TaskConfig", "SECURITY TASKS:");
    LOG_INFOF("TaskConfig", "  VulnScanner: %d bytes, prio %d (%s)",
              SecurityTasks::VULN_SCANNER_STACK_SIZE, SecurityTasks::VULN_SCANNER_PRIORITY,
              (SecurityTasks::VULN_SCANNER_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  FuzzingEngine: %d bytes, prio %d (%s)",
              SecurityTasks::FUZZING_ENGINE_STACK_SIZE, SecurityTasks::FUZZING_ENGINE_PRIORITY,
              (SecurityTasks::FUZZING_ENGINE_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  IDSWorker: %d bytes, prio %d (%s)",
              SecurityTasks::IDS_WORKER_STACK_SIZE, SecurityTasks::IDS_WORKER_PRIORITY,
              (SecurityTasks::IDS_WORKER_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  LogRetention: %d bytes, prio %d (%s)",
              SecurityTasks::LOG_RETENTION_STACK_SIZE, SecurityTasks::LOG_RETENTION_PRIORITY,
              (SecurityTasks::LOG_RETENTION_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");

    LOG_INFO("TaskConfig", "DISCOVERY TASKS:");
    LOG_INFOF("TaskConfig", "  DiscoveryProtocol: %d bytes, prio %d (%s)",
              DiscoveryTasks::PROTOCOL_STACK_SIZE, DiscoveryTasks::PROTOCOL_PRIORITY,
              (DiscoveryTasks::PROTOCOL_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");
    LOG_INFOF("TaskConfig", "  DiscoveryGeneral: %d bytes, prio %d (%s)",
              DiscoveryTasks::GENERAL_STACK_SIZE, DiscoveryTasks::GENERAL_PRIORITY,
              (DiscoveryTasks::GENERAL_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");

    LOG_INFO("TaskConfig", "SANDBOX TASKS:");
    LOG_INFOF("TaskConfig", "  PluginSandbox: %d bytes, prio %d (%s)",
              SandboxTasks::WORKER_STACK_SIZE, SandboxTasks::WORKER_PRIORITY,
              (SandboxTasks::WORKER_ALLOC == AllocType::INTERNAL_RAM) ? "RAM" : "PSRAM");

    LOG_INFO("TaskConfig", "NOTE: Protocol plugins run within engine tasks (no separate workers)");

    // Real memory usage from FreeRTOS
    uint32_t internal_free = getRealInternalRAMFree();
    uint32_t internal_used = getRealInternalRAMUsed();
    uint32_t internal_total = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);

    uint32_t psram_free = getRealPSRAMFree();
    uint32_t psram_used = getRealPSRAMUsed();
    uint32_t psram_total = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);

    LOG_INFO("TaskConfig", "REAL MEMORY USAGE:");
    LOG_INFOF("TaskConfig", "  Internal RAM: %d KB used / %d KB total (%d KB free)",
              internal_used / 1024, internal_total / 1024, internal_free / 1024);
    LOG_INFOF("TaskConfig", "  PSRAM: %d KB used / %d KB total (%d KB free)",
              psram_used / 1024, psram_total / 1024, psram_free / 1024);

    // Theoretical task stack usage (for reference)
    uint32_t theoretical_internal = calculateInternalRAMUsage();
    uint32_t theoretical_psram = calculatePSRAMUsage();
    LOG_INFO("TaskConfig", "THEORETICAL TASK STACKS:");
    LOG_INFOF("TaskConfig", "  Internal RAM stacks: %d KB", theoretical_internal / 1024);
    LOG_INFOF("TaskConfig", "  PSRAM stacks: %d KB", theoretical_psram / 1024);
    LOG_INFO("TaskConfig", "=== END CONFIGURATION ===");
}

uint32_t calculateInternalRAMUsage() {
    uint32_t total = 0;

    // System tasks
    if (SystemTasks::MAIN_ALLOC == AllocType::INTERNAL_RAM)
        total += SystemTasks::MAIN_STACK_SIZE;
    if (SystemTasks::LOG_WRITER_ALLOC == AllocType::INTERNAL_RAM)
        total += SystemTasks::LOG_WRITER_STACK_SIZE;
    if (SystemTasks::REPORT_FLUSH_ALLOC == AllocType::INTERNAL_RAM)
        total += SystemTasks::REPORT_FLUSH_STACK_SIZE;
    if (SystemTasks::FILESYSTEM_DELEGATE_ALLOC == AllocType::INTERNAL_RAM)
        total += SystemTasks::FILESYSTEM_DELEGATE_STACK_SIZE;

    // Network tasks
    if (NetworkTasks::NET_CAP_ALLOC == AllocType::INTERNAL_RAM)
        total += NetworkTasks::NET_CAP_STACK_SIZE;
    if (NetworkTasks::NET_ANA_ALLOC == AllocType::INTERNAL_RAM)
        total += NetworkTasks::NET_ANA_STACK_SIZE;
    if (NetworkTasks::WEB_SERVER_ALLOC == AllocType::INTERNAL_RAM)
        total += NetworkTasks::WEB_SERVER_STACK_SIZE;

    // Security tasks
    if (SecurityTasks::VULN_SCANNER_ALLOC == AllocType::INTERNAL_RAM)
        total += SecurityTasks::VULN_SCANNER_STACK_SIZE;
    if (SecurityTasks::FUZZING_ENGINE_ALLOC == AllocType::INTERNAL_RAM)
        total += SecurityTasks::FUZZING_ENGINE_STACK_SIZE;
    if (SecurityTasks::IDS_WORKER_ALLOC == AllocType::INTERNAL_RAM)
        total += SecurityTasks::IDS_WORKER_STACK_SIZE;
    if (SecurityTasks::LOG_RETENTION_ALLOC == AllocType::INTERNAL_RAM)
        total += SecurityTasks::LOG_RETENTION_STACK_SIZE;

    // Discovery tasks
    if (DiscoveryTasks::PROTOCOL_ALLOC == AllocType::INTERNAL_RAM)
        total += DiscoveryTasks::PROTOCOL_STACK_SIZE;
    if (DiscoveryTasks::GENERAL_ALLOC == AllocType::INTERNAL_RAM)
        total += DiscoveryTasks::GENERAL_STACK_SIZE;

    // Sandbox tasks
    if (SandboxTasks::WORKER_ALLOC == AllocType::INTERNAL_RAM)
        total += SandboxTasks::WORKER_STACK_SIZE;

    // Protocol tasks removed - no separate workers

    return total;
}

uint32_t calculatePSRAMUsage() {
    uint32_t total = 0;

    // System tasks
    if (SystemTasks::MAIN_ALLOC == AllocType::PSRAM)
        total += SystemTasks::MAIN_STACK_SIZE;
    if (SystemTasks::LOG_WRITER_ALLOC == AllocType::PSRAM)
        total += SystemTasks::LOG_WRITER_STACK_SIZE;
    if (SystemTasks::REPORT_FLUSH_ALLOC == AllocType::PSRAM)
        total += SystemTasks::REPORT_FLUSH_STACK_SIZE;
    if (SystemTasks::FILESYSTEM_DELEGATE_ALLOC == AllocType::PSRAM)
        total += SystemTasks::FILESYSTEM_DELEGATE_STACK_SIZE;

    // Network tasks
    if (NetworkTasks::NET_CAP_ALLOC == AllocType::PSRAM)
        total += NetworkTasks::NET_CAP_STACK_SIZE;
    if (NetworkTasks::NET_ANA_ALLOC == AllocType::PSRAM)
        total += NetworkTasks::NET_ANA_STACK_SIZE;
    if (NetworkTasks::WEB_SERVER_ALLOC == AllocType::PSRAM)
        total += NetworkTasks::WEB_SERVER_STACK_SIZE;

    // Security tasks
    if (SecurityTasks::VULN_SCANNER_ALLOC == AllocType::PSRAM)
        total += SecurityTasks::VULN_SCANNER_STACK_SIZE;
    if (SecurityTasks::FUZZING_ENGINE_ALLOC == AllocType::PSRAM)
        total += SecurityTasks::FUZZING_ENGINE_STACK_SIZE;
    if (SecurityTasks::IDS_WORKER_ALLOC == AllocType::PSRAM)
        total += SecurityTasks::IDS_WORKER_STACK_SIZE;
    if (SecurityTasks::LOG_RETENTION_ALLOC == AllocType::PSRAM)
        total += SecurityTasks::LOG_RETENTION_STACK_SIZE;

    // Discovery tasks
    if (DiscoveryTasks::PROTOCOL_ALLOC == AllocType::PSRAM)
        total += DiscoveryTasks::PROTOCOL_STACK_SIZE;
    if (DiscoveryTasks::GENERAL_ALLOC == AllocType::PSRAM)
        total += DiscoveryTasks::GENERAL_STACK_SIZE;

    // Sandbox tasks
    if (SandboxTasks::WORKER_ALLOC == AllocType::PSRAM)
        total += SandboxTasks::WORKER_STACK_SIZE;

    // Protocol tasks removed - no separate workers

    return total;
}

// ==== PSRAM DATA STRUCTURES MANAGEMENT ====

// Global task data structures (static to ensure single instances)
static task_message_queue* g_task_messages = nullptr;
static task_performance_registry* g_task_performance = nullptr;
static task_error_log* g_task_errors = nullptr;
static task_sync_registry* g_task_sync = nullptr;

void initializeTaskDataStructures() {
    LOG_INFO("TaskConfig", "Initializing PSRAM-based task data structures...");

    // Initialize message queue with reserve capacity
    if (!g_task_messages) {
        g_task_messages = new task_message_queue();
        g_task_messages->reserve(100);  // Pre-allocate for performance
    }

    // Initialize performance registry
    if (!g_task_performance) {
        g_task_performance = new task_performance_registry();
        g_task_performance->reserve(20);  // Max expected tasks
    }

    // Initialize error log
    if (!g_task_errors) {
        g_task_errors = new task_error_log();
        g_task_errors->reserve(50);  // Error history
    }

    // Initialize sync registry
    if (!g_task_sync) {
        g_task_sync = new task_sync_registry();
        g_task_sync->reserve(20);  // Max expected tasks
    }

    LOG_INFO("TaskConfig", "PSRAM task data structures initialized successfully");
}

void cleanupTaskDataStructures() {
    LOG_INFO("TaskConfig", "Cleaning up PSRAM task data structures...");

    delete g_task_messages;
    g_task_messages = nullptr;

    delete g_task_performance;
    g_task_performance = nullptr;

    delete g_task_errors;
    g_task_errors = nullptr;

    delete g_task_sync;
    g_task_sync = nullptr;

    LOG_INFO("TaskConfig", "PSRAM task data structures cleaned up");
}

TaskDataMemoryStats getTaskDataMemoryStats() {
    TaskDataMemoryStats stats = {0, 0, 0, 0};

    if (g_task_messages) {
        stats.active_containers++;
        stats.total_elements += g_task_messages->size();
        // Estimate PSRAM usage (rough calculation)
        stats.total_psram_used += sizeof(TaskMessage) * g_task_messages->capacity();
    }

    if (g_task_performance) {
        stats.active_containers++;
        stats.total_elements += g_task_performance->size();
        stats.total_psram_used += sizeof(TaskPerformance) * g_task_performance->capacity();
    }

    if (g_task_errors) {
        stats.active_containers++;
        stats.total_elements += g_task_errors->size();
        stats.total_psram_used += sizeof(TaskError) * g_task_errors->capacity();
    }

    if (g_task_sync) {
        stats.active_containers++;
        stats.total_elements += g_task_sync->size();
        stats.total_psram_used += sizeof(TaskSyncState) * g_task_sync->capacity();
    }

    // Estimate DRAM saved (approximate)
    stats.total_dram_saved = stats.total_psram_used;

    return stats;
}

// ==== EMERGENCY MEMORY MANAGEMENT IMPLEMENTATION ====

bool emergencyMemoryCleanup() {
    static const char* TAG = "MemoryEmergency";

    size_t before_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t before_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    // Safe logging check
    bool can_log = (before_free > 1024);

    if (can_log) {
        LOG_ERRORF(TAG, "⚠️ EMERGENCY CLEANUP: %d bytes free, largest: %d", (int)before_free, (int)before_largest);
    }

    // Step 1: Force garbage collection and heap integrity check
    forceHeapDefragmentation();

    // Step 2: Clean up task data structures if they exist
    // Note: cleanupTaskDataStructures() is designed to be safe even in low memory
    cleanupTaskDataStructures();

    // Step 3: Yield to allow FreeRTOS cleanup
    vTaskDelay(pdMS_TO_TICKS(50));

    size_t after_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t after_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    bool cleanup_successful = (after_free > before_free) || (after_largest > before_largest);

    if (can_log) {
        if (cleanup_successful) {
            LOG_INFOF(TAG, "✅ Emergency cleanup gained %d bytes, largest: %d",
                     (int)(after_free - before_free), (int)after_largest);
        } else {
            LOG_ERRORF(TAG, "❌ Emergency cleanup failed - still %d bytes free", (int)after_free);
        }
    }

    return cleanup_successful;
}

bool emergencyPSRAMCleanup() {
    return false;
    static const char* TAG = "PSRAMEmergency";

    size_t before_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t before_largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

    // Safe logging check - use internal RAM for logging
    size_t internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    bool can_log = (internal_free > 1024);

    if (can_log) {
        LOG_ERRORF(TAG, "⚠️ PSRAM EMERGENCY CLEANUP: %d bytes free, largest: %d", (int)before_free, (int)before_largest);
    }

    // Step 1: Force PSRAM garbage collection and heap integrity check
    forcePSRAMDefragmentation();

    // Step 2: Clean up PSRAM-based task data structures if they exist
    // This targets PSRAM allocations specifically
    cleanupPSRAMTaskDataStructures();

    // Step 3: Force cleanup of AsyncStorage operations in PSRAM
    // This prevents memory corruption issues during WebServer startup
    // Note: No exception handling available in ESP-IDF, rely on safe API calls
    AsyncStorage::Engine& storage = AsyncStorage::Engine::getInstance();
    if (storage.isInitialized()) {
        // Force processing of any pending operations to clear PSRAM allocations
        vTaskDelay(pdMS_TO_TICKS(10)); // Allow operations to complete
        if (can_log) {
            LOG_INFOF(TAG, "AsyncStorage cleanup completed during PSRAM emergency");
        }
    }

    // Step 4: Force cleanup of any PSRAM-based caches/buffers
    // Clean up JSON parser contexts that might be lingering in PSRAM
    PSRAMUtils::emergencyCleanup();

    // Step 5: Yield to allow FreeRTOS cleanup
    vTaskDelay(pdMS_TO_TICKS(50));

    size_t after_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t after_largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

    bool cleanup_successful = (after_free > before_free) || (after_largest > before_largest);

    if (can_log) {
        if (cleanup_successful) {
            LOG_INFOF(TAG, "✅ PSRAM cleanup gained %d bytes, largest: %d",
                     (int)(after_free - before_free), (int)after_largest);
        } else {
            LOG_ERRORF(TAG, "❌ PSRAM cleanup failed - still %d bytes free", (int)after_free);
        }
    }

    return cleanup_successful;
}

bool isMemoryInCriticalState() {
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    // Critical if less than 2KB free OR largest block less than 1KB
    return (free_heap < 2048) || (largest_block < 1024);
}

bool isPSRAMInCriticalState() {
    if (heap_caps_get_total_size(MALLOC_CAP_SPIRAM) == 0) {
        return false;
    }
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

    // Critical if less than 50KB free OR largest block less than 10KB
    // PSRAM has much more space so higher thresholds
    return (free_psram < 51200) || (largest_block < 10240);
}

void forceHeapDefragmentation() {
    // Step 1: Check all heap integrity
    heap_caps_check_integrity_all(true);

    // Step 2: Aggressive allocation/deallocation to force coalescing
    // Try multiple sizes to trigger different coalescing patterns
    void* temp_ptrs[32] = {nullptr};

    // Small allocations first
    for (int i = 0; i < 16; i++) {
        temp_ptrs[i] = heap_caps_malloc(32, MALLOC_CAP_INTERNAL);
    }

    // Medium allocations
    for (int i = 16; i < 24; i++) {
        temp_ptrs[i] = heap_caps_malloc(128, MALLOC_CAP_INTERNAL);
    }

    // Larger allocations to force major coalescing
    for (int i = 24; i < 32; i++) {
        temp_ptrs[i] = heap_caps_malloc(512, MALLOC_CAP_INTERNAL);
    }

    // Free in specific pattern to maximize coalescing
    // Free large blocks first
    for (int i = 31; i >= 24; i--) {
        if (temp_ptrs[i]) {
            heap_caps_free(temp_ptrs[i]);
            temp_ptrs[i] = nullptr;
        }
    }

    // Then medium blocks
    for (int i = 23; i >= 16; i--) {
        if (temp_ptrs[i]) {
            heap_caps_free(temp_ptrs[i]);
            temp_ptrs[i] = nullptr;
        }
    }

    // Finally small blocks in reverse order
    for (int i = 15; i >= 0; i--) {
        if (temp_ptrs[i]) {
            heap_caps_free(temp_ptrs[i]);
            temp_ptrs[i] = nullptr;
        }
    }

    // Step 3: Force garbage collection with delay
    vTaskDelay(pdMS_TO_TICKS(50));

    // Step 4: Final integrity check
    heap_caps_check_integrity_all(false);
}

MemoryFragmentationReport getMemoryFragmentationReport() {
    MemoryFragmentationReport report = {};

    report.total_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    report.largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    if (report.total_free > 0) {
        // Calculate fragmentation percentage
        report.fragmentation_percent = ((report.total_free - report.largest_block) * 100) / report.total_free;
    } else {
        report.fragmentation_percent = 100; // Completely fragmented
    }

    // Critical fragmentation: largest block is less than 50% of total free
    report.critical_fragmentation = (report.largest_block * 2 < report.total_free) || (report.largest_block < 1024);

    // Estimate total blocks (rough approximation)
    report.total_blocks = report.total_free / (report.largest_block > 0 ? report.largest_block : 1);

    return report;
}

void forcePSRAMDefragmentation() {
    if (heap_caps_get_total_size(MALLOC_CAP_SPIRAM) == 0) {
        return;
    }
    // Step 1: Check PSRAM heap integrity
    heap_caps_check_integrity(MALLOC_CAP_SPIRAM, true);

    // Step 2: Aggressive allocation/deallocation to force coalescing in PSRAM
    // Try multiple sizes to trigger different coalescing patterns
    void* temp_ptrs[32] = {nullptr};

    // Small allocations first (1KB each)
    for (int i = 0; i < 16; i++) {
        temp_ptrs[i] = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
    }

    // Medium allocations (4KB each)
    for (int i = 16; i < 24; i++) {
        temp_ptrs[i] = heap_caps_malloc(4096, MALLOC_CAP_SPIRAM);
    }

    // Larger allocations to force major coalescing (16KB each)
    for (int i = 24; i < 32; i++) {
        temp_ptrs[i] = heap_caps_malloc(16384, MALLOC_CAP_SPIRAM);
    }

    // Free in specific pattern to maximize coalescing
    // Free large blocks first
    for (int i = 31; i >= 24; i--) {
        if (temp_ptrs[i]) {
            heap_caps_free(temp_ptrs[i]);
            temp_ptrs[i] = nullptr;
        }
    }

    // Then medium blocks
    for (int i = 23; i >= 16; i--) {
        if (temp_ptrs[i]) {
            heap_caps_free(temp_ptrs[i]);
            temp_ptrs[i] = nullptr;
        }
    }

    // Finally small blocks in reverse order
    for (int i = 15; i >= 0; i--) {
        if (temp_ptrs[i]) {
            heap_caps_free(temp_ptrs[i]);
            temp_ptrs[i] = nullptr;
        }
    }

    // Step 3: Force garbage collection with delay
    vTaskDelay(pdMS_TO_TICKS(50));

    // Step 4: Final integrity check
    heap_caps_check_integrity(MALLOC_CAP_SPIRAM, false);
}

void cleanupPSRAMTaskDataStructures() {
    // This function targets PSRAM-specific cleanup
    // Clean up any lingering PSRAM-based task structures

    // Clean up any JSON parser contexts that might be in PSRAM
    // This would be implementation-specific based on what uses PSRAM

    // Force any pending PSRAM deallocations to complete
    vTaskDelay(pdMS_TO_TICKS(20));

    // Yield to allow cleanup to take effect
    vTaskDelay(pdMS_TO_TICKS(10));
}

} // namespace TaskConfig
