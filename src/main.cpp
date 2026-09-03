
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
  #include "esp_system.h"
  #include "esp_app_desc.h"
  #include "esp_event.h"
  #include "esp_log.h"
  #include "nvs_flash.h"
  #include "esp_netif.h"
  #include "esp_heap_caps.h"
  #include "esp_psram.h"
  #include "esp_littlefs.h"
  #include <time.h>
  #include <sys/time.h>
  #include <arpa/inet.h>
  #include "esp_task_wdt.h"
  // #include "esp_panic.h"    // Does not exist in ESP-IDF 5.5.0
  #include "esp_core_dump.h"
}

#include "core/async_storage_engine.h"
#include "core/configuration_manager.h"
#include "core/main_task_watchdog.h"
#include "core/crash_diagnostics.h"
#include "core/filesystem_task_delegate.h"
#include "core/time_manager.h"
#include "security/security_manager.h"
#include "core/reporting_engine.h"
#include "core/event_formatter.h"
#include "core/reliable_queue.h"
#include "core/log_file_manager.h"
#include "core/reporting_config_loader.h"
#include "core/memory_monitor.h"
#include "core/psram_allocator.h"
#include "core/psram_telemetry.h"
#include "core/task_config.h"
#include "core/fs_tools.h"
#include "assessment/fuzzing_engine.h"
#include "assessment/intrusion_detection_general.h"
#include "web/web_server.h"
#include "core/plugin_manager.h"
#include "core/logging_system.h"
#include "core/async_storage_engine.h"
#include "core/nvs_override.h"
#include "core/plugin_factory.h"
#include "core/psram_allocator.h"
#include "protocols/modbus_tcp_plugin.h"
#include "protocols/s7_plugin.h"
#include "protocols/profinet_plugin.h"
#include "protocols/ethernetip_plugin.h"
#include "protocols/opcua_plugin.h"
#include "assessment/vulnerability_scanner.h"
#include "provisioning/provisioning_coordinator.h"

#ifndef ESP32_OT_LITTLEFS_AUTO_FORMAT
#define ESP32_OT_LITTLEFS_AUTO_FORMAT 0
#endif

// Network additions
#include "core/network_engine.h"
#include "network/ethernet_manager.h"
#include "network/wifi_manager.h"
#include "network/eth_l2_adapter.h"
#include "network/management_interface_controller.h"
#include "lwip/ip4_addr.h"
#include "lwip/inet.h"
#include "cJSON.h"
#include "esp_heap_caps.h"
// PSRAM-only JSON parsing helpers
#include "core/psram_json_parser.h"
// Integer-only formatting helpers (avoid float dtoa allocations)
#include "core/format_utils.h"

// Route all cJSON allocations to PSRAM (8-bit) with DRAM fallback
#include "core/task_audit.h"
#include "core/task_alloc_helpers.h" // contains create_task_core1_psram(...) and STACK_WORDS_FROM_BYTES
#include "web/web_server_task.h"    // for WebTaskArgs and web_server_task
#include "core/audit_manager.h"
#include "core/boot_sequence.h"
#include "core/startup_status.h"
#include "assessment/signature_detector.h"
static const char* TAG = "MAIN";

// Defer Email reporter until WiFi STA is connected

// Forward declaration
static void log_dns_servers();

extern "C" void task_audit_run(void);

// Reset reason monitoring and system events
static const char* get_reset_reason_string(esp_reset_reason_t reason) {
    switch (reason) {
        case ESP_RST_POWERON:   return "POWER_ON";
        case ESP_RST_EXT:       return "EXTERNAL_PIN";
        case ESP_RST_SW:        return "SOFTWARE_RESTART";
        case ESP_RST_PANIC:     return "PANIC_CRASH";
        case ESP_RST_INT_WDT:   return "INTERRUPT_WATCHDOG";
        case ESP_RST_TASK_WDT:  return "TASK_WATCHDOG";
        case ESP_RST_WDT:       return "OTHER_WATCHDOG";
        case ESP_RST_DEEPSLEEP: return "DEEP_SLEEP_WAKEUP";
        case ESP_RST_BROWNOUT:  return "BROWNOUT_RESET";
        case ESP_RST_SDIO:      return "SDIO_RESET";
        default:                return "UNKNOWN";
    }
}

static bool is_abnormal_reset(esp_reset_reason_t reason) {
    return (reason == ESP_RST_PANIC ||
            reason == ESP_RST_INT_WDT ||
            reason == ESP_RST_TASK_WDT ||
            reason == ESP_RST_WDT ||
            reason == ESP_RST_BROWNOUT);
}

static void log_previous_crash_diagnostics(esp_reset_reason_t reset_reason,
                                           const char* reason_str);

// Global reporting engine pointer for web interface access
ReportingEngine* g_reporting = nullptr;

// Startup rollback callbacks.  They intentionally avoid allocating memory so
// they remain usable while unwinding a low-memory or partially initialized boot.
static void rollback_logger(void* context) {
    auto* logger = static_cast<Logger*>(context);
    if (logger) logger->stop();
}

static void rollback_nvs(void*) {
    (void)nvs_flash_deinit();
}

static void rollback_async_storage(void*) {
    AsyncStorage::Global::shutdown();
}

static void rollback_filesystem_delegate(void*) {
    FilesystemTaskDelegate::getInstance().shutdown();
}

static void rollback_nvs_override(void*) {
    nvs_override_disable();
}

static void rollback_littlefs(void* context) {
    auto* mounted = static_cast<bool*>(context);
    if (mounted && *mounted) {
        (void)esp_vfs_littlefs_unregister("storage");
        *mounted = false;
    }
}

static void rollback_watchdog(void* context) {
    auto* watchdog = static_cast<MainTaskWatchdog*>(context);
    if (watchdog) (void)watchdog->stop();
}

static void rollback_reporting(void* context) {
    g_reporting = nullptr;
    auto* reporting = static_cast<ReportingEngine*>(context);
    if (reporting) reporting->shutdown();
}

static void rollback_logger_reporting(void* context) {
    auto* logger = static_cast<Logger*>(context);
    if (logger) logger->setReportingEngine(nullptr);
}

static void rollback_psram_telemetry(void*) {
    PSRAMTelemetry::getInstance().shutdown();
}

static void rollback_network(void* context) {
    auto* network = static_cast<NetworkEngine*>(context);
    if (network) network->shutdown();
}

static void rollback_ethernet(void* context) {
    auto* ethernet = static_cast<EthernetManager*>(context);
    if (ethernet) ethernet->stop();
}

static void rollback_wifi(void* context) {
    auto* wifi = static_cast<WiFiManager*>(context);
    if (wifi) {
        wifi->stop();
        wifi->clearConfiguration();
    }
}

static void rollback_time_manager(void*) {
    TimeManager::clearWiFiAutoSync();
}

static std::uint32_t boot_sequence_clock(void*) {
    return static_cast<std::uint32_t>(esp_timer_get_time() / 1000ULL);
}

// Memory monitoring and early warning system


extern "C" void app_main(void) {
    BootSequence startup_sequence(&boot_sequence_clock);
    bool littlefs_rollback_mounted = false;

    // Construct the single logger object before init_async.  The previous
    // sequence let init_async allocate a heap logger and then overwrote
    // g_logger with this local static, orphaning the first writer task.
    static Logger logger;
    g_logger = &logger;
    if (!Logger::init_async(Logger::startupRingBytes())) {
        std::printf("[MAIN] Logger initialization failed; aborting startup\n");
        return;
    }
    startup_sequence.trackCleanup(&rollback_logger, &logger);

    auto rollback_startup = [&](const char* reason) {
        LOG_ERRORF(TAG, "Startup aborted: %s; rolling back initialized services", reason);
        startup_sequence.abort();
    };

    // Ensure JSON strings/trees are allocated in PSRAM to save DRAM
    PSRAMUtils::initializeCJSONHooks();

    // Ensure netif and default event loop are ready before WiFi handlers
    {
        esp_err_t e1 = esp_netif_init();
        if (e1 != ESP_OK && e1 != ESP_ERR_INVALID_STATE) {
            ESP_ERROR_CHECK(e1);
        }
        esp_err_t e2 = esp_event_loop_create_default();
        if (e2 != ESP_OK && e2 != ESP_ERR_INVALID_STATE) {
            ESP_ERROR_CHECK(e2);
        }
    }

    LOG_INFO(TAG, "Boot ESP32-OT-Security-Assessment - Security System");

    // RESET REASON MONITORING - Detect crashes and abnormal restarts
    esp_reset_reason_t reset_reason = esp_reset_reason();
    const char* reason_str = get_reset_reason_string(reset_reason);
    // Capture reset reason immediately, but defer persistent/coredump reads until
    // NVS and AsyncStorage are initialized below.
    LOG_INFOF(TAG, "Reset reason captured before service init: %s", reason_str);

    // Check PSRAM availability (following official LILYGO instructions)
    #ifdef CONFIG_SPIRAM
    uint32_t psram_size = esp_psram_get_size();
    if (psram_size > 0) {
        {
            char mbbuf[32];
            fmt_bytes_mb(mbbuf, sizeof(mbbuf), (uint32_t)psram_size, 1);
            LOG_INFOF(TAG, " PSRAM detected: %s (ESP32-WROVER-E)", mbbuf);
        }

        // Show heap distribution
        size_t spiram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        {
            char mbbuf[32];
            fmt_bytes_mb(mbbuf, sizeof(mbbuf), (uint32_t)spiram_free, 1);
            LOG_INFOF(TAG, "Memory: PSRAM %s free, Internal %u KB free",
                     mbbuf, (unsigned)(internal_free/1024));
        }
    } else {
        LOG_WARNING(TAG, "PSRAM not initialized despite CONFIG_SPIRAM enabled");
    }
    #else
    LOG_WARNING(TAG, "PSRAM support not enabled in configuration");
    size_t initial_internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    LOG_INFOF(TAG, "Internal RAM free: %u KB", (unsigned)(initial_internal_free/1024));
    #endif

    // Check IPC task stack size configuration
    #ifdef CONFIG_ESP_IPC_TASK_STACK_SIZE
    LOG_INFOF(TAG, "IPC Task Stack: %d bytes (%d KB)", CONFIG_ESP_IPC_TASK_STACK_SIZE, CONFIG_ESP_IPC_TASK_STACK_SIZE/1024);
    #endif


    // Base inits
    // FIRST: Initialize NVS for real (before any override)
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    LOG_INFO(TAG, "NVS flash initialized successfully");
    startup_sequence.trackCleanup(&rollback_nvs, nullptr);
    // Registered early so LittleFS is unmounted only after the filesystem and
    // reporting services have released all references to it.
    startup_sequence.trackCleanup(&rollback_littlefs, &littlefs_rollback_mounted);

    // SECOND: Pre-initialization memory safety checks for AsyncStorage
    size_t pre_async_internal_free = TaskConfig::getRealInternalRAMFree();
    size_t psram_free = TaskConfig::getRealPSRAMFree();

    LOG_INFOF(TAG, "Pre-AsyncStorage memory: Internal=%d, PSRAM=%d", (int)pre_async_internal_free, (int)psram_free);

    // Ensure minimum memory thresholds before AsyncStorage initialization
    if (pre_async_internal_free < 32768) { // 32KB minimum for AsyncStorage internal structures
        LOG_ERRORF(TAG, "Insufficient internal RAM (%d bytes) for AsyncStorage", (int)pre_async_internal_free);
        TaskConfig::emergencyMemoryCleanup();
        pre_async_internal_free = TaskConfig::getRealInternalRAMFree();
        if (pre_async_internal_free < 32768) {
            LOG_ERROR(TAG, "CRITICAL: Cannot initialize AsyncStorage - memory crisis");
            rollback_startup("internal RAM crisis before AsyncStorage");
            return;
        }
    }

#ifdef CONFIG_SPIRAM
    if (psram_free < 65536) { // 64KB minimum for AsyncStorage PSRAM operations
        LOG_ERRORF(TAG, "Insufficient PSRAM (%d bytes) for AsyncStorage", (int)psram_free);
        TaskConfig::emergencyPSRAMCleanup();
        psram_free = TaskConfig::getRealPSRAMFree();
        if (psram_free < 65536) {
            LOG_ERROR(TAG, "CRITICAL: Cannot initialize AsyncStorage - PSRAM crisis");
            rollback_startup("PSRAM crisis before AsyncStorage");
            return;
        }
    }
#else
    // The allocator and storage paths fall back to internal 8-bit RAM when
    // CONFIG_SPIRAM is absent.  Do not reject the boot solely because the
    // optional external heap is unavailable.
    LOG_WARNING(TAG, "PSRAM support disabled; AsyncStorage will use internal RAM fallback");
#endif

    // Force memory alignment and defragmentation before AsyncStorage initialization
    TaskConfig::forceHeapDefragmentation();
#ifdef CONFIG_SPIRAM
    TaskConfig::forcePSRAMDefragmentation();
#endif

    MemorySnapshot mem_before_async = MemoryMonitor::capture();

    // Register before the call: the engine can allocate a queue before a later
    // task creation fails and the rollback must reclaim that partial state.
    startup_sequence.trackCleanup(&rollback_async_storage, nullptr);
    const bool async_storage_initialized = AsyncStorage::Global::initialize();
    if (!startup_sequence.recordRequired("async_storage", async_storage_initialized)) {
        LOG_ERROR(TAG, "AsyncStorage engine initialization failed");
        rollback_startup("AsyncStorage initialization failure");
        return;
    }
    LOG_INFO(TAG, "AsyncStorage engine initialized successfully");
    MemoryMonitor::logDelta("AsyncStorage::initialize", mem_before_async);
    log_previous_crash_diagnostics(reset_reason, reason_str);

    // Initialize FilesystemTaskDelegate for PSRAM stack safety
    MemorySnapshot mem_before_fs_delegate = MemoryMonitor::capture();
    startup_sequence.trackCleanup(&rollback_filesystem_delegate, nullptr);
    const bool filesystem_delegate_initialized = FilesystemTaskDelegate::getInstance().initialize();
    if (!startup_sequence.recordRequired("filesystem_delegate", filesystem_delegate_initialized)) {
        LOG_ERROR(TAG, "FilesystemTaskDelegate initialization failed");
        rollback_startup("filesystem delegate initialization failure");
        return;
    }
    LOG_INFO(TAG, "FilesystemTaskDelegate initialized successfully");
    MemoryMonitor::logDelta("FilesystemTaskDelegate::initialize", mem_before_fs_delegate);

    // THIRD: Enable NVS override (now that NVS is real and ready)
    nvs_override_enable();
    startup_sequence.trackCleanup(&rollback_nvs_override, nullptr);
    LOG_INFO(TAG, "NVS override enabled - all NVS operations route through AsyncStorage");

    {
        esp_err_t e1b = esp_netif_init();
        if (e1b != ESP_OK && e1b != ESP_ERR_INVALID_STATE) {
            ESP_ERROR_CHECK(e1b);
        }
        esp_err_t e2b = esp_event_loop_create_default();
        if (e2b != ESP_OK && e2b != ESP_ERR_INVALID_STATE) {
            ESP_ERROR_CHECK(e2b);
        }
    }

    // Disable ESP-IDF direct logging to prevent duplication with ReportingEngine
    esp_log_level_set("*", ESP_LOG_NONE);

    // Panic handling remains in the native ESP-IDF path. The enabled flash
    // coredump profile is inspected on the next boot after storage is ready.
    LOG_INFO(TAG, "Native ESP-IDF panic handler active; flash coredump inspection enabled by build");

    // Logger system was initialized before NVS so every startup failure is
    // observable.  Keep the same object for the rest of app_main.
    MemorySnapshot mem_before_logger = MemoryMonitor::capture();
    // Redirect all ESP_LOG to our thread-safe logger - DISABLED to prevent duplication
    vTaskDelay(pdMS_TO_TICKS(100)); // Give logger time to start
    logger.setupESPLogRedirect();
    MemoryMonitor::logDelta("Logger::start", mem_before_logger);

    // Test log entries to verify file logging works
    LOG_INFO(TAG, "System startup - logging system initialized");

    // Reduce verbose WiFi logging to avoid fragmented log lines
    //esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("ESP", ESP_LOG_WARN);
    esp_log_level_set("FSDelegate", ESP_LOG_WARN);
    esp_log_level_set("REPORTING", ESP_LOG_INFO);
    esp_log_level_set("wifi", ESP_LOG_WARN);
    esp_log_level_set("wifi_init", ESP_LOG_WARN);
    esp_log_level_set("phy_init", ESP_LOG_WARN);
    esp_log_level_set("system_api", ESP_LOG_WARN);

    // Disable additional WiFi component logs
    esp_log_level_set("wpa", ESP_LOG_WARN);
    esp_log_level_set("wpa_supplicant", ESP_LOG_WARN);
    esp_log_level_set("tcpip_adapter", ESP_LOG_WARN);
    esp_log_level_set("esp_netif_handlers", ESP_LOG_WARN);
    esp_log_level_set("TASK_ALLOC", ESP_LOG_DEBUG);
    esp_log_level_set("DISCOVERY_MGR", ESP_LOG_DEBUG);

    // Enable debug logging for fuzzing components
    esp_log_level_set("FUZZING_ENGINE", ESP_LOG_DEBUG);
    esp_log_level_set("MODBUS_FUZZ", ESP_LOG_DEBUG);
    esp_log_level_set("S7_FUZZ", ESP_LOG_DEBUG);
    esp_log_level_set("OPCUA_FUZZ", ESP_LOG_DEBUG);
    esp_log_level_set("PROFINET_FUZZ", ESP_LOG_DEBUG);
    esp_log_level_set("ETHERNETIP_FUZZ", ESP_LOG_DEBUG);

    // Enable debug log for tools and file operations
    esp_log_level_set("FS_TOOLS", ESP_LOG_INFO);
    esp_log_level_set("DIR_SETUP", ESP_LOG_INFO);
    esp_log_level_set("LOG_FILE_MANAGER", ESP_LOG_INFO);
    esp_log_level_set("FileReporter", ESP_LOG_INFO);
    esp_log_level_set("AsyncStorage", ESP_LOG_INFO);

    // Check if we can find the IPC task and show runtime stack info
    TaskHandle_t ipc_task = xTaskGetHandle("ipc0");
    if (ipc_task != NULL) {
        UBaseType_t stack_remaining = uxTaskGetStackHighWaterMark(ipc_task);
        LOG_INFOF(TAG, "IPC0 Task Stack: %lu bytes remaining (runtime)", (unsigned long)(stack_remaining * sizeof(StackType_t)));
    } else {
        LOG_WARNING(TAG, "Could not find IPC0 task handle");
    }

    // Storage (LittleFS) initialization
    LOG_INFOF(TAG, "FIRMWARE v%s - HYBRID: PSRAM tasks + filesystem protection",
              esp_app_get_description()->version);
    LOG_INFO(TAG, "Initializing LittleFS storage...");
    esp_vfs_littlefs_conf_t littlefs_conf = {
        .base_path = "/data",
        .partition_label = "storage",
        .partition = NULL,
        // Formatting is destructive and must be an explicit build-time opt-in.
        // Release profiles leave ESP32_OT_LITTLEFS_AUTO_FORMAT at its fail-closed
        // default (0), preserving a recoverable partition on mount errors.
        .format_if_mount_failed = (ESP32_OT_LITTLEFS_AUTO_FORMAT != 0),
        .read_only = false,
        .dont_mount = false,
        .grow_on_mount = true,
    };

    esp_err_t littlefs_ret = esp_vfs_littlefs_register(&littlefs_conf);
    const bool littlefs_mounted = (littlefs_ret == ESP_OK);
    littlefs_rollback_mounted = littlefs_mounted;
    if (littlefs_ret != ESP_OK) {
        LOG_ERRORF(TAG, "Failed to initialize LittleFS: %s", esp_err_to_name(littlefs_ret));
        if (littlefs_ret == ESP_FAIL) {
            LOG_ERROR(TAG, "LittleFS mount failed, partition may be corrupted");
        } else if (littlefs_ret == ESP_ERR_NOT_FOUND) {
            LOG_ERROR(TAG, "LittleFS partition 'storage' not found");
        }
        if (ESP32_OT_LITTLEFS_AUTO_FORMAT == 0) {
            LOG_ERROR(TAG, "Automatic LittleFS formatting is disabled; existing data was preserved");
        }
    } else {
        LOG_INFO(TAG, " LittleFS mounted successfully at /data");
    }

    if (littlefs_mounted) {
        fs_print_littlefs_report("/data", "storage");

        // Never recursively purge /data/logs at boot. FileReporter enforces the
        // configured rotate_bytes/max_files bounds on append, preserving existing
        // evidence across reboots while still limiting future growth.
        LOG_INFO(TAG, "Preserving existing LittleFS logs; bounded rotation is applied on write");

        LOG_INFO(TAG, "Creating storage directories...");
        AsyncStorage::Global::ensureDataDirectories();

        // Test file creation and accessibility
        LOG_INFO("FILE_TEST", "Testing app.log file creation and access...");
        bool app_log_exists = false;
        esp_err_t check_result = AsyncStorage::Global::fileExists("/data/logs/app.log", app_log_exists);
        LOG_INFOF("FILE_TEST", "app.log existence check: result=%s, exists=%s",
                  esp_err_to_name(check_result), app_log_exists ? "true" : "false");

        if (app_log_exists) {
            size_t app_log_size = 0;
            esp_err_t size_result = AsyncStorage::Global::fileSize("/data/logs/app.log", app_log_size);
            LOG_INFOF("FILE_TEST", "app.log size check: result=%s, size=%zu bytes",
                      esp_err_to_name(size_result), app_log_size);
        }
    } else {
        LOG_WARNING(TAG, "Skipping LittleFS report and directory creation because storage is not mounted");
    }

    // Config
    LOG_INFO(TAG, "Initializing configuration manager...");
    MemorySnapshot mem_before_cfg = MemoryMonitor::capture();
    ConfigurationManager cfg;
    if (!cfg.initialize()) {
        LOG_ERROR(TAG, "ConfigurationManager initialization failed, attempting embedded fallback");
        if (!cfg.loadDevConfigFromSource()) {
            LOG_ERROR(TAG, "Embedded fallback configuration load failed");
        }
    }
    MemoryMonitor::logDelta("ConfigurationManager::initialize", mem_before_cfg);

    if (!ProvisioningCoordinator::continueOperationalBoot(cfg)) {
        rollback_startup("operational provisioning is not complete");
        return;
    }

    // WATCHDOG CONFIGURATION - Now that config is loaded, configure watchdog
    MainTaskWatchdog main_watchdog;
    startup_sequence.trackCleanup(&rollback_watchdog, &main_watchdog);
    WatchdogConfig wdt_cfg = cfg.getWatchdogConfig();
    // Keep the boot snapshot: saving config must not stop feeding a subscribed task.
    const uint32_t configured_timeout = wdt_cfg.timeout_seconds;
    wdt_cfg.timeout_seconds = MainTaskWatchdog::normalizeTimeoutSeconds(configured_timeout);
    MainTaskWatchdog::recordBootConfiguration(wdt_cfg.enabled,
                                               configured_timeout,
                                               wdt_cfg.timeout_seconds,
                                               wdt_cfg.panic_on_timeout,
                                               wdt_cfg.monitor_idle_cores);
    LOG_INFOF(TAG, "Task Watchdog effective configuration: source=%s, requested_timeout=%lus, effective_timeout=%lus",
              cfg.getConfigSourceName().c_str(),
              (unsigned long)configured_timeout,
              (unsigned long)wdt_cfg.timeout_seconds);
    if (wdt_cfg.enabled) {
        if (configured_timeout != wdt_cfg.timeout_seconds) {
            LOG_WARNINGF(TAG, "Task Watchdog timeout adjusted from %lus to %lus",
                         (unsigned long)configured_timeout, (unsigned long)wdt_cfg.timeout_seconds);
        }
        LOG_INFOF(TAG, "Configuring Task Watchdog from config: timeout=%lus, panic=%s, idle_cores=%s",
                 (unsigned long)wdt_cfg.timeout_seconds,
                 wdt_cfg.panic_on_timeout ? "true" : "false",
                 wdt_cfg.monitor_idle_cores ? "true" : "false");

        esp_task_wdt_config_t esp_wdt_config = {
            .timeout_ms = wdt_cfg.timeout_seconds * 1000,  // Convert to milliseconds
            .idle_core_mask = wdt_cfg.monitor_idle_cores ? static_cast<uint32_t>((1 << 0) | (1 << 1)) : 0U,
            .trigger_panic = wdt_cfg.panic_on_timeout
        };

        esp_err_t wdt_result = main_watchdog.configure(esp_wdt_config);
        if (wdt_result == ESP_OK) {
            LOG_INFO(TAG, " Task Watchdog configured from config.json");
        } else {
            LOG_WARNINGF(TAG, "Task Watchdog configuration failed: %s", esp_err_to_name(wdt_result));
        }
    } else {
        LOG_INFO(TAG, "Main task watchdog disabled in configuration; other SDK watchdogs unchanged");
    }

    // Security - dependency injection with automatic configuration loading
    MemorySnapshot mem_before_security = MemoryMonitor::capture();
    SecurityManager sec;
    sec.initialize(cfg.getSecurityConfig());
    MemoryMonitor::logDelta("SecurityManager::initialize", mem_before_security);

    // Reporting
    MemorySnapshot mem_before_reporting = MemoryMonitor::capture();
    ReportingEngine rep;
    startup_sequence.trackCleanup(&rollback_reporting, &rep);
    const bool reporting_initialized = rep.initialize(&cfg, &sec);
    if (!startup_sequence.recordRequired("reporting_engine", reporting_initialized)) {
        LOG_ERROR(TAG, "ReportingEngine initialization failed");
        rollback_startup("ReportingEngine initialization failure");
        return;
    }
    g_reporting = &rep;
    PSRAMQueueConfig qc;
    qc.backup_file = "/data/reportq/psram_queue.bin";
    qc.max_items = 512;
    qc.backoff_base_ms = 1000;
    qc.backoff_max_ms  = 60000;
    qc.sync_threshold = 10;
    qc.sync_interval_ms = 30000;
    rep.enableQueue(qc, /*flush_ms*/ 3000);
    MemoryMonitor::logDelta("ReportingEngine::initialize+queue", mem_before_reporting);

    MemorySnapshot mem_before_reporting_cfg = MemoryMonitor::capture();
    ReportingConfig::loadFromConfig(&cfg, &rep);
    MemoryMonitor::logDelta("ReportingConfig::loadFromConfig", mem_before_reporting_cfg);

    // LOG SYSTEM BOOT EVENT - Track all restarts (normal and abnormal)
        rep.reportSystemBootEvent(reset_reason);

    // Connect logging system to ReportingEngine for VERBOSE channels
    if (g_logger) {
        g_logger->setReportingEngine(&rep);
        startup_sequence.trackCleanup(&rollback_logger_reporting, g_logger);
        LOG_INFO(TAG, "Logging system connected to ReportingEngine for VERBOSE channels");
    }
    MemorySnapshot mem_before_reporting_endpoints = MemoryMonitor::capture();
    ReportingConfig::registerNetworkEndpoints(&cfg, &rep);
    MemoryMonitor::logDelta("ReportingConfig::registerNetworkEndpoints", mem_before_reporting_endpoints);

    // Initialize AuditManager with ReportingEngine
    AuditManager::getInstance().init(&rep);
    LOG_INFO(TAG, "AuditManager initialized with ReportingEngine");

    // Initialize PSRAM Telemetry with monitoring and watchdog
    startup_sequence.trackCleanup(&rollback_psram_telemetry, nullptr);
    if (PSRAMTelemetry::getInstance().initialize(60000)) {  // Update every 60s
        PSRAMTelemetry::getInstance().enableWatchdog(15000);  // Alert if DRAM < 15KB
        PSRAMTelemetry::getInstance().logMetrics("Startup");
        LOG_INFO(TAG, "PSRAMTelemetry initialized (60s interval, 15KB watchdog)");
    } else {
        LOG_ERROR(TAG, "Failed to initialize PSRAMTelemetry");
    }

    // Report system initialization start
    rep.reportEvent(
        PSRAMUtils::createPSRAMString("system_lifecycle"),
        PSRAMUtils::createPSRAMString("{\"status\":\"initializing\",\"phase\":\"startup\",\"device\":\"ESP32-T-POE-Pro\"}"));

    // Memory checkpoint after core services initialization
    MemoryMonitor::checkStatus("After Core Services");

    // === Network bring-up (Ethernet + WiFi) ===
    static EthernetManager eth(&cfg);  // Dependency injection
    static EthL2Adapter l2;
    static WiFiManager wifi(&cfg);  // Dependency injection
    TimeManager::configureWiFiAutoSync(&cfg, &wifi);
    startup_sequence.trackCleanup(&rollback_time_manager, nullptr);
    startup_sequence.trackCleanup(&rollback_wifi, &wifi);
    startup_sequence.trackCleanup(&rollback_ethernet, &eth);


    static NetworkEngine net;

    // NetworkEngine dual-core + taps + L2 adapter
    LOG_INFO(TAG, "Initializing NetworkEngine...");
    NetRingConfig ring_cfg;
    ring_cfg.slots = 32;      // Ultra-conservative: 32 slots for maximum system stability
    ring_cfg.buf_size = 800;  // Keep 800 bytes per slot
    // Total memory: 32 * 800 = 25.6KB (ultra-conservative for system stability)
    MemorySnapshot mem_before_net = MemoryMonitor::capture();
    // NetworkEngine may allocate ring/semaphore/task resources before
    // returning false, so track it before attempting initialization.
    startup_sequence.trackCleanup(&rollback_network, &net);
    const bool network_initialized = net.initialize(/*netif*/ nullptr, ring_cfg);
    if (!startup_sequence.recordRequired("network_engine", network_initialized)) {
        LOG_ERROR(TAG, "NetworkEngine initialization failed - insufficient memory");
        MemoryMonitor::checkStatus("NetworkEngine Failed", true); // Critical check
        rollback_startup("NetworkEngine initialization failure");
        return; // Startup rollback has completed.
    }
    LOG_INFO(TAG, "NetworkEngine initialized");
    MemoryMonitor::logDelta("NetworkEngine::initialize", mem_before_net);
    // AUDIT: Log NetworkEngine service startup
    AuditManager::getInstance().logServiceEvent("NetworkEngine", "started", "Network subsystem initialized successfully");
    MemoryMonitor::checkStatus("After NetworkEngine");

    // Plugin manager: initialize and register built-in plugins conditionally
    MemorySnapshot mem_before_plugin_manager = MemoryMonitor::capture();
    static PluginManager pm;
    const bool plugin_manager_initialized = pm.initialize(&cfg, &rep, &net, &sec);
    MemoryMonitor::logDelta("PluginManager::initialize", mem_before_plugin_manager);

    // Register plugins only if enabled in configuration
    MemorySnapshot mem_before_plugins = MemoryMonitor::capture();
    if (cfg.isFeatureEnabled("modbus", true)) {  // Default enabled for backward compatibility
        pm.registerPlugin(createPluginInPSRAM<ModbusTCPPlugin>());
        LOG_INFO(TAG, " ModbusTCP plugin registered");
    } else {
        LOG_INFO(TAG, " ModbusTCP plugin disabled in configuration");
    }

    if (cfg.isFeatureEnabled("s7", false)) {  // Default enabled for backward compatibility
        pm.registerPlugin(createPluginInPSRAM<S7Plugin>(/*tx*/&eth, &sec));
        LOG_INFO(TAG, " S7 plugin registered");
    } else {
        LOG_INFO(TAG, " S7 plugin disabled in configuration");
    }

    if (cfg.isFeatureEnabled("profinet", false)) {  // Default enabled for backward compatibility
        pm.registerPlugin(createPluginInPSRAM<PROFINETPlugin>(/*eth*/&eth));
        LOG_INFO(TAG, " PROFINET plugin registered");
    } else {
        LOG_INFO(TAG, " PROFINET plugin disabled in configuration");
    }

    if (cfg.isFeatureEnabled("ethernetip", false)) {  // Default enabled for backward compatibility
        pm.registerPlugin(createPluginInPSRAM<EtherNetIPPlugin>());
        LOG_INFO(TAG, " EtherNet/IP plugin registered");
    } else {
        LOG_INFO(TAG, " EtherNet/IP plugin disabled in configuration");
    }

    if (cfg.isFeatureEnabled("opcua", false)) {  // Default enabled for backward compatibility
        pm.registerPlugin(createPluginInPSRAM<OPCUAPlugin>());
        LOG_INFO(TAG, " OPC-UA plugin registered");
    } else {
        LOG_INFO(TAG, " OPC-UA plugin disabled in configuration");
    }

    MemoryMonitor::logDelta("Plugin registrations", mem_before_plugins);

    // Initialize signature detector for threat detection
    auto& sig_detector = SignatureDetection::SignatureDetector::getInstance();
    bool sig_init_success = sig_detector.initialize();
    if (sig_init_success) {
        LOG_INFO(TAG, " Signature detector initialized successfully");
        AuditManager::getInstance().logServiceEvent("SignatureDetector", "initialized", "Threat detection active");
    } else {
        LOG_WARNING(TAG, "Signature detector failed to initialize - threat detection disabled");
        AuditManager::getInstance().logServiceEvent("SignatureDetector", "init_failed", "Operating without threat detection");
    }

    // Initialize Ethernet with automatic configuration from config
    LOG_INFO(TAG, "Initializing Ethernet interface...");
    if (!eth.initializeFromConfig()) {
        LOG_ERROR(TAG, "Ethernet initialization failed - check cable connection and T-POE Pro hardware");
    } else {
        // Wait for the ETH interface to obtain an IP
        LOG_INFO(TAG, "Waiting for IP/DNS before enabling network reporters...");
        uint64_t start_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
        const uint64_t max_wait_ms = 15000; // 15s
        while (((uint64_t)(esp_timer_get_time() / 1000ULL) - start_ms) < max_wait_ms) {
            if (eth.hasValidIP()) break;
            vTaskDelay(pdMS_TO_TICKS(200));
        }

        // Set reporting engine and conditionally enable raw taps
        net.setReportingEngine(&rep);
    }

    // WiFi: Initialize from configuration (STA if configured, AP fallback)
    LOG_INFO(TAG, "Initializing WiFi from configuration...");
    bool wifi_sta_success = wifi.initializeFromConfig();

	// Enable email reporter on WiFi STA if already connected, otherwise on GOT_IP
	if (wifi_sta_success && wifi.isSTAConnected()) {
		ReportingConfig::registerEmailFromConfig(&cfg, &rep);
	} else {
		static esp_event_handler_instance_t s_email_inst;
		struct EmailRegCtx { ConfigurationManager* cfg; ReportingEngine* rep; };
		static EmailRegCtx email_ctx{ &cfg, &rep };
		auto on_wifi_got_ip = [](void* arg, esp_event_base_t base, int32_t id, void* data){
			if (ReportingConfig::isEmailRegistered()) return;
			EmailRegCtx* ctx = reinterpret_cast<EmailRegCtx*>(arg);
			ReportingConfig::registerEmailFromConfig(ctx->cfg, ctx->rep);
		};
		esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi_got_ip, &email_ctx, &s_email_inst);
	}

    static IntrusionDetectionGeneral ids;
    bool ids_initialized = false;

    // Always initialize shared passive services, even when IDS starts disabled.
    {
        MemorySnapshot mem_before_ids = MemoryMonitor::capture();
        ids_initialized = ids.initialize(&cfg, &rep, &pm);
        LOG_INFO(TAG, "IDS initialization completed");

        // === CRITICAL MEMORY CHECKPOINT BEFORE WHITELIST LOADING ===
        size_t free_before_whitelist = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t largest_before_whitelist = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

        // Critical memory state detection and emergency cleanup
        if (TaskConfig::isMemoryInCriticalState()) {
            if (free_before_whitelist > 1000) {
                LOG_ERRORF(TAG, "EMERGENCY: Memory critical before whitelist - %d bytes free, largest: %d",
                        (int)free_before_whitelist, (int)largest_before_whitelist);
            }

            if (TaskConfig::emergencyMemoryCleanup()) {
                size_t free_after_cleanup = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
                if (free_after_cleanup > 1000) {
                    LOG_INFOF(TAG, " Emergency cleanup gained %d bytes before whitelist",
                            (int)(free_after_cleanup - free_before_whitelist));
                }
            }
        }

        // Load whitelist from config.json using PSRAM-optimized method
        ids.reloadWhitelistFromConfig(); // Now uses PSRAM allocation for memory safety

        size_t free_after_whitelist = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        if (free_after_whitelist > 1000) {
            LOG_INFOF(TAG, " Whitelist loaded: %d bytes free (%d bytes consumed)",
                    (int)free_after_whitelist, (int)(free_before_whitelist - free_after_whitelist));
        }

        MemoryMonitor::logDelta("IDS::initialize+whitelist", mem_before_ids);

        ids.applyRuntimeConfig();
    }
    struct PassiveRuntimeContext { ConfigurationManager* cfg; IntrusionDetectionGeneral* ids; };
    static PassiveRuntimeContext passive_runtime{&cfg, &ids};
    auto apply_passive_config = [](void* context) {
        auto& runtime = *static_cast<PassiveRuntimeContext*>(context);
        SignatureDetection::SignatureDetector::getInstance().setEnabled(
            runtime.cfg->getPassiveDetectionFlags().signatures_enabled);
        runtime.ids->applyRuntimeConfig();
    };
    cfg.setConfigAppliedCallback(apply_passive_config, &passive_runtime);
    apply_passive_config(&passive_runtime);

    // Vulnerability Scanner
    VulnerabilityScanner* scannerPtr = nullptr;
    bool scanner_initialized = false;
    if (cfg.isFeatureEnabled("vuln_scanner", false)) {
        static VulnerabilityScanner scanner;
        scanner_initialized = scanner.initialize(&pm, &rep, &cfg, &sec);
        scannerPtr = &scanner;
    } else {
        LOG_INFO(TAG, "VulnerabilityScanner disabled by configuration");
    }

    // Fuzzing Engine - initialize after all core services are ready using PluginManager
    if (cfg.isFeatureEnabled("fuzzing", false)) {
        MemorySnapshot mem_before_fuzz = MemoryMonitor::capture();
        static FuzzingEngine fuzzEngine(&rep, &sec, &logger, &pm);
        extern FuzzingEngine* g_fuzz;
        g_fuzz = &fuzzEngine;
        LOG_INFO(TAG, "Fuzzing Engine initialized with PluginManager integration");
        MemoryMonitor::logDelta("FuzzingEngine::initialize", mem_before_fuzz);
    } else {
        extern FuzzingEngine* g_fuzz;
        g_fuzz = nullptr;
        LOG_INFO(TAG, "Fuzzing Engine disabled by configuration");
    }

    // Check heap integrity before critical L2 adapter operation
    if (!heap_caps_check_integrity_all(true)) {
        LOG_ERROR(TAG, "HEAP CORRUPTION DETECTED before L2 adapter attachment!");
        // Continue anyway but with warning
    }

    bool l2_attached_ok = false;
    if (eth.handle() && eth.netif()) {
        l2_attached_ok = l2.attach(eth.handle(), eth.netif(), &net);
        LOG_INFOF(TAG, "L2 adapter attach result: %s", l2_attached_ok ? "OK" : "FAIL");
    } else {
        LOG_WARNINGF(TAG, "L2 adapter not attached (eth=%p netif=%p) - raw L2 features (e.g., PROFINET DCP) may not work",
                     eth.handle(), eth.netif());
    }

    // Get actual IP addresses and display them
    bool has_ip = false;

    // Check Ethernet IP status
    if (eth.hasValidIP()) {
        char eth_ip[16] = {};
        eth.getIP(eth_ip, sizeof(eth_ip));
        LOG_INFOF(TAG, "Ethernet interface active with IP: %s", eth_ip);
        //TimeManager::requestSyncForNetif(eth.netif(), "Ethernet link ready");
        has_ip = true;
    } else if (eth.netif()) {
        LOG_WARNING(TAG, "Ethernet interface active but no IP assigned (check DHCP/cable)");
    } else {
        LOG_WARNING(TAG, " Ethernet interface not available");
    }


    // Register packet callback - general IDS/signatures stay centralized;
    // protocol plugins receive the BasePlugin template-method dispatch.
    net.registerPacketCallback([&](const NetworkPacket& pkt){
        // DEBUG: Direct log to serial for network packet monitoring
        /*printf("[PACKET_DEBUG] 📦 Packet captured: %s:%d -> %s:%d (proto=%d, len=%d)\n",
               pkt.src_ip.c_str(), pkt.src_port, pkt.dst_ip.c_str(), pkt.dst_port,
               (int)pkt.proto, (int)pkt.length);

        // Log payload details for the first 32 bytes
        if (pkt.data && pkt.length > 0) {
            printf("[PACKET_DEBUG] 🔍 Payload (first 32 bytes): ");
            int bytes_to_show = (pkt.length > 32) ? 32 : pkt.length;
            for (int i = 0; i < bytes_to_show; i++) {
                printf("%02X ", (unsigned char)pkt.data[i]);
            }
            printf("\n");
        }*/

        // One snapshot per packet. Presence never grants authorization on its own.
        const bool bypassAuthorization = PassiveDetection::dispatch(
            cfg.getPassiveDetectionFlags(),
            [&] { ids.getNetworkPresenceTracker().trackPacket(pkt); },
            [&] { return ids.onPacket(pkt); },
            [&] {
        if (pkt.data && pkt.length > 0) {
            auto& detector = SignatureDetection::SignatureDetector::getInstance();
            psram_string threat_report_json;
            SignatureDetection::DetectionResult detection = detector.analyzePacketWithReport(pkt, threat_report_json);

            if (detection.detected) {
                //printf("[PACKET_DEBUG] 🚨 THREAT DETECTED! CVE=%s, protocol=%d, offset=%lu\n",
                //       detection.cve_id, (int)detection.protocol, (unsigned long)detection.offset);

                static const psram_string kThreatDetectedType = PSRAMUtils::createPSRAMString("threat_detected");
                // Send detailed JSON threat report to reporting engine
                if (!threat_report_json.empty()) {
                    //printf("[PACKET_DEBUG] 📧 Sending threat report to the reporting system (JSON: %u bytes)\n", (unsigned)threat_report_json.length());
                    LOG_INFOF(TAG, "Sending threat detection event to reporting engine (JSON size: %u bytes)", (unsigned)threat_report_json.length());
                    rep.reportEvent(kThreatDetectedType, threat_report_json);
                    LOG_INFOF(TAG, "Detailed threat report sent to reporting channels - email dispatch initiated");
                }

                // Create structured threat detection report (backward compatibility)
                EventRecord threat_event;
                threat_event.channel = "security";
                threat_event.type = "threat_detected";
                threat_event.name = "CVE Pattern Match";
                threat_event.severity = "High";

                char offset_str[16];
                snprintf(offset_str, sizeof(offset_str), "%lu", (unsigned long)detection.offset);

                threat_event.ext = {
                    {"cve_id", detection.cve_id},
                    {"protocol", PluginManager::protocolTypeToString(detection.protocol)},
                    {"offset", offset_str},
                    {"src_ip", pkt.src_ip.c_str()},
                    {"dst_ip", pkt.dst_ip.c_str()}
                };

                // Submit security event through reporting engine
                rep.submit(threat_event);

                // Also audit the security event
                AuditManager::getInstance().logSecurityEvent("cve_pattern_match", nullptr, pkt.src_ip.c_str(), detection.cve_id);
            }
        }

        });

        // Forward to plugins with bypass flag
        if (auto* bp = pm.findByProtocol(pkt.proto)) {
            //printf("[PACKET_DEBUG] 🔌 Plugin activated for protocol %d - bypass=%s\n",
            //       (int)pkt.proto, bypassAuthorization ? "true" : "false");
            bp->onPacket(pkt, bypassAuthorization);
            //printf("[PACKET_DEBUG] ✅ Plugin processing completed\n");
        } else {
            //printf("[PACKET_DEBUG] ⚠️ No plugin available for protocol %d\n", (int)pkt.proto);
        }

        // Final summary of the processed packet
        //printf("[PACKET_DEBUG] 📋 Summary: %s:%d->%s:%d (proto=%d, len=%d, bypass=%s) - COMPLETED\n\n",
        //       pkt.src_ip.c_str(), pkt.src_port, pkt.dst_ip.c_str(), pkt.dst_port,
        //       (int)pkt.proto, (int)pkt.length, bypassAuthorization ? "true" : "false");

    });
    LOG_INFO(TAG, "Packet callback registered");

    // Check WiFi STA
    esp_netif_t* wifi_sta_netif = wifi.sta();
    if (wifi_sta_netif) {
        esp_netif_ip_info_t wifi_ip_info;
        if (esp_netif_get_ip_info(wifi_sta_netif, &wifi_ip_info) == ESP_OK && wifi_ip_info.ip.addr != 0) {
            LOG_INFOF(TAG, "WiFi STA: %s",
                     inet_ntoa(wifi_ip_info.ip));
            has_ip = true;
            // Time sync is triggered asynchronously via the IP_EVENT_STA_GOT_IP handler
            // and processed non-blocking in the main loop (TimeManager::processPendingSync).
        }
    }

    // Check WiFi AP
    esp_netif_t* wifi_ap_netif = wifi.ap();
    if (wifi_ap_netif) {
        esp_netif_ip_info_t ap_ip_info;
        if (esp_netif_get_ip_info(wifi_ap_netif, &ap_ip_info) == ESP_OK && ap_ip_info.ip.addr != 0) {
            LOG_INFOF(TAG, "WiFi AP: %s",
                     inet_ntoa(ap_ip_info.ip));
            has_ip = true;
        }
    }

    // Critical memory check before WebServer - this is where the original crash occurred
    MemoryMonitor::checkStatus("Before WebServer", true);

    // === CRITICAL MEMORY CHECK BEFORE WEBSERVER ===
    size_t free_before_ws = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_before_ws = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) > 1000) {
        LOG_INFOF(TAG, "Pre-WebServer memory: %d bytes free, largest: %d", (int)free_before_ws, (int)largest_before_ws);
    }

    size_t psram_used = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    LOG_INFOF(TAG, "PSRAM Buffer Summary: PSRAM used: %u bytes",
              (unsigned)psram_used);

    // === AGGRESSIVE MEMORY RECOVERY FOR WEBSERVER ===
    if (TaskConfig::isMemoryInCriticalState() || TaskConfig::isPSRAMInCriticalState() || largest_before_ws < 3000) {
        if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) > 1000) {
            LOG_ERRORF(TAG, "CRITICAL: Emergency cleanup before WebServer (largest block: %d)", (int)largest_before_ws);
        }

        // Multi-stage emergency cleanup - BOTH IRAM AND PSRAM
        for (int stage = 0; stage < 3; stage++) {
            // Clean up internal RAM
            TaskConfig::emergencyMemoryCleanup();

            // Clean up PSRAM
            TaskConfig::emergencyPSRAMCleanup();

            vTaskDelay(pdMS_TO_TICKS(150)); // Allow cleanup to settle (increased for PSRAM)

            size_t after_cleanup = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
            size_t after_psram_cleanup = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

            if (after_cleanup > 8000 && after_psram_cleanup > 50000) break; // Sufficient memory recovered
        }

        free_before_ws = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        largest_before_ws = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        size_t psram_free_after = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t psram_largest_after = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

        if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) > 1000) {
            LOG_INFOF(TAG, "Post-cleanup IRAM: %d bytes free, largest: %d", (int)free_before_ws, (int)largest_before_ws);
            LOG_INFOF(TAG, "Post-cleanup PSRAM: %d bytes free, largest: %d", (int)psram_free_after, (int)psram_largest_after);
        }
    }

    // Final check - only restart if completely insufficient
    if (largest_before_ws < 2000) {  // Only restart if largest block < 2KB
        if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) > 500) {
            LOG_ERRORF(TAG, "FATAL: Insufficient memory for WebServer, largest block: %d bytes", (int)largest_before_ws);
        }
        //esp_restart();
        //return;
    }

    // Early minimal WebServer bring-up to secure management UI before heavy modules
    LogFileManager* web_log_manager = ReportingConfig::getLogFileManager();
    static WebServer web; // single instance for whole runtime
    const bool web_initialized = web.initialize(&cfg, &rep, &logger,
                 /*plugins*/ nullptr,
                 /*ids*/ nullptr,
                 &eth, &wifi,
                 /*scanner*/ nullptr,
                 &sec, &net,
                 web_log_manager);

    // Always attach full runtime dependencies before serving API routes.
    // If omitted, /api/ids/presence/* can see null ids_/plugins_ when WebServer
    // starts after fallback path (AP/STA late start).
    web.attachFull(&pm, &ids, &eth, &wifi, scannerPtr, &net);

    // A single fail-closed controller owns management-interface selection.
    // Wi-Fi-only profiles never fall back to Ethernet, and overlapping IT/OT
    // subnets disable management until the configuration is safe again.
    static ManagementInterfaceController management_controller(web, eth, wifi);
    management_controller.tick();
    const bool web_started = web.isRunning();

    if (!web_started) {
        LOG_ERROR(TAG, " HTTP server failed to start on all interfaces (Ethernet, WiFi STA, WiFi AP)");
        LOG_INFO(TAG, "Web management unavailable - use serial console for configuration");
    }

    if (!has_ip) {
        LOG_INFO(TAG, "System up. Waiting for network connection...");
    } else {
        LOG_INFO(TAG, "Network running!");
    }

    // Report startup using observed service state rather than a static claim.
    // Optional services explicitly disabled by configuration are represented as
    // disabled; services waiting for an interface are starting, and failed
    // workers/interfaces are never advertised as active.
    const PassiveDetection::Flags passive_flags = cfg.getPassiveDetectionFlags();
    const bool scanner_requested = cfg.isFeatureEnabled("vuln_scanner", false);
    const bool web_waiting_for_interface =
        management_controller.state() == ManagementInterfaceState::WAITING_FOR_INTERFACE;
    StartupServiceStatus startup_services[] = {
        {"network_engine", network_initialized ? StartupServiceState::Running : StartupServiceState::Failed,
         true, network_initialized ? "initialized" : "initialization failed"},
        {"plugin_manager", plugin_manager_initialized ? StartupServiceState::Running : StartupServiceState::Failed,
         true, plugin_manager_initialized ? "initialized" : "initialization failed"},
        {"ids", !passive_flags.ids_enabled ? StartupServiceState::Disabled
             : (ids_initialized && ids.isActive() ? StartupServiceState::Running : StartupServiceState::Failed),
         passive_flags.ids_enabled, !passive_flags.ids_enabled ? "disabled by configuration"
             : (ids_initialized && ids.isActive() ? "worker active" : "worker failed to start")},
        {"vulnerability_scanner", !scanner_requested ? StartupServiceState::Disabled
             : (scanner_initialized && scannerPtr && scannerPtr->isRunning()
                ? StartupServiceState::Running : StartupServiceState::Failed),
         scanner_requested, !scanner_requested ? "disabled by configuration"
             : (scanner_initialized && scannerPtr && scannerPtr->isRunning()
                ? "worker active" : "initialization failed")},
        {"web_server", !web_initialized ? StartupServiceState::Failed
             : (web_started ? StartupServiceState::Running
                : (web_waiting_for_interface ? StartupServiceState::Starting
                                              : StartupServiceState::Failed)),
         true, !web_initialized ? "initialization failed"
             : (web_started ? "accepting connections"
                : (web_waiting_for_interface ? "waiting for management interface"
                                              : "server failed to start"))},
        {"reporting_engine", reporting_initialized && rep.isRunning() ? StartupServiceState::Running
             : StartupServiceState::Failed, true,
         reporting_initialized && rep.isRunning() ? "worker active" : "initialization failed"},
    };
    const StartupStatusSnapshot startup_snapshot{
        startup_services, sizeof(startup_services) / sizeof(startup_services[0])};
    cJSON* startup_root = cJSON_CreateObject();
    if (startup_root) {
        cJSON_AddStringToObject(startup_root, "status", startupSnapshotGlobalState(startup_snapshot));
        cJSON* active_services = cJSON_AddArrayToObject(startup_root, "services");
        cJSON* service_status = cJSON_AddObjectToObject(startup_root, "service_status");
        for (std::size_t i = 0; i < startup_snapshot.count; ++i) {
            const StartupServiceStatus& service = startup_snapshot.services[i];
            if (service.state == StartupServiceState::Running && active_services) {
                cJSON_AddItemToArray(active_services, cJSON_CreateString(service.name));
            }
            if (service_status) {
                cJSON* details = cJSON_AddObjectToObject(service_status, service.name);
                if (!details) continue;
                cJSON_AddStringToObject(details, "state", startupServiceStateName(service.state));
                cJSON_AddBoolToObject(details, "requested", service.requested);
                cJSON_AddStringToObject(details, "reason", service.reason ? service.reason : "");
            }
        }
        char* startup_json = cJSON_PrintUnformatted(startup_root);
        if (startup_json) {
            rep.reportEvent(PSRAMUtils::createPSRAMString("system_lifecycle"),
                            PSRAMUtils::createPSRAMString(startup_json));
            free(startup_json);
        }
        cJSON_Delete(startup_root);
    }

    // WATCHDOG REGISTRATION - Subscribe only when enabled; track the SDK result.
    const esp_err_t wdt_start_result = main_watchdog.start(wdt_cfg.enabled,
        static_cast<uint32_t>(esp_timer_get_time() / 1000000));
    if (wdt_start_result != ESP_OK) {
        LOG_WARNINGF(TAG, "Main task watchdog setup failed: %s (subscribed=%s)",
                     esp_err_to_name(wdt_start_result), main_watchdog.subscribed() ? "true" : "false");
    } else if (main_watchdog.subscribed()) {
        LOG_INFO(TAG, "Main task registered with watchdog");
    } else {
        LOG_INFO(TAG, "Main task watchdog disabled - task not registered");
    }
    LOG_INFO(TAG, "System initialization complete");


    MemoryMonitor::checkStatus("End inizialization", true);

    // AUDIT: Log system startup event with build information
    AuditManager::getInstance().logSystemStartup(esp_app_get_description()->version, __DATE__ " " __TIME__);

    // Keep main() running - ESP32 embedded systems typically don't exit main()
    esp_err_t last_watchdog_feed_error = ESP_OK;
    uint32_t last_memory_check = 0;
    while (true) {
        TimeManager::processPendingSync();
        management_controller.tick();

        uint32_t now = esp_timer_get_time() / 1000000; // seconds

        // If Ethernet becomes ready after startup, retry L2 adapter attachment once.
        if (!l2_attached_ok && eth.handle() && eth.netif()) {
            l2_attached_ok = l2.attach(eth.handle(), eth.netif(), &net);
            LOG_INFOF(TAG, "L2 adapter late attach result: %s", l2_attached_ok ? "OK" : "FAIL");
        }

        //MEMORY CHECK - Check memory status every 30 seconds
        if (now - last_memory_check >= 120) {
            MemoryMonitor::checkStatus("Loop", true);
            last_memory_check = now;
        }


        // Feed the actual subscription, not a possibly changed saved configuration.
        esp_err_t wdt_feed_result = ESP_OK;
        if (main_watchdog.feedIfDue(now, wdt_feed_result) &&
            wdt_feed_result != last_watchdog_feed_error) {
            if (wdt_feed_result != ESP_OK) {
                LOG_WARNINGF(TAG, "Main task watchdog heartbeat failed: %s (subscribed=%s)",
                             esp_err_to_name(wdt_feed_result), main_watchdog.subscribed() ? "true" : "false");
            } else {
                LOG_INFO(TAG, "Main task watchdog heartbeat recovered");
            }
            last_watchdog_feed_error = wdt_feed_result;
        }

        vTaskDelay(pdMS_TO_TICKS(1000));

        //task_audit_run();
    }

}

// Read crash metadata only after NVS and AsyncStorage have completed startup.
// The native ESP-IDF panic handler writes the coredump atomically; this boot-time
// reader never performs flash writes or allocates from the panic path.
static void log_previous_crash_diagnostics(esp_reset_reason_t reset_reason,
                                           const char* reason_str) {
    if (!is_abnormal_reset(reset_reason)) {
        LOG_INFOF(TAG, "Normal system boot: %s", reason_str);
        return;
    }

    LOG_ERRORF(TAG, "ABNORMAL RESTART DETECTED: %s", reason_str);

    // Keep compatibility with metadata produced by older development builds.
    // These reads are intentionally located after AsyncStorage initialization.
    std::string crash_reason;
    if (AsyncStorage::Global::nvsGet("crash_log", "crash_reason", crash_reason) == ESP_OK) {
        LOG_ERRORF(TAG, "Previous crash reason: %s", crash_reason.c_str());
    }

    uint32_t crash_addr = 0;
    if (AsyncStorage::Global::nvsGet("crash_log", "crash_addr", crash_addr) == ESP_OK) {
        LOG_ERRORF(TAG, "Crash address: 0x%08lx", (unsigned long)crash_addr);
    }

    uint32_t crash_time = 0;
    if (AsyncStorage::Global::nvsGet("crash_log", "last_crash_ms", crash_time) == ESP_OK) {
        LOG_ERRORF(TAG, "Last crash time: %lu ms", (unsigned long)crash_time);
    }

    const CrashDumpInspection coredump = CrashDiagnostics::inspectCoredump();
    if (coredump.image_status == ESP_OK) {
        LOG_ERROR(TAG, "Previous ESP-IDF coredump image is valid");
        if (coredump.hasPanicReason()) {
            LOG_ERRORF(TAG, "Coredump panic reason: %s", coredump.panic_reason);
        } else {
            LOG_WARNINGF(TAG, "Coredump image valid but panic reason unavailable: %s",
                         esp_err_to_name(coredump.reason_status));
        }
    } else if (coredump.image_status == ESP_ERR_NOT_FOUND) {
        LOG_WARNING(TAG, "No previous coredump image found");
    } else {
        LOG_WARNINGF(TAG, "Previous coredump image failed integrity check: %s",
                     esp_err_to_name(coredump.image_status));
    }
}

/*
// Utility: log current DNS servers on common interfaces (DHCP or static)
static void log_dns_servers()
{
    struct IfEntry { const char* ifkey; const char* name; } ifs[] = {
        { "WIFI_STA_DEF", "WiFi-STA" },
        { "ETH_DEF",      "ETH" }
    };
    for (auto& e : ifs) {
        esp_netif_t* nif = esp_netif_get_handle_from_ifkey(e.ifkey);
        if (!nif) continue;
        for (int t = (int)ESP_NETIF_DNS_MAIN; t <= (int)ESP_NETIF_DNS_FALLBACK; ++t) {
            esp_netif_dns_info_t info{};
            if (esp_netif_get_dns_info(nif, (esp_netif_dns_type_t)t, &info) == ESP_OK) {
                if (info.ip.type == IPADDR_TYPE_V4 && info.ip.u_addr.ip4.addr != 0) {
                    char ipstr[16];
                    snprintf(ipstr, sizeof(ipstr), IPSTR, IP2STR(&info.ip.u_addr.ip4));
                    const char* tt = (t==ESP_NETIF_DNS_MAIN?"MAIN":(t==ESP_NETIF_DNS_BACKUP?"BACKUP":"FALLBACK"));
                    LOG_INFOF("DNS", "[%s] %s DNS: %s", e.name, tt, ipstr);
                }
            }
        }
    }
}
*/
