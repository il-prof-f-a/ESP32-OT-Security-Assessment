#pragma once
#include <string>
#include <cstdarg>
#include <cstddef>
#include <atomic>
#include <cstdint>
#include "types.h"

extern "C" {
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "freertos/ringbuf.h"   // ← ring buffer for async logging
  #include "freertos/semphr.h"
  #include "freertos/queue.h"
}

/**
 * Log entry "high-level" (we keep the struct for API compatibility),
 * but the recommended path is to use logf()/log_json_block() which format
 * a complete line and perform a SINGLE async write.
 */
struct LogEntry {
    std::string tag;
    LogLevel    level;
    std::string message;
    uint64_t    timestamp_ms;
};

// Forward declaration
class ReportingEngine;

/**
 * Async logger:
 * - init_async(ring_bytes) creates a dedicated writer task + ring buffer.
 * - logf()/write_raw() enqueue complete messages (one line = one write).
 * - log_json_block() prints atomic JSON blocks (BEGIN/END in a single call).
 * - init_sync() remains available (fallback with mutex).
 *
 * NOTE:
 *   - Call init_async() once at startup, before logging.
 *   - The LOG_*F macros below use logf() (no fixed 256/1024 buffer).
 */
class Logger {
public:
    Logger();
    ~Logger();

    // Legacy config (no-op here: we keep the signature for compatibility)
    void updateConfig(const DebugConfig& cfg) { (void)cfg; }

    // "high-level" API compatible with your existing code
    void log(const char* tag, LogLevel lvl, const std::string& msg);

    // Lifecycle
    void start();     // alias of init_async() if you want to use it by instantiating g_logger
    void stop();      // stops the writer task and closes the ring

    // Connect the ReportingEngine if you need it (not used by the logger core)
    void setReportingEngine(ReportingEngine* reporting_engine) { reporting_engine_ = reporting_engine; }

    // ESP_LOGx → Logger redirection (optional)
    static int  espLogVprintf(const char* fmt, va_list args);
    void        setupESPLogRedirect();

    // ASYNCHRONOUS mode (recommended)
    static bool init_async(size_t ring_bytes = 16 * 1024); // creates ring + writer task
    static void shutdown();                                // stops the writer and frees the ring

    // SYNCHRONOUS mode (fallback, uses mutex around the write)
    static bool init_sync();

    // Formatted logging: ONE line = ONE write (newline auto-added if missing)
    static void logf(const char* tag, const char* fmt, ...);
    static void vlogf(const char* tag, const char* fmt, va_list ap);

    // Ready-made buffer (JSON or other)
    static void write_raw(const char* data, size_t len);

    // Atomic JSON block (BEGIN/END + payload in one shot)
    static void log_json_block(const char* tag, const char* json);

    static SemaphoreHandle_t s_mutex;

private:
    // Async writer worker
    static void  writerTaskThunk(void* arg);
           void  writerTaskLoop();

    // Enqueue into the ring (used by the statics via g_logger)
    void enqueue(const char* buf, size_t len);

    // State/resources
    RingbufHandle_t ring_        = nullptr;
    TaskHandle_t    writer_task_ = nullptr;
    std::atomic<bool> running_{false};
    ReportingEngine* reporting_engine_ = nullptr;

    // Dimensions/parameters
    static constexpr size_t DEFAULT_RING_BYTES = 16 * 1024;
    static constexpr size_t WRITER_STACK_SIZE  = 4096;    // adjust if necessary
    static constexpr UBaseType_t WRITER_PRIO   = tskIDLE_PRIORITY + 3;
    static constexpr BaseType_t  WRITER_CORE   = 1;       // pin on core 1 (ESP32)
};

// Global pointer (as in your code)
extern Logger* g_logger;

/* ===================== Conveniences / Macros ===================== */

/**
 * Legacy message-level macros (they enqueue asynchronously).
 * If g_logger is null, they do nothing.
 */
// Safe path (no heap allocations): uses stack buffer + ring buffer
// Avoid std::string in low-DRAM conditions which could generate exceptions
#define LOG_DEBUG(tag, msg)    do { Logger::logf((tag), "%s", (msg)); } while(0)
#define LOG_INFO(tag, msg)     do { Logger::logf((tag), "%s", (msg)); } while(0)
#define LOG_WARNING(tag, msg)  do { Logger::logf((tag), "%s", (msg)); } while(0)
#define LOG_ERROR(tag, msg)    do { Logger::logf((tag), "%s", (msg)); } while(0)

/**
 * Formatted macros — they use logf() (no fixed buffers on the stack).
 * They guarantee "one line = one write" and a trailing newline.
 */
#define LOG_DEBUGF(tag, fmt, ...)    do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)
#define LOG_INFOF(tag, fmt, ...)     do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)
#define LOG_WARNINGF(tag, fmt, ...)  do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)
#define LOG_ERRORF(tag, fmt, ...)    do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)

/**
 * Macro for atomic JSON blocks (BEGIN/END + payload in a single call).
 */
#define LOG_JSON_BLOCK(tag, json_cstr)  do { Logger::log_json_block((tag), (json_cstr)); } while(0)
