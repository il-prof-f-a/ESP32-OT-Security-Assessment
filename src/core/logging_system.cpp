#include "logging_system.h"
#include "reporting_engine.h"
#include "task_alloc_helpers.h"
#include "task_config.h"
#include "time_manager.h"
#include "psram_allocator.h"

#include <cstdio>
#include <ctime>
#include <cstring>
#include <cstdarg>
#include <inttypes.h>  // ← for PRIu32
#include <sys/time.h>
extern "C" {
    #include "esp_heap_caps.h"
    #include "freertos/ringbuf.h"
}
extern "C" {
  #include "esp_timer.h"
  #include "esp_log.h"   // esp_log_set_vprintf
  #include "esp_heap_caps.h"
}

// Global instance allocated in PSRAM to reduce DRAM usage
Logger* g_logger = nullptr;

// Simple timestamp utility for direct console logging
static void formatTimestampForConsole(char* buffer, size_t buffer_size, uint64_t timestamp_ms) {
    static time_t cached_real_time = 0;
    static uint64_t cached_boot_time_ms = 0;
    static bool has_ntp_time = false;
    static uint64_t last_sync_ms = 0;
    const uint64_t SYNC_INTERVAL_MS = 3ULL * 60 * 60 * 1000; // 3 hours

    uint64_t current_boot_ms = esp_timer_get_time() / 1000ULL;

    // Check if we need to update the cached time
    if (cached_real_time == 0 || (current_boot_ms - last_sync_ms) > SYNC_INTERVAL_MS) {
        time_t now;

        // Use TimeManager if available, fallback to system time
        if (TimeManager::isSynchronized()) {
            now = TimeManager::getCurrentTime();
            has_ntp_time = true; // TimeManager handles sync detection
        } else {
            time(&now);
            // Check if we have a reasonable timestamp (after year 2020)
            has_ntp_time = (now > 1577836800); // 1 Jan 2020 00:00:00 UTC
        }

        if (has_ntp_time) {
            cached_real_time = now;
            cached_boot_time_ms = current_boot_ms;
        }
        last_sync_ms = current_boot_ms;
    }

    if (buffer_size == 0) {
        return;
    }

    buffer[0] = '\0';

    if (has_ntp_time && cached_real_time > 0) {
        // Calculate real time for the specific log timestamp
        uint64_t elapsed_since_cache = timestamp_ms - cached_boot_time_ms;
        time_t log_real_time = cached_real_time + (elapsed_since_cache / 1000);
        struct tm timeinfo;
        localtime_r(&log_real_time, &timeinfo);

        // Format as yyyy.mm.dd hh:mm:ss using strftime to avoid format truncation warnings
        if (strftime(buffer, buffer_size, "%Y.%m.%d %H:%M:%S ", &timeinfo) == 0) {
            // Ensure zero-terminated even if the buffer was too small
            buffer[buffer_size - 1] = '\0';
        }
    } else {
        // Fallback to boot time: [HH:MM:SS.mmm]
        uint64_t seconds = timestamp_ms / 1000;
        uint64_t milliseconds = timestamp_ms % 1000;
        uint32_t hours = (seconds / 3600) % 24;
        uint32_t minutes = (seconds / 60) % 60;
        uint32_t secs = seconds % 60;

        if (buffer_size >= 2) {
            int written = snprintf(buffer, buffer_size, "[%02lu:%02lu:%02lu.%03lu] ",
                                   (unsigned long)hours,
                                   (unsigned long)minutes,
                                   (unsigned long)secs,
                                   (unsigned long)milliseconds);
            if (written < 0 || static_cast<size_t>(written) >= buffer_size) {
                buffer[buffer_size - 1] = '\0';
            }
        }
    }
}

static Logger* createLoggerInPSRAM() {
    // Allocate Logger in PSRAM to reduce pressure on internal DRAM
    Logger* logger = (Logger*)heap_caps_malloc(sizeof(Logger), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (logger) {
        new (logger) Logger(); // placement new
        return logger;
    } else {
        // Fallback to DRAM if PSRAM is not available
        return new Logger();
    }
}

// ==== Statics/Fallback sync ====
SemaphoreHandle_t Logger::s_mutex = nullptr;

// ======================= ctor/dtor =======================
Logger::Logger() {}
Logger::~Logger() { stop(); }

// ======================= init/shutdown =======================
bool Logger::init_async(size_t ring_bytes) {
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();

    if (!g_logger) g_logger = createLoggerInPSRAM();
    if (g_logger->ring_) return true; // already initialized

    // Allocate ring buffer in PSRAM to save DRAM
    const size_t ring_size = ring_bytes ? ring_bytes : DEFAULT_RING_BYTES;

    // Allocate buffer storage in PSRAM
    uint8_t* ring_storage = (uint8_t*)PSRAMUtils::allocatePreferred(ring_size);

    // Allocate control structure in DRAM (required by xRingbufferCreateStatic)
    StaticRingbuffer_t* ring_struct = (StaticRingbuffer_t*)malloc(sizeof(StaticRingbuffer_t));

    // Create static ring buffer with PSRAM storage if both allocations succeeded
    if (ring_storage && ring_struct) {
        g_logger->ring_ = xRingbufferCreateStatic(ring_size, RINGBUF_TYPE_BYTEBUF,
                                                 ring_storage, ring_struct);
    }

    // Fallback to regular DRAM allocation if PSRAM or struct allocation fails
    if (!g_logger->ring_) {
        // Free partial allocations if they succeeded
        if (ring_storage) {
            heap_caps_free(ring_storage);
        }
        if (ring_struct) {
            free(ring_struct);
        }
        // Use standard ring buffer in DRAM
        g_logger->ring_ = xRingbufferCreate(ring_size, RINGBUF_TYPE_BYTEBUF);
    }
    if (!g_logger->ring_) return false;

    g_logger->running_.store(true);

    // Create log_writer task using centralized configuration (with priority included)
    g_logger->writer_task_ = TaskConfig::createTask(
        &Logger::writerTaskThunk,
        "log_writer",
        TaskConfig::Presets::LOG_WRITER,
        g_logger,
        1
    );

    BaseType_t ok = (g_logger->writer_task_ != nullptr) ? pdPASS : pdFAIL;
    if (ok != pdPASS) {
        vRingbufferDelete(g_logger->ring_);
        g_logger->ring_ = nullptr;
        g_logger->running_.store(false);
        return false;
    }
    return true;
}

size_t Logger::startupRingBytes() {
#ifdef CONFIG_SPIRAM
    // Startup loads many signatures before the serial writer can drain them.
    // PSRAM-backed boards can absorb that burst without consuming DRAM.
    return 64 * 1024;
#else
    return DEFAULT_RING_BYTES;
#endif
}

void Logger::shutdown() {
    if (!g_logger) return;
    g_logger->stop();
}

void Logger::start() {
    (void) Logger::init_async(DEFAULT_RING_BYTES);
}

void Logger::stop() {
    running_.store(false);
    if (writer_task_) {
        vTaskDelete(writer_task_);
        writer_task_ = nullptr;
    }
    if (ring_) {
        vRingbufferDelete(ring_);
        ring_ = nullptr;
    }
}

// ======================= enqueue / writer =======================
void Logger::enqueue(const char* buf, size_t len) {
    if (!ring_ || !buf || !len) return;
    BaseType_t ok = xRingbufferSend(ring_, buf, len, 0 /* no wait */);
    if (!ok) {
        // Never enqueue a diagnostic into an already-full ring: that was both
        // misleading and recursive under sustained reporting traffic.
        dropped_messages_.fetch_add(1, std::memory_order_relaxed);
    }
}

void Logger::writerTaskThunk(void* arg) {
    static_cast<Logger*>(arg)->writerTaskLoop();
}

void Logger::writerTaskLoop() {
    for (;;) {
        size_t len = 0;
        char* item = (char*) xRingbufferReceive(ring_, &len, portMAX_DELAY);
        if (!item) continue;

        fwrite(item, 1, len, stdout);
        fflush(stdout);

        vRingbufferReturnItem(ring_, item);

        const uint32_t dropped = dropped_messages_.exchange(0, std::memory_order_relaxed);
        if (dropped > 0) {
            std::fprintf(stdout, "[log] %lu message(s) dropped while the serial ring was full\n",
                         static_cast<unsigned long>(dropped));
            std::fflush(stdout);
        }
    }
}

// ======================= Compatible "high-level" API =======================
void Logger::log(const char* tag, LogLevel lvl, const std::string& msg) {
    // CRITICAL: Prevent infinite recursion loop between LoggingSystem and ReportingEngine
    static thread_local bool in_log_processing = false;
    if (in_log_processing) {
        return; // Block recursive calls to prevent stack overflow and heap corruption
    }
    in_log_processing = true;

    // Forward ONLY to the ReportingEngine - the ReportingEngine handles verbosity and decides where to write
    if (reporting_engine_) {
        static const char* N[] = {"DEBUG","INFO","WARNING","ERROR"};
        const char* level = N[(int) ((lvl>=LogLevel::DEBUG && lvl<=LogLevel::ERROR)? lvl : LogLevel::INFO)];
        uint64_t t_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
        reporting_engine_->reportLogMessage(tag ? std::string(tag) : std::string("LOG"),
                                            std::string(level), msg, t_ms);
    }
    // Direct console writing removed - everything handled by the ReportingEngine

    in_log_processing = false;
}


// ======================= Formatted / JSON / Sync fallback =======================
bool Logger::init_sync() {
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    return s_mutex != nullptr;
}

void Logger::write_raw(const char* data, size_t len) {
    if (g_logger && g_logger->ring_) {
        g_logger->enqueue(data, len);
        return;
    }
    if (s_mutex) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        fwrite(data, 1, len, stdout);
        fflush(stdout);
        xSemaphoreGive(s_mutex);
    } else {
        fwrite(data, 1, len, stdout);
        fflush(stdout);
    }
}

void Logger::logf(const char* tag, const char* fmt, ...) {
    // Guard against float formatting when DRAM is low to avoid dtoa heap allocations.
    // Parse the printf format to detect actual float conversions (a/A/e/E/f/F/g/G),
    // not just any occurrence of those letters in plain text.
    auto fmt_has_float_conv = [](const char* s)->bool {
        if (!s) return false;
        while (*s) {
            if (*s != '%') { ++s; continue; }
            ++s; // skip '%'
            if (*s == '%') { ++s; continue; } // literal '%'
            // flags
            while (*s == '-' || *s == '+' || *s == ' ' || *s == '#' || *s == '0') ++s;
            // width
            if (*s == '*') { ++s; } else { while (*s >= '0' && *s <= '9') ++s; }
            // precision
            if (*s == '.') {
                ++s;
                if (*s == '*') { ++s; } else { while (*s >= '0' && *s <= '9') ++s; }
            }
            // length modifiers
            if (*s == 'h' || *s == 'l' || *s == 'j' || *s == 'z' || *s == 't' || *s == 'L') {
                char c = *s++;
                if ((c == 'h' && *s == 'h') || (c == 'l' && *s == 'l')) ++s; // hh or ll
            }
            // conversion
            char conv = *s ? *s++ : '\0';
            if (conv == 'a' || conv == 'A' || conv == 'e' || conv == 'E' || conv == 'f' || conv == 'F' || conv == 'g' || conv == 'G') {
                return true;
            }
        }
        return false;
    };

    bool has_float_conv = fmt_has_float_conv(fmt);

    size_t free_dram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (has_float_conv && free_dram < 30000) {
        // Skip formatting with floats under low memory; print a safe placeholder with timestamp
        uint64_t t_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
        char timestamp_buf[32];
        formatTimestampForConsole(timestamp_buf, sizeof(timestamp_buf), t_ms);

        char warn[256];
        int m = 0;
        m += snprintf(warn, sizeof(warn), "%s", timestamp_buf);
        if (tag && *tag) m += snprintf(warn + m, (m<0?0:sizeof(warn)-m), "[%s] ", tag);
        m += snprintf(warn + (m<0?0:m), (m<0?0:sizeof(warn)-m), "(lowmem) skipped float log: %s\n", fmt ? fmt : "");
        if (g_logger && g_logger->ring_) {
            g_logger->enqueue(warn, (size_t)((m>0)?m:0));
        } else if (s_mutex) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            fwrite(warn, 1, (size_t)((m>0)?m:0), stdout);
            fflush(stdout);
            xSemaphoreGive(s_mutex);
        } else {
            fwrite(warn, 1, (size_t)((m>0)?m:0), stdout);
            fflush(stdout);
        }
        return;
    }

    // Add timestamp to console output
    uint64_t t_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
    char timestamp_buf[32];
    formatTimestampForConsole(timestamp_buf, sizeof(timestamp_buf), t_ms);

    char line[768];
    int n = 0;

    // Add timestamp first
    n += snprintf(line, sizeof(line), "%s", timestamp_buf);

    // Add tag
    if (tag && *tag) n += snprintf(line + n, (n<0?0:sizeof(line)-n), "[%s] ", tag);

    // Add formatted message
    va_list ap; va_start(ap, fmt);
    n += vsnprintf(line + n, (n<0?0:sizeof(line)-n), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n >= (int)sizeof(line)-1) { line[sizeof(line)-2] = '\n'; line[sizeof(line)-1] = '\0'; }
    else if (n == 0 || line[n-1] != '\n') { line[n++] = '\n'; line[n] = '\0'; }

    if (g_logger && g_logger->ring_) {
        g_logger->enqueue(line, (size_t)n);
    } else if (s_mutex) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        fwrite(line, 1, n, stdout);
        fflush(stdout);
        xSemaphoreGive(s_mutex);
    } else {
        fwrite(line, 1, n, stdout);
        fflush(stdout);
    }
}

void Logger::vlogf(const char* tag, const char* fmt, va_list ap) {
    // Format the message
    char line[768];
    int n = vsnprintf(line, sizeof(line), fmt, ap);
    if (n < 0) return;
    if (n >= (int)sizeof(line)) {
        line[sizeof(line)-1] = '\0';
        n = sizeof(line)-1;
    }

    // Remove the trailing newline if present (the ReportingEngine handles it)
    if (n > 0 && line[n-1] == '\n') {
        line[n-1] = '\0';
    }

    // CRITICAL: Prevent infinite recursion loop between LoggingSystem and ReportingEngine
    static thread_local bool in_logf_processing = false;
    if (in_logf_processing) {
        return; // Block recursive calls to prevent stack overflow and heap corruption
    }
    in_logf_processing = true;

    // Forward ONLY to the ReportingEngine - the ReportingEngine handles verbosity and decides where to write
    if (g_logger && g_logger->reporting_engine_) {
        // Capture the exact timestamp at the moment of enqueueing (not during writing)
        uint64_t t_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

        // OPTIMIZATION: Use PSRAM strings instead of std::string to avoid Internal RAM allocations
        // Each LOG_INFOF previously created 3 std::string temporaries (~300 bytes Internal RAM)
        g_logger->reporting_engine_->reportLogMessage(
            tag ? PSRAMUtils::createPSRAMString(tag) : PSRAMUtils::createPSRAMString("LOG"),
            PSRAMUtils::createPSRAMString("INFO"), // LOG_INFOF always assumes INFO level
            PSRAMUtils::createPSRAMString(line),
            t_ms
        );
    } else {
    }
    // Direct console writing removed - everything handled by the ReportingEngine

    in_logf_processing = false;
}

void Logger::log_json_block(const char* tag, const char* json) {
    if (!json) json = "{}";
    Logger::logf(tag, "---JSON---\n%s\n---END JSON---", json);
}

// ======================= ESP_LOG redirection =======================
void Logger::setupESPLogRedirect() {
    esp_log_set_vprintf(&Logger::espLogVprintf);
    Logger::logf("Logger", "ESP_LOG redirected to Logger");
}

int Logger::espLogVprintf(const char* fmt, va_list args) {
    char buf[512];
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    if (len <= 0) return 0;

    // Remove trailing newline if present (logf adds it anyway)
    if (buf[len-1] == '\n') buf[len-1] = '\0';

    // Lightweight parsing: "E (ts) TAG: msg"
    const char* tag = "ESP";

    const char* after_paren = strstr(buf, ") ");
    const char* colon = after_paren ? strstr(after_paren+2, ": ") : nullptr;
    if (after_paren && colon && colon > after_paren+2) {
        // Tag between ") " and ": " - use PSRAM to save internal RAM
        static char* tagbuf = nullptr;
        const size_t TAGBUF_SIZE = 64;
        size_t tlen = (size_t)(colon - (after_paren+2));
        if (!tagbuf) {
            tagbuf = (char*)heap_caps_malloc(TAGBUF_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!tagbuf) {
                tag = "PSRAM_ERR"; // Fallback if no PSRAM
                goto use_fallback_tag;
            }
        }
        if (tlen >= TAGBUF_SIZE) tlen = TAGBUF_SIZE-1;
        memcpy(tagbuf, after_paren+2, tlen);
        tagbuf[tlen] = '\0';
        tag = tagbuf;
        use_fallback_tag:

        // Safe path: avoid std::string and heap allocations
        Logger::logf(tag, "%s", colon + 2);
    } else {
        // Safe path: avoid std::string
        Logger::logf(tag, "%s", buf);
    }
    return len;
}
