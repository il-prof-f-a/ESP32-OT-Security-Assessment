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
  #include "freertos/ringbuf.h"   // ← ring buffer per logging asincrono
  #include "freertos/semphr.h"
  #include "freertos/queue.h"
}

/**
 * Log entry "alto livello" (manteniamo la struct per compatibilità API),
 * ma il path consigliato è usare logf()/log_json_block() che formattano
 * una riga completa ed effettuano UNA sola write asincrona.
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
 * Logger asincrono:
 * - init_async(ring_bytes) crea un writer task dedicato + ring buffer.
 * - logf()/write_raw() accodano messaggi completi (una riga = una write).
 * - log_json_block() stampa blocchi JSON atomici (BEGIN/END in una sola chiamata).
 * - init_sync() resta disponibile (fallback con mutex).
 *
 * NOTE:
 *   - Chiama init_async() una volta all’avvio, prima di loggare.
 *   - Le macro LOG_*F qui sotto usano logf() (nessun buffer fisso 256/1024).
 */
class Logger {
public:
    Logger();
    ~Logger();

    // Config legacy (no-op qui: teniamo la firma per compatibilità)
    void updateConfig(const DebugConfig& cfg) { (void)cfg; }

    // API "alto livello" compatibile col tuo codice esistente
    void log(const char* tag, LogLevel lvl, const std::string& msg);

    // Lifecycle
    void start();     // alias di init_async() se vuoi usarlo istanziando g_logger
    void stop();      // ferma il writer task e chiude il ring

    // Collega il ReportingEngine se ti serve (non usato dal core del logger)
    void setReportingEngine(ReportingEngine* reporting_engine) { reporting_engine_ = reporting_engine; }

    // Redirezione ESP_LOGx → Logger (opzionale)
    static int  espLogVprintf(const char* fmt, va_list args);
    void        setupESPLogRedirect();

    // Modalità ASINCRONA (consigliata)
    static bool init_async(size_t ring_bytes = 16 * 1024); // crea ring + writer task
    static void shutdown();                                // ferma il writer e libera il ring

    // Modalità SINCRONA (fallback, usa mutex intorno alla write)
    static bool init_sync();

    // Logging formattato: UNA riga = UNA write (newline auto-se aggiunge se manca)
    static void logf(const char* tag, const char* fmt, ...);
    static void vlogf(const char* tag, const char* fmt, va_list ap);

    // Buffer già pronto (JSON o altro)
    static void write_raw(const char* data, size_t len);

    // Blocco JSON atomico (BEGIN/END + payload in un colpo solo)
    static void log_json_block(const char* tag, const char* json);

    static SemaphoreHandle_t s_mutex;

private:
    // Worker del writer asincrono
    static void  writerTaskThunk(void* arg);
           void  writerTaskLoop();

    // Enqueue nel ring (usata dalle static tramite g_logger)
    void enqueue(const char* buf, size_t len);

    // Stato/risorse
    RingbufHandle_t ring_        = nullptr;
    TaskHandle_t    writer_task_ = nullptr;
    std::atomic<bool> running_{false};
    ReportingEngine* reporting_engine_ = nullptr;

    // Dimensioni/parametri
    static constexpr size_t DEFAULT_RING_BYTES = 16 * 1024;
    static constexpr size_t WRITER_STACK_SIZE  = 4096;    // adatta se necessario
    static constexpr UBaseType_t WRITER_PRIO   = tskIDLE_PRIORITY + 3;
    static constexpr BaseType_t  WRITER_CORE   = 1;       // pin su core 1 (ESP32)
};

// Puntatore globale (come nel tuo codice)
extern Logger* g_logger;

/* ===================== Convenienze / Macro ===================== */

/**
 * Macro legacy a livello messaggio (accodano in asincrono).
 * Se g_logger è nullo, non fanno nulla.
 */
// Percorso sicuro (no allocazioni heap): usa buffer su stack + ring buffer
// Evita std::string in condizioni di DRAM bassa che potrebbero generare eccezioni
#define LOG_DEBUG(tag, msg)    do { Logger::logf((tag), "%s", (msg)); } while(0)
#define LOG_INFO(tag, msg)     do { Logger::logf((tag), "%s", (msg)); } while(0)
#define LOG_WARNING(tag, msg)  do { Logger::logf((tag), "%s", (msg)); } while(0)
#define LOG_ERROR(tag, msg)    do { Logger::logf((tag), "%s", (msg)); } while(0)

/**
 * Macro formattate — usano logf() (niente buffer fissi su stack).
 * Garantiscono “una riga = una write” e newline finale.
 */
#define LOG_DEBUGF(tag, fmt, ...)    do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)
#define LOG_INFOF(tag, fmt, ...)     do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)
#define LOG_WARNINGF(tag, fmt, ...)  do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)
#define LOG_ERRORF(tag, fmt, ...)    do { Logger::logf((tag), (fmt), ##__VA_ARGS__); } while(0)

/**
 * Macro per blocchi JSON atomici (BEGIN/END + payload in una sola chiamata).
 */
#define LOG_JSON_BLOCK(tag, json_cstr)  do { Logger::log_json_block((tag), (json_cstr)); } while(0)
