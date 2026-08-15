#pragma once
#include <string>
#include <mutex>
#include <queue>
#include "../core/psram_allocator.h"
#include "../core/task_config.h"
extern "C" {
  #include "esp_tls.h"
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "freertos/queue.h"
  #include "freertos/semphr.h"
}

struct EmailConfig {
    psram_string host;
    int port = 465;        // implicit TLS
    bool tls = true;
    psram_string username;
    psram_string password;
    psram_string from;
    psram_string to;
    psram_string subject;
    int timeout_ms = 5000;

    // Constructor with PSRAM-safe defaults
    EmailConfig() : subject(PSRAMUtils::createPSRAMString("ICS Alert")) {}
};

// Email event structure for queue-based processing
struct EmailEvent {
    EmailConfig config;  // Recipient-specific configuration
    psram_string payload;
    bool is_threat_alert;
    uint32_t timestamp_ms;
    uint32_t event_id;

    EmailEvent(const EmailConfig& cfg, const psram_string& data, bool threat = false)
        : config(cfg), payload(data), is_threat_alert(threat), timestamp_ms(0), event_id(0) {}
};

// Structure to pass data to email sending task (deprecated - use queue system)
struct EmailTaskData {
    EmailConfig config;
    psram_string payload;
    bool is_threat_alert;

    EmailTaskData(const EmailConfig& cfg, const psram_string& data, bool threat = false)
        : config(cfg), payload(data), is_threat_alert(threat) {}

    // No custom allocator - let PSRAM allocator handle everything consistently
};

class EmailReporter {
public:
    bool init(const EmailConfig& c);
    bool send(const char* payload);
    bool sendFormattedThreatAlert(const char* json_payload);

    // Queue-based asynchronous sending methods (NEW - recommended)
    bool enqueueEmail(const EmailConfig& config, const char* payload);
    bool enqueueThreatAlert(const EmailConfig& config, const char* json_payload);
    bool startEmailWorker();
    void stopEmailWorker();

    // Legacy: Direct task-based async methods (DEPRECATED - may cause crashes)
    bool sendAsync(const char* payload);
    bool sendFormattedThreatAlertAsync(const char* json_payload);

private:
    EmailConfig cfg_;
    std::mutex mtx_;

    // Email queue system
    static constexpr size_t EMAIL_QUEUE_SIZE = 10;
    static QueueHandle_t email_queue_;
    static TaskHandle_t email_worker_task_;
    static EmailReporter* instance_;
    static bool worker_running_;
    static SemaphoreHandle_t queue_mutex_;
    static uint32_t next_event_id_;

    // Queue-based email worker (static function for FreeRTOS task)
    static void emailWorkerTask(void* parameters);

    // Task-based email sending (deprecated static function for FreeRTOS task)
    static void emailSenderTask(void* parameters);

    // Synchronous email sending methods (used by tasks)
    bool smtp_send_mbedtls(const char* payload);  // New mbedTLS-based implementation
    bool smtp_send_tls(const char* payload);      // Legacy esp_tls implementation
    bool smtp_send_starttls(const char* payload);
    bool smtp_continue_with_tls(esp_tls_t* tls, const char* body);
    bool smtp_send_with_attachment(const char* body, const char* attachment_content, const char* attachment_name);
    // MIME body only (no attachment), base64-encoded with proper headers
    bool smtp_send_mime_body(const char* body, const char* content_type);
    // New: fully compliant MIME multipart/mixed with base64 parts and CRLF/dot handling
    bool smtp_send_mime_with_attachment(const char* body, const char* attachment_content, const char* attachment_name);
    std::string formatThreatEmailFromJSON(const char* json_payload);
    static char* b64(const char* s);
};
