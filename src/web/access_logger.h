#pragma once
#include "../core/psram_allocator.h"
#include <cstdint>
#include <mutex>

extern "C" {
    #include "esp_http_server.h"
}

// Fixed-size entry with char arrays to avoid dynamic allocations
enum class AccessLogKind : uint8_t {
    FULL = 0,   // full logging (page requests)
    LITE = 1    // compact logging (API)
};

struct AccessLogEntry {
    char timestamp[32];      // "YYYY-MM-DD HH:MM:SS.uuuuuu"
    char client_ip[64];      // IP address or "client_ip_unknown"
    char method[8];          // "GET", "POST", "PUT", "DELETE"
    char uri[256];           // Request URI (full for FULL, normalized for LITE)
    char user_agent[128];    // User-Agent header (only set for FULL)
    char payload[128];       // Request payload (only for FULL, truncated)
    int response_code;
    char auth_status[16];    // "SUCCESS", "FAILED", "NO_AUTH", "PENDING"
    bool is_https;
    size_t content_length;
    bool valid;              // Is this entry valid/used?
    AccessLogKind kind;
    int sockfd;

    AccessLogEntry() : response_code(0), is_https(false), content_length(0), valid(false), kind(AccessLogKind::FULL), sockfd(-1) {
        timestamp[0] = '\0';
        client_ip[0] = '\0';
        method[0] = '\0';
        uri[0] = '\0';
        user_agent[0] = '\0';
        payload[0] = '\0';
        auth_status[0] = '\0';
    }
};

class AccessLogger {
public:
    static AccessLogger& getInstance();

    void logRequest(httpd_req_t* req);
    void logRequest(httpd_req_t* req, const psram_string& payload);
    void logRequest(httpd_req_t* req, const char* payload);

    void logResponse(httpd_req_t* req, int response_code);
    void logResponse(httpd_req_t* req, int response_code, const psram_string& auth_status);
    void logResponse(httpd_req_t* req, int response_code, const char* auth_status);

    // MEMORY FIX: Returns PSRAM-allocated JSON string that MUST be freed with heap_caps_free()
    char* getRecentLogsJSON(int limit = 100);
    char* getApiMetricsJSON();

    void setDetailedLogging(bool enabled) { detailed_logging_ = enabled; }

private:
    AccessLogger();
    bool detailed_logging_;

    void extractClientIP(httpd_req_t* req, char* out, size_t out_size);
    void extractUserAgent(httpd_req_t* req, char* out, size_t out_size);
    void getCurrentTimestamp(char* out, size_t out_size);
    void writeToLogFile(const AccessLogEntry& entry);
    bool useFullLogging(httpd_req_t* req) const;
    void fillLiteEntry(AccessLogEntry& entry, httpd_req_t* req);
    void recordApiRequest(const char* method, const char* uri);
    void recordApiResponse(const AccessLogEntry& entry);

    // Static ring buffer allocated in PSRAM
    static const size_t MAX_MEMORY_ENTRIES = 200;
    AccessLogEntry* recent_entries_;  // Pointer to PSRAM-allocated array
    size_t head_;   // Next write position
    size_t count_;  // Number of valid entries (0..MAX_MEMORY_ENTRIES)
    std::mutex entries_mutex_;

    struct ApiMetrics {
        uint32_t total_requests = 0;
        uint32_t total_responses = 0;
        uint32_t method_get = 0;
        uint32_t method_post = 0;
        uint32_t method_put = 0;
        uint32_t method_delete = 0;
        uint32_t method_other = 0;
        uint32_t status_2xx = 0;
        uint32_t status_3xx = 0;
        uint32_t status_4xx = 0;
        uint32_t status_5xx = 0;
        uint32_t status_other = 0;
        uint32_t auth_failures = 0;
        psram_string last_error_uri;
        int last_error_code = 0;
    } api_metrics_;

    std::mutex metrics_mutex_;
};
