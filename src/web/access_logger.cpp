#include "access_logger.h"
#include "../core/logging_system.h"
#include "../core/async_storage_engine.h"
#include <mutex>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <algorithm>

extern "C" {
    #include "esp_timer.h"
    #include "esp_heap_caps.h"
    #include "cJSON.h"
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <errno.h>
}

// Forward declarations (implemented in web_server.cpp)
extern void webserver_httpd_monitor_note_request(httpd_req_t* req);
extern void webserver_httpd_monitor_note_response(httpd_req_t* req, int status_code, const char* auth_status);

static inline void copy_to_buffer(char* dest, size_t dest_size, const char* src) {
    if (!dest || dest_size == 0) {
        return;
    }
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t len = strnlen(src, dest_size - 1);
    memcpy(dest, src, len);
    dest[len] = '\0';
}

AccessLogger::AccessLogger() : detailed_logging_(true), head_(0), count_(0) {
    // Allocate ring buffer in PSRAM (one-time allocation, never freed)
    recent_entries_ = static_cast<AccessLogEntry*>(
        heap_caps_malloc(MAX_MEMORY_ENTRIES * sizeof(AccessLogEntry), MALLOC_CAP_SPIRAM)
    );

    if (!recent_entries_) {
        LOG_ERROR("ACCESS_LOG", "FATAL: Failed to allocate PSRAM for access log ring buffer!");
        // Fall back to nullptr - will crash if used, but better than corrupting RAM
        return;
    }

    // Initialize all entries
    for (size_t i = 0; i < MAX_MEMORY_ENTRIES; i++) {
        new (&recent_entries_[i]) AccessLogEntry();  // Placement new to call constructor
    }

    LOG_INFOF("ACCESS_LOG", "✅ Access log ring buffer allocated in PSRAM: %u bytes (%u entries)",
              (unsigned)(MAX_MEMORY_ENTRIES * sizeof(AccessLogEntry)),
              (unsigned)MAX_MEMORY_ENTRIES);
}

AccessLogger& AccessLogger::getInstance() {
    static AccessLogger instance;
    return instance;
}

void AccessLogger::logRequest(httpd_req_t* req) {
    logRequest(req, psram_string());
}

void AccessLogger::logRequest(httpd_req_t* req, const char* payload) {
    if (!payload) {
        logRequest(req, psram_string());
        return;
    }
    logRequest(req, PSRAMUtils::createPSRAMString(payload));
}

void AccessLogger::logRequest(httpd_req_t* req, const psram_string& payload) {
    if (!req) return;

    webserver_httpd_monitor_note_request(req);

    const bool full_logging = useFullLogging(req);

    // Get next slot in ring buffer
    std::lock_guard<std::mutex> lock(entries_mutex_);
    AccessLogEntry& entry = recent_entries_[head_];
    entry = AccessLogEntry();

    // Fill entry with fixed-size buffers (zero heap allocations!)
    getCurrentTimestamp(entry.timestamp, sizeof(entry.timestamp));
    extractClientIP(req, entry.client_ip, sizeof(entry.client_ip));

    const char* method_str = http_method_str((http_method)req->method);
    copy_to_buffer(entry.method, sizeof(entry.method), method_str);

    entry.response_code = 0;
    copy_to_buffer(entry.auth_status, sizeof(entry.auth_status), "PENDING");
    entry.is_https = (req->sess_ctx != nullptr);
    entry.content_length = req->content_len;
    entry.valid = true;
    entry.kind = full_logging ? AccessLogKind::FULL : AccessLogKind::LITE;

    if (full_logging) {
        const char* uri_src = req->uri;
        copy_to_buffer(entry.uri, sizeof(entry.uri), uri_src);

        extractUserAgent(req, entry.user_agent, sizeof(entry.user_agent));

        const size_t max_payload = sizeof(entry.payload) - 1;
        size_t payload_len = std::min(payload.size(), max_payload);
        if (payload_len > 0) {
            memcpy(entry.payload, payload.data(), payload_len);
        }
        entry.payload[payload_len] = '\0';
        if (payload.size() > max_payload) {
            constexpr char ellipsis[] = "...";
            constexpr size_t ellipsis_len = sizeof(ellipsis) - 1;
            const size_t copy_pos = (max_payload > ellipsis_len) ? (max_payload - ellipsis_len) : 0;
            memcpy(entry.payload + copy_pos, ellipsis, ellipsis_len);
            entry.payload[max_payload] = '\0';
        }
    } else {
        fillLiteEntry(entry, req);
    }

    // Normalized URI without query string (used for logging + metrics)
    char normalized_uri[256];
    copy_to_buffer(normalized_uri, sizeof(normalized_uri), entry.uri);
    char* query_pos = strchr(normalized_uri, '?');
    if (query_pos) {
        *query_pos = '\0';
    }

    if (full_logging) {
        LOG_INFOF("ACCESS", "Request: %s %s://<device>%s from %s [%s]",
                  entry.method,
                  entry.is_https ? "https" : "http",
                  normalized_uri,
                  entry.client_ip,
                  entry.user_agent);
        if (detailed_logging_) {
            writeToLogFile(entry);
        }
    } else {
        LOG_INFOF("ACCESS", "API request: %s %s from %s",
                  entry.method,
                  normalized_uri,
                  entry.client_ip);
        recordApiRequest(entry.method, normalized_uri);
    }

    // Advance ring buffer
    head_ = (head_ + 1) % MAX_MEMORY_ENTRIES;
    if (count_ < MAX_MEMORY_ENTRIES) {
        count_++;
    }
}

void AccessLogger::logResponse(httpd_req_t* req, int response_code) {
    logResponse(req, response_code, "NO_AUTH");
}

void AccessLogger::logResponse(httpd_req_t* req, int response_code, const char* auth_status) {
    if (!req) return;

    webserver_httpd_monitor_note_response(req, response_code, auth_status);

    char client_ip[64];
    extractClientIP(req, client_ip, sizeof(client_ip));

    const char* uri = req->uri;

    std::lock_guard<std::mutex> lock(entries_mutex_);

    // Search backwards in ring buffer for matching pending request
    for (size_t i = 0; i < count_; i++) {
        // Calculate index: start from most recent (head_-1) and go backwards
        size_t idx = (head_ + MAX_MEMORY_ENTRIES - 1 - i) % MAX_MEMORY_ENTRIES;
        AccessLogEntry& entry = recent_entries_[idx];

        if (!entry.valid) continue;

        if (strcmp(entry.client_ip, client_ip) == 0 &&
            strcmp(entry.uri, uri) == 0 &&
            entry.response_code == 0) {

            entry.response_code = response_code;
            copy_to_buffer(entry.auth_status, sizeof(entry.auth_status), auth_status ? auth_status : "UNKNOWN");

            if (entry.kind == AccessLogKind::FULL) {
                LOG_INFOF("ACCESS", "Response: %s %s -> %d %s from %s",
                          entry.method,
                          uri,
                          response_code,
                          entry.auth_status,
                          client_ip);
            } else {
                LOG_INFOF("ACCESS", "API response: %s %s -> %d (%s) from %s",
                          entry.method,
                          entry.uri,
                          response_code,
                          entry.auth_status,
                          client_ip);
                recordApiResponse(entry);
            }

            if (response_code == 401 || strcmp(entry.auth_status, "FAILED") == 0) {
                LOG_WARNINGF("SECURITY", "Authentication failure from %s to %s", client_ip, uri);
            }

            break;
        }
    }
}

void AccessLogger::logResponse(httpd_req_t* req, int response_code, const psram_string& auth_status) {
    logResponse(req, response_code, auth_status.c_str());
}

// MEMORY FIX: Returns PSRAM-allocated char* that caller MUST free with heap_caps_free()
// This eliminates the psram_string metadata overhead in Internal RAM
char* AccessLogger::getRecentLogsJSON(int limit) {
    std::lock_guard<std::mutex> lock(entries_mutex_);

    cJSON* root = cJSON_CreateArray();

    size_t entries_to_process = (limit < (int)count_) ? limit : count_;

    // Iterate backwards through ring buffer (most recent first)
    for (size_t i = 0; i < entries_to_process; i++) {
        size_t idx = (head_ + MAX_MEMORY_ENTRIES - 1 - i) % MAX_MEMORY_ENTRIES;
        const AccessLogEntry& e = recent_entries_[idx];

        if (!e.valid) continue;

        cJSON* entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "timestamp", e.timestamp);
        cJSON_AddStringToObject(entry, "client_ip", e.client_ip);
        cJSON_AddStringToObject(entry, "method", e.method);
        cJSON_AddStringToObject(entry, "uri", e.uri);
        cJSON_AddStringToObject(entry, "user_agent", e.user_agent);
        cJSON_AddStringToObject(entry, "payload", e.payload);
        cJSON_AddNumberToObject(entry, "response_code", e.response_code);
        cJSON_AddStringToObject(entry, "auth_status", e.auth_status);
        cJSON_AddBoolToObject(entry, "is_https", e.is_https);
        cJSON_AddNumberToObject(entry, "content_length", (double)e.content_length);
        cJSON_AddStringToObject(entry, "kind", (e.kind == AccessLogKind::FULL) ? "full" : "lite");
        cJSON_AddItemToArray(root, entry);
    }

    // cJSON_PrintUnformatted allocates in PSRAM (hooks configured at startup)
    char* json_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (json_string) {
        return json_string;
    }

    static const char empty_json[] = "[]";
    char* fallback = static_cast<char*>(heap_caps_malloc(sizeof(empty_json), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (fallback) {
        memcpy(fallback, empty_json, sizeof(empty_json));
    }
    return fallback;
}

char* AccessLogger::getApiMetricsJSON() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return nullptr;
    }

    cJSON* totals = cJSON_CreateObject();
    cJSON_AddNumberToObject(totals, "requests", (double)api_metrics_.total_requests);
    cJSON_AddNumberToObject(totals, "responses", (double)api_metrics_.total_responses);
    cJSON_AddNumberToObject(totals, "auth_failures", (double)api_metrics_.auth_failures);
    cJSON_AddItemToObject(root, "totals", totals);

    cJSON* methods = cJSON_CreateObject();
    cJSON_AddNumberToObject(methods, "GET", (double)api_metrics_.method_get);
    cJSON_AddNumberToObject(methods, "POST", (double)api_metrics_.method_post);
    cJSON_AddNumberToObject(methods, "PUT", (double)api_metrics_.method_put);
    cJSON_AddNumberToObject(methods, "DELETE", (double)api_metrics_.method_delete);
    cJSON_AddNumberToObject(methods, "OTHER", (double)api_metrics_.method_other);
    cJSON_AddItemToObject(root, "methods", methods);

    cJSON* statuses = cJSON_CreateObject();
    cJSON_AddNumberToObject(statuses, "2xx", (double)api_metrics_.status_2xx);
    cJSON_AddNumberToObject(statuses, "3xx", (double)api_metrics_.status_3xx);
    cJSON_AddNumberToObject(statuses, "4xx", (double)api_metrics_.status_4xx);
    cJSON_AddNumberToObject(statuses, "5xx", (double)api_metrics_.status_5xx);
    cJSON_AddNumberToObject(statuses, "other", (double)api_metrics_.status_other);
    cJSON_AddItemToObject(root, "statuses", statuses);

    cJSON* last_error = cJSON_CreateObject();
    cJSON_AddStringToObject(last_error, "uri", api_metrics_.last_error_uri.c_str());
    cJSON_AddNumberToObject(last_error, "code", (double)api_metrics_.last_error_code);
    cJSON_AddItemToObject(root, "last_error", last_error);

    char* json_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json_string) {
        return json_string;
    }

    static const char fallback_json[] = "{\"totals\":{\"requests\":0,\"responses\":0,\"auth_failures\":0},\"methods\":{\"GET\":0,\"POST\":0,\"PUT\":0,\"DELETE\":0,\"OTHER\":0},\"statuses\":{\"2xx\":0,\"3xx\":0,\"4xx\":0,\"5xx\":0,\"other\":0},\"last_error\":{\"uri\":\"\",\"code\":0}}";
    char* fallback = static_cast<char*>(heap_caps_malloc(sizeof(fallback_json), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (fallback) {
        memcpy(fallback, fallback_json, sizeof(fallback_json));
    }
    return fallback;
}

void AccessLogger::extractClientIP(httpd_req_t* req, char* out, size_t out_size) {
    if (!req || !out || out_size == 0) {
        if (out && out_size > 0) out[0] = '\0';
        return;
    }

    char header_val[64] = {0};
    if (httpd_req_get_hdr_value_str(req, "X-Forwarded-For", header_val, sizeof(header_val)) == ESP_OK) {
        // Take first IP before comma
        char* comma = strchr(header_val, ',');
        if (comma) *comma = '\0';
        copy_to_buffer(out, out_size, header_val);
        return;
    }

    if (httpd_req_get_hdr_value_str(req, "X-Real-IP", header_val, sizeof(header_val)) == ESP_OK) {
        copy_to_buffer(out, out_size, header_val);
        return;
    }

    int sockfd = httpd_req_to_sockfd(req);
    if (sockfd >= 0) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        if (getpeername(sockfd, (struct sockaddr*)&client_addr, &addr_len) == 0) {
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN)) {
                if (strcmp(ip_str, "0.0.0.0") != 0) {
                    copy_to_buffer(out, out_size, ip_str);
                    return;
                }
            }
        }
    }

        copy_to_buffer(out, out_size, "client_ip_unknown");
}

void AccessLogger::extractUserAgent(httpd_req_t* req, char* out, size_t out_size) {
    if (!out || out_size == 0) return;

    if (!req) {
        out[0] = '\0';
        return;
    }

    char user_agent[256] = {0};
    if (httpd_req_get_hdr_value_str(req, "User-Agent", user_agent, sizeof(user_agent)) == ESP_OK) {
        copy_to_buffer(out, out_size, user_agent);
    } else {
        out[0] = '\0';
    }
}

void AccessLogger::getCurrentTimestamp(char* out, size_t out_size) {
    if (!out || out_size == 0) return;

    uint64_t time_us = esp_timer_get_time();
    time_t seconds = static_cast<time_t>(time_us / 1000000ULL);
    uint32_t microseconds = static_cast<uint32_t>(time_us % 1000000ULL);

    struct tm tm_info;
    localtime_r(&seconds, &tm_info);

    int len = snprintf(out, out_size, "%04d-%02d-%02d %02d:%02d:%02d.%06lu",
                       tm_info.tm_year + 1900,
                       tm_info.tm_mon + 1,
                       tm_info.tm_mday,
                       tm_info.tm_hour,
                       tm_info.tm_min,
                       tm_info.tm_sec,
                       static_cast<unsigned long>(microseconds));
    if (len < 0) {
        copy_to_buffer(out, out_size, "1970-01-01 00:00:00.000000");
    }
}

void AccessLogger::writeToLogFile(const AccessLogEntry& entry) {
    // Build log line in stack buffer (no heap allocations!)
    char line[1024];
    int len = snprintf(line, sizeof(line), "%s|%s|%s|%s|%d|%s|%s|%s|%u\n",
                       entry.timestamp,
                       entry.client_ip,
                       entry.method,
                       entry.uri,
                       entry.response_code,
                       entry.auth_status,
                       entry.is_https ? "HTTPS" : "HTTP",
                       entry.user_agent,
                       static_cast<unsigned>(entry.content_length));

    if (len > 0 && len < (int)sizeof(line)) {
        const char* log_path = "/data/logs/access.log";
        AsyncStorage::Global::appendFileRaw(log_path, line, len);
    }
}

bool AccessLogger::useFullLogging(httpd_req_t* req) const {
    if (!req) {
        return true;
    }

    const char* uri = req->uri;
    if (uri[0] == '\0') {
        return true;
    }

    if (strcmp(uri, "/") == 0) {
        return true;
    }

    if (strncmp(uri, "/api/logs", 9) == 0) {
        return true;
    }

    if (strncmp(uri, "/web/", 5) == 0 || strncmp(uri, "/ui/", 4) == 0) {
        return true;
    }

    char accept_header[64];
    if (httpd_req_get_hdr_value_str(req, "Accept", accept_header, sizeof(accept_header)) == ESP_OK) {
        if (strstr(accept_header, "text/html") != nullptr) {
            return true;
        }
    }

    if (strncmp(uri, "/api/", 5) != 0) {
        return true;
    }

    return false;
}

void AccessLogger::fillLiteEntry(AccessLogEntry& entry, httpd_req_t* req) {
    const char* uri_src = req ? req->uri : "";
    copy_to_buffer(entry.uri, sizeof(entry.uri), uri_src);

    entry.user_agent[0] = '\0';
    entry.payload[0] = '\0';
    entry.is_https = (req && req->sess_ctx != nullptr);
    entry.content_length = req ? req->content_len : 0;
}

void AccessLogger::recordApiRequest(const char* method, const char* /*uri*/) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    ApiMetrics& m = api_metrics_;
    m.total_requests++;

    if (!method) {
        m.method_other++;
        return;
    }

    if (strcmp(method, "GET") == 0) {
        m.method_get++;
    } else if (strcmp(method, "POST") == 0) {
        m.method_post++;
    } else if (strcmp(method, "PUT") == 0) {
        m.method_put++;
    } else if (strcmp(method, "DELETE") == 0) {
        m.method_delete++;
    } else {
        m.method_other++;
    }
}

void AccessLogger::recordApiResponse(const AccessLogEntry& entry) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    ApiMetrics& m = api_metrics_;
    m.total_responses++;

    char normalized_uri[sizeof(entry.uri)];
    copy_to_buffer(normalized_uri, sizeof(normalized_uri), entry.uri);
    char* query_pos = strchr(normalized_uri, '?');
    if (query_pos) {
        *query_pos = '\0';
    }

    psram_string normalized(entry.uri);
    size_t qpos = normalized.find('?');
    if (qpos != psram_string::npos) {
        normalized.resize(qpos);
    }

    const int code = entry.response_code;
    if (code >= 200 && code < 300) {
        m.status_2xx++;
    } else if (code >= 300 && code < 400) {
        m.status_3xx++;
    } else if (code >= 400 && code < 500) {
        m.status_4xx++;
        m.last_error_uri = normalized;
        m.last_error_code = code;
    } else if (code >= 500 && code < 600) {
        m.status_5xx++;
        m.last_error_uri = normalized;
        m.last_error_code = code;
    } else {
        m.status_other++;
    }

    if (code == 401 || strcmp(entry.auth_status, "FAILED") == 0) {
        m.auth_failures++;
    }
}
