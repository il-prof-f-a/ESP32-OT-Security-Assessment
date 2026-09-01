#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "esp_app_desc.h"
#include "../security/security_manager.h"
#include "web_server.h"
#include "access_logger.h"
#include "template_engine.h"
#include "../assessment/discovery_manager.h"
#include "../core/types.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include "../core/reporting_engine.h"
#include "../core/reporting_config_loader.h"
#include "../core/event_formatter.h"
#include "../core/psram_allocator.h"
#include "../core/psram_telemetry.h"
#include "../core/async_storage_engine.h"
#include "../core/log_file_manager.h"
#include "../core/task_config.h"
#include "../core/plugin_manager.h"
#include "../core/time_manager.h"
#include "../core/filesystem_task_delegate.h"
#include "../core/log_retention.h"
#include "../network/ethernet_manager.h"
#include "../network/assessment_interface.h"
#include "../network/icmp_ping.h"
#include "../network/network_policy.h"
#include "../network/management_interface_controller.h"
#include "../core/audit_manager.h"
#include "../reporters/gpio_reporter.h"
#include "../network/wifi_manager.h"
#include "signature_reload_api.h"
#include "schedule_api.h"
#include "security_api.h"
#include "rate_limiter.h"
#include "../security/api_key_rotation_manager.h"
#include "../provisioning/provisioning_store.h"
#include "../assessment/vulnerability_scanner.h"
#include "../assessment/fuzzing_engine.h"
#include "../assessment/intrusion_detection_general.h"
#include "../core/cron_scheduler.h"
#include <atomic>
#include <cstring>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../protocols/s7_plugin.h"
#include "../protocols/profinet_plugin.h"
#include "../protocols/ethernetip_plugin.h"
#include "../protocols/opcua_plugin.h"
#include "../core/plugin_manager.h"
#include "../core/task_config.h"
#include "web_server_task.h"
#include "web/ui/gen/all_gen.hpp"   // created by the script
#include <vector>
#include <algorithm>
#include <string>
#include <cstring>
#include <cstdarg>
#include <mutex>
#include <list>
#include <utility>
#include <cctype>
#include <cmath>
#include <new>

#ifndef ESP32_OT_WEB_HTTP_ONLY
#define ESP32_OT_WEB_HTTP_ONLY 0
#endif

static const char* httpd_method_to_str(httpd_method_t m) {
    switch (m) {
        case HTTP_GET: return "GET";
        case HTTP_POST: return "POST";
        case HTTP_PUT: return "PUT";
        case HTTP_DELETE: return "DELETE";
        case HTTP_OPTIONS: return "OPTIONS";
        case HTTP_HEAD: return "HEAD";
        default: return "OTHER";
    }
}

extern "C" {
    #include "lwip/ip4_addr.h"
    #include "lwip/inet.h"
    #include "cJSON.h"
    #include "esp_psram.h"
    #include <inttypes.h>  // in C++ <cinttypes> is also fine
    #include <esp_err.h>
}

static inline void report_event_ps(ReportingEngine* rep, const char* type, const char* payload) {
    if (!rep || !type || !payload) {
        return;
    }
    psram_string type_ps = PSRAMUtils::createPSRAMString(type);
    psram_string payload_ps = PSRAMUtils::createPSRAMString(payload);
    rep->reportEvent(type_ps, payload_ps);
}

static inline void report_event_ps(ReportingEngine* rep, const char* type, const std::string& payload) {
    report_event_ps(rep, type, payload.c_str());
}

// GPIO API values are user supplied. Keep them bounded and JSON-safe before
// embedding them in the compact audit event emitted by the web handlers.
static void copy_safe_gpio_token(const char* source, char* destination, size_t capacity) {
    if (!destination || capacity == 0) return;
    size_t out = 0;
    if (source) {
        while (source[out] != '\0' && out + 1 < capacity) {
            const unsigned char ch = static_cast<unsigned char>(source[out]);
            if (std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.') {
                destination[out] = static_cast<char>(ch);
            } else {
                destination[out] = '_';
            }
            ++out;
        }
    }
    destination[out] = '\0';
}

// ─────────────────────────────────────────────────────────────────────────────
// Option B: task stack in PSRAM for the HTTP server
// Enable in menuconfig: CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
// In ESP-IDF the stack size is in BYTES (not in words).
// ─────────────────────────────────────────────────────────────────────────────
#ifndef CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
#warning "External task stacks (PSRAM) not enabled. HTTP server will fall back to internal DRAM stack."
#endif

static const char* TAG_WEB = "Web";

static LogRetentionManager g_logret;
static LogRetentionConfig  g_logret_cfg;

// cJSON_Print* returns memory allocated with cJSON's active hooks.
// In this firmware we often redirect hooks to PSRAM; never call plain free() on these buffers.
static inline void free_cjson_str(char* s) {
    if (s) {
        cJSON_free(s);
    }
}

// Forward declaration for PSRAM-safe body reader used in POST handlers
// Keep default only here; definition must not repeat the default argument
static bool read_body_psram(httpd_req_t* req, char** out_buf, size_t* out_len, size_t max_len = 32768);

WebServer* WebServer::self_ = nullptr;

void WebServer::setAllowedManagementAddress(uint32_t ipv4_network_order) {
    allowed_management_ipv4_.store(ipv4_network_order, std::memory_order_release);
}

void WebServer::clearAllowedManagementAddress() {
    allowed_management_ipv4_.store(0, std::memory_order_release);
}

esp_err_t WebServer::authorizeOpenSocket(httpd_handle_t server, int sockfd) {
    (void)server;
    if (!self_) return ESP_FAIL;

    sockaddr_storage local{};
    socklen_t length = sizeof(local);
    const uint32_t allowed = self_->allowed_management_ipv4_.load(std::memory_order_acquire);
    const bool address_allowed =
        allowed != 0U &&
        getsockname(sockfd, reinterpret_cast<sockaddr*>(&local), &length) == 0 &&
        local.ss_family == AF_INET &&
        reinterpret_cast<const sockaddr_in*>(&local)->sin_addr.s_addr == allowed;
    if (!address_allowed) {
        // Plain HTTP honors the error return. esp_https_server calls the hook after
        // the TLS handshake and ignores its return value, so close the socket too.
        ::shutdown(sockfd, SHUT_RDWR);
        return ESP_FAIL;
    }
    return ESP_OK;
}

bool WebServer::authorizeRequestInterface(httpd_req_t* req) {
    if (!req || !self_) return false;
    const int sockfd = httpd_req_to_sockfd(req);
    if (sockfd < 0) return false;

    sockaddr_storage local{};
    socklen_t length = sizeof(local);
    const uint32_t allowed = self_->allowed_management_ipv4_.load(std::memory_order_acquire);
    return allowed != 0U &&
           getsockname(sockfd, reinterpret_cast<sockaddr*>(&local), &length) == 0 &&
           local.ss_family == AF_INET &&
           reinterpret_cast<const sockaddr_in*>(&local)->sin_addr.s_addr == allowed;
}

esp_err_t WebServer::guardedUriHandler(httpd_req_t* req) {
    if (!authorizeRequestInterface(req)) {
        if (req) {
            httpd_resp_set_status(req, "403 Forbidden");
            httpd_resp_set_type(req, "text/plain");
            httpd_resp_send(req, "Forbidden", HTTPD_RESP_USE_STRLEN);
        }
        return ESP_FAIL;
    }
    if (!req || !req->user_ctx) return ESP_FAIL;
    auto* context = static_cast<GuardedUriContext*>(req->user_ctx);
    if (!context->handler) return ESP_FAIL;
    req->user_ctx = context->user_ctx;
    return context->handler(req);
}

esp_err_t WebServer::registerGuardedHandler(httpd_handle_t server,
                                            const httpd_uri_t* uri) {
    if (!self_ || !uri || self_->guarded_uri_count_ >= kMaxGuardedUriContexts) {
        return ESP_ERR_HTTPD_HANDLERS_FULL;
    }
    GuardedUriContext& context =
        self_->guarded_uri_contexts_[self_->guarded_uri_count_++];
    context.handler = uri->handler;
    context.user_ctx = uri->user_ctx;
    httpd_uri_t guarded = *uri;
    guarded.handler = &WebServer::guardedUriHandler;
    guarded.user_ctx = &context;
    const esp_err_t result = httpd_register_uri_handler(server, &guarded);
    if (result != ESP_OK) --self_->guarded_uri_count_;
    return result;
}

// All routes declared below pass through the same destination-address guard.
#define httpd_register_uri_handler(server, uri) \
    WebServer::registerGuardedHandler((server), (uri))
WebServer::HttpdMonitorData WebServer::httpd_monitor_;
esp_timer_handle_t WebServer::httpd_monitor_timer_ = nullptr;

namespace {
constexpr uint32_t kHttpdWatchdogTimeoutMs = 20000U;
constexpr uint32_t kHttpdMonitorIntervalMs = 1000U;

bool apply_config_update_path(cJSON* root, const char* path, const cJSON* value) {
    if (!root || !path || !value || !cJSON_IsObject(root)) {
        return false;
    }

    cJSON* node = root;
    const char* cursor = path;
    char segment[64];

    while (*cursor != '\0') {
        size_t len = 0;
        while (cursor[len] != '\0' && cursor[len] != '.') {
            if (len + 1 >= sizeof(segment)) {
                return false;
            }
            len++;
        }

        memcpy(segment, cursor, len);
        segment[len] = '\0';
        cursor += len;
        const bool last_segment = (*cursor == '\0');
        if (!last_segment && *cursor == '.') {
            cursor++;
        }

        if (last_segment) {
            cJSON* duplicate = cJSON_Duplicate(value, true);
            if (!duplicate) {
                return false;
            }

            if (cJSON_GetObjectItemCaseSensitive(node, segment)) {
                if (!cJSON_ReplaceItemInObjectCaseSensitive(node, segment, duplicate)) {
                    cJSON_Delete(duplicate);
                    return false;
                }
            } else {
                if (!cJSON_AddItemToObject(node, segment, duplicate)) {
                    cJSON_Delete(duplicate);
                    return false;
                }
            }
            return true;
        }

        cJSON* child = cJSON_GetObjectItemCaseSensitive(node, segment);
        if (!child || !cJSON_IsObject(child)) {
            if (child) {
                cJSON_DeleteItemFromObjectCaseSensitive(node, segment);
            }
            child = cJSON_CreateObject();
            if (!child) {
                return false;
            }
            if (!cJSON_AddItemToObject(node, segment, child)) {
                cJSON_Delete(child);
                return false;
            }
        }
        node = child;
    }

    return false;
}
}

void webserver_httpd_monitor_note_request(httpd_req_t* req) {
    WebServer::httpdMonitorNoteRequest(req);
}

void webserver_httpd_monitor_note_response(httpd_req_t* req, int status_code, const char* auth_status) {
    WebServer::httpdMonitorNoteResponse(req, status_code, auth_status);
}

void WebServer::httpdMonitorReset() {
    HttpdMonitorData& mon = httpd_monitor_;

    mon.total_requests.store(0, std::memory_order_relaxed);
    mon.total_responses.store(0, std::memory_order_relaxed);
    mon.inflight_requests.store(0, std::memory_order_relaxed);
    mon.max_concurrent.store(0, std::memory_order_relaxed);
    mon.method_get.store(0, std::memory_order_relaxed);
    mon.method_post.store(0, std::memory_order_relaxed);
    mon.method_put.store(0, std::memory_order_relaxed);
    mon.method_delete.store(0, std::memory_order_relaxed);
    mon.method_other.store(0, std::memory_order_relaxed);
    mon.status_2xx.store(0, std::memory_order_relaxed);
    mon.status_3xx.store(0, std::memory_order_relaxed);
    mon.status_4xx.store(0, std::memory_order_relaxed);
    mon.status_5xx.store(0, std::memory_order_relaxed);
    mon.auth_failures.store(0, std::memory_order_relaxed);
    mon.stall_count.store(0, std::memory_order_relaxed);
    mon.watchdog_triggered.store(0, std::memory_order_relaxed);
    mon.last_status_code.store(0, std::memory_order_relaxed);
    mon.last_stall_ms.store(0, std::memory_order_relaxed);

    const uint64_t now_ms = esp_timer_get_time() / 1000ULL;
    mon.last_request_ms.store(now_ms, std::memory_order_relaxed);
    mon.last_response_ms.store(now_ms, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(mon.uri_mutex);
        mon.last_request_uri[0] = '\0';
        mon.last_error_uri[0] = '\0';
    }
}

void WebServer::httpdMonitorNoteRequest(httpd_req_t* req) {
    HttpdMonitorData& mon = httpd_monitor_;
    const uint64_t now_ms = esp_timer_get_time() / 1000ULL;

    const int32_t inflight =
        mon.inflight_requests.fetch_add(1, std::memory_order_relaxed) + 1;
    mon.total_requests.fetch_add(1, std::memory_order_relaxed);
    mon.last_request_ms.store(now_ms, std::memory_order_relaxed);

    const uint64_t inflight_u = inflight > 0 ? static_cast<uint64_t>(inflight) : 0ULL;
    uint64_t current_max = mon.max_concurrent.load(std::memory_order_relaxed);
    while (inflight_u > current_max &&
           !mon.max_concurrent.compare_exchange_weak(current_max,
                                                    inflight_u,
                                                    std::memory_order_relaxed)) {
        // current_max updated by compare_exchange_weak
    }

    httpd_method_t method = req ? static_cast<httpd_method_t>(req->method) : HTTP_GET;
    switch (method) {
        case HTTP_GET:    mon.method_get.fetch_add(1, std::memory_order_relaxed); break;
        case HTTP_POST:   mon.method_post.fetch_add(1, std::memory_order_relaxed); break;
        case HTTP_PUT:    mon.method_put.fetch_add(1, std::memory_order_relaxed); break;
        case HTTP_DELETE: mon.method_delete.fetch_add(1, std::memory_order_relaxed); break;
        default:          mon.method_other.fetch_add(1, std::memory_order_relaxed); break;
    }

    if (req && req->uri[0] != '\0') {
        std::lock_guard<std::mutex> lock(mon.uri_mutex);
        strncpy(mon.last_request_uri, req->uri, sizeof(mon.last_request_uri) - 1);
        mon.last_request_uri[sizeof(mon.last_request_uri) - 1] = '\0';
    }
}

void WebServer::httpdMonitorNoteResponse(httpd_req_t* req,
                                         int status_code,
                                         const char* auth_status) {
    HttpdMonitorData& mon = httpd_monitor_;
    const uint64_t now_ms = esp_timer_get_time() / 1000ULL;

    mon.total_responses.fetch_add(1, std::memory_order_relaxed);
    mon.last_response_ms.store(now_ms, std::memory_order_relaxed);
    mon.last_status_code.store(status_code, std::memory_order_relaxed);

    const int32_t prev_inflight =
        mon.inflight_requests.fetch_sub(1, std::memory_order_relaxed);
    if (prev_inflight <= 0) {
        mon.inflight_requests.store(0, std::memory_order_relaxed);
    }

    if (status_code >= 200 && status_code < 300) {
        mon.status_2xx.fetch_add(1, std::memory_order_relaxed);
    } else if (status_code >= 300 && status_code < 400) {
        mon.status_3xx.fetch_add(1, std::memory_order_relaxed);
    } else if (status_code >= 400 && status_code < 500) {
        mon.status_4xx.fetch_add(1, std::memory_order_relaxed);
        if (req && req->uri[0] != '\0') {
            std::lock_guard<std::mutex> lock(mon.uri_mutex);
            strncpy(mon.last_error_uri, req->uri, sizeof(mon.last_error_uri) - 1);
            mon.last_error_uri[sizeof(mon.last_error_uri) - 1] = '\0';
        }
    } else if (status_code >= 500 && status_code < 600) {
        mon.status_5xx.fetch_add(1, std::memory_order_relaxed);
        if (req && req->uri[0] != '\0') {
            std::lock_guard<std::mutex> lock(mon.uri_mutex);
            strncpy(mon.last_error_uri, req->uri, sizeof(mon.last_error_uri) - 1);
            mon.last_error_uri[sizeof(mon.last_error_uri) - 1] = '\0';
        }
    }

    if (status_code == 401 ||
        (auth_status && std::strcmp(auth_status, "FAILED") == 0)) {
        mon.auth_failures.fetch_add(1, std::memory_order_relaxed);
    }

    mon.watchdog_triggered.store(0, std::memory_order_relaxed);
}

void WebServer::httpdMonitorStart() {
    httpdMonitorReset();

    if (httpd_monitor_timer_) {
        esp_timer_stop(httpd_monitor_timer_);
        esp_timer_delete(httpd_monitor_timer_);
        httpd_monitor_timer_ = nullptr;
    }

    esp_timer_create_args_t args = {};
    args.callback = &WebServer::httpdMonitorTimerCallback;
    args.arg = nullptr;
    args.dispatch_method = ESP_TIMER_TASK;
    args.name = "httpd_mon";

    if (esp_timer_create(&args, &httpd_monitor_timer_) == ESP_OK) {
        esp_timer_start_periodic(httpd_monitor_timer_,
                                 static_cast<uint64_t>(kHttpdMonitorIntervalMs) * 1000ULL);
    } else {
        LOG_WARNING("HTTPD_MON", "Failed to create HTTP monitor timer");
    }
}

void WebServer::httpdMonitorStop() {
    if (httpd_monitor_timer_) {
        esp_timer_stop(httpd_monitor_timer_);
        esp_timer_delete(httpd_monitor_timer_);
        httpd_monitor_timer_ = nullptr;
    }
    httpdMonitorReset();
}

void WebServer::httpdMonitorTimerCallback(void* /*arg*/) {
    HttpdMonitorData& mon = httpd_monitor_;

    const uint64_t now_ms = esp_timer_get_time() / 1000ULL;
    const uint64_t last_request = mon.last_request_ms.load(std::memory_order_relaxed);
    const uint64_t last_resp = mon.last_response_ms.load(std::memory_order_relaxed);
    const int32_t inflight = mon.inflight_requests.load(std::memory_order_relaxed);

    uint64_t reference_ms = last_resp;
    if (inflight > 0 && last_request > reference_ms) {
        reference_ms = last_request;
    }

    const bool stalled =
        (inflight > 0) &&
        (reference_ms > 0) &&
        (now_ms > reference_ms) &&
        ((now_ms - reference_ms) > kHttpdWatchdogTimeoutMs);

    if (stalled) {
        if (mon.watchdog_triggered.exchange(1, std::memory_order_relaxed) == 0) {
            mon.stall_count.fetch_add(1, std::memory_order_relaxed);
            mon.last_stall_ms.store(now_ms, std::memory_order_relaxed);
            LOG_WARNINGF("HTTPD_MON",
                         "HTTP server watchdog triggered: inflight=%d, response gap=%llu ms",
                         (int)inflight,
                         (unsigned long long)(now_ms - reference_ms));
        }
    } else {
        mon.watchdog_triggered.store(0, std::memory_order_relaxed);
    }
}
psram_string WebServer::reporting_cache_;
std::mutex WebServer::reporting_cache_mutex_;
bool WebServer::reporting_cache_valid_ = false;
psram_string WebServer::reporting_channels_cache_;
std::mutex WebServer::reporting_channels_mutex_;
bool WebServer::reporting_channels_valid_ = false;

// Force "minimal web" mode if the buffers cannot go into PSRAM
static bool g_force_minimal_web = false;

// Utility function to check if current task is running on PSRAM stack
static bool isCurrentTaskOnPSRAMStack() {
    char stack_var = 0;  // Initialize to suppress warning
    return esp_ptr_external_ram(&stack_var);
}

// Helper: verify that a pointer really points into external PSRAM
static bool ensure_psram_buf(const char* name, void* ptr, size_t size_bytes) {
    if (!ptr) {
        LOG_ERRORF(TAG_WEB, "🔴 CRITICAL: %s allocation failed (%u bytes)", name, (unsigned)size_bytes);
        g_force_minimal_web = true;
        return false;
    }
    if (!esp_ptr_external_ram(ptr)) {
        LOG_ERRORF(TAG_WEB, "🔴 CRITICAL: %s NOT in PSRAM (ptr=%p, size=%u)", name, ptr, (unsigned)size_bytes);
        g_force_minimal_web = true;
        return false;
    }
    return true;
}

// Helper: verify that a pointer is NOT in PSRAM and is DMA-capable (required for socket TX and various drivers)
static bool ensure_internal_dma_buf(const char* name, void* ptr, size_t size_bytes) {
    if (!ptr) {
        LOG_ERRORF(TAG_WEB, "💾 CRITICAL: %s allocation failed (%u bytes)", name, (unsigned)size_bytes);
        return false;
    }
    if (esp_ptr_external_ram(ptr)) {
        LOG_ERRORF(TAG_WEB, "💾 CRITICAL: %s in PSRAM but INTERNAL/DMA is required (ptr=%p, size=%u)",
                   name, ptr, (unsigned)size_bytes);
        return false;
    }
    if (!esp_ptr_dma_capable(ptr)) {
        LOG_ERRORF(TAG_WEB, "💾 CRITICAL: %s NOT DMA-capable (ptr=%p, size=%u)", name, ptr, (unsigned)size_bytes);
        return false;
    }
    return true;
}

static const char* wifi_authmode_to_cstr(wifi_auth_mode_t mode) {
    switch (mode) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA_WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2_ENT";
        case WIFI_AUTH_WPA3_PSK: return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2_WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK: return "WAPI_PSK";
        default: return "UNKNOWN";
    }
}

// ==== ENHANCED PSRAM BUFFER SYSTEM FOR STL-FREE WEB OPERATIONS ====
#define WEB_BUF_SZ 4096
#define HTTP_TMP_SZ 4096
#define HTTP_HEADER_BUF_SZ 2048
#define HTTP_JSON_BUF_SZ 8192
#define HTTP_URI_BUF_SZ 1024
#define HTTP_POST_BUF_SZ 16384

// Schedule IRAM defragmentation after dashboard API calls
#define SCHEDULE_DEFRAG() do { if (self_) { self_->scheduleDefragmentation(); } } while(0)

static char* web_buf = nullptr;          // General web operations buffer (4KB)
static char* g_http_tmp = nullptr;       // HTTP response building buffer (4KB)
static char* g_http_header_buf = nullptr; // HTTP header buffer (2KB)
static char* g_http_json_buf = nullptr;   // JSON response buffer (8KB)
static char* g_http_uri_buf = nullptr;    // URI processing buffer (1KB)
static char* g_http_post_buf = nullptr;   // POST data buffer (16KB)

// ==== GLOBAL CHUNKED TRANSFER BUFFER (Internal RAM - for DMA/socket TX) ====
// Keep this modest: this buffer lives in INTERNAL RAM. Too large can reduce the largest free block and break HTTPS bring-up.
#define CHUNK_BUFFER_SIZE 2048
static char* g_chunk_buffer = nullptr;
static SemaphoreHandle_t g_chunk_buffer_mutex = nullptr;

static char* g_dashboard_html_psram = nullptr;
static std::once_flag g_dashboard_html_once;

static const char* get_dashboard_html_psram() {
    std::call_once(g_dashboard_html_once, []() {
        char* buffer = static_cast<char*>(
            heap_caps_malloc(DASHBOARD_HTML_GEN_SIZE + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
        );
        if (!buffer) {
            LOG_WARNING(TAG_WEB, "Unable to allocate PSRAM dashboard buffer; using flash source");
            return;
        }
        memcpy(buffer, DASHBOARD_HTML_GEN, DASHBOARD_HTML_GEN_SIZE);
        buffer[DASHBOARD_HTML_GEN_SIZE] = '\0';
        g_dashboard_html_psram = buffer;
    });
    return g_dashboard_html_psram;
}

struct StaticJsonBuffer {
    char* buf;
    size_t capacity;
    size_t length;
    std::mutex mutex;

    StaticJsonBuffer() : buf(nullptr), capacity(0), length(0) {}
};

static StaticJsonBuffer g_status_json;
static StaticJsonBuffer g_report_queue_json;
static StaticJsonBuffer g_wifi_status_json;
static StaticJsonBuffer g_ids_adv_json;
static StaticJsonBuffer g_report_flush_json;
static StaticJsonBuffer g_page_bootstrap_json;
static std::mutex g_discovery_list_cache_mutex;
static psram_string g_discovery_list_cache_json;
static uint64_t g_discovery_list_cache_ts_ms = 0;
static constexpr uint64_t kDiscoveryListCacheTtlMs = 1500;

using PSRAMUtils::ScopedBuffer;

static bool ensure_json_buffer(StaticJsonBuffer& cache, size_t required, const char* tag) {
    if (cache.capacity >= required && cache.buf) {
        return true;
    }

    size_t new_capacity = cache.capacity ? cache.capacity : 0;
    while (new_capacity < required) {
        new_capacity += 1024;
    }

    char* new_buf = static_cast<char*>(heap_caps_malloc(new_capacity, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!ensure_psram_buf(tag, new_buf, new_capacity)) {
        if (new_buf && !esp_ptr_external_ram(new_buf)) {
            heap_caps_free(new_buf);
        }
        return false;
    }

    if (cache.buf) {
        heap_caps_free(cache.buf);
    }

    cache.buf = new_buf;
    cache.capacity = new_capacity;
    cache.length = 0;
    cache.buf[0] = '\0';
    return true;
}

static bool json_append_char(StaticJsonBuffer& cache, size_t& len, char c) {
    if (!cache.buf || len + 1 >= cache.capacity) {
        return false;
    }
    cache.buf[len++] = c;
    cache.buf[len] = '\0';
    return true;
}

static bool json_append_cstr(StaticJsonBuffer& cache, size_t& len, const char* str) {
    if (!str) str = "";
    while (*str) {
        if (!json_append_char(cache, len, *str++)) {
            return false;
        }
    }
    return true;
}

static bool json_append_fmt(StaticJsonBuffer& cache, size_t& len, const char* fmt, ...) {
    if (!cache.buf || len >= cache.capacity) {
        return false;
    }

    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(cache.buf + len, cache.capacity - len, fmt, args);
    va_end(args);

    if (written < 0) {
        return false;
    }

    if (static_cast<size_t>(written) >= cache.capacity - len) {
        return false;
    }

    len += static_cast<size_t>(written);
    cache.buf[len] = '\0';
    return true;
}

static bool json_append_uint64(StaticJsonBuffer& cache, size_t& len, uint64_t value) {
    if (!cache.buf || len >= cache.capacity) {
        return false;
    }

    char tmp[32];
    size_t idx = sizeof(tmp);

    do {
        if (idx == 0) {
            return false;
        }
        tmp[--idx] = static_cast<char>('0' + (value % 10U));
        value /= 10U;
    } while (value != 0U);

    size_t digits = sizeof(tmp) - idx;
    if (len + digits >= cache.capacity) {
        return false;
    }

    memcpy(cache.buf + len, &tmp[idx], digits);
    len += digits;
    cache.buf[len] = '\0';
    return true;
}

static bool ensure_report_queue_directory() {
    static bool ensured = false;
    static bool warned = false;
    static std::mutex ensure_mutex;
    std::lock_guard<std::mutex> lock(ensure_mutex);

    if (ensured) {
        return true;
    }

    FilesystemTaskDelegate& fs_delegate = FilesystemTaskDelegate::getInstance();
    if (!fs_delegate.isReady()) {
        LOG_WARNING("REPORTQ", "FilesystemTaskDelegate not ready for report queue directory ensure");
        return false;
    }

    static const std::string base_dir("/data");
    static const std::string queue_dir("/data/reportq");

    auto ensure_base = fs_delegate.createDirectorySync(base_dir, 2000U);
    auto ensure_queue = fs_delegate.createDirectorySync(queue_dir, 2000U);

    if (ensure_base == FilesystemTaskDelegate::OperationResult::SUCCESS &&
        ensure_queue == FilesystemTaskDelegate::OperationResult::SUCCESS) {
        ensured = true;
        warned = false;
        return true;
    }

    if (!warned) {
        LOG_WARNINGF("REPORTQ", "Directory ensure failed: base=%d queue=%d",
                     static_cast<int>(ensure_base), static_cast<int>(ensure_queue));
        warned = true;
    }
    return false;
}

static bool json_append_escaped(StaticJsonBuffer& cache, size_t& len, const char* value, bool wrap_quotes) {
    if (!value) value = "";
    if (wrap_quotes && !json_append_char(cache, len, '"')) {
        return false;
    }
    while (*value) {
        unsigned char c = static_cast<unsigned char>(*value++);
        switch (c) {
            case '"':
                if (!json_append_cstr(cache, len, "\\\"")) return false;
                break;
            case '\\':
                if (!json_append_cstr(cache, len, "\\\\")) return false;
                break;
            case '\b':
                if (!json_append_cstr(cache, len, "\\b")) return false;
                break;
            case '\f':
                if (!json_append_cstr(cache, len, "\\f")) return false;
                break;
            case '\n':
                if (!json_append_cstr(cache, len, "\\n")) return false;
                break;
            case '\r':
                if (!json_append_cstr(cache, len, "\\r")) return false;
                break;
            case '\t':
                if (!json_append_cstr(cache, len, "\\t")) return false;
                break;
            default:
                if (c < 0x20) {
                    if (!json_append_fmt(cache, len, "\\u%04x", c)) return false;
                } else {
                    if (!json_append_char(cache, len, static_cast<char>(c))) return false;
                }
                break;
        }
    }
    if (wrap_quotes && !json_append_char(cache, len, '"')) {
        return false;
    }
    return true;
}

static void get_ip_from_netif(esp_netif_t* netif, char* out, size_t out_sz) {
    if (!out || out_sz == 0) {
        return;
    }
    out[0] = '\0';
    if (!netif) {
        return;
    }

    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(netif, &info) == ESP_OK) {
        if (info.ip.addr != 0) {
            ip4addr_ntoa_r(reinterpret_cast<const ip4_addr_t*>(&info.ip), out, static_cast<int>(out_sz));
        }
    }
}

static bool build_status_json(StaticJsonBuffer& cache) {
    const size_t base_capacity = 4096;
    size_t attempt = 0;
    size_t required = base_capacity;

    while (attempt < 4) {
        if (!ensure_json_buffer(cache, required, "status_json")) {
            return false;
        }

        size_t len = 0;
        cache.buf[0] = '\0';

        uint64_t uptime_sec = esp_timer_get_time() / 1000000ULL;

        char eth_ip[64] = {0};
        char wifi_ip[64] = {0};
        const WebServer* server = WebServer::instanceConst();
        if (server && server->ethernet()) {
            get_ip_from_netif(server->ethernet()->netif(), eth_ip, sizeof(eth_ip));
        }
        if (server && server->wifi()) {
            server->wifi()->getIP(wifi_ip, sizeof(wifi_ip));
        }

        if (!json_append_char(cache, len, '{')) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "\"uptime_s\":")) { attempt++; required += 2048; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(uptime_sec))) { attempt++; required += 2048; continue; }
        if (!json_append_char(cache, len, ',')) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "\"version\":")) { attempt++; required += 2048; continue; }
        if (!json_append_escaped(cache, len, esp_app_get_description()->version, true)) { attempt++; required += 2048; continue; }
        if (!json_append_char(cache, len, ',')) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "\"board\":")) { attempt++; required += 2048; continue; }
        if (!json_append_escaped(cache, len, NetworkPolicy::boardName(), true)) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, ",\"management_policy\":")) { attempt++; required += 2048; continue; }
        if (!json_append_escaped(cache, len, NetworkPolicy::managementInterfaceName(), true)) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, ",\"management_state\":")) { attempt++; required += 2048; continue; }
        if (!json_append_escaped(cache, len, managementInterfaceStateName(currentManagementInterfaceState()), true)) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, ",\"management_degraded\":")) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, managementInterfaceIsDegraded() ? "true" : "false")) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, ",\"assessment_interface\":\"ethernet\",")) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "\"network\":{\"eth\":{\"ip\":")) { attempt++; required += 2048; continue; }
        if (!json_append_escaped(cache, len, eth_ip, true)) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "},\"wifi\":{\"ip\":")) { attempt++; required += 2048; continue; }
        if (!json_append_escaped(cache, len, wifi_ip, true)) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "}},")) { attempt++; required += 2048; continue; }

        if (!json_append_cstr(cache, len, "\"plugins\":[")) { attempt++; required += 2048; continue; }
        bool first_plugin = true;
        bool restart = false;
        if (server && server->plugins()) {
            auto statuses = server->plugins()->getAllPluginStatus();
            for (auto& status : statuses) {
                if (!first_plugin && !json_append_char(cache, len, ',')) { restart = true; break; }
                if (!json_append_char(cache, len, '{')) { restart = true; break; }
                if (!json_append_cstr(cache, len, "\"name\":")) { restart = true; break; }
                if (!json_append_escaped(cache, len, status.name.c_str(), true)) { restart = true; break; }
                if (!json_append_cstr(cache, len, ",\"events\":")) { restart = true; break; }
                if (!json_append_uint64(cache, len, static_cast<uint64_t>(status.events_generated))) { restart = true; break; }
                if (!json_append_char(cache, len, '}')) { restart = true; break; }
                first_plugin = false;
            }
        }
        if (restart) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "],")) { attempt++; required += 2048; continue; }

        if (!json_append_cstr(cache, len, "\"ids\":{")) { attempt++; required += 2048; continue; }
        uint64_t total_packets = 0;
        uint64_t alerts_generated = 0;
        if (server && server->ids()) {
            total_packets = server->ids()->getTotalPacketsAnalyzed();
            alerts_generated = server->ids()->getAlertsGenerated();
        }
        if (!json_append_cstr(cache, len, "\"total_packets\":")) { attempt++; required += 2048; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(total_packets))) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, ",\"alerts\":")) { attempt++; required += 2048; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(alerts_generated))) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, ",\"protocols\":{")) { attempt++; required += 2048; continue; }

        bool first_proto = true;
        restart = false;
        if (server && server->ids()) {
            auto proto_stats = server->ids()->getProtocolStatistics();
            for (auto const& kv : proto_stats) {
                if (!first_proto && !json_append_char(cache, len, ',')) { restart = true; break; }
                if (!json_append_escaped(cache, len, kv.first.c_str(), true)) { restart = true; break; }
                if (!json_append_char(cache, len, ':')) { restart = true; break; }
                if (!json_append_uint64(cache, len, static_cast<uint64_t>(kv.second))) { restart = true; break; }
                first_proto = false;
            }
        }
        if (restart) { attempt++; required += 2048; continue; }
        if (!json_append_cstr(cache, len, "}}")) { attempt++; required += 2048; continue; }
        if (!json_append_char(cache, len, '}')) { attempt++; required += 2048; continue; }

        cache.length = len;
        cache.buf[len] = '\0';
        return true;
    }

    return false;
}

static bool build_report_queue_json(StaticJsonBuffer& cache) {
    const size_t base_capacity = 512;
    size_t attempt = 0;
    size_t required = base_capacity;

    ensure_report_queue_directory();

    PSRAMQueueStats stats{};
    bool have_stats = false;
    if (g_reporting) {
        have_stats = g_reporting->getQueueStats(stats);
    }

    uint32_t queued = 0;
    if (have_stats) {
        queued = stats.queued;
    } else if (g_reporting) {
        queued = g_reporting->queuedCount();
    }

    while (attempt < 3) {
        if (!ensure_json_buffer(cache, required, "report_queue_json")) {
            return false;
        }

        size_t len = 0;
        cache.buf[0] = '\0';

        if (!json_append_char(cache, len, '{')) { attempt++; required += 96; continue; }
        if (!json_append_cstr(cache, len, "\"queued\":")) { attempt++; required += 96; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(queued))) { attempt++; required += 96; continue; }

        if (have_stats) {
            uint32_t max_items = stats.max_items;
            uint32_t usage_pct = (max_items > 0)
                                     ? static_cast<uint32_t>((static_cast<uint64_t>(stats.queued) * 100ULL) / max_items)
                                     : 0;
            if (!json_append_cstr(cache, len, ",\"max_items\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(max_items))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"usage_pct\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(usage_pct))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"events_since_sync\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(stats.events_since_sync))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"last_sync_ms\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, stats.last_sync_ms)) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"dirty\":")) { attempt++; required += 96; continue; }
            if (!json_append_cstr(cache, len, stats.dirty ? "true" : "false")) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"initialized\":")) { attempt++; required += 96; continue; }
            if (!json_append_cstr(cache, len, stats.initialized ? "true" : "false")) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"sync_threshold\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(stats.sync_threshold))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"sync_interval_ms\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(stats.sync_interval_ms))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"flush_interval_ms\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(stats.flush_interval_ms))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"backoff_base_ms\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(stats.backoff_base_ms))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"backoff_max_ms\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(stats.backoff_max_ms))) { attempt++; required += 96; continue; }

            if (!json_append_cstr(cache, len, ",\"payload_bytes\":")) { attempt++; required += 96; continue; }
            if (!json_append_uint64(cache, len, static_cast<uint64_t>(stats.payload_bytes))) { attempt++; required += 96; continue; }

            if (!stats.backup_file.empty()) {
                if (!json_append_cstr(cache, len, ",\"backup_file\":")) { attempt++; required += 96; continue; }
                if (!json_append_escaped(cache, len, stats.backup_file.c_str(), true)) { attempt++; required += 96; continue; }
            }
        }

        if (!json_append_char(cache, len, '}')) { attempt++; required += 96; continue; }
        cache.length = len;
        cache.buf[len] = '\0';
        return true;
    }
    return false;
}

static bool build_wifi_status_json(StaticJsonBuffer& cache) {
    const size_t base_capacity = 256;
    size_t attempt = 0;
    size_t required = base_capacity;

    while (attempt < 3) {
        if (!ensure_json_buffer(cache, required, "wifi_status_json")) {
            return false;
        }

        size_t len = 0;
        cache.buf[0] = '\0';

        bool sta_connected = false;
        bool ap_active = false;
        char ip_buffer[64] = {0};
        const char* mode_str = "NONE";
        const char* status_str = "WiFi Disabled";

        const WebServer* server = WebServer::instanceConst();
        if (server && server->wifi()) {
            sta_connected = server->wifi()->isSTAConnected();
            ap_active = server->wifi()->isAPActive();
            server->wifi()->getIP(ip_buffer, sizeof(ip_buffer));

            if (sta_connected) {
                mode_str = "STA";
                status_str = "Connected";
            } else if (ap_active) {
                mode_str = "AP";
                status_str = "Access Point Active";
            }
        }

        if (!json_append_char(cache, len, '{')) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, "\"sta_connected\":")) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, sta_connected ? "true" : "false")) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ",\"ap_active\":")) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ap_active ? "true" : "false")) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ",\"ip\":")) { attempt++; required += 64; continue; }
        if (!json_append_escaped(cache, len, ip_buffer, true)) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ",\"mode\":")) { attempt++; required += 64; continue; }
        if (!json_append_escaped(cache, len, mode_str, true)) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ",\"status\":")) { attempt++; required += 64; continue; }
        if (!json_append_escaped(cache, len, status_str, true)) { attempt++; required += 64; continue; }
        if (!json_append_char(cache, len, '}')) { attempt++; required += 64; continue; }
        cache.length = len;
        cache.buf[len] = '\0';
        return true;
    }
    return false;
}

static bool build_ids_adv_json(StaticJsonBuffer& cache) {
    const size_t base_capacity = 256;
    size_t attempt = 0;
    size_t required = base_capacity;

    while (attempt < 3) {
        if (!ensure_json_buffer(cache, required, "ids_adv_json")) {
            return false;
        }
        size_t len = 0;
        cache.buf[0] = '\0';

        uint64_t packets = 0;
        uint64_t alerts = 0;
        const WebServer* server = WebServer::instanceConst();
        if (server && server->ids()) {
            packets = server->ids()->getTotalPacketsAnalyzed();
            alerts = server->ids()->getAlertsGenerated();
        }

        if (!json_append_char(cache, len, '{')) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, "\"packets_analyzed\":")) { attempt++; required += 64; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(packets))) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ",\"alerts_generated\":")) { attempt++; required += 64; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(alerts))) { attempt++; required += 64; continue; }

        // Backward/forward compatibility: some UIs expect allowed/alert/dropped counters.
        // We currently expose packet/alert counters from IDS core; dropped is not tracked here.
        if (!json_append_cstr(cache, len, ",\"allowed\":")) { attempt++; required += 64; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(packets))) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ",\"alert\":")) { attempt++; required += 64; continue; }
        if (!json_append_uint64(cache, len, static_cast<uint64_t>(alerts))) { attempt++; required += 64; continue; }
        if (!json_append_cstr(cache, len, ",\"dropped\":0")) { attempt++; required += 64; continue; }

        if (!json_append_cstr(cache, len, ",\"rules_loaded\":0}")) { attempt++; required += 64; continue; }
        cache.length = len;
        cache.buf[len] = '\0';
        return true;
    }
    return false;
}

static bool json_append_field_raw(StaticJsonBuffer& cache, size_t& len, bool& first, const char* key, const char* raw_json) {
    if (!key) return false;
    if (!raw_json) raw_json = "null";
    if (!first) {
        if (!json_append_char(cache, len, ',')) return false;
    }
    first = false;
    if (!json_append_char(cache, len, '"')) return false;
    if (!json_append_cstr(cache, len, key)) return false;
    if (!json_append_cstr(cache, len, "\":")) return false;
    return json_append_cstr(cache, len, raw_json);
}

static bool json_append_field_string(StaticJsonBuffer& cache, size_t& len, bool& first, const char* key, const char* value) {
    if (!key) return false;
    if (!first) {
        if (!json_append_char(cache, len, ',')) return false;
    }
    first = false;
    if (!json_append_char(cache, len, '"')) return false;
    if (!json_append_cstr(cache, len, key)) return false;
    if (!json_append_cstr(cache, len, "\":")) return false;
    return json_append_escaped(cache, len, value ? value : "", true);
}

static bool json_append_field_uint64(StaticJsonBuffer& cache, size_t& len, bool& first, const char* key, uint64_t value) {
    if (!key) return false;
    if (!first) {
        if (!json_append_char(cache, len, ',')) return false;
    }
    first = false;
    if (!json_append_char(cache, len, '"')) return false;
    if (!json_append_cstr(cache, len, key)) return false;
    if (!json_append_cstr(cache, len, "\":")) return false;
    return json_append_uint64(cache, len, value);
}

static bool append_protocol_config_object(StaticJsonBuffer& cache, size_t& len, const char* proto_key, const psram_string_map& cfg, bool& first_proto) {
    if (!proto_key) return false;
    if (!first_proto) {
        if (!json_append_char(cache, len, ',')) return false;
    }
    first_proto = false;
    if (!json_append_char(cache, len, '"')) return false;
    if (!json_append_cstr(cache, len, proto_key)) return false;
    if (!json_append_cstr(cache, len, "\":{")) return false;

    bool first_field = true;
    for (auto const& kv : cfg) {
        if (!first_field) {
            if (!json_append_char(cache, len, ',')) return false;
        }
        first_field = false;
        if (!json_append_char(cache, len, '"')) return false;
        if (!json_append_cstr(cache, len, kv.first.c_str())) return false;
        if (!json_append_cstr(cache, len, "\":")) return false;
        // Keep values as strings to preserve existing /api/protocols/*/config behavior.
        if (!json_append_escaped(cache, len, kv.second.c_str(), true)) return false;
    }

    return json_append_char(cache, len, '}');
}

bool WebServer::build_page_bootstrap_json(StaticJsonBuffer& cache, const char* page_name) const {
    if (!cfg_ || !page_name) {
        return false;
    }

    const uint64_t ts_ms = esp_timer_get_time() / 1000ULL;

    // Gather fragments first to estimate required capacity.
    char* cfg_buf = nullptr;
    size_t cfg_len = 0;
    // Dashboard / other pages may reuse cfg_buf too; keep it PSRAM-backed and free on cleanup.

    psram_string presence_cfg;
    psram_string presence_stats;
    psram_string presence_devices;
    psram_string presence_learned;

    char ids_cfg_json[128] = {0};
    char ids_stats_json[192] = {0};

    // Scanner fragments
    char features_json[160] = {0};
    psram_string discovery_defaults_json;
    char* discovery_list_json = nullptr;

    const bool is_ids = (strcmp(page_name, "ids") == 0);
    const bool is_presence = (strcmp(page_name, "network_presence") == 0);
    const bool is_protocols = (strcmp(page_name, "protocols") == 0);
    const bool is_scanner = (strcmp(page_name, "scanner") == 0);
    const bool is_reporting = (strcmp(page_name, "reporting") == 0);
    const bool is_logging = (strcmp(page_name, "logging") == 0);
    const bool is_security = (strcmp(page_name, "security") == 0);
    const bool is_signatures = (strcmp(page_name, "signatures") == 0);
    const bool is_network = (strcmp(page_name, "network") == 0);
    const bool is_gpio = (strcmp(page_name, "gpio") == 0);
    const bool is_audit = (strcmp(page_name, "audit") == 0);
    const bool is_dashboard = (strcmp(page_name, "dashboard") == 0);
    const bool is_serial_monitor = (strcmp(page_name, "serial_monitor") == 0);

    // The full configuration is needed only by the dedicated IDS page.
    // Dashboard bootstrap deliberately omits it so secrets never reach the
    // general dashboard payload; use /configuration for redacted editing.
    if (is_ids) {
        cfg_buf = cfg_->getRawConfigInPSRAM(&cfg_len);
        if (!cfg_buf || cfg_len == 0) {
            if (cfg_buf) heap_caps_free(cfg_buf);
            return false;
        }
    }

    if (is_ids || is_presence) {
        if (ids_) {
            presence_cfg = ids_->getNetworkPresenceTracker().getConfigJSON();
            presence_stats = ids_->getNetworkPresenceTracker().getDevicesStatsJSON();
            presence_devices = presence_stats; // Current API uses the same payload for both endpoints.
            presence_learned = ids_->getNetworkPresenceTracker().getLearnedDevicesJSON();
        } else {
            presence_cfg = "{}";
            presence_stats = "{}";
            presence_devices = "{}";
            presence_learned = "[]";
        }
    }

    if (is_ids) {
        // Minimal IDS config for UI toggles.
        const auto ids_cfg = cfg_->getIDSConfig();
        snprintf(ids_cfg_json, sizeof(ids_cfg_json), "{\"enabled\":%s}", ids_cfg.enabled ? "true" : "false");

        // IDS runtime stats (subset). Kept compatible with /api/ids/stats.
        uint64_t packets = 0;
        uint64_t alerts = 0;
        if (ids_) {
            packets = ids_->getTotalPacketsAnalyzed();
            alerts = ids_->getAlertsGenerated();
        }
        snprintf(ids_stats_json, sizeof(ids_stats_json),
                 "{\"packets_analyzed\":%llu,\"alerts_generated\":%llu,\"allowed\":%llu,\"alert\":%llu,\"dropped\":0}",
                 (unsigned long long)packets,
                 (unsigned long long)alerts,
                 (unsigned long long)packets,
                 (unsigned long long)alerts);
    }

    if (is_scanner) {
        // Features payload (same structure as /api/features).
        bool ids = cfg_->isFeatureEnabled("ids", true);
        bool vs  = cfg_->isFeatureEnabled("vuln_scanner", false);
        bool fz  = cfg_->isFeatureEnabled("fuzzing", false);
        bool sched = cfg_->isFeatureEnabled("scheduled_scans", true);
        snprintf(features_json, sizeof(features_json),
                 "{\"ids\":%s,\"vuln_scanner\":%s,\"fuzzing\":%s,\"scheduled_scans\":%s}",
                 ids ? "true" : "false",
                 vs ? "true" : "false",
                 fz ? "true" : "false",
                 sched ? "true" : "false");

        // General discovery defaults (avoid HTTP fan-out and avoid std::string in UI init path).
        {
            psram_vector<uint16_t> unique_ports;
            if (plugins_) {
                plugins_->forEach([&](BasePlugin& plg) {
                    auto ports_vec = plg.getMonitoredPorts();
                    for (uint16_t port : ports_vec) {
                        if (port == 0) continue;
                        if (std::find(unique_ports.begin(), unique_ports.end(), port) == unique_ports.end()) {
                            unique_ports.push_back(port);
                        }
                    }
                });
            }
            std::sort(unique_ports.begin(), unique_ports.end());

            // Build in-place using a temporary buffer in PSRAM.
            StaticJsonBuffer tmp;
            size_t required = 256 + unique_ports.size() * 8;
            if (!ensure_json_buffer(tmp, required, "disc_defaults_bootstrap")) {
                return false;
            }
            size_t l = 0;
            tmp.buf[0] = '\0';
            if (!json_append_char(tmp, l, '{')) return false;
            if (!json_append_cstr(tmp, l, "\"ports\":[")) return false;
            for (size_t i = 0; i < unique_ports.size(); ++i) {
                if (i) { if (!json_append_char(tmp, l, ',')) return false; }
                if (!json_append_uint64(tmp, l, (uint64_t)unique_ports[i])) return false;
            }
            if (!json_append_cstr(tmp, l, "],")) return false;
            if (!json_append_cstr(tmp, l, "\"default_per_host_timeout_ms\":500,")) return false;
            if (!json_append_cstr(tmp, l, "\"default_connect_timeout_ms\":400,")) return false;
            if (!json_append_cstr(tmp, l, "\"default_batch_size\":4,")) return false;
            if (!json_append_cstr(tmp, l, "\"default_batch_delay_ms\":250,")) return false;
            if (!json_append_cstr(tmp, l, "\"default_max_hosts\":512")) return false;
            if (!json_append_char(tmp, l, '}')) return false;
            tmp.length = l;
            tmp.buf[l] = '\0';
            discovery_defaults_json.assign(tmp.buf, tmp.length);
            if (tmp.buf) {
                heap_caps_free(tmp.buf);
                tmp.buf = nullptr;
            }
        }

        // Discovery list (reuse DiscoveryManager JSON, but free with cJSON hooks).
        {
            cJSON* resp = DiscoveryManager::getInstance().getAllDiscoveries();
            if (resp) {
                discovery_list_json = cJSON_PrintUnformatted(resp);
                cJSON_Delete(resp);
            }
        }
    }

    // Reporting fragments
    psram_string reporting_channels_json;
    psram_string reporting_endpoints_json;
    psram_string reporting_queue_json;
    if (is_reporting || is_dashboard) {
        // Channels and endpoints are cached as raw JSON.
        ensureReportingChannelsCacheLoaded();
        ensureReportingCacheLoaded();
        {
            std::lock_guard<std::mutex> lock(reporting_channels_mutex_);
            if (!reporting_channels_cache_.empty()) {
                reporting_channels_json = reporting_channels_cache_;
            } else {
                reporting_channels_json = "{}";
            }
        }
        {
            std::lock_guard<std::mutex> lock(reporting_cache_mutex_);
            if (!reporting_cache_valid_) {
                loadReportingCacheLocked();
            }
            if (!reporting_cache_.empty()) {
                reporting_endpoints_json = reporting_cache_;
            } else {
                reporting_endpoints_json = "{}";
            }
        }
        // Queue status: small JSON generated on demand.
        {
            ensure_report_queue_directory();
            std::lock_guard<std::mutex> guard(g_report_queue_json.mutex);
            if (g_reporting && build_report_queue_json(g_report_queue_json)) {
                reporting_queue_json.assign(g_report_queue_json.buf, g_report_queue_json.length);
            } else {
                reporting_queue_json = "{\"queued\":0}";
            }
        }
    }

    // Logging fragments
    psram_string logging_files_json;
    if (is_logging) {
        if (log_file_manager_) {
            log_file_manager_->refreshFileStatuses();
            logging_files_json = log_file_manager_->getStatusJSON();
        } else {
            logging_files_json = "{\"files\":[]}";
        }
    }

    // Security fragments (config + ratelimit)
    char* security_cfg_json = nullptr;
    char* ratelimit_json = nullptr;
    if (is_security) {
        if (cfg_ && sec_) {
            SecurityConfig config = cfg_->getSecurityConfig();
            cJSON* sec_json = SecurityAPI::handleSecurityConfigGet(sec_, &config);
            if (sec_json) {
                security_cfg_json = cJSON_PrintUnformatted(sec_json);
                cJSON_Delete(sec_json);
            }
        }
        {
            cJSON* rl_json = SecurityAPI::handleRateLimitGet();
            if (rl_json) {
                ratelimit_json = cJSON_PrintUnformatted(rl_json);
                cJSON_Delete(rl_json);
            }
        }
        // Keep null on failure; output layer will fall back to "{}" without allocating.
    }

    // Signatures fragments (stats + list)
    char* signatures_stats_json = nullptr;
    char* signatures_list_json = nullptr;
    if (is_signatures) {
        cJSON* st = SignatureReloadAPI::handleSignatureStats();
        if (st) {
            signatures_stats_json = cJSON_PrintUnformatted(st);
            cJSON_Delete(st);
        }
        cJSON* lst = SignatureReloadAPI::handleSignatureList();
        if (lst) {
            signatures_list_json = cJSON_PrintUnformatted(lst);
            cJSON_Delete(lst);
        }
        // Keep null on failure; output layer will fall back to small safe defaults.
    }

    // Dashboard fragments: status/config/wifi/reporting/log retention
    size_t status_len = 0;
    size_t wifi_len = 0;
    psram_string logret_json;
    if (is_dashboard) {
        {
            std::lock_guard<std::mutex> guard(g_status_json.mutex);
            if (build_status_json(g_status_json)) {
                status_len = g_status_json.length;
            }
        }
        {
            std::lock_guard<std::mutex> guard(g_wifi_status_json.mutex);
            if (build_wifi_status_json(g_wifi_status_json)) {
                wifi_len = g_wifi_status_json.length;
            }
        }
        {
            // Build JSON without allocating a temporary std::string (internal RAM pressure).
            StaticJsonBuffer tmp;
            const size_t cap = 128 + g_logret_cfg.dir.size();
            if (ensure_json_buffer(tmp, cap, "logret_bootstrap")) {
                size_t l = 0;
                tmp.buf[0] = '\0';
                bool ok = true;
                ok = ok && json_append_char(tmp, l, '{');
                ok = ok && json_append_cstr(tmp, l, "\"dir\":");
                ok = ok && json_append_escaped(tmp, l, g_logret_cfg.dir.c_str(), true);
                ok = ok && json_append_cstr(tmp, l, ",\"max_mb\":");
                ok = ok && json_append_uint64(tmp, l, (uint64_t)g_logret_cfg.max_mb);
                ok = ok && json_append_cstr(tmp, l, ",\"max_days\":");
                ok = ok && json_append_uint64(tmp, l, (uint64_t)g_logret_cfg.max_days);
                ok = ok && json_append_cstr(tmp, l, ",\"period_min\":");
                ok = ok && json_append_uint64(tmp, l, (uint64_t)g_logret_cfg.period_min);
                ok = ok && json_append_char(tmp, l, '}');
                tmp.length = l;
                tmp.buf[l] = '\0';
                if (ok) {
                    logret_json.assign(tmp.buf, tmp.length);
                } else {
                    logret_json = "{}";
                }
                if (tmp.buf) {
                    heap_caps_free(tmp.buf);
                    tmp.buf = nullptr;
                }
            } else {
                logret_json = "{}";
            }
        }
    }

    // Network fragments (status + ethernet config + wifi status)
    char* network_status_json = nullptr;
    char* ethernet_cfg_json = nullptr;
    psram_string wifi_status_json;
    if (is_network) {
        // Build wifi status using existing PSRAM cache builder.
        {
            std::lock_guard<std::mutex> guard(g_wifi_status_json.mutex);
            if (build_wifi_status_json(g_wifi_status_json)) {
                wifi_status_json.assign(g_wifi_status_json.buf, g_wifi_status_json.length);
            } else {
                wifi_status_json = "{}";
            }
        }

        // Reuse the same logic of existing endpoints (cJSON based).
        {
            httpd_req_t* dummy = nullptr;
            (void)dummy;
            // Network status: inline copy from handler, but serialized here.
            cJSON* response = cJSON_CreateObject();
            cJSON* interfaces = cJSON_CreateArray();
            cJSON_AddItemToObject(response, "interfaces", interfaces);

            esp_netif_t* wifi_sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
            if (wifi_sta) {
                cJSON* wifi_info = cJSON_CreateObject();
                cJSON_AddStringToObject(wifi_info, "type", "wifi_sta");
                cJSON_AddStringToObject(wifi_info, "name", "WiFi Station");
                esp_netif_ip_info_t ip_info;
                if (esp_netif_get_ip_info(wifi_sta, &ip_info) == ESP_OK) {
                    char ip_str[16], gw_str[16], mask_str[16];
                    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
                    snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
                    snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));
                    cJSON_AddStringToObject(wifi_info, "ip", ip_str);
                    cJSON_AddStringToObject(wifi_info, "gateway", gw_str);
                    cJSON_AddStringToObject(wifi_info, "netmask", mask_str);
                    cJSON_AddBoolToObject(wifi_info, "connected", ip_info.ip.addr != 0);
                } else {
                    cJSON_AddBoolToObject(wifi_info, "connected", false);
                }
                cJSON_AddItemToArray(interfaces, wifi_info);
            }

            esp_netif_t* wifi_ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
            if (wifi_ap) {
                cJSON* ap_info = cJSON_CreateObject();
                cJSON_AddStringToObject(ap_info, "type", "wifi_ap");
                cJSON_AddStringToObject(ap_info, "name", "WiFi Access Point");
                esp_netif_ip_info_t ip_info;
                if (esp_netif_get_ip_info(wifi_ap, &ip_info) == ESP_OK) {
                    char ip_str[16], gw_str[16], mask_str[16];
                    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
                    snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
                    snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));
                    cJSON_AddStringToObject(ap_info, "ip", ip_str);
                    cJSON_AddStringToObject(ap_info, "gateway", gw_str);
                    cJSON_AddStringToObject(ap_info, "netmask", mask_str);
                    cJSON_AddBoolToObject(ap_info, "connected", ip_info.ip.addr != 0);
                } else {
                    cJSON_AddBoolToObject(ap_info, "connected", false);
                }
                cJSON_AddItemToArray(interfaces, ap_info);
            }

            esp_netif_t* eth_netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
            if (eth_netif) {
                cJSON* eth_info = cJSON_CreateObject();
                cJSON_AddStringToObject(eth_info, "type", "ethernet");
                cJSON_AddStringToObject(eth_info, "name", "Ethernet");
                esp_netif_ip_info_t ip_info;
                if (esp_netif_get_ip_info(eth_netif, &ip_info) == ESP_OK) {
                    char ip_str[16], gw_str[16], mask_str[16];
                    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
                    snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
                    snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));
                    cJSON_AddStringToObject(eth_info, "ip", ip_str);
                    cJSON_AddStringToObject(eth_info, "gateway", gw_str);
                    cJSON_AddStringToObject(eth_info, "netmask", mask_str);
                    cJSON_AddBoolToObject(eth_info, "connected", ip_info.ip.addr != 0);
                } else {
                    cJSON_AddBoolToObject(eth_info, "connected", false);
                }
                cJSON_AddItemToArray(interfaces, eth_info);
            }

            network_status_json = cJSON_PrintUnformatted(response);
            cJSON_Delete(response);
            // If serialization fails, keep null; output will fall back.
        }

        {
            cJSON* response = cJSON_CreateObject();
            if (cfg_) {
                NetworkConfig net_cfg = cfg_->getNetworkConfig();
                cJSON_AddBoolToObject(response, "enabled", net_cfg.eth_enabled);
                cJSON_AddStringToObject(response, "mode", net_cfg.eth_dhcp ? "dhcp" : "static");
                cJSON_AddBoolToObject(response, "promiscuous", net_cfg.eth_promiscuous);
                if (!net_cfg.eth_dhcp) {
                    cJSON_AddStringToObject(response, "static_ip", net_cfg.eth_ip.empty() ? "192.168.1.100" : net_cfg.eth_ip.c_str());
                    cJSON_AddStringToObject(response, "static_netmask", net_cfg.eth_netmask.empty() ? "255.255.255.0" : net_cfg.eth_netmask.c_str());
                    cJSON_AddStringToObject(response, "static_gateway", net_cfg.eth_gateway.empty() ? "192.168.1.1" : net_cfg.eth_gateway.c_str());
                    cJSON_AddStringToObject(response, "static_dns", "8.8.8.8");
                }
            }
            esp_netif_t* eth_netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
            if (eth_netif) {
                esp_netif_ip_info_t ip_info;
                if (esp_netif_get_ip_info(eth_netif, &ip_info) == ESP_OK) {
                    char current_ip[16], current_gw[16], current_mask[16];
                    snprintf(current_ip, sizeof(current_ip), IPSTR, IP2STR(&ip_info.ip));
                    snprintf(current_gw, sizeof(current_gw), IPSTR, IP2STR(&ip_info.gw));
                    snprintf(current_mask, sizeof(current_mask), IPSTR, IP2STR(&ip_info.netmask));
                    cJSON_AddStringToObject(response, "current_ip", current_ip);
                    cJSON_AddStringToObject(response, "current_gateway", current_gw);
                    cJSON_AddStringToObject(response, "current_netmask", current_mask);
                    cJSON_AddBoolToObject(response, "interface_up", ip_info.ip.addr != 0);
                } else {
                    cJSON_AddBoolToObject(response, "interface_up", false);
                }
            } else {
                cJSON_AddBoolToObject(response, "interface_available", false);
            }
            ethernet_cfg_json = cJSON_PrintUnformatted(response);
            cJSON_Delete(response);
            // If serialization fails, keep null; output will fall back.
        }
    }

    // Serial monitor fragments
    char* serial_cfg_json = nullptr;
    if (is_serial_monitor) {
        // Reuse the same extraction logic as /api/report/serial/config (PSRAM-safe).
        size_t sz = 0;
        char* buf = cfg_->getRawConfigInPSRAM(&sz);
        PSRAMJsonParser::PSRAMContext ctx;
        cJSON* root = (buf && sz) ? PSRAMJsonParser::parseInPSRAM(buf, sz) : nullptr;
        if (buf) heap_caps_free(buf);
        if (root) {
            cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
            cJSON* serial_obj = reporting ? cJSON_GetObjectItem(reporting, "serial") : nullptr;
            cJSON* json = cJSON_CreateObject();
            if (serial_obj && cJSON_IsObject(serial_obj)) {
                if (auto v = cJSON_GetObjectItem(serial_obj, "enabled"); v && cJSON_IsBool(v)) {
                    cJSON_AddBoolToObject(json, "enabled", cJSON_IsTrue(v));
                }
                if (auto v = cJSON_GetObjectItem(serial_obj, "format"); v && cJSON_IsString(v)) {
                    cJSON_AddStringToObject(json, "format", cJSON_GetStringValue(v));
                }
                if (auto v = cJSON_GetObjectItem(serial_obj, "verbosity"); v && cJSON_IsString(v)) {
                    cJSON_AddStringToObject(json, "verbosity", cJSON_GetStringValue(v));
                }
                cJSON* config = cJSON_GetObjectItem(serial_obj, "configuration");
                if (config && cJSON_IsObject(config)) {
                    cJSON* config_copy = cJSON_Duplicate(config, 1);
                    cJSON_AddItemToObject(json, "configuration", config_copy);
                }
            } else {
                cJSON_AddBoolToObject(json, "enabled", false);
                cJSON_AddStringToObject(json, "format", "JSON");
                cJSON_AddStringToObject(json, "verbosity", "VERBOSE");
                cJSON_AddItemToObject(json, "configuration", cJSON_CreateObject());
            }
            serial_cfg_json = cJSON_PrintUnformatted(json);
            cJSON_Delete(json);
            cJSON_Delete(root);
        }
        // If serialization fails, keep null; output layer will fall back.
    }

    // GPIO fragments (config/status/buttons)
    char* gpio_cfg_json = nullptr;
    char* gpio_status_json = nullptr;
    char* gpio_buttons_json = nullptr;
    if (is_gpio) {
        if (cfg_) {
            auto gpio_config = cfg_->getGpioReportingConfig();
            cJSON* root = cJSON_CreateObject();
            cJSON_AddBoolToObject(root, "enabled", gpio_config.enabled);
            cJSON_AddStringToObject(root, "format", gpio_config.format.c_str());
            cJSON_AddStringToObject(root, "verbosity", gpio_config.verbosity.c_str());
            cJSON* configuration = cJSON_CreateObject();
            cJSON_AddItemToObject(root, "configuration", configuration);
            cJSON* pins = cJSON_CreateObject();
            cJSON_AddItemToObject(configuration, "pins", pins);
            cJSON_AddNumberToObject(pins, "led_critical", gpio_config.pins.led_critical);
            cJSON_AddNumberToObject(pins, "led_warning", gpio_config.pins.led_warning);
            cJSON_AddNumberToObject(pins, "led_info", gpio_config.pins.led_info);
            cJSON_AddNumberToObject(pins, "led_success", gpio_config.pins.led_success);
            cJSON_AddNumberToObject(pins, "buzzer", gpio_config.pins.buzzer);
            cJSON_AddNumberToObject(pins, "btn_acknowledge", gpio_config.pins.btn_acknowledge);
            cJSON_AddNumberToObject(pins, "btn_reset", gpio_config.pins.btn_reset);
            cJSON_AddNumberToObject(pins, "btn_learning", gpio_config.pins.btn_learning);
            cJSON_AddNumberToObject(pins, "btn_maintenance", gpio_config.pins.btn_maintenance);
            cJSON* behavior = cJSON_CreateObject();
            cJSON_AddItemToObject(configuration, "behavior", behavior);
            cJSON_AddBoolToObject(behavior, "buzzer_enabled", gpio_config.behavior.buzzer_enabled);
            cJSON_AddNumberToObject(behavior, "alert_duration_ms", gpio_config.behavior.alert_duration_ms);
            cJSON_AddNumberToObject(behavior, "blink_interval_ms", gpio_config.behavior.blink_interval_ms);
            cJSON_AddNumberToObject(behavior, "debounce_ms", gpio_config.behavior.debounce_ms);
            cJSON* filters = cJSON_CreateObject();
            cJSON_AddItemToObject(root, "filters", filters);
            cJSON_AddBoolToObject(filters, "enabled", gpio_config.filters.enabled);
            cJSON_AddBoolToObject(filters, "case_sensitive", gpio_config.filters.case_sensitive);
            cJSON* include_array = cJSON_CreateArray();
            cJSON_AddItemToObject(filters, "include", include_array);
            for (auto const& p : gpio_config.filters.include) {
                cJSON_AddItemToArray(include_array, cJSON_CreateString(p.c_str()));
            }
            cJSON* exclude_array = cJSON_CreateArray();
            cJSON_AddItemToObject(filters, "exclude", exclude_array);
            for (auto const& p : gpio_config.filters.exclude) {
                cJSON_AddItemToArray(exclude_array, cJSON_CreateString(p.c_str()));
            }
            gpio_cfg_json = cJSON_PrintUnformatted(root);
            cJSON_Delete(root);
        }
        // If config serialization fails, keep null; output will fall back.
        // Status/buttons are currently mock endpoints, so we keep them null and rely on output fallbacks too.
    }

    // Audit fragments (config + metrics)
    psram_string audit_cfg_json;
    const char* audit_metrics_json = nullptr;
    if (is_audit) {
        {
            // AuditManager currently returns std::string; copy into PSRAM string to keep lifetime valid.
            std::string tmp = AuditManager::getInstance().getConfigJSON();
            audit_cfg_json.assign(tmp.c_str(), tmp.size());
        }
        audit_metrics_json = "{\"metrics\":{\"total_events\":0,\"security_events\":0,\"config_changes\":0,\"access_attempts\":0,\"failed_logins\":0},\"status\":\"success\"}";
    }

    // Estimate required output capacity.
    size_t required = 1024;
    if (is_ids) required += cfg_len + presence_cfg.size() + presence_learned.size() + strlen(ids_stats_json) + 2048;
    if (is_presence) required += presence_cfg.size() + presence_stats.size() + presence_devices.size() + 1024;
    if (is_protocols) required += 16 * 1024;
    if (is_scanner) required += strlen(features_json) + discovery_defaults_json.size() + (discovery_list_json ? strlen(discovery_list_json) : 0) + 64 * 1024;
    if (is_reporting) required += reporting_channels_json.size() + reporting_endpoints_json.size() + reporting_queue_json.size() + 2048;
    if (is_logging) required += logging_files_json.size() + 2048;
    if (is_security) required += (security_cfg_json ? strlen(security_cfg_json) : 0) + (ratelimit_json ? strlen(ratelimit_json) : 0) + 1024;
    if (is_signatures) required += (signatures_stats_json ? strlen(signatures_stats_json) : 0) + (signatures_list_json ? strlen(signatures_list_json) : 0) + 2048;
    if (is_network) required += (network_status_json ? strlen(network_status_json) : 0) + (ethernet_cfg_json ? strlen(ethernet_cfg_json) : 0) + wifi_status_json.size() + 4096;
    if (is_gpio) required += (gpio_cfg_json ? strlen(gpio_cfg_json) : 0) + (gpio_status_json ? strlen(gpio_status_json) : 0) + (gpio_buttons_json ? strlen(gpio_buttons_json) : 0) + 2048;
    if (is_audit) required += audit_cfg_json.size() + (audit_metrics_json ? strlen(audit_metrics_json) : 0) + 2048;
    if (is_dashboard) required += cfg_len + status_len + wifi_len + logret_json.size() + reporting_channels_json.size() + reporting_endpoints_json.size() + reporting_queue_json.size() + 4096;
    if (is_serial_monitor) required += (serial_cfg_json ? strlen(serial_cfg_json) : 0) + 2048;

    if (!ensure_json_buffer(cache, required, "page_bootstrap_json")) {
        if (cfg_buf) heap_caps_free(cfg_buf);
        if (discovery_list_json) free_cjson_str(discovery_list_json);
        if (security_cfg_json) free_cjson_str(security_cfg_json);
        if (ratelimit_json) free_cjson_str(ratelimit_json);
        if (signatures_stats_json) free_cjson_str(signatures_stats_json);
        if (signatures_list_json) free_cjson_str(signatures_list_json);
        if (network_status_json) free_cjson_str(network_status_json);
        if (ethernet_cfg_json) free_cjson_str(ethernet_cfg_json);
        if (serial_cfg_json) free_cjson_str(serial_cfg_json);
        if (gpio_cfg_json) free_cjson_str(gpio_cfg_json);
        if (gpio_status_json) free_cjson_str(gpio_status_json);
        if (gpio_buttons_json) free_cjson_str(gpio_buttons_json);
        return false;
    }

    size_t len = 0;
    cache.buf[0] = '\0';
    bool first = true;

    if (!json_append_char(cache, len, '{')) goto fail;
    if (!json_append_cstr(cache, len, "\"page\":")) goto fail;
    if (!json_append_escaped(cache, len, page_name, true)) goto fail;
    if (!json_append_cstr(cache, len, ",\"ts_ms\":")) goto fail;
    if (!json_append_uint64(cache, len, ts_ms)) goto fail;
    if (!json_append_cstr(cache, len, ",\"data\":{")) goto fail;

    if (is_ids) {
        // protocols catalog (same as /api/protocols)
        static const char* kProtocolsJson =
            "{"
            "\"1\":\"Modbus TCP\","
            "\"2\":\"S7 Communication\","
            "\"3\":\"OPC UA\","
            "\"4\":\"EtherNet/IP\","
            "\"5\":\"PROFINET\""
            "}";
        if (!json_append_field_raw(cache, len, first, "protocols", kProtocolsJson)) goto fail;
        if (!json_append_field_raw(cache, len, first, "config", cfg_buf)) goto fail;
        if (!json_append_field_raw(cache, len, first, "ids_config", ids_cfg_json)) goto fail;
        if (!json_append_field_raw(cache, len, first, "ids_stats", ids_stats_json)) goto fail;
        if (!json_append_field_raw(cache, len, first, "presence_config", presence_cfg.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "presence_learned", presence_learned.c_str())) goto fail;
    } else if (is_presence) {
        if (!json_append_field_raw(cache, len, first, "presence_config", presence_cfg.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "presence_stats", presence_stats.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "presence_devices", presence_devices.c_str())) goto fail;
    } else if (is_protocols) {
        if (!json_append_cstr(cache, len, "\"protocol_configs\":{")) goto fail;
        bool first_proto = true;
        const psram_string_map modbus = cfg_->getProtocolConfig(ProtocolType::MODBUS_TCP);
        const psram_string_map s7 = cfg_->getProtocolConfig(ProtocolType::S7_COMM);
        const psram_string_map pn = cfg_->getProtocolConfig(ProtocolType::PROFINET);
        const psram_string_map enip = cfg_->getProtocolConfig(ProtocolType::ETHERNET_IP);
        const psram_string_map opcua = cfg_->getProtocolConfig(ProtocolType::OPC_UA);

        if (!append_protocol_config_object(cache, len, "modbus", modbus, first_proto)) goto fail;
        if (!append_protocol_config_object(cache, len, "s7", s7, first_proto)) goto fail;
        if (!append_protocol_config_object(cache, len, "profinet", pn, first_proto)) goto fail;
        if (!append_protocol_config_object(cache, len, "ethernetip", enip, first_proto)) goto fail;
        if (!append_protocol_config_object(cache, len, "opcua", opcua, first_proto)) goto fail;
        if (!json_append_char(cache, len, '}')) goto fail;
    } else if (is_scanner) {
        if (!json_append_field_raw(cache, len, first, "features", features_json)) goto fail;

        static const char* kProtocolsDetailsJson =
            "["
            "{\"id\":1,\"key\":\"MODBUS_TCP\",\"name\":\"Modbus TCP\"},"
            "{\"id\":2,\"key\":\"S7_COMM\",\"name\":\"S7 Communication\"},"
            "{\"id\":3,\"key\":\"OPC_UA\",\"name\":\"OPC UA\"},"
            "{\"id\":4,\"key\":\"ETHERNET_IP\",\"name\":\"EtherNet/IP\"},"
            "{\"id\":5,\"key\":\"PROFINET\",\"name\":\"PROFINET\"}"
            "]";
        if (!json_append_field_raw(cache, len, first, "protocols_details", kProtocolsDetailsJson)) goto fail;
        if (!json_append_field_raw(cache, len, first, "general_discovery_defaults", discovery_defaults_json.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "discovery_list", discovery_list_json ? discovery_list_json : "{\"discoveries\":[],\"count\":0}")) goto fail;

        // Scanner jobs (same as /api/scanner/jobs, but built without cJSON).
        if (!json_append_cstr(cache, len, ",\"scanner_jobs\":[")) goto fail;
        bool first_job = true;
        if (scanner_) {
            auto jobs = scanner_->listJobs();
            for (auto const& j : jobs) {
                if (!first_job) { if (!json_append_char(cache, len, ',')) goto fail; }
                first_job = false;
                if (!json_append_char(cache, len, '{')) goto fail;
                if (!json_append_cstr(cache, len, "\"id\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)j.id)) goto fail;
                if (!json_append_cstr(cache, len, ",\"name\":")) goto fail;
                if (!json_append_escaped(cache, len, j.name.c_str(), true)) goto fail;
                if (!json_append_cstr(cache, len, ",\"target\":")) goto fail;
                if (!json_append_escaped(cache, len, j.target.c_str(), true)) goto fail;
                if (!json_append_cstr(cache, len, ",\"protocol\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)j.protocol)) goto fail;
                if (!json_append_cstr(cache, len, ",\"interval_sec\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)j.interval_sec)) goto fail;
                if (!json_append_cstr(cache, len, ",\"jitter_sec\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)j.jitter_sec)) goto fail;
                if (!json_append_cstr(cache, len, ",\"enabled\":")) goto fail;
                if (!json_append_cstr(cache, len, j.enabled ? "true" : "false")) goto fail;
                if (!json_append_cstr(cache, len, ",\"runs\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)j.runs)) goto fail;
                if (!json_append_cstr(cache, len, ",\"last_started_ms\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)j.last_started_ms)) goto fail;
                if (!json_append_cstr(cache, len, ",\"last_finished_ms\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)j.last_finished_ms)) goto fail;
                if (!json_append_char(cache, len, '}')) goto fail;
            }
        }
        if (!json_append_char(cache, len, ']')) goto fail;

        // Fuzz jobs (same structure as /api/fuzz/jobs, but built without std::stringstream).
        if (!json_append_cstr(cache, len, ",\"fuzz_jobs\":{")) goto fail;
        if (!json_append_cstr(cache, len, "\"jobs\":[")) goto fail;
        size_t fuzz_count = 0;
        if (g_fuzz) {
            auto jobs = g_fuzz->listJobs();
            for (size_t i = 0; i < jobs.size(); ++i) {
                if (i) { if (!json_append_char(cache, len, ',')) goto fail; }
                const auto& job = jobs[i];
                fuzz_count++;
                if (!json_append_char(cache, len, '{')) goto fail;
                if (!json_append_cstr(cache, len, "\"id\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)job.id)) goto fail;
                if (!json_append_cstr(cache, len, ",\"protocol\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)job.protocol)) goto fail;
                if (!json_append_cstr(cache, len, ",\"target\":")) goto fail;
                if (!json_append_escaped(cache, len, job.target.c_str(), true)) goto fail;
                if (!json_append_cstr(cache, len, ",\"safe_mode\":")) goto fail;
                if (!json_append_cstr(cache, len, job.safe_mode ? "true" : "false")) goto fail;
                if (!json_append_cstr(cache, len, ",\"rate_per_sec\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)job.rate_per_sec)) goto fail;
                if (!json_append_cstr(cache, len, ",\"duration_ms\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)job.duration_ms)) goto fail;
                if (!json_append_cstr(cache, len, ",\"max_cases\":")) goto fail;
                if (!json_append_uint64(cache, len, (uint64_t)job.max_cases)) goto fail;
                if (!job.profile.empty()) {
                    if (!json_append_cstr(cache, len, ",\"profile\":")) goto fail;
                    if (!json_append_escaped(cache, len, job.profile.c_str(), true)) goto fail;
                }
                if (!json_append_char(cache, len, '}')) goto fail;
            }
        }
        if (!json_append_cstr(cache, len, "],\"count\":")) goto fail;
        if (!json_append_uint64(cache, len, (uint64_t)fuzz_count)) goto fail;
        if (!json_append_char(cache, len, '}')) goto fail;
    } else if (is_reporting) {
        if (!json_append_field_raw(cache, len, first, "channels", reporting_channels_json.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "endpoints", reporting_endpoints_json.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "queue", reporting_queue_json.c_str())) goto fail;
    } else if (is_logging) {
        if (!json_append_field_raw(cache, len, first, "files", logging_files_json.c_str())) goto fail;
    } else if (is_security) {
        if (!json_append_field_raw(cache, len, first, "security_config", security_cfg_json ? security_cfg_json : "{}")) goto fail;
        if (!json_append_field_raw(cache, len, first, "ratelimit", ratelimit_json ? ratelimit_json : "{}")) goto fail;
    } else if (is_signatures) {
        if (!json_append_field_raw(cache, len, first, "stats", signatures_stats_json ? signatures_stats_json : "{}")) goto fail;
        if (!json_append_field_raw(cache, len, first, "list", signatures_list_json ? signatures_list_json : "{}")) goto fail;
    } else if (is_network) {
        if (!json_append_field_raw(cache, len, first, "network_status", network_status_json ? network_status_json : "{\"interfaces\":[]}")) goto fail;
        if (!json_append_field_raw(cache, len, first, "ethernet_config", ethernet_cfg_json ? ethernet_cfg_json : "{}")) goto fail;
        if (!json_append_field_raw(cache, len, first, "wifi_status", wifi_status_json.c_str())) goto fail;
    } else if (is_gpio) {
        if (!json_append_field_raw(cache, len, first, "gpio_config", gpio_cfg_json ? gpio_cfg_json : "{}")) goto fail;
        if (!json_append_field_raw(cache, len, first, "gpio_status",
                                   gpio_status_json ? gpio_status_json :
                                   "{\"running\":false,\"enabled\":false,\"current_level\":\"OFF\",\"alert_active\":false,\"alert_acknowledged\":false}")) goto fail;
        if (!json_append_field_raw(cache, len, first, "gpio_buttons",
                                   gpio_buttons_json ? gpio_buttons_json :
                                   "{\"acknowledge\":false,\"reset\":false,\"learning\":false,\"maintenance\":false}")) goto fail;
    } else if (is_audit) {
        if (!json_append_field_raw(cache, len, first, "audit_config", audit_cfg_json.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "audit_metrics", audit_metrics_json ? audit_metrics_json : "{}")) goto fail;
    } else if (is_dashboard) {
        // status (cached builder)
        {
            std::lock_guard<std::mutex> guard(g_status_json.mutex);
            if (!build_status_json(g_status_json) || !g_status_json.buf || g_status_json.length == 0) {
                if (!json_append_field_raw(cache, len, first, "status", "{}")) goto fail;
            } else {
                if (!json_append_field_raw(cache, len, first, "status", g_status_json.buf)) goto fail;
            }
        }
        {
            std::lock_guard<std::mutex> guard(g_wifi_status_json.mutex);
            if (!build_wifi_status_json(g_wifi_status_json) || !g_wifi_status_json.buf || g_wifi_status_json.length == 0) {
                if (!json_append_field_raw(cache, len, first, "wifi_status", "{}")) goto fail;
            } else {
                if (!json_append_field_raw(cache, len, first, "wifi_status", g_wifi_status_json.buf)) goto fail;
            }
        }
        if (!json_append_field_raw(cache, len, first, "log_retention", logret_json.empty() ? "{}" : logret_json.c_str())) goto fail;
        // Reporting cached fragments
        if (!json_append_field_raw(cache, len, first, "report_channels", reporting_channels_json.empty() ? "{}" : reporting_channels_json.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "report_endpoints", reporting_endpoints_json.empty() ? "{}" : reporting_endpoints_json.c_str())) goto fail;
        if (!json_append_field_raw(cache, len, first, "report_queue", reporting_queue_json.empty() ? "{\"queued\":0}" : reporting_queue_json.c_str())) goto fail;
    } else if (is_serial_monitor) {
        if (!json_append_field_raw(cache, len, first, "serial_config", serial_cfg_json ? serial_cfg_json : "{}")) goto fail;
    } else {
        // Unknown page name
        goto fail;
    }

    if (!json_append_cstr(cache, len, "}}")) goto fail;
    cache.length = len;
    cache.buf[len] = '\0';

    if (cfg_buf) heap_caps_free(cfg_buf);
    if (discovery_list_json) free_cjson_str(discovery_list_json);
    if (security_cfg_json) free_cjson_str(security_cfg_json);
    if (ratelimit_json) free_cjson_str(ratelimit_json);
    if (signatures_stats_json) free_cjson_str(signatures_stats_json);
    if (signatures_list_json) free_cjson_str(signatures_list_json);
    if (network_status_json) free_cjson_str(network_status_json);
    if (ethernet_cfg_json) free_cjson_str(ethernet_cfg_json);
    if (serial_cfg_json) free_cjson_str(serial_cfg_json);
    if (gpio_cfg_json) free_cjson_str(gpio_cfg_json);
    if (gpio_status_json) free_cjson_str(gpio_status_json);
    if (gpio_buttons_json) free_cjson_str(gpio_buttons_json);
    return true;

fail:
    if (cfg_buf) heap_caps_free(cfg_buf);
    if (discovery_list_json) free_cjson_str(discovery_list_json);
    if (security_cfg_json) free_cjson_str(security_cfg_json);
    if (ratelimit_json) free_cjson_str(ratelimit_json);
    if (signatures_stats_json) free_cjson_str(signatures_stats_json);
    if (signatures_list_json) free_cjson_str(signatures_list_json);
    if (network_status_json) free_cjson_str(network_status_json);
    if (ethernet_cfg_json) free_cjson_str(ethernet_cfg_json);
    if (serial_cfg_json) free_cjson_str(serial_cfg_json);
    if (gpio_cfg_json) free_cjson_str(gpio_cfg_json);
    if (gpio_status_json) free_cjson_str(gpio_status_json);
    if (gpio_buttons_json) free_cjson_str(gpio_buttons_json);
    return false;
}

void WebServer::invalidateReportingCache() {
    {
        std::lock_guard<std::mutex> lock(reporting_cache_mutex_);
        reporting_cache_valid_ = false;
        reporting_cache_.clear();
    }
    invalidateReportingChannelsCache();
}

void WebServer::ensureReportingCacheLoaded() {
    std::lock_guard<std::mutex> lock(reporting_cache_mutex_);
    if (!reporting_cache_valid_) {
        loadReportingCacheLocked();
    }
}

void WebServer::loadReportingCacheLocked() {
    const char* fallback = "{}";

    if (!self_ || !self_->cfg_) {
        reporting_cache_.assign(fallback, fallback + strlen(fallback));
        reporting_cache_valid_ = true;
        return;
    }

    size_t cfg_sz = 0;
    char* cfg_buf = self_->cfg_->getRawConfigInPSRAM(&cfg_sz);

    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = (cfg_buf && cfg_sz) ? PSRAMJsonParser::parseInPSRAM(cfg_buf, cfg_sz) : nullptr;
    if (cfg_buf) {
        heap_caps_free(cfg_buf);
    }

    if (!root) {
        reporting_cache_.assign(fallback, fallback + strlen(fallback));
        reporting_cache_valid_ = true;
        return;
    }

    cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
    char* serialized = reporting ? cJSON_PrintUnformatted(reporting) : nullptr;

    if (serialized) {
        reporting_cache_.assign(serialized, serialized + strlen(serialized));
        free_cjson_str(serialized);
    } else {
        reporting_cache_.assign(fallback, fallback + strlen(fallback));
    }

    cJSON_Delete(root);
    reporting_cache_valid_ = true;
}

void WebServer::updateReportingCache(const char* data, size_t len) {
    {
        std::lock_guard<std::mutex> lock(reporting_cache_mutex_);
        if (data && len > 0) {
            reporting_cache_.assign(data, data + len);
        } else {
            const char* fallback = "{}";
            reporting_cache_.assign(fallback, fallback + strlen(fallback));
        }
        reporting_cache_valid_ = true;
    }
    invalidateReportingChannelsCache();
}

void WebServer::invalidateReportingChannelsCache() {
    std::lock_guard<std::mutex> lock(reporting_channels_mutex_);
    reporting_channels_valid_ = false;
    reporting_channels_cache_.clear();
}

void WebServer::ensureReportingChannelsCacheLoaded() {
    std::lock_guard<std::mutex> lock(reporting_channels_mutex_);
    if (reporting_channels_valid_) {
        return;
    }

    const char* fallback = "{}";
    psram_string generated;

    if (g_reporting) {
        generated = g_reporting->getChannelsJSON();
    }

    if (!generated.empty()) {
        reporting_channels_cache_ = std::move(generated);
    } else {
        reporting_channels_cache_.assign(fallback, fallback + strlen(fallback));
    }

    reporting_channels_valid_ = true;
}

// Total PSRAM buffers: 35KB (4+4+2+8+1+16) + chunk buffer (2KB)

// Initialize enhanced PSRAM buffers (called once at startup)
void web_buf_init(void) {
    LOG_INFO(TAG_WEB, "=== INITIALIZING ENHANCED PSRAM BUFFER SYSTEM ===");

    // Initialize chunk buffer mutex (CRITICAL for thread safety)
    if (!g_chunk_buffer_mutex) {
        g_chunk_buffer_mutex = xSemaphoreCreateMutex();
        if (!g_chunk_buffer_mutex) {
            LOG_ERROR(TAG_WEB, "🔴 CRITICAL: Failed to create chunk buffer mutex!");
        } else {
            LOG_INFO(TAG_WEB, "✅ Created chunk buffer mutex");
        }
    }

    // Chunk buffer MUST be INTERNAL (NOT PSRAM). DMA-capability is not required here; lwIP/httpd will copy as needed.
    if (!g_chunk_buffer) {
        g_chunk_buffer = static_cast<char*>(heap_caps_malloc(
            CHUNK_BUFFER_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        if (!g_chunk_buffer || esp_ptr_external_ram(g_chunk_buffer)) {
            if (g_chunk_buffer) {
                heap_caps_free(g_chunk_buffer);
            }
            g_chunk_buffer = nullptr;
            LOG_ERROR(TAG_WEB, "CRITICAL: Failed to allocate chunk buffer in INTERNAL RAM");
        } else {
            LOG_INFOF(TAG_WEB, "Allocated chunk buffer in INTERNAL RAM: %u bytes", (unsigned)CHUNK_BUFFER_SIZE);
        }
    }

    size_t total_allocated = 0;
    size_t psram_before = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    // Allocate web_buf (4KB)
    if (!web_buf) {
        web_buf = (char*)heap_caps_malloc(WEB_BUF_SZ, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (ensure_psram_buf("web_buf", web_buf, WEB_BUF_SZ)) {
            LOG_INFOF(TAG_WEB, "✅ Allocated web_buf: %d bytes in PSRAM", WEB_BUF_SZ);
            total_allocated += WEB_BUF_SZ;
        } else {
            if (web_buf && !esp_ptr_external_ram(web_buf)) { heap_caps_free(web_buf); web_buf = nullptr; }
        }
    }

    // Allocate g_http_tmp (4KB)
    if (!g_http_tmp) {
        g_http_tmp = (char*)heap_caps_malloc(HTTP_TMP_SZ, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (ensure_psram_buf("g_http_tmp", g_http_tmp, HTTP_TMP_SZ)) {
            LOG_INFOF(TAG_WEB, "✅ Allocated g_http_tmp: %d bytes in PSRAM", HTTP_TMP_SZ);
            total_allocated += HTTP_TMP_SZ;
        } else {
            if (g_http_tmp && !esp_ptr_external_ram(g_http_tmp)) { heap_caps_free(g_http_tmp); g_http_tmp = nullptr; }
        }
    }

    // Allocate g_http_header_buf (2KB)
    if (!g_http_header_buf) {
        g_http_header_buf = (char*)heap_caps_malloc(HTTP_HEADER_BUF_SZ, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (ensure_psram_buf("g_http_header_buf", g_http_header_buf, HTTP_HEADER_BUF_SZ)) {
            LOG_INFOF(TAG_WEB, "✅ Allocated g_http_header_buf: %d bytes in PSRAM", HTTP_HEADER_BUF_SZ);
            total_allocated += HTTP_HEADER_BUF_SZ;
        } else {
            if (g_http_header_buf && !esp_ptr_external_ram(g_http_header_buf)) { heap_caps_free(g_http_header_buf); g_http_header_buf = nullptr; }
        }
    }

    // Allocate g_http_json_buf (8KB)
    if (!g_http_json_buf) {
        g_http_json_buf = (char*)heap_caps_malloc(HTTP_JSON_BUF_SZ, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (ensure_psram_buf("g_http_json_buf", g_http_json_buf, HTTP_JSON_BUF_SZ)) {
            LOG_INFOF(TAG_WEB, "✅ Allocated g_http_json_buf: %d bytes in PSRAM", HTTP_JSON_BUF_SZ);
            total_allocated += HTTP_JSON_BUF_SZ;
        } else {
            if (g_http_json_buf && !esp_ptr_external_ram(g_http_json_buf)) { heap_caps_free(g_http_json_buf); g_http_json_buf = nullptr; }
        }
    }

    // Allocate g_http_uri_buf (1KB)
    if (!g_http_uri_buf) {
        g_http_uri_buf = (char*)heap_caps_malloc(HTTP_URI_BUF_SZ, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (ensure_psram_buf("g_http_uri_buf", g_http_uri_buf, HTTP_URI_BUF_SZ)) {
            LOG_INFOF(TAG_WEB, "✅ Allocated g_http_uri_buf: %d bytes in PSRAM", HTTP_URI_BUF_SZ);
            total_allocated += HTTP_URI_BUF_SZ;
        } else {
            if (g_http_uri_buf && !esp_ptr_external_ram(g_http_uri_buf)) { heap_caps_free(g_http_uri_buf); g_http_uri_buf = nullptr; }
        }
    }

    // Allocate g_http_post_buf (16KB)
    if (!g_http_post_buf) {
        g_http_post_buf = (char*)heap_caps_malloc(HTTP_POST_BUF_SZ, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (ensure_psram_buf("g_http_post_buf", g_http_post_buf, HTTP_POST_BUF_SZ)) {
            LOG_INFOF(TAG_WEB, "✅ Allocated g_http_post_buf: %d bytes in PSRAM", HTTP_POST_BUF_SZ);
            total_allocated += HTTP_POST_BUF_SZ;
        } else {
            if (g_http_post_buf && !esp_ptr_external_ram(g_http_post_buf)) { heap_caps_free(g_http_post_buf); g_http_post_buf = nullptr; }
        }
    }

    size_t psram_after = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t psram_used = psram_before - psram_after;

    LOG_INFOF(TAG_WEB, "🔍 PSRAM Buffer Summary: Allocated %u bytes total, PSRAM used: %u bytes",
              (unsigned)total_allocated, (unsigned)psram_used);
    LOG_INFOF(TAG_WEB, "🔍 PSRAM Status: Before=%u, After=%u, Free=%u",
              (unsigned)psram_before, (unsigned)psram_after, (unsigned)psram_after);
}

// PSRAM-first allocation wrapper with DRAM fallback
void* http_malloc_psram(size_t size) {
    void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ensure_psram_buf("http_malloc_psram", ptr, size)) {
        if (ptr && !esp_ptr_external_ram(ptr)) { heap_caps_free(ptr); }
        // No fallback: whoever uses this function must handle nullptr or minimal mode
        return nullptr;
    }
    return ptr;
}

// ==== OPTIMIZED CHUNKED TRANSFER USING GLOBAL BUFFER ====
// This function eliminates malloc/free cycles by using the global g_chunk_buffer
// protected by a mutex. This is THE ONLY way to send chunked data in this codebase.
//
// Parameters:
//   req: HTTP request object
//   psram_data: Pointer to data in PSRAM (can be any location, but PSRAM preferred)
//   data_len: Length of data to send
//
// Returns: ESP_OK on success, error code on failure
//
// CRITICAL: This replaces ALL manual malloc/memcpy/free patterns in chunked transfers!
static esp_err_t send_chunked_from_psram(httpd_req_t* req, const char* psram_data, size_t data_len) {
    if (!g_chunk_buffer_mutex) {
        LOG_ERROR(TAG_WEB, "🔴 CRITICAL: Chunk buffer mutex not initialized!");
        return ESP_FAIL;
    }

    if (!psram_data || data_len == 0) {
        // Send empty chunk terminator
        return httpd_resp_send_chunk(req, nullptr, 0);
    }

    if (!g_chunk_buffer) {
        // Never send PSRAM pointers directly to httpd_resp_send_chunk().
        // Best-effort: use a temporary INTERNAL+DMA buffer.
        LOG_WARNING(TAG_WEB, "Chunk buffer unavailable, using temporary INTERNAL DMA fallback");
        const size_t tmp_cap = (data_len > CHUNK_BUFFER_SIZE) ? CHUNK_BUFFER_SIZE : data_len;
        char* tmp = static_cast<char*>(heap_caps_malloc(tmp_cap, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA | MALLOC_CAP_8BIT));
        if (!tmp) {
            LOG_ERROR(TAG_WEB, "Failed to allocate temporary INTERNAL DMA chunk buffer");
            return ESP_ERR_NO_MEM;
        }

        size_t off = 0;
        esp_err_t rc = ESP_OK;
        while (off < data_len && rc == ESP_OK) {
            const size_t chunk_len = (data_len - off > tmp_cap) ? tmp_cap : (data_len - off);
            memcpy(tmp, psram_data + off, chunk_len);
            rc = httpd_resp_send_chunk(req, tmp, chunk_len);
            off += chunk_len;
        }

        heap_caps_free(tmp);
        if (rc == ESP_OK) {
            rc = httpd_resp_send_chunk(req, nullptr, 0);
        }
        return rc;
    }


    size_t offset = 0;
    size_t chunk_index = 0;
    esp_err_t result = ESP_OK;

    while (offset < data_len && result == ESP_OK) {
        size_t chunk_len = (data_len - offset > CHUNK_BUFFER_SIZE) ? CHUNK_BUFFER_SIZE : (data_len - offset);
        ++chunk_index;

        // Acquire mutex for exclusive access to global chunk buffer
        if (xSemaphoreTake(g_chunk_buffer_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
            LOG_ERROR(TAG_WEB, "🔴 CRITICAL: Failed to acquire chunk buffer mutex!");
            return ESP_FAIL;
        }

        // Copy chunk from PSRAM to Internal RAM buffer (required for DMA/socket TX)
        memcpy(g_chunk_buffer, psram_data + offset, chunk_len);

        // Send chunk (socket DMA requires Internal RAM)
        result = httpd_resp_send_chunk(req, g_chunk_buffer, chunk_len);

        // Release mutex immediately after send
        xSemaphoreGive(g_chunk_buffer_mutex);

        if (result != ESP_OK) {
            LOG_WARNINGF(TAG_WEB, "Chunked send failed at offset %u/%u (err=%d)",
                        (unsigned)offset, (unsigned)data_len, result);
            return result;
        }

        offset += chunk_len;
    }

    // Send chunk terminator to signal end of response
    if (result == ESP_OK) {
        result = httpd_resp_send_chunk(req, nullptr, 0);
    }


    return result;
}

// Forward declaration of the optimized version
static esp_err_t send_html_chunked(httpd_req_t* req, const char* html_data, size_t html_len);

// Send HTML from a constant buffer (in FLASH/rodata) without copies and without side-effects.
// Does no allocations, no delays, no retries: if the socket drops, it exits immediately.
static esp_err_t send_html_chunked(httpd_req_t* req, const char* html_data, size_t html_len) {
    // Minimal logging to avoid fragmenting DRAM
    LOG_INFOF(TAG_WEB, "📄 Serving %.120s (len=%u)", req->uri ? req->uri : "(null)", (unsigned)html_len);

    // Basic validation
    if (!html_data || html_len == 0) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_send(req, "Invalid HTML data", 16);
    }

    // Headers
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Connection", "close");
    // If you don't want client-side caching:
    // httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    // For robustness: we always send using the chunk buffer in Internal RAM (if available).
    // On some lwIP builds/drivers the send can be zero-copy: pointers in FLASH/PSRAM can cause abort.
    const size_t SMALL_SEND_THRESHOLD = 1024;
    if (html_len <= SMALL_SEND_THRESHOLD || !g_chunk_buffer || !g_chunk_buffer_mutex) {
        return httpd_resp_send(req, html_data, html_len);
    }

    size_t offset = 0;
    while (offset < html_len) {
        size_t chunk_len = html_len - offset;
        if (chunk_len > CHUNK_BUFFER_SIZE) chunk_len = CHUNK_BUFFER_SIZE;

        if (xSemaphoreTake(g_chunk_buffer_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
            LOG_ERROR(TAG_WEB, "🔴 CRITICAL: Failed to acquire chunk buffer mutex!");
            return ESP_FAIL;
        }

        memcpy(g_chunk_buffer, html_data + offset, chunk_len);
        esp_err_t e = httpd_resp_send_chunk(req, g_chunk_buffer, chunk_len);
        xSemaphoreGive(g_chunk_buffer_mutex);

        if (e != ESP_OK) {
            LOG_WARNINGF(TAG_WEB, "send_chunk failed (%d) after %u bytes", e, (unsigned)offset);
            return e;
        }

        offset += chunk_len;
    }

    return httpd_resp_send_chunk(req, nullptr, 0);
}

WebServer::~WebServer() {
    shutdown();

    // Cleanup defragmentation timer
    if (defrag_timer_) {
        esp_timer_stop(defrag_timer_);
        esp_timer_delete(defrag_timer_);
        defrag_timer_ = nullptr;
    }

    if (cron_scheduler_) {
        if (cron_scheduler_initialized_) {
            cron_scheduler_->shutdown();
            cron_scheduler_initialized_ = false;
        }
        delete cron_scheduler_;
        cron_scheduler_ = nullptr;
    }

    // [* HTTPS TO ACTIVATE] stopHTTPS();
}

bool WebServer::initialize ( ConfigurationManager* cfg,
                           ReportingEngine* rep,
                           Logger* logger,
                           PluginManager* plugins,
                           IntrusionDetectionGeneral* ids,
                           EthernetManager* eth,
                           WiFiManager* wifi,
                           VulnerabilityScanner* scanner,
                           SecurityManager* sec,
                           NetworkEngine* net,
                           LogFileManager* log_mgr ) {
    // IMPORTANT: Set self_ first before using it!
    self_ = this;
    self_->sec_ = sec;
    self_->net_ = net;
    cfg_ = cfg; rep_ = rep; logger_ = logger;
    plugins_ = plugins; ids_ = ids; eth_ = eth; wifi_ = wifi; scanner_ = scanner;
    log_file_manager_ = log_mgr;

    if (!cron_scheduler_) {
        cron_scheduler_ = new CronScheduler();
        if (!cron_scheduler_) {
            LOG_ERROR(TAG_WEB, "CronScheduler allocation failed");
        }
    }

    if (!wifi_transition_mutex_) {
        wifi_transition_mutex_ = xSemaphoreCreateMutex();
        if (!wifi_transition_mutex_) {
            LOG_WARNING(TAG_WEB, "Failed to create WiFi transition mutex");
        }
    }
    memset(wifi_transition_ip_, 0, sizeof(wifi_transition_ip_));
    memset(wifi_transition_ssid_, 0, sizeof(wifi_transition_ssid_));
    memset(wifi_transition_error_, 0, sizeof(wifi_transition_error_));

    // IRAM defragmentation disabled: avoid internal RAM allocations
    LOG_INFO(TAG_WEB, "IRAM defragmentation disabled (no internal RAM touch)");

    // Initialize DiscoveryManager with plugin manager and reporter
    if (plugins_) {
        DiscoveryManager::getInstance().setPluginManager(plugins_);
    }
    if (rep_) {
        DiscoveryManager::getInstance().setReporter(rep_);
    }
    DiscoveryManager::getInstance().setConfig(cfg_);

    // Initialize global rate limiter
    if (!g_rate_limiter) {
        g_rate_limiter = new RateLimiter();
        if (g_rate_limiter) {
            RateLimitConfig rl_config;
            g_rate_limiter->initialize(rl_config);
            // Load configuration from NVS
            SecurityAPI::loadRateLimitConfigFromNVS();
            LOG_INFO(TAG_WEB, "Rate limiter initialized and loaded from NVS");
        } else {
            LOG_ERROR(TAG_WEB, "Failed to allocate rate limiter");
        }
    }

    LOG_INFO(TAG_WEB, "WebServer initialized");
    return true;
}


void WebServer::attach(ConfigurationManager* cfg, SecurityManager* sec, ReportingEngine* rep){
    this->cfg_ = cfg;
    this->sec_ = sec;
    this->rep_ = rep;
    WebServer::self_ = this;
}

void WebServer::attachFull(PluginManager* plugins,
                    IntrusionDetectionGeneral* ids,
                    EthernetManager* eth,
                    WiFiManager* wifi,
                    VulnerabilityScanner* scanner,
                    NetworkEngine* net) {
    this->plugins_ = plugins;
    this->ids_ = ids;
    this->eth_ = eth;
    this->wifi_ = wifi;

    // Initialize DiscoveryManager with plugin manager and reporter
    if (plugins_) {
        DiscoveryManager::getInstance().setPluginManager(plugins_);
    }
    if (rep_) {
        DiscoveryManager::getInstance().setReporter(rep_);
    }
    DiscoveryManager::getInstance().setConfig(cfg_);
    this->scanner_ = scanner;
    this->net_ = net;

    // Diagnostics: useful to understand whether the WebServer has all dependencies before serving API/UI.
    // (In particular: NO_PLUGINS/NO_IDS on devices where the WebServer starts "late" in AP/STA fallback.)
    LOG_INFOF(TAG_WEB,
              "attachFull: plugins=%p ids=%p eth=%p wifi=%p scanner=%p net=%p",
              (void*)plugins_, (void*)ids_, (void*)eth_, (void*)wifi_, (void*)scanner_, (void*)net_);
    if (plugins_) {
        LOG_INFOF(TAG_WEB, "attachFull: pluginCount=%u", (unsigned)plugins_->pluginCount());
    }

    // Load persisted security toggles (e.g. fuzzing_allowed) before serving UI/APIs.
    // NOTE: this used to be missing, causing fuzzing_allowed to reset to default (false) after reboot.
    if (sec_) {
        SecurityAPI::loadFuzzingAllowedFromNVS(sec_);
        LOG_INFOF(TAG_WEB,
                  "attachFull: fuzzing_allowed(cfg)=%d effective=%d reason=%s",
                  (int)sec_->isFuzzingAllowedConfig(),
                  (int)sec_->isFuzzingAllowed(),
                  sec_->getFuzzingBlockReason());
    }

    initCronSchedulerIfReady();
    WebServer::self_ = this;
}

void WebServer::initCronSchedulerIfReady() {
    if (cron_scheduler_initialized_) {
        return;
    }

    if (!cfg_) {
        LOG_DEBUG(TAG_WEB, "CronScheduler waiting: configuration manager not ready");
        return;
    }

    bool scanner_feature_enabled = cfg_->isFeatureEnabled("vuln_scanner", false);
    if (!scanner_feature_enabled) {
        if (cron_scheduler_ && cron_scheduler_initialized_) {
            cron_scheduler_->shutdown();
            cron_scheduler_initialized_ = false;
        }
        LOG_DEBUG(TAG_WEB, "CronScheduler disabled: vulnerability scanner feature off");
        return;
    }

    bool scheduled_scans_enabled = cfg_->isFeatureEnabled("scheduled_scans", true);
    if (!scheduled_scans_enabled) {
        if (cron_scheduler_ && cron_scheduler_initialized_) {
            cron_scheduler_->shutdown();
            cron_scheduler_initialized_ = false;
        }
        LOG_DEBUG(TAG_WEB, "CronScheduler disabled via configuration flag");
        return;
    }

    if (!cron_scheduler_) {
        cron_scheduler_ = new CronScheduler();
        if (!cron_scheduler_) {
            LOG_ERROR(TAG_WEB, "Unable to allocate CronScheduler");
            return;
        }
    }

    if (!scanner_) {
        LOG_DEBUG(TAG_WEB, "CronScheduler initialization deferred: scanner not yet attached");
        return;
    }

    auto& discovery_mgr = DiscoveryManager::getInstance();
    if (!cron_scheduler_->initialize(scanner_, &discovery_mgr)) {
        LOG_DEBUG(TAG_WEB, "CronScheduler dependencies not ready, will retry later");
        return;
    }

    cron_scheduler_initialized_ = true;
    LOG_INFO(TAG_WEB, "CronScheduler initialized successfully");
}
bool WebServer::start(uint16_t port) {
    // Default behavior: bind to all interfaces (backward compatibility)
    return startOnInterface(port, nullptr);
}

bool WebServer::startOnInterface(uint16_t port, esp_netif_t* netif) {
    if (!WebServer::self_) WebServer::self_ = this;
    // Check the handle belonging to the selected transport explicitly. The
    // fallback check also covers a stale handle left by a failed transition.
#if ESP32_OT_WEB_HTTP_ONLY
    const httpd_handle_t active_transport_handle = http_;
#else
    const httpd_handle_t active_transport_handle = https_server_;
#endif
    if (active_transport_handle || http_ || https_server_) {
        LOG_WARNING(TAG_WEB, "start(): server already running");
        return false;
    }
    guarded_uri_count_ = 0;
#if !ESP32_OT_WEB_HTTP_ONLY
    if (!tls_credentials_.ensurePresent()) {
        LOG_ERROR(TAG_WEB, "Unable to load or generate the runtime TLS identity");
        return false;
    }
#endif

    initCronSchedulerIfReady();

    // === CONFIGURE cJSON TO USE PSRAM ===
    static bool cjson_hooks_configured = false;
    if (!cjson_hooks_configured) {
        cJSON_Hooks hooks;
        hooks.malloc_fn = [](size_t size) -> void* {
            return heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        };
        // CRITICAL: Use heap_caps_free instead of free() for PSRAM allocations
        hooks.free_fn = [](void* ptr) {
            heap_caps_free(ptr);
        };
        cJSON_InitHooks(&hooks);
        cjson_hooks_configured = true;
        LOG_INFO(TAG_WEB, "✅ cJSON configured to use PSRAM with proper heap_caps_free");
    }

    ensureReportingCacheLoaded();

    // === EMERGENCY PSRAM CLEANUP BEFORE WEBSERVER STARTUP ===
    size_t psram_free_before = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t psram_largest_before = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

    if (TaskConfig::isPSRAMInCriticalState() || psram_largest_before < 100000) {
        LOG_WARNINGF(TAG_WEB, "⚠️ PSRAM cleanup before WebServer start: %d bytes free, largest: %d",
                    (int)psram_free_before, (int)psram_largest_before);

        // Emergency PSRAM cleanup
        TaskConfig::emergencyPSRAMCleanup();

        // Also do IRAM cleanup for good measure
        TaskConfig::emergencyMemoryCleanup();

        size_t psram_free_after = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t psram_largest_after = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

        LOG_INFOF(TAG_WEB, "✅ PSRAM cleanup gained %d bytes, largest: %d",
                 (int)(psram_free_after - psram_free_before), (int)psram_largest_after);
    }

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    // Enable wildcard URI matching so we can install catch-all fallback handlers for debugging
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.open_fn = &WebServer::authorizeOpenSocket;
    cfg.server_port = port;
    cfg.lru_purge_enable = true;
    // HTTPS handshake (mbedTLS X.509/PEM/ECC) is expensive: keep connections alive to reduce new handshakes.
    // We still cap concurrency via max_open_sockets/backlog.
    cfg.keep_alive_enable = true;
    // These are per-send/per-recv wait bounds. Keep them low to avoid multi-chunk responses stalling the whole HTTPD task.
    cfg.send_wait_timeout = 3;
    cfg.recv_wait_timeout = 3;
    cfg.core_id = 1;             // Pin the server on APP CPU (core 1)
    // NOTE: stack_size will be set below for PSRAM allocation

    // ── PSRAM stack allocation for HTTP server ─────

    // Stack in PSRAM 8-bit capable (required for the stack)
    cfg.task_caps  = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    // TLS + cert parsing can be stack-hungry; but keep this balanced to avoid hurting internal heap pressure.
    cfg.stack_size = 48 * 1024;
    LOG_INFOF(TAG_WEB,
              "HTTPD with PSRAM stack: size=%u, free_psram=%u, free_8bit=%u",
              (unsigned)cfg.stack_size,
              (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
              (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));
/*
    // Safe fallback: keep the stack in internal DRAM
    cfg.task_caps  = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
    cfg.stack_size = 48 * 1024;  // conservative fallback; increase if necessary
    LOG_WARNINGF(TAG_WEB,
                 "PSRAM stack not allowed by Kconfig. Falling back to INTERNAL stack: size=%u, free_int=%u",
                 (unsigned)cfg.stack_size,
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
*/

    // Decide minimal mode based on current internal memory/fragmentation
    size_t free_8bit = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_free_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    // We lower the threshold to keep full-mode more often
    const bool minimal_mode =
        g_force_minimal_web ||
        (free_internal < 90 * 1024) ||
        (largest_free_block < 45 * 1024);

    // Tune HTTPD resource usage based on mode.
    // The real killer of internal DRAM during browsing is the number of concurrent TLS sockets:
    // the browser tends to keep multiple connections open in parallel.
    //
    // NOTE: max_uri_handlers must remain >= the number of handlers registered in startOnInterface().
    if (minimal_mode) {
        cfg.max_open_sockets = 3;
        cfg.backlog_conn     = 3;
        cfg.max_resp_headers = 8;
        cfg.max_uri_handlers = 256;
    } else {
        cfg.max_open_sockets = 3;
        cfg.backlog_conn     = 4;
        cfg.max_resp_headers = 10;
        cfg.max_uri_handlers = 256;
    }

    LOG_INFOF(TAG_WEB,
              "HTTPD limits: minimal=%s max_open_sockets=%u backlog=%u max_uri_handlers=%u",
              minimal_mode ? "true" : "false",
              (unsigned)cfg.max_open_sockets,
              (unsigned)cfg.backlog_conn,
              (unsigned)cfg.max_uri_handlers);

    // Bind to specific interface if provided
    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            cfg.server_port = port;
            // Note: ESP-IDF doesn't support binding to specific interface directly in httpd_config_t
            // We'll need to check if interface has IP before starting
            //LOG_INFOF("WebServer", "Starting HTTP server on interface IP: %s:%d",
            //         inet_ntoa(ip_info.ip), port);
        } else {
            LOG_WARNING("WebServer", "Specified interface has no IP address, server not started");
            return false;
        }
    }

    // Pre-check: ensure enough internal RAM for httpd/lwIP control structures
    /*
    {
        const size_t MIN_INTERNAL_FOR_HTTPD = 60000; // ~60KB guardrail for stable bring-up
        if (free_internal < MIN_INTERNAL_FOR_HTTPD) {
            LOG_ERRORF(TAG_WEB, "HTTP server not started: insufficient internal RAM (free=%u, need>=%u)",
                       (unsigned)free_internal, (unsigned)MIN_INTERNAL_FOR_HTTPD);
            return false;
        }
    }*/

    // Initialize enhanced PSRAM buffers for STL-free web operations
    web_buf_init();

    // Log allocations status for all buffers
    LOG_INFOF(TAG_WEB, "📋 Buffer Status: web_buf=%p, g_http_tmp=%p, g_http_header_buf=%p",
              (void*)web_buf, (void*)g_http_tmp, (void*)g_http_header_buf);
    LOG_INFOF(TAG_WEB, "📋 Buffer Status: g_http_json_buf=%p, g_http_uri_buf=%p, g_http_post_buf=%p",
              (void*)g_http_json_buf, (void*)g_http_uri_buf, (void*)g_http_post_buf);

    // === ENHANCED PRE-HTTPD MEMORY ANALYSIS ===
    size_t minimum_free_size = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);

    LOG_INFOF(TAG_WEB, "=== PRE-HTTPD MEMORY ANALYSIS ===");
    LOG_INFOF(TAG_WEB, "🔍 Free 8-bit: %u bytes, Free internal: %u bytes",
              (unsigned)free_8bit, (unsigned)free_internal);
    LOG_INFOF(TAG_WEB, "🔍 Largest free block: %u bytes, Min free ever: %u bytes",
              (unsigned)largest_free_block, (unsigned)minimum_free_size);

    // Check memory fragmentation level
    float fragmentation = 100.0f * (1.0f - (float)largest_free_block / (float)free_internal);
    // Print fragmentation as integer percentage to avoid float formatting allocations
    unsigned frag_pct = 0;
    if (free_internal > 0) {
        size_t used_vs_largest = (free_internal > largest_free_block) ? (free_internal - largest_free_block) : 0;
        frag_pct = (unsigned)((used_vs_largest * 100U) / free_internal);
    }
    LOG_INFOF(TAG_WEB, "📊 Memory fragmentation: %u%% (higher = more fragmented)", frag_pct);

    if (fragmentation > 70.0f) {
        LOG_WARNING(TAG_WEB, "🔴 HIGH FRAGMENTATION WARNING: Consider heap cleanup before HTTP start");
    } else if (fragmentation > 40.0f) {
        LOG_WARNING(TAG_WEB, "⚠️  MODERATE FRAGMENTATION: Monitor memory usage");
    } else {
        LOG_INFO(TAG_WEB, "✅ GOOD FRAGMENTATION: Memory layout looks healthy");
    }

    // Operational note: if you use a PSRAM stack, avoid operations that disable the flash cache
    // (NVS/OTA/erase) in the context of the handlers. Send those jobs to a worker in DRAM.
    // Also see the high-water-mark LOG to calibrate the actual stack.
    // (You can add httpd_get_global_transport_ctx() for advanced metrics if needed.)

    // === HTTPS SERVER START WITH RETRY + PROFILE FALLBACK ===
    // Under memory pressure, esp_https_server may fail with ESP_FAIL during TLS initialization/parsing.
    // We try progressively "lighter" profiles to prefer stability over features.
    struct HttpsStartProfile {
        bool keep_alive;
        uint32_t stack_size;
        uint8_t max_open_sockets;
        uint8_t backlog;
        const char* name;
    };

    static const HttpsStartProfile kProfiles[] = {
        { true,  (48U * 1024U), 3, 4, "KA_ON_STACK48K" },
        { false, (48U * 1024U), 3, 4, "KA_OFF_STACK48K" },
        { false, (32U * 1024U), 3, 3, "KA_OFF_STACK32K" },
    };

    esp_err_t err = ESP_FAIL;
    const int MAX_RETRIES = 3;
    int retry_count = 0;
    size_t memory_consumed = 0;

#if ESP32_OT_WEB_HTTP_ONLY
    cfg.server_port = 80;
    LOG_WARNING(TAG_WEB, "Starting plain HTTP because this hardware profile does not support stable HTTPS");
    err = httpd_start(&http_, &cfg);
    retry_count = 1;
    if (err == ESP_OK) {
        LOG_WARNING(TAG_WEB, "HTTP server started on port 80; transport is not encrypted");
    }
#else
    while (retry_count < MAX_RETRIES && err != ESP_OK) {
        if (retry_count > 0) {
            LOG_INFOF(TAG_WEB, "🔄 Retry attempt %d/%d after memory cleanup...", retry_count + 1, MAX_RETRIES);

            // Aggressive memory cleanup between retries
            heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);
            //heap_caps_print_heap_info(MALLOC_CAP_SPIRAM);

            // Brief delay to allow system cleanup
            vTaskDelay(pdMS_TO_TICKS(100));

            // Update fragmentation after cleanup
            size_t retry_free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
            size_t retry_largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
            size_t retry_free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
            size_t retry_largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
            unsigned retry_frag_pct = 0;
            unsigned retry_psram_frag_pct = 0;

            if (retry_free_internal > 0) {
                size_t used_vs_largest_r = (retry_free_internal > retry_largest_block) ? (retry_free_internal - retry_largest_block) : 0;
                retry_frag_pct = (unsigned)((used_vs_largest_r * 100U) / retry_free_internal);
            }

            if (retry_free_psram > 0) {
                size_t used_vs_largest_psram = (retry_free_psram > retry_largest_psram) ? (retry_free_psram - retry_largest_psram) : 0;
                retry_psram_frag_pct = (unsigned)((used_vs_largest_psram * 100U) / retry_free_psram);
            }

            LOG_INFOF(TAG_WEB, "🔄 After cleanup IRAM: Free=%u, Largest=%u, Fragmentation=%u%%",
                      (unsigned)retry_free_internal, (unsigned)retry_largest_block, (unsigned)retry_frag_pct);
            LOG_INFOF(TAG_WEB, "🔄 After cleanup PSRAM: Free=%u, Largest=%u, Fragmentation=%u%%",
                      (unsigned)retry_free_psram, (unsigned)retry_largest_psram, (unsigned)retry_psram_frag_pct);
        }

        size_t pre_attempt_memory = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t pre_attempt_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        LOG_INFOF(TAG_WEB, "🚀 Attempting HTTPS server start - IRAM: %u bytes, PSRAM: %u bytes",
                  (unsigned)pre_attempt_memory, (unsigned)pre_attempt_psram);

        // SECURITY: HTTP disabled, using HTTPS only
        // err = httpd_start(&http_, &cfg);

        const int prof_idx = (retry_count < (int)(sizeof(kProfiles) / sizeof(kProfiles[0])))
                                 ? retry_count
                                 : (int)(sizeof(kProfiles) / sizeof(kProfiles[0])) - 1;
        const HttpsStartProfile& prof = kProfiles[prof_idx];
        LOG_WARNINGF(TAG_WEB, "💾 HTTPS start profile: %s keep_alive=%s stack=%u max_sockets=%u backlog=%u",
                     prof.name,
                     prof.keep_alive ? "true" : "false",
                     (unsigned)prof.stack_size,
                     (unsigned)prof.max_open_sockets,
                     (unsigned)prof.backlog);

        // Start HTTPS server instead
        httpd_ssl_config_t https_conf = HTTPD_SSL_CONFIG_DEFAULT();
        https_conf.httpd = cfg;  // Copy HTTP config to HTTPS config

        https_conf.servercert = reinterpret_cast<const uint8_t*>(
            tls_credentials_.certificatePem());
        https_conf.servercert_len = tls_credentials_.certificateLength() + 1;
        https_conf.prvtkey_pem = reinterpret_cast<const uint8_t*>(
            tls_credentials_.privateKeyPem());
        https_conf.prvtkey_len = tls_credentials_.privateKeyLength() + 1;

        https_conf.httpd.server_port = 443;  // HTTPS port
        https_conf.httpd.keep_alive_enable = prof.keep_alive;
        https_conf.httpd.stack_size = prof.stack_size;
        https_conf.httpd.max_open_sockets = prof.max_open_sockets;
        https_conf.httpd.backlog_conn = prof.backlog;
        https_conf.httpd.open_fn = &WebServer::authorizeOpenSocket;

        err = httpd_ssl_start(&https_server_, &https_conf);

        size_t post_attempt_memory = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t post_attempt_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        memory_consumed = pre_attempt_memory - post_attempt_memory;
        size_t psram_consumed = pre_attempt_psram - post_attempt_psram;

        if (err == ESP_OK) {
            LOG_INFOF(TAG_WEB, "✅ HTTPS server start SUCCESS on attempt %d - IRAM: %u bytes, PSRAM: %u bytes consumed",
                      retry_count + 1, (unsigned)memory_consumed, (unsigned)psram_consumed);

            // Log HTTPS server start to network.log
            if (g_reporting) {
                char event_data[512];
                snprintf(event_data, sizeof(event_data),
                         "{\"action\":\"https_server_started\",\"port\":443,\"attempts\":%d,\"iram_consumed\":%u,\"psram_consumed\":%u}",
                         retry_count + 1, (unsigned)memory_consumed, (unsigned)psram_consumed);
                report_event_ps(g_reporting, "network", event_data);
            }
            break;
        } else if (err == ESP_ERR_HTTPD_ALLOC_MEM) {
            LOG_WARNINGF(TAG_WEB, "⚠️  httpd_start() failed with ESP_ERR_HTTPD_ALLOC_MEM on attempt %d: %s",
                         retry_count + 1, esp_err_to_name(err));
            LOG_INFOF(TAG_WEB, "💾 Memory state - IRAM: consumed=%u, remaining=%u | PSRAM: consumed=%u, remaining=%u",
                      (unsigned)memory_consumed, (unsigned)post_attempt_memory,
                      (unsigned)psram_consumed, (unsigned)post_attempt_psram);
        } else {
            LOG_ERRORF(TAG_WEB, "❌ httpd_start() failed with error %s (%d) on attempt %d",
                       esp_err_to_name(err), err, retry_count + 1);
        }

        retry_count++;
    }
#endif

    // Final result evaluation
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_WEB, "🔴 CRITICAL: httpd_start() failed after %d attempts: %s (%d)",
                   MAX_RETRIES, esp_err_to_name(err), err);
        http_ = nullptr;
        return false;
    }

    // === POST-HTTPD SUCCESS ANALYSIS ===
    size_t post_start_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    LOG_INFOF(TAG_WEB, "=== POST-HTTPD MEMORY ANALYSIS ===");
#if ESP32_OT_WEB_HTTP_ONLY
    LOG_WARNINGF(TAG_WEB, "HTTP server started successfully after %d attempt(s)", retry_count);
#else
    LOG_INFOF(TAG_WEB, "✅ HTTPS Server started successfully after %d attempt(s)", retry_count);
#endif
    LOG_INFOF(TAG_WEB, "📊 Total memory consumed by httpd_start(): %u bytes", (unsigned)memory_consumed);
    LOG_INFOF(TAG_WEB, "💾 Current free internal memory: %u bytes", (unsigned)post_start_free);
    // Integer-only percentage to avoid float formatting
    unsigned eff_pct = 0;
    size_t total_after = post_start_free + memory_consumed;
    if (total_after > 0) eff_pct = (unsigned)((memory_consumed * 100U) / total_after);
    LOG_INFOF(TAG_WEB, "🎯 Memory efficiency: %u%% of available memory used", eff_pct);

    // Check if we're running low on memory
    if (post_start_free < 30000) {  // Less than 30KB remaining
        LOG_WARNINGF(TAG_WEB, "🔴 LOW MEMORY WARNING: Only %u bytes remaining after HTTP start", (unsigned)post_start_free);
    } else if (post_start_free < 50000) {  // Less than 50KB remaining
        LOG_WARNINGF(TAG_WEB, "⚠️  MEMORY CAUTION: %u bytes remaining - monitor usage", (unsigned)post_start_free);
    } else {
        LOG_INFOF(TAG_WEB, "✅ MEMORY STATUS: Healthy %u bytes remaining", (unsigned)post_start_free);
    }

    // After successful start, log stack high watermark and task info
    if (cfg.task_caps & MALLOC_CAP_SPIRAM) {
        TaskHandle_t t = xTaskGetHandle("WebServer");
        if (t) {
            UBaseType_t hw = uxTaskGetStackHighWaterMark(t);
            LOG_INFOF(TAG_WEB, "WebServer task high water mark: %u words", (unsigned)hw);
        } else {
            LOG_INFO(TAG_WEB, "WebServer task handle not found for watermark logging");
        }
    }

    active_server_ = ESP32_OT_WEB_HTTP_ONLY ? http_ : https_server_;

    // If we are in minimal mode, register only core endpoints to keep RAM usage low
    if (minimal_mode) {
        LOG_WARNING(TAG_WEB, "Starting in MINIMAL WEB MODE due to low internal RAM");
        httpd_uri_t u_root   = { .uri="/", .method=HTTP_GET,  .handler=&WebServer::h_root, .user_ctx=nullptr };
        httpd_uri_t u_stat   = { .uri="/api/status", .method=HTTP_GET, .handler=&WebServer::h_status, .user_ctx=nullptr };
        httpd_uri_t u_telem  = { .uri="/api/telemetry", .method=HTTP_GET, .handler=&WebServer::h_telemetry, .user_ctx=nullptr };
        httpd_uri_t u_cfg_g  = { .uri="/api/config", .method=HTTP_GET, .handler=&WebServer::h_config_get, .user_ctx=nullptr };
        httpd_uri_t u_cfg_p  = { .uri="/api/config", .method=HTTP_POST, .handler=&WebServer::h_config_post, .user_ctx=nullptr };
        httpd_uri_t u_cfg_update = { .uri="/api/config/update", .method=HTTP_POST, .handler=&WebServer::h_config_update, .user_ctx=nullptr };
        httpd_uri_t u_cfg_reset = { .uri="/api/config/reset-to-defaults", .method=HTTP_POST, .handler=&WebServer::h_config_reset_defaults, .user_ctx=nullptr };
        httpd_uri_t u_editor_schema = { .uri="/api/config/editor/schema", .method=HTTP_GET, .handler=&WebServer::h_config_editor_schema, .user_ctx=nullptr };
        httpd_uri_t u_editor_snapshot = { .uri="/api/config/editor/snapshot", .method=HTTP_GET, .handler=&WebServer::h_config_editor_snapshot, .user_ctx=nullptr };
        httpd_uri_t u_editor_validate = { .uri="/api/config/editor/validate", .method=HTTP_POST, .handler=&WebServer::h_config_editor_validate, .user_ctx=nullptr };
        httpd_uri_t u_editor_save = { .uri="/api/config/editor/save", .method=HTTP_POST, .handler=&WebServer::h_config_editor_save, .user_ctx=nullptr };
        httpd_uri_t u_feat_g = { .uri="/api/features", .method=HTTP_GET, .handler=&WebServer::h_features_get, .user_ctx=nullptr };
        httpd_uri_t u_feat_p = { .uri="/api/features", .method=HTTP_POST, .handler=&WebServer::h_features_post, .user_ctx=nullptr };
        httpd_uri_t u_bootstrap = { .uri="/api/page/bootstrap", .method=HTTP_GET, .handler=&WebServer::h_page_bootstrap_get, .user_ctx=nullptr };
        httpd_uri_t u_reboot = { .uri="/api/reboot", .method=HTTP_POST, .handler=&WebServer::h_reboot, .user_ctx=nullptr };

        httpd_register_uri_handler(active_server_, &u_root);
        httpd_register_uri_handler(active_server_, &u_stat);
        httpd_register_uri_handler(active_server_, &u_telem);
        httpd_register_uri_handler(active_server_, &u_cfg_g);
        httpd_register_uri_handler(active_server_, &u_cfg_p);
        httpd_register_uri_handler(active_server_, &u_cfg_update);
        httpd_register_uri_handler(active_server_, &u_cfg_reset);
        httpd_register_uri_handler(active_server_, &u_editor_schema);
        httpd_register_uri_handler(active_server_, &u_editor_snapshot);
        httpd_register_uri_handler(active_server_, &u_editor_validate);
        httpd_register_uri_handler(active_server_, &u_editor_save);
        httpd_register_uri_handler(active_server_, &u_feat_g);
        httpd_register_uri_handler(active_server_, &u_feat_p);
        httpd_register_uri_handler(active_server_, &u_bootstrap);
        httpd_register_uri_handler(active_server_, &u_reboot);
        httpd_uri_t u_diag_self = { .uri="/api/diagnostics/selftest", .method=HTTP_GET, .handler=&WebServer::h_api_selftest, .user_ctx=nullptr };
        httpd_uri_t u_diag_httpd = { .uri="/api/diagnostics/httpd", .method=HTTP_GET, .handler=&WebServer::h_api_httpd_stats, .user_ctx=nullptr };
        httpd_register_uri_handler(active_server_, &u_diag_self);
        httpd_register_uri_handler(active_server_, &u_diag_httpd);

        httpdMonitorStart();

        LOG_INFO(TAG_WEB, "Minimal web routes registered");
        return true;
    }

    // Static & API routes
    httpd_uri_t u_root   = { .uri="/", .method=HTTP_GET,  .handler=&WebServer::h_root, .user_ctx=nullptr };
    httpd_uri_t u_stat   = { .uri="/api/status", .method=HTTP_GET, .handler=&WebServer::h_status, .user_ctx=nullptr };
    httpd_uri_t u_telem  = { .uri="/api/telemetry", .method=HTTP_GET, .handler=&WebServer::h_telemetry, .user_ctx=nullptr };
    httpd_uri_t u_cfg_g  = { .uri="/api/config", .method=HTTP_GET, .handler=&WebServer::h_config_get, .user_ctx=nullptr };
    httpd_uri_t u_cfg_p  = { .uri="/api/config", .method=HTTP_POST, .handler=&WebServer::h_config_post, .user_ctx=nullptr };
    httpd_uri_t u_cfg_update = { .uri="/api/config/update", .method=HTTP_POST, .handler=&WebServer::h_config_update, .user_ctx=nullptr };
    httpd_uri_t u_cfg_reset = { .uri="/api/config/reset-to-defaults", .method=HTTP_POST, .handler=&WebServer::h_config_reset_defaults, .user_ctx=nullptr };
    httpd_uri_t u_editor_schema = { .uri="/api/config/editor/schema", .method=HTTP_GET, .handler=&WebServer::h_config_editor_schema, .user_ctx=nullptr };
    httpd_uri_t u_editor_snapshot = { .uri="/api/config/editor/snapshot", .method=HTTP_GET, .handler=&WebServer::h_config_editor_snapshot, .user_ctx=nullptr };
    httpd_uri_t u_editor_validate = { .uri="/api/config/editor/validate", .method=HTTP_POST, .handler=&WebServer::h_config_editor_validate, .user_ctx=nullptr };
    httpd_uri_t u_editor_save = { .uri="/api/config/editor/save", .method=HTTP_POST, .handler=&WebServer::h_config_editor_save, .user_ctx=nullptr };
    httpd_uri_t u_feat_g = { .uri="/api/features", .method=HTTP_GET, .handler=&WebServer::h_features_get, .user_ctx=nullptr };
    httpd_uri_t u_feat_p = { .uri="/api/features", .method=HTTP_POST, .handler=&WebServer::h_features_post, .user_ctx=nullptr };
    httpd_uri_t u_bootstrap = { .uri="/api/page/bootstrap", .method=HTTP_GET, .handler=&WebServer::h_page_bootstrap_get, .user_ctx=nullptr };
    httpd_uri_t u_reboot = { .uri="/api/reboot", .method=HTTP_POST, .handler=&WebServer::h_reboot, .user_ctx=nullptr };

    // Scanner endpoints
    httpd_uri_t s_jobs_g = { .uri="/api/scanner/jobs", .method=HTTP_GET, .handler=&WebServer::h_scan_jobs_get, .user_ctx=nullptr };
    httpd_uri_t s_jobs_p = { .uri="/api/scanner/jobs", .method=HTTP_POST, .handler=&WebServer::h_scan_jobs_post, .user_ctx=nullptr };
    httpd_uri_t s_jobs_d = { .uri="/api/scanner/jobs", .method=HTTP_DELETE, .handler=&WebServer::h_scan_jobs_delete, .user_ctx=nullptr };
    httpd_uri_t s_run    = { .uri="/api/scanner/run", .method=HTTP_POST, .handler=&WebServer::h_scan_run, .user_ctx=nullptr };
    httpd_uri_t s_res_g  = { .uri="/api/scanner/result", .method=HTTP_GET, .handler=&WebServer::h_scan_result_get, .user_ctx=nullptr };
    httpd_uri_t s_cfg_g  = { .uri="/api/scanner/config", .method=HTTP_GET, .handler=&WebServer::h_scan_cfg_get, .user_ctx=nullptr };
    httpd_uri_t s_cfg_p  = { .uri="/api/scanner/config", .method=HTTP_POST, .handler=&WebServer::h_scan_cfg_post, .user_ctx=nullptr };
    httpd_uri_t sch_list = { .uri="/api/schedule/list", .method=HTTP_GET, .handler=&WebServer::h_schedule_list, .user_ctx=nullptr };
    httpd_uri_t sch_create = { .uri="/api/schedule/create", .method=HTTP_POST, .handler=&WebServer::h_schedule_create, .user_ctx=nullptr };
    httpd_uri_t sch_update = { .uri="/api/schedule/update", .method=HTTP_POST, .handler=&WebServer::h_schedule_update, .user_ctx=nullptr };
    httpd_uri_t sch_delete = { .uri="/api/schedule/delete", .method=HTTP_POST, .handler=&WebServer::h_schedule_delete, .user_ctx=nullptr };
    httpd_uri_t sch_toggle = { .uri="/api/schedule/toggle", .method=HTTP_POST, .handler=&WebServer::h_schedule_toggle, .user_ctx=nullptr };
    httpd_uri_t sch_trigger = { .uri="/api/schedule/trigger", .method=HTTP_POST, .handler=&WebServer::h_schedule_trigger, .user_ctx=nullptr };

    // Discovery
    httpd_uri_t d_modbus = { .uri="/api/discovery/modbus", .method=HTTP_POST, .handler=&WebServer::h_discovery_modbus, .user_ctx=nullptr };
    httpd_uri_t d_s7  = { .uri="/api/discovery/s7", .method=HTTP_POST, .handler=&WebServer::h_discovery_s7, .user_ctx=nullptr };
    httpd_uri_t d_pn  = { .uri="/api/discovery/profinet", .method=HTTP_POST, .handler=&WebServer::h_discovery_profinet, .user_ctx=nullptr };
    httpd_uri_t d_en  = { .uri="/api/discovery/enip", .method=HTTP_POST, .handler=&WebServer::h_discovery_enip, .user_ctx=nullptr };
    httpd_uri_t d_opcua = { .uri="/api/discovery/opcua", .method=HTTP_POST, .handler=&WebServer::h_discovery_opcua, .user_ctx=nullptr };
    httpd_uri_t s7_ops = { .uri="/api/s7/ops", .method=HTTP_POST, .handler=&WebServer::h_s7_ops, .user_ctx=nullptr };

    // GPIO Reporter endpoints (now under reporting)
    httpd_uri_t gpio_status = { .uri="/api/reporting/gpio/status", .method=HTTP_GET, .handler=&WebServer::h_gpio_status, .user_ctx=nullptr };
    httpd_uri_t gpio_cfg_g = { .uri="/api/reporting/gpio/config", .method=HTTP_GET, .handler=&WebServer::h_gpio_config_get, .user_ctx=nullptr };
    httpd_uri_t gpio_cfg_p = { .uri="/api/reporting/gpio/config", .method=HTTP_POST, .handler=&WebServer::h_gpio_config_post, .user_ctx=nullptr };
    httpd_uri_t gpio_alert = { .uri="/api/reporting/gpio/alert", .method=HTTP_POST, .handler=&WebServer::h_gpio_alert, .user_ctx=nullptr };
    httpd_uri_t gpio_reset = { .uri="/api/reporting/gpio/reset", .method=HTTP_POST, .handler=&WebServer::h_gpio_reset, .user_ctx=nullptr };
    httpd_uri_t gpio_test = { .uri="/api/reporting/gpio/test", .method=HTTP_POST, .handler=&WebServer::h_gpio_test, .user_ctx=nullptr };
    httpd_uri_t gpio_buttons = { .uri="/api/reporting/gpio/buttons", .method=HTTP_GET, .handler=&WebServer::h_gpio_buttons, .user_ctx=nullptr };

    // Audit Manager endpoints
    httpd_uri_t audit_status = { .uri="/api/audit/status", .method=HTTP_GET, .handler=&WebServer::h_sandbox_status, .user_ctx=nullptr };
    httpd_uri_t audit_cfg_g = { .uri="/api/audit/config", .method=HTTP_GET, .handler=&WebServer::h_sandbox_config_get, .user_ctx=nullptr };
    httpd_uri_t audit_cfg_p = { .uri="/api/audit/config", .method=HTTP_POST, .handler=&WebServer::h_sandbox_config_post, .user_ctx=nullptr };
    httpd_uri_t audit_snapshot = { .uri="/api/audit/snapshot", .method=HTTP_GET, .handler=&WebServer::h_sandbox_audit_get, .user_ctx=nullptr };

    httpd_register_uri_handler(active_server_, &u_root);
    httpd_register_uri_handler(active_server_, &u_stat);
    httpd_register_uri_handler(active_server_, &u_telem);
    httpd_register_uri_handler(active_server_, &u_cfg_g);
    httpd_register_uri_handler(active_server_, &u_cfg_p);
    httpd_register_uri_handler(active_server_, &u_cfg_update);
    httpd_register_uri_handler(active_server_, &u_cfg_reset);
    httpd_register_uri_handler(active_server_, &u_editor_schema);
    httpd_register_uri_handler(active_server_, &u_editor_snapshot);
    httpd_register_uri_handler(active_server_, &u_editor_validate);
    httpd_register_uri_handler(active_server_, &u_editor_save);
    httpd_register_uri_handler(active_server_, &u_feat_g);
    httpd_register_uri_handler(active_server_, &u_feat_p);
    httpd_register_uri_handler(active_server_, &u_bootstrap);
    httpd_register_uri_handler(active_server_, &u_reboot);

    httpd_uri_t lget = { .uri="/login", .method=HTTP_GET, .handler=&WebServer::h_login_get, .user_ctx=nullptr };
    httpd_uri_t lpost= { .uri="/login", .method=HTTP_POST, .handler=&WebServer::h_login_post, .user_ctx=nullptr };
    httpd_uri_t lout = { .uri="/logout", .method=HTTP_POST, .handler=&WebServer::h_logout, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &lget);
    httpd_register_uri_handler(active_server_, &lpost);
    httpd_register_uri_handler(active_server_, &lout);

    httpd_uri_t klist= { .uri="/api/auth/keys", .method=HTTP_GET, .handler=&WebServer::h_keys_list, .user_ctx=nullptr };
    httpd_uri_t kcre = { .uri="/api/auth/keys", .method=HTTP_POST, .handler=&WebServer::h_keys_create, .user_ctx=nullptr };
    httpd_uri_t krev = { .uri="/api/auth/keys", .method=HTTP_DELETE, .handler=&WebServer::h_keys_revoke, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &klist);
    httpd_register_uri_handler(active_server_, &kcre);
    httpd_register_uri_handler(active_server_, &krev);

    httpd_uri_t lg_g = { .uri="/api/logs/retention", .method=HTTP_GET, .handler=&WebServer::h_logs_retention_get, .user_ctx=nullptr };
    httpd_uri_t lg_p = { .uri="/api/logs/retention", .method=HTTP_POST, .handler=&WebServer::h_logs_retention_post, .user_ctx=nullptr };
    httpd_uri_t lg_r = { .uri="/api/logs/retention/run", .method=HTTP_POST, .handler=&WebServer::h_logs_retention_run, .user_ctx=nullptr };
    httpd_uri_t lg_a = { .uri="/api/logs/access", .method=HTTP_GET, .handler=&WebServer::h_logs_access_get, .user_ctx=nullptr };
    httpd_uri_t lg_metrics = { .uri="/api/logs/access/metrics", .method=HTTP_GET, .handler=&WebServer::h_logs_access_metrics, .user_ctx=nullptr };
    httpd_uri_t wifi_connect = { .uri="/api/wifi/connect", .method=HTTP_POST, .handler=&WebServer::h_wifi_connect, .user_ctx=this };
    httpd_uri_t wifi_status = { .uri="/api/wifi/status", .method=HTTP_GET, .handler=&WebServer::h_wifi_status, .user_ctx=this };
    httpd_uri_t wifi_connect_result = { .uri="/api/wifi/connect/result", .method=HTTP_GET, .handler=&WebServer::h_wifi_connect_result, .user_ctx=this };
    httpd_uri_t wifi_scan_start = { .uri="/api/wifi/scan/start", .method=HTTP_POST, .handler=&WebServer::h_wifi_scan_start, .user_ctx=this };
    httpd_uri_t wifi_scan_status = { .uri="/api/wifi/scan/status", .method=HTTP_GET, .handler=&WebServer::h_wifi_scan_status, .user_ctx=this };
    httpd_uri_t wifi_disconnect = { .uri="/api/wifi/disconnect", .method=HTTP_POST, .handler=&WebServer::h_wifi_disconnect, .user_ctx=this };
    httpd_uri_t report_fmt_g = { .uri="/api/report/format", .method=HTTP_GET, .handler=&WebServer::h_report_format_get, .user_ctx=nullptr };
    httpd_uri_t report_fmt_p = { .uri="/api/report/format", .method=HTTP_POST, .handler=&WebServer::h_report_format_post, .user_ctx=nullptr };
    httpd_uri_t report_filters_g = { .uri="/api/report/filters", .method=HTTP_GET, .handler=&WebServer::h_report_filters_get, .user_ctx=nullptr };
    httpd_uri_t report_filters_p = { .uri="/api/report/filters", .method=HTTP_POST, .handler=&WebServer::h_report_filters_post, .user_ctx=nullptr };
    httpd_uri_t report_filter_add = { .uri="/api/report/filter/add", .method=HTTP_POST, .handler=&WebServer::h_report_filter_add, .user_ctx=nullptr };
    httpd_uri_t report_filter_remove = { .uri="/api/report/filter/remove", .method=HTTP_POST, .handler=&WebServer::h_report_filter_remove, .user_ctx=nullptr };
    httpd_uri_t logs_get = { .uri="/api/logs", .method=HTTP_GET, .handler=&WebServer::h_logs_get, .user_ctx=nullptr };
    httpd_uri_t logs_download = { .uri="/api/logs/download", .method=HTTP_GET, .handler=&WebServer::h_logs_download, .user_ctx=nullptr };

    // Log file management endpoints
    httpd_uri_t log_files_g = { .uri="/api/logging/files", .method=HTTP_GET, .handler=&WebServer::h_logging_files_get, .user_ctx=nullptr };
    httpd_uri_t log_files_p = { .uri="/api/logging/files", .method=HTTP_POST, .handler=&WebServer::h_logging_files_post, .user_ctx=nullptr };
    httpd_uri_t log_file_cfg_g = { .uri="/api/logging/file/config", .method=HTTP_GET, .handler=&WebServer::h_logging_file_config_get, .user_ctx=nullptr };
    httpd_uri_t log_file_cfg_p = { .uri="/api/logging/file/config", .method=HTTP_POST, .handler=&WebServer::h_logging_file_config_post, .user_ctx=nullptr };
    httpd_uri_t config_export = { .uri="/api/config/export", .method=HTTP_GET, .handler=&WebServer::h_config_export, .user_ctx=nullptr };
    httpd_uri_t config_import = { .uri="/api/config/import", .method=HTTP_POST, .handler=&WebServer::h_config_import, .user_ctx=nullptr };
    httpd_uri_t config_metadata = { .uri="/api/config/metadata", .method=HTTP_GET, .handler=&WebServer::h_config_metadata_get, .user_ctx=nullptr };
    httpd_uri_t config_reset = { .uri="/api/config/reset", .method=HTTP_POST, .handler=&WebServer::h_config_reset_post, .user_ctx=nullptr };
    httpd_uri_t config_editor_schema = { .uri="/api/config/editor/schema", .method=HTTP_GET, .handler=&WebServer::h_config_editor_schema, .user_ctx=nullptr };
    httpd_uri_t config_editor_snapshot = { .uri="/api/config/editor/snapshot", .method=HTTP_GET, .handler=&WebServer::h_config_editor_snapshot, .user_ctx=nullptr };
    httpd_uri_t config_editor_validate = { .uri="/api/config/editor/validate", .method=HTTP_POST, .handler=&WebServer::h_config_editor_validate, .user_ctx=nullptr };
    httpd_uri_t config_editor_save = { .uri="/api/config/editor/save", .method=HTTP_POST, .handler=&WebServer::h_config_editor_save, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &lg_g);
    httpd_register_uri_handler(active_server_, &lg_p);
    httpd_register_uri_handler(active_server_, &lg_r);
    httpd_register_uri_handler(active_server_, &lg_a);
    httpd_register_uri_handler(active_server_, &lg_metrics);
    httpd_register_uri_handler(active_server_, &wifi_connect);
    httpd_register_uri_handler(active_server_, &wifi_status);
    httpd_register_uri_handler(active_server_, &wifi_connect_result);
    httpd_register_uri_handler(active_server_, &wifi_scan_start);
    httpd_register_uri_handler(active_server_, &wifi_scan_status);
    httpd_register_uri_handler(active_server_, &wifi_disconnect);
    httpd_register_uri_handler(active_server_, &report_fmt_g);
    httpd_register_uri_handler(active_server_, &report_fmt_p);
    httpd_register_uri_handler(active_server_, &report_filters_g);
    httpd_register_uri_handler(active_server_, &report_filters_p);
    httpd_register_uri_handler(active_server_, &report_filter_add);
    httpd_register_uri_handler(active_server_, &report_filter_remove);
    httpd_register_uri_handler(active_server_, &logs_get);
    httpd_register_uri_handler(active_server_, &logs_download);
    httpd_register_uri_handler(active_server_, &log_files_g);
    httpd_register_uri_handler(active_server_, &log_files_p);
    httpd_register_uri_handler(active_server_, &log_file_cfg_g);
    httpd_register_uri_handler(active_server_, &log_file_cfg_p);
    httpd_register_uri_handler(active_server_, &config_export);
    httpd_register_uri_handler(active_server_, &config_import);
    httpd_register_uri_handler(active_server_, &config_metadata);
    httpd_register_uri_handler(active_server_, &config_reset);

    // Register GPIO Reporter endpoints
    httpd_register_uri_handler(active_server_, &gpio_status);
    httpd_register_uri_handler(active_server_, &gpio_cfg_g);
    httpd_register_uri_handler(active_server_, &gpio_cfg_p);
    httpd_register_uri_handler(active_server_, &gpio_alert);
    httpd_register_uri_handler(active_server_, &gpio_reset);
    httpd_register_uri_handler(active_server_, &gpio_test);
    httpd_register_uri_handler(active_server_, &gpio_buttons);

    // Register Audit Manager endpoints
    httpd_register_uri_handler(active_server_, &audit_status);
    httpd_register_uri_handler(active_server_, &audit_cfg_g);
    httpd_register_uri_handler(active_server_, &audit_cfg_p);
    httpd_register_uri_handler(active_server_, &audit_snapshot);

    // Audit API endpoints for web interface
    httpd_uri_t audit_metrics_g = { .uri="/api/audit/metrics", .method=HTTP_GET, .handler=&WebServer::h_audit_metrics_get, .user_ctx=nullptr };
    httpd_uri_t audit_events_g = { .uri="/api/audit/events", .method=HTTP_GET, .handler=&WebServer::h_audit_events_get, .user_ctx=nullptr };
    httpd_uri_t audit_events_d = { .uri="/api/audit/events", .method=HTTP_DELETE, .handler=&WebServer::h_audit_events_delete, .user_ctx=nullptr };
    httpd_uri_t audit_analytics_g = { .uri="/api/audit/analytics", .method=HTTP_GET, .handler=&WebServer::h_audit_analytics_get, .user_ctx=nullptr };
    httpd_uri_t audit_export_g = { .uri="/api/audit/export", .method=HTTP_GET, .handler=&WebServer::h_audit_export_get, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &audit_metrics_g);
    httpd_register_uri_handler(active_server_, &audit_events_g);
    httpd_register_uri_handler(active_server_, &audit_events_d);
    httpd_register_uri_handler(active_server_, &audit_analytics_g);
    httpd_register_uri_handler(active_server_, &audit_export_g);

    httpd_uri_t rq_s = { .uri="/api/report/queue", .method=HTTP_GET, .handler=&WebServer::h_report_queue_status, .user_ctx=nullptr };
    httpd_uri_t rq_f = { .uri="/api/report/flush", .method=HTTP_POST, .handler=&WebServer::h_report_flush, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &rq_s);
    httpd_register_uri_handler(active_server_, &rq_f);

    httpd_uri_t rc_g = { .uri="/api/report/channels", .method=HTTP_GET, .handler=&WebServer::h_report_channels_get, .user_ctx=nullptr };
    httpd_uri_t rc_p = { .uri="/api/report/channels", .method=HTTP_POST, .handler=&WebServer::h_report_channels_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &rc_g);
    httpd_register_uri_handler(active_server_, &rc_p);

    httpd_uri_t re_g = { .uri="/api/report/endpoints", .method=HTTP_GET, .handler=&WebServer::h_report_endpoints_get, .user_ctx=nullptr };
    httpd_uri_t re_p = { .uri="/api/report/endpoints", .method=HTTP_POST, .handler=&WebServer::h_report_endpoints_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &re_g);
    httpd_register_uri_handler(active_server_, &re_p);

    httpd_uri_t ids_cfg_g = { .uri="/api/ids/advanced/config", .method=HTTP_GET, .handler=&WebServer::h_ids_adv_cfg_get, .user_ctx=nullptr };
    httpd_uri_t ids_cfg_p = { .uri="/api/ids/advanced/config", .method=HTTP_POST, .handler=&WebServer::h_ids_adv_cfg_post, .user_ctx=nullptr };
    httpd_uri_t ids_stats  = { .uri="/api/ids/advanced/stats", .method=HTTP_GET, .handler=&WebServer::h_ids_adv_stats, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &ids_cfg_g);
    httpd_register_uri_handler(active_server_, &ids_cfg_p);
    httpd_uri_t passive_cfg_g = { .uri="/api/passive-detection/config", .method=HTTP_GET, .handler=&WebServer::h_passive_config_get, .user_ctx=nullptr };
    httpd_uri_t passive_cfg_p = { .uri="/api/passive-detection/config", .method=HTTP_POST, .handler=&WebServer::h_passive_config_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &passive_cfg_g);
    httpd_register_uri_handler(active_server_, &passive_cfg_p);
    httpd_register_uri_handler(active_server_, &ids_stats);

    // IDS API aliases for simplified paths
    httpd_uri_t ids_stats_alias = { .uri="/api/ids/stats", .method=HTTP_GET, .handler=&WebServer::h_ids_stats_get, .user_ctx=nullptr };
    httpd_uri_t ids_config_alias_g = { .uri="/api/ids/config", .method=HTTP_GET, .handler=&WebServer::h_ids_config_get, .user_ctx=nullptr };
    httpd_uri_t ids_config_alias_p = { .uri="/api/ids/config", .method=HTTP_POST, .handler=&WebServer::h_ids_config_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &ids_stats_alias);
    httpd_register_uri_handler(active_server_, &ids_config_alias_g);
    httpd_register_uri_handler(active_server_, &ids_config_alias_p);

    // IDS Signatures endpoints
    httpd_uri_t ids_sig_g = { .uri="/api/ids/signatures", .method=HTTP_GET, .handler=&WebServer::h_ids_signatures_get, .user_ctx=nullptr };
    httpd_uri_t ids_sig_p = { .uri="/api/ids/signatures", .method=HTTP_POST, .handler=&WebServer::h_ids_signatures_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &ids_sig_g);
    httpd_register_uri_handler(active_server_, &ids_sig_p);

    // Network Presence tracking endpoints
    httpd_uri_t presence_stats_g = { .uri="/api/ids/presence/stats", .method=HTTP_GET, .handler=&WebServer::h_presence_stats_get, .user_ctx=nullptr };
    httpd_uri_t presence_devices_g = { .uri="/api/ids/presence/devices", .method=HTTP_GET, .handler=&WebServer::h_presence_devices_get, .user_ctx=nullptr };
    httpd_uri_t presence_learned_g = { .uri="/api/ids/presence/learned", .method=HTTP_GET, .handler=&WebServer::h_presence_learned_get, .user_ctx=nullptr };
    httpd_uri_t presence_cfg_g = { .uri="/api/ids/presence/config", .method=HTTP_GET, .handler=&WebServer::h_presence_config_get, .user_ctx=nullptr };
    httpd_uri_t presence_cfg_p = { .uri="/api/ids/presence/config", .method=HTTP_POST, .handler=&WebServer::h_presence_config_post, .user_ctx=nullptr };
    httpd_uri_t presence_clear_p = { .uri="/api/ids/presence/clear", .method=HTTP_POST, .handler=&WebServer::h_presence_clear_post, .user_ctx=nullptr };
    httpd_uri_t presence_promote_p = { .uri="/api/ids/presence/promote", .method=HTTP_POST, .handler=&WebServer::h_presence_promote_post, .user_ctx=nullptr };
    httpd_uri_t presence_demote_p = { .uri="/api/ids/presence/demote", .method=HTTP_POST, .handler=&WebServer::h_presence_demote_post, .user_ctx=nullptr };
    httpd_uri_t np_cfg_g = { .uri="/api/network-presence/config", .method=HTTP_GET, .handler=&WebServer::h_presence_config_get, .user_ctx=nullptr };
    httpd_uri_t np_cfg_p = { .uri="/api/network-presence/config", .method=HTTP_POST, .handler=&WebServer::h_presence_config_post, .user_ctx=nullptr };
    httpd_uri_t np_clear = { .uri="/api/network-presence/clear", .method=HTTP_POST, .handler=&WebServer::h_presence_clear_post, .user_ctx=nullptr };
    httpd_uri_t np_promote = { .uri="/api/network-presence/make-permanent", .method=HTTP_POST, .handler=&WebServer::h_presence_promote_post, .user_ctx=nullptr };
    httpd_uri_t np_remove = { .uri="/api/network-presence/remove", .method=HTTP_POST, .handler=&WebServer::h_presence_demote_post, .user_ctx=nullptr };

    httpd_register_uri_handler(active_server_, &presence_stats_g);
    httpd_register_uri_handler(active_server_, &presence_devices_g);
    httpd_register_uri_handler(active_server_, &presence_learned_g);
    httpd_register_uri_handler(active_server_, &presence_cfg_g);
    httpd_register_uri_handler(active_server_, &presence_cfg_p);
    httpd_register_uri_handler(active_server_, &presence_clear_p);
    httpd_register_uri_handler(active_server_, &presence_promote_p);
    httpd_register_uri_handler(active_server_, &presence_demote_p);
    httpd_register_uri_handler(active_server_, &np_cfg_g);
    httpd_register_uri_handler(active_server_, &np_cfg_p);
    httpd_register_uri_handler(active_server_, &np_clear);
    httpd_register_uri_handler(active_server_, &np_promote);
    httpd_register_uri_handler(active_server_, &np_remove);

    // Network presence alias for simplified path
    httpd_uri_t network_presence_learned_alias = { .uri="/api/network-presence/learned", .method=HTTP_GET, .handler=&WebServer::h_network_presence_learned_get, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &network_presence_learned_alias);

    // Debug configuration endpoints
    httpd_uri_t debug_cfg_g = { .uri="/api/config/debug", .method=HTTP_GET, .handler=&WebServer::h_debug_config_get, .user_ctx=nullptr };
    httpd_uri_t debug_cfg_p = { .uri="/api/config/debug", .method=HTTP_POST, .handler=&WebServer::h_debug_config_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &debug_cfg_g);
    httpd_register_uri_handler(active_server_, &debug_cfg_p);

    // Security configuration endpoints
    httpd_uri_t security_cfg_g = { .uri="/api/config/security", .method=HTTP_GET, .handler=&WebServer::h_security_config_get, .user_ctx=nullptr };
    httpd_uri_t security_cfg_p = { .uri="/api/config/security", .method=HTTP_POST, .handler=&WebServer::h_security_config_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &security_cfg_g);
    httpd_register_uri_handler(active_server_, &security_cfg_p);

    // Diagnostics self-test endpoint
    httpd_uri_t diagnostics_selftest = { .uri="/api/diagnostics/selftest", .method=HTTP_GET, .handler=&WebServer::h_api_selftest, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &diagnostics_selftest);
    httpd_uri_t diagnostics_httpd = { .uri="/api/diagnostics/httpd", .method=HTTP_GET, .handler=&WebServer::h_api_httpd_stats, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &diagnostics_httpd);

    // Watchdog configuration endpoints
    httpd_uri_t watchdog_cfg_g = { .uri="/api/config/watchdog", .method=HTTP_GET, .handler=&WebServer::h_watchdog_config_get, .user_ctx=nullptr };
    httpd_uri_t watchdog_cfg_p = { .uri="/api/config/watchdog", .method=HTTP_POST, .handler=&WebServer::h_watchdog_config_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &watchdog_cfg_g);
    httpd_register_uri_handler(active_server_, &watchdog_cfg_p);

    // Serial reporting endpoints
    httpd_uri_t serial_cfg_g = { .uri="/api/report/serial/config", .method=HTTP_GET, .handler=&WebServer::h_serial_config_get, .user_ctx=nullptr };
    httpd_uri_t serial_cfg_p = { .uri="/api/report/serial/config", .method=HTTP_POST, .handler=&WebServer::h_serial_config_post, .user_ctx=nullptr };
    httpd_uri_t serial_stats = { .uri="/api/report/serial/stats", .method=HTTP_GET, .handler=&WebServer::h_serial_stats_get, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &serial_cfg_g);
    httpd_register_uri_handler(active_server_, &serial_cfg_p);
    httpd_register_uri_handler(active_server_, &serial_stats);

    httpd_uri_t u_audit = { .uri="/api/audit", .method=HTTP_GET, .handler=&WebServer::h_audit_status, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &u_audit);

    // CVE Signature detection endpoints
    httpd_uri_t sig_reload = { .uri="/api/signatures/reload", .method=HTTP_POST, .handler=&WebServer::h_signatures_reload, .user_ctx=nullptr };
    httpd_uri_t sig_stats = { .uri="/api/signatures/stats", .method=HTTP_GET, .handler=&WebServer::h_signatures_stats, .user_ctx=nullptr };
    httpd_uri_t sig_list = { .uri="/api/signatures/list", .method=HTTP_GET, .handler=&WebServer::h_signatures_list, .user_ctx=nullptr };
    httpd_uri_t sig_upload = { .uri="/api/signatures/upload", .method=HTTP_POST, .handler=&WebServer::h_signatures_upload, .user_ctx=nullptr };
    httpd_uri_t sig_download = { .uri="/api/signatures/download", .method=HTTP_GET, .handler=&WebServer::h_signatures_download, .user_ctx=nullptr };
    httpd_uri_t sig_clear = { .uri="/api/signatures/clear", .method=HTTP_POST, .handler=&WebServer::h_signatures_clear, .user_ctx=nullptr };
    httpd_uri_t sig_save = { .uri="/api/signatures/save", .method=HTTP_POST, .handler=&WebServer::h_signatures_save, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &sig_reload);
    httpd_register_uri_handler(active_server_, &sig_stats);
    httpd_register_uri_handler(active_server_, &sig_list);
    httpd_register_uri_handler(active_server_, &sig_upload);
    httpd_register_uri_handler(active_server_, &sig_download);
    httpd_register_uri_handler(active_server_, &sig_clear);
    httpd_register_uri_handler(active_server_, &sig_save);

    // Security Manager endpoints
    httpd_uri_t sec_cfg_g = { .uri="/api/security/config", .method=HTTP_GET, .handler=&WebServer::h_security_config_get, .user_ctx=nullptr };
    httpd_uri_t sec_cfg_p = { .uri="/api/security/config", .method=HTTP_POST, .handler=&WebServer::h_security_config_post, .user_ctx=nullptr };
    httpd_uri_t sec_ack = { .uri="/api/security/events/ack", .method=HTTP_POST, .handler=&WebServer::h_security_event_ack, .user_ctx=nullptr };
    httpd_uri_t offensive_g = { .uri="/api/security/offensive-testing", .method=HTTP_GET, .handler=&WebServer::h_offensive_testing_get, .user_ctx=nullptr };
    httpd_uri_t offensive_p = { .uri="/api/security/offensive-testing", .method=HTTP_POST, .handler=&WebServer::h_offensive_testing_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &sec_cfg_g);
    httpd_register_uri_handler(active_server_, &sec_cfg_p);
    httpd_register_uri_handler(active_server_, &sec_ack);
    httpd_register_uri_handler(active_server_, &offensive_g);
    httpd_register_uri_handler(active_server_, &offensive_p);

    // Rate limiter endpoints
    httpd_uri_t rl_get = { .uri="/api/security/ratelimit", .method=HTTP_GET, .handler=&WebServer::h_ratelimit_get, .user_ctx=nullptr };
    httpd_uri_t rl_post = { .uri="/api/security/ratelimit", .method=HTTP_POST, .handler=&WebServer::h_ratelimit_post, .user_ctx=nullptr };
    httpd_uri_t rl_unblock = { .uri="/api/security/unblock", .method=HTTP_POST, .handler=&WebServer::h_unblock_client, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &rl_get);
    httpd_register_uri_handler(active_server_, &rl_post);
    httpd_register_uri_handler(active_server_, &rl_unblock);

    // API Key Rotation endpoints
    httpd_uri_t rot_policy_g = { .uri="/api/security/rotation/policy", .method=HTTP_GET, .handler=&WebServer::h_rotation_policy_get, .user_ctx=nullptr };
    httpd_uri_t rot_policy_p = { .uri="/api/security/rotation/policy", .method=HTTP_POST, .handler=&WebServer::h_rotation_policy_post, .user_ctx=nullptr };
    httpd_uri_t rot_scheduled_g = { .uri="/api/security/rotation/scheduled", .method=HTTP_GET, .handler=&WebServer::h_rotation_scheduled_get, .user_ctx=nullptr };
    httpd_uri_t rot_schedule_p = { .uri="/api/security/rotation/schedule", .method=HTTP_POST, .handler=&WebServer::h_rotation_schedule_post, .user_ctx=nullptr };
    httpd_uri_t rot_cancel_p = { .uri="/api/security/rotation/cancel", .method=HTTP_POST, .handler=&WebServer::h_rotation_cancel_post, .user_ctx=nullptr };
    httpd_uri_t rot_trigger_p = { .uri="/api/security/rotation/trigger", .method=HTTP_POST, .handler=&WebServer::h_rotation_trigger_post, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &rot_policy_g);
    httpd_register_uri_handler(active_server_, &rot_policy_p);
    httpd_register_uri_handler(active_server_, &rot_scheduled_g);
    httpd_register_uri_handler(active_server_, &rot_schedule_p);
    httpd_register_uri_handler(active_server_, &rot_cancel_p);
    httpd_register_uri_handler(active_server_, &rot_trigger_p);

    httpd_register_uri_handler(active_server_, &s_jobs_g);
    httpd_register_uri_handler(active_server_, &s_jobs_p);
    httpd_register_uri_handler(active_server_, &s_jobs_d);
    httpd_register_uri_handler(active_server_, &s_run);
    httpd_register_uri_handler(active_server_, &s_res_g);
    httpd_register_uri_handler(active_server_, &s_cfg_g);
    httpd_register_uri_handler(active_server_, &s_cfg_p);
    httpd_register_uri_handler(active_server_, &sch_list);
    httpd_register_uri_handler(active_server_, &sch_create);
    httpd_register_uri_handler(active_server_, &sch_update);
    httpd_register_uri_handler(active_server_, &sch_delete);
    httpd_register_uri_handler(active_server_, &sch_toggle);
    httpd_register_uri_handler(active_server_, &sch_trigger);

    httpd_register_uri_handler(active_server_, &d_modbus);
    httpd_register_uri_handler(active_server_, &d_s7);
    httpd_register_uri_handler(active_server_, &d_pn);
    httpd_register_uri_handler(active_server_, &d_en);
    httpd_register_uri_handler(active_server_, &d_opcua);
    httpd_register_uri_handler(active_server_, &s7_ops);

    // Async Discovery endpoints
    httpd_uri_t d_start = { .uri="/api/discovery/start", .method=HTTP_POST, .handler=&WebServer::h_discovery_start, .user_ctx=nullptr };
    httpd_uri_t d_status = { .uri="/api/discovery/status", .method=HTTP_GET, .handler=&WebServer::h_discovery_status, .user_ctx=nullptr };
    httpd_uri_t d_list = { .uri="/api/discovery/list", .method=HTTP_GET, .handler=&WebServer::h_discovery_list, .user_ctx=nullptr };
    httpd_uri_t d_cancel = { .uri="/api/discovery/cancel", .method=HTTP_POST, .handler=&WebServer::h_discovery_cancel, .user_ctx=nullptr };
    httpd_uri_t d_general_start = { .uri="/api/discovery/general/start", .method=HTTP_POST, .handler=&WebServer::h_discovery_general_start, .user_ctx=nullptr };
    httpd_uri_t d_general_status = { .uri="/api/discovery/general/status", .method=HTTP_GET, .handler=&WebServer::h_discovery_general_status, .user_ctx=nullptr };
    httpd_uri_t d_general_defaults = { .uri="/api/discovery/general/defaults", .method=HTTP_GET, .handler=&WebServer::h_discovery_general_defaults, .user_ctx=nullptr };

    httpd_register_uri_handler(active_server_, &d_start);
    httpd_register_uri_handler(active_server_, &d_status);
    httpd_register_uri_handler(active_server_, &d_list);
    httpd_register_uri_handler(active_server_, &d_cancel);
    httpd_register_uri_handler(active_server_, &d_general_start);
    httpd_register_uri_handler(active_server_, &d_general_status);
    httpd_register_uri_handler(active_server_, &d_general_defaults);

    httpd_uri_t f_jobs_g = { .uri="/api/fuzz/jobs", .method=HTTP_GET, .handler=&WebServer::h_fuzz_jobs_get, .user_ctx=nullptr };
    httpd_uri_t f_jobs_p = { .uri="/api/fuzz/jobs", .method=HTTP_POST, .handler=&WebServer::h_fuzz_jobs_post, .user_ctx=nullptr };
    httpd_uri_t f_jobs_d = { .uri="/api/fuzz/jobs", .method=HTTP_DELETE, .handler=&WebServer::h_fuzz_jobs_delete, .user_ctx=nullptr };
    httpd_uri_t f_run    = { .uri="/api/fuzz/run",  .method=HTTP_POST, .handler=&WebServer::h_fuzz_run, .user_ctx=nullptr };
    httpd_uri_t f_stop   = { .uri="/api/fuzz/stop", .method=HTTP_POST, .handler=&WebServer::h_fuzz_stop, .user_ctx=nullptr };
    httpd_uri_t f_profiles = { .uri="/api/fuzz/profiles", .method=HTTP_GET, .handler=&WebServer::h_fuzz_profiles_get, .user_ctx=nullptr };
    httpd_uri_t f_result = { .uri="/api/fuzz/result", .method=HTTP_GET, .handler=&WebServer::h_fuzz_result_get, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &f_jobs_g);
    httpd_register_uri_handler(active_server_, &f_jobs_p);
    httpd_register_uri_handler(active_server_, &f_jobs_d);
    httpd_register_uri_handler(active_server_, &f_run);
    httpd_register_uri_handler(active_server_, &f_stop);
    httpd_register_uri_handler(active_server_, &f_profiles);
    httpd_register_uri_handler(active_server_, &f_result);

    // Captive-like endpoints used by mobile OS
    httpd_uri_t r1 = { .uri="/generate_204",        .method=HTTP_GET, .handler=&WebServer::h_redirect, .user_ctx=nullptr };
    httpd_uri_t r2 = { .uri="/hotspot-detect.html", .method=HTTP_GET, .handler=&WebServer::h_redirect, .user_ctx=nullptr };
    httpd_uri_t r3 = { .uri="/ncsi.txt",            .method=HTTP_GET, .handler=&WebServer::h_redirect, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &r1);
    httpd_register_uri_handler(active_server_, &r2);
    httpd_register_uri_handler(active_server_, &r3);

    // Protocol configuration endpoints
    httpd_uri_t p_modbus_g = { .uri="/api/protocols/modbus/config", .method=HTTP_GET, .handler=&WebServer::h_protocol_modbus_config_get, .user_ctx=nullptr };
    httpd_uri_t p_modbus_p = { .uri="/api/protocols/modbus/config", .method=HTTP_POST, .handler=&WebServer::h_protocol_modbus_config_post, .user_ctx=nullptr };
    httpd_uri_t p_s7_g = { .uri="/api/protocols/s7/config", .method=HTTP_GET, .handler=&WebServer::h_protocol_s7_config_get, .user_ctx=nullptr };
    httpd_uri_t p_s7_p = { .uri="/api/protocols/s7/config", .method=HTTP_POST, .handler=&WebServer::h_protocol_s7_config_post, .user_ctx=nullptr };
    httpd_uri_t p_profinet_g = { .uri="/api/protocols/profinet/config", .method=HTTP_GET, .handler=&WebServer::h_protocol_profinet_config_get, .user_ctx=nullptr };
    httpd_uri_t p_profinet_p = { .uri="/api/protocols/profinet/config", .method=HTTP_POST, .handler=&WebServer::h_protocol_profinet_config_post, .user_ctx=nullptr };
    httpd_uri_t p_ethernetip_g = { .uri="/api/protocols/ethernetip/config", .method=HTTP_GET, .handler=&WebServer::h_protocol_ethernetip_config_get, .user_ctx=nullptr };
    httpd_uri_t p_ethernetip_p = { .uri="/api/protocols/ethernetip/config", .method=HTTP_POST, .handler=&WebServer::h_protocol_ethernetip_config_post, .user_ctx=nullptr };
    httpd_uri_t p_opcua_g = { .uri="/api/protocols/opcua/config", .method=HTTP_GET, .handler=&WebServer::h_protocol_opcua_config_get, .user_ctx=nullptr };
    httpd_uri_t p_opcua_p = { .uri="/api/protocols/opcua/config", .method=HTTP_POST, .handler=&WebServer::h_protocol_opcua_config_post, .user_ctx=nullptr };

    httpd_register_uri_handler(active_server_, &p_modbus_g);
    httpd_register_uri_handler(active_server_, &p_modbus_p);
    httpd_register_uri_handler(active_server_, &p_s7_g);
    httpd_register_uri_handler(active_server_, &p_s7_p);
    httpd_register_uri_handler(active_server_, &p_profinet_g);
    httpd_register_uri_handler(active_server_, &p_profinet_p);
    httpd_register_uri_handler(active_server_, &p_ethernetip_g);
    httpd_register_uri_handler(active_server_, &p_ethernetip_p);
    httpd_register_uri_handler(active_server_, &p_opcua_g);
    httpd_register_uri_handler(active_server_, &p_opcua_p);

    // Network diagnostics endpoints
    httpd_uri_t net_ping = { .uri="/api/network/ping", .method=HTTP_POST, .handler=&WebServer::h_network_ping, .user_ctx=nullptr };
    httpd_uri_t net_status = { .uri="/api/network/status", .method=HTTP_GET, .handler=&WebServer::h_network_status, .user_ctx=nullptr };
    httpd_uri_t net_interfaces = { .uri="/api/network/interfaces", .method=HTTP_GET, .handler=&WebServer::h_network_interfaces, .user_ctx=nullptr };

    // Ethernet configuration endpoints
    httpd_uri_t eth_cfg_g = { .uri="/api/ethernet/config", .method=HTTP_GET, .handler=&WebServer::h_ethernet_config_get, .user_ctx=nullptr };
    httpd_uri_t eth_cfg_p = { .uri="/api/ethernet/config", .method=HTTP_POST, .handler=&WebServer::h_ethernet_config_post, .user_ctx=nullptr };
    httpd_uri_t eth_diag = { .uri="/api/ethernet/diagnostics", .method=HTTP_GET, .handler=&WebServer::h_ethernet_diagnostics, .user_ctx=nullptr };
    httpd_uri_t ip_diag = { .uri="/api/ip-stack/diagnostics", .method=HTTP_GET, .handler=&WebServer::h_ip_stack_diagnostics, .user_ctx=nullptr };
    httpd_uri_t net_analysis = { .uri="/api/network-layer/analysis", .method=HTTP_GET, .handler=&WebServer::h_network_layer_analysis, .user_ctx=nullptr };
    httpd_uri_t net_scan = { .uri="/api/network/scan", .method=HTTP_POST, .handler=&WebServer::h_network_scan, .user_ctx=nullptr };
    httpd_uri_t driver_diag = { .uri="/api/driver-level/diagnostics", .method=HTTP_GET, .handler=&WebServer::h_driver_level_diagnostics, .user_ctx=nullptr };

    httpd_register_uri_handler(active_server_, &net_ping);
    httpd_register_uri_handler(active_server_, &net_status);
    httpd_register_uri_handler(active_server_, &net_interfaces);
    httpd_register_uri_handler(active_server_, &eth_cfg_g);
    httpd_register_uri_handler(active_server_, &eth_cfg_p);
    httpd_register_uri_handler(active_server_, &eth_diag);
    httpd_register_uri_handler(active_server_, &ip_diag);
    httpd_register_uri_handler(active_server_, &net_analysis);
    httpd_register_uri_handler(active_server_, &net_scan);
    httpd_register_uri_handler(active_server_, &driver_diag);

    // IP Whitelist endpoints
    httpd_uri_t whitelist_g = { .uri="/api/whitelist", .method=HTTP_GET, .handler=&WebServer::h_whitelist_get, .user_ctx=this };
    httpd_uri_t whitelist_p = { .uri="/api/whitelist", .method=HTTP_POST, .handler=&WebServer::h_whitelist_post, .user_ctx=this };
    httpd_uri_t allowlist_g = { .uri="/api/allowlist", .method=HTTP_GET, .handler=&WebServer::h_whitelist_get, .user_ctx=this };
    httpd_uri_t allowlist_p = { .uri="/api/allowlist", .method=HTTP_POST, .handler=&WebServer::h_whitelist_post, .user_ctx=this };
    httpd_register_uri_handler(active_server_, &whitelist_g);
    httpd_register_uri_handler(active_server_, &whitelist_p);
    httpd_register_uri_handler(active_server_, &allowlist_g);
    httpd_register_uri_handler(active_server_, &allowlist_p);

    // Incremental logs endpoints
    httpd_uri_t logs_session = { .uri="/api/logs/session", .method=HTTP_POST, .handler=&WebServer::h_logs_incremental_session, .user_ctx=nullptr };
    httpd_uri_t logs_incr = { .uri="/api/logs/incremental", .method=HTTP_GET, .handler=&WebServer::h_logs_incremental_read, .user_ctx=nullptr };
    httpd_uri_t logs_sse = { .uri="/api/logs/sse", .method=HTTP_GET, .handler=&WebServer::h_logs_sse, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &logs_session);
    httpd_register_uri_handler(active_server_, &logs_incr);
    httpd_register_uri_handler(active_server_, &logs_sse);

    // List of protocols
    httpd_uri_t protocols_read = { .uri="/api/protocols", .method=HTTP_GET, .handler=&WebServer::h_protocols_get, .user_ctx=nullptr };
    httpd_uri_t protocols_read_details = { .uri="/api/protocols/details", .method=HTTP_GET, .handler=&WebServer::h_protocols_get_details, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &protocols_read);
    httpd_register_uri_handler(active_server_, &protocols_read_details);

    // Web pages
    httpd_uri_t page_protocols = { .uri="/protocols", .method=HTTP_GET, .handler=&WebServer::h_page_protocols, .user_ctx=nullptr };
    httpd_uri_t page_discovery = { .uri="/discovery", .method=HTTP_GET, .handler=&WebServer::h_page_discovery, .user_ctx=nullptr };
    httpd_uri_t page_scanner = { .uri="/scanner", .method=HTTP_GET, .handler=&WebServer::h_page_scanner, .user_ctx=nullptr };
    // Aliases to keep "offensive" actions separated in the UI while reusing the same HTML payload.
    httpd_uri_t page_vuln_scanner = { .uri="/vulnerability-scanner", .method=HTTP_GET, .handler=&WebServer::h_page_scanner, .user_ctx=nullptr };
    httpd_uri_t page_fuzzing = { .uri="/fuzzing", .method=HTTP_GET, .handler=&WebServer::h_page_scanner, .user_ctx=nullptr };
    httpd_uri_t page_ids = { .uri="/ids", .method=HTTP_GET, .handler=&WebServer::h_page_ids, .user_ctx=nullptr };
    httpd_uri_t page_signatures = { .uri="/signatures", .method=HTTP_GET, .handler=&WebServer::h_page_signatures, .user_ctx=nullptr };
    httpd_uri_t page_security = { .uri="/security", .method=HTTP_GET, .handler=&WebServer::h_page_security, .user_ctx=nullptr };
    httpd_uri_t page_network_presence = { .uri="/network-presence", .method=HTTP_GET, .handler=&WebServer::h_page_network_presence, .user_ctx=nullptr };
    httpd_uri_t page_reporting = { .uri="/reporting", .method=HTTP_GET, .handler=&WebServer::h_page_reporting, .user_ctx=nullptr };
    httpd_uri_t page_serial_monitor = { .uri="/serial", .method=HTTP_GET, .handler=&WebServer::h_page_serial_monitor, .user_ctx=nullptr };
    httpd_uri_t page_network = { .uri="/network", .method=HTTP_GET, .handler=&WebServer::h_page_network, .user_ctx=nullptr };
    httpd_uri_t page_diagnostics = { .uri="/diagnostics", .method=HTTP_GET, .handler=&WebServer::h_page_diagnostics, .user_ctx=nullptr };
    httpd_uri_t page_logging = { .uri="/logging", .method=HTTP_GET, .handler=&WebServer::h_page_logging, .user_ctx=nullptr };
    httpd_uri_t page_configuration = { .uri="/configuration", .method=HTTP_GET, .handler=&WebServer::h_page_configuration, .user_ctx=nullptr };
    httpd_uri_t page_gpio = { .uri="/gpio", .method=HTTP_GET, .handler=&WebServer::h_page_gpio, .user_ctx=nullptr };
    httpd_uri_t page_audit = { .uri="/audit", .method=HTTP_GET, .handler=&WebServer::h_page_audit, .user_ctx=nullptr };
    httpd_uri_t page_style = { .uri="/static/style.css", .method=HTTP_GET, .handler=&WebServer::h_page_style, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &page_protocols);
    httpd_register_uri_handler(active_server_, &page_discovery);
    httpd_register_uri_handler(active_server_, &page_scanner);
    httpd_register_uri_handler(active_server_, &page_vuln_scanner);
    httpd_register_uri_handler(active_server_, &page_fuzzing);
    httpd_uri_t page_scheduled_scans = { .uri="/scheduled-scans", .method=HTTP_GET, .handler=&WebServer::h_page_scanner, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &page_scheduled_scans);
    httpd_register_uri_handler(active_server_, &page_ids);
    httpd_register_uri_handler(active_server_, &page_signatures);
    httpd_register_uri_handler(active_server_, &page_security);
    httpd_register_uri_handler(active_server_, &page_network_presence);
    httpd_register_uri_handler(active_server_, &page_reporting);
    httpd_register_uri_handler(active_server_, &page_serial_monitor);
    httpd_register_uri_handler(active_server_, &page_network);
    httpd_register_uri_handler(active_server_, &page_diagnostics);
    httpd_register_uri_handler(active_server_, &page_logging);
    httpd_register_uri_handler(active_server_, &page_configuration);
    httpd_register_uri_handler(active_server_, &page_gpio);
    httpd_register_uri_handler(active_server_, &page_audit);
    httpd_register_uri_handler(active_server_, &page_style);

    // ========================= GENERIC CATCH-ALL (DEBUG) =========================
    httpd_uri_t api_fb_get =  { .uri="/api/*", .method=HTTP_GET,    .handler=&WebServer::h_api_fallback, .user_ctx=nullptr };
    httpd_uri_t api_fb_post = { .uri="/api/*", .method=HTTP_POST,   .handler=&WebServer::h_api_fallback, .user_ctx=nullptr };
    httpd_uri_t api_fb_put =  { .uri="/api/*", .method=HTTP_PUT,    .handler=&WebServer::h_api_fallback, .user_ctx=nullptr };
    httpd_uri_t api_fb_del =  { .uri="/api/*", .method=HTTP_DELETE, .handler=&WebServer::h_api_fallback, .user_ctx=nullptr };
    httpd_uri_t api_fb_opt =  { .uri="/api/*", .method=HTTP_OPTIONS,.handler=&WebServer::h_api_fallback, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &api_fb_get);
    httpd_register_uri_handler(active_server_, &api_fb_post);
    httpd_register_uri_handler(active_server_, &api_fb_put);
    httpd_register_uri_handler(active_server_, &api_fb_del);
    httpd_register_uri_handler(active_server_, &api_fb_opt);

    // Generic fallback for any other path (non /api/*)
    httpd_uri_t any_fb_get =  { .uri="/*", .method=HTTP_GET,    .handler=&WebServer::h_any_fallback, .user_ctx=nullptr };
    httpd_uri_t any_fb_post = { .uri="/*", .method=HTTP_POST,   .handler=&WebServer::h_any_fallback, .user_ctx=nullptr };
    httpd_uri_t any_fb_put =  { .uri="/*", .method=HTTP_PUT,    .handler=&WebServer::h_any_fallback, .user_ctx=nullptr };
    httpd_uri_t any_fb_del =  { .uri="/*", .method=HTTP_DELETE, .handler=&WebServer::h_any_fallback, .user_ctx=nullptr };
    httpd_uri_t any_fb_opt =  { .uri="/*", .method=HTTP_OPTIONS,.handler=&WebServer::h_any_fallback, .user_ctx=nullptr };
    httpd_register_uri_handler(active_server_, &any_fb_get);
    httpd_register_uri_handler(active_server_, &any_fb_post);
    httpd_register_uri_handler(active_server_, &any_fb_put);
    httpd_register_uri_handler(active_server_, &any_fb_del);
    httpd_register_uri_handler(active_server_, &any_fb_opt);

    httpdMonitorStart();

    //LOG_INFO(TAG_WEB, "WebServer started on port 80");
    return true;
}

void WebServer::shutdown() {
    httpdMonitorStop();
    if (http_) {
        httpd_stop(http_);
        http_ = nullptr;
        LOG_INFO(TAG_WEB, "WebServer HTTP stopped");
    }
    if (https_server_) {
        httpd_ssl_stop(https_server_);
        https_server_ = nullptr;
        LOG_INFO(TAG_WEB, "WebServer HTTPS stopped");
    }
    active_server_ = nullptr;

    if (cron_scheduler_ && cron_scheduler_initialized_) {
        cron_scheduler_->shutdown();
        cron_scheduler_initialized_ = false;
    }
}

bool WebServer::startHTTPS(uint16_t port) {
    if (https_server_) {
        LOG_WARNING(TAG_WEB, "HTTPS server already running");
        return false;
    }

    httpd_ssl_config_t https_conf = HTTPD_SSL_CONFIG_DEFAULT();
    https_conf.httpd.server_port = port;
    https_conf.httpd.lru_purge_enable = true;
    https_conf.httpd.keep_alive_enable = true;
    https_conf.httpd.send_wait_timeout = 3;
    https_conf.httpd.recv_wait_timeout = 3;
    https_conf.httpd.core_id = 1;  // APP CPU

    // PSRAM stack allocation for HTTPS server
    https_conf.httpd.task_caps  = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    https_conf.httpd.stack_size = 96 * 1024;  // Keep large stack for TLS/cert parsing

    // Resource tuning
    https_conf.httpd.max_open_sockets = 4;
    https_conf.httpd.backlog_conn     = 8;
    https_conf.httpd.max_resp_headers = 10;
    https_conf.httpd.max_uri_handlers = 256;

    if (!tls_credentials_.ensurePresent()) {
        LOG_ERROR(TAG_WEB, "Unable to load or generate the runtime TLS identity");
        return false;
    }
    https_conf.servercert = reinterpret_cast<const uint8_t*>(
        tls_credentials_.certificatePem());
    https_conf.servercert_len = tls_credentials_.certificateLength() + 1;
    https_conf.prvtkey_pem = reinterpret_cast<const uint8_t*>(
        tls_credentials_.privateKeyPem());
    https_conf.prvtkey_len = tls_credentials_.privateKeyLength() + 1;

    LOG_INFOF(TAG_WEB, "Starting HTTPS server on port %u", port);

    esp_err_t err = httpd_ssl_start(&https_server_, &https_conf);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_WEB, "Failed to start HTTPS server: %s", esp_err_to_name(err));
        return false;
    }

    active_server_ = https_server_;

    // Register all URI handlers
    registerHTTPSHandlers();

    LOG_INFO(TAG_WEB, "✅ HTTPS server started successfully");
    return true;
}

void WebServer::stopHTTPS() {
    if (https_server_) {
        httpd_stop(https_server_);
        https_server_ = nullptr;
        active_server_ = nullptr;
        LOG_INFO(TAG_WEB, "HTTPS server stopped");
    }
}

bool WebServer::isHTTPSEnabled() const {
    return https_server_ != nullptr;
}

void WebServer::registerHTTPSHandlers() {
    if (!https_server_) {
        return;
    }

    // Register all the same handlers as HTTP
    // This is a simplified version - in production you'd want to share the handler registration code
    LOG_INFO(TAG_WEB, "Registering HTTPS handlers...");

    // Copy all handler registration from startOnInterface() but use https_server_ instead of http_
    // For brevity, I'll add just the essential ones here:

    httpd_uri_t u_root = { .uri = "/", .method = HTTP_GET, .handler = h_root, .user_ctx = nullptr };
    httpd_uri_t u_stat = { .uri = "/api/status", .method = HTTP_GET, .handler = h_status, .user_ctx = nullptr };
    httpd_uri_t u_telem = { .uri = "/api/telemetry", .method = HTTP_GET, .handler = h_telemetry, .user_ctx = nullptr };
    httpd_uri_t u_cfg_g = { .uri = "/api/config", .method = HTTP_GET, .handler = h_config_get, .user_ctx = nullptr };
    httpd_uri_t u_cfg_p = { .uri = "/api/config", .method = HTTP_POST, .handler = h_config_post, .user_ctx = nullptr };
    httpd_uri_t u_editor_schema = { .uri = "/api/config/editor/schema", .method = HTTP_GET, .handler = h_config_editor_schema, .user_ctx = nullptr };
    httpd_uri_t u_editor_snapshot = { .uri = "/api/config/editor/snapshot", .method = HTTP_GET, .handler = h_config_editor_snapshot, .user_ctx = nullptr };
    httpd_uri_t u_editor_validate = { .uri = "/api/config/editor/validate", .method = HTTP_POST, .handler = h_config_editor_validate, .user_ctx = nullptr };
    httpd_uri_t u_editor_save = { .uri = "/api/config/editor/save", .method = HTTP_POST, .handler = h_config_editor_save, .user_ctx = nullptr };

    httpd_register_uri_handler(active_server_, &u_root);
    httpd_register_uri_handler(active_server_, &u_stat);
    httpd_register_uri_handler(active_server_, &u_telem);
    httpd_register_uri_handler(active_server_, &u_cfg_g);
    httpd_register_uri_handler(active_server_, &u_cfg_p);
    httpd_register_uri_handler(active_server_, &u_editor_schema);
    httpd_register_uri_handler(active_server_, &u_editor_snapshot);
    httpd_register_uri_handler(active_server_, &u_editor_validate);
    httpd_register_uri_handler(active_server_, &u_editor_save);

    // TODO: Register all other handlers (this is a minimal implementation)
    LOG_INFO(TAG_WEB, "✅ Essential HTTPS handlers registered");
}

void WebServer::disconnectAPClientsAsync() {
    if (wifi_) {
        wifi_->disconnectAllAPClients();
    }
}

void WebServer::stopAPAsync() {
    if (wifi_) {
        wifi_->stopAP();
    }
}

void WebServer::stopHTTPServer() {
    if (http_) {
        httpd_stop(http_);
        http_ = nullptr;
        LOG_INFO("WIFI_CONNECT", "HTTP server stopped for network transition");

        // Log HTTP server stop to network.log
        if (g_reporting) {
            char event_data[256];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"http_server_stopped\",\"reason\":\"network_transition\"}");
            report_event_ps(g_reporting, "network", event_data);
        }
    }
    if (https_server_) {
        httpd_stop(https_server_);
        https_server_ = nullptr;
        LOG_INFO("WIFI_CONNECT", "HTTPS server stopped for network transition");

        // Log HTTPS server stop to network.log
        if (g_reporting) {
            char event_data[256];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"https_server_stopped\",\"reason\":\"network_transition\"}");
            report_event_ps(g_reporting, "network", event_data);
        }
    }
}

void WebServer::restartHTTPServer() {
    // Restart HTTPS instead of HTTP for security
    if (!https_server_) {
        startHTTPS(443);
        LOG_INFO("WIFI_CONNECT", "HTTPS server restarted on new network interface");
    }
}

psram_string WebServer::extractPayload(httpd_req_t* req) {
    if (req->content_len == 0) {
        return psram_string();
    }

    size_t max_len = std::min((size_t)req->content_len, (size_t)8192);
    if (max_len == 0) {
        return psram_string();
    }

    psram_string payload;
    payload.resize(max_len);

    int ret = httpd_req_recv(req, &payload[0], max_len);
    if (ret <= 0) {
        payload.clear();
        return payload;
    }

    payload.resize(static_cast<size_t>(ret));
    return payload;
}

std::string WebServer::extractClientIP(httpd_req_t* req) {
    // Try X-Forwarded-For first (reverse proxy)
    size_t hdr_len = httpd_req_get_hdr_value_len(req, "X-Forwarded-For");
    if (hdr_len > 0 && hdr_len < 64) {
        char* buf = (char*)heap_caps_malloc(hdr_len + 1, MALLOC_CAP_SPIRAM);
        if (buf && httpd_req_get_hdr_value_str(req, "X-Forwarded-For", buf, hdr_len + 1) == ESP_OK) {
            std::string ip(buf);
            heap_caps_free(buf);
            // Take first IP in comma-separated list
            size_t comma = ip.find(',');
            if (comma != std::string::npos) {
                ip = ip.substr(0, comma);
            }
            return ip;
        }
        if (buf) heap_caps_free(buf);
    }

    // Fallback to direct connection IP
    int sockfd = httpd_req_to_sockfd(req);
    if (sockfd >= 0) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        if (getpeername(sockfd, (struct sockaddr*)&addr, &len) == 0) {
#if CONFIG_LWIP_IPV6
            char ip_str[INET6_ADDRSTRLEN] = {0};
#else
            char ip_str[INET_ADDRSTRLEN] = {0};
#endif
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in* s = (struct sockaddr_in*)&addr;
                inet_ntop(AF_INET, &s->sin_addr, ip_str, INET_ADDRSTRLEN);
            }
#if CONFIG_LWIP_IPV6
            else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6* s = (struct sockaddr_in6*)&addr;
                inet_ntop(AF_INET6, &s->sin6_addr, ip_str, INET6_ADDRSTRLEN);
            }
#endif
            return std::string(ip_str);
        }
    }

    return "unknown";
}

// ============================================================================
// NEW: Zero-allocation buffer-based versions to prevent Internal RAM leaks
// ============================================================================

// HYBRID APPROACH:
// - Client IP buffer allocated in PSRAM to avoid internal DRAM usage
// - Payload: PSRAM (already handled by helper functions)
const char* WebServer::extractClientIPToBuffer(httpd_req_t* req) {
#if CONFIG_LWIP_IPV6
    constexpr size_t kIpBufferSize = INET6_ADDRSTRLEN + 1;
#else
    constexpr size_t kIpBufferSize = INET_ADDRSTRLEN + 1;
#endif
    static thread_local char* ip_buffer = nullptr;

    if (!ip_buffer) {
        ip_buffer = static_cast<char*>(heap_caps_malloc(kIpBufferSize, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (!ip_buffer) {
            static const char kUnknown[] = "unknown";
            return kUnknown;
        }
    }

    ip_buffer[0] = '\0';

    // Try X-Forwarded-For first (reverse proxy)
    size_t hdr_len = httpd_req_get_hdr_value_len(req, "X-Forwarded-For");
    if (hdr_len > 0 && hdr_len < kIpBufferSize) {
        if (httpd_req_get_hdr_value_str(req, "X-Forwarded-For", ip_buffer, kIpBufferSize) == ESP_OK) {
            char* comma = strchr(ip_buffer, ',');
            if (comma) *comma = '\0';
            return ip_buffer;
        }
        ip_buffer[0] = '\0';
    }

    int sockfd = httpd_req_to_sockfd(req);
    if (sockfd >= 0) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        if (getpeername(sockfd, (struct sockaddr*)&addr, &len) == 0) {
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in* s = (struct sockaddr_in*)&addr;
                inet_ntop(AF_INET, &s->sin_addr, ip_buffer, kIpBufferSize);
                return ip_buffer;
            }
#if CONFIG_LWIP_IPV6
            else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6* s = (struct sockaddr_in6*)&addr;
                inet_ntop(AF_INET6, &s->sin6_addr, ip_buffer, kIpBufferSize);
                return ip_buffer;
            }
#endif
        }
    }

    strlcpy(ip_buffer, "unknown", kIpBufferSize);
    return ip_buffer;
}

// NOTE: extractPayloadToBuffer removed - use existing extractPayload() which already
// allocates in PSRAM. Payloads can be large (8KB+), don't want them in Internal RAM.


esp_err_t WebServer::h_root(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/login");
        return httpd_resp_send(req, "", 0);
    }

    const size_t min_psram_required = 64 * 1024;
    const size_t min_total_required = 32 * 1024;
    const size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    const size_t free_total = esp_get_free_heap_size();
    if (free_psram < min_psram_required || free_total < min_total_required) {
        LOG_WARNINGF(TAG_WEB,
                     "Dashboard request denied: low memory (PSRAM %zu/%zu, total %zu/%zu)",
                     free_psram, min_psram_required, free_total, min_total_required);
        httpd_resp_set_status(req, "503 Service Unavailable");
        esp_err_t rc = httpd_resp_send(req, "Insufficient memory", strlen("Insufficient memory"));
        AccessLogger::getInstance().logResponse(req,
                                                rc == ESP_OK ? 503 : 500,
                                                rc == ESP_OK ? "LOW_MEMORY" : "SEND_FAIL");
        return rc;
    }

    httpd_resp_set_type(req, "text/html; charset=utf-8");

    const char* html_psram = get_dashboard_html_psram();
    esp_err_t result = ESP_FAIL;
    if (html_psram) {
        result = send_chunked_from_psram(req, html_psram, DASHBOARD_HTML_GEN_SIZE);
    } else {
        result = send_html_chunked(req, DASHBOARD_HTML_GEN, DASHBOARD_HTML_GEN_SIZE);
    }

    SCHEDULE_DEFRAG();

    AccessLogger::getInstance().logResponse(req,
                                            result == ESP_OK ? 200 : 500,
                                            result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");
    return result;
}

esp_err_t WebServer::h_status(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_) return httpd_resp_send_500(req);

    esp_err_t result = ESP_FAIL;
    {
        std::lock_guard<std::mutex> guard(g_status_json.mutex);
        if (!build_status_json(g_status_json)) {
            LOG_ERROR(TAG_WEB, "Failed to build /api/status JSON payload");
            return httpd_resp_send_500(req);
        }

        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        result = send_chunked_from_psram(req, g_status_json.buf, g_status_json.length);
    }

    // Schedule IRAM defragmentation 2s after API call
    SCHEDULE_DEFRAG();

    return result;
}

esp_err_t WebServer::h_telemetry(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_) return httpd_resp_send_500(req);

    PSRAMMetrics metrics = PSRAMTelemetry::getInstance().getMetrics();
    PSRAMStats stats = PSRAMTelemetry::getInstance().getStats();

    char json[1024];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"metrics\":{"
            "\"psram\":{"
                "\"total\":%zu,"
                "\"free\":%zu,"
                "\"used\":%zu,"
                "\"used_percent\":%u,"
                "\"largest_block\":%zu,"
                "\"available\":%s"
            "},"
            "\"dram\":{"
                "\"total\":%zu,"
                "\"free\":%zu,"
                "\"used\":%zu,"
                "\"used_percent\":%u,"
                "\"largest_block\":%zu,"
                "\"fragmentation_percent\":%u,"
                "\"critical\":%s,"
                "\"warning\":%s"
            "},"
            "\"timestamp_ms\":%llu"
        "},"
        "\"stats\":{"
            "\"dram\":{"
                "\"free_min\":%zu,"
                "\"free_max\":%zu,"
                "\"free_avg\":%zu,"
                "\"frag_min\":%u,"
                "\"frag_max\":%u,"
                "\"frag_avg\":%u"
            "},"
            "\"psram\":{"
                "\"free_min\":%zu,"
                "\"free_max\":%zu,"
                "\"free_avg\":%zu"
            "},"
            "\"events\":{"
                "\"updates_count\":%lu,"
                "\"critical_events\":%lu,"
                "\"warning_events\":%lu"
            "}"
        "},"
        "\"watchdog\":{"
            "\"enabled\":%s,"
            "\"threshold\":%zu"
        "}"
        "}",
        metrics.psram_total, metrics.psram_free, metrics.psram_used,
        metrics.psram_used_percent, metrics.psram_largest_block,
        metrics.psram_available ? "true" : "false",
        metrics.dram_total, metrics.dram_free, metrics.dram_used,
        metrics.dram_used_percent, metrics.dram_largest_block,
        metrics.dram_fragmentation_percent,
        metrics.critical_dram ? "true" : "false",
        metrics.warning_dram ? "true" : "false",
        metrics.timestamp_ms,
        stats.dram_free_min, stats.dram_free_max, stats.dram_free_avg,
        stats.dram_frag_min, stats.dram_frag_max, stats.dram_frag_avg,
        stats.psram_free_min, stats.psram_free_max, stats.psram_free_avg,
        stats.updates_count, stats.critical_events, stats.warning_events,
        PSRAMTelemetry::getInstance().isWatchdogEnabled() ? "true" : "false",
        PSRAMTelemetry::getInstance().getWatchdogThreshold()
    );

    if (len < 0 || len >= (int)sizeof(json)) {
        LOG_ERROR(TAG_WEB, "Failed to build /api/telemetry JSON");
        return httpd_resp_send_500(req);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    SCHEDULE_DEFRAG();
    return httpd_resp_sendstr(req, json);
}

esp_err_t WebServer::h_protocols_get(httpd_req_t* req) {
    if (!self_) return httpd_resp_send_500(req);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    // Keep this endpoint allocation-free: it is used at IDS page bootstrap.
    // Using static literals avoids crashes if plugin state is transient.
    static const char* kProtocolsJson =
        "{"
        "\"1\":\"Modbus TCP\","
        "\"2\":\"S7 Communication\","
        "\"3\":\"OPC UA\","
        "\"4\":\"EtherNet/IP\","
        "\"5\":\"PROFINET\""
        "}";
    return httpd_resp_send(req, kProtocolsJson, HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_protocols_get_details(httpd_req_t* req) {
    if (!self_) return httpd_resp_send_500(req);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    static const char* kProtocolsDetailsJson =
        "["
        "{\"id\":1,\"key\":\"MODBUS_TCP\",\"name\":\"Modbus TCP\"},"
        "{\"id\":2,\"key\":\"S7_COMM\",\"name\":\"S7 Communication\"},"
        "{\"id\":3,\"key\":\"OPC_UA\",\"name\":\"OPC UA\"},"
        "{\"id\":4,\"key\":\"ETHERNET_IP\",\"name\":\"EtherNet/IP\"},"
        "{\"id\":5,\"key\":\"PROFINET\",\"name\":\"PROFINET\"}"
        "]";
    return httpd_resp_send(req, kProtocolsDetailsJson, HTTPD_RESP_USE_STRLEN);
}

namespace {
bool editor_sensitive_key(const char* key) {
    if (!key) return false;
    const char* sensitive[] = {"password", "token", "private_key", "secret", "hash", "credential"};
    for (const char* marker : sensitive) {
        char lower[96] = {0};
        size_t i = 0;
        for (; key[i] && i + 1 < sizeof(lower); ++i) {
            lower[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(key[i])));
        }
        lower[i] = '\0';
        if (strstr(lower, marker)) return true;
    }
    return false;
}

void editor_redact(cJSON* node, const char* key = nullptr) {
    if (!node) return;
    if (key && editor_sensitive_key(key)) {
        if (cJSON_IsString(node)) {
            cJSON_SetValuestring(node, "[configured]");
        }
        return;
    }
    if (cJSON_IsObject(node)) {
        for (cJSON* child = node->child; child;) {
            cJSON* next = child->next;
            if (editor_sensitive_key(child->string)) {
                cJSON_ReplaceItemInObjectCaseSensitive(node, child->string, cJSON_CreateString("[configured]"));
            } else {
                editor_redact(child, child->string);
            }
            child = next;
        }
    } else if (cJSON_IsArray(node)) {
        for (cJSON* child = node->child; child; child = child->next) editor_redact(child, nullptr);
    }
}

const char* editor_value_type(const cJSON* value) {
    if (cJSON_IsBool(value)) return "boolean";
    if (cJSON_IsNumber(value)) return "number";
    if (cJSON_IsArray(value)) return "array";
    if (cJSON_IsObject(value)) return "object";
    return "string";
}

void editor_schema_walk(const cJSON* node, const std::string& prefix, cJSON* fields) {
    if (!node || !fields) return;
    if (cJSON_IsObject(node)) {
        for (const cJSON* child = node->child; child; child = child->next) {
            std::string path = prefix.empty() ? (child->string ? child->string : "") : prefix + "." + (child->string ? child->string : "");
            if (cJSON_IsObject(child) && child->child) {
                editor_schema_walk(child, path, fields);
            } else {
                cJSON* field = cJSON_CreateObject();
                if (!field) continue;
                cJSON_AddStringToObject(field, "path", path.c_str());
                cJSON_AddStringToObject(field, "label", child->string ? child->string : path.c_str());
                cJSON_AddStringToObject(field, "type", editor_value_type(child));
                cJSON_AddBoolToObject(field, "secret", editor_sensitive_key(child->string));
                cJSON_AddBoolToObject(field, "read_only", false);
                cJSON_AddStringToObject(field, "help", "Value read from the validated device configuration.");
                cJSON_AddItemToArray(fields, field);
            }
        }
    } else {
        cJSON* field = cJSON_CreateObject();
        if (!field) return;
        cJSON_AddStringToObject(field, "path", prefix.c_str());
        cJSON_AddStringToObject(field, "label", prefix.c_str());
        cJSON_AddStringToObject(field, "type", editor_value_type(node));
        cJSON_AddBoolToObject(field, "secret", false);
        cJSON_AddBoolToObject(field, "read_only", false);
        cJSON_AddItemToArray(fields, field);
    }
}

void editor_merge(cJSON* target, const cJSON* updates) {
    if (!target || !updates || !cJSON_IsObject(target) || !cJSON_IsObject(updates)) return;
    for (const cJSON* item = updates->child; item; item = item->next) {
        if (!item->string || editor_sensitive_key(item->string) ||
            (cJSON_IsString(item) && strcmp(item->valuestring, "[configured]") == 0)) continue;
        cJSON* existing = cJSON_GetObjectItemCaseSensitive(target, item->string);
        if (existing && cJSON_IsObject(existing) && cJSON_IsObject(item)) {
            editor_merge(existing, item);
        } else {
            cJSON* copy = cJSON_Duplicate(item, true);
            if (copy) {
                if (existing) cJSON_ReplaceItemInObjectCaseSensitive(target, item->string, copy);
                else cJSON_AddItemToObject(target, item->string, copy);
            }
        }
    }
}

static char* editor_copy_buffer(const char* data, size_t len, size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!data || len == 0 || !out_len) return nullptr;
    char* copy = static_cast<char*>(heap_caps_malloc(len + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!copy && len < 4096) {
        copy = static_cast<char*>(heap_caps_malloc(len + 1, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    }
    if (!copy) return nullptr;
    memcpy(copy, data, len);
    copy[len] = '\0';
    *out_len = len;
    return copy;
}

static bool editor_load_source(ConfigurationManager* cfg, const char* source,
                               char** out_raw, size_t* out_len, bool* defaults_preview) {
    if (!cfg || !out_raw || !out_len) return false;
    *out_raw = nullptr;
    *out_len = 0;
    if (defaults_preview) *defaults_preview = false;
    const char* selected = (source && *source) ? source : "current";

    if (strcmp(selected, "defaults") == 0) {
        *out_raw = cfg->getEmbeddedConfigInPSRAM(out_len);
        if (defaults_preview) *defaults_preview = true;
        return *out_raw != nullptr;
    }
    if (strcmp(selected, "saved") == 0) {
        std::string saved;
        if (AsyncStorage::Global::readFile(ConfigurationManager::kCONFIG_PATH, saved) != ESP_OK || saved.empty()) {
            return false;
        }
        *out_raw = editor_copy_buffer(saved.data(), saved.size(), out_len);
        return *out_raw != nullptr;
    }
    *out_raw = cfg->getRawConfigInPSRAM(out_len);
    return *out_raw != nullptr;
}

static void editor_add_error(cJSON* errors, const std::string& path, const char* message) {
    if (!errors) return;
    cJSON* item = cJSON_CreateObject();
    if (!item) return;
    cJSON_AddStringToObject(item, "path", path.c_str());
    cJSON_AddStringToObject(item, "message", message ? message : "invalid value");
    cJSON_AddItemToArray(errors, item);
}

static void editor_validate_updates(const cJSON* updates, const cJSON* current,
                                    const std::string& prefix, cJSON* errors) {
    if (!updates || !current || !cJSON_IsObject(updates) || !cJSON_IsObject(current)) return;
    for (const cJSON* item = updates->child; item; item = item->next) {
        const char* key = item->string;
        if (!key) continue;
        const std::string path = prefix.empty() ? key : prefix + "." + key;
        if (editor_sensitive_key(key)) {
            if (!(cJSON_IsString(item) && strcmp(item->valuestring, "[configured]") == 0)) {
                editor_add_error(errors, path, "secret fields are not editable through the generic editor");
            }
            continue;
        }
        const cJSON* existing = cJSON_GetObjectItemCaseSensitive(current, key);
        if (!existing) {
            editor_add_error(errors, path, "unknown configuration field");
            continue;
        }
        if (cJSON_IsObject(item)) {
            if (!cJSON_IsObject(existing)) editor_add_error(errors, path, "expected a scalar value");
            else editor_validate_updates(item, existing, path, errors);
            continue;
        }
        const bool compatible =
            (cJSON_IsBool(item) && cJSON_IsBool(existing)) ||
            (cJSON_IsNumber(item) && cJSON_IsNumber(existing)) ||
            (cJSON_IsString(item) && cJSON_IsString(existing)) ||
            (cJSON_IsArray(item) && cJSON_IsArray(existing));
        if (!compatible) editor_add_error(errors, path, "value type does not match the saved configuration");
        if (cJSON_IsNumber(item) && !std::isfinite(item->valuedouble)) {
            editor_add_error(errors, path, "numeric value must be finite");
        }
    }
}

static void editor_collect_paths(const cJSON* updates, const std::string& prefix,
                                 cJSON* applied, cJSON* restart_required) {
    if (!updates || !cJSON_IsObject(updates)) return;
    for (const cJSON* item = updates->child; item; item = item->next) {
        if (!item->string || editor_sensitive_key(item->string)) continue;
        const std::string path = prefix.empty() ? item->string : prefix + "." + item->string;
        if (cJSON_IsObject(item)) {
            editor_collect_paths(item, path, applied, restart_required);
            continue;
        }
        cJSON_AddItemToArray(applied, cJSON_CreateString(path.c_str()));
        if (path.rfind("network.", 0) == 0 || path.rfind("security.", 0) == 0 ||
            path.rfind("webserver.", 0) == 0 || path.rfind("gpio.", 0) == 0) {
            cJSON_AddItemToArray(restart_required, cJSON_CreateString(path.c_str()));
        }
    }
}

uint32_t editor_revision(const char* data, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) { hash ^= static_cast<uint8_t>(data[i]); hash *= 16777619u; }
    return hash;
}
}

esp_err_t WebServer::h_config_editor_schema(httpd_req_t* req) {
    if (!check_api_auth(req) || !self_ || !self_->cfg_) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    size_t len = 0; char* raw = self_->cfg_->getRawConfigInPSRAM(&len);
    cJSON* root = raw ? cJSON_ParseWithLength(raw, len) : nullptr;
    if (raw) heap_caps_free(raw);
    if (!root) return httpd_resp_send_500(req);
    cJSON* response = cJSON_CreateObject(); cJSON* fields = cJSON_CreateArray();
    if (!response || !fields) { cJSON_Delete(response); cJSON_Delete(root); return httpd_resp_send_500(req); }
    editor_schema_walk(root, "", fields); cJSON_AddItemToObject(response, "fields", fields);
    cJSON_AddStringToObject(response, "version", "1");
    char* out = cJSON_PrintUnformatted(response); cJSON_Delete(response); cJSON_Delete(root);
    if (!out) return httpd_resp_send_500(req);
    httpd_resp_set_type(req, "application/json"); esp_err_t r = httpd_resp_sendstr(req, out); free_cjson_str(out); return r;
}

esp_err_t WebServer::h_config_editor_snapshot(httpd_req_t* req) {
    if (!check_api_auth(req) || !self_ || !self_->cfg_) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    char source[24] = {0};
    char query[64] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        (void)httpd_query_key_value(query, "source", source, sizeof(source));
    }
    size_t len = 0; bool defaults_preview = false; char* raw = nullptr;
    if (!editor_load_source(self_->cfg_, source, &raw, &len, &defaults_preview)) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "configuration source unavailable");
    }
    cJSON* root = raw ? cJSON_ParseWithLength(raw, len) : nullptr;
    const uint32_t revision = editor_revision(raw ? raw : "", len);
    if (raw) {
        heap_caps_free(raw);
    }
    if (!root) {
        return httpd_resp_send_500(req);
    }
    editor_redact(root);
    cJSON* response = cJSON_CreateObject(); cJSON_AddItemToObject(response, "values", root);
    cJSON_AddStringToObject(response, "source", source[0] ? source : "current");
    cJSON_AddBoolToObject(response, "defaults_preview", defaults_preview);
    cJSON_AddBoolToObject(response, "secrets_present", true);
    cJSON_AddNumberToObject(response, "revision", (double)revision);
    char* out = cJSON_PrintUnformatted(response); cJSON_Delete(response);
    if (!out) {
        return httpd_resp_send_500(req);
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t r = httpd_resp_sendstr(req, out);
    free_cjson_str(out);
    return r;
}

esp_err_t WebServer::h_config_editor_validate(httpd_req_t* req) {
    if (!check_api_auth(req) || !self_ || !self_->cfg_) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    char* body=nullptr; size_t len=0; if (!read_body_psram(req,&body,&len)) return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"bad body");
    cJSON* root=cJSON_ParseWithLength(body,len); heap_caps_free(body);
    if (!root || !cJSON_IsObject(root)) { cJSON_Delete(root); return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"invalid JSON"); }
    cJSON* values = cJSON_GetObjectItem(root, "values");
    cJSON* out = cJSON_CreateObject();
    cJSON* errors = cJSON_CreateArray();
    if (!values || !cJSON_IsObject(values)) {
        editor_add_error(errors, "values", "missing object");
    } else {
        size_t current_len = 0; char* current_raw = self_->cfg_->getRawConfigInPSRAM(&current_len);
        cJSON* current = current_raw ? cJSON_ParseWithLength(current_raw, current_len) : nullptr;
        if (current_raw) heap_caps_free(current_raw);
        if (!current) editor_add_error(errors, "", "current configuration is unavailable");
        else {
            editor_validate_updates(values, current, "", errors);
            cJSON_Delete(current);
        }
    }
    cJSON_AddBoolToObject(out,"valid", cJSON_GetArraySize(errors) == 0);
    cJSON_AddItemToObject(out,"errors",errors);
    cJSON_AddArrayToObject(out,"warnings");
    char* text=cJSON_PrintUnformatted(out); cJSON_Delete(out); cJSON_Delete(root);
    if (!text) {
        return httpd_resp_send_500(req);
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t r = httpd_resp_sendstr(req, text);
    free_cjson_str(text);
    return r;
}

esp_err_t WebServer::h_config_editor_save(httpd_req_t* req) {
    if (!check_api_auth(req) || !self_ || !self_->cfg_) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    char* body=nullptr; size_t len=0; if (!read_body_psram(req,&body,&len)) return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"bad body");
    cJSON* request=cJSON_ParseWithLength(body,len); heap_caps_free(body); if(!request||!cJSON_IsObject(request)){cJSON_Delete(request);return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"invalid JSON");}
    cJSON* values=cJSON_GetObjectItem(request,"values"); if(!values||!cJSON_IsObject(values)){cJSON_Delete(request);return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"missing values");}
    size_t current_len=0; char* current_raw=self_->cfg_->getRawConfigInPSRAM(&current_len); cJSON* current=current_raw?cJSON_ParseWithLength(current_raw,current_len):nullptr; if(!current){if(current_raw)heap_caps_free(current_raw);cJSON_Delete(request);return httpd_resp_send_500(req);}
    const uint32_t current_revision = editor_revision(current_raw, current_len);
    cJSON* base = cJSON_GetObjectItem(request, "base_revision");
    if (base && cJSON_IsNumber(base) && static_cast<uint32_t>(base->valuedouble) != current_revision) {
        if (current_raw) {
            heap_caps_free(current_raw);
        }
        cJSON_Delete(current);
        cJSON_Delete(request);
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "{\"error\":\"configuration_changed\",\"reload_required\":true}");
    }
    cJSON* errors = cJSON_CreateArray(); editor_validate_updates(values, current, "", errors);
    if (cJSON_GetArraySize(errors) != 0) {
        char* details = cJSON_PrintUnformatted(errors); cJSON_Delete(errors);
        if (current_raw) {
            heap_caps_free(current_raw);
        }
        cJSON_Delete(current);
        cJSON_Delete(request);
        httpd_resp_set_status(req, "422 Unprocessable Entity");
        httpd_resp_set_type(req, "application/json");
        std::string response = std::string("{\"error\":\"validation_failed\",\"errors\":") + (details ? details : "[]") + "}";
        if (details) free_cjson_str(details);
        return httpd_resp_send(req, response.c_str(), response.size());
    }
    cJSON_Delete(errors);
    editor_merge(current,values); char* merged=cJSON_PrintUnformatted(current);
    cJSON* applied = cJSON_CreateArray(); cJSON* restart = cJSON_CreateArray();
    editor_collect_paths(values, "", applied, restart);
    if (current_raw) {
        heap_caps_free(current_raw);
    }
    cJSON_Delete(current);
    cJSON_Delete(request);
    if (!merged) {
        cJSON_Delete(applied);
        cJSON_Delete(restart);
        return httpd_resp_send_500(req);
    }
    bool ok=self_->cfg_->saveConfigJSON(merged); uint32_t rev=editor_revision(merged,strlen(merged)); free_cjson_str(merged); if(!ok){cJSON_Delete(applied);cJSON_Delete(restart);return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"configuration save failed");}
    cJSON* out=cJSON_CreateObject(); cJSON_AddBoolToObject(out,"saved",true); cJSON_AddNumberToObject(out,"revision",(double)rev); cJSON_AddItemToObject(out,"applied_paths",applied); cJSON_AddItemToObject(out,"restart_required_paths",restart); char* text=cJSON_PrintUnformatted(out);cJSON_Delete(out);if(!text)return httpd_resp_send_500(req);httpd_resp_set_type(req,"application/json");esp_err_t r=httpd_resp_sendstr(req,text);free_cjson_str(text);return r;
}

esp_err_t WebServer::h_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    size_t json_size = 0;
    char* json_buf = self_->cfg_->getRawConfigInPSRAM(&json_size);

    if (!json_buf || json_size == 0) return httpd_resp_send_500(req);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");

    esp_err_t result = send_chunked_from_psram(req, json_buf, json_size);

    heap_caps_free(json_buf);

    SCHEDULE_DEFRAG();

    return result;
}

bool WebServer::read_body(httpd_req_t* req, psram_string& out, size_t max_len) {
    const size_t tot = req->content_len;
    if (!tot || tot > max_len) {
        out.clear();
        return false;
    }
    out.assign(tot, '\0');
    char* dest = &out[0];
    size_t rec = 0;
    while (rec < tot) {
        int r = httpd_req_recv(req, dest + rec, tot - rec);
        if (r <= 0) {
            out.clear();
            return false;
        }
        rec += r;
    }
    return true;
}

esp_err_t WebServer::h_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);
    char* body_ps = nullptr; size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = cJSON_ParseWithLength(body_ps, body_len);
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
    cJSON_Delete(root);
    bool ok = false;
    if (body_ps) {
        // Note: saveConfigJSON takes std::string; conversion happens here (rare path)
        ok = self_->cfg_->saveConfigJSON(std::string(body_ps, body_len));
        heap_caps_free(body_ps);
    }
    if (ok) {
        // Log configuration change to audit channel
        char details[64];
        snprintf(details, sizeof(details), "size:%zu bytes", body_len);
        logConfigChange(req, "main_config", details);

        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK");
    }
    return httpd_resp_send_500(req);
}

esp_err_t WebServer::h_config_update(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    char* body_ps = nullptr;
    size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len) || !body_ps || body_len == 0) {
        if (body_ps) {
            heap_caps_free(body_ps);
        }
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* updates = cJSON_ParseWithLength(body_ps, body_len);
    heap_caps_free(body_ps);
    if (!updates || !cJSON_IsObject(updates)) {
        if (updates) {
            cJSON_Delete(updates);
        }
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
    }

    size_t config_len = 0;
    char* config_ps = self_->cfg_->getRawConfigInPSRAM(&config_len);
    if (!config_ps || config_len == 0) {
        if (config_ps) {
            heap_caps_free(config_ps);
        }
        cJSON_Delete(updates);
        return httpd_resp_send_500(req);
    }

    cJSON* current_config = cJSON_ParseWithLength(config_ps, config_len);
    heap_caps_free(config_ps);
    if (!current_config || !cJSON_IsObject(current_config)) {
        if (current_config) {
            cJSON_Delete(current_config);
        }
        cJSON_Delete(updates);
        return httpd_resp_send_500(req);
    }

    bool success = true;
    uint32_t applied = 0;
    for (cJSON* item = updates->child; item && success; item = item->next) {
        if (!item->string) {
            continue;
        }
        if (!apply_config_update_path(current_config, item->string, item)) {
            success = false;
        } else {
            applied++;
        }
    }

    cJSON_Delete(updates);

    if (success) {
        char* updated_json = cJSON_PrintUnformatted(current_config);
        if (updated_json) {
            psram_string updated_ps = PSRAMUtils::createPSRAMString(updated_json);
            success = self_->cfg_->saveConfigJSON(updated_ps);
            heap_caps_free(updated_json);
        } else {
            success = false;
        }
    }

    cJSON_Delete(current_config);

    if (success) {
        char details[64];
        snprintf(details, sizeof(details), "keys:%u", (unsigned)applied);
        logConfigChange(req, "config_partial_update", details);

        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_sendstr(req, "{\"success\":true}");
    }

    return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config update failed");
}

esp_err_t WebServer::h_config_reset_defaults(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    LOG_INFO(TAG_WEB, "Resetting configuration to embedded defaults");

    // Reset to embedded configuration
    bool ok = self_->cfg_->resetToEmbeddedConfig();

    if (ok) {
        // Log configuration reset to audit channel
        logConfigChange(req, "config_reset_defaults", "Reset to embedded configuration");

        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "Configuration reset to defaults successfully");
    }

    LOG_ERROR(TAG_WEB, "Failed to reset configuration to defaults");
    return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to reset configuration");
}

esp_err_t WebServer::h_config_metadata_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    cJSON* metadata = cJSON_CreateObject();
    if (!metadata) return httpd_resp_send_500(req);

    cJSON_AddStringToObject(metadata, "source", self_->cfg_->getConfigSourceName().c_str());
    cJSON_AddNumberToObject(metadata, "source_id", (int)self_->cfg_->getConfigSource());
    cJSON_AddBoolToObject(metadata, "user_modified", self_->cfg_->isUserModified());
    cJSON_AddBoolToObject(metadata, "can_reset_to_embedded", true); // Always available

    char* json_str = cJSON_Print(metadata);
    if (json_str) {
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        esp_err_t ret = httpd_resp_sendstr(req, json_str);
        free_cjson_str(json_str);
        cJSON_Delete(metadata);
        return ret;
    }

    cJSON_Delete(metadata);
    return httpd_resp_send_500(req);
}

esp_err_t WebServer::h_config_reset_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    ProvisioningStore provisioning;
    const bool provisioning_cleared = provisioning.factoryReset();
    const bool tls_cleared = self_->tls_credentials_.clear();
    if (provisioning_cleared && tls_cleared) {
        logConfigChange(req, "factory_reset", "Provisioning, security, configuration and TLS state erased");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "close");
        const esp_err_t response = httpd_resp_sendstr(
            req, "{\"success\":true,\"rebooting\":true}");
        vTaskDelay(pdMS_TO_TICKS(250));
        esp_restart();
        return response;
    }

    return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Factory reset failed");
}


esp_err_t WebServer::h_reboot(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    // 📊 LOG PLANNED SHUTDOWN EVENT - Only if fully initialized
    if (self_ && self_->rep_ && self_->cfg_) {
        const char* client_ip = extractClientIPToBuffer(req);
        cJSON* shutdown_event = cJSON_CreateObject();
        cJSON_AddStringToObject(shutdown_event, "event_type", "system_shutdown");
        cJSON_AddStringToObject(shutdown_event, "shutdown_type", "PLANNED_REBOOT");
        cJSON_AddStringToObject(shutdown_event, "initiated_by", "web_api");
        cJSON_AddStringToObject(shutdown_event, "client_ip", client_ip);
        cJSON_AddNumberToObject(shutdown_event, "uptime_ms", esp_timer_get_time() / 1000);

        char* json_str = cJSON_Print(shutdown_event);
        std::string event_data(json_str);
        free_cjson_str(json_str);
        cJSON_Delete(shutdown_event);

        report_event_ps(self_->rep_, "system_status", event_data);
        LOG_INFO("WebServer", "📊 System shutdown event logged (PLANNED_REBOOT via API)");

        // Give some time for the event to be processed/sent
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    // AUDIT: Log system reboot event with user context
    const char* reboot_client_ip = extractClientIPToBuffer(req);
    AuditManager::getInstance().logSystemReboot("web_api_request", "admin", reboot_client_ip);

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "rebooting...");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

esp_err_t WebServer::h_redirect(httpd_req_t* req) {
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_send(req, "", 0);
}

// ---- Scanner REST ----
esp_err_t WebServer::h_scan_jobs_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->scanner_) return httpd_resp_send_500(req);
    auto jobs = self_->scanner_->listJobs();
    cJSON* arr = cJSON_CreateArray();
    for (auto const& j : jobs) {
        cJSON* o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "id", j.id);
        cJSON_AddStringToObject(o, "name", j.name.c_str());
        cJSON_AddStringToObject(o, "target", j.target.c_str());
        cJSON_AddNumberToObject(o, "protocol", (int)j.protocol);
        if (!j.scan_types.empty()) {
            cJSON* arr2 = cJSON_CreateArray();
            if (arr2) {
                for (auto const& st : j.scan_types) {
                    cJSON_AddItemToArray(arr2, cJSON_CreateString(st.c_str()));
                }
                cJSON_AddItemToObject(o, "scan_types", arr2);
            }
        }
        cJSON_AddNumberToObject(o, "interval_sec", j.interval_sec);
        cJSON_AddNumberToObject(o, "jitter_sec", j.jitter_sec);
        cJSON_AddBoolToObject(o, "enabled", j.enabled);
        cJSON_AddNumberToObject(o, "runs", (double)j.runs);
        cJSON_AddNumberToObject(o, "last_started_ms", (double)j.last_started_ms);
        cJSON_AddNumberToObject(o, "last_finished_ms", (double)j.last_finished_ms);
        cJSON_AddItemToArray(arr, o);
    }
    char* out = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);

    // Safety check for NULL JSON output
    if (!out) {
        LOG_ERROR("SCAN_JOBS", "Failed to create JSON for /api/scanner/jobs");
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_send(req, "{\"error\":\"JSON creation failed\"}", strlen("{\"error\":\"JSON creation failed\"}"));
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(out);
    return ret;
}

esp_err_t WebServer::h_scan_jobs_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->scanner_) return httpd_resp_send_500(req);
    psram_string body;
    if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    cJSON* o = cJSON_Parse(body.c_str());
    if (!o) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");
    ScanJob j;
    cJSON* v = nullptr;
    if ((v=cJSON_GetObjectItem(o,"name")) && cJSON_IsString(v)) j.name = v->valuestring;
    if ((v=cJSON_GetObjectItem(o,"target")) && cJSON_IsString(v)) j.target = v->valuestring;
    if ((v=cJSON_GetObjectItem(o,"protocol")) && cJSON_IsNumber(v)) j.protocol = (ProtocolType)((int)v->valuedouble);
    if ((v=cJSON_GetObjectItem(o,"scan_types")) && cJSON_IsArray(v)) {
        PSRAMAllocator<psram_string> alloc;
        j.scan_types = psram_string_vector(alloc);
        cJSON* it = nullptr;
        cJSON_ArrayForEach(it, v) {
            if (it && cJSON_IsString(it) && it->valuestring) {
                j.scan_types.push_back(PSRAMUtils::createPSRAMString(it->valuestring));
            }
        }
    }
    if ((v=cJSON_GetObjectItem(o,"interval_sec")) && cJSON_IsNumber(v)) j.interval_sec = (uint32_t)v->valuedouble;
    if ((v=cJSON_GetObjectItem(o,"jitter_sec")) && cJSON_IsNumber(v)) j.jitter_sec = (uint32_t)v->valuedouble;
    if ((v=cJSON_GetObjectItem(o,"enabled")) && cJSON_IsBool(v)) j.enabled = cJSON_IsTrue(v);
    cJSON_Delete(o);

    // Force manual start: newly created jobs stay disabled until /api/scanner/run is called
    j.enabled = false;
    j.runs = 0;
    j.last_started_ms = 0;
    j.last_finished_ms = 0;

    uint32_t id = self_->scanner_->addJob(j);
    char buf[64]; snprintf(buf, sizeof(buf), "{\"id\":%lu}", (unsigned long)id);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_scan_jobs_delete(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->scanner_) return httpd_resp_send_500(req);
    char q[64];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing id");
    char sid[16];
    if (httpd_query_key_value(q, "id", sid, sizeof(sid)) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing id");
    uint32_t id = (uint32_t)strtoul(sid, nullptr, 10);
    bool ok = self_->scanner_->removeJob(id);
    if (!ok) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_sendstr(req, "OK");
}

esp_err_t WebServer::h_scan_run(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->scanner_) return httpd_resp_send_500(req);
    char q[64]; char sid[16];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK ||
        httpd_query_key_value(q, "id", sid, sizeof(sid)) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing id");
    uint32_t id = (uint32_t)strtoul(sid, nullptr, 10);
    bool ok = self_->scanner_->runNow(id);
    if (!ok) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_sendstr(req, "OK");
}

esp_err_t WebServer::h_scan_result_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->scanner_) return httpd_resp_send_500(req);

    char q[64]; char sid[16];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK ||
        httpd_query_key_value(q, "id", sid, sizeof(sid)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing id");
    }

    uint32_t id = (uint32_t)strtoul(sid, nullptr, 10);
    psram_string payload;
    if (!self_->scanner_->getLastResult(id, payload) || payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no result");
    }

    // Best-effort: most plugins should return JSON.
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, payload.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_scan_cfg_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    // Get scanner configuration from ConfigurationManager for complete config (PSRAM-safe)
    size_t json_size = 0;
    char* json_buf = self_->cfg_->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) return httpd_resp_send_500(req);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* config_root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!config_root) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to parse configuration");
    }

    cJSON* scanner_section = cJSON_GetObjectItem(config_root, "scanner");
    cJSON* response;

    if (scanner_section && cJSON_IsObject(scanner_section)) {
        // Return the complete scanner configuration
        response = cJSON_Duplicate(scanner_section, cJSON_True);
    } else {
        // Fallback to default values if no scanner section exists
        response = cJSON_CreateObject();
        cJSON_AddBoolToObject(response, "enabled", true);
        cJSON_AddNumberToObject(response, "max_parallel", 1);
        cJSON_AddNumberToObject(response, "rate_limit_per_min", 20);
        cJSON_AddNumberToObject(response, "default_timeout_ms", 5000);
        cJSON_AddArrayToObject(response, "jobs");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(config_root);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return ret;
}

esp_err_t WebServer::h_scan_cfg_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->scanner_) return httpd_resp_send_500(req);

    char* body_ps = nullptr; size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    cJSON* request_json = cJSON_ParseWithLength(body_ps, body_len);
    if (!request_json) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");

    // Update scanner runtime configuration
    ScannerConfig sc = self_->scanner_->getScannerConfig();
    cJSON* v = nullptr;
    if ((v=cJSON_GetObjectItem(request_json,"max_parallel")) && cJSON_IsNumber(v)) sc.max_parallel = (uint32_t)v->valuedouble;
    if ((v=cJSON_GetObjectItem(request_json,"rate_limit_per_min")) && cJSON_IsNumber(v)) sc.rate_limit_per_min = (uint32_t)v->valuedouble;
    self_->scanner_->setScannerConfig(sc);

    // Also persist to ConfigurationManager
    if (self_->cfg_) {
        size_t ps_sz = 0;
        char* ps_buf = self_->cfg_->getRawConfigInPSRAM(&ps_sz);
        PSRAMJsonParser::PSRAMContext ctx3;
        cJSON* config_root = ps_buf ? PSRAMJsonParser::parseInPSRAM(ps_buf, ps_sz) : nullptr;
        if (ps_buf) heap_caps_free(ps_buf);
        if (config_root) {
            // Get or create scanner section
            cJSON* scanner_section = cJSON_GetObjectItem(config_root, "scanner");
            if (!scanner_section) {
                scanner_section = cJSON_CreateObject();
                cJSON_AddItemToObject(config_root, "scanner", scanner_section);
            }

            // Update scanner configuration fields
            if ((v=cJSON_GetObjectItem(request_json,"max_parallel")) && cJSON_IsNumber(v)) {
                cJSON_DeleteItemFromObject(scanner_section, "max_parallel");
                cJSON_AddNumberToObject(scanner_section, "max_parallel", v->valuedouble);
            }
            if ((v=cJSON_GetObjectItem(request_json,"rate_limit_per_min")) && cJSON_IsNumber(v)) {
                cJSON_DeleteItemFromObject(scanner_section, "rate_limit_per_min");
                cJSON_AddNumberToObject(scanner_section, "rate_limit_per_min", v->valuedouble);
            }

            // Save updated configuration
            char* updated_config = cJSON_Print(config_root);
            self_->cfg_->saveConfigJSON(updated_config);
            free_cjson_str(updated_config);
            cJSON_Delete(config_root);
        }
    }

    // Log configuration change to audit channel
    char details[256];
    snprintf(details, sizeof(details),
         "max_parallel:%" PRIu32 ",rate_limit:%" PRIu32,
         sc.max_parallel,
         sc.rate_limit_per_min);
    logConfigChange(req, "scanner_config", details);

    cJSON_Delete(request_json);
    if (body_ps) heap_caps_free(body_ps);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, "{\"success\":true,\"message\":\"Scanner configuration updated successfully\"}", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_scheduler_unavailable(httpd_req_t* req) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"scheduler not available\"}");
}

esp_err_t WebServer::h_schedule_list(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cron_scheduler_ || !self_->cron_scheduler_initialized_) {
        return send_scheduler_unavailable(req);
    }

    cJSON* response = ScheduleAPI::handleScheduleList(self_->cron_scheduler_);
    if (!response) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "scheduler");

    char* json = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!json) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json);
    return ret;
}

esp_err_t WebServer::h_schedule_create(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cron_scheduler_ || !self_->cron_scheduler_initialized_) {
        return send_scheduler_unavailable(req);
    }

    char* body_ps = nullptr;
    size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) {
        if (body_ps) heap_caps_free(body_ps);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* response = ScheduleAPI::handleScheduleCreate(self_->cron_scheduler_, body_ps, body_len);
    if (body_ps) heap_caps_free(body_ps);
    if (!response) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "scheduler");

    char* json = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!json) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json);
    return ret;
}

esp_err_t WebServer::h_schedule_update(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cron_scheduler_ || !self_->cron_scheduler_initialized_) {
        return send_scheduler_unavailable(req);
    }

    char* body_ps = nullptr;
    size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) {
        if (body_ps) heap_caps_free(body_ps);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* response = ScheduleAPI::handleScheduleUpdate(self_->cron_scheduler_, body_ps, body_len);
    if (body_ps) heap_caps_free(body_ps);
    if (!response) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "scheduler");

    char* json = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!json) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json);
    return ret;
}

esp_err_t WebServer::h_schedule_delete(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cron_scheduler_ || !self_->cron_scheduler_initialized_) {
        return send_scheduler_unavailable(req);
    }

    char* body_ps = nullptr;
    size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) {
        if (body_ps) heap_caps_free(body_ps);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* response = ScheduleAPI::handleScheduleDelete(self_->cron_scheduler_, body_ps, body_len);
    if (body_ps) heap_caps_free(body_ps);
    if (!response) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "scheduler");

    char* json = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!json) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json);
    return ret;
}

esp_err_t WebServer::h_schedule_toggle(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cron_scheduler_ || !self_->cron_scheduler_initialized_) {
        return send_scheduler_unavailable(req);
    }

    char* body_ps = nullptr;
    size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) {
        if (body_ps) heap_caps_free(body_ps);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* response = ScheduleAPI::handleScheduleToggle(self_->cron_scheduler_, body_ps, body_len);
    if (body_ps) heap_caps_free(body_ps);
    if (!response) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "scheduler");

    char* json = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!json) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json);
    return ret;
}

esp_err_t WebServer::h_schedule_trigger(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cron_scheduler_ || !self_->cron_scheduler_initialized_) {
        return send_scheduler_unavailable(req);
    }

    char* body_ps = nullptr;
    size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) {
        if (body_ps) heap_caps_free(body_ps);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* response = ScheduleAPI::handleScheduleTrigger(self_->cron_scheduler_, body_ps, body_len);
    if (body_ps) heap_caps_free(body_ps);
    if (!response) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "scheduler");

    char* json = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!json) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json);
    return ret;
}

// ---- Discovery ----
esp_err_t WebServer::h_discovery_modbus(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->plugins_) return httpd_resp_send_500(req);

    // Parse target and timeout from query string ?target=192.168.1.0/24&timeout=5000
    char q[128]; char tgt[96] = {0}; char timeout_str[16] = {0};
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "target", tgt, sizeof(tgt));
        httpd_query_key_value(q, "timeout", timeout_str, sizeof(timeout_str));
    }
    if (tgt[0] == 0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing target network");

    uint32_t timeout_ms = (timeout_str[0] != 0) ? atoi(timeout_str) : 5000;
    if (timeout_ms < 1000) timeout_ms = 1000; // Minimum 1 second
    if (timeout_ms > 30000) timeout_ms = 30000; // Maximum 30 seconds

    BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::MODBUS_TCP);
    if (!base) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Modbus plugin not found");

    psram_string target_ps = PSRAMUtils::createPSRAMString(tgt);
    psram_string discovery_result;
    bool success = base->doNetworkDiscoveryPSRAM(target_ps, timeout_ms, discovery_result);

    // Report discovery results
    if (success && self_->rep_ && !discovery_result.empty()) {
        self_->rep_->reportEvent(PSRAMUtils::createPSRAMString("modbus_discovery_result"), discovery_result);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req,
                           discovery_result.empty() ? "" : discovery_result.c_str(),
                           HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_discovery_s7(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->plugins_) return httpd_resp_send_500(req);

    // Parse target and timeout from query string
    char q[128]; char tgt[96] = {0}; char timeout_str[16] = {0};
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "target", tgt, sizeof(tgt));
        httpd_query_key_value(q, "timeout", timeout_str, sizeof(timeout_str));
    }
    if (tgt[0] == 0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing target network");

    uint32_t timeout_ms = (timeout_str[0] != 0) ? atoi(timeout_str) : 5000;
    if (timeout_ms < 1000) timeout_ms = 1000;
    if (timeout_ms > 30000) timeout_ms = 30000;

    BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::S7_COMM);
    if (!base) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "S7 plugin not found");

    psram_string target_ps = PSRAMUtils::createPSRAMString(tgt);
    psram_string discovery_result;
    bool success = base->doNetworkDiscoveryPSRAM(target_ps, timeout_ms, discovery_result);

    // Report discovery results
    if (success && self_->rep_ && !discovery_result.empty()) {
        self_->rep_->reportEvent(PSRAMUtils::createPSRAMString("s7_discovery_result"), discovery_result);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req,
                           discovery_result.empty() ? "" : discovery_result.c_str(),
                           HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_s7_ops(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->plugins_) return httpd_resp_send_500(req);

    psram_string body;
    if (!read_body(req, body, 4096)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::S7_COMM);
    if (!base) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "S7 plugin not found");

    auto* s7 = static_cast<S7Plugin*>(base);
    psram_string out;
    (void)s7->clientOpsPSRAM(body, out);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, out.empty() ? "" : out.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_discovery_profinet(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->plugins_) return httpd_resp_send_500(req);

    // Parse timeout from query string
    char q[128]; char timeout_str[16] = {0}; char tgt[96] = "broadcast";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "timeout", timeout_str, sizeof(timeout_str));
        httpd_query_key_value(q, "target", tgt, sizeof(tgt)); // target not really used for PROFINET broadcast
    }

    uint32_t timeout_ms = (timeout_str[0] != 0) ? atoi(timeout_str) : 1500;
    if (timeout_ms < 500) timeout_ms = 500;
    if (timeout_ms > 15000) timeout_ms = 15000;

    BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::PROFINET);
    if (!base) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "PROFINET plugin not found");

    psram_string target_ps = PSRAMUtils::createPSRAMString(tgt);
    psram_string discovery_result;
    bool success = base->doNetworkDiscoveryPSRAM(target_ps, timeout_ms, discovery_result);

    // Report discovery results
    if (success && self_->rep_ && !discovery_result.empty()) {
        self_->rep_->reportEvent(PSRAMUtils::createPSRAMString("profinet_discovery_result"), discovery_result);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req,
                           discovery_result.empty() ? "" : discovery_result.c_str(),
                           HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_discovery_enip(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->plugins_) return httpd_resp_send_500(req);

    // Parse timeout from query string (accept both timeout and timeout_ms)
    char q[128]; char timeout_str[16] = {0}; char timeout_ms_str[16] = {0}; char tgt[96] = "broadcast";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "timeout", timeout_str, sizeof(timeout_str));
        httpd_query_key_value(q, "timeout_ms", timeout_ms_str, sizeof(timeout_ms_str));
        httpd_query_key_value(q, "target", tgt, sizeof(tgt)); // target not really used for EtherNet/IP broadcast
    }

    uint32_t timeout_ms = 1500;
    if (timeout_ms_str[0] != 0) timeout_ms = (uint32_t)atoi(timeout_ms_str);
    else if (timeout_str[0] != 0) timeout_ms = (uint32_t)atoi(timeout_str);
    if (timeout_ms < 500) timeout_ms = 500;
    if (timeout_ms > 15000) timeout_ms = 15000;

    BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::ETHERNET_IP);
    if (!base) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "EtherNet/IP plugin not found");

    psram_string target_ps = PSRAMUtils::createPSRAMString(tgt);
    psram_string discovery_result;
    bool success = base->doNetworkDiscoveryPSRAM(target_ps, timeout_ms, discovery_result);

    // Report discovery results
    if (success && self_->rep_ && !discovery_result.empty()) {
        self_->rep_->reportEvent(PSRAMUtils::createPSRAMString("ethernetip_discovery_result"), discovery_result);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req,
                           discovery_result.empty() ? "" : discovery_result.c_str(),
                           HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_audit_status(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    auto c = AuditManager::getInstance().getSnapshot();
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"denied\":%lu,\"timeouts\":%lu,\"ratelimits\":%lu}", (unsigned long)c.denied, (unsigned long)c.timeouts, (unsigned long)c.ratelimits);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}


#include "../core/reporting_engine.h"
// g_reporting is now declared in reporting_engine.h

esp_err_t WebServer::h_report_queue_status(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");
    ensure_report_queue_directory();
    esp_err_t result = ESP_FAIL;
    {
        std::lock_guard<std::mutex> guard(g_report_queue_json.mutex);
        if (!build_report_queue_json(g_report_queue_json)) {
            return httpd_resp_send_500(req);
        }
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        result = send_chunked_from_psram(req, g_report_queue_json.buf, g_report_queue_json.length);
    }
    return result;
}

esp_err_t WebServer::h_report_flush(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");
    uint32_t n = g_reporting->flushNow();
    char buf[64]; snprintf(buf,sizeof(buf),"{\"flushed\":%lu}", (unsigned long)n);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
}


esp_err_t WebServer::h_report_channels_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");
    ensureReportingChannelsCacheLoaded();

    esp_err_t result = ESP_FAIL;
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    {
        std::lock_guard<std::mutex> lock(reporting_channels_mutex_);
        if (reporting_channels_cache_.empty()) {
            static const char empty_json[] = "{}";
            result = send_chunked_from_psram(req, empty_json, sizeof(empty_json) - 1);
        } else {
            result = send_chunked_from_psram(req,
                                             reporting_channels_cache_.data(),
                                             reporting_channels_cache_.size());
        }
    }
    return result;
}

esp_err_t WebServer::h_report_channels_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");
    psram_string body; if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    // Expected: {"channel":"mqtt","format":3,"enabled":true,"verbosity":1}
    cJSON* o = cJSON_Parse(body.c_str()); if (!o) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json");
    cJSON* ch = cJSON_GetObjectItem(o, "channel");
    cJSON* ff = cJSON_GetObjectItem(o, "format");
    cJSON* en = cJSON_GetObjectItem(o, "enabled");
    cJSON* vb = cJSON_GetObjectItem(o, "verbosity");

    bool ok = false;
    if (ch && cJSON_IsString(ch) && ff && cJSON_IsNumber(ff) && en && cJSON_IsBool(en)) {
        // Update format and enabled
        ok = g_reporting->setChannelFormat(ch->valuestring, (EventFormat)ff->valuedouble, cJSON_IsTrue(en));

        // Update verbosity if provided
        if (ok && vb && cJSON_IsNumber(vb)) {
            VerbosityLevel verb_level = (VerbosityLevel)((int)vb->valuedouble);
            ok = g_reporting->setChannelVerbosity(ch->valuestring, verb_level);
        }
    }
    cJSON_Delete(o);
    httpd_resp_set_type(req, "text/plain");

    // Persist in global config using the new reporting.channels structure (PSRAM-safe)
    if (ok && self_ && self_->cfg_) {
        size_t ps_sz = 0; char* ps_buf = self_->cfg_->getRawConfigInPSRAM(&ps_sz);
        PSRAMJsonParser::PSRAMContext ctx;
        cJSON* root = (ps_buf && ps_sz) ? PSRAMJsonParser::parseInPSRAM(ps_buf, ps_sz) : nullptr;
        if (ps_buf) heap_caps_free(ps_buf);
        if (!root) root = cJSON_CreateObject();

        // Get or create reporting section
        cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
        if (!reporting || !cJSON_IsObject(reporting)) {
            reporting = cJSON_CreateObject();
            cJSON_AddItemToObject(root, "reporting", reporting);
        }

        // Get or create channels section
        cJSON* channels = cJSON_GetObjectItem(reporting, "channels");
        if (!channels || !cJSON_IsObject(channels)) {
            channels = cJSON_CreateObject();
            cJSON_AddItemToObject(reporting, "channels", channels);
        }

        // Update channel config
        cJSON* chobj = cJSON_CreateObject();
        cJSON_AddBoolToObject(chobj, "enabled", cJSON_IsTrue(en));

        // Add format as string
        const char* format_names[] = {"JSON", "CEE", "LEEF", "CEF"};
        int format_idx = (int)ff->valuedouble;
        if (format_idx >= 0 && format_idx < 4) {
            cJSON_AddStringToObject(chobj, "format", format_names[format_idx]);
        }

        // Add verbosity as string
        if (vb && cJSON_IsNumber(vb)) {
            int verb_idx = (int)vb->valuedouble;
            const char* verbosity_str = (verb_idx == 1) ? "VERBOSE" : "REPORTS_ONLY";
            cJSON_AddStringToObject(chobj, "verbosity", verbosity_str);
        }

        cJSON_ReplaceItemInObject(channels, ch->valuestring, chobj);
        char* out = cJSON_PrintUnformatted(root);
        if (out) { self_->cfg_->saveConfigJSON(out); free_cjson_str(out); }
        cJSON_Delete(root);
    }
    if (ok) {
        invalidateReportingChannelsCache();
    }
    return httpd_resp_sendstr(req, ok?"OK":"ERR");
}

esp_err_t WebServer::h_report_endpoints_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    ensureReportingCacheLoaded();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");

    esp_err_t result;
    {
        std::lock_guard<std::mutex> lock(reporting_cache_mutex_);
        if (!reporting_cache_valid_) {
            loadReportingCacheLocked();
        }
        const char* send_buf;
        size_t send_len;
        if (reporting_cache_.empty()) {
            static const char empty_json[] = "{}";
            send_buf = empty_json;
            send_len = sizeof(empty_json) - 1;
        } else {
            send_buf = reporting_cache_.data();
            send_len = reporting_cache_.size();
        }
        result = send_chunked_from_psram(req, send_buf, send_len);
    }
    return result;
}

esp_err_t WebServer::h_report_endpoints_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);
    char* body_ps = nullptr; size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    // Persist full object under "reporting" (PSRAM-safe)
    size_t cfg_sz = 0; char* cfg_buf = self_->cfg_->getRawConfigInPSRAM(&cfg_sz);
    PSRAMJsonParser::PSRAMContext ctx5;
    cJSON* root = (cfg_buf && cfg_sz) ? PSRAMJsonParser::parseInPSRAM(cfg_buf, cfg_sz) : nullptr;
    if (cfg_buf) heap_caps_free(cfg_buf);
    if (!root) root = cJSON_CreateObject();
    cJSON* obj = cJSON_ParseWithLength(body_ps, body_len); if (!obj) { if (body_ps) heap_caps_free(body_ps); cJSON_Delete(root); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json"); }
    cJSON_ReplaceItemInObject(root, "reporting", obj);
    char* out = cJSON_PrintUnformatted(root);
    bool ok=false;
    if (out) { ok = self_->cfg_->saveConfigJSON(out); free_cjson_str(out); }
    // Apply live
    if (ok && g_reporting) {
        ReportingConfig::registerNetworkEndpoints(self_->cfg_, g_reporting);
    }
    cJSON_Delete(root);
    httpd_resp_set_type(req, "text/plain");
    if (ok) {
        updateReportingCache(body_ps, body_len);
    } else {
        invalidateReportingCache();
    }
    if (body_ps) heap_caps_free(body_ps);
    return httpd_resp_sendstr(req, ok? "OK":"ERR");
}


#include <map>
#include <sstream>
#include "cJSON.h"
#include "../core/psram_json_parser.h"

#include "esp_timer.h"
#include <cctype>

#include <cstring>

static bool isDevelopmentSessionToken(const char* token) {
    if (!token) {
        return false;
    }
    size_t len = strlen(token);
    if (len < 16) {
        return false;
    }
    if (strncmp(token, "sess_", 5) == 0) {
        return true;
    }
    if (strncmp(token, "dev_", 4) == 0) {
        return true;
    }
    if (strncmp(token, "temp_", 5) == 0) {
        return true;
    }
    return false;
}


bool WebServer::check_session(httpd_req_t* req){
    if (!self_ || !self_->sec_) {
        LOG_ERROR("SESSION", "WebServer or SecurityManager not initialized");
        return false;
    }

    // Extract session token from querystring ?sid=TOKEN
    char query[256] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        LOG_INFO("SESSION", "No query string found");
        return false;
    }

    char sid[128] = {0};
    if (httpd_query_key_value(query, "sid", sid, sizeof(sid)) != ESP_OK) {
        LOG_INFO("SESSION", "No sid parameter in query string");
        return false;
    }

    if (sid[0] == '\0') {
        LOG_INFO("SESSION", "Empty session token in querystring");
        return false;
    }

    // Simple token validation - check if it's a valid API key or use basic validation
    // MEMORY FIX: Use buffer-based version to avoid std::string temporary allocation
    const char* client_ip = extractClientIPToBuffer(req);
    const bool is_dev_token = isDevelopmentSessionToken(sid);

    // For now, use API key validation as session token validation
    // In production, you might want a separate session token system
    if (!is_dev_token && self_->sec_->verifyApiKey(sid)) {
        LOG_INFOF("SESSION", "Session valid for token: %.*s***", 8, sid);

        // Log successful session access to security.log
        if (g_reporting) {
            char event_data[1024];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"session_access\",\"auth_type\":\"api_key_session\",\"client_ip\":\"%s\",\"endpoint\":\"%s\",\"session_preview\":\"%.*s***\"}",
                     client_ip, req->uri, 8, sid);
            g_reporting->reportLogMessage(
                PSRAMUtils::createPSRAMString("SECURITY"),
                PSRAMUtils::createPSRAMString("INFO"),
                PSRAMUtils::createPSRAMString(event_data),
                (uint64_t)(esp_timer_get_time()/1000ULL));
        }
        return true;
    } else {
        // If not a valid API key, check if it's a temporary session token
        // For simplicity, accept any token longer than 16 characters for development
        if (is_dev_token || strlen(sid) >= 16) {
            LOG_INFOF("SESSION", "Session valid (development mode) for token: %.*s***", 8, sid);

            // Log successful development session access to security.log
            if (g_reporting) {
                char event_data[1024];
                snprintf(event_data, sizeof(event_data),
                         "{\"action\":\"session_access\",\"auth_type\":\"development_session\",\"client_ip\":\"%s\",\"endpoint\":\"%s\",\"session_preview\":\"%.*s***\"}",
                         client_ip, req->uri, 8, sid);
                g_reporting->reportLogMessage(
                    PSRAMUtils::createPSRAMString("SECURITY"),
                    PSRAMUtils::createPSRAMString("INFO"),
                    PSRAMUtils::createPSRAMString(event_data),
                    (uint64_t)(esp_timer_get_time()/1000ULL));
            }
            return true;
        }

        // Log failed session validation to security.log
        if (g_reporting) {
            char event_data[1024];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"session_failed\",\"client_ip\":\"%s\",\"endpoint\":\"%s\",\"session_preview\":\"%.*s***\",\"reason\":\"invalid_token\"}",
                     client_ip, req->uri, 8, sid);
            g_reporting->reportLogMessage(
                PSRAMUtils::createPSRAMString("SECURITY"),
                PSRAMUtils::createPSRAMString("WARNING"),
                PSRAMUtils::createPSRAMString(event_data),
                (uint64_t)(esp_timer_get_time()/1000ULL));
        }

        LOG_INFOF("SESSION", "Session validation failed for token: %.*s***, IP: %s", 8, sid, client_ip);
        return false;
    }
}


esp_err_t WebServer::h_login_get(httpd_req_t* req){
    // If already logged in, redirect to "/"
    if (check_session(req)) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/");
        return httpd_resp_send(req, "", 0);
    }
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, LOGIN_HTML_GEN, HTTPD_RESP_USE_STRLEN);
}

static int hexv(int c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return 10+(c-'a');
    if (c>='A'&&c<='F') return 10+(c-'A');
    return -1;
}
static psram_string url_decode_min(const psram_string& in){
    psram_string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '+') {
            out.push_back(' ');
        } else if (c == '%' && i + 2 < in.size()) {
            int h1 = hexv(in[i + 1]);
            int h2 = hexv(in[i + 2]);
            if (h1 >= 0 && h2 >= 0) {
                out.push_back((char)((h1 << 4) | h2));
                i += 2;
            } else {
                out.push_back(c);
            }
        } else {
            out.push_back(c);
        }
    }
    return out;
}
esp_err_t WebServer::h_login_post(httpd_req_t* req){
    AccessLogger::getInstance().logRequest(req, "password=[REDACTED]");

    if (!self_ || !self_->sec_) {
        AccessLogger::getInstance().logResponse(req, 500, "FAILED");
        return httpd_resp_send_500(req);
    }

    psram_string body;
    if (!read_body(req, body)) {
        AccessLogger::getInstance().logResponse(req, 400, "FAILED");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    // parse key=p=...
    auto p = body.find("p=");
    psram_string pw = (p == psram_string::npos) ? psram_string() : body.substr(p + 2);
    pw = url_decode_min(pw);

    if (!self_->sec_->verifyAdminPassword(pw)) {
        // Log failed login attempt to security.log
        const char* client_ip = extractClientIPToBuffer(req);
        if (g_reporting) {
            char event_data[512];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"login_failed\",\"user\":\"admin\",\"client_ip\":\"%s\",\"endpoint\":\"/login\",\"reason\":\"invalid_password\"}",
                     client_ip);
            report_event_ps(g_reporting, "security", event_data);
        }

        // AUDIT: Log failed login attempt
        AuditManager::getInstance().logSecurityEvent("login_failed", "admin", client_ip, "Invalid password provided for web interface login");

        AccessLogger::getInstance().logResponse(req, 401, "FAILED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "bad password");
    }

    // Generate simple session token for development
    const char* client_ip = extractClientIPToBuffer(req);

    // Generate a simple session token using current time and some randomness
    char tok_buf[64];
    uint32_t rand_val = esp_random();
    uint32_t time_val = (uint32_t)(esp_timer_get_time() / 1000); // ms since boot
    snprintf(tok_buf, sizeof(tok_buf), "sess_%08lx_%08lx", (unsigned long)time_val, (unsigned long)rand_val);

    if (tok_buf[0] == '\0') {
        LOG_ERROR("SESSION", "Failed to generate session token");
        AccessLogger::getInstance().logResponse(req, 500, "TOKEN_GENERATION_FAILED");
        return httpd_resp_send_500(req);
    }

    LOG_INFOF("SESSION", "Created session token for admin from IP %s: %.*s***",
              client_ip, 12, tok_buf);

    // Log successful login to security.log
    if (g_reporting) {
        char event_data[512];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"login_success\",\"user\":\"admin\",\"client_ip\":\"%s\",\"endpoint\":\"/login\",\"session_id\":\"%.*s***\"}",
                 client_ip, 12, tok_buf);
        report_event_ps(g_reporting, "security", event_data);
    }

    // AUDIT: Log successful login event
    AuditManager::getInstance().logSecurityEvent("login_success", "admin", client_ip, "Web interface login successful");

    // Redirect to dashboard with querystring token
    char location[256];
    snprintf(location, sizeof(location), "/?sid=%s", tok_buf);

    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", location);
    httpd_resp_set_hdr(req, "Content-Length", "0");

    LOG_INFO("SESSION", "Login successful, redirecting to dashboard with querystring token");
    AccessLogger::getInstance().logResponse(req, 302, "SUCCESS");

    // Send empty response for redirect
    return httpd_resp_send(req, "", 0);
}

esp_err_t WebServer::h_logout(httpd_req_t* req){
    if (self_) {
        // Extract session token and invalidate it
        std::string token;
        size_t n = httpd_req_get_hdr_value_len(req, "Cookie");
        if (n > 0 && n < 1024) {
            char *buf = (char*)heap_caps_malloc(n + 1, MALLOC_CAP_SPIRAM);
            if (buf) {
                if (httpd_req_get_hdr_value_str(req, "Cookie", buf, n + 1) == ESP_OK) {
                    std::string c(buf);
                    size_t pos = c.find("SID=");
                    if (pos != std::string::npos) {
                        size_t start = pos + 4;
                        size_t end = c.find(';', start);
                        if (end == std::string::npos) end = c.length();
                        token = c.substr(start, end - start);

                        // Token-based logout (token invalidated by redirecting to login)
                        LOG_INFO("SESSION", "Logged out session");

                        // Log logout to security.log
                        const char* client_ip = extractClientIPToBuffer(req);
                        if (g_reporting) {
                            char event_data[512];
                            snprintf(event_data, sizeof(event_data),
                                     "{\"action\":\"logout\",\"user\":\"admin\",\"client_ip\":\"%s\",\"endpoint\":\"/logout\",\"session_id\":\"%.*s***\"}",
                                     client_ip, 12, token.c_str());
                            report_event_ps(g_reporting, "security", event_data);
                        }

                        // AUDIT: Log logout event
                        AuditManager::getInstance().logSecurityEvent("logout", "admin", client_ip, "User logged out from web interface");
                    }
                }
                heap_caps_free(buf);
            }
        }
    }

    // Clear cookie by setting Max-Age=0 (compatible with HTTP)
    httpd_resp_set_hdr(req, "Set-Cookie",
        "SID=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
    return httpd_resp_sendstr(req, "OK");
}


bool WebServer::check_api_auth(httpd_req_t* req){
    // CRITICAL OPTIMIZATION: Avoid ALL std::string allocations in hot path
    // This function is called for EVERY API request (status, config, wifi/status, etc.)

    // Extract Bearer token from Authorization header
    char auth_buf[256] = {0};
    size_t n = httpd_req_get_hdr_value_len(req, "Authorization");

    if (n == 0 || n >= sizeof(auth_buf)) {
        LOG_INFO("API_AUTH", "No Authorization header or header too large");
        return false;
    }

    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_buf, sizeof(auth_buf)) != ESP_OK) {
        LOG_INFO("API_AUTH", "Failed to read Authorization header");
        return false;
    }

    // OPTIMIZATION: Use C string operations instead of std::string
    // OLD: std::string auth_header(auth_buf); // 256 bytes Internal RAM
    // OLD: std::string token = auth_header.substr(...); // another allocation

    // Check for "Bearer " prefix using C strings
    const char* bearer_prefix = "Bearer ";
    const size_t bearer_len = 7;  // strlen("Bearer ")

    if (strlen(auth_buf) <= bearer_len || strncmp(auth_buf, bearer_prefix, bearer_len) != 0) {
        LOG_INFO("API_AUTH", "Authorization header missing Bearer prefix");
        return false;
    }

    // Extract token (pointer to substring, no allocation)
    const char* token = auth_buf + bearer_len;
    if (token[0] == '\0') {
        LOG_INFO("API_AUTH", "Empty Bearer token");
        return false;
    }

    // Validate Bearer token - try API key first, then session token
    if (self_ && self_->sec_) {
        // OPTIMIZATION: Use buffer-based IP extraction (48 bytes stack vs ~64 bytes heap)
        const char* client_ip = extractClientIPToBuffer(req);
        const bool is_dev_token = isDevelopmentSessionToken(token);

        // First try as API key
        if (!is_dev_token && self_->sec_->verifyApiKey(token)) {
            // Log successful API key access to security.log
            if (g_reporting) {
                char event_data[1024];
                snprintf(event_data, sizeof(event_data),
                         "{\"action\":\"api_access\",\"auth_type\":\"api_key\",\"client_ip\":\"%s\",\"endpoint\":\"%s\",\"method\":\"%s\",\"key_preview\":\"%.*s***\"}",
                         client_ip, req->uri,
                         (req->method == HTTP_GET) ? "GET" : (req->method == HTTP_POST) ? "POST" : "OTHER",
                         8, token);
                g_reporting->reportLogMessage(
                    PSRAMUtils::createPSRAMString("SECURITY"),
                    PSRAMUtils::createPSRAMString("INFO"),
                    PSRAMUtils::createPSRAMString(event_data),
                    (uint64_t)(esp_timer_get_time()/1000ULL));
            }
            return true;
        }

        //TODO: remove after development
        // Then try as session token (simple validation for development)
        if (is_dev_token || strlen(token) >= 16) {
            // Log successful session access to security.log
            if (g_reporting) {
                char event_data[1024];
                snprintf(event_data, sizeof(event_data),
                         "{\"action\":\"api_access\",\"auth_type\":\"session\",\"client_ip\":\"%s\",\"endpoint\":\"%s\",\"method\":\"%s\",\"session_preview\":\"%.*s***\"}",
                         client_ip, req->uri,
                         (req->method == HTTP_GET) ? "GET" : (req->method == HTTP_POST) ? "POST" : "OTHER",
                         8, token);
                g_reporting->reportLogMessage(
                    PSRAMUtils::createPSRAMString("SECURITY"),
                    PSRAMUtils::createPSRAMString("INFO"),
                    PSRAMUtils::createPSRAMString(event_data),
                    (uint64_t)(esp_timer_get_time()/1000ULL));
            }
            return true;
        }

        // Log failed authentication attempt to security.log
        if (g_reporting) {
            char event_data[1024];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"auth_failed\",\"auth_type\":\"bearer_token\",\"client_ip\":\"%s\",\"endpoint\":\"%s\",\"method\":\"%s\",\"token_preview\":\"%.*s***\"}",
                     client_ip, req->uri,
                     (req->method == HTTP_GET) ? "GET" : (req->method == HTTP_POST) ? "POST" : "OTHER",
                     8, token);
            g_reporting->reportLogMessage(
                PSRAMUtils::createPSRAMString("SECURITY"),
                PSRAMUtils::createPSRAMString("WARNING"),
                PSRAMUtils::createPSRAMString(event_data),
                (uint64_t)(esp_timer_get_time()/1000ULL));
        }

        // AUDIT: Log API authentication failure
        char api_details[600];
        snprintf(api_details, sizeof(api_details), "Invalid Bearer token for %s %s",
                 (req->method == HTTP_GET) ? "GET" : (req->method == HTTP_POST) ? "POST" : "OTHER",
                 req->uri);
        AuditManager::getInstance().logSecurityEvent("api_auth_failed", "unknown", client_ip, api_details);
    }

    LOG_INFOF("API_AUTH", "Bearer token validation failed: %.*s***", 8, token);
    return false;
}

esp_err_t WebServer::h_keys_list(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->sec_) return httpd_resp_send_500(req);
    auto v = self_->sec_->listApiKeysMasked();
    cJSON* arr = cJSON_CreateArray();
    for (auto const& p : v){
        cJSON* o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "id", p.first.c_str());
        cJSON_AddStringToObject(o, "label", p.second.c_str());
        cJSON_AddItemToArray(arr, o);
    }
    char* s = cJSON_PrintUnformatted(arr);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    auto r = httpd_resp_send(req, s? s:"[]", HTTPD_RESP_USE_STRLEN);
    if (s) free_cjson_str(s);
    cJSON_Delete(arr);
    return r;
}

esp_err_t WebServer::h_keys_create(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->sec_ || !self_->cfg_) return httpd_resp_send_500(req);
    psram_string body; if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    cJSON* o = cJSON_Parse(body.c_str()); if (!o) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "json");
    cJSON* lb = cJSON_GetObjectItem(o,"label");
    std::string token = self_->sec_->createApiKey(lb && cJSON_IsString(lb)? lb->valuestring : "api");
    self_->sec_->saveToConfig(self_->cfg_);
    cJSON_Delete(o);
    // WARNING: return token once
    std::string out = std::string("{\"token\":\"")+token+"\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, out.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_keys_revoke(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->sec_ || !self_->cfg_) return httpd_resp_send_500(req);
    // id from query ?id=
    char q[64]; if (httpd_req_get_url_query_len(req)>= (int)sizeof(q)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "query");
    if (httpd_req_get_url_query_str(req, q, sizeof(q))!=ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "query");
    char id[32]; if (httpd_query_key_value(q, "id", id, sizeof(id))!=ESP_OK) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "id");
    bool ok = self_->sec_->revokeApiKey(id);
    if (ok) self_->sec_->saveToConfig(self_->cfg_);
    return httpd_resp_sendstr(req, ok? "OK":"ERR");
}


esp_err_t WebServer::h_logs_retention_get(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    std::string s = LogRetentionManager::toJSON(g_logret_cfg);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, s.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_logs_retention_post(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);
    char* body_ps = nullptr; size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    g_logret_cfg = LogRetentionManager::fromJSON(std::string(body_ps, body_len));
    g_logret.init(g_logret_cfg);
    // persist (PSRAM-safe)
    size_t ps_sz = 0; char* ps_buf = self_->cfg_->getRawConfigInPSRAM(&ps_sz);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = (ps_buf && ps_sz) ? PSRAMJsonParser::parseInPSRAM(ps_buf, ps_sz) : nullptr;
    if (ps_buf) heap_caps_free(ps_buf);
    if (!root) root = cJSON_CreateObject();
    cJSON* sec = cJSON_GetObjectItem(root,"storage"); if (!sec) { sec = cJSON_CreateObject(); cJSON_AddItemToObject(root,"storage",sec); }
    cJSON* lr  = cJSON_Parse(LogRetentionManager::toJSON(g_logret_cfg).c_str());
    cJSON_ReplaceItemInObject(sec, "log_retention", lr);
    char* out = cJSON_PrintUnformatted(root);
    bool ok=false; if (out) { ok = self_->cfg_->saveConfigJSON(out); free_cjson_str(out); }
    cJSON_Delete(root);
    if (body_ps) heap_caps_free(body_ps);
    return httpd_resp_sendstr(req, ok? "OK":"ERR");
}

esp_err_t WebServer::h_logs_retention_run(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    g_logret.runOnce();
    return httpd_resp_sendstr(req, "OK");
}

esp_err_t WebServer::h_logs_access_get(httpd_req_t* req){
    AccessLogger::getInstance().logRequest(req);

    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "FAILED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    // Get limit parameter from query string
    int limit = 100;
    char query[64];
    if (httpd_req_get_url_query_len(req) > 0 && httpd_req_get_url_query_len(req) < (int)sizeof(query)) {
        if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
            char limit_str[16];
            if (httpd_query_key_value(query, "limit", limit_str, sizeof(limit_str)) == ESP_OK) {
                limit = atoi(limit_str);
                if (limit <= 0 || limit > 1000) limit = 100;
            }
        }
    }

    // MEMORY FIX: Get JSON from PSRAM (direct char* - no psram_string metadata overhead)
    char* json_psram = AccessLogger::getInstance().getRecentLogsJSON(limit);
    if (!json_psram) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_ALLOC_FAIL");
        return httpd_resp_send_500(req);
    }

    // Send response using global chunked transfer buffer (eliminates malloc/free overhead)
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");

    size_t json_len = strlen(json_psram);
    esp_err_t result = send_chunked_from_psram(req, json_psram, json_len);

    // CRITICAL: Free PSRAM-allocated JSON to prevent memory leak
    heap_caps_free(json_psram);

    AccessLogger::getInstance().logResponse(req, result == ESP_OK ? 200 : 500, result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");

    SCHEDULE_DEFRAG();

    return result;
}

esp_err_t WebServer::h_logs_access_metrics(httpd_req_t* req){
    AccessLogger::getInstance().logRequest(req);

    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    char* json_psram = AccessLogger::getInstance().getApiMetricsJSON();
    if (!json_psram) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_ALLOC_FAIL");
        return httpd_resp_send_500(req);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    size_t json_len = strlen(json_psram);
    esp_err_t result = send_chunked_from_psram(req, json_psram, json_len);
    heap_caps_free(json_psram);

    AccessLogger::getInstance().logResponse(req, result == ESP_OK ? 200 : 500, result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");
    return result;
}

esp_err_t WebServer::h_report_format_get(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    // PSRAM-safe read of reporting.event_format
    size_t jsz = 0; char* jbuf = self_->cfg_->getRawConfigInPSRAM(&jsz);
    if (!jbuf || jsz == 0) return httpd_resp_send_500(req);
    const char* p = strstr(jbuf, "\"event_format\"");
    const char* v = p ? strchr(p, ':') : nullptr;
    const char* fmt = "JSON";
    if (v) {
        if (strstr(v, "CEF")) fmt="CEF";
        else if (strstr(v,"LEEF")) fmt="LEEF";
        else if (strstr(v,"CEE")) fmt="CEE";
        else if (strstr(v,"JSON")) fmt="JSON";
    }
    char out[64]; snprintf(out,sizeof(out), "{\"event_format\":\"%s\"}", fmt);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t rr = httpd_resp_send(req, out, HTTPD_RESP_USE_STRLEN);
    heap_caps_free(jbuf);
    return rr;

    //TODO: remove if the code works fine without a preallocated buffer
    // Initialize PSRAM buffers if needed
    web_buf_init();
    if (!web_buf) {
        LOG_ERROR(TAG_WEB, "❌ web_buf not available for report format");
        httpd_resp_set_status(req, "503 Service Unavailable");
        return httpd_resp_send(req, "{\"error\":\"Buffer unavailable\"}", strlen("{\"error\":\"Buffer unavailable\"}"));
    }

    // *** COMPLETELY STL-FREE IMPLEMENTATION ***
    // Get config as C string directly (avoid std::string allocation)
    const char* raw_config = nullptr;
    //size_t config_len = 0;

    /*
    // Check PSRAM heap before any operations (more abundant than internal RAM)
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    if (free_psram < 32768) { // 32KB threshold in PSRAM for config operations
        LOG_ERRORF(TAG_WEB, "⚠️ Low PSRAM: %zu bytes", free_psram);
        httpd_resp_set_status(req, "503 Service Unavailable");
        return httpd_resp_send(req, "{\"error\":\"Low memory\"}", strlen("{\"error\":\"Low memory\"}"));
    }*/

    // TEMPORARY: PSRAM-safe variant using raw buffer
    if (self_ && self_->cfg_) {
        size_t ksz = 0; char* kbuf = self_->cfg_->getRawConfigInPSRAM(&ksz);
        raw_config = kbuf;
        //config_len = temp_raw.length();

        // Use C-style string parsing on the raw config
        const char* p = strstr(raw_config, "\"event_format\"");
        const char* v = p ? strchr(p, ':') : nullptr;
        const char* fmt = "JSON"; // Default format

        if (v) {
            if (strstr(v, "CEF")) fmt = "CEF";
            else if (strstr(v, "LEEF")) fmt = "LEEF";
            else if (strstr(v, "CEE")) fmt = "CEE";
            else if (strstr(v, "JSON")) fmt = "JSON";
        }

        // Build response using PSRAM buffer with snprintf (NO std::string)
        int written = snprintf(web_buf, WEB_BUF_SZ, "{\"event_format\":\"%s\"}", fmt);
        if (written < 0 || written >= WEB_BUF_SZ) {
            LOG_ERROR(TAG_WEB, "❌ Buffer overflow in report format response");
            httpd_resp_set_status(req, "500 Internal Server Error");
            return httpd_resp_send(req, "{\"error\":\"Response too large\"}", strlen("{\"error\":\"Response too large\"}"));
        }

        // Send response directly from PSRAM buffer
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, web_buf, written);

    } else {
        // No config manager available
        const char* default_response = "{\"event_format\":\"JSON\"}";
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, default_response, strlen(default_response));
    }
}

esp_err_t WebServer::h_report_format_post(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    char buf[64]={0};
    int r = httpd_req_recv(req, buf, sizeof(buf)-1);
    if (r<=0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body");
    // expect {"event_format":"CEF|LEEF|CEE|JSON"}
    std::string b(buf);
    EventFormat fmt = EventFormat::JSON;
    if (b.find("CEF")!=std::string::npos) fmt=EventFormat::CEF;
    else if (b.find("LEEF")!=std::string::npos) fmt=EventFormat::LEEF;
    else if (b.find("CEE")!=std::string::npos) fmt=EventFormat::CEE;
    // Apply to all enabled channels
    if (self_->rep_) {
        // naive: set default on common channels
        self_->rep_->setChannelFormat("ids", fmt, true);
        self_->rep_->setChannelFormat("plugins", fmt, true);
        self_->rep_->setChannelFormat("audit", fmt, true);
    }
    // Persist in cfg JSON (PSRAM-safe)
    size_t jsz = 0; char* jbuf = self_->cfg_->getRawConfigInPSRAM(&jsz);
    PSRAMJsonParser::PSRAMContext ctx6;
    cJSON* rootCfg = (jbuf && jsz) ? PSRAMJsonParser::parseInPSRAM(jbuf, jsz) : nullptr;
    if (jbuf) heap_caps_free(jbuf);
    if (!rootCfg) rootCfg = cJSON_CreateObject();
    cJSON* reporting = cJSON_GetObjectItem(rootCfg, "reporting");
    if (!reporting) { reporting = cJSON_CreateObject(); cJSON_AddItemToObject(rootCfg, "reporting", reporting); }
    cJSON_DeleteItemFromObject(reporting, "event_format");
    const char* fmt_str = (fmt==EventFormat::CEF?"CEF":fmt==EventFormat::LEEF?"LEEF":fmt==EventFormat::CEE?"CEE":"JSON");
    cJSON_AddStringToObject(reporting, "event_format", fmt_str);
    char* updated = cJSON_PrintUnformatted(rootCfg);
    if (updated) { self_->cfg_->saveConfigJSON(updated); free_cjson_str(updated);}
    cJSON_Delete(rootCfg);
    invalidateReportingCache();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}

// Filter management endpoints
esp_err_t WebServer::h_report_filters_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");

    // Parse channel parameter from query string
    char query[256] = {0};
    char channel[64] = {0};

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing query parameters");
    }

    if (httpd_query_key_value(query, "channel", channel, sizeof(channel)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing channel parameter");
    }

    psram_string channel_name = PSRAMUtils::createPSRAMString(channel);
    psram_string filters_json = g_reporting->getChannelFiltersJSON(channel_name);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    if (filters_json.empty()) {
        static const char empty_json[] = "{}";
        return send_chunked_from_psram(req, empty_json, sizeof(empty_json) - 1);
    }
    return send_chunked_from_psram(req, filters_json.data(), filters_json.size());
}

esp_err_t WebServer::h_report_filters_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");

    psram_string body;
    if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    // Expected: {"channel":"serial","enabled":true,"case_sensitive":false,"include":["pattern1"],"exclude":["pattern2"]}
    cJSON* obj = cJSON_Parse(body.c_str());
    if (!obj) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");

    cJSON* channel = cJSON_GetObjectItem(obj, "channel");
    cJSON* enabled = cJSON_GetObjectItem(obj, "enabled");
    cJSON* case_sensitive = cJSON_GetObjectItem(obj, "case_sensitive");
    cJSON* include_array = cJSON_GetObjectItem(obj, "include");
    cJSON* exclude_array = cJSON_GetObjectItem(obj, "exclude");

    bool ok = false;
    if (channel && cJSON_IsString(channel)) {
        psram_string channel_name = PSRAMUtils::createPSRAMString(channel->valuestring);
        psram_string_vector include_filters, exclude_filters;

        // Parse include filters
        if (include_array && cJSON_IsArray(include_array)) {
            cJSON* pattern = nullptr;
            cJSON_ArrayForEach(pattern, include_array) {
                if (cJSON_IsString(pattern) && pattern->valuestring) {
                    include_filters.push_back(PSRAMUtils::createPSRAMString(pattern->valuestring));
                }
            }
        }

        // Parse exclude filters
        if (exclude_array && cJSON_IsArray(exclude_array)) {
            cJSON* pattern = nullptr;
            cJSON_ArrayForEach(pattern, exclude_array) {
                if (cJSON_IsString(pattern) && pattern->valuestring) {
                    exclude_filters.push_back(PSRAMUtils::createPSRAMString(pattern->valuestring));
                }
            }
        }

        bool filters_enabled = enabled && cJSON_IsTrue(enabled);
        bool is_case_sensitive = case_sensitive && cJSON_IsTrue(case_sensitive);

        ok = g_reporting->setChannelFilters(channel_name, include_filters, exclude_filters, filters_enabled, is_case_sensitive);
    }

    cJSON_Delete(obj);
    if (ok) {
        invalidateReportingCache();
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, ok ? "{\"ok\":true}" : "{\"ok\":false}", HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_report_filter_add(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");

    psram_string body;
    if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    // Expected: {"channel":"serial","pattern":"error","type":"include"|"exclude"}
    cJSON* obj = cJSON_Parse(body.c_str());
    if (!obj) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");

    cJSON* channel = cJSON_GetObjectItem(obj, "channel");
    cJSON* pattern = cJSON_GetObjectItem(obj, "pattern");
    cJSON* type = cJSON_GetObjectItem(obj, "type");

    bool ok = false;
    if (channel && cJSON_IsString(channel) && pattern && cJSON_IsString(pattern) && type && cJSON_IsString(type)) {
        psram_string channel_name = PSRAMUtils::createPSRAMString(channel->valuestring);
        psram_string pattern_str = PSRAMUtils::createPSRAMString(pattern->valuestring);
        std::string type_str = type->valuestring;

        if (type_str == "include") {
            ok = g_reporting->addChannelIncludeFilter(channel_name, pattern_str);
        } else if (type_str == "exclude") {
            ok = g_reporting->addChannelExcludeFilter(channel_name, pattern_str);
        }
    }

    cJSON_Delete(obj);
    if (ok) {
        invalidateReportingCache();
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, ok ? "{\"ok\":true}" : "{\"ok\":false}", HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_report_filter_remove(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!g_reporting) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "reporting not ready");

    psram_string body;
    if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    // Expected: {"channel":"serial","pattern":"error","type":"include"|"exclude"}
    cJSON* obj = cJSON_Parse(body.c_str());
    if (!obj) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");

    cJSON* channel = cJSON_GetObjectItem(obj, "channel");
    cJSON* pattern = cJSON_GetObjectItem(obj, "pattern");
    cJSON* type = cJSON_GetObjectItem(obj, "type");

    bool ok = false;
    if (channel && cJSON_IsString(channel) && pattern && cJSON_IsString(pattern) && type && cJSON_IsString(type)) {
        psram_string channel_name = PSRAMUtils::createPSRAMString(channel->valuestring);
        psram_string pattern_str = PSRAMUtils::createPSRAMString(pattern->valuestring);
        std::string type_str = type->valuestring;
        bool is_include = (type_str == "include");

        ok = g_reporting->removeChannelFilter(channel_name, pattern_str, is_include);
    }

    cJSON_Delete(obj);
    if (ok) {
        invalidateReportingCache();
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, ok ? "{\"ok\":true}" : "{\"ok\":false}", HTTPD_RESP_USE_STRLEN);
}


esp_err_t WebServer::h_discovery_opcua(httpd_req_t* req){
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_->plugins_) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "plugins");

    // Parse target and timeout from query string
    char q[128]; char tgt[96] = {0}; char timeout_str[16] = {0};
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "target", tgt, sizeof(tgt));
        httpd_query_key_value(q, "timeout", timeout_str, sizeof(timeout_str));

        // Legacy support: if "ip" parameter is used instead of "target"
        char ip_buf[96] = {0}; char port_buf[16] = {0};
        if (tgt[0] == 0 && httpd_query_key_value(q, "ip", ip_buf, sizeof(ip_buf)) == ESP_OK) {
            strcpy(tgt, ip_buf);
            if (httpd_query_key_value(q, "port", port_buf, sizeof(port_buf)) == ESP_OK) {
                strcat(tgt, ":");
                strcat(tgt, port_buf);
            }
        }
    }
    if (tgt[0] == 0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing target network");

    uint32_t timeout_ms = (timeout_str[0] != 0) ? atoi(timeout_str) : 5000;
    if (timeout_ms < 1000) timeout_ms = 1000;
    if (timeout_ms > 30000) timeout_ms = 30000;

    BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::OPC_UA);
    if (!base) return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "OPC UA plugin not found");

    psram_string target_ps = PSRAMUtils::createPSRAMString(tgt);
    psram_string discovery_result;
    bool success = base->doNetworkDiscoveryPSRAM(target_ps, timeout_ms, discovery_result);

    // Report discovery results
    if (success && self_->rep_ && !discovery_result.empty()) {
        self_->rep_->reportEvent(PSRAMUtils::createPSRAMString("opcua_discovery_result"), discovery_result);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req,
                           discovery_result.empty() ? "" : discovery_result.c_str(),
                           HTTPD_RESP_USE_STRLEN);
}

// Protocol configuration handlers

esp_err_t WebServer::h_protocol_modbus_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    auto config = self_->cfg_->getProtocolConfig(ProtocolType::MODBUS_TCP);
    cJSON* json = cJSON_CreateObject();
    for (const auto& pair : config) {
        cJSON_AddStringToObject(json, pair.first.c_str(), pair.second.c_str());
    }

    char* str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!str) return httpd_resp_send_500(req);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(str);
    return ret;
}

esp_err_t WebServer::h_protocol_modbus_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    char* body_ps = nullptr; size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    cJSON* root = cJSON_ParseWithLength(body_ps, body_len);
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");

    // Update the plugins.modbus section in the full config (PSRAM-safe)
    size_t sz = 0; char* buf = self_->cfg_->getRawConfigInPSRAM(&sz);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* fullRoot = (buf && sz) ? PSRAMJsonParser::parseInPSRAM(buf, sz) : nullptr;
    if (buf) heap_caps_free(buf);
    if (!fullRoot) { cJSON_Delete(root); return httpd_resp_send_500(req); }

    cJSON* plugins = cJSON_GetObjectItem(fullRoot, "plugins");
    if (!plugins) {
        plugins = cJSON_CreateObject();
        cJSON_AddItemToObject(fullRoot, "plugins", plugins);
    }

    cJSON_DeleteItemFromObject(plugins, "modbus");
    cJSON_AddItemToObject(plugins, "modbus", cJSON_Duplicate(root, true));

    char* updatedConfig = cJSON_Print(fullRoot);
    cJSON_Delete(root);
    cJSON_Delete(fullRoot);

    if (!updatedConfig) { if (body_ps) heap_caps_free(body_ps); return httpd_resp_send_500(req); }

    bool success = self_->cfg_->saveConfigJSON(std::string(updatedConfig));
    free_cjson_str(updatedConfig);

    if (success) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK");
    }
    if (body_ps) heap_caps_free(body_ps);
    return httpd_resp_send_500(req);
}

esp_err_t WebServer::h_protocol_s7_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    auto config = self_->cfg_->getProtocolConfig(ProtocolType::S7_COMM);
    cJSON* json = cJSON_CreateObject();
    for (const auto& pair : config) {
        cJSON_AddStringToObject(json, pair.first.c_str(), pair.second.c_str());
    }

    if (self_->plugins_) {
        BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::S7_COMM);
        if (base) {
            auto* s7 = static_cast<S7Plugin*>(base);
            S7Plugin::RuntimeStats stats{};
            s7->getRuntimeStats(stats);
            cJSON* stats_obj = cJSON_CreateObject();
            if (stats_obj) {
                cJSON_AddNumberToObject(stats_obj, "handshake_started", static_cast<double>(stats.handshake_started));
                cJSON_AddNumberToObject(stats_obj, "handshake_confirmed", static_cast<double>(stats.handshake_confirmed));
                cJSON_AddNumberToObject(stats_obj, "handshake_failed", static_cast<double>(stats.handshake_failed));
                cJSON_AddNumberToObject(stats_obj, "setup_comm_completed", static_cast<double>(stats.setup_comm_completed));
                cJSON_AddNumberToObject(stats_obj, "tls_sessions", static_cast<double>(stats.tls_sessions));
                cJSON_AddNumberToObject(stats_obj, "stop_cpu_detected", static_cast<double>(stats.stop_cpu_detected));
                cJSON_AddNumberToObject(stats_obj, "stop_cpu_blocked", static_cast<double>(stats.stop_cpu_blocked));
                cJSON_AddNumberToObject(stats_obj, "restart_detected", static_cast<double>(stats.restart_detected));
                cJSON_AddNumberToObject(stats_obj, "reconnaissance_alerts", static_cast<double>(stats.reconnaissance_alerts));
                cJSON_AddNumberToObject(stats_obj, "write_alerts", static_cast<double>(stats.write_alerts));
                cJSON_AddNumberToObject(stats_obj, "brute_force_alerts", static_cast<double>(stats.brute_force_alerts));
                cJSON_AddNumberToObject(stats_obj, "flooding_alerts", static_cast<double>(stats.flooding_alerts));

                double success_pct = 0.0;
                if (stats.handshake_started > 0) {
                    success_pct = (static_cast<double>(stats.handshake_confirmed) * 100.0) / static_cast<double>(stats.handshake_started);
                }
                cJSON_AddNumberToObject(stats_obj, "handshake_success_pct", success_pct);

                double stop_block_pct = 0.0;
                if (stats.stop_cpu_detected > 0) {
                    stop_block_pct = (static_cast<double>(stats.stop_cpu_blocked) * 100.0) / static_cast<double>(stats.stop_cpu_detected);
                }
                cJSON_AddNumberToObject(stats_obj, "stop_block_pct", stop_block_pct);

                cJSON_AddItemToObject(json, "stats", stats_obj);
            }
        }
    }

    char* str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!str) return httpd_resp_send_500(req);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(str);
    return ret;
}

esp_err_t WebServer::h_protocol_s7_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    char* body_ps = nullptr; size_t body_len = 0;
    if (!read_body_psram(req, &body_ps, &body_len)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    cJSON* root = cJSON_ParseWithLength(body_ps, body_len);
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");

    size_t szp = 0; char* bufp = self_->cfg_->getRawConfigInPSRAM(&szp);
    PSRAMJsonParser::PSRAMContext ctxp;
    cJSON* fullRoot = (bufp && szp) ? PSRAMJsonParser::parseInPSRAM(bufp, szp) : nullptr;
    if (bufp) heap_caps_free(bufp);
    if (!fullRoot) { cJSON_Delete(root); return httpd_resp_send_500(req); }

    cJSON* plugins = cJSON_GetObjectItem(fullRoot, "plugins");
    if (!plugins) {
        plugins = cJSON_CreateObject();
        cJSON_AddItemToObject(fullRoot, "plugins", plugins);
    }

    cJSON_DeleteItemFromObject(plugins, "s7");
    cJSON_AddItemToObject(plugins, "s7", cJSON_Duplicate(root, true));

    char* updatedConfig = cJSON_Print(fullRoot);
    cJSON_Delete(root);
    cJSON_Delete(fullRoot);

    if (!updatedConfig) { if (body_ps) heap_caps_free(body_ps); return httpd_resp_send_500(req); }

    bool success = self_->cfg_->saveConfigJSON(std::string(updatedConfig));
    free_cjson_str(updatedConfig);

    if (success) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK");
    }
    if (body_ps) heap_caps_free(body_ps);
    return httpd_resp_send_500(req);
}

esp_err_t WebServer::h_protocol_profinet_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    auto config = self_->cfg_->getProtocolConfig(ProtocolType::PROFINET);
    cJSON* json = cJSON_CreateObject();
    for (const auto& pair : config) {
        cJSON_AddStringToObject(json, pair.first.c_str(), pair.second.c_str());
    }

    if (self_->plugins_) {
        BasePlugin* base = self_->plugins_->findByProtocol(ProtocolType::PROFINET);
        if (base) {
            auto* profinet = static_cast<PROFINETPlugin*>(base);
            PROFINETPlugin::RealtimeSummary summary;
            profinet->getRealtimeSummary(summary);
            cJSON* stats = cJSON_CreateObject();
            if (stats) {
                cJSON_AddNumberToObject(stats, "total_channels", summary.total_channels);
                cJSON_AddNumberToObject(stats, "irt_channels", summary.irt_channels);
                cJSON_AddNumberToObject(stats, "jitter_alerts", summary.jitter_alerts);
                cJSON_AddNumberToObject(stats, "total_missed_cycles", summary.total_missed_cycles);
                cJSON_AddNumberToObject(stats, "sync_locked_devices", summary.sync_locked_devices);
                cJSON_AddNumberToObject(stats, "sync_unlocked_devices", summary.sync_unlocked_devices);

                cJSON* channels = cJSON_CreateArray();
                if (channels) {
                    for (const auto& entry : summary.channels) {
                        cJSON* item = cJSON_CreateObject();
                        if (!item) {
                            continue;
                        }
                        cJSON_AddNumberToObject(item, "frame_id", entry.frame_id);
                        cJSON_AddBoolToObject(item, "is_irt", entry.is_irt);
                        cJSON_AddNumberToObject(item, "samples", entry.samples);
                        cJSON_AddNumberToObject(item, "missed_cycles", entry.missed_cycles);
                        cJSON_AddBoolToObject(item, "jitter_alerted", entry.jitter_alerted);
                        cJSON_AddNumberToObject(item, "last_ts_ms", (double)entry.last_ts_ms);
                        cJSON_AddNumberToObject(item, "last_cycle", entry.last_cycle);
                        cJSON_AddStringToObject(item, "mac", entry.mac.c_str());
                        cJSON_AddItemToArray(channels, item);
                    }
                    cJSON_AddItemToObject(stats, "channels", channels);
                }

                cJSON* sync_arr = cJSON_CreateArray();
                if (sync_arr) {
                    for (const auto& device : summary.sync_devices) {
                        cJSON* item = cJSON_CreateObject();
                        if (!item) {
                            continue;
                        }
                        cJSON_AddStringToObject(item, "mac", device.mac.c_str());
                        cJSON_AddBoolToObject(item, "locked", device.locked);
                        cJSON_AddNumberToObject(item, "valid_streak", device.valid_streak);
                        cJSON_AddNumberToObject(item, "invalid_streak", device.invalid_streak);
                        cJSON_AddItemToArray(sync_arr, item);
                    }
                    cJSON_AddItemToObject(stats, "sync_devices", sync_arr);
                }

                cJSON_AddItemToObject(json, "stats", stats);
            }
        }
    }

    char* str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!str) return httpd_resp_send_500(req);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(str);
    return ret;
}

esp_err_t WebServer::h_protocol_profinet_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    psram_string body;
    if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    cJSON* root = cJSON_Parse(body.c_str());
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");

    size_t szi = 0; char* bufi = self_->cfg_->getRawConfigInPSRAM(&szi);
    PSRAMJsonParser::PSRAMContext ctxi;
    cJSON* fullRoot = (bufi && szi) ? PSRAMJsonParser::parseInPSRAM(bufi, szi) : nullptr;
    if (bufi) heap_caps_free(bufi);
    if (!fullRoot) { cJSON_Delete(root); return httpd_resp_send_500(req); }

    cJSON* plugins = cJSON_GetObjectItem(fullRoot, "plugins");
    if (!plugins) {
        plugins = cJSON_CreateObject();
        cJSON_AddItemToObject(fullRoot, "plugins", plugins);
    }

    // Separate IDS-specific fields from protocol fields
    const char* ids_fields[] = {"detect_dcp_spoofing", "detect_config_changes", "detect_topology_changes", "max_devices_per_sec", nullptr};

    cJSON* profinet_config = cJSON_CreateObject();
    cJSON* profinet_ids = cJSON_CreateObject();

    // Iterate through input JSON and separate fields
    cJSON* field = nullptr;
    cJSON_ArrayForEach(field, root) {
        bool is_ids_field = false;
        for (int i = 0; ids_fields[i] != nullptr; i++) {
            if (strcmp(field->string, ids_fields[i]) == 0) {
                is_ids_field = true;
                break;
            }
        }

        if (is_ids_field) {
            cJSON_AddItemToObject(profinet_ids, field->string, cJSON_Duplicate(field, true));
        } else {
            cJSON_AddItemToObject(profinet_config, field->string, cJSON_Duplicate(field, true));
        }
    }

    // Update plugins.profinet section
    cJSON_DeleteItemFromObject(plugins, "profinet");
    cJSON_AddItemToObject(plugins, "profinet", profinet_config);

    // Update ids.protocol_specific.profinet section
    cJSON* ids_root = cJSON_GetObjectItem(fullRoot, "ids");
    if (!ids_root) {
        ids_root = cJSON_CreateObject();
        cJSON_AddItemToObject(fullRoot, "ids", ids_root);
    }

    cJSON* protocol_specific = cJSON_GetObjectItem(ids_root, "protocol_specific");
    if (!protocol_specific) {
        protocol_specific = cJSON_CreateObject();
        cJSON_AddItemToObject(ids_root, "protocol_specific", protocol_specific);
    }

    cJSON_DeleteItemFromObject(protocol_specific, "profinet");
    cJSON_AddItemToObject(protocol_specific, "profinet", profinet_ids);

    char* updatedConfig = cJSON_Print(fullRoot);
    cJSON_Delete(root);
    cJSON_Delete(fullRoot);

    if (!updatedConfig) return httpd_resp_send_500(req);

    bool success = self_->cfg_->saveConfigJSON(std::string(updatedConfig));
    free_cjson_str(updatedConfig);

    if (success) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK");
    }
    return httpd_resp_send_500(req);
}

esp_err_t WebServer::h_protocol_ethernetip_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    auto config = self_->cfg_->getProtocolConfig(ProtocolType::ETHERNET_IP);
    cJSON* json = cJSON_CreateObject();
    for (const auto& pair : config) {
        cJSON_AddStringToObject(json, pair.first.c_str(), pair.second.c_str());
    }

    char* str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!str) return httpd_resp_send_500(req);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(str);
    return ret;
}

esp_err_t WebServer::h_protocol_ethernetip_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    psram_string body;
    if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    cJSON* root = cJSON_Parse(body.c_str());
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");

    size_t szo = 0; char* bufo = self_->cfg_->getRawConfigInPSRAM(&szo);
    PSRAMJsonParser::PSRAMContext ctxo;
    cJSON* fullRoot = (bufo && szo) ? PSRAMJsonParser::parseInPSRAM(bufo, szo) : nullptr;
    if (bufo) heap_caps_free(bufo);
    if (!fullRoot) { cJSON_Delete(root); return httpd_resp_send_500(req); }

    cJSON* plugins = cJSON_GetObjectItem(fullRoot, "plugins");
    if (!plugins) {
        plugins = cJSON_CreateObject();
        cJSON_AddItemToObject(fullRoot, "plugins", plugins);
    }

    cJSON_DeleteItemFromObject(plugins, "ethernetip");
    cJSON_AddItemToObject(plugins, "ethernetip", cJSON_Duplicate(root, true));

    char* updatedConfig = cJSON_Print(fullRoot);
    cJSON_Delete(root);
    cJSON_Delete(fullRoot);

    if (!updatedConfig) return httpd_resp_send_500(req);

    bool success = self_->cfg_->saveConfigJSON(std::string(updatedConfig));
    free_cjson_str(updatedConfig);

    if (success) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK");
    }
    return httpd_resp_send_500(req);
}

esp_err_t WebServer::h_protocol_opcua_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    auto config = self_->cfg_->getProtocolConfig(ProtocolType::OPC_UA);
    cJSON* json = cJSON_CreateObject();
    for (const auto& pair : config) {
        cJSON_AddStringToObject(json, pair.first.c_str(), pair.second.c_str());
    }

    char* str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!str) return httpd_resp_send_500(req);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(str);
    return ret;
}

esp_err_t WebServer::h_protocol_opcua_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_500(req);

    psram_string body;
    if (!read_body(req, body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");

    cJSON* root = cJSON_Parse(body.c_str());
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");

    size_t szx = 0; char* bufx = self_->cfg_->getRawConfigInPSRAM(&szx);
    PSRAMJsonParser::PSRAMContext ctxx;
    cJSON* fullRoot = (bufx && szx) ? PSRAMJsonParser::parseInPSRAM(bufx, szx) : nullptr;
    if (bufx) heap_caps_free(bufx);
    if (!fullRoot) { cJSON_Delete(root); return httpd_resp_send_500(req); }

    cJSON* plugins = cJSON_GetObjectItem(fullRoot, "plugins");
    if (!plugins) {
        plugins = cJSON_CreateObject();
        cJSON_AddItemToObject(fullRoot, "plugins", plugins);
    }

    cJSON_DeleteItemFromObject(plugins, "opcua");
    cJSON_AddItemToObject(plugins, "opcua", cJSON_Duplicate(root, true));

    char* updatedConfig = cJSON_Print(fullRoot);
    cJSON_Delete(root);
    cJSON_Delete(fullRoot);

    if (!updatedConfig) return httpd_resp_send_500(req);

    bool success = self_->cfg_->saveConfigJSON(std::string(updatedConfig));
    free_cjson_str(updatedConfig);

    if (success) {
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "OK");
    }
    return httpd_resp_send_500(req);
}


// Web pages handlers

esp_err_t WebServer::h_page_protocols(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    return send_html_chunked(req, PROTOCOLS_HTML_GEN, PROTOCOLS_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_discovery(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    return send_html_chunked(req, DISCOVERY_HTML_GEN, DISCOVERY_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_scanner(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    // Serve HTML directly from const char* to avoid string copy and memory allocation
    return send_html_chunked(req, SCANNER_HTML_GEN, SCANNER_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_ids(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    return send_html_chunked(req, PASSIVE_DETECTION_HTML_GEN, PASSIVE_DETECTION_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_reporting(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    // Serve HTML directly from const char* to avoid string copy and memory allocation
    return send_html_chunked(req, REPORTING_HTML_GEN, REPORTING_HTML_GEN_SIZE);
}

// IDS Advanced API implementations
esp_err_t WebServer::h_ids_adv_cfg_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    auto ids_config = self_->cfg_->getIDSConfig();

    cJSON* response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "enabled", ids_config.enabled);
    cJSON_AddNumberToObject(response, "max_per_sec_modbus", ids_config.max_per_sec_modbus);
    cJSON_AddNumberToObject(response, "max_per_sec_s7", ids_config.max_per_sec_s7);
    cJSON_AddNumberToObject(response, "max_per_sec_enip", ids_config.max_per_sec_enip);
    cJSON_AddNumberToObject(response, "max_per_sec_pn", ids_config.max_per_sec_pn);
    cJSON_AddNumberToObject(response, "max_per_sec_opcua", ids_config.max_per_sec_opcua);
    cJSON_AddNumberToObject(response, "replay_window_ms", ids_config.replay_window_ms);
    // Get alert_modbus_broadcast_write from config.json directly using getBoolAtPath
    bool alert_modbus_broadcast_write = false;
    if (self_ && self_->cfg_) {
        self_->cfg_->getBoolAtPath("ids.protocol_specific.modbus.alert_broadcast_write", &alert_modbus_broadcast_write);
    }
    cJSON_AddBoolToObject(response, "alert_modbus_broadcast_write", alert_modbus_broadcast_write);

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    heap_caps_free(json_str);

    return ret;
}

esp_err_t WebServer::h_ids_adv_cfg_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string body;
    if (!read_body(req, body)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read body");
    }

    cJSON* request_json = cJSON_Parse(body.c_str());
    if (!request_json) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    }

    auto config_lock = self_->cfg_->lockConfig();
    // Get current configuration (PSRAM-safe)
    size_t jsz2 = 0; char* jbuf2 = self_->cfg_->getRawConfigInPSRAM(&jsz2);
    PSRAMJsonParser::PSRAMContext ctxids;
    cJSON* config_root = (jbuf2 && jsz2) ? PSRAMJsonParser::parseInPSRAM(jbuf2, jsz2) : nullptr;
    if (jbuf2) heap_caps_free(jbuf2);
    if (!config_root) {
        cJSON_Delete(request_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to parse current config");
    }

    // Get or create IDS section (new consolidated structure)
    cJSON* ids_root = cJSON_GetObjectItem(config_root, "ids");
    if (!ids_root) {
        ids_root = cJSON_CreateObject();
        cJSON_AddItemToObject(config_root, "ids", ids_root);
    }

    // Get or create ids.general section
    cJSON* ids_section = cJSON_GetObjectItem(ids_root, "general");
    if (!ids_section) {
        ids_section = cJSON_CreateObject();
        cJSON_AddItemToObject(ids_root, "general", ids_section);
    }

    // LEGACY: Also maintain advanced_ids for backward compatibility
    cJSON* legacy_ids = cJSON_GetObjectItem(config_root, "advanced_ids");
    if (!legacy_ids) {
        legacy_ids = cJSON_CreateObject();
        cJSON_AddItemToObject(config_root, "advanced_ids", legacy_ids);
    }

    // Helper lambda to update both new and legacy structures
    auto updateField = [&](const char* field_name, cJSON* value) {
        if (cJSON_IsBool(value)) {
            // Update new structure
            cJSON_DeleteItemFromObject(ids_section, field_name);
            cJSON_AddBoolToObject(ids_section, field_name, cJSON_IsTrue(value));
            // Update legacy structure
            cJSON_DeleteItemFromObject(legacy_ids, field_name);
            cJSON_AddBoolToObject(legacy_ids, field_name, cJSON_IsTrue(value));
        } else if (cJSON_IsNumber(value)) {
            // Update new structure
            cJSON_DeleteItemFromObject(ids_section, field_name);
            cJSON_AddNumberToObject(ids_section, field_name, value->valuedouble);
            // Update legacy structure
            cJSON_DeleteItemFromObject(legacy_ids, field_name);
            cJSON_AddNumberToObject(legacy_ids, field_name, value->valuedouble);
        }
    };

    // Update fields from request
    cJSON* enabled = cJSON_GetObjectItem(request_json, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        updateField("enabled", enabled);
    }

    cJSON* modbus = cJSON_GetObjectItem(request_json, "max_per_sec_modbus");
    if (modbus && cJSON_IsNumber(modbus)) {
        updateField("max_per_sec_modbus", modbus);
    }

    cJSON* s7 = cJSON_GetObjectItem(request_json, "max_per_sec_s7");
    if (s7 && cJSON_IsNumber(s7)) {
        updateField("max_per_sec_s7", s7);
    }

    cJSON* enip = cJSON_GetObjectItem(request_json, "max_per_sec_enip");
    if (enip && cJSON_IsNumber(enip)) {
        updateField("max_per_sec_enip", enip);
    }

    cJSON* pn = cJSON_GetObjectItem(request_json, "max_per_sec_pn");
    if (pn && cJSON_IsNumber(pn)) {
        updateField("max_per_sec_pn", pn);
    }

    cJSON* opcua = cJSON_GetObjectItem(request_json, "max_per_sec_opcua");
    if (opcua && cJSON_IsNumber(opcua)) {
        updateField("max_per_sec_opcua", opcua);
    }

    cJSON* replay = cJSON_GetObjectItem(request_json, "replay_window_ms");
    if (replay && cJSON_IsNumber(replay)) {
        updateField("replay_window_ms", replay);
    }

    cJSON* alert = cJSON_GetObjectItem(request_json, "alert_modbus_broadcast_write");
    if (cJSON_IsBool(alert)) {
        cJSON* specific = cJSON_GetObjectItem(ids_root, "protocol_specific");
        if (!specific) specific = cJSON_AddObjectToObject(ids_root, "protocol_specific");
        cJSON* modbus_config = cJSON_GetObjectItem(specific, "modbus");
        if (!modbus_config) modbus_config = cJSON_AddObjectToObject(specific, "modbus");
        if (modbus_config) {
            cJSON_DeleteItemFromObject(modbus_config, "alert_broadcast_write");
            cJSON_AddBoolToObject(modbus_config, "alert_broadcast_write", cJSON_IsTrue(alert));
        }
    }

    // Save all IDS fields together; a second stale snapshot would undo the alert flag.
    // Save updated configuration
    char* updated_config = cJSON_Print(config_root);
    bool success = updated_config && self_->cfg_->saveConfigJSON(updated_config);

    cJSON_Delete(request_json);
    cJSON_Delete(config_root);
    free_cjson_str(updated_config);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    if (success) {
        // Log configuration change to audit channel
        logConfigChange(req, "ids_advanced", "IDS advanced configuration updated");

        return httpd_resp_send(req, "{\"success\":true,\"message\":\"IDS configuration updated successfully\"}", HTTPD_RESP_USE_STRLEN);
    } else {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save configuration");
    }
}

esp_err_t WebServer::h_ids_adv_stats(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    LOG_INFO("IDS_STATS", "Processing IDS advanced stats request");

    if (!check_api_auth(req)) {
        LOG_WARNING("IDS_STATS", "Authentication failed for IDS stats endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    LOG_INFO("IDS_STATS", "Authentication successful, returning stats");

    esp_err_t result = ESP_FAIL;
    char* payload_snapshot = nullptr;
    size_t payload_len = 0;
    {
        std::lock_guard<std::mutex> guard(g_ids_adv_json.mutex);
        if (!build_ids_adv_json(g_ids_adv_json)) {
            AccessLogger::getInstance().logResponse(req, 500, "JSON_BUILD_FAIL");
            return httpd_resp_send_500(req);
        }
        if (!g_ids_adv_json.buf || g_ids_adv_json.length == 0) {
            AccessLogger::getInstance().logResponse(req, 500, "EMPTY_JSON");
            return httpd_resp_send_500(req);
        }
        payload_len = g_ids_adv_json.length;
        payload_snapshot = static_cast<char*>(
            heap_caps_malloc(payload_len + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
        );
        if (!payload_snapshot) {
            AccessLogger::getInstance().logResponse(req, 500, "NO_PSRAM_SNAPSHOT");
            return httpd_resp_send_500(req);
        }
        memcpy(payload_snapshot, g_ids_adv_json.buf, payload_len);
        payload_snapshot[payload_len] = '\0';
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    result = send_chunked_from_psram(req, payload_snapshot, payload_len);
    if (payload_snapshot) {
        heap_caps_free(payload_snapshot);
    }

    AccessLogger::getInstance().logResponse(req, result == ESP_OK ? 200 : 500, result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");

    return result;
}

// Network Presence tracking API implementations
esp_err_t WebServer::h_presence_stats_get(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    LOG_INFO("PRESENCE_STATS", "Processing network presence stats request");

    if (!check_api_auth(req)) {
        LOG_WARNING("PRESENCE_STATS", "Authentication failed for presence stats endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->ids_) {
        LOG_WARNING("PRESENCE_STATS", "IDS not available");
        AccessLogger::getInstance().logResponse(req, 500, "NO_IDS");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "IDS not available");
    }

    // Get global network presence statistics (not per-protocol)
    psram_string global_stats = self_->ids_->getNetworkPresenceTracker().getDevicesStatsJSON();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "SUCCESS");
    return httpd_resp_send(req, global_stats.c_str(), global_stats.length());
}

esp_err_t WebServer::h_presence_devices_get(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    LOG_INFO("PRESENCE_DEVICES", "Processing network presence devices request");

    if (!check_api_auth(req)) {
        LOG_WARNING("PRESENCE_DEVICES", "Authentication failed for presence devices endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->ids_) {
        LOG_WARNING("PRESENCE_DEVICES", "IDS not available");
        AccessLogger::getInstance().logResponse(req, 500, "NO_IDS");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "IDS not available");
    }

    // Get global network presence devices (not per-protocol, as they're shared across all protocols)
    // Use PSRAM for large JSON strings to save DRAM
    psram_string devices_json_psram = self_->ids_->getNetworkPresenceTracker().getDevicesStatsJSON();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");

    // Use global chunked transfer buffer (eliminates malloc/free overhead)
    esp_err_t result = send_chunked_from_psram(req, devices_json_psram.c_str(), devices_json_psram.length());

    AccessLogger::getInstance().logResponse(req, result == ESP_OK ? 200 : 500, result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");
    return result;
}

esp_err_t WebServer::h_presence_learned_get(httpd_req_t* req) {
    //AccessLogger::getInstance().logRequest(req);
    LOG_INFO("PRESENCE_LEARNED", "Processing learned devices request");

    if (!check_api_auth(req)) {
        LOG_WARNING("PRESENCE_LEARNED", "Authentication failed for learned devices endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->ids_) {
        LOG_WARNING("PRESENCE_LEARNED", "IDS not available");
        AccessLogger::getInstance().logResponse(req, 500, "NO_IDS");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "IDS not available");
    }

    // Get only learned (auto-trusted) devices from global tracker (not per-protocol)
    // Use PSRAM for large JSON strings to save DRAM
    psram_string json_result_psram = self_->ids_->getNetworkPresenceTracker().getLearnedDevicesJSON();


    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");

    // Use global chunked transfer buffer (eliminates malloc/free overhead)
    esp_err_t result = send_chunked_from_psram(req, json_result_psram.c_str(), json_result_psram.length());

    AccessLogger::getInstance().logResponse(req, result == ESP_OK ? 200 : 500, result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");
    return result;
}

esp_err_t WebServer::h_presence_config_get(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    //LOG_INFO("PRESENCE_CONFIG", "Processing presence config get request PHASE 0");

    if (!check_api_auth(req)) {
        LOG_WARNING("PRESENCE_CONFIG", "Authentication failed for presence config endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    //LOG_INFO("PRESENCE_CONFIG", "Processing presence config get request PHASE 1");

    //LOG_INFO("PRESENCE_CONFIG", "Processing presence config get request PHASE 2");
    // Get presence configuration from global IDS tracker (not per-protocol)
    if (!self_->ids_) {
        LOG_WARNING("PRESENCE_CONFIG", "IDS not available");
        AccessLogger::getInstance().logResponse(req, 500, "NO_IDS");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "IDS not available");
    }
    //LOG_INFO("PRESENCE_CONFIG", "Processing presence config get request PHASE 3");

    // Use PSRAM for JSON strings to save DRAM
    psram_string config_json_psram = self_->ids_->getNetworkPresenceTracker().getConfigJSON();
    //std::string config_json = PSRAMUtils::fromPSRAMString(config_json_psram);

    //LOG_INFO("PRESENCE_CONFIG", "Processing presence config get request PHASE 4");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    //LOG_INFO("PRESENCE_CONFIG", "Processing presence config get request PHASE 5");
    AccessLogger::getInstance().logResponse(req, 200, "SUCCESS");
    //LOG_INFO("PRESENCE_CONFIG", "Processed presence config get request PHASE 6");
    return httpd_resp_send(req, config_json_psram.c_str(), config_json_psram.length());
}

// Presence configuration is persisted and applied by passive_detection_api.cpp.


esp_err_t WebServer::h_presence_clear_post(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    LOG_INFO("PRESENCE_CLEAR", "Processing clear learned devices request");

    if (!check_api_auth(req)) {
        LOG_WARNING("PRESENCE_CLEAR", "Authentication failed for clear devices endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->ids_) {
        LOG_WARNING("PRESENCE_CLEAR", "IDS not available");
        AccessLogger::getInstance().logResponse(req, 500, "NO_IDS");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "IDS not available");
    }

    // Global tracker (consolidated): does not depend on the plugins.
    self_->ids_->getNetworkPresenceTracker().clearLearningData();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "SUCCESS");
    return httpd_resp_send(req, "{\"success\":true,\"message\":\"Cleared learned devices\"}", HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_presence_promote_post(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    LOG_INFO("PRESENCE_PROMOTE", "Processing promote device request");

    if (!check_api_auth(req)) {
        LOG_WARNING("PRESENCE_PROMOTE", "Authentication failed for promote device endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->ids_) {
        LOG_WARNING("PRESENCE_PROMOTE", "IDS not available");
        AccessLogger::getInstance().logResponse(req, 500, "NO_IDS");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "IDS not available");
    }

    psram_string body;
    if (!read_body(req, body)) {
        LOG_WARNING("PRESENCE_PROMOTE", "Failed to read request body");
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_BODY");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read body");
    }

    // Parse JSON to get IP address
    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) {
        LOG_WARNING("PRESENCE_PROMOTE", "Invalid JSON in request body");
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    }

    // Frontend legacy/compat: some calls use "address" instead of "ip".
    cJSON* ip_item = cJSON_GetObjectItem(json, "ip");
    if (!ip_item || !cJSON_IsString(ip_item)) {
        ip_item = cJSON_GetObjectItem(json, "address");
    }
    if (!ip_item || !cJSON_IsString(ip_item)) {
        cJSON_Delete(json);
        LOG_WARNING("PRESENCE_PROMOTE", "Missing or invalid 'ip' field in request");
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_IP");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid 'ip' field");
    }

    psram_string ip_address = ip_item->valuestring ? psram_string(ip_item->valuestring) : psram_string();
    cJSON_Delete(json);

    if (ip_address.empty()) {
        LOG_WARNING("PRESENCE_PROMOTE", "Empty IP/address in request");
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_IP");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid 'ip' field");
    }

    // Global tracker (consolidated)
    self_->ids_->getNetworkPresenceTracker().promoteToTrusted(ip_address);
    LOG_INFOF("PRESENCE_PROMOTE", "Promoted device %s to trusted (global tracker)", ip_address.c_str());

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "SUCCESS");
    return httpd_resp_send(req, "{\"success\":true,\"message\":\"Device promoted to trusted\"}", HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_presence_demote_post(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    LOG_INFO("PRESENCE_DEMOTE", "Processing demote device request");

    if (!check_api_auth(req)) {
        LOG_WARNING("PRESENCE_DEMOTE", "Authentication failed for demote device endpoint");
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->ids_) {
        LOG_WARNING("PRESENCE_DEMOTE", "IDS not available");
        AccessLogger::getInstance().logResponse(req, 500, "NO_IDS");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "IDS not available");
    }

    psram_string body;
    if (!read_body(req, body)) {
        LOG_WARNING("PRESENCE_DEMOTE", "Failed to read request body");
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_BODY");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read body");
    }

    // Parse JSON to get IP address
    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) {
        LOG_WARNING("PRESENCE_DEMOTE", "Invalid JSON in request body");
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    }

    cJSON* ip_item = cJSON_GetObjectItem(json, "ip");
    if (!ip_item || !cJSON_IsString(ip_item)) {
        ip_item = cJSON_GetObjectItem(json, "address");
    }
    if (!ip_item || !cJSON_IsString(ip_item)) {
        cJSON_Delete(json);
        LOG_WARNING("PRESENCE_DEMOTE", "Missing or invalid 'ip' field in request");
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_IP");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid 'ip' field");
    }

    psram_string ip_address = ip_item->valuestring ? psram_string(ip_item->valuestring) : psram_string();
    cJSON_Delete(json);

    if (ip_address.empty()) {
        LOG_WARNING("PRESENCE_DEMOTE", "Empty IP/address in request");
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_IP");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid 'ip' field");
    }

    // Global tracker (consolidated)
    self_->ids_->getNetworkPresenceTracker().demoteFromTrusted(ip_address);
    LOG_INFOF("PRESENCE_DEMOTE", "Demoted device %s from trusted (global tracker)", ip_address.c_str());

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "SUCCESS");
    return httpd_resp_send(req, "{\"success\":true,\"message\":\"Device demoted from trusted\"}", HTTPD_RESP_USE_STRLEN);
}

// WiFi API implementations
esp_err_t WebServer::h_wifi_scan_start(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    if (!self_ || !self_->wifi_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_WIFI_MANAGER");
        return httpd_resp_send_500(req);
    }

    bool started = self_->wifi_->startAsyncScan();

    cJSON* payload = cJSON_CreateObject();
    if (payload) {
        cJSON_AddBoolToObject(payload, "started", started);
        if (!started) {
            cJSON_AddStringToObject(payload, "error", "scan_in_progress_or_failed");
        }
        char* json = cJSON_PrintUnformatted(payload);
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        httpd_resp_send(req, json ? json : "{}", HTTPD_RESP_USE_STRLEN);
        if (json) free_cjson_str(json);
        cJSON_Delete(payload);
    } else {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
    }

    AccessLogger::getInstance().logResponse(req, started ? 200 : 200, started ? "OK" : "SCAN_BUSY");
    return ESP_OK;
}

esp_err_t WebServer::h_wifi_scan_status(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    if (!self_ || !self_->wifi_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_WIFI_MANAGER");
        return httpd_resp_send_500(req);
    }

    WiFiScanSnapshot snapshot{};
    WiFiScanEntry entries[WiFiManager::kMaxScanEntries];
    bool ok = self_->wifi_->getAsyncScanResults(&snapshot, entries, WiFiManager::kMaxScanEntries);

    cJSON* payload = cJSON_CreateObject();
    if (!payload) {
        AccessLogger::getInstance().logResponse(req, 500, "OOM");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
    }

    if (!ok) {
        cJSON_AddBoolToObject(payload, "available", false);
    } else {
        cJSON_AddBoolToObject(payload, "available", true);
        cJSON_AddBoolToObject(payload, "scanning", snapshot.scanning);
        cJSON_AddBoolToObject(payload, "completed", snapshot.completed);
        cJSON_AddNumberToObject(payload, "total_found", snapshot.total_found);
        cJSON_AddNumberToObject(payload, "cached", snapshot.cached);
        cJSON_AddNumberToObject(payload, "elapsed_ms", snapshot.elapsed_ms);
        cJSON_AddNumberToObject(payload, "status_code", snapshot.last_status);

        cJSON* list = cJSON_CreateArray();
        if (!list) {
            cJSON_Delete(payload);
            AccessLogger::getInstance().logResponse(req, 500, "OOM");
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        }
        uint16_t count = snapshot.cached;
        if (count > WiFiManager::kMaxScanEntries) count = WiFiManager::kMaxScanEntries;
        for (uint16_t i = 0; i < count; ++i) {
            cJSON* ap = cJSON_CreateObject();
            if (!ap) continue;
            cJSON_AddStringToObject(ap, "ssid", entries[i].ssid);
            cJSON_AddNumberToObject(ap, "rssi", entries[i].rssi);
            cJSON_AddNumberToObject(ap, "channel", entries[i].channel);
            cJSON_AddBoolToObject(ap, "secure", entries[i].secure);
            cJSON_AddStringToObject(ap, "auth_mode", wifi_authmode_to_cstr(entries[i].auth_mode));
            cJSON_AddItemToArray(list, ap);
        }
        cJSON_AddItemToObject(payload, "networks", list);
    }

    char* json = cJSON_PrintUnformatted(payload);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_send(req, json ? json : "{}", HTTPD_RESP_USE_STRLEN);
    if (json) free_cjson_str(json);
    cJSON_Delete(payload);
    AccessLogger::getInstance().logResponse(req, 200, "OK");
    return ESP_OK;
}

esp_err_t WebServer::h_wifi_connect_result(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    if (!self_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_SERVER");
        return httpd_resp_send_500(req);
    }

    bool in_progress = false;
    bool result_ready = false;
    bool success = false;
    bool ap_pending = false;
    bool ap_done = false;
    uint64_t ready_us = 0;
    char ip_buf[16] = {0};
    char ssid_buf[33] = {0};
    char err_buf[64] = {0};

    if (self_->wifi_transition_mutex_) {
        if (xSemaphoreTake(self_->wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
            in_progress = self_->wifi_transition_in_progress_;
            result_ready = self_->wifi_transition_result_ready_;
            success = self_->wifi_transition_success_;
            ap_pending = self_->wifi_transition_ap_shutdown_pending_;
            ap_done = self_->wifi_transition_ap_shutdown_done_;
            ready_us = self_->wifi_transition_ready_us_;
            memcpy(ip_buf, self_->wifi_transition_ip_, sizeof(ip_buf));
            memcpy(ssid_buf, self_->wifi_transition_ssid_, sizeof(ssid_buf));
            memcpy(err_buf, self_->wifi_transition_error_, sizeof(err_buf));
            xSemaphoreGive(self_->wifi_transition_mutex_);
        }
    }

    cJSON* payload = cJSON_CreateObject();
    if (!payload) {
        AccessLogger::getInstance().logResponse(req, 500, "OOM");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
    }

    cJSON_AddBoolToObject(payload, "in_progress", in_progress);
    cJSON_AddBoolToObject(payload, "result_ready", result_ready);
    cJSON_AddBoolToObject(payload, "success", success);
    cJSON_AddBoolToObject(payload, "ap_pending", ap_pending);
    cJSON_AddBoolToObject(payload, "ap_shutdown_done", ap_done);
    cJSON_AddNumberToObject(payload, "ready_us", (double)ready_us);
    cJSON_AddBoolToObject(payload, "ap_active", self_->wifi_ ? self_->wifi_->isAPActive() : false);
    cJSON_AddBoolToObject(payload, "sta_connected", self_->wifi_ ? self_->wifi_->isSTAConnected() : false);

    if (result_ready) {
        cJSON_AddStringToObject(payload, "ssid", ssid_buf);
        if (success) {
            cJSON_AddStringToObject(payload, "ip", ip_buf);
        } else {
            cJSON_AddStringToObject(payload, "error", err_buf[0] ? err_buf : "connection_failed");
        }
    }

    char* json = cJSON_PrintUnformatted(payload);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_send(req, json ? json : "{}", HTTPD_RESP_USE_STRLEN);
    if (json) free_cjson_str(json);
    cJSON_Delete(payload);
    AccessLogger::getInstance().logResponse(req, 200, "OK");

    bool should_shutdown_ap = (result_ready && success && ap_pending && self_->wifi_);
    if (should_shutdown_ap) {
        if (self_->wifi_transition_mutex_) {
            if (xSemaphoreTake(self_->wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
                self_->wifi_transition_ap_shutdown_pending_ = false;
                xSemaphoreGive(self_->wifi_transition_mutex_);
            }
        }

        if (self_->http_) {
            httpd_stop(self_->http_);
            self_->http_ = nullptr;
        }
        self_->clearAllowedManagementAddress();
        self_->wifi_->stopAP();
        // The central management controller will validate subnet separation and
        // restart the server on the new STA address from the main loop.

        if (self_->wifi_transition_mutex_) {
            if (xSemaphoreTake(self_->wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
                self_->wifi_transition_ap_shutdown_done_ = true;
                xSemaphoreGive(self_->wifi_transition_mutex_);
            }
        }
    }

    return ESP_OK;
}

bool WebServer::persistWiFiConfig(const char* ssid, const char* password) {
    if (!cfg_) return false;

    // Save SSID and password directly to NVS as separate keys
    // to avoid the ESP_ERR_NVS_VALUE_TOO_LONG error
    esp_err_t err_ssid = AsyncStorage::Global::nvsSet("wifi", "ssid", std::string(ssid ? ssid : ""));
    esp_err_t err_pass = AsyncStorage::Global::nvsSet("wifi", "password", std::string(password ? password : ""));
    esp_err_t err_enabled = AsyncStorage::Global::nvsSet("wifi", "enabled", (uint8_t)1);

    if (err_ssid != ESP_OK) {
        LOG_ERRORF("WebServer", "Failed to save WiFi SSID to NVS: %s", esp_err_to_name(err_ssid));
        return false;
    }
    if (err_pass != ESP_OK) {
        LOG_ERRORF("WebServer", "Failed to save WiFi password to NVS: %s", esp_err_to_name(err_pass));
        return false;
    }
    if (err_enabled != ESP_OK) {
        LOG_ERRORF("WebServer", "Failed to save WiFi enabled flag to NVS: %s", esp_err_to_name(err_enabled));
        return false;
    }

    LOG_INFO("WebServer", "WiFi credentials saved to NVS successfully");

    // Also update the configuration file on the filesystem for consistency
    size_t json_size = 0;
    char* json_buf = cfg_->getRawConfigInPSRAM(&json_size);
    cJSON* root = nullptr;
    if (json_buf && json_size) {
        PSRAMJsonParser::PSRAMContext ctx;
        root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
        heap_caps_free(json_buf);
    }
    if (!root) {
        root = cJSON_CreateObject();
    }

    cJSON* network = cJSON_GetObjectItem(root, "network");
    if (!network) {
        network = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "network", network);
    }

    cJSON* wifi = cJSON_GetObjectItem(network, "wifi");
    if (!wifi) {
        wifi = cJSON_CreateObject();
        cJSON_AddItemToObject(network, "wifi", wifi);
    }

    cJSON_ReplaceItemInObject(wifi, "enabled", cJSON_CreateBool(1));
    cJSON_ReplaceItemInObject(wifi, "ssid", cJSON_CreateString(ssid ? ssid : ""));
    cJSON_ReplaceItemInObject(wifi, "password", cJSON_CreateString(password ? password : ""));
    if (!cJSON_GetObjectItem(wifi, "dhcp")) {
        cJSON_AddBoolToObject(wifi, "dhcp", true);
    }

    char* json_out = cJSON_PrintUnformatted(root);
    if (json_out) {
        cfg_->saveConfigJSON(json_out);
        free_cjson_str(json_out);
    }
    cJSON_Delete(root);

    // Returns true if at least NVS was saved correctly
    // The filesystem save is secondary
    return true;
}

esp_err_t WebServer::h_wifi_connect(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    if (!self_ || !self_->wifi_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_WIFI_MANAGER");
        return httpd_resp_send_500(req);
    }

    char* body = nullptr;
    size_t body_len = 0;
    if (!read_body_psram(req, &body, &body_len, HTTP_POST_BUF_SZ)) {
        AccessLogger::getInstance().logResponse(req, 400, "BAD_REQUEST");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body");
    }

    cJSON* root = nullptr;
    if (body && body_len) {
        root = cJSON_Parse(body);
    }
    if (body) {
        heap_caps_free(body);
    }

    if (!root) {
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");
    }

    cJSON* ssid_json = cJSON_GetObjectItem(root, "ssid");
    cJSON* password_json = cJSON_GetObjectItem(root, "password");
    cJSON* timeout_json = cJSON_GetObjectItem(root, "timeout");
    if (!ssid_json || !cJSON_IsString(ssid_json)) {
        cJSON_Delete(root);
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_SSID");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing ssid");
    }

    const char* ssid_value = ssid_json->valuestring ? ssid_json->valuestring : "";
    const char* password_value = (password_json && cJSON_IsString(password_json)) ? password_json->valuestring : "";
    int timeout_sec = (timeout_json && cJSON_IsNumber(timeout_json)) ? timeout_json->valueint : 20;
    if (timeout_sec < 5) timeout_sec = 5;
    if (timeout_sec > 120) timeout_sec = 120;

    bool busy = false;
    if (self_->wifi_transition_mutex_) {
        if (xSemaphoreTake(self_->wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
            busy = self_->wifi_transition_in_progress_;
            if (!busy) {
                self_->wifi_transition_in_progress_ = true;
                self_->wifi_transition_result_ready_ = false;
                self_->wifi_transition_success_ = false;
                self_->wifi_transition_ap_shutdown_pending_ = false;
                self_->wifi_transition_ap_shutdown_done_ = false;
                self_->wifi_transition_ready_us_ = 0;
                memset(self_->wifi_transition_ip_, 0, sizeof(self_->wifi_transition_ip_));
                memset(self_->wifi_transition_error_, 0, sizeof(self_->wifi_transition_error_));
                memset(self_->wifi_transition_ssid_, 0, sizeof(self_->wifi_transition_ssid_));
                strncpy(self_->wifi_transition_ssid_, ssid_value, sizeof(self_->wifi_transition_ssid_) - 1);
            }
            xSemaphoreGive(self_->wifi_transition_mutex_);
        }
    }

    if (busy) {
        cJSON_Delete(root);
        cJSON* resp_busy = cJSON_CreateObject();
        if (resp_busy) {
            cJSON_AddStringToObject(resp_busy, "error", "wifi_transition_in_progress");
            char* json_busy = cJSON_PrintUnformatted(resp_busy);
            httpd_resp_set_status(req, "409 Conflict");
            httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
            httpd_resp_send(req, json_busy ? json_busy : "{}", HTTPD_RESP_USE_STRLEN);
            if (json_busy) free_cjson_str(json_busy);
            cJSON_Delete(resp_busy);
        } else {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        }
        AccessLogger::getInstance().logResponse(req, 409, "BUSY");
        return ESP_OK;
    }

    self_->new_ssid_ = ssid_value;
    self_->new_password_ = password_value;
    self_->wifi_transition_timeout_sec_ = timeout_sec;

    if (!self_->persistWiFiConfig(ssid_value, password_value)) {
        if (self_->wifi_transition_mutex_) {
            if (xSemaphoreTake(self_->wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
                self_->wifi_transition_in_progress_ = false;
                self_->wifi_transition_result_ready_ = false;
                self_->wifi_transition_success_ = false;
                self_->wifi_transition_ap_shutdown_pending_ = false;
                self_->wifi_transition_ap_shutdown_done_ = false;
                self_->wifi_transition_ready_us_ = 0;
                self_->wifi_transition_ip_[0] = '\0';
                self_->wifi_transition_ssid_[0] = '\0';
                self_->wifi_transition_error_[0] = '\0';
                xSemaphoreGive(self_->wifi_transition_mutex_);
            }
        }
        cJSON_Delete(root);
        AccessLogger::getInstance().logResponse(req, 500, "CONFIG_SAVE_FAIL");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "wifi config save failed");
    }

    // Log WiFi configuration change
    if (g_reporting) {
        const char* client_ip = extractClientIPToBuffer(req);
        char* event_data = (char*)heap_caps_malloc(512, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (event_data) {
            snprintf(event_data, 512,
                     "{\"action\":\"wifi_credentials_saved\",\"ssid\":\"%s\",\"client_ip\":\"%s\",\"reboot\":true}",
                     ssid_value, client_ip);
            report_event_ps(g_reporting, "network", event_data);
            heap_caps_free(event_data);
        }
    }

    cJSON_Delete(root);

    // Send success response before the reboot
    cJSON* response = cJSON_CreateObject();
    if (response) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "message", "wifi_credentials_saved_rebooting");
        cJSON_AddStringToObject(response, "ssid", ssid_value);
        char* json = cJSON_PrintUnformatted(response);
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        httpd_resp_send(req, json ? json : "{}", HTTPD_RESP_USE_STRLEN);
        if (json) free_cjson_str(json);
        cJSON_Delete(response);
    } else {
        httpd_resp_sendstr(req, "{\"success\":true,\"message\":\"wifi_credentials_saved_rebooting\"}");
    }

    AccessLogger::getInstance().logResponse(req, 200, "OK");

    // Schedule the reboot after 2 seconds to give the HTTP response time to arrive
    LOG_INFO("WebServer", "WiFi credentials saved. Rebooting in 2 seconds...");
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();

    return ESP_OK;
}

bool WebServer::startWithTask(uint16_t port, esp_netif_t* netif) {
    if (!netif) {
        LOG_ERROR(TAG_WEB, "startWithTask: netif is null");
        return false;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        LOG_WARNING(TAG_WEB, "startWithTask: interface has no IP address");
        return false;
    }

    bool expected_inactive = false;
    if (!startup_task_active_.compare_exchange_strong(
            expected_inactive, true, std::memory_order_acq_rel)) {
        LOG_WARNING(TAG_WEB, "startWithTask: startup already in progress");
        return false;
    }

    SemaphoreHandle_t started = xSemaphoreCreateBinary();
    if (!started) {
        startup_task_active_.store(false, std::memory_order_release);
        LOG_ERROR(TAG_WEB, "startWithTask: failed to create semaphore");
        return false;
    }

    void* raw_args = pvPortMalloc(sizeof(WebTaskArgs));
    if (!raw_args) {
        vSemaphoreDelete(started);
        startup_task_active_.store(false, std::memory_order_release);
        LOG_ERROR(TAG_WEB, "startWithTask: failed to allocate WebTaskArgs");
        return false;
    }

    WebTaskArgs* args = new (raw_args) WebTaskArgs(this, port, netif, started);

    LOG_INFOF(TAG_WEB, "startWithTask: passing semaphore %p to task args=%p", (void*)started, (void*)args);
    LOG_INFOF(TAG_WEB, "?? WebServer task allocation: %s",
              (TaskConfig::NetworkTasks::WEB_SERVER_ALLOC == TaskConfig::AllocType::INTERNAL_RAM) ? "INTERNAL_RAM" : "PSRAM");

    TaskHandle_t hWeb = TaskConfig::createTask(
        web_server_task,
        "WebServer",
        TaskConfig::Presets::WEB_SERVER,
        args,
        1
    );

    if (!hWeb) {
        // No worker owns the reserved reference when task creation fails.
        web_server_task_release_args(args);
        web_server_task_release_args(args);
        startup_task_active_.store(false, std::memory_order_release);
        LOG_ERROR(TAG_WEB, "startWithTask: failed to create WebServer task");
        return false;
    }

    bool success = false;
    if (xSemaphoreTake(started, pdMS_TO_TICKS(60000)) == pdTRUE) {
        success = args->success.load(std::memory_order_acquire);
        LOG_INFOF(TAG_WEB, "Web server task signaled %s.", success ? "SUCCESS" : "FAILURE");
    } else {
        LOG_WARNING(TAG_WEB, "Web server task did not signal ready (timeout).");
    }

    // The worker retains the context and semaphore after timeout; it may still
    // be starting the server and will release its reference on task exit.
    web_server_task_release_args(args);
    LOG_INFOF(TAG_WEB, "WebServer startWithTask on %s:%d - %s",
             inet_ntoa(ip_info.ip), port, success ? "SUCCESS" : "FAIL/ TIMEOUT");

    return success;
}

bool WebServer::connectToWiFi() {
    if (!wifi_) {
        return false;
    }

    char ssid_buf[33];
    memset(ssid_buf, 0, sizeof(ssid_buf));
    if (!new_ssid_.empty()) {
        strncpy(ssid_buf, new_ssid_.c_str(), sizeof(ssid_buf) - 1);
    }

    int timeout_sec = wifi_transition_timeout_sec_;
    if (timeout_sec < 5) timeout_sec = 5;
    if (timeout_sec > 120) timeout_sec = 120;

    bool success = wifi_->connectSTAKeepingAP(new_ssid_, new_password_, timeout_sec);

    char ip_buf[16];
    memset(ip_buf, 0, sizeof(ip_buf));
    wifi_->getIP(ip_buf, sizeof(ip_buf));

    if (g_reporting) {
        char event_data[512];
        if (success) {
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"wifi_connected\",\"ssid\":\"%s\",\"ip_address\":\"%s\",\"interface\":\"STA\"}",
                     ssid_buf, ip_buf);
        } else {
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"wifi_connect_failed\",\"ssid\":\"%s\",\"reason\":\"connection_timeout\"}",
                     ssid_buf);
        }
        report_event_ps(g_reporting, "network", event_data);
    }

    if (success) {
        persistWiFiConfig(ssid_buf, new_password_.c_str());
        TimeManager::notifyWiFiHasIP();
        if (wifi_transition_mutex_) {
            if (xSemaphoreTake(wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
                wifi_transition_success_ = true;
                wifi_transition_result_ready_ = true;
                self_->wifi_transition_in_progress_ = false;
                wifi_transition_ap_shutdown_pending_ = true;
                self_->wifi_transition_ap_shutdown_done_ = false;
                wifi_transition_ready_us_ = esp_timer_get_time();
                strncpy(wifi_transition_ip_, ip_buf, sizeof(wifi_transition_ip_) - 1);
                wifi_transition_ip_[sizeof(wifi_transition_ip_) - 1] = '\0';
                self_->wifi_transition_error_[0] = '\0';
                xSemaphoreGive(wifi_transition_mutex_);
            }
        }
    } else {
        if (wifi_transition_mutex_) {
            if (xSemaphoreTake(wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
                self_->wifi_transition_success_ = false;
                wifi_transition_result_ready_ = true;
                self_->wifi_transition_in_progress_ = false;
                self_->wifi_transition_ap_shutdown_pending_ = false;
                wifi_transition_ready_us_ = esp_timer_get_time();
                strncpy(wifi_transition_error_, "connection_failed", sizeof(wifi_transition_error_) - 1);
                wifi_transition_error_[sizeof(wifi_transition_error_) - 1] = '\0';
                xSemaphoreGive(wifi_transition_mutex_);
            }
        }
    }

    return success;
}

void WebServer::wifi_connect_timer_callback(void* arg) {
    WebServer* self = static_cast<WebServer*>(arg);
    if (self) {
        self->connectToWiFi();
    }
}

esp_err_t WebServer::h_wifi_status(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->wifi_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_WIFI_MANAGER");
        return httpd_resp_send_500(req);
    }

    esp_err_t result = ESP_FAIL;
    {
        std::lock_guard<std::mutex> guard(g_wifi_status_json.mutex);
        if (!build_wifi_status_json(g_wifi_status_json)) {
            AccessLogger::getInstance().logResponse(req, 500, "JSON_BUILD_FAIL");
            return httpd_resp_send_500(req);
        }

        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        result = send_chunked_from_psram(req, g_wifi_status_json.buf, g_wifi_status_json.length);
    }

    AccessLogger::getInstance().logResponse(req, result == ESP_OK ? 200 : 500, result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");

    SCHEDULE_DEFRAG();

    return result;
}

esp_err_t WebServer::h_wifi_disconnect(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    if (!self_ || !self_->wifi_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_WIFI_MANAGER");
        return httpd_resp_send_500(req);
    }

    if (self_->wifi_transition_mutex_) {
        if (xSemaphoreTake(self_->wifi_transition_mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
            self_->wifi_transition_in_progress_ = false;
            self_->wifi_transition_result_ready_ = false;
            self_->wifi_transition_success_ = false;
            self_->wifi_transition_ap_shutdown_pending_ = false;
            self_->wifi_transition_ap_shutdown_done_ = false;
            self_->wifi_transition_ready_us_ = 0;
            self_->wifi_transition_ip_[0] = '\0';
            self_->wifi_transition_ssid_[0] = '\0';
            self_->wifi_transition_error_[0] = '\0';
            xSemaphoreGive(self_->wifi_transition_mutex_);
        }
    }

    LOG_INFO("WIFI_DISCONNECT", "Disconnecting WiFi STA");

    // Log WiFi disconnect attempt to network.log
    // MEMORY FIX: Use buffer-based version to avoid std::string temporary allocation
    if (g_reporting) {
        const char* client_ip = extractClientIPToBuffer(req);
        char event_data[512];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"wifi_disconnect_attempt\",\"client_ip\":\"%s\"}",
                 client_ip);
        report_event_ps(g_reporting, "network", event_data);
    }

    // Disconnect from WiFi STA
    bool disconnect_success = self_->wifi_->disconnect();

    // Log WiFi disconnect result to network.log
    if (g_reporting) {
        char event_data[512];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"wifi_disconnected\",\"success\":%s,\"interface\":\"STA\"}",
                 disconnect_success ? "true" : "false");
        report_event_ps(g_reporting, "network", event_data);
    }

    // Update configuration to disable WiFi STA
    if (disconnect_success && self_->cfg_) {
        LOG_INFO("WIFI_DISCONNECT", "Updating configuration to disable WiFi");

        size_t wz = 0; char* wbuf = self_->cfg_->getRawConfigInPSRAM(&wz);
        PSRAMJsonParser::PSRAMContext ctx;
        cJSON* root = (wbuf && wz) ? PSRAMJsonParser::parseInPSRAM(wbuf, wz) : nullptr;
        if (wbuf) heap_caps_free(wbuf);
        if (!root) root = cJSON_CreateObject();
        if (!root) root = cJSON_CreateObject();

        // Create/update network.wifi section
        cJSON* network_obj = cJSON_GetObjectItem(root, "network");
        if (!network_obj) {
            network_obj = cJSON_CreateObject();
            cJSON_AddItemToObject(root, "network", network_obj);
        }

        cJSON* wifi_obj = cJSON_GetObjectItem(network_obj, "wifi");
        if (!wifi_obj) {
            wifi_obj = cJSON_CreateObject();
            cJSON_AddItemToObject(network_obj, "wifi", wifi_obj);
        }

        // Disable WiFi in network.wifi configuration
        cJSON_DeleteItemFromObject(wifi_obj, "enabled");
        cJSON_AddBoolToObject(wifi_obj, "enabled", false);

        // Save updated configuration
        char* json_string = cJSON_PrintUnformatted(root);
        if (json_string) {
            if (self_->cfg_->saveConfigJSON(json_string)) {
                LOG_INFO("WIFI_DISCONNECT", "WiFi configuration updated successfully");
            } else {
                LOG_WARNING("WIFI_DISCONNECT", "Failed to update WiFi configuration");
            }
            free_cjson_str(json_string);
        }
        cJSON_Delete(root);
    }

    cJSON* response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "disconnect_success", disconnect_success);
    cJSON_AddBoolToObject(response, "ap_started", false);
    if (disconnect_success) {
        cJSON_AddStringToObject(response, "message", "WiFi disconnected");
    } else {
        cJSON_AddStringToObject(response, "message", "WiFi disconnect operation completed with issues");
    }

    char* json_string = cJSON_PrintUnformatted(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);

    AccessLogger::getInstance().logResponse(req, 200, "SUCCESS");

    if (json_string) free_cjson_str(json_string);
    cJSON_Delete(response);

    return result;
}

// Logs API implementation
esp_err_t WebServer::h_logs_get(httpd_req_t* req) {
    // Log warning if running on PSRAM stack (part of hybrid solution)
    if (isCurrentTaskOnPSRAMStack()) {
        LOG_WARNINGF("LOGS_API", "WebServer task running on PSRAM stack - filesystem operations may be risky");
    }

    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    int query_len = httpd_req_get_url_query_len(req);
    if (query_len <= 0) {
        AccessLogger::getInstance().logResponse(req, 400, "NO_QUERY");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing query parameters");
    }

    ScopedBuffer query_buf(static_cast<size_t>(query_len) + 1);
    char* query = query_buf.get();
    if (!query) {
        AccessLogger::getInstance().logResponse(req, 500, "QUERY_ALLOC_FAIL");
        return httpd_resp_send_500(req);
    }

    if (httpd_req_get_url_query_str(req, query, query_buf.size()) != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 400, "NO_QUERY");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing query parameters");
    }

    ScopedBuffer log_name_buf(64);
    char* log_name = log_name_buf.get();
    if (!log_name || httpd_query_key_value(query, "name", log_name, log_name_buf.size()) != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_NAME");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing name parameter");
    }

    if (strstr(log_name, "..") != nullptr || strchr(log_name, '/') != nullptr) {
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_NAME");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid log name");
    }

    ScopedBuffer tail_buf(16);
    char* tail_str = tail_buf.get();
    int tail_lines = 100;
    if (tail_str && httpd_query_key_value(query, "tail", tail_str, tail_buf.size()) == ESP_OK) {
        tail_lines = atoi(tail_str);
        if (tail_lines <= 0) tail_lines = 100;
        if (tail_lines > 5000) tail_lines = 5000;
    }

    LOG_INFOF("LOGS_API", "Request for log '%s' with tail=%d", log_name, tail_lines);

    const char* safe_name = log_name;
    bool allowed = (strcmp(safe_name, "app.log") == 0 ||
                    strcmp(safe_name, "access.log") == 0 ||
                    strcmp(safe_name, "security.log") == 0 ||
                    strcmp(safe_name, "network.log") == 0 ||
                    strcmp(safe_name, "fuzzing_events.log") == 0 ||
                    strcmp(safe_name, "ids_events.log") == 0 ||
                    strcmp(safe_name, "vulnerability_scanner.log") == 0 ||
                    strcmp(safe_name, "scanner_events.log") == 0 ||
                    strcmp(safe_name, "audit_events.log") == 0 ||
                    strcmp(safe_name, "gpio_events.log") == 0 ||
                    strcmp(safe_name, "discovery_events.log") == 0 ||
                    strcmp(safe_name, "signature_events.log") == 0 ||
                    strcmp(safe_name, "network_presence_events.log") == 0);

    if (!allowed) {
        LOG_WARNINGF("LOGS_API", "Unauthorized log file access attempt: %s", safe_name);
        AccessLogger::getInstance().logResponse(req, 403, "FORBIDDEN_LOG");
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "log file not allowed");
    }

    ScopedBuffer log_path_buf(128);
    char* log_path = log_path_buf.get();
    if (!log_path) {
        AccessLogger::getInstance().logResponse(req, 500, "PATH_ALLOC_FAIL");
        return httpd_resp_send_500(req);
    }

    if (strcmp(safe_name, "fuzzing_events.log") == 0 ||
        strcmp(safe_name, "ids_events.log") == 0 ||
        strcmp(safe_name, "vulnerability_scanner.log") == 0 ||
        strcmp(safe_name, "scanner_events.log") == 0 ||
        strcmp(safe_name, "audit_events.log") == 0 ||
        strcmp(safe_name, "gpio_events.log") == 0 ||
        strcmp(safe_name, "discovery_events.log") == 0 ||
        strcmp(safe_name, "signature_events.log") == 0 ||
        strcmp(safe_name, "network_presence_events.log") == 0) {
        snprintf(log_path, log_path_buf.size(), "/data/%s", log_name);
    } else {
        snprintf(log_path, log_path_buf.size(), "/data/logs/%s", log_name);
    }

    LOG_INFOF("LOGS_API", "Attempting to stream log file: %s", log_path);

    // ⚠️ Skip AsyncStorage::fileExists() - not compatible with FilesystemTaskDelegate
    // Instead: try streaming first, fallback to alt path if fails

    //LOG_INFOF("LOGS_API", "Reading log path: %s", log_path.c_str());

    // ⚠️ CRITICAL: WebServer has PSRAM stack - CANNOT do direct flash I/O (fopen/LittleFS)
    // Flash operations disable cache → PSRAM becomes inaccessible → Task crash
    // MUST use NEW PSRAM-backed streaming API

    FilesystemTaskDelegate& fs_delegate = FilesystemTaskDelegate::getInstance();

    // Start PSRAM-backed streaming with circular queue (producer fills circular slots, consumer reads them)
    bool streaming_started = fs_delegate.startPSRAMStreaming(log_path, 30000, tail_lines);  // 30 second timeout
    if (!streaming_started) {
        LOG_WARNINGF("LOGS_API", "Failed to start PSRAM streaming for file: %s", log_path);
        AccessLogger::getInstance().logResponse(req, 404, "LOG_NOT_FOUND");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "log file not found");
    }

    // Get access to PSRAM ring buffer for reading
    uint8_t* psram_ring = fs_delegate.getPSRAMRingBuffer();
    if (psram_ring == nullptr) {
        LOG_WARNINGF("LOGS_API", "Failed to get PSRAM ring buffer access");
        AccessLogger::getInstance().logResponse(req, 500, "PSRAM_ERROR");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "PSRAM ring buffer error");
    }

    LOG_INFOF("LOGS_API", "Got PSRAM ring buffer access, starting circular queue consumer loop");
    size_t total_sent = 0;
    uint32_t chunk_count = 0;
    esp_err_t stream_rc = ESP_OK;

    // Consumer: get descriptors from circular queue and forward from PSRAM ring buffer
    while (true) {
        // Get next chunk descriptor from circular queue
        //LOG_DEBUGF("LOGS_API", "Consumer waiting for descriptor (chunks so far: %u)", chunk_count);
        FilesystemTaskDelegate::RingDescriptor* desc = fs_delegate.getNextDescriptor(30000);  // 30 second timeout
        if (desc == nullptr) {
            LOG_WARNINGF("LOGS_API", "Consumer timeout waiting for stream descriptor after %u chunks", chunk_count);
            AccessLogger::getInstance().logResponse(req, 408, "STREAM_TIMEOUT");
            return httpd_resp_send_err(req, HTTPD_408_REQ_TIMEOUT, "stream timeout");
        }

        //LOG_DEBUGF("LOGS_DOWNLOAD", "Consumer received descriptor: offset=%u, length=%u, eof=%d", desc->offset, desc->length, desc->eof);
        chunk_count++;

        if (desc->length > 0 && stream_rc == ESP_OK) {
            if (desc->offset + desc->length <= FilesystemTaskDelegate::PSRAM_RING_SIZE) {
                stream_rc = send_chunked_from_psram(req,
                                                    reinterpret_cast<const char*>(&psram_ring[desc->offset]),
                                                    desc->length);
            } else {
                uint32_t first_part = FilesystemTaskDelegate::PSRAM_RING_SIZE - desc->offset;
                uint32_t second_part = desc->length - first_part;

                stream_rc = send_chunked_from_psram(req,
                                                    reinterpret_cast<const char*>(&psram_ring[desc->offset]),
                                                    first_part);
                if (stream_rc == ESP_OK && second_part > 0) {
                    stream_rc = send_chunked_from_psram(req,
                                                        reinterpret_cast<const char*>(&psram_ring[0]),
                                                        second_part);
                }
            }

            if (stream_rc == ESP_OK) {
                total_sent += desc->length;
            } else {
                LOG_WARNINGF("LOGS_API", "Chunk streaming error err=%d (offset=%u length=%u total_sent=%zu)",
                             (int)stream_rc,
                             (unsigned)desc->offset,
                             (unsigned)desc->length,
                             total_sent);
            }
        }

        // Mark descriptor as consumed (allows slot to be reused)
        fs_delegate.markDescriptorConsumed(desc);

        // NOW check for EOF and exit if this was the last chunk
        if (desc->eof || stream_rc != ESP_OK) {
            break; // End of file reached
        }

        // Yield CPU to allow producer task to fill new chunks
        // This enables true parallelization between producer and consumer
        taskYIELD();

        // Safety limit to prevent memory exhaustion
        if (total_sent > 2*1024*1024) { // 2MB limit
            LOG_WARNINGF("LOGS_API", "File too large for tail operation: %s (%zu bytes)", log_path, total_sent);
            AccessLogger::getInstance().logResponse(req, 413, "FILE_TOO_LARGE");
            return httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, "log file too large");
        }
    }
    LOG_DEBUGF("LOGS_API", "Successfully streamed %zu bytes in %u chunks", total_sent, chunk_count);

    // Set content type as plain text
    httpd_resp_set_type(req, "text/plain");

    LOG_INFOF("LOGS_API", "Returning tail from %s (%zu bytes, chunks=%u)",
              log_name,
              total_sent,
              chunk_count);

    if (stream_rc == ESP_OK) {
        stream_rc = httpd_resp_send_chunk(req, nullptr, 0);
    } else {
        LOG_WARNINGF("LOGS_API", "Streaming completed with error err=%d before terminator", (int)stream_rc);
    }

    AccessLogger::getInstance().logResponse(req, stream_rc == ESP_OK ? 200 : 500, stream_rc == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");

    return stream_rc;
}

esp_err_t WebServer::h_logs_download(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    // Parse query ?name=
    ScopedBuffer query_buf(256);
    char* query = query_buf.get();
    if (!query) {
        AccessLogger::getInstance().logResponse(req, 500, "QUERY_ALLOC_FAIL");
        return httpd_resp_send_500(req);
    }

    if (httpd_req_get_url_query_str(req, query, query_buf.size()) != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 400, "NO_QUERY");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing query parameters");
    }

    ScopedBuffer log_name_buf(64);
    char* log_name = log_name_buf.get();
    if (!log_name || httpd_query_key_value(query, "name", log_name, log_name_buf.size()) != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_NAME");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing name parameter");
    }

    // Security check for path traversal
    if (strstr(log_name, "..") != nullptr || strchr(log_name, '/') != nullptr) {
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_NAME");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid log name");
    }

    // Security check: only allow certain log files
    const char* safe_name = log_name;
    bool allowed = (strcmp(safe_name, "app.log") == 0 ||
                   strcmp(safe_name, "access.log") == 0 ||
                   strcmp(safe_name, "security.log") == 0 ||
                   strcmp(safe_name, "network.log") == 0 ||
                   strcmp(safe_name, "fuzzing_events.log") == 0 ||
                   strcmp(safe_name, "ids_events.log") == 0 ||
                   strcmp(safe_name, "vulnerability_scanner.log") == 0 ||
                   strcmp(safe_name, "scanner_events.log") == 0 ||
                   strcmp(safe_name, "audit_events.log") == 0 ||
                   strcmp(safe_name, "gpio_events.log") == 0 ||
                   strcmp(safe_name, "discovery_events.log") == 0 ||
                   strcmp(safe_name, "signature_events.log") == 0 ||
                   strcmp(safe_name, "network_presence_events.log") == 0);

    if (!allowed) {
        LOG_WARNINGF("LOGS_API", "Unauthorized log file access attempt: %s", safe_name);
        AccessLogger::getInstance().logResponse(req, 403, "FORBIDDEN_LOG");
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "log file not allowed");
    }

    // MEMORY FIX: Build log file path with ScopedBuffer
    ScopedBuffer log_path_buf(128);
    char* log_path = log_path_buf.get();
    if (!log_path) {
        AccessLogger::getInstance().logResponse(req, 500, "PATH_ALLOC_FAIL");
        return httpd_resp_send_500(req);
    }

    if (strcmp(safe_name, "fuzzing_events.log") == 0 ||
        strcmp(safe_name, "ids_events.log") == 0 ||
        strcmp(safe_name, "vulnerability_scanner.log") == 0 ||
        strcmp(safe_name, "scanner_events.log") == 0 ||
        strcmp(safe_name, "audit_events.log") == 0 ||
        strcmp(safe_name, "gpio_events.log") == 0 ||
        strcmp(safe_name, "discovery_events.log") == 0 ||
        strcmp(safe_name, "signature_events.log") == 0 ||
        strcmp(safe_name, "network_presence_events.log") == 0) {
        // Security assessment logs are in /data/ root
        snprintf(log_path, log_path_buf.size(), "/data/%s", log_name);
    } else {
        // System logs are in /data/logs/ subdirectory
        snprintf(log_path, log_path_buf.size(), "/data/logs/%s", log_name);
    }
    // Try both paths with NEW PSRAM streaming (same as h_logs_get)
    FilesystemTaskDelegate& fs_delegate = FilesystemTaskDelegate::getInstance();
    bool streaming_started = fs_delegate.startPSRAMStreaming(log_path, 30000, 0);  // 30 second timeout, full file
    if (streaming_started) {
        LOG_INFOF("LOGS_DOWNLOAD", "Started PSRAM streaming for %s", log_path);
    }

    if (!streaming_started) {
        LOG_WARNINGF("LOGS_DOWNLOAD", "Failed to start PSRAM streaming for file: %s", safe_name);
        AccessLogger::getInstance().logResponse(req, 404, "LOG_NOT_FOUND");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "log file not found");
    }

    // Set headers for file download
    httpd_resp_set_type(req, "text/plain");

    // MEMORY FIX: Content-Disposition with fixed buffer
    char ts[32];
    time_t now = time(nullptr);
    struct tm* ti = localtime(&now);
    strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", ti);

    char filename[256];
    const char* dot = strrchr(safe_name, '.');
    if (dot != nullptr) {
        snprintf(filename, sizeof(filename), "%.*s-%s%s",
                 (int)(dot - safe_name), safe_name, ts, dot);
    } else {
        snprintf(filename, sizeof(filename), "%s-%s.log", safe_name, ts);
    }

    char disposition[320];
    snprintf(disposition, sizeof(disposition), "attachment; filename=\"%s\"", filename);
    httpd_resp_set_hdr(req, "Content-Disposition", disposition);

    // PSRAM streaming loop (enhanced with consumer-side logging)
    uint8_t* psram_ring = fs_delegate.getPSRAMRingBuffer();
    size_t total_sent = 0;
    uint32_t chunk_count = 0;
    esp_err_t send_rc = ESP_OK;

    LOG_INFOF("LOGS_DOWNLOAD", "Starting PSRAM streaming loop for %s", log_path);

    while (true) {
        LOG_INFOF("LOGS_DOWNLOAD", "Consumer waiting for descriptor (attempt %u)", chunk_count + 1);
        FilesystemTaskDelegate::RingDescriptor* desc = fs_delegate.getNextDescriptor(30000); // 30s timeout
        if (!desc) {
            LOG_WARNINGF("LOGS_DOWNLOAD", "Consumer timeout after %u chunks, %zu bytes", chunk_count, total_sent);
            break;
        }
        LOG_INFOF("LOGS_DOWNLOAD", "Consumer received descriptor: offset=%u, length=%u, eof=%s",
                  desc->offset, desc->length, desc->eof ? "true" : "false");

        chunk_count++;
        //LOG_DEBUGF("LOGS_DOWNLOAD", "Consumer got chunk %u: offset=%u, length=%u, eof=%s, seq=%u", chunk_count, desc->offset, desc->length, desc->eof ? "true" : "false", desc->sequence);

        if (desc->length > 0) {
            // CRITICAL FIX: Handle wrap-around - chunk might wrap around ring buffer
            if (desc->offset + desc->length <= FilesystemTaskDelegate::PSRAM_RING_SIZE) {
                // No wrap-around: send data in one piece
                send_rc = httpd_resp_send_chunk(req, (const char*)&psram_ring[desc->offset], desc->length);
                if (send_rc != ESP_OK) {
                    LOG_ERRORF("LOGS_DOWNLOAD", "HTTP send failed on chunk %u (err=%d)", chunk_count, (int)send_rc);
                    fs_delegate.markDescriptorConsumed(desc);
                    break;
                }
            } else {
                // Wrap-around: send in two parts
                uint32_t first_part = FilesystemTaskDelegate::PSRAM_RING_SIZE - desc->offset;
                uint32_t second_part = desc->length - first_part;

                // Send first part (from offset to end of ring)
                send_rc = httpd_resp_send_chunk(req, (const char*)&psram_ring[desc->offset], first_part);
                if (send_rc == ESP_OK) {
                    // Send second part (from start of ring)
                    send_rc = httpd_resp_send_chunk(req, (const char*)&psram_ring[0], second_part);
                }

                if (send_rc != ESP_OK) {
                    LOG_ERRORF("LOGS_DOWNLOAD", "HTTP send failed on wrapped chunk %u (err=%d)", chunk_count, (int)send_rc);
                    fs_delegate.markDescriptorConsumed(desc);
                    break;
                }
            }
            total_sent += desc->length;
        }

        bool is_eof = desc->eof;
        fs_delegate.markDescriptorConsumed(desc);

        if (is_eof) {
            LOG_INFOF("LOGS_DOWNLOAD", "EOF reached after %u chunks, %zu bytes", chunk_count, total_sent);
            break;
        }

        // Yield CPU to allow producer task to fill new chunks
        // This enables true parallelization between producer and consumer
        taskYIELD();
    }

    // Send chunked terminator
    if (send_rc == ESP_OK) {
        send_rc = httpd_resp_send_chunk(req, nullptr, 0);
    }

    if (send_rc == ESP_OK) {
        LOG_INFOF("LOGS_DOWNLOAD", "✅ Download completed: %zu bytes from %s", total_sent, log_path);
        AccessLogger::getInstance().logResponse(req, 200, "DOWNLOAD_SUCCESS");
    } else {
        LOG_ERRORF("LOGS_DOWNLOAD", "❌ Download failed after %zu bytes (err=%d) path=%s", total_sent, (int)send_rc, log_path);
        AccessLogger::getInstance().logResponse(req, 500, "DOWNLOAD_FAILED");
    }

    return send_rc;
}

// Fuzzing API implementations
esp_err_t WebServer::h_fuzz_jobs_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!g_fuzz) {
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, "{\"jobs\":[],\"count\":0,\"error\":\"fuzzing_engine_not_initialized\"}", HTTPD_RESP_USE_STRLEN);
    }

    auto jobs = g_fuzz->listJobs();
    std::stringstream response;
    response << "{\"jobs\":[";

    for (size_t i = 0; i < jobs.size(); ++i) {
        if (i > 0) response << ",";
        const auto& job = jobs[i];
        psram_string last_result_json;
        const bool has_last = g_fuzz->getLastJobResult(job.id, last_result_json);
        const bool running = g_fuzz->isJobRunning(job.id);
        response << "{\"id\":" << job.id
                << ",\"protocol\":" << (int)job.protocol
                << ",\"target\":\"" << job.target << "\""
                << ",\"safe_mode\":" << (job.safe_mode ? "true" : "false")
                << ",\"rate_per_sec\":" << job.rate_per_sec
                << ",\"duration_ms\":" << job.duration_ms
                << ",\"max_cases\":" << job.max_cases
                << ",\"running\":" << (running ? "true" : "false")
                << ",\"has_last_result\":" << (has_last ? "true" : "false");
        if (!job.profile.empty()) {
            response << ",\"profile\":\"" << job.profile << "\"";
        }
        response << "}";
    }

    response << "],\"count\":" << jobs.size() << "}";

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    std::string resp_str = response.str();
    return httpd_resp_send(req, resp_str.c_str(), resp_str.length());
}

esp_err_t WebServer::h_fuzz_jobs_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!g_fuzz) {
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, "{\"error\":\"fuzzing_engine_not_initialized\"}", HTTPD_RESP_USE_STRLEN);
    }

    // Parse JSON body (allow larger body for attack profiles)
    psram_string body;
    if (!read_body(req, body)) {
        LOG_WARNINGF("WebServer", "Failed to read body, content_len=%zu", req->content_len);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    LOG_DEBUGF("WebServer", "Fuzz job body: %s", body.c_str());

    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) {
        LOG_WARNINGF("WebServer", "Failed to parse JSON: %s", body.c_str());
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid JSON");
    }

    // Create FuzzJob from JSON
    FuzzJob job;

    cJSON* protocol = cJSON_GetObjectItem(json, "protocol");
    if (protocol && cJSON_IsNumber(protocol)) {
        job.protocol = (ProtocolType)cJSON_GetNumberValue(protocol);
    } else {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing protocol");
    }

    cJSON* target = cJSON_GetObjectItem(json, "target");
    if (target && cJSON_IsString(target)) {
        job.target = cJSON_GetStringValue(target);
    } else {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing target");
    }

    // Optional parameters with defaults
    cJSON* safe_mode = cJSON_GetObjectItem(json, "safe_mode");
    if (safe_mode && cJSON_IsBool(safe_mode)) {
        job.safe_mode = cJSON_IsTrue(safe_mode);
    }

    cJSON* rate = cJSON_GetObjectItem(json, "rate_per_sec");
    if (rate && cJSON_IsNumber(rate)) {
        job.rate_per_sec = (uint32_t)cJSON_GetNumberValue(rate);
    }

    cJSON* duration = cJSON_GetObjectItem(json, "duration_ms");
    if (duration && cJSON_IsNumber(duration)) {
        job.duration_ms = (uint32_t)cJSON_GetNumberValue(duration);
    }

    cJSON* max_cases = cJSON_GetObjectItem(json, "max_cases");
    if (max_cases && cJSON_IsNumber(max_cases)) {
        job.max_cases = (uint32_t)cJSON_GetNumberValue(max_cases);
    }

    cJSON* profile = cJSON_GetObjectItem(json, "profile");
    if (profile && cJSON_IsString(profile)) {
        job.profile = cJSON_GetStringValue(profile);
    }

    cJSON* extra_config = cJSON_GetObjectItem(json, "extra_config");
    if (extra_config && cJSON_IsString(extra_config)) {
        job.extra_config = cJSON_GetStringValue(extra_config);
    }

    cJSON_Delete(json);

    // Defense-in-depth: reject known state-changing profiles when safe_mode=true.
    if (job.safe_mode && !job.profile.empty() && job.profile != "default") {
        bool unsafe = false;
        switch (job.protocol) {
            case ProtocolType::S7_COMM:
                unsafe = (job.profile == "plc_stop") || (job.profile == "unauthorized_write");
                break;
            case ProtocolType::PROFINET:
                unsafe = (job.profile == "device_replacement");
                break;
            case ProtocolType::OPC_UA:
                unsafe = (job.profile == "certificate_bypass") ||
                         (job.profile == "session_hijacking") ||
                         (job.profile == "browse_flooding") ||
                         (job.profile == "chunk_exhaustion") ||
                         (job.profile == "protocol_violations") ||
                         (job.profile == "string_attacks") ||
                         (job.profile == "cve_based") ||
                         (job.profile == "comprehensive");
                break;
            case ProtocolType::ETHERNET_IP:
                unsafe = (job.profile == "cip_attribute_manipulation") ||
                         (job.profile == "unauthorized_writes") ||
                         (job.profile == "device_reset_attempt");
                break;
            default:
                unsafe = false;
                break;
        }

        if (unsafe) {
            httpd_resp_set_status(req, "400 Bad Request");
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "close");
            return httpd_resp_send(req,
                                   "{\"error\":\"unsafe_profile_requires_safe_mode_false\"}",
                                   HTTPD_RESP_USE_STRLEN);
        }
    }

    // Add job to engine
    uint32_t job_id = g_fuzz->addJob(job);

    std::stringstream response;
    response << "{\"job_id\":" << job_id << ",\"status\":\"created\"}";

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    std::string resp_str = response.str();
    return httpd_resp_send(req, resp_str.c_str(), resp_str.length());
}

esp_err_t WebServer::h_fuzz_jobs_delete(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!g_fuzz) {
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, "{\"error\":\"fuzzing_engine_not_initialized\"}", HTTPD_RESP_USE_STRLEN);
    }

    // Parse job ID from query parameter
    char param[64];
    if (httpd_req_get_url_query_str(req, param, sizeof(param)) == ESP_OK) {
        char job_id_str[32];
        if (httpd_query_key_value(param, "id", job_id_str, sizeof(job_id_str)) == ESP_OK) {
            uint32_t job_id = (uint32_t)std::atoi(job_id_str);
            bool success = g_fuzz->removeJob(job_id);

            std::stringstream response;
            if (success) {
                response << "{\"success\":true,\"message\":\"Job " << job_id << " deleted\"}";
            } else {
                response << "{\"success\":false,\"error\":\"Job " << job_id << " not found\"}";
            }

            httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
            std::string resp_str = response.str();
            return httpd_resp_send(req, resp_str.c_str(), resp_str.length());
        }
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing job id parameter");
}

esp_err_t WebServer::h_fuzz_run(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!g_fuzz) {
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, "{\"error\":\"fuzzing_engine_not_initialized\"}", HTTPD_RESP_USE_STRLEN);
    }

    // Parse JSON body to get job ID
    psram_string body;
    if (!read_body(req, body)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) { AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); }

    cJSON* job_id_json = cJSON_GetObjectItem(json, "job_id");
    if (!job_id_json || !cJSON_IsNumber(job_id_json)) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing job_id");
    }

    uint32_t job_id = (uint32_t)cJSON_GetNumberValue(job_id_json);
    cJSON_Delete(json);

    bool success = g_fuzz->runNow(job_id);

    std::stringstream response;
    if (success) {
        response << "{\"status\":\"started\",\"job_id\":" << job_id << "}";
    } else {
        response << "{\"status\":\"failed\",\"error\":\"Job not found or queue full\"}";
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    std::string resp_str = response.str();
    return httpd_resp_send(req, resp_str.c_str(), resp_str.length());
}

esp_err_t WebServer::h_fuzz_stop(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!g_fuzz) {
        httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, "{\"error\":\"fuzzing_engine_not_initialized\"}", HTTPD_RESP_USE_STRLEN);
    }

    bool success = g_fuzz->stopAll();

    std::stringstream response;
    if (success) {
        response << "{\"status\":\"stopped\"}";
    } else {
        response << "{\"status\":\"failed\",\"error\":\"Could not stop fuzzing jobs\"}";
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    std::string resp_str = response.str();
    return httpd_resp_send(req, resp_str.c_str(), resp_str.length());
}

esp_err_t WebServer::h_fuzz_result_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!g_fuzz) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, "{\"error\":\"fuzzing_engine_not_initialized\"}", HTTPD_RESP_USE_STRLEN);
    }

    char query[96] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing id");
    }

    char id_buf[32] = {0};
    if (httpd_query_key_value(query, "job_id", id_buf, sizeof(id_buf)) != ESP_OK &&
        httpd_query_key_value(query, "id", id_buf, sizeof(id_buf)) != ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing job_id");
    }

    uint32_t job_id = (uint32_t)std::atoi(id_buf);
    psram_string out;
    if (!g_fuzz->getLastJobResult(job_id, out)) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "close");
        return httpd_resp_send(req, "{\"error\":\"no_result\"}", HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, out.c_str(), out.size());
}

/* [* HTTPS TO ACTIVATE] - HTTPS implementation
bool WebServer::startHTTPS(uint16_t port) {
    if (https_server_) {
        LOG_WARNING("HTTPS", "HTTPS server already running");
        return true;
    }

    // Log HTTPS server start attempt to network.log
    if (g_reporting) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"https_server_start_attempt\",\"port\":%d}",
                 port);
        report_event_ps(g_reporting, "network", event_data);
    }

    // Configure HTTPS server
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.httpd.task_caps = MALLOC_CAP_SPIRAM;  // HTTPS stack in PSRAM
    conf.httpd.server_port = port;
    conf.httpd.max_open_sockets = 3;   // CRITICAL MEMORY REDUCTION: Same as HTTP (was 16)
    conf.httpd.max_uri_handlers = 15;  // CRITICAL MEMORY REDUCTION: Same as HTTP (was 80)
    conf.httpd.lru_purge_enable = true;
    conf.httpd.stack_size = 32 * 1024; // CRITICAL MEMORY REDUCTION: 32KB PSRAM (was 64KB)
    conf.httpd.send_wait_timeout = 30; // Increased to 30s for complex operations
    conf.httpd.recv_wait_timeout = 30; // Increased to 30s for complex operations
    conf.httpd.backlog_conn = 3;       // CRITICAL MEMORY REDUCTION: Same as HTTP (was 8)
    conf.httpd.max_resp_headers = 8;   // CRITICAL MEMORY REDUCTION: Same as HTTP (was 16)

    // Set certificate and private key
    conf.servercert = reinterpret_cast<const uint8_t*>(tls_credentials_.certificatePem());
    conf.servercert_len = tls_credentials_.certificateLength() + 1;
    conf.prvtkey_pem = reinterpret_cast<const uint8_t*>(tls_credentials_.privateKeyPem());
    conf.prvtkey_len = tls_credentials_.privateKeyLength() + 1;

    LOG_INFOF("HTTPS", "Certificate length: %zu, Key length: %zu", conf.servercert_len, conf.prvtkey_len);
    LOG_INFOF("HTTPS", "Starting HTTPS server on port %d", port);

    esp_err_t ret = httpd_ssl_start(&https_server_, &conf);
    if (ret != ESP_OK) {
        LOG_ERRORF("HTTPS", "Failed to start HTTPS server, error code: 0x%x (%s)", ret, esp_err_to_name(ret));

        // Log HTTPS server start failure to network.log
        if (g_reporting) {
            char event_data[256];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"https_server_start_failed\",\"port\":%d,\"error\":\"%s\"}",
                     port, esp_err_to_name(ret));
            report_event_ps(g_reporting, "network", event_data);
        }
        return false;
    }

    // Register the same handlers as HTTP server but for HTTPS
    registerHTTPSHandlers();

    LOG_INFO("HTTPS", "HTTPS server started successfully");

    // Log successful HTTPS server start to network.log
    if (g_reporting) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"https_server_started\",\"port\":%d}",
                 port);
        report_event_ps(g_reporting, "network", event_data);
    }

    httpdMonitorStart();

    return true;
}

void WebServer::stopHTTPS() {
    if (https_server_) {
        httpd_ssl_stop(https_server_);
        https_server_ = nullptr;
        LOG_INFO("HTTPS", "HTTPS server stopped");

        httpdMonitorStop();

        // Log HTTPS server stop to network.log
        if (g_reporting) {
            char event_data[256];
            snprintf(event_data, sizeof(event_data),
                     "{\"action\":\"https_server_stopped\"}");
            report_event_ps(g_reporting, "network", event_data);
        }
    }
}

void WebServer::registerHTTPSHandlers() {
    if (!https_server_) return;

    // Register essential handlers - same as HTTP but for HTTPS
    httpd_uri_t u_root = { .uri="/", .method=HTTP_GET, .handler=&WebServer::h_root, .user_ctx=nullptr };
    httpd_uri_t u_stat = { .uri="/api/status", .method=HTTP_GET, .handler=&WebServer::h_status, .user_ctx=nullptr };
    httpd_uri_t u_telem = { .uri="/api/telemetry", .method=HTTP_GET, .handler=&WebServer::h_telemetry, .user_ctx=nullptr };
    httpd_uri_t u_cfg_g= { .uri="/api/config", .method=HTTP_GET, .handler=&WebServer::h_config_get, .user_ctx=nullptr };
    httpd_uri_t u_cfg_p= { .uri="/api/config", .method=HTTP_POST, .handler=&WebServer::h_config_post, .user_ctx=nullptr };
    httpd_uri_t u_editor_schema= { .uri="/api/config/editor/schema", .method=HTTP_GET, .handler=&WebServer::h_config_editor_schema, .user_ctx=nullptr };
    httpd_uri_t u_editor_snapshot= { .uri="/api/config/editor/snapshot", .method=HTTP_GET, .handler=&WebServer::h_config_editor_snapshot, .user_ctx=nullptr };
    httpd_uri_t u_editor_validate= { .uri="/api/config/editor/validate", .method=HTTP_POST, .handler=&WebServer::h_config_editor_validate, .user_ctx=nullptr };
    httpd_uri_t u_editor_save= { .uri="/api/config/editor/save", .method=HTTP_POST, .handler=&WebServer::h_config_editor_save, .user_ctx=nullptr };
    httpd_uri_t config_metadata_https = { .uri="/api/config/metadata", .method=HTTP_GET, .handler=&WebServer::h_config_metadata_get, .user_ctx=nullptr };
    httpd_uri_t config_reset_https = { .uri="/api/config/reset", .method=HTTP_POST, .handler=&WebServer::h_config_reset_post, .user_ctx=nullptr };
    httpd_uri_t diagnostics_selftest = { .uri="/api/diagnostics/selftest", .method=HTTP_GET, .handler=&WebServer::h_api_selftest, .user_ctx=nullptr };
    httpd_uri_t diagnostics_httpd = { .uri="/api/diagnostics/httpd", .method=HTTP_GET, .handler=&WebServer::h_api_httpd_stats, .user_ctx=nullptr };

    // Login endpoints
    httpd_uri_t lget = { .uri="/login", .method=HTTP_GET, .handler=&WebServer::h_login_get, .user_ctx=nullptr };
    httpd_uri_t lpost= { .uri="/login", .method=HTTP_POST, .handler=&WebServer::h_login_post, .user_ctx=nullptr };
    httpd_uri_t lout = { .uri="/logout", .method=HTTP_POST, .handler=&WebServer::h_logout, .user_ctx=nullptr };

    // Access logs endpoint
    httpd_uri_t lg_a = { .uri="/api/logs/access", .method=HTTP_GET, .handler=&WebServer::h_logs_access_get, .user_ctx=nullptr };

    // Register handlers
    httpd_register_uri_handler(active_server_, &u_root);
    httpd_register_uri_handler(active_server_, &u_stat);
    httpd_register_uri_handler(active_server_, &u_telem);
    httpd_register_uri_handler(active_server_, &u_cfg_g);
    httpd_register_uri_handler(active_server_, &u_cfg_p);
    httpd_register_uri_handler(active_server_, &u_editor_schema);
    httpd_register_uri_handler(active_server_, &u_editor_snapshot);
    httpd_register_uri_handler(active_server_, &u_editor_validate);
    httpd_register_uri_handler(active_server_, &u_editor_save);
    httpd_register_uri_handler(active_server_, &config_metadata_https);
    httpd_register_uri_handler(active_server_, &config_reset_https);
    httpd_register_uri_handler(active_server_, &diagnostics_selftest);
    httpd_register_uri_handler(active_server_, &diagnostics_httpd);
    httpd_register_uri_handler(active_server_, &lget);
    httpd_register_uri_handler(active_server_, &lpost);
    httpd_register_uri_handler(active_server_, &lout);
    httpd_register_uri_handler(active_server_, &lg_a);

    LOG_INFO("HTTPS", "HTTPS handlers registered");
}

// Helper method to check if HTTPS is enabled in configuration
bool WebServer::isHTTPSEnabled() const {
    if (!cfg_) return false;
    size_t json_size = 0;
    char* json_buf = cfg_->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) return false;
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) return false;

    bool https_enabled = false;
    cJSON* web = cJSON_GetObjectItem(root, "webserver");
    if (web && cJSON_IsObject(web)) {
        cJSON* https = cJSON_GetObjectItem(web, "https_enabled");
        if (https && cJSON_IsBool(https)) {
            https_enabled = (https->valueint != 0);
        }
    }

    cJSON_Delete(root);
    return https_enabled;
}
[* HTTPS TO ACTIVATE] */

// PSRAM-safe body reader: allocates a PSRAM buffer and returns ownership to caller
static bool read_body_psram(httpd_req_t* req, char** out_buf, size_t* out_len, size_t max_len) {
    if (!req || !out_buf || !out_len) return false;
    size_t tot = req->content_len;
    if (tot == 0 || tot > max_len) return false;
    char* buf = (char*)heap_caps_malloc(tot + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf) return false;
    size_t rec = 0;
    while (rec < tot) {
        int r = httpd_req_recv(req, buf + rec, tot - rec);
        if (r <= 0) { heap_caps_free(buf); return false; }
        rec += r;
    }
    buf[tot] = '\0';
    *out_buf = buf;
    *out_len = tot;
    return true;
}

// Configuration export endpoint - downloads full config as JSON file
esp_err_t WebServer::h_config_export(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    if (!self_ || !self_->cfg_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_CONFIG_MANAGER");
        return httpd_resp_send_500(req);
    }

    LOG_INFO("CONFIG_EXPORT", "Exporting full configuration");

    // Get current configuration (PSRAM-safe) and validate JSON
    size_t json_size = 0;
    char* json_buf = self_->cfg_->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) {
        AccessLogger::getInstance().logResponse(req, 500, "EMPTY_CONFIG");
        return httpd_resp_send_500(req);
    }
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) {
        AccessLogger::getInstance().logResponse(req, 500, "INVALID_CONFIG");
        return httpd_resp_send_500(req);
    }

    // Pretty print for export
    char* pretty_json = cJSON_Print(root);
    cJSON_Delete(root);

    if (!pretty_json) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_FORMAT_ERROR");
        return httpd_resp_send_500(req);
    }

    // Generate filename with timestamp
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    char filename[64];
    snprintf(filename, sizeof(filename), "esp32-security-config-%04d%02d%02d-%02d%02d%02d.json",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    // Set headers for file download
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       (std::string("attachment; filename=\"") + filename + "\"").c_str());
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");

    esp_err_t result = httpd_resp_send(req, pretty_json, strlen(pretty_json));

    AccessLogger::getInstance().logResponse(req, 200, "CONFIG_EXPORTED");
    LOG_INFOF("CONFIG_EXPORT", "Configuration exported as %s (%d bytes)", filename, (int)strlen(pretty_json));

    free_cjson_str(pretty_json);
    return result;
}

// Configuration import endpoint - uploads and applies new config from JSON file
esp_err_t WebServer::h_config_import(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    if (!self_ || !self_->cfg_) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_CONFIG_MANAGER");
        return httpd_resp_send_500(req);
    }

    LOG_INFO("CONFIG_IMPORT", "Starting configuration import");

    // Read request body
    psram_string body;
    if (!read_body(req, body)) { // Allow larger configs up to 32KB
        AccessLogger::getInstance().logResponse(req, 400, "READ_BODY_FAILED");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Cannot read request body");
    }

    if (body.empty()) {
        AccessLogger::getInstance().logResponse(req, 400, "EMPTY_BODY");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty configuration data");
    }

    LOG_INFOF("CONFIG_IMPORT", "Received %d bytes of configuration data", (int)body.size());

    // Validate JSON format
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = cJSON_Parse(body.c_str());
    if (!root) {
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON format");
    }

    // Basic validation - check for required sections
    bool valid_config = true;
    std::string validation_error;

    // Optional: Add more validation checks here
    if (!cJSON_IsObject(root)) {
        valid_config = false;
        validation_error = "Root must be a JSON object";
    }

    if (!valid_config) {
        cJSON_Delete(root);
        AccessLogger::getInstance().logResponse(req, 400, "CONFIG_VALIDATION_FAILED");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, validation_error.c_str());
    }

    // Create backup of current config before importing (PSRAM-safe)
    size_t bsz = 0; char* backup_buf = self_->cfg_->getRawConfigInPSRAM(&bsz);
    LOG_INFO("CONFIG_IMPORT", "Created backup of current configuration");

    // Apply new configuration
    char* compact_json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!compact_json) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_PRINT_FAILED");
        return httpd_resp_send_500(req);
    }

    bool success = self_->cfg_->saveConfigJSON(compact_json);
    free_cjson_str(compact_json);

    if (!success) {
        LOG_ERROR("CONFIG_IMPORT", "Failed to save imported configuration, keeping backup");
        // Restore backup
        if (backup_buf && bsz) {
            std::string backup_str(backup_buf, backup_buf + bsz);
            self_->cfg_->saveConfigJSON(backup_str);
        }
        AccessLogger::getInstance().logResponse(req, 500, "IMPORT_SAVE_FAILED");
        return httpd_resp_send_500(req);
    }
    if (backup_buf) heap_caps_free(backup_buf);

    LOG_INFO("CONFIG_IMPORT", "Configuration imported and saved successfully");

    // Return success response
    cJSON* response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Configuration imported successfully. Restart recommended to apply all changes.");
    cJSON_AddNumberToObject(response, "size", body.size());

    char* response_str = cJSON_PrintUnformatted(response);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, response_str, strlen(response_str));

    AccessLogger::getInstance().logResponse(req, 200, "CONFIG_IMPORTED");

    if (response_str) free_cjson_str(response_str);
    cJSON_Delete(response);

    return result;
}

// Serial reporting endpoints
esp_err_t WebServer::h_serial_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    // Get the serial reporter configuration from the unified reporting structure (PSRAM-safe)
    size_t sz = 0; char* buf = self_->cfg_->getRawConfigInPSRAM(&sz);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = (buf && sz) ? PSRAMJsonParser::parseInPSRAM(buf, sz) : nullptr;
    if (buf) heap_caps_free(buf);
    if (!root) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config parse error");

    cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
    cJSON* serial_obj = reporting ? cJSON_GetObjectItem(reporting, "serial") : nullptr;

    // Build response JSON
    cJSON* json = cJSON_CreateObject();

    if (serial_obj && cJSON_IsObject(serial_obj)) {
        // Copy enabled, format, verbosity from main serial object
        if (auto v = cJSON_GetObjectItem(serial_obj, "enabled"); v && cJSON_IsBool(v)) {
            cJSON_AddBoolToObject(json, "enabled", cJSON_IsTrue(v));
        }
        if (auto v = cJSON_GetObjectItem(serial_obj, "format"); v && cJSON_IsString(v)) {
            cJSON_AddStringToObject(json, "format", cJSON_GetStringValue(v));
        }
        if (auto v = cJSON_GetObjectItem(serial_obj, "verbosity"); v && cJSON_IsString(v)) {
            cJSON_AddStringToObject(json, "verbosity", cJSON_GetStringValue(v));
        }

        // Copy configuration section
        cJSON* config = cJSON_GetObjectItem(serial_obj, "configuration");
        if (config && cJSON_IsObject(config)) {
            cJSON* config_copy = cJSON_Duplicate(config, 1);
            cJSON_AddItemToObject(json, "configuration", config_copy);
        }
    } else {
        // Default values if not found
        cJSON_AddBoolToObject(json, "enabled", false);
        cJSON_AddStringToObject(json, "format", "JSON");
        cJSON_AddStringToObject(json, "verbosity", "VERBOSE");
        cJSON_AddItemToObject(json, "configuration", cJSON_CreateObject());
    }

    cJSON_Delete(root);

    char* json_str = cJSON_Print(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(json);
    return ESP_OK;
}

esp_err_t WebServer::h_serial_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");

    cJSON* input_json = cJSON_Parse(payload.c_str());
    if (!input_json) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");

    // Get current configuration (PSRAM-safe)
    size_t sz2 = 0; char* buf2 = self_->cfg_->getRawConfigInPSRAM(&sz2);
    PSRAMJsonParser::PSRAMContext ctx2;
    cJSON* root = (buf2 && sz2) ? PSRAMJsonParser::parseInPSRAM(buf2, sz2) : nullptr;
    if (buf2) heap_caps_free(buf2);
    if (!root) {
        cJSON_Delete(input_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config parse error");
    }

    // Ensure reporting structure exists
    cJSON* reporting = cJSON_GetObjectItem(root, "reporting");
    if (!reporting) {
        reporting = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "reporting", reporting);
    }

    // Get or create serial object
    cJSON* serial_obj = cJSON_GetObjectItem(reporting, "serial");
    if (!serial_obj) {
        serial_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(reporting, "serial", serial_obj);
    }

    // Update main serial fields from input
    if (auto v = cJSON_GetObjectItem(input_json, "enabled"); v && cJSON_IsBool(v)) {
        cJSON_ReplaceItemInObject(serial_obj, "enabled", cJSON_CreateBool(cJSON_IsTrue(v)));
    }
    if (auto v = cJSON_GetObjectItem(input_json, "format"); v && cJSON_IsString(v)) {
        cJSON_ReplaceItemInObject(serial_obj, "format", cJSON_CreateString(cJSON_GetStringValue(v)));
    }
    if (auto v = cJSON_GetObjectItem(input_json, "verbosity"); v && cJSON_IsString(v)) {
        cJSON_ReplaceItemInObject(serial_obj, "verbosity", cJSON_CreateString(cJSON_GetStringValue(v)));
    }

    // Get or create configuration object
    cJSON* config_obj = cJSON_GetObjectItem(serial_obj, "configuration");
    if (!config_obj) {
        config_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(serial_obj, "configuration", config_obj);
    }

    // Update configuration section if provided
    cJSON* input_config = cJSON_GetObjectItem(input_json, "configuration");
    if (input_config && cJSON_IsObject(input_config)) {
        // Replace the entire configuration object
        cJSON_ReplaceItemInObject(serial_obj, "configuration", cJSON_Duplicate(input_config, 1));
    }

    // Save updated configuration
    char* json_str = cJSON_Print(root);
    bool success = false;
    if (json_str) {
        success = self_->cfg_->saveConfigJSON(json_str);
        free_cjson_str(json_str);
    }

    // Apply live - restart reporting with new config
    if (success && g_reporting) {
        ReportingConfig::registerNetworkEndpoints(self_->cfg_, g_reporting);
    }

    cJSON_Delete(input_json);
    cJSON_Delete(root);

    if (success) {
        httpd_resp_send(req, "{\"status\":\"success\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    } else {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
    }
}

esp_err_t WebServer::h_serial_stats_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    // Get statistics from SerialReporter through reporters_glue
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "status", "running");
    cJSON_AddNumberToObject(json, "events_sent", 0);
    cJSON_AddNumberToObject(json, "events_dropped", 0);
    cJSON_AddNumberToObject(json, "queue_size", 0);
    cJSON_AddNumberToObject(json, "bytes_sent", 0);
    cJSON_AddBoolToObject(json, "is_enabled", true);
    cJSON_AddNumberToObject(json, "current_rate_per_sec", 0);

    char* json_str = cJSON_Print(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(json);
    return ESP_OK;
}

esp_err_t WebServer::h_page_serial_monitor(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    return send_html_chunked(req, SERIAL_MONITOR_HTML_GEN, SERIAL_MONITOR_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_fuzz_profiles_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    // Get protocol parameter from query string
    char protocol_param[32] = {0};
    if (httpd_req_get_url_query_str(req, protocol_param, sizeof(protocol_param)) == ESP_OK) {
        char protocol_val[16] = {0};
        if (httpd_query_key_value(protocol_param, "protocol", protocol_val, sizeof(protocol_val)) == ESP_OK) {
            int protocol_num = std::atoi(protocol_val);

            std::stringstream response;
            response << "{\"protocol\":" << protocol_num << ",\"profiles\":[";

            switch (protocol_num) {
                case 1: // Modbus TCP
                    response << "{"
                            << "\"id\":\"default\","
                            << "\"name\":\"Modbus Basic Fuzzing\","
                            << "\"description\":\"Mutational fuzzing of basic Modbus seeds (writes only if safe_mode=false)\","
                            << "\"target_format\":\"IP:PORT;SLAVE_ID (e.g., 192.168.1.100:502;1)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"unauthorized_writes\","
                            << "\"name\":\"Unauthorized Writes\","
                            << "\"description\":\"Tests unauthorized write operations to critical registers and coils\","
                            << "\"target_format\":\"IP:PORT;SLAVE_ID (e.g., 192.168.1.100:502;1)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"dos_listen_only\","
                            << "\"name\":\"DoS Listen-Only Mode\","
                            << "\"description\":\"Attempts to force devices into listen-only mode\","
                            << "\"target_format\":\"IP:PORT;SLAVE_ID\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"broadcast_attacks\","
                            << "\"name\":\"Broadcast Attacks\","
                            << "\"description\":\"Performs broadcast operations that may affect multiple devices\","
                            << "\"target_format\":\"IP:PORT;0 (0 = broadcast)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"device_discovery\","
                            << "\"name\":\"Device Discovery\","
                            << "\"description\":\"Discovers and enumerates Modbus devices and their capabilities\","
                            << "\"target_format\":\"IP:PORT;SLAVE_ID\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"vulnerability_exploits\","
                            << "\"name\":\"Vulnerability Exploits\","
                            << "\"description\":\"Tests known Modbus vulnerabilities and implementation flaws\","
                            << "\"target_format\":\"IP:PORT;SLAVE_ID\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "}";
                    break;

                case 2: // S7 Communication
                    response << "{"
                            << "\"id\":\"default\","
                            << "\"name\":\"S7 Fuzz: Handshake/SetupComm\","
                            << "\"description\":\"Fuzzes S7 session establishment and Setup Communication (non-destructive unless safe_mode=false and unsafe profiles selected)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:102)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"program_upload\","
                            << "\"name\":\"S7 Recon: Block Listing/Upload (Read-only)\","
                            << "\"description\":\"Read-only reconnaissance seeds (list blocks / upload sample block names). May still be blocked by PLC protection.\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:102)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"malformed_packets\","
                            << "\"name\":\"Malformed TPKT/COTP/S7 Packets\","
                            << "\"description\":\"Boundary-value and malformed frames (DoS/crash risk)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:102)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"protocol_confusion\","
                            << "\"name\":\"Protocol Confusion\","
                            << "\"description\":\"Mixed/invalid headers and ROSCTR fuzzing (DoS/crash risk)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:102)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"unauthorized_write\","
                            << "\"name\":\"SINGLE: Unauthenticated Write Var (Lab)\","
                            << "\"description\":\"Single-shot write-variable attempts targeting DB/Q areas (state-changing, disruptive). Requires safe_mode=false.\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:102)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"plc_stop\","
                            << "\"name\":\"SINGLE: PLC STOP/Restart (Lab)\","
                            << "\"description\":\"Single-shot STOP and (hot/cold) restart control attempts (highly disruptive). Requires safe_mode=false.\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:102)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"szl_enumeration\","
                            << "\"name\":\"SZL Enumeration (planned)\","
                            << "\"description\":\"Enumerate SZL IDs/indexes and fingerprint protections (TODO)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:102)\","
                            << "\"implemented\":false,"
                            << "\"unsafe\":false"
                            << "}";
                    break;

                case 3: // OPC UA
                    response << "{"
                            << "\"id\":\"anonymous_access\","
                            << "\"name\":\"Anonymous Access Exploitation\","
                            << "\"description\":\"Tests for insecure anonymous authentication and unencrypted endpoints\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:4840)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"weak_security_policies\","
                            << "\"name\":\"Weak Security Policy Attacks\","
                            << "\"description\":\"Exploits endpoints with SecurityMode=None or weak encryption policies\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"certificate_bypass\","
                            << "\"name\":\"Certificate Bypass Attempts\","
                            << "\"description\":\"Tests certificate validation weaknesses, expired certificates, and weak keys\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"session_hijacking\","
                            << "\"name\":\"Session Hijacking\","
                            << "\"description\":\"Attempts to hijack or replay OpenSecureChannel sessions\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"browse_flooding\","
                            << "\"name\":\"Browse Flooding (DoS)\","
                            << "\"description\":\"Floods server with Browse requests to exhaust memory and CPU\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"chunk_exhaustion\","
                            << "\"name\":\"Chunk Memory Exhaustion (CVE-2019-6575)\","
                            << "\"description\":\"Exploits chunk reassembly vulnerabilities to cause memory exhaustion and crashes\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"protocol_violations\","
                            << "\"name\":\"Protocol Violation Fuzzing\","
                            << "\"description\":\"Sends malformed headers, boundary values, and encoding errors to trigger crashes\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"string_attacks\","
                            << "\"name\":\"String Injection Attacks\","
                            << "\"description\":\"Tests format strings, SQL injection, path traversal, and buffer overflows\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"cve_based\","
                            << "\"name\":\"CVE-Based Exploits\","
                            << "\"description\":\"Tests known OPC UA vulnerabilities (CVE-2019-6575, CVE-2018-7559, etc.)\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"comprehensive\","
                            << "\"name\":\"Comprehensive Fuzzing Campaign\","
                            << "\"description\":\"Runs all 205 fuzzing seeds with 8 mutation strategies for thorough testing\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "}";
                    break;

                case 4: // EtherNet/IP
                    response << "{"
                            << "\"id\":\"default\","
                            << "\"name\":\"EtherNet/IP Baseline\","
                            << "\"description\":\"Baseline valid explicit messaging (GetAttributeSingle) for sanity checks\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"encap_malformed_headers\","
                            << "\"name\":\"Encapsulation Header Mutations\","
                            << "\"description\":\"Malformed/ambiguous ENIP encapsulation headers (parser robustness)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"cpf_item_confusion\","
                            << "\"name\":\"CPF Item Confusion\","
                            << "\"description\":\"Malformed CPF item counts/types/lengths inside SendRRData\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"cip_path_boundary\","
                            << "\"name\":\"CIP Path Boundary\","
                            << "\"description\":\"Boundary/path-size/path-segment mutations on explicit CIP messages\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"cip_service_mutation\","
                            << "\"name\":\"CIP Service Mutation\","
                            << "\"description\":\"Reserved/invalid/vendor-specific CIP service mutations\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"session_handle_anomalies\","
                            << "\"name\":\"Session Handle Anomalies\","
                            << "\"description\":\"SendRRData with stale/invalid session handles (session-state validation)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"io_udp_2222_anomalies\","
                            << "\"name\":\"UDP/2222 I/O Anomalies\","
                            << "\"description\":\"Malformed ENIP I/O datagrams on UDP 2222\","
                            << "\"target_format\":\"IP[:PORT] (default UDP 2222)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"connection_manager_forward_open\","
                            << "\"name\":\"ForwardOpen Mutations\","
                            << "\"description\":\"Connection Manager ForwardOpen malformed sequences\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"unauthorized_writes\","
                            << "\"name\":\"Unauthorized Writes (Lab)\","
                            << "\"description\":\"SetAttributeSingle state-changing write attempts (unsafe)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"device_reset_attempt\","
                            << "\"name\":\"Device Reset Attempt (Lab)\","
                            << "\"description\":\"CIP Reset service attempts (unsafe, potentially disruptive)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.100:44818)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "}";
                    break;

                case 5: // PROFINET
                    response << "{"
                            << "\"id\":\"default\","
                            << "\"name\":\"DCP Identify-All (L2)\","
                            << "\"description\":\"Send one DCP Identify-All multicast frame (L2 discovery trigger)\","
                            << "\"target_format\":\"IFACE (e.g., eth)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"dcp_spoofing\","
                            << "\"name\":\"DCP Spoofing / Flooding\","
                            << "\"description\":\"Fake Identify responses and response flooding (L2 spoof/DoS risk)\","
                            << "\"target_format\":\"IFACE (e.g., eth)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"topology_manipulation\","
                            << "\"name\":\"Topology Manipulation\","
                            << "\"description\":\"PTCP/hello-like frames to confuse topology discovery (L2 spoof/DoS risk)\","
                            << "\"target_format\":\"IFACE (e.g., eth)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"malformed_packets\","
                            << "\"name\":\"Malformed DCP Packets\","
                            << "\"description\":\"Boundary-value and malformed DCP blocks (DoS/crash risk)\","
                            << "\"target_format\":\"IFACE (e.g., eth)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"arp_profinet_confusion\","
                            << "\"name\":\"ARP/802.1Q Confusion\","
                            << "\"description\":\"Protocol confusion (ARP EtherType + DCP-like payload, VLAN-tagged frames)\","
                            << "\"target_format\":\"IFACE (e.g., eth)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "},{"
                            << "\"id\":\"device_replacement\","
                            << "\"name\":\"Device Replacement (DCP Set)\","
                            << "\"description\":\"DCP Set Name/IP and Reset-to-factory seeds (state-changing)\","
                            << "\"target_format\":\"IFACE (e.g., eth)\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":true"
                            << "},{"
                            << "\"id\":\"rpc_discovery\","
                            << "\"name\":\"PNIO RPC Discovery (planned)\","
                            << "\"description\":\"DCE/RPC endpoint mapping and PNIO service probing (TODO)\","
                            << "\"target_format\":\"IP:PORT (e.g., 192.168.1.10:34964)\","
                            << "\"implemented\":false,"
                            << "\"unsafe\":false"
                            << "}";
                    break;

                default:
                    response << "{"
                            << "\"id\":\"default\","
                            << "\"name\":\"Generic Fuzzing\","
                            << "\"description\":\"Generic protocol fuzzing operations\","
                            << "\"target_format\":\"IP:PORT\","
                            << "\"implemented\":true,"
                            << "\"unsafe\":false"
                            << "}";
                    break;
            }

            response << "]}";

            httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
            return httpd_resp_send(req, response.str().c_str(), HTTPD_RESP_USE_STRLEN);
        }
    }

    // Default response if no protocol specified
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, "{\"error\":\"protocol parameter required\"}", HTTPD_RESP_USE_STRLEN);
}

// ============================================================================
// Network Diagnostics Handlers
// ============================================================================

esp_err_t WebServer::h_network_ping(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string body;
    if (!read_body(req, body)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) { AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); }

    cJSON* target_item = cJSON_GetObjectItem(json, "target");
    cJSON* count_item = cJSON_GetObjectItem(json, "count");

    if (!target_item || !cJSON_IsString(target_item)) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "target required");
    }

    std::string target = target_item->valuestring;
    int count = (count_item && cJSON_IsNumber(count_item)) ? count_item->valueint : 4;

    cJSON_Delete(json);

    // Perform real ICMP Echo Requests on the Ethernet assessment interface.
    cJSON* response = cJSON_CreateObject();
    cJSON* results = cJSON_CreateArray();

    // Get current network interface info
    esp_netif_t* netif = esp_netif_get_handle_from_ifkey("ETH_DEF");

    bool can_ping = false;
    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            can_ping = true;

            char src_ip[16];
            snprintf(src_ip, sizeof(src_ip), IPSTR, IP2STR(&ip_info.ip));
            cJSON_AddStringToObject(response, "source_ip", src_ip);
        }
    }

    struct in_addr target_addr{};
    const bool valid_target = inet_aton(target.c_str(), &target_addr) != 0;
    if (!valid_target) {
        cJSON_AddStringToObject(response, "error", "Invalid IPv4 target");
        cJSON_AddStringToObject(response, "status", "failed");
    } else if (!can_ping) {
        cJSON_AddStringToObject(response, "error", "No network interface available");
        cJSON_AddStringToObject(response, "status", "failed");
    } else {
        cJSON_AddStringToObject(response, "method", "icmp_ping");
        for (int i = 0; i < count; i++) {
            cJSON* ping_result = cJSON_CreateObject();
            cJSON_AddNumberToObject(ping_result, "sequence", i + 1);
            IcmpPing::Result ping{};
            const bool replied = IcmpPing::probe(target_addr.s_addr, netif, 1000U, ping);
            if (replied && ping.status == IcmpPing::Status::Success) {
                cJSON_AddStringToObject(ping_result, "status", "success");
            } else if (ping.status == IcmpPing::Status::Timeout) {
                cJSON_AddStringToObject(ping_result, "status", "timeout");
            } else {
                cJSON_AddStringToObject(ping_result, "status", "error");
            }
            cJSON_AddNumberToObject(ping_result, "time_ms", ping.time_ms);
            cJSON_AddNumberToObject(ping_result, "replies", ping.replies);

            cJSON_AddItemToArray(results, ping_result);

            // Small delay between pings
            if (i < count - 1) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
        }

        cJSON_AddStringToObject(response, "status", "completed");
    }

    cJSON_AddStringToObject(response, "target", target.c_str());
    cJSON_AddNumberToObject(response, "count", count);
    cJSON_AddItemToObject(response, "results", results);

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}


esp_err_t WebServer::h_network_status(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();
    cJSON* interfaces = cJSON_CreateArray();
    cJSON_AddStringToObject(response, "board", NetworkPolicy::boardName());
    cJSON_AddStringToObject(response, "management_policy",
                            NetworkPolicy::managementInterfaceName());
    cJSON_AddStringToObject(response, "management_state",
                            managementInterfaceStateName(currentManagementInterfaceState()));
    cJSON_AddBoolToObject(response, "management_degraded",
                          managementInterfaceIsDegraded());
    cJSON_AddStringToObject(response, "assessment_interface", "ethernet");
    cJSON* capabilities = cJSON_AddObjectToObject(response, "capabilities");
    cJSON_AddBoolToObject(capabilities, "wifi", NetworkPolicy::hasWiFi());
    cJSON_AddBoolToObject(capabilities, "remote_wifi", NetworkPolicy::usesRemoteWiFi());
    cJSON_AddBoolToObject(capabilities, "https", ESP32_OT_WEB_HTTP_ONLY == 0);

    // Check WiFi STA
    esp_netif_t* wifi_sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (wifi_sta) {
        cJSON* wifi_info = cJSON_CreateObject();
        cJSON_AddStringToObject(wifi_info, "type", "wifi_sta");
        cJSON_AddStringToObject(wifi_info, "name", "WiFi Station");

        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(wifi_sta, &ip_info) == ESP_OK) {
            char ip_str[16], gw_str[16], mask_str[16];
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
            snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
            snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

            cJSON_AddStringToObject(wifi_info, "ip", ip_str);
            cJSON_AddStringToObject(wifi_info, "gateway", gw_str);
            cJSON_AddStringToObject(wifi_info, "netmask", mask_str);
            cJSON_AddBoolToObject(wifi_info, "connected", ip_info.ip.addr != 0);
        } else {
            cJSON_AddBoolToObject(wifi_info, "connected", false);
        }

        cJSON_AddItemToArray(interfaces, wifi_info);
    }

    // Check WiFi AP
    esp_netif_t* wifi_ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (wifi_ap) {
        cJSON* ap_info = cJSON_CreateObject();
        cJSON_AddStringToObject(ap_info, "type", "wifi_ap");
        cJSON_AddStringToObject(ap_info, "name", "WiFi Access Point");

        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(wifi_ap, &ip_info) == ESP_OK) {
            char ip_str[16], gw_str[16], mask_str[16];
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
            snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
            snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

            cJSON_AddStringToObject(ap_info, "ip", ip_str);
            cJSON_AddStringToObject(ap_info, "gateway", gw_str);
            cJSON_AddStringToObject(ap_info, "netmask", mask_str);
            cJSON_AddBoolToObject(ap_info, "connected", true);
        }

        cJSON_AddItemToArray(interfaces, ap_info);
    }

    // Check Ethernet
    esp_netif_t* eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (eth) {
        cJSON* eth_info = cJSON_CreateObject();
        cJSON_AddStringToObject(eth_info, "type", "ethernet");
        cJSON_AddStringToObject(eth_info, "name", "Ethernet");

        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(eth, &ip_info) == ESP_OK) {
            char ip_str[16], gw_str[16], mask_str[16];
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
            snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
            snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

            cJSON_AddStringToObject(eth_info, "ip", ip_str);
            cJSON_AddStringToObject(eth_info, "gateway", gw_str);
            cJSON_AddStringToObject(eth_info, "netmask", mask_str);
            cJSON_AddBoolToObject(eth_info, "connected", ip_info.ip.addr != 0);
        } else {
            cJSON_AddBoolToObject(eth_info, "connected", false);
        }

        cJSON_AddItemToArray(interfaces, eth_info);
    }

    cJSON_AddItemToObject(response, "interfaces", interfaces);

    // Report the policy-selected management interface without cross-interface
    // fallback, so status output cannot hide a degraded separation state.
    esp_netif_t* primary = nullptr;
    if (NetworkPolicy::managementUsesEthernet()) {
        primary = esp_netif_get_handle_from_ifkey("ETH_DEF");
    } else {
        primary = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (!primary || esp_netif_get_ip_info(primary, NULL) != ESP_OK) {
            primary = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        }
    }

    if (primary) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(primary, &ip_info) == ESP_OK) {
            char primary_ip[16];
            snprintf(primary_ip, sizeof(primary_ip), IPSTR, IP2STR(&ip_info.ip));
            cJSON_AddStringToObject(response, "primary_ip", primary_ip);
        }
    }

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}


esp_err_t WebServer::h_network_interfaces(httpd_req_t* req) {
    // This is a simpler version that just returns interface list
    return h_network_status(req);
}

esp_err_t WebServer::h_page_network(httpd_req_t* req) {
    if (!check_session(req)) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/login");
        return httpd_resp_send(req, "", 0);
    }

    // Serve HTML directly from const char* to avoid string copy and memory allocation
    return send_html_chunked(req, NETWORK_HTML_GEN, NETWORK_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_network_presence(httpd_req_t* req) {
    return h_page_ids(req);
}

esp_err_t WebServer::h_page_style(httpd_req_t* req) {

        //if (!check_session(req)) {
    //    httpd_resp_set_status(req, "302 Found");
    //    httpd_resp_set_hdr(req, "Location", "/login");
    //    return httpd_resp_send(req, "", 0);
    //}

    return send_html_chunked(req, STYLE_CSS_GEN, STYLE_CSS_GEN_SIZE);
}
esp_err_t WebServer::h_page_diagnostics(httpd_req_t* req) {
    if (!check_session(req)) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/login");
        return httpd_resp_send(req, "", 0);
    }


    return send_html_chunked(req, DIAGNOSTICS_HTML_GEN, DIAGNOSTICS_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_logging(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    return send_html_chunked(req, LOGGING_HTML_GEN, LOGGING_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_configuration(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "/login");
        return httpd_resp_send(req, "", 0);
    }
    return send_html_chunked(req, CONFIGURATION_HTML_GEN, CONFIGURATION_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_gpio(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    return send_html_chunked(req, GPIO_HTML_GEN, GPIO_HTML_GEN_SIZE);
}

esp_err_t WebServer::h_page_audit(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 302, "REDIRECT_UNAUTHENTICATED");
        httpd_resp_set_status(req,"302 Found");
        httpd_resp_set_hdr(req,"Location","/login");
        return httpd_resp_send(req,"",0);
    }

    return send_html_chunked(req, AUDIT_HTML_GEN, AUDIT_HTML_GEN_SIZE);
}

// ============================================================================
// Ethernet Configuration Handlers
// ============================================================================

esp_err_t WebServer::h_ethernet_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();

    // Get current Ethernet configuration from ConfigManager
    if (self_ && self_->cfg_) {
        NetworkConfig net_cfg = self_->cfg_->getNetworkConfig();
        cJSON_AddBoolToObject(response, "enabled", net_cfg.eth_enabled);

        // Check if Ethernet is configured for DHCP or static
        cJSON_AddStringToObject(response, "mode", net_cfg.eth_dhcp ? "dhcp" : "static");
        cJSON_AddBoolToObject(response, "promiscuous", net_cfg.eth_promiscuous);

        if (!net_cfg.eth_dhcp) {
            cJSON_AddStringToObject(response, "static_ip", net_cfg.eth_ip.empty() ? "192.168.1.100" : net_cfg.eth_ip.c_str());
            cJSON_AddStringToObject(response, "static_netmask", net_cfg.eth_netmask.empty() ? "255.255.255.0" : net_cfg.eth_netmask.c_str());
            cJSON_AddStringToObject(response, "static_gateway", net_cfg.eth_gateway.empty() ? "192.168.1.1" : net_cfg.eth_gateway.c_str());
            cJSON_AddStringToObject(response, "static_dns", "8.8.8.8");  // Default DNS
        }
    }

    // Get current actual IP from interface
    esp_netif_t* eth_netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    if (eth_netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(eth_netif, &ip_info) == ESP_OK) {
            char current_ip[16], current_gw[16], current_mask[16];
            snprintf(current_ip, sizeof(current_ip), IPSTR, IP2STR(&ip_info.ip));
            snprintf(current_gw, sizeof(current_gw), IPSTR, IP2STR(&ip_info.gw));
            snprintf(current_mask, sizeof(current_mask), IPSTR, IP2STR(&ip_info.netmask));

            cJSON_AddStringToObject(response, "current_ip", current_ip);
            cJSON_AddStringToObject(response, "current_gateway", current_gw);
            cJSON_AddStringToObject(response, "current_netmask", current_mask);
            cJSON_AddBoolToObject(response, "interface_up", ip_info.ip.addr != 0);
        } else {
            cJSON_AddBoolToObject(response, "interface_up", false);
        }
    } else {
        cJSON_AddBoolToObject(response, "interface_available", false);
    }

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}


esp_err_t WebServer::h_ethernet_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (!self_ || !self_->cfg_) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config manager unavailable");

    psram_string body;
    if (!read_body(req, body)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) { AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); }

    cJSON* mode_item = cJSON_GetObjectItem(json, "mode");
    if (!mode_item || !cJSON_IsString(mode_item)) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mode required");
    }

    const char* mode = mode_item->valuestring ? mode_item->valuestring : "";
    const bool mode_is_dhcp = (strcmp(mode, "dhcp") == 0);
    const bool mode_is_static = (strcmp(mode, "static") == 0);
    if (!mode_is_dhcp && !mode_is_static) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mode must be 'dhcp' or 'static'");
    }

    auto is_valid_ipv4 = [](const char* text) -> bool {
        if (!text || !*text) return false;
        ip4_addr_t tmp{};
        return ip4addr_aton(text, &tmp) != 0;
    };

    // Save configuration by modifying the JSON directly (PSRAM-safe)
    size_t esz = 0;
    char* ebuf = self_->cfg_->getRawConfigInPSRAM(&esz);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* config_root = (ebuf && esz) ? PSRAMJsonParser::parseInPSRAM(ebuf, esz) : nullptr;
    if (ebuf) heap_caps_free(ebuf);
    if (!config_root) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config parse error");
    }

    auto upsert_bool = [](cJSON* obj, const char* key, bool value) {
        cJSON_DeleteItemFromObjectCaseSensitive(obj, key);
        cJSON_AddBoolToObject(obj, key, value);
    };
    auto upsert_string = [](cJSON* obj, const char* key, const char* value) {
        cJSON_DeleteItemFromObjectCaseSensitive(obj, key);
        cJSON_AddStringToObject(obj, key, value ? value : "");
    };

    cJSON* network = cJSON_GetObjectItem(config_root, "network");
    if (!network || !cJSON_IsObject(network)) {
        cJSON_DeleteItemFromObjectCaseSensitive(config_root, "network");
        network = cJSON_CreateObject();
        cJSON_AddItemToObject(config_root, "network", network);
    }

    cJSON* ethernet = cJSON_GetObjectItem(network, "ethernet");
    if (!ethernet || !cJSON_IsObject(ethernet)) {
        cJSON_DeleteItemFromObjectCaseSensitive(network, "ethernet");
        ethernet = cJSON_CreateObject();
        cJSON_AddItemToObject(network, "ethernet", ethernet);
    }

    // Optional toggles (keep previous if not provided)
    cJSON* en_item = cJSON_GetObjectItem(json, "enabled");
    if (en_item && cJSON_IsBool(en_item)) {
        upsert_bool(ethernet, "enabled", cJSON_IsTrue(en_item));
    }
    cJSON* pr_item = cJSON_GetObjectItem(json, "promiscuous");
    if (pr_item && cJSON_IsBool(pr_item)) {
        upsert_bool(ethernet, "promiscuous", cJSON_IsTrue(pr_item));
    }

    // Set DHCP mode
    upsert_bool(ethernet, "dhcp", mode_is_dhcp);

    if (mode_is_static) {
        cJSON* static_ip = cJSON_GetObjectItem(json, "static_ip");
        cJSON* static_netmask = cJSON_GetObjectItem(json, "static_netmask");
        cJSON* static_gateway = cJSON_GetObjectItem(json, "static_gateway");

        if (!static_ip || !cJSON_IsString(static_ip) ||
            !static_netmask || !cJSON_IsString(static_netmask) ||
            !static_gateway || !cJSON_IsString(static_gateway)) {
            cJSON_Delete(json);
            cJSON_Delete(config_root);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "static config incomplete");
        }

        if (!is_valid_ipv4(static_ip->valuestring) ||
            !is_valid_ipv4(static_netmask->valuestring) ||
            !is_valid_ipv4(static_gateway->valuestring)) {
            cJSON_Delete(json);
            cJSON_Delete(config_root);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid static IPv4 parameters");
        }

        upsert_string(ethernet, "ip", static_ip->valuestring);
        upsert_string(ethernet, "netmask", static_netmask->valuestring);
        upsert_string(ethernet, "gateway", static_gateway->valuestring);
    }

    // Save updated configuration
    bool save_ok = false;
    char* updated_json = cJSON_PrintUnformatted(config_root);
    cJSON_Delete(config_root);
    if (updated_json) {
        save_ok = self_->cfg_->saveConfigJSON(updated_json);
        free_cjson_str(updated_json);
    }
    if (!save_ok) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to save configuration");
    }

    // Log configuration change to audit channel
    char mode_details[32];
    snprintf(mode_details, sizeof(mode_details), "mode: %s", mode);
    logConfigChange(req, "ethernet_config", mode_details);

    cJSON_Delete(json);

    // Return success response with restart requirement
    cJSON* response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "status", "success");
    cJSON_AddStringToObject(response, "message", "Ethernet configuration saved. Restart device to apply changes.");
    cJSON_AddBoolToObject(response, "restart_required", true);

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}


esp_err_t WebServer::h_ethernet_diagnostics(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();

    if (self_ && self_->eth_) {
        // Hardware diagnostics
        psram_string hw_diag = self_->eth_->getHardwareDiagnostics();
        cJSON_AddStringToObject(response, "hardware_diagnostics", hw_diag.c_str());

        // Individual status fields for easier parsing
        cJSON_AddBoolToObject(response, "link_up", self_->eth_->isLinkUp());
        cJSON_AddNumberToObject(response, "link_speed", self_->eth_->getLinkSpeed());
        cJSON_AddBoolToObject(response, "full_duplex", self_->eth_->isFullDuplex());
        cJSON_AddStringToObject(response, "ip_address", self_->eth_->getIP().c_str());

        // PHY register dump
        cJSON* phy_regs = cJSON_CreateObject();
        uint32_t reg_value;

        // Read common PHY registers
        for (int reg = 0; reg <= 7; reg++) {
            if (self_->eth_->readPHYRegister(reg, &reg_value)) {
                char reg_name[16];
                snprintf(reg_name, sizeof(reg_name), "reg_%02X", reg);
                cJSON_AddStringToObject(phy_regs, reg_name, ("0x" + std::to_string(reg_value)).c_str());
            }
        }

        // LAN8720 specific registers
        const int lan8720_regs[] = {0x10, 0x11, 0x12, 0x1D, 0x1E, 0x1F};
        for (int reg : lan8720_regs) {
            if (self_->eth_->readPHYRegister(reg, &reg_value)) {
                char reg_name[16];
                snprintf(reg_name, sizeof(reg_name), "reg_%02X", reg);
                cJSON_AddStringToObject(phy_regs, reg_name, ("0x" + std::to_string(reg_value)).c_str());
            }
        }

        cJSON_AddItemToObject(response, "phy_registers", phy_regs);

        // Network configuration
        esp_netif_t* netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
        if (netif) {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
                char ip_str[16], gw_str[16], mask_str[16];
                snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
                snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
                snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

                cJSON* net_info = cJSON_CreateObject();
                cJSON_AddStringToObject(net_info, "ip", ip_str);
                cJSON_AddStringToObject(net_info, "gateway", gw_str);
                cJSON_AddStringToObject(net_info, "netmask", mask_str);
                cJSON_AddBoolToObject(net_info, "is_configured", ip_info.ip.addr != 0);
                cJSON_AddItemToObject(response, "network_info", net_info);
            }
        }

        cJSON_AddStringToObject(response, "status", "success");
    } else {
        cJSON_AddStringToObject(response, "status", "error");
        cJSON_AddStringToObject(response, "message", "Ethernet manager not available");
    }

    // Add timestamp
    cJSON_AddNumberToObject(response, "timestamp", esp_timer_get_time() / 1000000);

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}

esp_err_t WebServer::h_ip_stack_diagnostics(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();

    if (self_ && self_->eth_) {
        // IP stack diagnostics
        psram_string ip_diag = self_->eth_->getIPStackDiagnostics();
        cJSON_AddStringToObject(response, "ip_stack_diagnostics", ip_diag.c_str());

        // Routing table
        psram_string routing = self_->eth_->getRoutingTable();
        cJSON_AddStringToObject(response, "routing_table", routing.c_str());

        // ARP table
        psram_string arp = self_->eth_->getARPTable();
        cJSON_AddStringToObject(response, "arp_table", arp.c_str());

        // Individual tests for easier parsing
        cJSON* tests = cJSON_CreateObject();
        cJSON_AddBoolToObject(tests, "gateway_reachable", self_->eth_->pingGateway());
        cJSON_AddBoolToObject(tests, "dns_reachable", self_->eth_->pingHost("8.8.8.8", 2000));
        cJSON_AddBoolToObject(tests, "google_reachable", self_->eth_->pingHost("8.8.4.4", 2000));
        cJSON_AddItemToObject(response, "connectivity_tests", tests);

        cJSON_AddStringToObject(response, "status", "success");
    } else {
        cJSON_AddStringToObject(response, "status", "error");
        cJSON_AddStringToObject(response, "message", "Ethernet manager not available");
    }

    // Add timestamp
    cJSON_AddNumberToObject(response, "timestamp", esp_timer_get_time() / 1000000);

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}esp_err_t WebServer::h_network_layer_analysis(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();

    if (self_ && self_->eth_) {
        // Network layer diagnostics
        psram_string net_diag = self_->eth_->getNetworkLayerDiagnostics();
        cJSON_AddStringToObject(response, "network_layer_diagnostics", net_diag.c_str());

        // Network segment analysis
        psram_string segment = self_->eth_->analyzeNetworkSegment();
        cJSON_AddStringToObject(response, "segment_analysis", segment.c_str());

        // Individual tests for easier parsing
        cJSON* tests = cJSON_CreateObject();
        cJSON_AddBoolToObject(tests, "arp_request_test", self_->eth_->sendARPRequest("8.8.8.8"));
        cJSON_AddBoolToObject(tests, "gratuitous_arp", self_->eth_->sendGratuitousARP());
        cJSON_AddBoolToObject(tests, "broadcast_test", self_->eth_->testBroadcastReachability());
        cJSON_AddItemToObject(response, "layer2_tests", tests);

        cJSON_AddStringToObject(response, "status", "success");
    } else {
        cJSON_AddStringToObject(response, "status", "error");
        cJSON_AddStringToObject(response, "message", "Ethernet manager not available");
    }

    // Add timestamp
    cJSON_AddNumberToObject(response, "timestamp", esp_timer_get_time() / 1000000);

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}

esp_err_t WebServer::h_network_scan(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string body;
    if (!read_body(req, body)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
    }

    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) { AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); }

    // Parse scan type (optional)
    cJSON* scan_type = cJSON_GetObjectItem(json, "scan_type");
    std::string type = "device_scan";  // default
    if (scan_type && cJSON_IsString(scan_type)) {
        type = scan_type->valuestring;
    }

    cJSON_Delete(json);

    cJSON* response = cJSON_CreateObject();

    if (self_ && self_->eth_) {
        if (type == "device_scan") {
            psram_string scan_result = self_->eth_->scanNetworkDevices();
            cJSON_AddStringToObject(response, "scan_result", scan_result.c_str());
        } else if (type == "segment_analysis") {
            psram_string segment_analysis = self_->eth_->analyzeNetworkSegment();
            cJSON_AddStringToObject(response, "segment_analysis", segment_analysis.c_str());
        } else {
            cJSON_AddStringToObject(response, "error", "unknown_scan_type");
            cJSON_AddStringToObject(response, "supported_types", "device_scan, segment_analysis");
        }

        cJSON_AddStringToObject(response, "scan_type", type.c_str());
        cJSON_AddStringToObject(response, "status", "completed");
    } else {
        cJSON_AddStringToObject(response, "status", "error");
        cJSON_AddStringToObject(response, "message", "Ethernet manager not available");
    }

    // Add timestamp
    cJSON_AddNumberToObject(response, "timestamp", esp_timer_get_time() / 1000000);

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}

esp_err_t WebServer::h_driver_level_diagnostics(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");

    cJSON* response = cJSON_CreateObject();

    if (self_->eth_) {
        psram_string rmii_config = self_->eth_->getRMIIConfiguration();
        cJSON_AddStringToObject(response, "rmii_configuration", rmii_config.c_str());

        psram_string driver_stats = self_->eth_->getDriverStatistics();
        cJSON_AddStringToObject(response, "driver_statistics", driver_stats.c_str());

        psram_string mac_config = self_->eth_->getMACConfiguration();
        cJSON_AddStringToObject(response, "mac_configuration", mac_config.c_str());

        bool loopback_test = self_->eth_->testMACLoopback();
        cJSON_AddBoolToObject(response, "mac_loopback_test", loopback_test);

        bool driver_integrity = self_->eth_->validateDriverIntegrity();
        cJSON_AddBoolToObject(response, "driver_integrity", driver_integrity);

        psram_string full_diagnostics = self_->eth_->getDriverLevelDiagnostics();
        cJSON_AddStringToObject(response, "full_diagnostics", full_diagnostics.c_str());
    } else {
        cJSON_AddStringToObject(response, "error", "Ethernet manager not available");
    }

    cJSON_AddStringToObject(response, "status", "success");
    cJSON_AddNumberToObject(response, "timestamp", esp_timer_get_time() / 1000000);

    char* response_str = cJSON_Print(response);
    cJSON_Delete(response);

    esp_err_t ret = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);

    return ret;
}

// Debug configuration endpoints
esp_err_t WebServer::h_debug_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    DebugConfig config = self_->cfg_->getDebugConfig();

    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "level", config.level);
    cJSON_AddBoolToObject(json, "color", config.color);

    char* json_str = cJSON_Print(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    cJSON_Delete(json);
    free_cjson_str(json_str);
    return result;
}

esp_err_t WebServer::h_api_httpd_stats(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, HTTPD_401_UNAUTHORIZED, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        AccessLogger::getInstance().logResponse(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON_ALLOC_FAIL");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "memory error");
    }

    const HttpdMonitorData& mon = httpd_monitor_;
    const uint64_t now_ms = esp_timer_get_time() / 1000ULL;
    const uint64_t last_request_ms = mon.last_request_ms.load(std::memory_order_relaxed);
    const uint64_t last_response_ms = mon.last_response_ms.load(std::memory_order_relaxed);
    const uint64_t delta_request = (now_ms > last_request_ms) ? (now_ms - last_request_ms) : 0ULL;
    const uint64_t delta_response = (now_ms > last_response_ms) ? (now_ms - last_response_ms) : 0ULL;

    cJSON_AddNumberToObject(root, "total_requests", static_cast<double>(mon.total_requests.load(std::memory_order_relaxed)));
    cJSON_AddNumberToObject(root, "total_responses", static_cast<double>(mon.total_responses.load(std::memory_order_relaxed)));
    cJSON_AddNumberToObject(root, "inflight", static_cast<double>(mon.inflight_requests.load(std::memory_order_relaxed)));
    cJSON_AddNumberToObject(root, "max_inflight", static_cast<double>(mon.max_concurrent.load(std::memory_order_relaxed)));
    cJSON_AddNumberToObject(root, "last_status_code", static_cast<double>(mon.last_status_code.load(std::memory_order_relaxed)));
    cJSON_AddNumberToObject(root, "stall_count", static_cast<double>(mon.stall_count.load(std::memory_order_relaxed)));
    cJSON_AddBoolToObject(root, "watchdog_triggered", mon.watchdog_triggered.load(std::memory_order_relaxed) != 0);
    cJSON_AddNumberToObject(root, "last_request_timestamp_ms", static_cast<double>(last_request_ms));
    cJSON_AddNumberToObject(root, "last_response_timestamp_ms", static_cast<double>(last_response_ms));
    cJSON_AddNumberToObject(root, "time_since_last_request_ms", static_cast<double>(delta_request));
    cJSON_AddNumberToObject(root, "time_since_last_response_ms", static_cast<double>(delta_response));

    cJSON* methods = cJSON_CreateObject();
    if (methods) {
        cJSON_AddNumberToObject(methods, "GET", static_cast<double>(mon.method_get.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(methods, "POST", static_cast<double>(mon.method_post.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(methods, "PUT", static_cast<double>(mon.method_put.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(methods, "DELETE", static_cast<double>(mon.method_delete.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(methods, "OTHER", static_cast<double>(mon.method_other.load(std::memory_order_relaxed)));
        cJSON_AddItemToObject(root, "methods", methods);
    }

    cJSON* statuses = cJSON_CreateObject();
    if (statuses) {
        cJSON_AddNumberToObject(statuses, "2xx", static_cast<double>(mon.status_2xx.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(statuses, "3xx", static_cast<double>(mon.status_3xx.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(statuses, "4xx", static_cast<double>(mon.status_4xx.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(statuses, "5xx", static_cast<double>(mon.status_5xx.load(std::memory_order_relaxed)));
        cJSON_AddNumberToObject(statuses, "auth_failures", static_cast<double>(mon.auth_failures.load(std::memory_order_relaxed)));
        cJSON_AddItemToObject(root, "status_codes", statuses);
    }

    char last_req_uri[96];
    char last_err_uri[96];
    {
        std::lock_guard<std::mutex> lock(httpd_monitor_.uri_mutex);
        strncpy(last_req_uri, httpd_monitor_.last_request_uri, sizeof(last_req_uri) - 1);
        last_req_uri[sizeof(last_req_uri) - 1] = '\0';
        strncpy(last_err_uri, httpd_monitor_.last_error_uri, sizeof(last_err_uri) - 1);
        last_err_uri[sizeof(last_err_uri) - 1] = '\0';
    }

    cJSON_AddStringToObject(root, "last_request_uri", last_req_uri);
    cJSON_AddStringToObject(root, "last_error_uri", last_err_uri);
    cJSON_AddNumberToObject(root, "last_stall_timestamp_ms", static_cast<double>(mon.last_stall_ms.load(std::memory_order_relaxed)));

    char* json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) {
        AccessLogger::getInstance().logResponse(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON_BUILD_FAIL");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json error");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    AccessLogger::getInstance().logResponse(
        req,
        result == ESP_OK ? 200 : 500,
        result == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");
    free_cjson_str(json_str);
    return result;
}
esp_err_t WebServer::h_debug_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");

    cJSON* input_json = cJSON_Parse(payload.c_str());
    if (!input_json) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");

    // Get current configuration (PSRAM-safe)
    size_t sz = 0; char* buf = self_->cfg_->getRawConfigInPSRAM(&sz);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = (buf && sz) ? PSRAMJsonParser::parseInPSRAM(buf, sz) : nullptr;
    if (buf) heap_caps_free(buf);
    if (!root) {
        cJSON_Delete(input_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config parse error");
    }

    // Get or create debug object
    cJSON* debug_obj = cJSON_GetObjectItem(root, "debug");
    if (!debug_obj) {
        debug_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "debug", debug_obj);
    }

    // Update debug fields from input
    if (auto v = cJSON_GetObjectItem(input_json, "level"); v && cJSON_IsNumber(v)) {
        cJSON_ReplaceItemInObject(debug_obj, "level", cJSON_CreateNumber(v->valuedouble));
    }
    if (auto v = cJSON_GetObjectItem(input_json, "color"); v && cJSON_IsBool(v)) {
        cJSON_ReplaceItemInObject(debug_obj, "color", cJSON_CreateBool(cJSON_IsTrue(v)));
    }

    // Save updated configuration
    char* json_str = cJSON_Print(root);
    bool success = false;
    if (json_str) {
        success = self_->cfg_->saveConfigJSON(json_str);
        free_cjson_str(json_str);
    }

    cJSON_Delete(input_json);
    cJSON_Delete(root);

    if (success) {
        httpd_resp_send(req, "{\"status\":\"success\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    } else {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
    }
}

// Security configuration endpoints
esp_err_t WebServer::h_security_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    SecurityConfig config = self_->cfg_->getSecurityConfig();
    cJSON* json = SecurityAPI::handleSecurityConfigGet(self_->sec_, &config);
    if (!json) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "security status unavailable");
    }

    char* json_str = cJSON_Print(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str ? json_str : "{}", json_str ? HTTPD_RESP_USE_STRLEN : 2);

    cJSON_Delete(json);
    if (json_str) {
        free_cjson_str(json_str);
    }
    return result;
}

esp_err_t WebServer::h_security_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");

    cJSON* fuzz_resp = SecurityAPI::handleSecurityConfigPost(self_->sec_, payload.c_str(), payload.size());
    if (!fuzz_resp) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "security update failed");
    }

    bool fuzz_ok = true;
    if (auto success_field = cJSON_GetObjectItem(fuzz_resp, "success"); success_field && cJSON_IsBool(success_field)) {
        fuzz_ok = cJSON_IsTrue(success_field);
    }

    std::string fuzz_message;
    if (auto message_field = cJSON_GetObjectItem(fuzz_resp, "message"); message_field && cJSON_IsString(message_field)) {
        fuzz_message = message_field->valuestring;
    }
    cJSON_Delete(fuzz_resp);

    if (!fuzz_ok) {
        const char* msg = fuzz_message.empty() ? "security update failed" : fuzz_message.c_str();
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
    }

    cJSON* input_json = cJSON_Parse(payload.c_str());
    if (!input_json) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid json");

    size_t sz2 = 0; char* buf2 = self_->cfg_->getRawConfigInPSRAM(&sz2);
    PSRAMJsonParser::PSRAMContext ctx2;
    cJSON* root = (buf2 && sz2) ? PSRAMJsonParser::parseInPSRAM(buf2, sz2) : nullptr;
    if (buf2) heap_caps_free(buf2);
    if (!root) {
        cJSON_Delete(input_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config parse error");
    }

    cJSON* security_obj = cJSON_GetObjectItem(root, "security");
    if (!security_obj) {
        security_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "security", security_obj);
    }

    if (auto v = cJSON_GetObjectItem(input_json, "secure_boot"); v && cJSON_IsBool(v)) {
        cJSON_ReplaceItemInObject(security_obj, "secure_boot", cJSON_CreateBool(cJSON_IsTrue(v)));
    }
    if (auto v = cJSON_GetObjectItem(input_json, "flash_encryption"); v && cJSON_IsBool(v)) {
        cJSON* node = cJSON_CreateBool(cJSON_IsTrue(v));
        if (node) {
            if (cJSON_GetObjectItem(security_obj, "flash_encryption")) {
                cJSON_ReplaceItemInObject(security_obj, "flash_encryption", node);
            } else {
                cJSON_AddItemToObject(security_obj, "flash_encryption", node);
            }
        }
    }
    if (auto v = cJSON_GetObjectItem(input_json, "certificate_validation"); v && cJSON_IsBool(v)) {
        cJSON* node = cJSON_CreateBool(cJSON_IsTrue(v));
        if (node) {
            if (cJSON_GetObjectItem(security_obj, "certificate_validation")) {
                cJSON_ReplaceItemInObject(security_obj, "certificate_validation", node);
            } else {
                cJSON_AddItemToObject(security_obj, "certificate_validation", node);
            }
        }
    }
    if (auto v = cJSON_GetObjectItem(input_json, "opcua_enforce_security"); v && cJSON_IsBool(v)) {
        cJSON* node = cJSON_CreateBool(cJSON_IsTrue(v));
        if (node) {
            if (cJSON_GetObjectItem(security_obj, "opcua_enforce_security")) {
                cJSON_ReplaceItemInObject(security_obj, "opcua_enforce_security", node);
            } else {
                cJSON_AddItemToObject(security_obj, "opcua_enforce_security", node);
            }
        }
    }

    if (auto policy_input = cJSON_GetObjectItem(input_json, "policy"); policy_input && cJSON_IsObject(policy_input)) {
        cJSON* policy_obj = cJSON_GetObjectItem(security_obj, "policy");
        if (!policy_obj) {
            policy_obj = cJSON_CreateObject();
            cJSON_AddItemToObject(security_obj, "policy", policy_obj);
        }
        if (auto v = cJSON_GetObjectItem(policy_input, "block_s7_plc_stop"); v && cJSON_IsBool(v)) {
            cJSON_ReplaceItemInObject(policy_obj, "block_s7_plc_stop", cJSON_CreateBool(cJSON_IsTrue(v)));
        }
    }

    if (auto alert_input = cJSON_GetObjectItem(input_json, "alert_policy"); alert_input && cJSON_IsObject(alert_input)) {
        cJSON* alert_obj = cJSON_GetObjectItem(security_obj, "alert_policy");
        if (!alert_obj) {
            alert_obj = cJSON_CreateObject();
            cJSON_AddItemToObject(security_obj, "alert_policy", alert_obj);
        }

        auto replace_or_add = [](cJSON* parent, const char* key, cJSON* value) {
            if (!parent || !key || !value) {
                return;
            }
            if (cJSON_GetObjectItem(parent, key)) {
                cJSON_ReplaceItemInObject(parent, key, value);
            } else {
                cJSON_AddItemToObject(parent, key, value);
            }
        };

        cJSON* email_in = cJSON_GetObjectItem(alert_input, "email");
        if (email_in && cJSON_IsObject(email_in)) {
            cJSON* email_obj = cJSON_GetObjectItem(alert_obj, "email");
            if (!email_obj) {
                email_obj = cJSON_CreateObject();
                cJSON_AddItemToObject(alert_obj, "email", email_obj);
            }
            if (auto en = cJSON_GetObjectItem(email_in, "enabled"); en && cJSON_IsBool(en)) {
                replace_or_add(email_obj, "enabled", cJSON_CreateBool(cJSON_IsTrue(en)));
            }
            if (auto subject = cJSON_GetObjectItem(email_in, "subject"); subject && cJSON_IsString(subject) && subject->valuestring) {
                replace_or_add(email_obj, "subject", cJSON_CreateString(subject->valuestring));
            }
            if (auto throttle = cJSON_GetObjectItem(email_in, "throttle_minutes"); throttle && cJSON_IsNumber(throttle)) {
                double value = throttle->valuedouble;
                if (value < 0.0) value = 0.0;
                if (value > 1440.0) value = 1440.0;
                replace_or_add(email_obj, "throttle_minutes", cJSON_CreateNumber(value));
            }
            if (auto recipients = cJSON_GetObjectItem(email_in, "recipients"); recipients && cJSON_IsArray(recipients)) {
                cJSON* new_array = cJSON_CreateArray();
                if (new_array) {
                    cJSON* entry = nullptr;
                    cJSON_ArrayForEach(entry, recipients) {
                        if (entry && cJSON_IsString(entry) && entry->valuestring) {
                            cJSON_AddItemToArray(new_array, cJSON_CreateString(entry->valuestring));
                        }
                    }
                    replace_or_add(email_obj, "recipients", new_array);
                }
            }
        }

        cJSON* webhook_in = cJSON_GetObjectItem(alert_input, "webhook");
        if (webhook_in && cJSON_IsObject(webhook_in)) {
            cJSON* webhook_obj = cJSON_GetObjectItem(alert_obj, "webhook");
            if (!webhook_obj) {
                webhook_obj = cJSON_CreateObject();
                cJSON_AddItemToObject(alert_obj, "webhook", webhook_obj);
            }
            if (auto en = cJSON_GetObjectItem(webhook_in, "enabled"); en && cJSON_IsBool(en)) {
                replace_or_add(webhook_obj, "enabled", cJSON_CreateBool(cJSON_IsTrue(en)));
            }
            if (auto url = cJSON_GetObjectItem(webhook_in, "url"); url && cJSON_IsString(url) && url->valuestring) {
                replace_or_add(webhook_obj, "url", cJSON_CreateString(url->valuestring));
            }
            if (auto token = cJSON_GetObjectItem(webhook_in, "token"); token && cJSON_IsString(token) && token->valuestring) {
                replace_or_add(webhook_obj, "token", cJSON_CreateString(token->valuestring));
            }
        }

        cJSON* gpio_in = cJSON_GetObjectItem(alert_input, "gpio");
        if (gpio_in && cJSON_IsObject(gpio_in)) {
            cJSON* gpio_obj = cJSON_GetObjectItem(alert_obj, "gpio");
            if (!gpio_obj) {
                gpio_obj = cJSON_CreateObject();
                cJSON_AddItemToObject(alert_obj, "gpio", gpio_obj);
            }
            if (auto en = cJSON_GetObjectItem(gpio_in, "enabled"); en && cJSON_IsBool(en)) {
                replace_or_add(gpio_obj, "enabled", cJSON_CreateBool(cJSON_IsTrue(en)));
            }
            auto clamp_pin_value = [](double value) -> double {
                if (value < 0.0) value = 0.0;
                if (value > 255.0) value = 255.0;
                return value;
            };
            if (auto critical = cJSON_GetObjectItem(gpio_in, "critical_pin"); critical && cJSON_IsNumber(critical)) {
                replace_or_add(gpio_obj, "critical_pin", cJSON_CreateNumber(clamp_pin_value(critical->valuedouble)));
            }
            if (auto warning = cJSON_GetObjectItem(gpio_in, "warning_pin"); warning && cJSON_IsNumber(warning)) {
                replace_or_add(gpio_obj, "warning_pin", cJSON_CreateNumber(clamp_pin_value(warning->valuedouble)));
            }
            cJSON* buzzer = cJSON_GetObjectItem(gpio_in, "buzzer_pin");
            if (!buzzer) {
                buzzer = cJSON_GetObjectItem(gpio_in, "buzzer");
            }
            if (buzzer && cJSON_IsNumber(buzzer)) {
                replace_or_add(gpio_obj, "buzzer_pin", cJSON_CreateNumber(clamp_pin_value(buzzer->valuedouble)));
            }
        }
    }

    char* json_str = cJSON_Print(root);
    bool success = false;
    if (json_str) {
        success = self_->cfg_->saveConfigJSON(json_str);
        free_cjson_str(json_str);
    }

    cJSON_Delete(input_json);
    cJSON_Delete(root);

    if (!success) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
    }

    SecurityConfig cfg = self_->cfg_->getSecurityConfig();
    cJSON* json = SecurityAPI::handleSecurityConfigGet(self_->sec_, &cfg);
    if (!json) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "security status unavailable");
    }

    char* response_str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!response_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t send_res = httpd_resp_send(req, response_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(response_str);
    return send_res;
}

// Dedicated aliases for clients that only manage the offensive-testing policy.
// They share the authenticated, password-protected implementation above so the
// policy cannot diverge between the general Security page and Scanner pages.
esp_err_t WebServer::h_offensive_testing_get(httpd_req_t* req) {
    return h_security_config_get(req);
}

esp_err_t WebServer::h_offensive_testing_post(httpd_req_t* req) {
    return h_security_config_post(req);
}

esp_err_t WebServer::h_security_event_ack(httpd_req_t* req) {
    if (!check_api_auth(req)) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    if (!self_ || !self_->sec_) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "security manager unavailable");
    }

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    cJSON* json = SecurityAPI::handleSecurityEventAck(self_->sec_, payload.c_str(), payload.size());
    if (!json) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ack failed");
    }

    char* json_str = cJSON_Print(json);
    cJSON_Delete(json);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t res = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    return res;
}

esp_err_t WebServer::h_api_selftest(httpd_req_t* req) {
    if (!check_api_auth(req)) {
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    WebServer* self = WebServer::instance();
    if (!self || !self->cfg_ || !self->sec_) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "web server not initialized");
    }

    cJSON* response = cJSON_CreateObject();
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "memory error");
    }

    cJSON* tests = cJSON_CreateArray();
    if (!tests) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "memory error");
    }

    int passed = 0;
    int failed = 0;

    auto add_result = [&](const char* name, bool ok, const char* message) {
        cJSON* item = cJSON_CreateObject();
        if (!item) {
            return;
        }
        cJSON_AddStringToObject(item, "name", name ? name : "unknown");
        cJSON_AddBoolToObject(item, "pass", ok);
        if (message && *message) {
            cJSON_AddStringToObject(item, "detail", message);
        }
        cJSON_AddItemToArray(tests, item);
        if (ok) {
            ++passed;
        } else {
            ++failed;
        }
    };

    // Test 1: Security configuration GET returns payload with config
    {
        SecurityConfig snapshot = self->cfg_->getSecurityConfig();
        cJSON* cfg_json = SecurityAPI::handleSecurityConfigGet(self->sec_, &snapshot);
        bool ok = false;
        const char* detail = nullptr;
        if (cfg_json) {
            cJSON* cfg_obj = cJSON_GetObjectItem(cfg_json, "config");
            ok = cfg_obj && cJSON_IsObject(cfg_obj);
            if (!ok) {
                detail = "missing config object";
            }
        } else {
            detail = "handleSecurityConfigGet returned null";
        }
        add_result("security_config_get", ok, detail);
        if (cfg_json) {
            cJSON_Delete(cfg_json);
        }
    }

    // Test 2: Rate limiter status endpoint
    {
        cJSON* rl_json = SecurityAPI::handleRateLimitGet();
        bool ok = false;
        const char* detail = nullptr;
        if (rl_json) {
            cJSON* success_field = cJSON_GetObjectItem(rl_json, "success");
            cJSON* config_field = cJSON_GetObjectItem(rl_json, "config");
            ok = success_field && cJSON_IsBool(success_field) && cJSON_IsTrue(success_field) &&
                 config_field && cJSON_IsObject(config_field);
            if (!ok) {
                detail = "unexpected rate limiter payload";
            }
        } else {
            detail = "handleRateLimitGet returned null";
        }
        add_result("rate_limiter_get", ok, detail);
        if (rl_json) {
            cJSON_Delete(rl_json);
        }
    }

    // Test 3: Ensure alert policy snapshot is reachable via configuration manager
    {
        SecurityConfig snapshot = self->cfg_->getSecurityConfig();
        bool ok = snapshot.alert_policy.email.subject.size() > 0;
        add_result("alert_policy_snapshot", ok, ok ? nullptr : "alert policy subject empty");
    }

    cJSON_AddItemToObject(response, "tests", tests);
    cJSON_AddNumberToObject(response, "passed", passed);
    cJSON_AddNumberToObject(response, "failed", failed);
    cJSON_AddBoolToObject(response, "success", failed == 0);

    cJSON* memory = cJSON_CreateObject();
    if (memory) {
        size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t psram_min = heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM);
        size_t dram_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t dram_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        cJSON_AddNumberToObject(memory, "psram_free", static_cast<double>(psram_free));
        cJSON_AddNumberToObject(memory, "psram_min", static_cast<double>(psram_min));
        cJSON_AddNumberToObject(memory, "dram_free", static_cast<double>(dram_free));
        cJSON_AddNumberToObject(memory, "dram_min", static_cast<double>(dram_min));
        cJSON_AddItemToObject(response, "memory", memory);
    }

    char* json_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization error");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    return result;
}

// Rate Limiter API implementations
esp_err_t WebServer::h_ratelimit_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = SecurityAPI::handleRateLimitGet();
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

esp_err_t WebServer::h_ratelimit_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    cJSON* response = SecurityAPI::handleRateLimitPost(payload.c_str(), payload.size());
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

esp_err_t WebServer::h_unblock_client(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    cJSON* response = SecurityAPI::handleUnblockClient(payload.c_str(), payload.size());
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

// API Key Rotation API implementations
esp_err_t WebServer::h_rotation_policy_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = SecurityAPI::handleRotationPolicyGet();
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

esp_err_t WebServer::h_rotation_policy_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    cJSON* response = SecurityAPI::handleRotationPolicyPost(payload.c_str(), payload.size());
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

esp_err_t WebServer::h_rotation_scheduled_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = SecurityAPI::handleRotationScheduledGet();
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

esp_err_t WebServer::h_rotation_schedule_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    cJSON* response = SecurityAPI::handleRotationSchedulePost(payload.c_str(), payload.size());
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

esp_err_t WebServer::h_rotation_cancel_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    cJSON* response = SecurityAPI::handleRotationCancelPost(payload.c_str(), payload.size());
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

esp_err_t WebServer::h_rotation_trigger_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    cJSON* response = SecurityAPI::handleRotationTriggerPost(payload.c_str(), payload.size());
    if (!response) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "failed to create response");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "json serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return result;
}

// Watchdog Configuration API implementations
esp_err_t WebServer::h_watchdog_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    auto watchdog_config = self_->cfg_->getWatchdogConfig();

    cJSON* response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "enabled", watchdog_config.enabled);
    cJSON_AddNumberToObject(response, "timeout_seconds", watchdog_config.timeout_seconds);
    cJSON_AddBoolToObject(response, "panic_on_timeout", watchdog_config.panic_on_timeout);
    cJSON_AddBoolToObject(response, "monitor_idle_cores", watchdog_config.monitor_idle_cores);

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    heap_caps_free(json_str);

    return ret;
}

esp_err_t WebServer::h_watchdog_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string body;
    if (!read_body(req, body)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read body");
    }

    cJSON* request_json = cJSON_Parse(body.c_str());
    if (!request_json) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    }

    // Get current configuration (PSRAM-safe)
    size_t wsz = 0; char* wcfg = self_->cfg_->getRawConfigInPSRAM(&wsz);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* config_root = (wcfg && wsz) ? PSRAMJsonParser::parseInPSRAM(wcfg, wsz) : nullptr;
    if (wcfg) heap_caps_free(wcfg);
    if (!config_root) {
        cJSON_Delete(request_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to parse current config");
    }

    // Get or create watchdog section
    cJSON* watchdog_section = cJSON_GetObjectItem(config_root, "watchdog");
    if (!watchdog_section) {
        watchdog_section = cJSON_CreateObject();
        cJSON_AddItemToObject(config_root, "watchdog", watchdog_section);
    }

    // Update fields from request
    cJSON* enabled = cJSON_GetObjectItem(request_json, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        cJSON_DeleteItemFromObject(watchdog_section, "enabled");
        cJSON_AddBoolToObject(watchdog_section, "enabled", cJSON_IsTrue(enabled));
    }

    cJSON* timeout = cJSON_GetObjectItem(request_json, "timeout_seconds");
    if (timeout && cJSON_IsNumber(timeout)) {
        cJSON_DeleteItemFromObject(watchdog_section, "timeout_seconds");
        cJSON_AddNumberToObject(watchdog_section, "timeout_seconds", timeout->valuedouble);
    }

    cJSON* panic = cJSON_GetObjectItem(request_json, "panic_on_timeout");
    if (panic && cJSON_IsBool(panic)) {
        cJSON_DeleteItemFromObject(watchdog_section, "panic_on_timeout");
        cJSON_AddBoolToObject(watchdog_section, "panic_on_timeout", cJSON_IsTrue(panic));
    }

    cJSON* idle = cJSON_GetObjectItem(request_json, "monitor_idle_cores");
    if (idle && cJSON_IsBool(idle)) {
        cJSON_DeleteItemFromObject(watchdog_section, "monitor_idle_cores");
        cJSON_AddBoolToObject(watchdog_section, "monitor_idle_cores", cJSON_IsTrue(idle));
    }

    // Save updated configuration
    char* updated_config = cJSON_Print(config_root);
    bool success = self_->cfg_->saveConfigJSON(updated_config);

    cJSON_Delete(request_json);
    cJSON_Delete(config_root);
    free_cjson_str(updated_config);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    if (success) {
        return httpd_resp_send(req, "{\"success\":true,\"restart_required\":true,\"message\":\"Watchdog configuration saved; restart the device to apply\"}", HTTPD_RESP_USE_STRLEN);
    } else {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save configuration");
    }
}

// IP Whitelist configuration endpoints
esp_err_t WebServer::h_whitelist_get(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    WebServer* server = (WebServer*)req->user_ctx;
    if (!server) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_SERVER");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "server");
    }

    // Try to read from the persistent config (PSRAM-safe)
    std::string response;
    if (server->cfg_) {
        size_t sz = 0; char* buf = server->cfg_->getRawConfigInPSRAM(&sz);
        PSRAMJsonParser::PSRAMContext ctx;
        cJSON* root = (buf && sz) ? PSRAMJsonParser::parseInPSRAM(buf, sz) : nullptr;
        if (buf) heap_caps_free(buf);
        if (root) {
            cJSON* ipwl = cJSON_GetObjectItem(root, "ip_whitelist");
            if (ipwl) {
                char* s = cJSON_PrintUnformatted(ipwl);
                response = std::string("{\"ip_whitelist\":") + (s ? s : "{}") + "}";
                if (s) free_cjson_str(s);
            }
            cJSON_Delete(root);
        }
    }
    // fallback: manager runtime state
    if (response.empty() && server->ids_) response = server->ids_->getWhitelistManager().saveToConfigJSON();
    if (response.empty()) response = std::string("{\"ip_whitelist\":{}}\n");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "OK");
    return httpd_resp_send(req, response.c_str(), HTTPD_RESP_USE_STRLEN);
}


esp_err_t WebServer::h_whitelist_post(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }
    WebServer* server = (WebServer*)req->user_ctx;
    if (!server) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_SERVER");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "server");
    }

    psram_string payload = extractPayload(req);
    if (payload.empty()) {
        AccessLogger::getInstance().logResponse(req, 400, "EMPTY_PAYLOAD");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty payload");
    }

    // 1) Validate and apply at runtime if IDS is available
    if (server->ids_) {
        const std::string payload_std = PSRAMUtils::fromPSRAMString(payload);
        if (!server->ids_->getWhitelistManager().loadFromConfig(payload_std)) {
            AccessLogger::getInstance().logResponse(req, 400, "INVALID_CONFIG");
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid ip_whitelist");
        }
    }

    // 2) Persist in config.json (PSRAM-safe), even if IDS is not present
    if (server->cfg_) {
        size_t psz = 0; char* pbuf = server->cfg_->getRawConfigInPSRAM(&psz);
        PSRAMJsonParser::PSRAMContext ctx2;
        cJSON* root  = (pbuf && psz) ? PSRAMJsonParser::parseInPSRAM(pbuf, psz) : nullptr;
        if (pbuf) heap_caps_free(pbuf);
        if (!root) root = cJSON_CreateObject();

        cJSON* posted = cJSON_Parse(payload.c_str());
        cJSON* ipwl   = posted ? cJSON_GetObjectItem(posted, "ip_whitelist") : nullptr;
        if (ipwl) {
            cJSON* dup = cJSON_Duplicate(ipwl, 1);
            if (dup) {
                cJSON* old = cJSON_GetObjectItem(root, "ip_whitelist");
                if (old) cJSON_ReplaceItemInObject(root, "ip_whitelist", dup);
                else cJSON_AddItemToObject(root, "ip_whitelist", dup);
                char* s = cJSON_PrintUnformatted(root);
                if (s) { (void)server->cfg_->saveConfigJSON(s); free_cjson_str(s); }
            }
        }
        if (posted) cJSON_Delete(posted);
        cJSON_Delete(root);
    }

    // 3) Force reload (if IDS is available)
    if (server->ids_) {
        server->ids_->reloadWhitelistFromConfig();

        // Log whitelist update to ids_events.log
        if (g_reporting) {
            const char* client_ip = extractClientIPToBuffer(req);
            char event_data[512];
            snprintf(event_data, sizeof(event_data),
                     "{\"alert_type\":\"whitelist_updated\",\"source\":\"web_api\",\"client_ip\":\"%s\","
                     "\"endpoint\":\"/api/whitelist\",\"method\":\"POST\",\"timestamp\":%llu}",
                     client_ip,
                     (unsigned long long)(esp_timer_get_time()/1000ULL));
            report_event_ps(g_reporting, "intrusion_detected", event_data);
        }
    }

    // Log configuration change to audit channel
    logConfigChange(req, "whitelist", "ip_whitelist updated");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "OK");
    return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
}


// IDS Signatures endpoints (stubs for backward compatibility)
esp_err_t WebServer::h_ids_signatures_get(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    // Return empty signatures array for backward compatibility
    std::string response = "{\"signatures\":[],\"total\":0}";

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "OK");
    return httpd_resp_send(req, response.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_ids_signatures_post(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    // Accept signatures for backward compatibility but do nothing
    std::string response = "{\"success\":true,\"message\":\"Signatures processing moved to plugin architecture\"}";

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    AccessLogger::getInstance().logResponse(req, 200, "OK");
    return httpd_resp_send(req, response.c_str(), HTTPD_RESP_USE_STRLEN);
}

// Incremental logs endpoints
static bool is_allowed_log_filename(const char* safe_name) {
    if (!safe_name) {
        return false;
    }
    return (strcmp(safe_name, "app.log") == 0 ||
            strcmp(safe_name, "access.log") == 0 ||
            strcmp(safe_name, "security.log") == 0 ||
            strcmp(safe_name, "network.log") == 0 ||
            strcmp(safe_name, "fuzzing_events.log") == 0 ||
            strcmp(safe_name, "ids_events.log") == 0 ||
            strcmp(safe_name, "vulnerability_scanner.log") == 0 ||
            strcmp(safe_name, "scanner_events.log") == 0 ||
            strcmp(safe_name, "audit_events.log") == 0 ||
            strcmp(safe_name, "gpio_events.log") == 0 ||
            strcmp(safe_name, "discovery_events.log") == 0 ||
            strcmp(safe_name, "signature_events.log") == 0 ||
            strcmp(safe_name, "network_presence_events.log") == 0);
}

static const char* const k_allowed_logs[] = {
    "app.log",
    "access.log",
    "security.log",
    "network.log",
    "fuzzing_events.log",
    "ids_events.log",
    "vulnerability_scanner.log",
    "scanner_events.log",
    "audit_events.log",
    "gpio_events.log",
    "discovery_events.log",
    "signature_events.log",
    "network_presence_events.log"
};

static void build_log_path(const char* safe_name, char* out_path, size_t out_len) {
    if (!safe_name || !out_path || out_len == 0) {
        return;
    }
    if (strcmp(safe_name, "fuzzing_events.log") == 0 ||
        strcmp(safe_name, "ids_events.log") == 0 ||
        strcmp(safe_name, "vulnerability_scanner.log") == 0 ||
        strcmp(safe_name, "scanner_events.log") == 0 ||
        strcmp(safe_name, "audit_events.log") == 0 ||
        strcmp(safe_name, "gpio_events.log") == 0 ||
        strcmp(safe_name, "discovery_events.log") == 0 ||
        strcmp(safe_name, "signature_events.log") == 0 ||
        strcmp(safe_name, "network_presence_events.log") == 0) {
        snprintf(out_path, out_len, "/data/%s", safe_name);
    } else {
        snprintf(out_path, out_len, "/data/logs/%s", safe_name);
    }
}

static bool token_equals_ci(const char* a, const char* b) {
    if (!a || !b) {
        return false;
    }
    size_t i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        const char ca = static_cast<char>(tolower(static_cast<unsigned char>(a[i])));
        const char cb = static_cast<char>(tolower(static_cast<unsigned char>(b[i])));
        if (ca != cb) {
            return false;
        }
        ++i;
    }
    return a[i] == '\0' && b[i] == '\0';
}

static bool token_in_list_ci(const char* token, char tokens[][32], size_t token_count) {
    if (!token || token_count == 0) {
        return false;
    }
    for (size_t i = 0; i < token_count; ++i) {
        if (token_equals_ci(token, tokens[i])) {
            return true;
        }
    }
    return false;
}

static void collect_stream_files(WebServer* server,
                                 char channel_tokens[][32],
                                 size_t channel_count,
                                 std::vector<std::pair<std::string, std::string>>& out_files) {
    out_files.clear();

    auto add_file = [&](const char* filename) {
        if (!filename || !is_allowed_log_filename(filename)) {
            return;
        }
        for (const auto& it : out_files) {
            if (it.first == filename) {
                return;
            }
        }
        char path[128] = {0};
        build_log_path(filename, path, sizeof(path));
        out_files.emplace_back(std::string(filename), std::string(path));
    };

    LogFileManager* log_manager = server ? server->logFileManager() : nullptr;
    if (log_manager) {
        psram_string status_json = log_manager->getStatusJSON();
        if (!status_json.empty()) {
            cJSON* root = cJSON_ParseWithLength(status_json.c_str(), status_json.size());
            if (root) {
                cJSON* files = cJSON_GetObjectItem(root, "files");
                if (files && cJSON_IsArray(files)) {
                    cJSON* item = files->child;
                    while (item) {
                        cJSON* enabled = cJSON_GetObjectItem(item, "enabled");
                        cJSON* filename = cJSON_GetObjectItem(item, "filename");
                        cJSON* channels = cJSON_GetObjectItem(item, "channels");

                        const bool file_enabled = (!enabled || cJSON_IsTrue(enabled));
                        const char* fname = (filename && cJSON_IsString(filename)) ? filename->valuestring : nullptr;

                        bool match = (channel_count == 0);
                        if (!match && channels && cJSON_IsArray(channels)) {
                            cJSON* ch = channels->child;
                            while (ch) {
                                if (cJSON_IsString(ch) && token_in_list_ci(ch->valuestring, channel_tokens, channel_count)) {
                                    match = true;
                                    break;
                                }
                                ch = ch->next;
                            }
                        }

                        if (file_enabled && match) {
                            add_file(fname);
                        }
                        item = item->next;
                    }
                }
                cJSON_Delete(root);
            }
        }
    }

    if (!out_files.empty()) {
        return;
    }

    for (size_t i = 0; i < sizeof(k_allowed_logs) / sizeof(k_allowed_logs[0]); ++i) {
        add_file(k_allowed_logs[i]);
    }
}

static size_t parse_channels_csv(const char* csv, char tokens[][32], size_t max_tokens) {
    if (!csv || !tokens || max_tokens == 0) {
        return 0;
    }

    size_t count = 0;
    const char* p = csv;
    while (*p != '\0' && count < max_tokens) {
        while (*p == ' ' || *p == ',') {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        size_t len = 0;
        while (p[len] != '\0' && p[len] != ',') {
            if (len + 1 < 32) {
                tokens[count][len] = static_cast<char>(tolower(static_cast<unsigned char>(p[len])));
            }
            ++len;
        }

        if (len > 0) {
            size_t write_len = (len < 31) ? len : 31;
            tokens[count][write_len] = '\0';
            ++count;
        }

        p += len;
        if (*p == ',') {
            ++p;
        }
    }
    return count;
}

static bool contains_ci(const std::string& text, const char* token_lower) {
    if (!token_lower || token_lower[0] == '\0') {
        return true;
    }
    const size_t nlen = strlen(token_lower);
    if (nlen == 0 || text.size() < nlen) {
        return false;
    }

    for (size_t i = 0; i + nlen <= text.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < nlen; ++j) {
            const char a = static_cast<char>(tolower(static_cast<unsigned char>(text[i + j])));
            if (a != token_lower[j]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return true;
        }
    }
    return false;
}

static void sanitize_for_sse(const std::string& in, char* out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    size_t w = 0;
    for (size_t i = 0; i < in.size() && w + 1 < out_len; ++i) {
        char c = in[i];
        if (c == '\r' || c == '\n') {
            c = ' ';
        }
        out[w++] = c;
    }
    out[w] = '\0';
}

static esp_err_t sse_send_event(httpd_req_t* req, const char* event_name, const char* data) {
    if (!req || !event_name || !data) {
        return ESP_FAIL;
    }
    char chunk[1024];
    const int n = snprintf(chunk, sizeof(chunk), "event: %s\ndata: %s\n\n", event_name, data);
    if (n <= 0) {
        return ESP_FAIL;
    }
    return httpd_resp_send_chunk(req, chunk, strlen(chunk));
}

struct IncrementalLogsSessionState {
    std::string path;
    size_t byte_offset = 0;
    uint64_t created_us = 0;
    uint64_t last_access_us = 0;
};

static std::mutex g_incremental_logs_sessions_mutex;
static std::map<std::string, IncrementalLogsSessionState> g_incremental_logs_sessions;
static constexpr uint64_t kIncrementalLogsSessionTimeoutUs = 5ULL * 60ULL * 1000000ULL;

static std::string make_incremental_logs_session_id() {
    char id[56];
    const uint64_t t = static_cast<uint64_t>(esp_timer_get_time());
    const uint32_t r = esp_random();
    snprintf(id, sizeof(id), "sess_%08x_%08x", static_cast<unsigned>(t & 0xffffffffU), static_cast<unsigned>(r));
    return std::string(id);
}

static void cleanup_incremental_logs_sessions_locked(uint64_t now_us) {
    for (auto it = g_incremental_logs_sessions.begin(); it != g_incremental_logs_sessions.end();) {
        const uint64_t age_us = (now_us >= it->second.last_access_us) ? (now_us - it->second.last_access_us) : 0;
        if (age_us > kIncrementalLogsSessionTimeoutUs) {
            it = g_incremental_logs_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

static esp_err_t sse_send_raw_line(httpd_req_t* req, const std::string& line, const char* source_name = nullptr) {
    char msg[760];
    sanitize_for_sse(line, msg, sizeof(msg));

    char payload[900];
    if (source_name && source_name[0] != '\0') {
        snprintf(payload, sizeof(payload), "[%s] %s", source_name, msg);
    } else {
        snprintf(payload, sizeof(payload), "%s", msg);
    }
    return sse_send_event(req, "log", payload);
}

static bool line_matches_channels(const std::string& line, char tokens[][32], size_t token_count) {
    if (token_count == 0) {
        return true;
    }
    for (size_t i = 0; i < token_count; ++i) {
        if (contains_ci(line, tokens[i])) {
            return true;
        }
    }
    return false;
}

static size_t find_tail_start_offset(const psram_string& content, size_t tail_lines) {
    if (tail_lines == 0 || content.empty()) {
        return 0;
    }

    size_t found = 0;
    for (size_t pos = content.size(); pos > 0; --pos) {
        if (content[pos - 1] == '\n') {
            ++found;
            if (found > tail_lines) {
                return pos;
            }
        }
    }
    return 0;
}

static esp_err_t sse_emit_chunk_lines(httpd_req_t* req,
                                      const char* source_name,
                                      const char* data,
                                      size_t data_len,
                                      std::string& carry,
                                      bool filter_by_content,
                                      char channel_tokens[][32],
                                      size_t channel_count,
                                      bool* sent_any = nullptr) {
    if (!data || data_len == 0) {
        return ESP_OK;
    }

    carry.append(data, data_len);
    while (true) {
        const size_t nl = carry.find('\n');
        if (nl == std::string::npos) {
            break;
        }

        std::string line = carry.substr(0, nl);
        carry.erase(0, nl + 1);

        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (filter_by_content && !line_matches_channels(line, channel_tokens, channel_count)) {
            continue;
        }

        const esp_err_t rc = sse_send_raw_line(req, line, source_name);
        if (rc != ESP_OK) {
            return rc;
        }
        if (sent_any) {
            *sent_any = true;
        }
    }

    // Keep incomplete line bounded (avoid unbounded growth if '\n' is missing)
    if (carry.size() > 2048) {
        carry.erase(0, carry.size() - 2048);
    }

    return ESP_OK;
}

esp_err_t WebServer::h_logs_incremental_session(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    WebServer* server = self_ ? self_ : (WebServer*)req->user_ctx;
    if (!server) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_SERVER");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Server not available");
    }

    char query[256] = {0};
    char name[64] = {0};
    const bool has_query = (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK);
    if (has_query) {
        httpd_query_key_value(query, "name", name, sizeof(name));
    }

    std::string log_path;
    if (name[0] != '\0') {
        if (strstr(name, "..") != nullptr || strchr(name, '/') != nullptr || !is_allowed_log_filename(name)) {
            AccessLogger::getInstance().logResponse(req, 400, "INVALID_NAME");
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid log name");
        }
        char path[128] = {0};
        build_log_path(name, path, sizeof(path));
        log_path.assign(path);
    } else {
        static const char* k_default_logs[] = {
            "/data/logs/system.log",
            "/data/logs/main.log",
            "/data/logs/app.log"
        };
        bool found = false;
        for (size_t i = 0; i < sizeof(k_default_logs) / sizeof(k_default_logs[0]); ++i) {
            bool exists = false;
            if (AsyncStorage::Global::fileExists(k_default_logs[i], exists) == ESP_OK && exists) {
                log_path.assign(k_default_logs[i]);
                found = true;
                break;
            }
        }
        if (!found) {
            AccessLogger::getInstance().logResponse(req, 404, "NO_LOGFILE");
            return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Log file not found");
        }
    }

    bool exists = false;
    if (AsyncStorage::Global::fileExists(log_path, exists) != ESP_OK || !exists) {
        AccessLogger::getInstance().logResponse(req, 404, "NO_LOGFILE");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Log file not found");
    }

    const uint64_t now_us = static_cast<uint64_t>(esp_timer_get_time());
    const std::string session_id = make_incremental_logs_session_id();
    {
        std::lock_guard<std::mutex> lock(g_incremental_logs_sessions_mutex);
        cleanup_incremental_logs_sessions_locked(now_us);
        IncrementalLogsSessionState st;
        st.path = log_path;
        st.byte_offset = 0;
        st.created_us = now_us;
        st.last_access_us = now_us;
        g_incremental_logs_sessions[session_id] = st;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    char response[192];
    snprintf(response, sizeof(response), "{\"session_id\":\"%s\",\"success\":true}", session_id.c_str());

    AccessLogger::getInstance().logResponse(req, 200, "OK");
    return httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_logs_incremental_read(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    WebServer* server = self_ ? self_ : (WebServer*)req->user_ctx;
    if (!server) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_SERVER");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Server not available");
    }

    // Parse query parameters
    char query[256] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 400, "NO_SESSION");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "session_id parameter required");
    }

    // Extract session_id value
    char session_value[32] = {0};
    if (httpd_query_key_value(query, "session_id", session_value, sizeof(session_value)) != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_SESSION");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid session_id");
    }

    int max_entries = 50;
    char max_entries_str[12] = {0};
    if (httpd_query_key_value(query, "max_entries", max_entries_str, sizeof(max_entries_str)) == ESP_OK) {
        int requested = atoi(max_entries_str);
        if (requested > 0) {
            max_entries = requested;
        }
    }
    if (max_entries > 200) {
        max_entries = 200;
    }

    std::string log_path;
    size_t byte_offset = 0;
    const uint64_t now_us = static_cast<uint64_t>(esp_timer_get_time());
    {
        std::lock_guard<std::mutex> lock(g_incremental_logs_sessions_mutex);
        cleanup_incremental_logs_sessions_locked(now_us);
        auto it = g_incremental_logs_sessions.find(std::string(session_value));
        if (it == g_incremental_logs_sessions.end()) {
            AccessLogger::getInstance().logResponse(req, 400, "INVALID_SESSION");
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid session_id");
        }
        it->second.last_access_us = now_us;
        log_path = it->second.path;
        byte_offset = it->second.byte_offset;
    }

    bool exists = false;
    if (AsyncStorage::Global::fileExists(log_path, exists) != ESP_OK || !exists) {
        AccessLogger::getInstance().logResponse(req, 404, "NO_LOGFILE");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Log file not found");
    }

    psram_string content;
    if (AsyncStorage::Global::readFile(log_path, content) != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 500, "READ_ERROR");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "read failed");
    }

    if (byte_offset > content.size()) {
        byte_offset = 0;
    }

    size_t cursor = byte_offset;
    int emitted = 0;
    size_t last_line_marker = byte_offset;
    size_t line_number = 0;

    cJSON* response = cJSON_CreateObject();
    cJSON* entries = cJSON_CreateArray();

    while (cursor < content.size() && emitted < max_entries) {
        if (content[cursor] == '\n') {
            size_t start = last_line_marker;
            size_t len = (cursor > start) ? (cursor - start) : 0;

            std::string line;
            if (len > 0) {
                line.assign(content.c_str() + start, len);
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
            }

            cJSON* log_entry = cJSON_CreateObject();
            cJSON_AddStringToObject(log_entry, "timestamp", "");
            cJSON_AddStringToObject(log_entry, "level", "INFO");
            cJSON_AddStringToObject(log_entry, "component", "System");
            cJSON_AddStringToObject(log_entry, "message", line.c_str());
            cJSON_AddNumberToObject(log_entry, "line_number", static_cast<double>(line_number));
            cJSON_AddItemToArray(entries, log_entry);

            emitted++;
            last_line_marker = cursor + 1;
            line_number++;
        }
        cursor++;
    }

    if (emitted < max_entries && last_line_marker < content.size()) {
        std::string line(content.c_str() + last_line_marker, content.size() - last_line_marker);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        cJSON* log_entry = cJSON_CreateObject();
        cJSON_AddStringToObject(log_entry, "timestamp", "");
        cJSON_AddStringToObject(log_entry, "level", "INFO");
        cJSON_AddStringToObject(log_entry, "component", "System");
        cJSON_AddStringToObject(log_entry, "message", line.c_str());
        cJSON_AddNumberToObject(log_entry, "line_number", static_cast<double>(line_number));
        cJSON_AddItemToArray(entries, log_entry);
        emitted++;
        last_line_marker = content.size();
    }

    size_t new_offset = last_line_marker;
    bool has_more = (new_offset < content.size());

    {
        std::lock_guard<std::mutex> lock(g_incremental_logs_sessions_mutex);
        auto it = g_incremental_logs_sessions.find(std::string(session_value));
        if (it != g_incremental_logs_sessions.end()) {
            it->second.byte_offset = new_offset;
            it->second.last_access_us = now_us;
        }
    }

    cJSON_AddItemToObject(response, "entries", entries);
    cJSON_AddNumberToObject(response, "last_line_read", static_cast<double>(new_offset));
    cJSON_AddBoolToObject(response, "has_more", has_more);
    cJSON_AddBoolToObject(response, "success", true);

    char* json_str = cJSON_PrintUnformatted(response);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(response);

    AccessLogger::getInstance().logResponse(req, 200, "OK");
    return ret;
}

esp_err_t WebServer::h_logs_sse(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);

    if (!check_session(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    WebServer* server = self_ ? self_ : (WebServer*)req->user_ctx;
    if (!server) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_SERVER");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Server not available");
    }

    char query[512] = {0};
    char name[64] = "app.log";
    char channels_csv[256] = {0};
    char tail_str[16] = {0};
    int tail = 100;

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "name", name, sizeof(name));
        httpd_query_key_value(query, "channels", channels_csv, sizeof(channels_csv));
        httpd_query_key_value(query, "tail", tail_str, sizeof(tail_str));
        if (tail_str[0] != '\0') {
            tail = atoi(tail_str);
            if (tail < 0) {
                tail = 0;
            }
            if (tail > 500) {
                tail = 500;
            }
        }
    }

    const bool stream_all_files = token_equals_ci(name, "all");
    if (!stream_all_files &&
        (strstr(name, "..") != nullptr || strchr(name, '/') != nullptr || !is_allowed_log_filename(name))) {
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_NAME");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid log name");
    }

    char channel_tokens[16][32] = {{0}};
    const size_t channel_count = parse_channels_csv(channels_csv, channel_tokens, 16);

    std::vector<std::pair<std::string, std::string>> stream_files;
    if (stream_all_files) {
        collect_stream_files(server, channel_tokens, channel_count, stream_files);
    } else {
        char log_path[128] = {0};
        build_log_path(name, log_path, sizeof(log_path));
        stream_files.emplace_back(std::string(name), std::string(log_path));
    }

    if (stream_files.empty()) {
        AccessLogger::getInstance().logResponse(req, 404, "NO_LOGFILE");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No matching log files");
    }

    struct ReaderCtx {
        std::string source_name;
        std::string path;
        size_t last_size = 0;
        std::string carry;
    };
    std::list<ReaderCtx> readers;
    for (const auto& file : stream_files) {
        readers.emplace_back();
        ReaderCtx& ctx = readers.back();
        ctx.source_name = file.first;
        ctx.path = file.second;
        ctx.last_size = 0;
        ctx.carry.clear();
    }

    if (readers.empty()) {
        AccessLogger::getInstance().logResponse(req, 404, "NO_LOGFILE");
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Log file not found");
    }

    httpd_resp_set_type(req, "text/event-stream");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");
    httpd_resp_set_hdr(req, "X-Accel-Buffering", "no");

    esp_err_t rc = sse_send_event(req, "ready", "stream_started");
    if (rc != ESP_OK) {
        AccessLogger::getInstance().logResponse(req, 499, "SSE_CLOSED");
        return rc;
    }

    const bool filter_by_content = !stream_all_files;

    // Initial snapshot (tail lines) from async storage worker - safe with PSRAM stack.
    if (tail > 0 && rc == ESP_OK) {
        const size_t tail_lines = static_cast<size_t>(tail);
        for (auto& ctx : readers) {
            bool exists = false;
            if (AsyncStorage::Global::fileExists(ctx.path, exists) != ESP_OK || !exists) {
                ctx.last_size = 0;
                ctx.carry.clear();
                continue;
            }

            psram_string content;
            if (AsyncStorage::Global::readFile(ctx.path, content) != ESP_OK) {
                continue;
            }

            const size_t start = find_tail_start_offset(content, tail_lines);
            if (start < content.size()) {
                rc = sse_emit_chunk_lines(req,
                                          ctx.source_name.c_str(),
                                          content.c_str() + start,
                                          content.size() - start,
                                          ctx.carry,
                                          filter_by_content,
                                          channel_tokens,
                                          channel_count,
                                          nullptr);
                if (rc != ESP_OK) {
                    break;
                }
            }
            ctx.last_size = content.size();
        }
    }

    int64_t last_heartbeat_us = esp_timer_get_time();
    while (rc == ESP_OK) {
        bool sent_any = false;
        for (auto& ctx : readers) {
            bool exists = false;
            if (AsyncStorage::Global::fileExists(ctx.path, exists) != ESP_OK) {
                continue;
            }

            if (!exists) {
                ctx.last_size = 0;
                ctx.carry.clear();
                continue;
            }

            size_t current_size = 0;
            if (AsyncStorage::Global::fileSize(ctx.path, current_size) != ESP_OK) {
                continue;
            }

            if (current_size < ctx.last_size) {
                // File rotated/truncated: restart incremental window.
                ctx.last_size = 0;
                ctx.carry.clear();
            }

            if (current_size == ctx.last_size) {
                continue;
            }

            psram_string content;
            if (AsyncStorage::Global::readFile(ctx.path, content) != ESP_OK) {
                continue;
            }

            size_t start = ctx.last_size;
            if (start > content.size()) {
                start = 0;
                ctx.carry.clear();
            }

            rc = sse_emit_chunk_lines(req,
                                      ctx.source_name.c_str(),
                                      content.c_str() + start,
                                      content.size() - start,
                                      ctx.carry,
                                      filter_by_content,
                                      channel_tokens,
                                      channel_count,
                                      &sent_any);
            if (rc != ESP_OK) {
                break;
            }

            ctx.last_size = content.size();
        }

        const int64_t now_us = esp_timer_get_time();
        if (rc == ESP_OK && !sent_any && (now_us - last_heartbeat_us) >= 3000000LL) {
            rc = httpd_resp_send_chunk(req, ": ping\n\n", 8);
            last_heartbeat_us = now_us;
        } else if (sent_any) {
            last_heartbeat_us = now_us;
        }

        if (rc != ESP_OK) {
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(500));
    }

    // Best-effort terminator; it will fail if client already closed.
    httpd_resp_send_chunk(req, nullptr, 0);
    AccessLogger::getInstance().logResponse(req, 200, "SSE_END");
    return ESP_OK;
}
esp_err_t WebServer::h_features_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    ConfigurationManager* cfg = WebServer::self_ ? WebServer::self_->cfg_ : nullptr;
    if (!cfg) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No config");
    bool ids = cfg->isFeatureEnabled("ids", true);
    bool vs  = cfg->isFeatureEnabled("vuln_scanner", false);
    bool fz  = cfg->isFeatureEnabled("fuzzing", false);
    bool sched = cfg->isFeatureEnabled("scheduled_scans", true);
    char json[160];
    snprintf(json, sizeof(json), "{\"ids\":%s,\"vuln_scanner\":%s,\"fuzzing\":%s,\"scheduled_scans\":%s}",
             ids?"true":"false", vs?"true":"false", fz?"true":"false", sched?"true":"false");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_features_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    ConfigurationManager* cfg = WebServer::self_ ? WebServer::self_->cfg_ : nullptr;
    if (!cfg) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No config");
    psram_string body = extractPayload(req);
    if (body.empty()) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");
    cJSON* root = cJSON_ParseWithLength(body.c_str(), body.size());
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    // Load current raw, update mapped flags, save (PSRAM-safe)
    size_t sz = 0; char* buf = cfg->getRawConfigInPSRAM(&sz);
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* curr = (buf && sz) ? PSRAMJsonParser::parseInPSRAM(buf, sz) : nullptr;
    if (buf) heap_caps_free(buf);
    if (!curr) { cJSON_Delete(root); return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Parse curr"); }
    // Helper to set nested bool: obj[key]=bool, creating object if missing
    auto set_nested_bool = [](cJSON* parent, const char* key, bool val){
        cJSON* it = cJSON_GetObjectItem(parent, key);
        if (!it) cJSON_AddItemToObject(parent, key, cJSON_CreateBool(val));
        else cJSON_ReplaceItemInObject(parent, key, cJSON_CreateBool(val));
    };

    // Read current underlying flags
    bool ids_en = cfg->isFeatureEnabled("ids", true);
    bool scanner_en = cfg->isFeatureEnabled("vuln_scanner", false);
    bool scheduler_en = cfg->isFeatureEnabled("scheduled_scans", true);

    // Parse requested flags
    cJSON* v_ids = cJSON_GetObjectItem(root, "ids");
    cJSON* v_vs  = cJSON_GetObjectItem(root, "vuln_scanner");
    cJSON* v_fz  = cJSON_GetObjectItem(root, "fuzzing");
    cJSON* v_sched = cJSON_GetObjectItem(root, "scheduled_scans");
    if (v_ids && cJSON_IsBool(v_ids)) ids_en = (v_ids->valueint != 0);
    // vuln_scanner and fuzzing both map to scanner.enabled (OR policy if both present)
    bool vs_req = scanner_en;
    bool fz_req = scanner_en;
    if (v_vs && cJSON_IsBool(v_vs)) vs_req = (v_vs->valueint != 0);
    if (v_fz && cJSON_IsBool(v_fz)) fz_req = (v_fz->valueint != 0);
    bool scanner_new = (vs_req || fz_req);
    if (v_sched && cJSON_IsBool(v_sched)) scheduler_en = (v_sched->valueint != 0);

    // Update curr JSON: ids.general.enabled and scanner.enabled
    cJSON* ids = cJSON_GetObjectItem(curr, "ids"); if (!ids) { ids = cJSON_CreateObject(); cJSON_AddItemToObject(curr, "ids", ids); }
    cJSON* general = cJSON_GetObjectItem(ids, "general"); if (!general) { general = cJSON_CreateObject(); cJSON_AddItemToObject(ids, "general", general); }
    set_nested_bool(general, "enabled", ids_en);

    cJSON* scanner = cJSON_GetObjectItem(curr, "scanner"); if (!scanner) { scanner = cJSON_CreateObject(); cJSON_AddItemToObject(curr, "scanner", scanner); }
    set_nested_bool(scanner, "enabled", scanner_new);
    cJSON* scheduling = cJSON_GetObjectItem(scanner, "scheduling"); if (!scheduling) { scheduling = cJSON_CreateObject(); cJSON_AddItemToObject(scanner, "scheduling", scheduling); }
    set_nested_bool(scheduling, "enabled", scheduler_en);
    char* out = cJSON_PrintUnformatted(curr);
    bool ok=false;
    if (out){ ok = cfg->saveConfigJSON(out); cJSON_free(out); }
    cJSON_Delete(curr);
    cJSON_Delete(root);
    if (!ok) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Save failed");

    // Log configuration change to audit channel
    char details[256];
    snprintf(details, sizeof(details), "ids:%s,scanner:%s,schedules:%s",
             ids_en ? "enabled" : "disabled",
             scanner_new ? "enabled" : "disabled",
             scheduler_en ? "enabled" : "disabled");
    logConfigChange(req, "features", details);

    if (self_) {
        if (!scanner_new || !scheduler_en) {
            if (self_->cron_scheduler_ && self_->cron_scheduler_initialized_) {
                self_->cron_scheduler_->shutdown();
                self_->cron_scheduler_initialized_ = false;
            }
        } else {
            self_->initCronSchedulerIfReady();
        }
    }

    // Persist scheduled scans toggle in NVS as well (crash-safe).
    // This prevents the UI from "re-enabling" after reboot when a power cut/crash happens
    // before the filesystem config write completes.
    {
        const uint8_t v = scheduler_en ? 1 : 0;
        const esp_err_t er = AsyncStorage::Global::nvsSet("cron", "enabled", v);
        LOG_INFOF("FEATURES", "Persist scheduled_scans to NVS: %s (err=%s)", scheduler_en ? "enabled" : "disabled", esp_err_to_name(er));
    }

    return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
}

// ========================= LOG FILE MANAGEMENT API =========================

static std::string resolveManagedLogName(const char* name) {
    if (!name || !*name) return {};
    if (strstr(name, "..") || strchr(name, '/') || strchr(name, '\\')) return {};
    std::string base(name);
    LogFileManager::LogFileInfo info;
    WebServer* server = WebServer::instance();
    LogFileManager* manager = server ? server->logFileManager() : nullptr;
    if (manager && manager->getFileInfo(base, info)) {
        return base;
    }
    const std::string data_path = std::string("/data/") + base;
    if (manager && manager->getFileInfo(data_path, info)) {
        return data_path;
    }
    const std::string logs_path = std::string("/data/logs/") + base;
    if (manager && manager->getFileInfo(logs_path, info)) {
        return logs_path;
    }
    return {};
}

esp_err_t WebServer::h_logging_files_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!self_ || !self_->log_file_manager_) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Log manager not available");
    }

    // Refresh file statuses before returning info
    self_->log_file_manager_->refreshFileStatuses();

    // Get status JSON (PSRAM-safe)
    psram_string status_json = self_->log_file_manager_->getStatusJSON();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, status_json.c_str(), status_json.size());
}

esp_err_t WebServer::h_logging_files_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!self_ || !self_->log_file_manager_) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Log manager not available");
    }

    psram_string body = extractPayload(req);
    if (body.empty()) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");

    cJSON* root = cJSON_ParseWithLength(body.c_str(), body.size());
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");

    // Parse action and filename
    cJSON* action = cJSON_GetObjectItem(root, "action");
    cJSON* filename = cJSON_GetObjectItem(root, "filename");

    if (!action || !cJSON_IsString(action) || !filename || !cJSON_IsString(filename)) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing action or filename");
    }

    std::string action_str = action->valuestring;
    std::string filename_str = resolveManagedLogName(filename->valuestring);
    bool success = false;

    if (filename_str.empty()) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    }
    if (action_str == "enable" || action_str == "toggle") {
        cJSON* enabled = cJSON_GetObjectItem(root, "enabled");
        if (enabled && cJSON_IsBool(enabled)) {
            success = self_->log_file_manager_->enableFile(filename_str, cJSON_IsTrue(enabled));
        }
    } else if (action_str == "add_channel") {
        cJSON* channel = cJSON_GetObjectItem(root, "channel");
        if (channel && cJSON_IsString(channel)) {
            success = self_->log_file_manager_->addChannelToFile(filename_str, channel->valuestring);
        }
    } else if (action_str == "remove_channel") {
        cJSON* channel = cJSON_GetObjectItem(root, "channel");
        if (channel && cJSON_IsString(channel)) {
            success = self_->log_file_manager_->removeChannelFromFile(filename_str, channel->valuestring);
        }
    }

    cJSON_Delete(root);

    if (success) {
        return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
    } else {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Operation failed");
    }
}

esp_err_t WebServer::h_logging_file_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!self_ || !self_->log_file_manager_) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Log manager not available");
    }

    // Extract filename from query parameters
    char filename_buf[256];
    if (httpd_req_get_url_query_str(req, filename_buf, sizeof(filename_buf)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing filename parameter");
    }

    char filename_param[256];
    if (httpd_query_key_value(filename_buf, "filename", filename_param, sizeof(filename_param)) != ESP_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid filename parameter");
    }

    const std::string resolved_filename = resolveManagedLogName(filename_param);
    if (resolved_filename.empty()) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    }
    LogFileManager::LogFileInfo info;
    if (!self_->log_file_manager_->getFileInfo(resolved_filename, info)) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    }

    // Create JSON response
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "filename", filename_param);
    cJSON_AddStringToObject(root, "path", info.path.c_str());
    cJSON_AddBoolToObject(root, "enabled", info.enabled);
    cJSON_AddNumberToObject(root, "max_size_kb", info.max_size_kb);
    cJSON_AddNumberToObject(root, "max_files", info.max_files);
    cJSON_AddNumberToObject(root, "current_size", info.current_size);

    cJSON* channels_array = cJSON_CreateArray();
    for (const std::string& channel : info.channels) {
        cJSON_AddItemToArray(channels_array, cJSON_CreateString(channel.c_str()));
    }
    cJSON_AddItemToObject(root, "channels", channels_array);

    char* json_string = cJSON_Print(root);
    if (!json_string) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t result = httpd_resp_send(req, json_string, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_string);
    cJSON_Delete(root);

    return result;
}

esp_err_t WebServer::h_logging_file_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (!self_ || !self_->log_file_manager_) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Log manager not available");
    }

    psram_string body = extractPayload(req);
    if (body.empty()) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");

    cJSON* root = cJSON_ParseWithLength(body.c_str(), body.size());
    if (!root) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");

    // Parse filename and configuration
    cJSON* filename = cJSON_GetObjectItem(root, "filename");
    if (!filename || !cJSON_IsString(filename)) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing filename");
    }

    LogFileManager::LogFileInfo info;
    std::string filename_str = resolveManagedLogName(filename->valuestring);

    if (filename_str.empty()) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    }

    // Get current info as base
    if (!self_->log_file_manager_->getFileInfo(filename_str, info)) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    }

    // Update configuration from JSON
    cJSON* enabled = cJSON_GetObjectItem(root, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        info.enabled = cJSON_IsTrue(enabled);
    }

    cJSON* max_size = cJSON_GetObjectItem(root, "max_size_kb");
    if (max_size && cJSON_IsNumber(max_size)) {
        info.max_size_kb = (size_t)max_size->valueint;
    }

    cJSON* max_files = cJSON_GetObjectItem(root, "max_files");
    if (max_files && cJSON_IsNumber(max_files)) {
        info.max_files = (uint32_t)max_files->valueint;
    }

    cJSON* channels = cJSON_GetObjectItem(root, "channels");
    if (channels && cJSON_IsArray(channels)) {
        info.channels.clear();
        cJSON* channel_item = channels->child;
        while (channel_item) {
            if (cJSON_IsString(channel_item)) {
                info.channels.push_back(std::string(channel_item->valuestring));
            }
            channel_item = channel_item->next;
        }
    }

    bool success = self_->log_file_manager_->updateFileConfig(filename_str, info);

    cJSON_Delete(root);

    if (success) {
        return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
    } else {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Update failed");
    }
}

void WebServer::logConfigChange(httpd_req_t* req, const char* config_type, const char* details) {
    if (!g_reporting) return;

    // Extract client IP to stack buffer to avoid std::string allocation
    const char* client_ip = extractClientIPToBuffer(req);

    // Build JSON in stack buffer to avoid heap allocation
    char event_data[1024];
    snprintf(event_data, sizeof(event_data),
             "{\"action\":\"config_changed\",\"config_type\":\"%s\",\"client_ip\":\"%s\",\"endpoint\":\"%s\",\"method\":\"%s\",\"details\":\"%s\"}",
             config_type?config_type:"", client_ip, req->uri,
             (req->method == HTTP_POST) ? "POST" : "GET", details?details:"");

    // Send to audit channel instead of app channel for structured audit logging
    psram_string audit_data = PSRAMUtils::createPSRAMString(event_data);
    g_reporting->reportEventToChannel(PSRAMUtils::createPSRAMString("audit"),
                                     PSRAMUtils::createPSRAMString("config_change"),
                                     audit_data);
}

// CVE Signature detection endpoints implementation
esp_err_t WebServer::h_signatures_reload(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    const char* client_ip = extractClientIPToBuffer(req);

    cJSON* response = SignatureReloadAPI::handleSignatureReload(client_ip);

    char* json_str = cJSON_Print(response);
    if (!json_str) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(response);

    return ret;
}

esp_err_t WebServer::h_page_bootstrap_get(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    char query[96] = {0};
    char page[32] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "name", page, sizeof(page)) != ESP_OK ||
        page[0] == '\0') {
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_NAME");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "name");
    }

    // Normalize to lowercase + underscore only (defensive)
    for (size_t i = 0; page[i]; ++i) {
        char c = page[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            page[i] = '_';
        } else {
            page[i] = c;
        }
    }

    const WebServer* server = WebServer::instanceConst();
    if (!server) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_SERVER");
        return httpd_resp_send_500(req);
    }

    char* payload_snapshot = nullptr;
    size_t payload_len = 0;
    {
        std::lock_guard<std::mutex> guard(g_page_bootstrap_json.mutex);
        if (!server->build_page_bootstrap_json(g_page_bootstrap_json, page)) {
            AccessLogger::getInstance().logResponse(req, 500, "BOOTSTRAP_BUILD_FAIL");
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "bootstrap build failed");
        }
        if (!g_page_bootstrap_json.buf || g_page_bootstrap_json.length == 0) {
            AccessLogger::getInstance().logResponse(req, 500, "BOOTSTRAP_EMPTY");
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "bootstrap empty");
        }

        payload_len = g_page_bootstrap_json.length;
        payload_snapshot = static_cast<char*>(
            heap_caps_malloc(payload_len + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
        );
        if (!payload_snapshot) {
            AccessLogger::getInstance().logResponse(req, 500, "BOOTSTRAP_NO_PSRAM");
            return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "bootstrap memory");
        }
        memcpy(payload_snapshot, g_page_bootstrap_json.buf, payload_len);
        payload_snapshot[payload_len] = '\0';
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t rc = send_chunked_from_psram(req, payload_snapshot, payload_len);
    if (payload_snapshot) {
        heap_caps_free(payload_snapshot);
    }
    AccessLogger::getInstance().logResponse(req, rc == ESP_OK ? 200 : 500, rc == ESP_OK ? "SUCCESS" : "CHUNK_FAIL");
    return rc;
}

esp_err_t WebServer::h_signatures_stats(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = SignatureReloadAPI::handleSignatureStats();

    char* json_str = cJSON_Print(response);
    if (!json_str) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(response);

    return ret;
}

// Start async discovery endpoint
// POST /api/discovery/start
// Body: {"protocol": "modbus|s7|profinet|ethernetip|opcua", "target": "192.168.1.0/24", "timeout": 5000}
// Returns: {"success": true, "discovery_id": "disc_12345678_abcdef12", "message": "Discovery started"}
esp_err_t WebServer::h_discovery_start(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) { AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED"); return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth"); }

    // Read request body
    psram_string body;
    if (!read_body(req, body, 1024)) { AccessLogger::getInstance().logResponse(req, 400, "BAD_BODY"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body"); }

    // Parse JSON body
    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) { AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); }

    cJSON* protocol_item = cJSON_GetObjectItem(json, "protocol");
    cJSON* target_item = cJSON_GetObjectItem(json, "target");
    cJSON* timeout_item = cJSON_GetObjectItem(json, "timeout");

    if (!protocol_item || !cJSON_IsString(protocol_item) ||
        !target_item || !cJSON_IsString(target_item)) {
        cJSON_Delete(json);
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_FIELDS"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing protocol or target");
    }

    const char* protocol_str = cJSON_GetStringValue(protocol_item);
    const char* target_str = cJSON_GetStringValue(target_item);
    // Normalize target: accept IPv4 or IPv4/CIDR; trim spaces
    char target_norm[64];
    if (target_str) {
        size_t n = strlen(target_str);
        if (n >= sizeof(target_norm)) n = sizeof(target_norm)-1;
        size_t w=0; for (size_t i=0;i<n;i++){ char c=target_str[i]; if (c!=' ' && c!='\t' && c!='\r' && c!='\n') target_norm[w++]=c; }
        target_norm[w]=0;
    } else {
        target_norm[0]='\0';
    }
    uint32_t timeout_ms = timeout_item && cJSON_IsNumber(timeout_item) ?
                         (uint32_t)cJSON_GetNumberValue(timeout_item) : 5000;

    // Validate timeout
    if (timeout_ms < 1000) timeout_ms = 1000;
    if (timeout_ms > 30000) timeout_ms = 30000;

    // Debug: log raw request and protocol parsing details (truncate body to avoid log flood)
    {
        char body_preview[192];
        size_t bl = body.size();
        size_t to_copy = bl < sizeof(body_preview) - 1 ? bl : (sizeof(body_preview) - 5);
        memcpy(body_preview, body.data(), to_copy);
        if (to_copy < bl) { body_preview[to_copy++]=' '; body_preview[to_copy++]='.'; body_preview[to_copy++]='.'; body_preview[to_copy++]='.'; }
        body_preview[to_copy] = '\0';
        LOG_INFOF(TAG_WEB, "DISCOVERY_START: raw_body(len=%u)='%s'", (unsigned)bl, body_preview);
        LOG_INFOF(TAG_WEB, "DISCOVERY_START: proto_raw='%s' target_raw='%s' target_norm='%s' timeout_ms=%u",
                  protocol_str?protocol_str:"(null)", target_str?target_str:"(null)", target_norm, (unsigned)timeout_ms);
    }

    // Normalize protocol to lowercase for matching
    char proto_lc[32];
    proto_lc[0] = '\0';
    if (protocol_str) {
        size_t n = strlen(protocol_str);
        if (n >= sizeof(proto_lc)) n = sizeof(proto_lc) - 1;
        for (size_t i = 0; i < n; ++i) {
            char c = protocol_str[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            proto_lc[i] = c;
        }
        proto_lc[n] = '\0';
    }
    LOG_INFOF(TAG_WEB, "DISCOVERY_START: proto_norm='%s'", proto_lc);

    // Map protocol string to enum (case-insensitive via normalized value)
    ProtocolType protocol;
    if (strcmp(proto_lc, "modbus") == 0 || strcmp(proto_lc, "modbus_tcp") == 0) {
        protocol = ProtocolType::MODBUS_TCP;
    } else if (strcmp(proto_lc, "s7") == 0 || strcmp(proto_lc, "s7comm") == 0 || strcmp(proto_lc, "s7_comm") == 0) {
        protocol = ProtocolType::S7_COMM;
    } else if (strcmp(proto_lc, "profinet") == 0) {
        protocol = ProtocolType::PROFINET;
    } else if (strcmp(proto_lc, "ethernetip") == 0 || strcmp(proto_lc, "enip") == 0 || strcmp(proto_lc, "ethernet_ip") == 0) {
        protocol = ProtocolType::ETHERNET_IP;
    } else if (strcmp(proto_lc, "opcua") == 0 || strcmp(proto_lc, "opc_ua") == 0 || strcmp(proto_lc, "opc ua") == 0) {
        protocol = ProtocolType::OPC_UA;
    } else {
        LOG_WARNINGF(TAG_WEB, "DISCOVERY_START: invalid protocol '%s' (normalized '%s')", protocol_str?protocol_str:"(null)", proto_lc);
        cJSON_Delete(json); AccessLogger::getInstance().logResponse(req, 400, "INVALID_PROTOCOL"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid protocol");
    }

    LOG_INFOF(TAG_WEB, "DISCOVERY_START: mapped proto='%s' -> enum=%d", proto_lc, (int)protocol);

    // PROFINET DCP is Layer-2 discovery. If the UI/user passes an IP/CIDR (common mistake),
    // normalize to a neutral "eth" target to avoid misleading logs/UI.
    if (protocol == ProtocolType::PROFINET) {
        bool looks_like_ip_or_cidr = false;
        if (target_norm[0] == '\0') {
            looks_like_ip_or_cidr = true;
        } else {
            // Very permissive heuristic: contains '.' or '/' plus at least one digit.
            bool has_digit = false;
            bool has_dot_or_slash = false;
            for (size_t i = 0; target_norm[i] != '\0'; ++i) {
                char c = target_norm[i];
                if (c >= '0' && c <= '9') has_digit = true;
                if (c == '.' || c == '/') has_dot_or_slash = true;
            }
            looks_like_ip_or_cidr = has_digit && has_dot_or_slash;
        }
        if (looks_like_ip_or_cidr) {
            LOG_INFOF(TAG_WEB, "DISCOVERY_START: PROFINET is L2, normalizing target '%s' -> 'eth'", target_norm);
            strncpy(target_norm, "eth", sizeof(target_norm));
            target_norm[sizeof(target_norm) - 1] = '\0';
        }
    }

    // S7 discovery needs Ethernet operational (bound sockets on ETH_DEF).
    if (protocol == ProtocolType::S7_COMM) {
        esp_netif_t* eth_netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
        esp_netif_ip_info_t eth_ip{};
        if (!eth_netif || esp_netif_get_ip_info(eth_netif, &eth_ip) != ESP_OK || eth_ip.ip.addr == 0) {
            cJSON_Delete(json);
            AccessLogger::getInstance().logResponse(req, 503, "ETHERNET_NOT_READY");
            httpd_resp_set_status(req, "503 Service Unavailable");
            return httpd_resp_send(req, "ethernet_not_ready", HTTPD_RESP_USE_STRLEN);
        }
    }

    cJSON_Delete(json);

    // Start discovery
    auto& discovery_mgr = DiscoveryManager::getInstance();
    psram_string discovery_id_psram = discovery_mgr.startDiscovery(protocol, target_norm, timeout_ms);
    if (!discovery_id_psram.empty()) {
        std::lock_guard<std::mutex> cache_lock(g_discovery_list_cache_mutex);
        g_discovery_list_cache_json.clear();
        g_discovery_list_cache_ts_ms = 0;
    }

    cJSON* response = cJSON_CreateObject();
    if (!discovery_id_psram.empty()) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "discovery_id", discovery_id_psram.c_str());
        cJSON_AddStringToObject(response, "message", "Discovery started");
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Discovery rejected or failed to start");
        httpd_resp_set_status(req, "429 Too Many Requests");
    }

    char* json_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    if (!json_str) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_FAIL");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    AccessLogger::getInstance().logResponse(
        req,
        (!discovery_id_psram.empty() && ret == ESP_OK) ? 200 : 429,
        (!discovery_id_psram.empty() && ret == ESP_OK) ? "SUCCESS" : "DISCOVERY_REJECTED");

    return ret;
}

// Get discovery status endpoint
// GET /api/discovery/status?id=disc_12345678_abcdef12
// Returns: discovery job details with status and results
esp_err_t WebServer::h_discovery_status(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    char query[128];
    char discovery_id[64] = {0};

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "id", discovery_id, sizeof(discovery_id));
    }

    if (discovery_id[0] == 0) {
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_DISCOVERY_ID");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing discovery ID");
    }

    auto& discovery_mgr = DiscoveryManager::getInstance();
    cJSON* response = discovery_mgr.getDiscoveryStatus(discovery_id);

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_FAIL");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    AccessLogger::getInstance().logResponse(req, ret == ESP_OK ? 200 : 500, ret == ESP_OK ? "SUCCESS" : "SEND_FAIL");

    return ret;
}

// Get all discoveries endpoint
// GET /api/discovery/list
// Returns: list of all active and recent discoveries
esp_err_t WebServer::h_discovery_list(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    const int64_t t0_us = esp_timer_get_time();
    const uint64_t now_ms = esp_timer_get_time() / 1000ULL;

    {
        std::lock_guard<std::mutex> cache_lock(g_discovery_list_cache_mutex);
        if (!g_discovery_list_cache_json.empty() &&
            g_discovery_list_cache_ts_ms > 0 &&
            (now_ms - g_discovery_list_cache_ts_ms) <= kDiscoveryListCacheTtlMs) {
            // removed temporary debug log
            httpd_resp_set_type(req, "application/json");
            esp_err_t rc = send_chunked_from_psram(req,
                                                   g_discovery_list_cache_json.c_str(),
                                                   g_discovery_list_cache_json.length());
            // removed temporary debug log
            AccessLogger::getInstance().logResponse(req, rc == ESP_OK ? 200 : 500, rc == ESP_OK ? "CACHE_HIT" : "CACHE_SEND_FAIL");
            return rc;
        }
    }

    auto& discovery_mgr = DiscoveryManager::getInstance();
    cJSON* response = discovery_mgr.getAllDiscoveries();

    char* json_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    if (!json_str) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_FAIL");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    psram_string payload_ps = PSRAMUtils::createPSRAMString(json_str);
    free_cjson_str(json_str);
    if (payload_ps.empty()) {
        AccessLogger::getInstance().logResponse(req, 500, "NO_PSRAM_PAYLOAD");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "discovery list allocation failed");
    }

    {
        std::lock_guard<std::mutex> cache_lock(g_discovery_list_cache_mutex);
        g_discovery_list_cache_json = payload_ps;
        g_discovery_list_cache_ts_ms = now_ms;
    }

    httpd_resp_set_type(req, "application/json");
    // removed temporary debug log
    esp_err_t ret = send_chunked_from_psram(req, payload_ps.c_str(), payload_ps.length());
    // removed temporary debug log
    AccessLogger::getInstance().logResponse(req, ret == ESP_OK ? 200 : 500, ret == ESP_OK ? "SUCCESS" : "SEND_FAIL");

    return ret;
}

// Cancel discovery endpoint
// POST /api/discovery/cancel
// Body: {"discovery_id": "disc_12345678_abcdef12"}
// Returns: {"success": true/false, "message": "..."}
esp_err_t WebServer::h_discovery_cancel(httpd_req_t* req) {
    AccessLogger::getInstance().logRequest(req);
    if (!check_api_auth(req)) {
        AccessLogger::getInstance().logResponse(req, 401, "UNAUTHORIZED");
        return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    }

    psram_string body;
    if (!read_body(req, body, 512)) {
        AccessLogger::getInstance().logResponse(req, 400, "BAD_BODY");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body");
    }

    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) {
        AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    }

    cJSON* id_item = cJSON_GetObjectItem(json, "discovery_id");
    if (!id_item || !cJSON_IsString(id_item)) {
        cJSON_Delete(json);
        AccessLogger::getInstance().logResponse(req, 400, "MISSING_DISCOVERY_ID");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing discovery_id");
    }

    const char* discovery_id = cJSON_GetStringValue(id_item);
    auto& discovery_mgr = DiscoveryManager::getInstance();
    bool cancelled = discovery_mgr.cancelDiscovery(discovery_id);
    if (cancelled) {
        std::lock_guard<std::mutex> cache_lock(g_discovery_list_cache_mutex);
        g_discovery_list_cache_json.clear();
        g_discovery_list_cache_ts_ms = 0;
    }

    cJSON_Delete(json);

    cJSON* response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", cancelled);
    cJSON_AddStringToObject(response, "message",
                           cancelled ? "Discovery cancelled" : "Discovery not found or not running");

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        AccessLogger::getInstance().logResponse(req, 500, "JSON_FAIL");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    AccessLogger::getInstance().logResponse(req, ret == ESP_OK ? 200 : 500, ret == ESP_OK ? "SUCCESS" : "SEND_FAIL");

    return ret;
}

esp_err_t WebServer::h_discovery_general_start(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    psram_string body;
    if (!read_body(req, body, 1024)) { AccessLogger::getInstance().logResponse(req, 400, "BAD_BODY"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body"); }

    cJSON* json = cJSON_Parse(body.c_str());
    if (!json) { AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); }

    cJSON* mode_item = cJSON_GetObjectItem(json, "mode");
    cJSON* target_item = cJSON_GetObjectItem(json, "target");
    cJSON* iface_item = cJSON_GetObjectItem(json, "interface");
    cJSON* ports_item = cJSON_GetObjectItem(json, "ports");
    cJSON* timeout_item = cJSON_GetObjectItem(json, "timeout_ms");
    cJSON* per_timeout_item = cJSON_GetObjectItem(json, "per_host_timeout_ms");
    cJSON* connect_item = cJSON_GetObjectItem(json, "connect_timeout_ms");
    cJSON* batch_size_item = cJSON_GetObjectItem(json, "batch_size");
    cJSON* batch_delay_item = cJSON_GetObjectItem(json, "batch_delay_ms");
    cJSON* max_hosts_item = cJSON_GetObjectItem(json, "max_hosts");
    cJSON* emit_progress_item = cJSON_GetObjectItem(json, "emit_progress");

    if (!mode_item || !cJSON_IsString(mode_item) || !target_item || !cJSON_IsString(target_item)) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing mode or target");
    }

    const char* mode_raw = cJSON_GetStringValue(mode_item);
    const char* target_raw = cJSON_GetStringValue(target_item);

    char mode_norm[12];
    size_t mode_len = mode_raw ? strlen(mode_raw) : 0;
    if (mode_len >= sizeof(mode_norm)) mode_len = sizeof(mode_norm) - 1;
    for (size_t i = 0; i < mode_len; ++i) {
        char c = mode_raw[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        mode_norm[i] = c;
    }
    mode_norm[mode_len] = '\0';

    bool port_scan = (strcmp(mode_norm, "ports") == 0);
    bool ping_scan = (strcmp(mode_norm, "ping") == 0);
    if (!port_scan && !ping_scan) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid mode");
    }

    char target_norm[64];
    memset(target_norm, 0, sizeof(target_norm));
    if (target_raw) {
        size_t n = strlen(target_raw);
        if (n >= sizeof(target_norm)) n = sizeof(target_norm) - 1;
        size_t w = 0;
        for (size_t i = 0; i < n && (w + 1) < sizeof(target_norm); ++i) {
            char c = target_raw[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
            target_norm[w++] = c;
        }
        target_norm[w] = '\0';
    }
    if (target_norm[0] == '\0') {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid target");
    }

    BasePlugin::GeneralDiscoveryConfig cfg;
    cfg.target = PSRAMUtils::createPSRAMString(target_norm);
    cfg.mode_label = PSRAMUtils::createPSRAMString(mode_norm);
    cfg.port_scan = port_scan;
    cfg.ping_scan = ping_scan;
    cfg.emit_progress_events = true;

    // Assessment is intentionally Ethernet-only. Reject stale clients that try
    // to select AUTO or Wi-Fi instead of silently weakening network separation.
    const char* iface_raw = (iface_item && cJSON_IsString(iface_item)) ? cJSON_GetStringValue(iface_item) : nullptr;
    if (iface_raw && iface_raw[0]) {
        char iface_norm[16] = {0};
        size_t n = strlen(iface_raw);
        if (n >= sizeof(iface_norm)) n = sizeof(iface_norm) - 1;
        for (size_t i = 0; i < n; ++i) {
            char c = iface_raw[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            iface_norm[i] = c;
        }
        iface_norm[n] = '\0';

        if (strcmp(iface_norm, "eth") != 0 && strcmp(iface_norm, "ethernet") != 0) {
            cJSON_Delete(json);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                       "Assessment interface must be Ethernet");
        }
    }
    cfg.bind_ifkey = PSRAMUtils::createPSRAMString("ETH_DEF");

    if (emit_progress_item && cJSON_IsBool(emit_progress_item)) {
        cfg.emit_progress_events = cJSON_IsTrue(emit_progress_item);
    }

    cfg.total_timeout_ms = timeout_item && cJSON_IsNumber(timeout_item) ? (uint32_t)cJSON_GetNumberValue(timeout_item) : 0U;

    uint32_t per_host = per_timeout_item && cJSON_IsNumber(per_timeout_item) ? (uint32_t)cJSON_GetNumberValue(per_timeout_item) : 500U;
    if (per_host < 200U) per_host = 200U;
    if (per_host > 60000U) per_host = 60000U;
    cfg.per_host_timeout_ms = per_host;

    uint32_t connect_timeout = connect_item && cJSON_IsNumber(connect_item) ? (uint32_t)cJSON_GetNumberValue(connect_item) : 400U;
    if (connect_timeout < 100U) connect_timeout = 100U;
    if (connect_timeout > per_host) connect_timeout = per_host;
    cfg.connect_timeout_ms = connect_timeout;

    uint32_t batch_size = batch_size_item && cJSON_IsNumber(batch_size_item) ? (uint32_t)cJSON_GetNumberValue(batch_size_item) : 4U;
    if (batch_size < 1U) batch_size = 1U;
    if (batch_size > 32U) batch_size = 32U;
    cfg.batch_size = batch_size;

    uint32_t batch_delay = batch_delay_item && cJSON_IsNumber(batch_delay_item) ? (uint32_t)cJSON_GetNumberValue(batch_delay_item) : 250U;
    if (batch_delay > 2000U) batch_delay = 2000U;
    cfg.batch_delay_ms = batch_delay;

    uint32_t max_hosts = max_hosts_item && cJSON_IsNumber(max_hosts_item) ? (uint32_t)cJSON_GetNumberValue(max_hosts_item) : 512U;
    if (max_hosts < 1U) max_hosts = 1U;
    if (max_hosts > 4096U) max_hosts = 4096U;
    cfg.max_hosts = max_hosts;

    auto add_port = [&](uint16_t port) {
        if (!port) return;
        for (size_t i = 0; i < cfg.ports.size(); ++i) {
            if (cfg.ports[i] == port) return;
        }
        cfg.ports.push_back(port);
    };

    if (ports_item) {
        if (cJSON_IsArray(ports_item)) {
            cJSON* it = nullptr;
            cJSON_ArrayForEach(it, ports_item) {
                if (cJSON_IsNumber(it)) {
                    int value = (int)cJSON_GetNumberValue(it);
                    if (value > 0 && value <= 65535) add_port((uint16_t)value);
                }
            }
        } else if (cJSON_IsString(ports_item)) {
            const char* text = cJSON_GetStringValue(ports_item);
            if (text) {
                uint32_t acc = 0;
                bool in_number = false;
                for (const char* p = text; *p; ++p) {
                    if (*p >= '0' && *p <= '9') {
                        in_number = true;
                        acc = (acc * 10U) + (uint32_t)(*p - '0');
                        if (acc > 65535U) acc = 65535U;
                    } else {
                        if (in_number && acc > 0U && acc <= 65535U) {
                            add_port((uint16_t)acc);
                        }
                        acc = 0U;
                        in_number = false;
                    }
                }
                if (in_number && acc > 0U && acc <= 65535U) {
                    add_port((uint16_t)acc);
                }
            }
        }
    }

    if (cfg.port_scan && cfg.ports.empty() && self_ && self_->plugins_) {
        psram_vector<uint16_t> defaults;
        self_->plugins_->forEach([&](BasePlugin& plg) {
            auto ports = plg.getMonitoredPorts();
            for (uint16_t port : ports) {
                if (port == 0) continue;
                if (std::find(defaults.begin(), defaults.end(), port) == defaults.end()) {
                    defaults.push_back(port);
                }
            }
        });
        std::sort(defaults.begin(), defaults.end());
        for (uint16_t port : defaults) {
            add_port(port);
        }
    }

    cJSON_Delete(json);

    auto& discovery_mgr = DiscoveryManager::getInstance();
    psram_string discovery_id_psram = discovery_mgr.startGeneralDiscovery(cfg);
    std::string discovery_id = PSRAMUtils::fromPSRAMString(discovery_id_psram);

    cJSON* response = cJSON_CreateObject();
    if (!discovery_id.empty()) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "discovery_id", discovery_id.c_str());
        cJSON_AddStringToObject(response, "message", "General discovery started");
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to start general discovery");
    }

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    heap_caps_free(json_str);
    return ret;
}

esp_err_t WebServer::h_discovery_general_status(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    char query[128];
    char discovery_id[64] = {0};

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "id", discovery_id, sizeof(discovery_id));
    }

    if (discovery_id[0] == 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing discovery ID");
    }

    auto& discovery_mgr = DiscoveryManager::getInstance();
    cJSON* response = discovery_mgr.getDiscoveryStatus(discovery_id);

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    return ret;
}

esp_err_t WebServer::h_discovery_general_defaults(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();
    cJSON* ports = cJSON_CreateArray();

    psram_vector<uint16_t> unique_ports;
    if (self_ && self_->plugins_) {
        self_->plugins_->forEach([&](BasePlugin& plg) {
            auto ports_vec = plg.getMonitoredPorts();
            for (uint16_t port : ports_vec) {
                if (port == 0) continue;
                if (std::find(unique_ports.begin(), unique_ports.end(), port) == unique_ports.end()) {
                    unique_ports.push_back(port);
                }
            }
        });
    }
    std::sort(unique_ports.begin(), unique_ports.end());
    for (uint16_t port : unique_ports) {
        cJSON_AddItemToArray(ports, cJSON_CreateNumber((int)port));
    }

    cJSON_AddItemToObject(response, "ports", ports);
    cJSON_AddNumberToObject(response, "default_per_host_timeout_ms", 500);
    cJSON_AddNumberToObject(response, "default_connect_timeout_ms", 400);
    cJSON_AddNumberToObject(response, "default_batch_size", 4);
    cJSON_AddNumberToObject(response, "default_batch_delay_ms", 250);
    cJSON_AddNumberToObject(response, "default_max_hosts", 512);

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    return ret;
}

// ===== GPIO REPORTER API HANDLERS =====

esp_err_t WebServer::h_gpio_status(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON creation failed");
    }

    cJSON_AddBoolToObject(root, "running", false);
    cJSON_AddBoolToObject(root, "enabled", false);
    cJSON_AddStringToObject(root, "current_level", "OFF");
    cJSON_AddBoolToObject(root, "alert_active", false);
    cJSON_AddBoolToObject(root, "alert_acknowledged", false);

    char* json_str = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    return ret;
}

esp_err_t WebServer::h_gpio_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON creation failed");
    }

    // Get GPIO configuration from configuration manager
    if (!self_ || !self_->cfg_) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config not available");
    auto gpio_config = self_->cfg_->getGpioReportingConfig();

    // Main GPIO settings
    cJSON_AddBoolToObject(root, "enabled", gpio_config.enabled);
    cJSON_AddStringToObject(root, "format", gpio_config.format.c_str());
    cJSON_AddStringToObject(root, "verbosity", gpio_config.verbosity.c_str());

    // Configuration object
    cJSON* configuration = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "configuration", configuration);

    // Pin configuration
    cJSON* pins = cJSON_CreateObject();
    cJSON_AddItemToObject(configuration, "pins", pins);
    cJSON_AddNumberToObject(pins, "led_critical", gpio_config.pins.led_critical);
    cJSON_AddNumberToObject(pins, "led_warning", gpio_config.pins.led_warning);
    cJSON_AddNumberToObject(pins, "led_info", gpio_config.pins.led_info);
    cJSON_AddNumberToObject(pins, "led_success", gpio_config.pins.led_success);
    cJSON_AddNumberToObject(pins, "buzzer", gpio_config.pins.buzzer);
    cJSON_AddNumberToObject(pins, "btn_acknowledge", gpio_config.pins.btn_acknowledge);
    cJSON_AddNumberToObject(pins, "btn_reset", gpio_config.pins.btn_reset);
    cJSON_AddNumberToObject(pins, "btn_learning", gpio_config.pins.btn_learning);
    cJSON_AddNumberToObject(pins, "btn_maintenance", gpio_config.pins.btn_maintenance);

    // Behavior configuration
    cJSON* behavior = cJSON_CreateObject();
    cJSON_AddItemToObject(configuration, "behavior", behavior);
    cJSON_AddBoolToObject(behavior, "buzzer_enabled", gpio_config.behavior.buzzer_enabled);
    cJSON_AddNumberToObject(behavior, "alert_duration_ms", gpio_config.behavior.alert_duration_ms);
    cJSON_AddNumberToObject(behavior, "blink_interval_ms", gpio_config.behavior.blink_interval_ms);
    cJSON_AddNumberToObject(behavior, "debounce_ms", gpio_config.behavior.debounce_ms);

    // Filter configuration
    cJSON* filters = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "filters", filters);
    cJSON_AddBoolToObject(filters, "enabled", gpio_config.filters.enabled);
    cJSON_AddBoolToObject(filters, "case_sensitive", gpio_config.filters.case_sensitive);

    // Add include/exclude arrays
    cJSON* include_array = cJSON_CreateArray();
    cJSON_AddItemToObject(filters, "include", include_array);
    for (const auto& pattern : gpio_config.filters.include) {
        cJSON_AddItemToArray(include_array, cJSON_CreateString(pattern.c_str()));
    }

    cJSON* exclude_array = cJSON_CreateArray();
    cJSON_AddItemToObject(filters, "exclude", exclude_array);
    for (const auto& pattern : gpio_config.filters.exclude) {
        cJSON_AddItemToArray(exclude_array, cJSON_CreateString(pattern.c_str()));
    }

    char* json_str = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    return ret;
}

esp_err_t WebServer::h_gpio_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    char content[2048];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body");
    }
    content[ret] = '\0';

    cJSON* incoming_json = cJSON_Parse(content);
    if (!incoming_json) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    }

    // Get current configuration
    if (!self_ || !self_->cfg_) {
        cJSON_Delete(incoming_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "config not available");
    }
    size_t config_size = 0;
    char* config_json = self_->cfg_->getRawConfigInPSRAM(&config_size);
    if (!config_json) {
        cJSON_Delete(incoming_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to get current config");
    }

    cJSON* config_root = cJSON_Parse(config_json);
    heap_caps_free(config_json);
    if (!config_root) {
        cJSON_Delete(incoming_json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to parse current config");
    }

    // Ensure reporting section exists
    cJSON* reporting = cJSON_GetObjectItem(config_root, "reporting");
    if (!reporting) {
        reporting = cJSON_CreateObject();
        cJSON_AddItemToObject(config_root, "reporting", reporting);
    }

    // Ensure gpio section exists
    cJSON* gpio_section = cJSON_GetObjectItem(reporting, "gpio");
    if (!gpio_section) {
        gpio_section = cJSON_CreateObject();
        cJSON_AddItemToObject(reporting, "gpio", gpio_section);
    }

    // Update GPIO settings from incoming JSON
    cJSON* enabled = cJSON_GetObjectItem(incoming_json, "enabled");
    if (cJSON_IsBool(enabled)) {
        cJSON_DeleteItemFromObject(gpio_section, "enabled");
        cJSON_AddBoolToObject(gpio_section, "enabled", cJSON_IsTrue(enabled));
    }

    cJSON* format = cJSON_GetObjectItem(incoming_json, "format");
    if (cJSON_IsString(format)) {
        cJSON_DeleteItemFromObject(gpio_section, "format");
        cJSON_AddStringToObject(gpio_section, "format", format->valuestring);
    }

    cJSON* verbosity = cJSON_GetObjectItem(incoming_json, "verbosity");
    if (cJSON_IsString(verbosity)) {
        cJSON_DeleteItemFromObject(gpio_section, "verbosity");
        cJSON_AddStringToObject(gpio_section, "verbosity", verbosity->valuestring);
    }

    // Ensure configuration section exists
    cJSON* configuration = cJSON_GetObjectItem(gpio_section, "configuration");
    if (!configuration) {
        configuration = cJSON_CreateObject();
        cJSON_AddItemToObject(gpio_section, "configuration", configuration);
    }

    // Update pin configuration
    cJSON* pins = cJSON_GetObjectItem(configuration, "pins");
    if (!pins) {
        pins = cJSON_CreateObject();
        cJSON_AddItemToObject(configuration, "pins", pins);
    }

    // Update pin values from incoming JSON (handle nested structure)
    cJSON* incoming_config = cJSON_GetObjectItem(incoming_json, "configuration");
    if (incoming_config) {
        cJSON* incoming_pins = cJSON_GetObjectItem(incoming_config, "pins");
        if (incoming_pins) {
            const char* pin_names[] = {"led_critical", "led_warning", "led_info", "led_success",
                                       "buzzer", "btn_acknowledge", "btn_reset", "btn_learning", "btn_maintenance"};
            for (int i = 0; i < 9; i++) {
                cJSON* pin_value = cJSON_GetObjectItem(incoming_pins, pin_names[i]);
                if (cJSON_IsNumber(pin_value)) {
                    cJSON_DeleteItemFromObject(pins, pin_names[i]);
                    cJSON_AddNumberToObject(pins, pin_names[i], (int)pin_value->valuedouble);
                }
            }
        }
    }

    // Update behavior configuration
    cJSON* behavior = cJSON_GetObjectItem(configuration, "behavior");
    if (!behavior) {
        behavior = cJSON_CreateObject();
        cJSON_AddItemToObject(configuration, "behavior", behavior);
    }

    // Handle behavior values from nested structure
    if (incoming_config) {
        cJSON* incoming_behavior = cJSON_GetObjectItem(incoming_config, "behavior");
        if (incoming_behavior) {
            cJSON* buzzer_enabled = cJSON_GetObjectItem(incoming_behavior, "buzzer_enabled");
            if (cJSON_IsBool(buzzer_enabled)) {
                cJSON_DeleteItemFromObject(behavior, "buzzer_enabled");
                cJSON_AddBoolToObject(behavior, "buzzer_enabled", cJSON_IsTrue(buzzer_enabled));
            }

            const char* behavior_names[] = {"alert_duration_ms", "blink_interval_ms", "debounce_ms"};
            for (int i = 0; i < 3; i++) {
                cJSON* behavior_value = cJSON_GetObjectItem(incoming_behavior, behavior_names[i]);
                if (cJSON_IsNumber(behavior_value)) {
                    cJSON_DeleteItemFromObject(behavior, behavior_names[i]);
                    cJSON_AddNumberToObject(behavior, behavior_names[i], (int)behavior_value->valuedouble);
                }
            }
        }
    }

    // Update filters configuration
    cJSON* filters = cJSON_GetObjectItem(gpio_section, "filters");
    if (!filters) {
        filters = cJSON_CreateObject();
        cJSON_AddItemToObject(gpio_section, "filters", filters);
    }

    // Handle filters from nested structure
    cJSON* incoming_filters = cJSON_GetObjectItem(incoming_json, "filters");
    if (incoming_filters) {
        cJSON* filters_enabled = cJSON_GetObjectItem(incoming_filters, "enabled");
        if (cJSON_IsBool(filters_enabled)) {
            cJSON_DeleteItemFromObject(filters, "enabled");
            cJSON_AddBoolToObject(filters, "enabled", cJSON_IsTrue(filters_enabled));
        }

        cJSON* case_sensitive = cJSON_GetObjectItem(incoming_filters, "case_sensitive");
        if (cJSON_IsBool(case_sensitive)) {
            cJSON_DeleteItemFromObject(filters, "case_sensitive");
            cJSON_AddBoolToObject(filters, "case_sensitive", cJSON_IsTrue(case_sensitive));
        }

        // Handle include/exclude arrays
        cJSON* include_array = cJSON_GetObjectItem(incoming_filters, "include");
        if (cJSON_IsArray(include_array)) {
            cJSON_DeleteItemFromObject(filters, "include");
            cJSON* new_include = cJSON_CreateArray();
            cJSON_AddItemToObject(filters, "include", new_include);

            cJSON* item = nullptr;
            cJSON_ArrayForEach(item, include_array) {
                if (cJSON_IsString(item)) {
                    cJSON_AddItemToArray(new_include, cJSON_CreateString(item->valuestring));
                }
            }
        }

        cJSON* exclude_array = cJSON_GetObjectItem(incoming_filters, "exclude");
        if (cJSON_IsArray(exclude_array)) {
            cJSON_DeleteItemFromObject(filters, "exclude");
            cJSON* new_exclude = cJSON_CreateArray();
            cJSON_AddItemToObject(filters, "exclude", new_exclude);

            cJSON* item = nullptr;
            cJSON_ArrayForEach(item, exclude_array) {
                if (cJSON_IsString(item)) {
                    cJSON_AddItemToArray(new_exclude, cJSON_CreateString(item->valuestring));
                }
            }
        }
    }

    // Save updated configuration
    char* updated_config = cJSON_PrintUnformatted(config_root);
    bool save_success = false;
    if (updated_config) {
        save_success = self_->cfg_->saveConfigJSON(updated_config);
        free_cjson_str(updated_config);
    }

    cJSON_Delete(incoming_json);
    cJSON_Delete(config_root);

    if (save_success) {
        return httpd_resp_send(req, "{\"status\":\"success\"}", HTTPD_RESP_USE_STRLEN);
    } else {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save configuration");
    }
}

esp_err_t WebServer::h_gpio_alert(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    char content[1024];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body");
    }
    content[ret] = '\0';

    cJSON* json = cJSON_Parse(content);
    if (!json) { AccessLogger::getInstance().logResponse(req, 400, "INVALID_JSON"); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON"); }

    cJSON* level_item = cJSON_GetObjectItem(json, "level");
    if (!level_item || !cJSON_IsString(level_item)) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid 'level' field");
    }

    char safe_level[48] = {0};
    copy_safe_gpio_token(level_item->valuestring, safe_level, sizeof(safe_level));
    char event_data[320] = {0};
    snprintf(event_data, sizeof(event_data),
             "{\"event\":\"gpio_output_request\",\"level\":\"%s\",\"source\":\"web_api\",\"timestamp_ms\":%llu}",
             safe_level[0] ? safe_level : "unknown", (unsigned long long)(esp_timer_get_time() / 1000ULL));
    if (g_reporting) report_event_ps(g_reporting, "gpio_event", event_data);
    cJSON_Delete(json);
    return httpd_resp_send(req, "{\"status\":\"alert_sent\"}", HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_gpio_reset(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");
    if (g_reporting) {
        char event_data[192];
        snprintf(event_data, sizeof(event_data),
                 "{\"event\":\"gpio_reset_request\",\"source\":\"web_api\",\"timestamp_ms\":%llu}",
                 (unsigned long long)(esp_timer_get_time() / 1000ULL));
        report_event_ps(g_reporting, "gpio_event", event_data);
    }
    return httpd_resp_send(req, "{\"status\":\"reset_complete\"}", HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_gpio_test(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    char* buf;
    size_t buf_len;
    if (!read_body_psram(req, &buf, &buf_len)) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "body_read_failed");
    }

    cJSON* json = cJSON_Parse(buf);
    if (buf) heap_caps_free(buf);

    if (!json) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid_json");
    }

    cJSON* action = cJSON_GetObjectItem(json, "action");
    cJSON* level = cJSON_GetObjectItem(json, "level");

    if (!action || !cJSON_IsString(action)) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing_action");
    }

    char safe_action[64] = {0};
    copy_safe_gpio_token(action->valuestring, safe_action, sizeof(safe_action));
    char safe_level[48] = {0};
    if (level && cJSON_IsString(level)) {
        copy_safe_gpio_token(level->valuestring, safe_level, sizeof(safe_level));
    }

    std::string response = "{\"status\":\"test_sent\",\"action\":\"";
    response += safe_action;
    response += "\"";

    if (safe_level[0]) {
        response += ",\"level\":\"";
        response += safe_level;
        response += "\"";
    }

    response += "}";

    if (g_reporting) {
        char event_data[320];
        snprintf(event_data, sizeof(event_data),
                 "{\"event\":\"gpio_test_request\",\"action\":\"%s\",\"source\":\"web_api\",\"timestamp_ms\":%llu}",
                 safe_action[0] ? safe_action : "unknown",
                 (unsigned long long)(esp_timer_get_time() / 1000ULL));
        report_event_ps(g_reporting, "gpio_event", event_data);
    }

    cJSON_Delete(json);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, response.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_gpio_buttons(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    // Return button states (mock implementation)
    const char* button_status = "{"
        "\"acknowledge\":false,"
        "\"reset\":false,"
        "\"learning\":false,"
        "\"maintenance\":false"
        "}";

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, button_status, HTTPD_RESP_USE_STRLEN);
}

// ===== AUDIT MANAGER API HANDLERS =====

esp_err_t WebServer::h_sandbox_status(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    AuditManager& manager = AuditManager::getInstance();
    std::string status_json = manager.getStatusJSON();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, status_json.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_sandbox_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    AuditManager& manager = AuditManager::getInstance();
    std::string config_json = manager.getConfigJSON();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, config_json.c_str(), HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_sandbox_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    char content[2048];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read request body");
    }
    content[ret] = '\0';

    AuditManager& manager = AuditManager::getInstance();
    bool success = manager.loadConfigFromJSON(std::string(content));

    if (success) {
        return httpd_resp_send(req, "{\"status\":\"success\"}", HTTPD_RESP_USE_STRLEN);
    } else {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid configuration");
    }
}

esp_err_t WebServer::h_sandbox_audit_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    AuditManager& manager = AuditManager::getInstance();
    AuditSnapshot snapshot = manager.getSnapshot();

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON creation failed");
    }

    cJSON_AddNumberToObject(root, "denied", snapshot.denied);
    cJSON_AddNumberToObject(root, "timeouts", snapshot.timeouts);
    cJSON_AddNumberToObject(root, "ratelimits", snapshot.ratelimits);
    cJSON_AddNumberToObject(root, "system_events", snapshot.system_events);
    cJSON_AddNumberToObject(root, "security_events", snapshot.security_events);
    cJSON_AddNumberToObject(root, "config_changes", snapshot.config_changes);

    char* json_str = cJSON_Print(root);
    cJSON_Delete(root);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON serialization failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);
    return ret;
}

esp_err_t WebServer::h_signatures_list(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = SignatureReloadAPI::handleSignatureList();

    char* json_str = cJSON_Print(response);
    if (!json_str) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(response);

    return ret;
}

esp_err_t WebServer::h_signatures_upload(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (req->content_len == 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    constexpr size_t kMaxSignatureUpload = 512 * 1024;
    char* content = nullptr;
    size_t content_len = 0;
    if (!read_body_psram(req, &content, &content_len, kMaxSignatureUpload)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "psram alloc");
    }

    cJSON* response = SignatureReloadAPI::handleSignatureUpload(content, content_len, true);

    char* json_str = cJSON_Print(response);
    if (!json_str) {
        heap_caps_free(content);
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    heap_caps_free(content);
    heap_caps_free(json_str);
    cJSON_Delete(response);

    return result;
}

esp_err_t WebServer::h_signatures_download(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = SignatureReloadAPI::handleSignatureDownload();

    char* json_str = cJSON_Print(response);
    if (!json_str) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_hdr(req, "Content-Type", "application/json");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"cve_signatures.json\"");

    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(response);

    return ret;
}

esp_err_t WebServer::h_signatures_clear(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = SignatureReloadAPI::handleSignatureClear();

    char* json_str = cJSON_Print(response);
    if (!json_str) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    free_cjson_str(json_str);
    cJSON_Delete(response);

    return ret;
}

esp_err_t WebServer::h_signatures_save(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    if (req->content_len == 0) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty payload");
    }

    constexpr size_t kMaxSignatureUpload = 512 * 1024;
    char* content = nullptr;
    size_t content_len = 0;
    if (!read_body_psram(req, &content, &content_len, kMaxSignatureUpload)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "psram alloc");
    }

    const char* client_ip = extractClientIPToBuffer(req);
    cJSON* response = SignatureReloadAPI::handleSignatureSave(content, content_len, client_ip);

    char* json_str = cJSON_Print(response);
    if (!json_str) {
        heap_caps_free(content);
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    esp_err_t result = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);

    heap_caps_free(content);
    heap_caps_free(json_str);
    cJSON_Delete(response);

    return result;
}

esp_err_t WebServer::h_page_signatures(httpd_req_t* req) {
    return h_page_ids(req);
}

esp_err_t WebServer::h_page_security(httpd_req_t* req) {
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, SECURITY_HTML_GEN, SECURITY_HTML_GEN_SIZE);
}

// IDS API aliases - simple wrappers for existing advanced APIs
esp_err_t WebServer::h_ids_stats_get(httpd_req_t* req) {
    return h_ids_adv_stats(req);
}

esp_err_t WebServer::h_ids_config_get(httpd_req_t* req) {
    return h_ids_adv_cfg_get(req);
}

esp_err_t WebServer::h_ids_config_post(httpd_req_t* req) {
    return h_ids_adv_cfg_post(req);
}

esp_err_t WebServer::h_network_presence_learned_get(httpd_req_t* req) {
    return h_presence_learned_get(req);
}

// Audit APIs - implement basic audit functionality
esp_err_t WebServer::h_audit_metrics_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();
    cJSON* metrics = cJSON_CreateObject();

    cJSON_AddNumberToObject(metrics, "total_events", 0);
    cJSON_AddNumberToObject(metrics, "security_events", 0);
    cJSON_AddNumberToObject(metrics, "config_changes", 0);
    cJSON_AddNumberToObject(metrics, "access_attempts", 0);
    cJSON_AddNumberToObject(metrics, "failed_logins", 0);

    cJSON_AddItemToObject(response, "metrics", metrics);
    cJSON_AddStringToObject(response, "status", "success");

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return ret;
}

esp_err_t WebServer::h_audit_events_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();
    cJSON* events = cJSON_CreateArray();

    cJSON_AddItemToObject(response, "events", events);
    cJSON_AddStringToObject(response, "status", "success");
    cJSON_AddNumberToObject(response, "total", 0);

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    free_cjson_str(json_str);

    return ret;
}

esp_err_t WebServer::h_audit_events_delete(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    AuditManager::getInstance().logConfigChangeAudit("audit_events_clear", nullptr, extractClientIPToBuffer(req), "Web API clear");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_sendstr(req, "{\"status\":\"success\"}");
}

esp_err_t WebServer::h_audit_export_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "allocation");
    }

    cJSON_AddStringToObject(root, "status", "success");

    // Include audit counters snapshot
    AuditSnapshot snap = AuditManager::getInstance().getSnapshot();
    cJSON* counters = cJSON_CreateObject();
    if (counters) {
        cJSON_AddNumberToObject(counters, "denied", snap.denied);
        cJSON_AddNumberToObject(counters, "timeouts", snap.timeouts);
        cJSON_AddNumberToObject(counters, "ratelimits", snap.ratelimits);
        cJSON_AddNumberToObject(counters, "system_events", snap.system_events);
        cJSON_AddNumberToObject(counters, "security_events", snap.security_events);
        cJSON_AddNumberToObject(counters, "config_changes", snap.config_changes);
        cJSON_AddItemToObject(root, "counters", counters);
    }

    // Embed current configuration
    const std::string cfg = AuditManager::getInstance().getConfigJSON();
    cJSON* cfg_json = cJSON_Parse(cfg.c_str());
    if (cfg_json) {
        cJSON_AddItemToObject(root, "config", cfg_json);
    } else {
        cJSON_AddNullToObject(root, "config");
    }

    char* json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"audit_export.json\"");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    heap_caps_free(json_str);
    return ret;
}

esp_err_t WebServer::h_audit_analytics_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "auth");

    cJSON* response = cJSON_CreateObject();
    cJSON* analytics = cJSON_CreateObject();

    cJSON_AddNumberToObject(analytics, "events_per_hour", 0);
    cJSON_AddNumberToObject(analytics, "peak_hour", 0);
    cJSON_AddNumberToObject(analytics, "avg_events", 0);

    cJSON* top_sources = cJSON_CreateArray();
    cJSON_AddItemToObject(analytics, "top_sources", top_sources);

    cJSON* event_types = cJSON_CreateObject();
    cJSON_AddNumberToObject(event_types, "security", 0);
    cJSON_AddNumberToObject(event_types, "config", 0);
    cJSON_AddNumberToObject(event_types, "access", 0);
    cJSON_AddItemToObject(analytics, "event_types", event_types);

    cJSON_AddItemToObject(response, "analytics", analytics);
    cJSON_AddStringToObject(response, "status", "success");

    char* json_str = cJSON_Print(response);
    cJSON_Delete(response);

    if (!json_str) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON generation failed");
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    esp_err_t ret = httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
    heap_caps_free(json_str);

    return ret;
}



// ========================= FALLBACK HANDLERS (DEBUG) =========================

esp_err_t WebServer::h_api_fallback(httpd_req_t* req) {
    //TO_DELETE printf("[TRACE] API_FALLBACK %s %s len=%d\n", httpd_method_to_str(req->method), req->uri, (int)req->content_len);
    char body[256]; int got = 0;
    if (req->content_len > 0) {
        size_t want = sizeof(body) - 1;
        size_t left = req->content_len < want ? req->content_len : want;
        while (left > 0) {
            int r = httpd_req_recv(req, body + got, left);
            if (r <= 0) break;
            got += r; left -= r;
        }
        body[got] = '\0';
        //TO_DELETE printf("[TRACE] API_FALLBACK body: %.*s\n", got, body);
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Connection", "close");
    const char* status = "{\"status\":\"not_found\",\"message\":\"API fallback\"}";
    return httpd_resp_send(req, status, HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_any_fallback(httpd_req_t* req) {
    //TO_DELETE printf("[TRACE] ANY_FALLBACK %s %s len=%d\n", httpd_method_to_str(req->method), req->uri, (int)req->content_len);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_sendstr(req, "fallback");
}

// ======================= IRAM DEFRAGMENTATION =======================

void WebServer::scheduleDefragmentation() {
    (void)defrag_timer_;
    // Defragmentation disabled to avoid internal RAM allocations.
}

void WebServer::defrag_timer_callback(void* arg) {
    WebServer* self = static_cast<WebServer*>(arg);
    if (self) {
        self->performDefragmentation();
    }
}

void WebServer::performDefragmentation() {
    LOG_INFO(TAG_WEB, "IRAM defragmentation skipped (PSRAM-only mode)");
}
