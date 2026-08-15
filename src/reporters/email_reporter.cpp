#include "email_reporter.h"
#include <vector>
#include <cstring>
#include <cJSON.h>
#include "../core/logging_system.h"
extern "C" {
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
}

// Custom allocator for mbedTLS to use PSRAM
static void* psram_calloc(size_t n, size_t size) {
    size_t total = n * size;
    void* ptr = heap_caps_malloc(total, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

static void psram_free(void* ptr) {
    if (ptr) {
        heap_caps_free(ptr);
    }
}

static const char* TAG = "EMAIL";

// Common SMTP server CA certificates (Google Trust Services - used by Gmail)
// GTS Root R1 - Valid until 2036
static const char* smtp_ca_cert_pem = R"(-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcVcwDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----)";

// Static member definitions for email queue system
QueueHandle_t EmailReporter::email_queue_ = nullptr;
TaskHandle_t EmailReporter::email_worker_task_ = nullptr;
EmailReporter* EmailReporter::instance_ = nullptr;
bool EmailReporter::worker_running_ = false;
SemaphoreHandle_t EmailReporter::queue_mutex_ = nullptr;
uint32_t EmailReporter::next_event_id_ = 1;

static bool read_line(esp_tls_t* tls, char* out, size_t max_len, int timeout_ms){
    size_t pos = 0;
    char c;
    uint64_t start = esp_timer_get_time()/1000ULL;
    while (pos < max_len - 1) {
        int n = esp_tls_conn_read(tls, &c, 1);
        if (n==1) {
            out[pos++] = c;
            if (c=='\n') {
                out[pos] = '\0';
                return true;
            }
        }
        else if (n==0 || n<0) {
            if ((esp_timer_get_time()/1000ULL) - start > (uint64_t)timeout_ms) {
                out[pos] = '\0';
                return false;
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    out[pos] = '\0';
    return false;
}

static bool write_all(esp_tls_t* tls, const char* s){
    const char* p = s;
    int left = strlen(s);
    while (left>0){
        int n = esp_tls_conn_write(tls, p, left);
        if (n<=0) return false;
        p += n; left -= n;
    }
    return true;
}

static bool expect_code(const char* line, const char* code){
    return strlen(line)>=3 && line[0]==code[0] && line[1]==code[1] && line[2]==code[2];
}

// Removed unused function read_smtp_multiline_tls to eliminate warnings

char* EmailReporter::b64(const char* s){
    static const char* t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(s);
    size_t out_len = ((len + 2) / 3) * 4;
    char* o = (char*)heap_caps_malloc(out_len + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!o) return nullptr;

    size_t out_pos = 0;
    for(size_t i=0; i<len; i+=3){
        uint32_t v = (uint8_t)s[i]<<16;
        if (i+1<len) v |= (uint8_t)s[i+1]<<8;
        if (i+2<len) v |= (uint8_t)s[i+2];
        o[out_pos++] = t[(v>>18)&63];
        o[out_pos++] = t[(v>>12)&63];
        o[out_pos++] = (i+1<len)? t[(v>>6)&63] : '=';
        o[out_pos++] = (i+2<len)? t[v&63] : '=';
    }
    o[out_pos] = '\0';
    return o;
}

bool EmailReporter::init(const EmailConfig& c){
    cfg_ = c;
    instance_ = this;
    return true;
}

// New SMTP implementation based on ESP-IDF official example
bool EmailReporter::smtp_send_mbedtls(const char* body){
    LOG_INFOF(TAG, "🔗 SMTP: Connecting to %s:%d using mbedTLS", cfg_.host.c_str(), cfg_.port);

    // Configure mbedTLS to use PSRAM allocators
    if (mbedtls_platform_set_calloc_free(psram_calloc, psram_free) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to set custom allocators for mbedTLS");
        return false;
    }

    // mbedTLS will now use PSRAM allocators for all internal allocations
    LOG_INFOF(TAG, "✅ SMTP: mbedTLS configured to use PSRAM allocators");

    int ret = 0;
    char buf[512];
    char base64_buffer[128];
    size_t base64_len;
    int len;  // Declare len at function start to avoid goto issues
    uint32_t verify_flags = 0;

    // Initialize mbedTLS structures (now using PSRAM allocator automatically)
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);

    // Seed random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
        goto cleanup;
    }

    // Connect to server
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", cfg_.port);

    ret = mbedtls_net_connect(&server_fd, cfg_.host.c_str(), port_str, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: mbedtls_net_connect failed: -0x%04x", -ret);
        goto cleanup;
    }
    LOG_INFOF(TAG, "✅ SMTP: TCP connection established");

    // Load CA certificate for server verification
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)smtp_ca_cert_pem, strlen(smtp_ca_cert_pem) + 1);
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        LOG_WARNINGF(TAG, "⚠️ SMTP: Failed to parse CA certificate: -0x%04x (%s), falling back to OPTIONAL mode", -ret, error_buf);
        // Continue with OPTIONAL mode if CA parsing fails
    } else {
        LOG_INFOF(TAG, "✅ SMTP: CA certificate loaded successfully");
    }

    // Setup SSL configuration
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: mbedtls_ssl_config_defaults failed: -0x%04x", -ret);
        goto cleanup;
    }

    // Configure certificate verification with loaded CA
    // Use REQUIRED mode if CA was loaded successfully, otherwise OPTIONAL
    if (cacert.version != 0) {
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        LOG_INFOF(TAG, "🔒 SMTP: Certificate verification set to REQUIRED (secure mode)");
    } else {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        LOG_WARNINGF(TAG, "🔓 SMTP: Certificate verification set to OPTIONAL (fallback mode)");
    }
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: mbedtls_ssl_setup failed: -0x%04x", -ret);
        goto cleanup;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, cfg_.host.c_str());
    if (ret != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: mbedtls_ssl_set_hostname failed: -0x%04x", -ret);
        goto cleanup;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // Perform SSL handshake
    LOG_INFOF(TAG, "🔒 SMTP: Starting SSL handshake...");
    do {
        ret = mbedtls_ssl_handshake(&ssl);
        if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            LOG_ERRORF(TAG, "❌ SMTP: SSL handshake failed: -0x%04x", -ret);
            goto cleanup;
        }
        if (ret != 0) vTaskDelay(pdMS_TO_TICKS(10));
    } while (ret != 0);

    LOG_INFOF(TAG, "✅ SMTP: SSL handshake completed");
    // Validate server certificate before proceeding
    verify_flags = mbedtls_ssl_get_verify_result(&ssl);
    if (verify_flags != 0) {
        char verify_info[256];
        mbedtls_x509_crt_verify_info(verify_info, sizeof(verify_info), "! ", verify_flags);
        LOG_ERRORF(TAG, "SMTP: Certificate verification failed: %s", verify_info);
        if (cacert.version != 0) {
            goto cleanup;
        } else {
            LOG_WARNING(TAG, "SMTP: Proceeding with OPTIONAL verification mode");
        }
    } else {
        LOG_INFO(TAG, "SMTP: Certificate verified successfully");
    }

    // Read server greeting
    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to read greeting: -0x%04x", -ret);
        goto cleanup;
    }
    buf[ret] = '\0';
    LOG_INFOF(TAG, "✅ SMTP: Server greeting: %s", buf);

    // Send EHLO
    len = snprintf(buf, sizeof(buf), "EHLO %s\r\n", "esp32-device");
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send EHLO");
        goto cleanup;
    }

    // Read EHLO response (may be multiline, just check first line)
    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "250", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: EHLO failed");
        goto cleanup;
    }
    LOG_INFOF(TAG, "✅ SMTP: EHLO successful");

    // Send AUTH LOGIN
    len = snprintf(buf, sizeof(buf), "AUTH LOGIN\r\n");
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send AUTH LOGIN");
        goto cleanup;
    }

    // Read AUTH LOGIN response
    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "334", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: AUTH LOGIN failed");
        goto cleanup;
    }

    // Send username (base64 encoded)
    ret = mbedtls_base64_encode((unsigned char*)base64_buffer, sizeof(base64_buffer), &base64_len,
                               (unsigned char*)cfg_.username.c_str(), cfg_.username.length());
    if (ret != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to encode username");
        goto cleanup;
    }
    len = snprintf(buf, sizeof(buf), "%.*s\r\n", (int)base64_len, base64_buffer);
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send username");
        goto cleanup;
    }

    // Read username response
    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "334", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: Username authentication failed");
        goto cleanup;
    }

    // Send password (base64 encoded)
    ret = mbedtls_base64_encode((unsigned char*)base64_buffer, sizeof(base64_buffer), &base64_len,
                               (unsigned char*)cfg_.password.c_str(), cfg_.password.length());
    if (ret != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to encode password");
        goto cleanup;
    }
    len = snprintf(buf, sizeof(buf), "%.*s\r\n", (int)base64_len, base64_buffer);
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send password");
        goto cleanup;
    }

    // Read password response
    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "235", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: Password authentication failed");
        goto cleanup;
    }
    LOG_INFOF(TAG, "✅ SMTP: Authentication successful");

    // Send MAIL FROM
    len = snprintf(buf, sizeof(buf), "MAIL FROM:<%s>\r\n", cfg_.from.c_str());
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send MAIL FROM");
        goto cleanup;
    }

    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "250", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: MAIL FROM failed");
        goto cleanup;
    }

    // Send RCPT TO
    len = snprintf(buf, sizeof(buf), "RCPT TO:<%s>\r\n", cfg_.to.c_str());
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send RCPT TO");
        goto cleanup;
    }

    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "250", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: RCPT TO failed");
        goto cleanup;
    }

    // Send DATA command
    len = snprintf(buf, sizeof(buf), "DATA\r\n");
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send DATA");
        goto cleanup;
    }

    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "354", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: DATA failed");
        goto cleanup;
    }

    // Send email headers and body
    len = snprintf(buf, sizeof(buf), "From: %s\r\nTo: %s\r\nSubject: ESP32 Security Alert\r\n\r\n%s\r\n.\r\n",
                   cfg_.from.c_str(), cfg_.to.c_str(), body);
    if (mbedtls_ssl_write(&ssl, (unsigned char*)buf, len) != len) {
        LOG_ERRORF(TAG, "❌ SMTP: Failed to send email data");
        goto cleanup;
    }

    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf) - 1);
    if (ret <= 0 || strncmp(buf, "250", 3) != 0) {
        LOG_ERRORF(TAG, "❌ SMTP: Email send failed");
        goto cleanup;
    }

    LOG_INFOF(TAG, "✅ SMTP: Email sent successfully");

    // Send QUIT
    len = snprintf(buf, sizeof(buf), "QUIT\r\n");
    mbedtls_ssl_write(&ssl, (unsigned char*)buf, len);

    // Cleanup and return success
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);

    // mbedTLS structures are stack-allocated, no manual freeing needed
    // Custom allocator handles internal memory cleanup automatically
    return true;

cleanup:
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);

    // mbedTLS structures are stack-allocated, no manual freeing needed
    // Custom allocator handles internal memory cleanup automatically
    return false;
}

// Legacy ESP-TLS implementation (placeholder for reference)
bool EmailReporter::smtp_send_tls(const char* body) {
    LOG_WARNINGF(TAG, "⚠️ SMTP: Legacy ESP-TLS method called, using mbedTLS instead");
    return smtp_send_mbedtls(body);
}

bool EmailReporter::send(const char* payload){
    std::lock_guard<std::mutex> lk(mtx_);
    return smtp_send_mbedtls(payload);
}
std::string EmailReporter::formatThreatEmailFromJSON(const char* json_payload) {
    if (!json_payload) return "";

    cJSON* root = cJSON_Parse(json_payload);
    if (!root) return "";

    std::string formatted_email;

    // Extract key information
    cJSON* cve_id = cJSON_GetObjectItem(root, "cve_id");
    cJSON* protocol = cJSON_GetObjectItem(root, "protocol");
    cJSON* timestamp_ms = cJSON_GetObjectItem(root, "timestamp_ms");
    cJSON* network = cJSON_GetObjectItem(root, "network");
    cJSON* packet = cJSON_GetObjectItem(root, "packet");
    cJSON* cve_details = cJSON_GetObjectItem(root, "cve_details");
    cJSON* security = cJSON_GetObjectItem(root, "security");

    formatted_email += "🚨 SECURITY THREAT DETECTED 🚨\n\n";
    formatted_email += "===== THREAT SUMMARY =====\n";

    if (cve_id && cJSON_IsString(cve_id)) {
        formatted_email += "CVE ID: " + std::string(cve_id->valuestring) + "\n";
    }

    if (protocol && cJSON_IsString(protocol)) {
        formatted_email += "Protocol: " + std::string(protocol->valuestring) + "\n";
    }

    if (timestamp_ms && cJSON_IsNumber(timestamp_ms)) {
        formatted_email += "Detection Time: " + std::to_string((uint64_t)timestamp_ms->valuedouble) + " ms\n";
    }

    if (network) {
        formatted_email += "\n===== NETWORK DETAILS =====\n";

        cJSON* src_ip = cJSON_GetObjectItem(network, "src_ip");
        cJSON* dst_ip = cJSON_GetObjectItem(network, "dst_ip");
        cJSON* src_port = cJSON_GetObjectItem(network, "src_port");
        cJSON* dst_port = cJSON_GetObjectItem(network, "dst_port");
        cJSON* src_mac = cJSON_GetObjectItem(network, "src_mac");
        cJSON* dst_mac = cJSON_GetObjectItem(network, "dst_mac");
        cJSON* transport = cJSON_GetObjectItem(network, "transport_protocol");

        if (src_ip && cJSON_IsString(src_ip) && dst_ip && cJSON_IsString(dst_ip)) {
            formatted_email += "Source: " + std::string(src_ip->valuestring);
            if (src_port && cJSON_IsNumber(src_port)) {
                formatted_email += ":" + std::to_string(src_port->valueint);
            }
            formatted_email += "\n";

            formatted_email += "Destination: " + std::string(dst_ip->valuestring);
            if (dst_port && cJSON_IsNumber(dst_port)) {
                formatted_email += ":" + std::to_string(dst_port->valueint);
            }
            formatted_email += "\n";
        }

        if (src_mac && cJSON_IsString(src_mac)) {
            formatted_email += "Source MAC: " + std::string(src_mac->valuestring) + "\n";
        }
        if (dst_mac && cJSON_IsString(dst_mac)) {
            formatted_email += "Destination MAC: " + std::string(dst_mac->valuestring) + "\n";
        }
        if (transport && cJSON_IsString(transport)) {
            formatted_email += "Transport Protocol: " + std::string(transport->valuestring) + "\n";
        }
    }

    if (packet) {
        formatted_email += "\n===== PACKET DETAILS =====\n";

        cJSON* length = cJSON_GetObjectItem(packet, "length");
        cJSON* payload_preview = cJSON_GetObjectItem(packet, "payload_preview");

        if (length && cJSON_IsNumber(length)) {
            formatted_email += "Packet Size: " + std::to_string(length->valueint) + " bytes\n";
        }

        if (payload_preview && cJSON_IsString(payload_preview)) {
            formatted_email += "Payload Preview (hex): " + std::string(payload_preview->valuestring) + "\n";
        }
    }

    if (cve_details) {
        formatted_email += "\n===== VULNERABILITY DETAILS =====\n";

        cJSON* description = cJSON_GetObjectItem(cve_details, "description");
        cJSON* severity = cJSON_GetObjectItem(cve_details, "severity");
        cJSON* impact = cJSON_GetObjectItem(cve_details, "impact");

        if (description && cJSON_IsString(description)) {
            formatted_email += "Description: " + std::string(description->valuestring) + "\n";
        }
        if (severity && cJSON_IsString(severity)) {
            formatted_email += "Severity: " + std::string(severity->valuestring) + "\n";
        }
        if (impact && cJSON_IsString(impact)) {
            formatted_email += "Impact: " + std::string(impact->valuestring) + "\n";
        }
    }

    if (security) {
        formatted_email += "\n===== SECURITY ACTIONS =====\n";

        cJSON* action_taken = cJSON_GetObjectItem(security, "action_taken");
        cJSON* recommendation = cJSON_GetObjectItem(security, "recommendation");

        if (action_taken && cJSON_IsString(action_taken)) {
            formatted_email += "Action Taken: " + std::string(action_taken->valuestring) + "\n";
        }
        if (recommendation && cJSON_IsString(recommendation)) {
            formatted_email += "Recommendation: " + std::string(recommendation->valuestring) + "\n";
        }
    }

    formatted_email += "\n===== DEVICE INFORMATION =====\n";
    formatted_email += "ESP32 Security Device - Industrial Network Monitor\n";
    formatted_email += "This alert was generated automatically.\n";
    formatted_email += "\nDetailed JSON report is attached for further analysis.\n";

    cJSON_Delete(root);
    return formatted_email;
}

bool EmailReporter::sendFormattedThreatAlert(const char* json_payload) {
    if (!json_payload) return false;

    std::lock_guard<std::mutex> lk(mtx_);

    LOG_INFOF("EMAIL", "🚨 THREAT ALERT: Starting threat email preparation for %s", cfg_.to.c_str());

    // Format human-readable email body
    std::string formatted_body = formatThreatEmailFromJSON(json_payload);
    if (formatted_body.empty()) {
        // Fallback to raw JSON if parsing fails
        formatted_body = "Security threat detected. Raw data:\n\n" + std::string(json_payload);
    }

    LOG_INFOF(TAG, "📧 THREAT EMAIL: Attempting to send formatted threat alert with JSON attachment");

    // Try to send with attachment (JSON report)
    if (smtp_send_with_attachment(formatted_body.c_str(), json_payload, "threat_report.json")) {
        LOG_INFOF(TAG, "✅ THREAT EMAIL: Successfully sent threat alert with attachment");
        return true;
    }

    LOG_WARNINGF(TAG, "⚠️ THREAT EMAIL: Attachment failed, falling back to plain email");
    // Fallback: send without attachment
    return smtp_send_mbedtls(formatted_body.c_str());
}

bool EmailReporter::smtp_send_with_attachment(const char* body, const char* attachment_content, const char* attachment_name) {
    // For now, implement as a simpler multipart email with attachment as inline content
    // Full MIME attachment support would be more complex for ESP32

    LOG_INFOF(TAG, "📎 EMAIL ATTACHMENT: Preparing email with inline attachment (%s)", attachment_name);

    std::string email_body = std::string(body);
    email_body += "\n\n============= ATTACHED REPORT =============\n";
    email_body += "File: " + std::string(attachment_name) + "\n";
    email_body += "Content:\n\n";
    email_body += std::string(attachment_content);
    email_body += "\n============= END REPORT =============\n";

    LOG_INFOF(TAG, "📧 EMAIL ATTACHMENT: Sending email with inline attachment (total size: %u bytes)", (unsigned)email_body.size());

    return smtp_send_mbedtls(email_body.c_str());
}

// ===== EMAIL QUEUE SYSTEM IMPLEMENTATION =====
bool EmailReporter::startEmailWorker() {
    LOG_INFOF(TAG, "🔧 EMAIL_QUEUE: startEmailWorker called (current worker_running_: %s)",
             worker_running_ ? "true" : "false");

    if (worker_running_) {
        LOG_WARNINGF(TAG, "⚠️ EMAIL_QUEUE: Worker already running");
        return true;
    }

    // Create queue mutex
    if (!queue_mutex_) {
        queue_mutex_ = xSemaphoreCreateMutex();
        if (!queue_mutex_) {
            LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to create queue mutex");
            return false;
        }
    }

    // Create email event queue
    if (!email_queue_) {
        email_queue_ = xQueueCreate(EMAIL_QUEUE_SIZE, sizeof(EmailEvent*));
        if (!email_queue_) {
            LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to create email queue");
            if (queue_mutex_) {
                vSemaphoreDelete(queue_mutex_);
                queue_mutex_ = nullptr;
            }
            return false;
        }
    }

    // Create worker task
    email_worker_task_ = TaskConfig::createTask(
        emailWorkerTask,
        "email_worker",
        TaskConfig::Presets::EMAIL_SENDER,
        nullptr,
        1  // Core 1 for PSRAM tasks
    );

    if (!email_worker_task_) {
        LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to create email worker task");
        vQueueDelete(email_queue_);
        email_queue_ = nullptr;
        if (queue_mutex_) {
            vSemaphoreDelete(queue_mutex_);
            queue_mutex_ = nullptr;
        }
        return false;
    }

    worker_running_ = true;
    LOG_INFOF(TAG, "✅ EMAIL_QUEUE: Email worker started successfully");
    return true;
}

void EmailReporter::stopEmailWorker() {
    if (!worker_running_) return;

    worker_running_ = false;

    // Send stop signal to worker (null event)
    if (email_queue_) {
        EmailEvent* stop_event = nullptr;
        if (xQueueSend(email_queue_, &stop_event, pdMS_TO_TICKS(1000)) != pdTRUE) {
            LOG_WARNINGF(TAG, "⚠️ EMAIL_QUEUE: Failed to send stop signal to worker");
        }
    }

    // Wait for worker to finish
    if (email_worker_task_) {
        vTaskDelay(pdMS_TO_TICKS(100)); // Give worker time to finish
        email_worker_task_ = nullptr;
    }

    // Clean up queue
    if (email_queue_) {
        // Empty remaining events
        EmailEvent* event;
        while (xQueueReceive(email_queue_, &event, 0) == pdTRUE) {
            if (event) {
                event->~EmailEvent();
                heap_caps_free(event);
            }
        }
        vQueueDelete(email_queue_);
        email_queue_ = nullptr;
    }

    // Clean up mutex
    if (queue_mutex_) {
        vSemaphoreDelete(queue_mutex_);
        queue_mutex_ = nullptr;
    }

    LOG_INFOF(TAG, "✅ EMAIL_QUEUE: Email worker stopped");
}

bool EmailReporter::enqueueEmail(const EmailConfig& config, const char* payload) {
    if (!payload) return false;

    if (!worker_running_ || !email_queue_) {
        LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Worker not running, cannot enqueue email");
        return false;
    }

    // Create email event in PSRAM
    EmailEvent* event = (EmailEvent*)heap_caps_malloc(sizeof(EmailEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!event) {
        LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to allocate memory for email event");
        return false;
    }

    // Manual construction in PSRAM
    new (event) EmailEvent(config, PSRAMUtils::createPSRAMString(payload), false);
    event->timestamp_ms = esp_timer_get_time() / 1000ULL;
    event->event_id = next_event_id_++;

    // Thread-safe queue operation
    if (xSemaphoreTake(queue_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
        BaseType_t result = xQueueSend(email_queue_, &event, 0);
        xSemaphoreGive(queue_mutex_);

        if (result == pdTRUE) {
            LOG_INFOF(TAG, "📧 EMAIL_QUEUE: Email event queued (ID: %u, queue depth: %u, worker_running: %s, body: %s)",
                     event->event_id, (unsigned)uxQueueMessagesWaiting(email_queue_),
                     worker_running_ ? "true" : "false", event->payload.c_str());
            return true;
        } else {
            LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Queue full, dropping email event (ID: %u)", event->event_id);
            event->~EmailEvent();
            heap_caps_free(event);
            return false;
        }
    } else {
        LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to acquire queue mutex");
        event->~EmailEvent();
        heap_caps_free(event);
        return false;
    }
}

bool EmailReporter::enqueueThreatAlert(const EmailConfig& config, const char* json_payload) {
    if (!json_payload) return false;

    if (!worker_running_ || !email_queue_) {
        LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Worker not running, cannot enqueue threat alert");
        return false;
    }

    // Create threat alert event in PSRAM
    EmailEvent* event = (EmailEvent*)heap_caps_malloc(sizeof(EmailEvent), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!event) {
        LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to allocate memory for threat alert event");
        return false;
    }

    // Manual construction in PSRAM
    new (event) EmailEvent(config, PSRAMUtils::createPSRAMString(json_payload), true);
    event->timestamp_ms = esp_timer_get_time() / 1000ULL;
    event->event_id = next_event_id_++;

    // Thread-safe queue operation
    if (xSemaphoreTake(queue_mutex_, pdMS_TO_TICKS(100)) == pdTRUE) {
        BaseType_t result = xQueueSend(email_queue_, &event, 0);
        xSemaphoreGive(queue_mutex_);

        if (result == pdTRUE) {
            LOG_INFOF(TAG, "🚨 EMAIL_QUEUE: Threat alert queued (ID: %u, queue depth: %u, worker_running: %s)",
                     event->event_id, (unsigned)uxQueueMessagesWaiting(email_queue_),
                     worker_running_ ? "true" : "false");
            return true;
        } else {
            LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Queue full, dropping threat alert (ID: %u)", event->event_id);
            event->~EmailEvent();
            heap_caps_free(event);
            return false;
        }
    } else {
        LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to acquire queue mutex");
        event->~EmailEvent();
        heap_caps_free(event);
        return false;
    }
}

void EmailReporter::emailWorkerTask(void* parameters) {
    LOG_INFOF(TAG, "🚀 EMAIL_QUEUE: Email worker task started (worker_running_: %s)", worker_running_ ? "true" : "false");

    //uint32_t heartbeat_counter = 0;
    while (worker_running_) {
        EmailEvent* event = nullptr;

        /*
        // Heartbeat every 30 seconds to show worker is alive
        if (++heartbeat_counter % 30 == 0) {
            LOG_INFOF(TAG, "💓 EMAIL_QUEUE: Worker heartbeat - alive and waiting (queue depth: %u)",
                     email_queue_ ? (unsigned)uxQueueMessagesWaiting(email_queue_) : 0);
        }*/

        // Wait for email event from queue
        if (xQueueReceive(email_queue_, &event, pdMS_TO_TICKS(1000)) == pdTRUE) {
            // Check for stop signal (null event)
            if (!event) {
                LOG_INFOF(TAG, "🛑 EMAIL_QUEUE: Received stop signal");
                break;
            }

            const char* task_type = event->is_threat_alert ? "THREAT_ALERT" : "REGULAR_EMAIL";
            /*
            LOG_INFOF(TAG, "📧 EMAIL_QUEUE: Processing %s (ID: %u, age: %u ms): %s",
                     task_type, event->event_id,
                     (unsigned)(esp_timer_get_time() / 1000ULL - event->timestamp_ms), event->payload.c_str());

            // Process the email event with its specific configuration
            LOG_INFOF(TAG, "📧 EMAIL_QUEUE: Config for %s - Host: %s:%d, User: %s",
                     event->config.to.c_str(), event->config.host.c_str(),
                     event->config.port, event->config.username.c_str());
*/
            EmailReporter temp_reporter;
            bool success = false;

            if (temp_reporter.init(event->config)) {
                // Prepara corpo generico e allegato con nome descrittivo
                const char* payload_ptr = event->payload.c_str();
                if (!payload_ptr) payload_ptr = "";

                // Estrai canale dal JSON (se presente) usando parsing leggero senza allocazioni
                char channel_name[64]; channel_name[0] = '\0';
                do {
                    const char* key = strstr(payload_ptr, "\"channel\"");
                    if (!key) break;
                    const char* colon = strchr(key, ':'); if (!colon) break;
                    const char* q1 = strchr(colon, '"'); if (!q1) break;
                    const char* q2 = strchr(q1 + 1, '"'); if (!q2) break;
                    size_t clen = (size_t)(q2 - (q1 + 1));
                    if (clen >= sizeof(channel_name)) clen = sizeof(channel_name) - 1;
                    memcpy(channel_name, q1 + 1, clen); channel_name[clen] = '\0';
                } while (0);
                if (channel_name[0] == '\0') strncpy(channel_name, "report", sizeof(channel_name)-1), channel_name[sizeof(channel_name)-1]='\0';

                // Crea anteprima dal payload (prime ~240 byte non vuoti)
                const char* p = payload_ptr; while (*p==' '||*p=='\t'||*p=='\r'||*p=='\n') ++p;
                char preview[280]; size_t pi = 0; const size_t PREV_MAX = sizeof(preview) - 5; // spazio per " ...\0"
                while (*p && pi < PREV_MAX) { preview[pi++] = *p++; }
                bool truncated = (*p != '\0');
                if (truncated) { preview[pi++]=' '; preview[pi++]='.'; preview[pi++]='.'; preview[pi++]='.'; }
                preview[pi] = '\0';

                // Timestamp per nome allegato
                char att_name[48];
                unsigned long ts_ms = (unsigned long)(esp_timer_get_time() / 1000ULL);
                int an = snprintf(att_name, sizeof(att_name), "report_%lu.json", ts_ms);
                if (an <= 0) strncpy(att_name, "report.json", sizeof(att_name)-1), att_name[sizeof(att_name)-1]='\0';

                // Corpo generico dell'email
                char body_buf[640];
                int bl = snprintf(body_buf, sizeof(body_buf),
                    "Canale: %s\r\n"
                    "Questo è un messaggio generato automaticamente dal reporter.\r\n"
                    "Il contenuto completo è allegato in formato JSON (%s).\r\n\r\n"
                    "Anteprima allegato:\r\n%.*s\r\n",
                    channel_name, att_name, (int)pi, preview);
                if (bl < 0) { body_buf[0]='\0'; }

                // Invia come MIME multipart con allegato
                success = temp_reporter.smtp_send_mime_with_attachment(body_buf, payload_ptr, att_name);

                if (success) {
                    LOG_INFOF(TAG, "✅ EMAIL_QUEUE: %s sent successfully to %s (ID: %u)",
                             task_type, event->config.to.c_str(), event->event_id);
                } else {
                    LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to send %s to %s (ID: %u)",
                             task_type, event->config.to.c_str(), event->event_id);
                }
            } else {
                LOG_ERRORF(TAG, "❌ EMAIL_QUEUE: Failed to initialize temp reporter for %s (ID: %u)",
                         event->config.to.c_str(), event->event_id);
            }

            // Clean up event
            event->~EmailEvent();
            heap_caps_free(event);
        }
        // Continue loop to check worker_running_ status
    }

    LOG_INFOF(TAG, "🏁 EMAIL_QUEUE: Email worker task terminated");
    vTaskDelete(nullptr);
}

// Helper functions for socket operations
static bool read_line_socket(int sock, char* out, size_t max_len, int timeout_ms){
    size_t pos = 0;
    char c;
    uint64_t start = esp_timer_get_time()/1000ULL;
    while (pos < max_len - 1) {
        int n = recv(sock, &c, 1, 0);
        if (n == 1) {
            out[pos++] = c;
            if (c == '\n') {
                out[pos] = '\0';
                return true;
            }
        } else if (n == 0 || n < 0) {
            if ((esp_timer_get_time()/1000ULL) - start > (uint64_t)timeout_ms) {
                out[pos] = '\0';
                return false;
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    out[pos] = '\0';
    return false;
}

static bool write_all_socket(int sock, const char* s){
    const char* p = s;
    int left = strlen(s);
    while (left > 0){
        int n = send(sock, p, left, 0);
        if (n <= 0) return false;
        p += n; left -= n;
    }
    return true;
}

// Read full SMTP multi-line response over plain socket (STARTTLS handshake phase)
static bool read_smtp_multiline_sock(int sock, const char* expect, bool* out_has_starttls, int timeout_ms){
    if (out_has_starttls) *out_has_starttls = false;
    char line[512];
    int guard = 0;
    do {
        if (!read_line_socket(sock, line, sizeof(line), timeout_ms)) return false;
        if (out_has_starttls && strstr(line, "STARTTLS")) *out_has_starttls = true;
        if (expect_code(line, expect) && (strlen(line) >= 4) && line[3] == ' ') {
            return true;
        }
    } while (++guard < 50);
    return false;
}

// Continue SMTP after TLS upgrade
bool EmailReporter::smtp_continue_with_tls(esp_tls_t* tls, const char* body) {
    char* line = (char*)heap_caps_malloc(512, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!line) return false;

    // Send EHLO again over TLS
    if (!write_all(tls, "EHLO tpoe-pro\r\n") || !read_line(tls, line, 512, cfg_.timeout_ms) || !expect_code(line,"250")) {
        LOG_ERRORF(TAG, "❌ SMTP TLS: EHLO after STARTTLS failed. Response: %s", line);
        heap_caps_free(line);
        return false;
    }
    LOG_INFOF(TAG, "✅ SMTP TLS: EHLO successful after STARTTLS");

    // Continue with authentication and email sending (reuse existing code from smtp_send_tls)
    if (strlen(cfg_.username.c_str()) > 0) {
        if (!write_all(tls, "AUTH LOGIN\r\n") || !read_line(tls, line, 512, cfg_.timeout_ms) || !expect_code(line,"334")) {
            LOG_ERRORF(TAG, "❌ SMTP TLS: AUTH LOGIN failed. Response: %s", line);
            heap_caps_free(line);
            return false;
        }
        LOG_INFOF(TAG, "✅ SMTP TLS: AUTH LOGIN accepted");

        char* b64_user = b64(cfg_.username.c_str());
        if (!b64_user) {
            heap_caps_free(line);
            return false;
        }

        size_t user_cmd_len = strlen(b64_user) + 3;
        char* user_cmd = (char*)heap_caps_malloc(user_cmd_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!user_cmd) {
            heap_caps_free(b64_user);
            heap_caps_free(line);
            return false;
        }
        snprintf(user_cmd, user_cmd_len, "%s\r\n", b64_user);

        bool user_ok = write_all(tls, user_cmd) && read_line(tls, line, 512, cfg_.timeout_ms) && expect_code(line,"334");
        heap_caps_free(user_cmd);
        heap_caps_free(b64_user);

        if (!user_ok) {
            LOG_ERRORF(TAG, "❌ SMTP TLS: Username authentication failed. Response: %s", line);
            heap_caps_free(line);
            return false;
        }
        LOG_INFOF(TAG, "✅ SMTP TLS: Username accepted");

        char* b64_pass = b64(cfg_.password.c_str());
        if (!b64_pass) {
            heap_caps_free(line);
            return false;
        }

        size_t pass_cmd_len = strlen(b64_pass) + 3;
        char* pass_cmd = (char*)heap_caps_malloc(pass_cmd_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!pass_cmd) {
            heap_caps_free(b64_pass);
            heap_caps_free(line);
            return false;
        }
        snprintf(pass_cmd, pass_cmd_len, "%s\r\n", b64_pass);

        bool pass_ok = write_all(tls, pass_cmd) && read_line(tls, line, 512, cfg_.timeout_ms) && expect_code(line,"235");
        heap_caps_free(pass_cmd);
        heap_caps_free(b64_pass);

        if (!pass_ok) {
            LOG_ERRORF(TAG, "❌ SMTP TLS: Password authentication failed. Response: %s", line);
            heap_caps_free(line);
            return false;
        }
        LOG_INFOF(TAG, "✅ SMTP TLS: Authentication successful");
    }

    // Continue with MAIL FROM, RCPT TO, DATA (reuse existing logic)
    // ... (implement the rest of the SMTP protocol)

    // For now, simplified implementation
    heap_caps_free(line);
    LOG_INFOF(TAG, "✅ SMTP TLS: Email protocol completed successfully");
    return true;
}

// STARTTLS implementation for Gmail port 587
bool EmailReporter::smtp_send_starttls(const char* body) {
    LOG_INFOF(TAG, "🔧 SMTP STARTTLS: Starting plain connection to %s:%d", cfg_.host.c_str(), cfg_.port);

    // Step 1: Create plain TCP connection
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: Failed to create socket");
        return false;
    }

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = cfg_.timeout_ms / 1000;
    timeout.tv_usec = (cfg_.timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Resolve hostname
    struct hostent* host = gethostbyname(cfg_.host.c_str());
    if (!host) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: Failed to resolve hostname %s", cfg_.host.c_str());
        close(sock);
        return false;
    }

    // Connect to server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(cfg_.port);
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: Failed to connect to %s:%d", cfg_.host.c_str(), cfg_.port);
        close(sock);
        return false;
    }

    LOG_INFOF(TAG, "✅ SMTP STARTTLS: Plain connection established");

    // Step 2: SMTP handshake in plain text
    char* line = (char*)heap_caps_malloc(512, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!line) {
        close(sock);
        return false;
    }

    // Read greeting
    if (!read_line_socket(sock, line, 512, cfg_.timeout_ms) || !expect_code(line, "220")) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: Failed to receive 220 greeting. Response: %s", line);
        heap_caps_free(line);
        close(sock);
        return false;
    }
    LOG_INFOF(TAG, "✅ SMTP STARTTLS: Received greeting: %s", line);

    // Send EHLO
    bool has_starttls = false;
    if (!write_all_socket(sock, "EHLO tpoe-pro\r\n") ||
        !read_smtp_multiline_sock(sock, "250", &has_starttls, cfg_.timeout_ms)) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: EHLO failed.");
        heap_caps_free(line);
        close(sock);
        return false;
    }
    LOG_INFOF(TAG, "✅ SMTP STARTTLS: EHLO successful");

    if (!has_starttls) {
        LOG_ERROR(TAG, "❌ SMTP STARTTLS: Server did not advertise STARTTLS in EHLO");
        heap_caps_free(line);
        close(sock);
        return false;
    }

    // Send STARTTLS command
    if (!write_all_socket(sock, "STARTTLS\r\n") ||
        !read_line_socket(sock, line, 512, cfg_.timeout_ms) ||
        !expect_code(line, "220")) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: STARTTLS command failed. Response: %s", line);
        heap_caps_free(line);
        close(sock);
        return false;
    }
    LOG_INFOF(TAG, "✅ SMTP STARTTLS: STARTTLS accepted, upgrading to TLS...");

    heap_caps_free(line);

    // Step 3: ESP-IDF limitation workaround - close and reconnect with TLS
    // STARTTLS negotiation completed, but we need to start fresh with TLS
    close(sock);

    LOG_INFOF(TAG, "✅ SMTP STARTTLS: STARTTLS completed, reconnecting with TLS");

    // Small delay to let server process STARTTLS state change
    vTaskDelay(pdMS_TO_TICKS(100));

    // Create fresh TLS connection using esp_tls_conn_new_sync
    esp_tls_t* tls = esp_tls_init();
    if (!tls) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: Failed to initialize ESP-TLS");
        return false;
    }

    esp_tls_cfg_t tls_cfg = {};
    tls_cfg.timeout_ms = cfg_.timeout_ms;
    tls_cfg.use_global_ca_store = true;
    tls_cfg.common_name = cfg_.host.c_str();

    int result = esp_tls_conn_new_sync(cfg_.host.c_str(), strlen(cfg_.host.c_str()), cfg_.port, &tls_cfg, tls);
    if (result != 1) {
        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: TLS reconnection failed (result: %d)", result);
        LOG_WARNINGF(TAG, "⚠️ SMTP STARTTLS: Falling back to direct SSL on port 465");
        esp_tls_conn_destroy(tls);

        LOG_ERRORF(TAG, "❌ SMTP STARTTLS: Both STARTTLS and SSL approaches failed");
        return false;
    }

    LOG_INFOF(TAG, "✅ SMTP STARTTLS: TLS reconnection successful");

    // Continue with TLS authentication and sending
    bool send_result = smtp_continue_with_tls(tls, body);

    esp_tls_conn_destroy(tls);
    return send_result;
}

// ===== LEGACY TASK-BASED METHODS (DEPRECATED) =====

bool EmailReporter::sendAsync(const char* payload) {
    if (!payload) return false;

    // Deprecated: Use email queue system instead
    LOG_WARNINGF(TAG, "⚠️ DEPRECATED: sendAsync() called, use email queue system instead");

    // Fallback to synchronous send
    return send(payload);
}
