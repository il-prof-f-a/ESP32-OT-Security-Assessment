#include "email_reporter.h"
#include <cstring>
#include "../core/logging_system.h"
extern "C" {
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform.h"
}
static const char* TAG = "EMAIL";

// PSRAM allocators (copy for this TU)
static void* psram_calloc_mime(size_t n, size_t size) {
    size_t total = n * size;
    void* ptr = heap_caps_malloc(total, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr) std::memset(ptr, 0, total);
    return ptr;
}
static void psram_free_mime(void* ptr) { if (ptr) heap_caps_free(ptr); }

// Non-blocking helpers (copy for this TU)
static bool ssl_write_all_nb_mime(mbedtls_ssl_context* ssl, const char* data, size_t len, int timeout_ms) {
    size_t off = 0; uint64_t start = esp_timer_get_time()/1000ULL;
    while (off < len) {
        int ret = mbedtls_ssl_write(ssl, (const unsigned char*)(data + off), (int)(len - off));
        if (ret > 0) { off += (size_t)ret; continue; }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (((esp_timer_get_time()/1000ULL) - start) > (uint64_t)timeout_ms) return false;
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        return false;
    }
    return true;
}
static bool ssl_read_line_nb_mime(mbedtls_ssl_context* ssl, char* out, size_t max_len, int timeout_ms) {
    if (!out || max_len == 0) return false;
    size_t pos = 0; uint64_t start = esp_timer_get_time()/1000ULL;
    while (pos < max_len - 1) {
        int ret = mbedtls_ssl_read(ssl, (unsigned char*)(out + pos), 1);
        if (ret == 1) { char c = out[pos++]; if (c == '\n') { out[pos] = '\0'; return true; } continue; }
        if (ret == 0) { out[pos] = '\0'; return (pos > 0); }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (((esp_timer_get_time()/1000ULL) - start) > (uint64_t)timeout_ms) { out[pos] = '\0'; return false; }
            vTaskDelay(pdMS_TO_TICKS(5)); continue;
        }
        out[pos] = '\0'; return false;
    }
    out[pos] = '\0'; return false;
}

// Small helpers for headers and CRLF
static bool send_crlf_mime(mbedtls_ssl_context* ssl, int timeout_ms) {
    return ssl_write_all_nb_mime(ssl, "\r\n", 2, timeout_ms);
}
static bool send_header_kv_mime(mbedtls_ssl_context* ssl, const char* k, const char* v, int timeout_ms) {
    char hb[256]; int l = snprintf(hb, sizeof(hb), "%s: %s\r\n", k, v);
    return ssl_write_all_nb_mime(ssl, hb, l, timeout_ms);
}

bool EmailReporter::smtp_send_mime_with_attachment(const char* body, const char* attachment_content, const char* attachment_name) {
    if (!body) return false;
    mbedtls_platform_set_calloc_free(psram_calloc_mime, psram_free_mime);

    int ret = 0; int len = 0; char resp[512];
    bool has_attachment = (attachment_content && attachment_name && attachment_name[0] != '\0' && attachment_content[0] != '\0');
    char boundary[64];
    mbedtls_net_context server_fd; mbedtls_ssl_context ssl; mbedtls_ssl_config conf; mbedtls_ctr_drbg_context ctr_drbg; mbedtls_entropy_context entropy;
    mbedtls_net_init(&server_fd); mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf); mbedtls_ctr_drbg_init(&ctr_drbg); mbedtls_entropy_init(&entropy);
    LOG_INFO(TAG, "SMTP(MIME): begin");
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) { LOG_ERRORF(TAG, "SMTP(MIME): drbg seed failed -0x%04x", -ret); goto cleanup; }
    { char port_str[6]; snprintf(port_str, sizeof(port_str), "%d", cfg_.port);
      LOG_INFOF(TAG, "SMTP(MIME): connect %s:%s", cfg_.host.c_str(), port_str);
      if ((ret = mbedtls_net_connect(&server_fd, cfg_.host.c_str(), port_str, MBEDTLS_NET_PROTO_TCP)) != 0) { LOG_ERRORF(TAG, "SMTP(MIME): net_connect failed -0x%04x", -ret); goto cleanup; }
      struct timeval tv; tv.tv_sec = cfg_.timeout_ms/1000; tv.tv_usec = (cfg_.timeout_ms%1000)*1000;
      setsockopt(server_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(server_fd.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)); }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) { LOG_ERRORF(TAG, "SMTP(MIME): ssl_config_defaults failed -0x%04x", -ret); goto cleanup; }
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) { LOG_ERRORF(TAG, "SMTP(MIME): ssl_setup failed -0x%04x", -ret); goto cleanup; }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, cfg_.host.c_str())) != 0) { LOG_ERRORF(TAG, "SMTP(MIME): set_hostname failed -0x%04x", -ret); goto cleanup; }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    do { ret = mbedtls_ssl_handshake(&ssl); if (ret!=0 && ret!=MBEDTLS_ERR_SSL_WANT_READ && ret!=MBEDTLS_ERR_SSL_WANT_WRITE) { LOG_ERRORF(TAG, "SMTP(MIME): handshake failed -0x%04x", -ret); goto cleanup; } if (ret!=0) vTaskDelay(pdMS_TO_TICKS(10)); } while (ret!=0);
    LOG_INFO(TAG, "SMTP(MIME): TLS handshake done");
    // Read server greeting (may be multiline 220- ... 220 <space>)
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"220",3)!=0) { LOG_ERRORF(TAG, "SMTP(MIME): bad greeting: %s", resp); goto cleanup; }
    while (resp[3] == '-') { if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms)) goto cleanup; }
    len = snprintf(resp, sizeof(resp), "EHLO %s\r\n", "esp32-device"); if (!ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms)) { LOG_ERROR(TAG, "SMTP(MIME): send EHLO failed"); goto cleanup; }
    // EHLO response may be multiline 250- ... 250 <space>
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"250",3)!=0) { LOG_ERRORF(TAG, "SMTP(MIME): EHLO failed: %s", resp); goto cleanup; }
    while (resp[3] == '-') {
        if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms)) goto cleanup;
        if (strncmp(resp, "250", 3) != 0) { LOG_ERRORF(TAG, "SMTP(MIME): EHLO line unexpected: %s", resp); goto cleanup; }
    }
    len = snprintf(resp, sizeof(resp), "AUTH LOGIN\r\n"); if (!ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms)) { LOG_ERROR(TAG, "SMTP(MIME): send AUTH LOGIN failed"); goto cleanup; }
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"334",3)!=0) { LOG_ERRORF(TAG, "SMTP(MIME): AUTH prompt failed: %s", resp); goto cleanup; }
    { unsigned char b64[160]; size_t b64len=0; if (mbedtls_base64_encode(b64, sizeof(b64), &b64len, (const unsigned char*)cfg_.username.c_str(), cfg_.username.length())!=0) goto cleanup;
      len = snprintf(resp, sizeof(resp), "%.*s\r\n", (int)b64len, (const char*)b64); if (!ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms)) goto cleanup; }
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"334",3)!=0) goto cleanup;
    { unsigned char b64[160]; size_t b64len=0; if (mbedtls_base64_encode(b64, sizeof(b64), &b64len, (const unsigned char*)cfg_.password.c_str(), cfg_.password.length())!=0) goto cleanup;
      len = snprintf(resp, sizeof(resp), "%.*s\r\n", (int)b64len, (const char*)b64); if (!ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms)) goto cleanup; }
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"235",3)!=0) goto cleanup;
    len = snprintf(resp, sizeof(resp), "MAIL FROM:<%s>\r\n", cfg_.from.c_str()); if (!ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms)) goto cleanup;
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"250",3)!=0) goto cleanup;
    len = snprintf(resp, sizeof(resp), "RCPT TO:<%s>\r\n", cfg_.to.c_str()); if (!ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms)) goto cleanup;
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"250",3)!=0) goto cleanup;
    len = snprintf(resp, sizeof(resp), "DATA\r\n"); if (!ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms)) goto cleanup;
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"354",3)!=0) goto cleanup;
    snprintf(boundary, sizeof(boundary), "----ESP32-BOUNDARY-%08X", (unsigned)esp_timer_get_time());
    if (!send_header_kv_mime(&ssl, "From", cfg_.from.c_str(), cfg_.timeout_ms)) goto cleanup;
    if (!send_header_kv_mime(&ssl, "To",   cfg_.to.c_str(),   cfg_.timeout_ms)) goto cleanup;
    {
        const char* subj = cfg_.subject.empty()?"ESP32 Security Alert":cfg_.subject.c_str();
        if (!send_header_kv_mime(&ssl, "Subject", subj, cfg_.timeout_ms)) goto cleanup;
    }
    if (!send_header_kv_mime(&ssl, "MIME-Version", "1.0", cfg_.timeout_ms)) goto cleanup;
    {
        char ct[128];
        int lct=snprintf(ct,sizeof(ct),"multipart/mixed; boundary=\"%s\"", boundary);
        (void)lct;
        if (!send_header_kv_mime(&ssl, "Content-Type", ct, cfg_.timeout_ms)) goto cleanup;
    }
    if (!send_crlf_mime(&ssl, cfg_.timeout_ms)) goto cleanup;
    { char lnb[256]; int l3=snprintf(lnb,sizeof(lnb),"--%s\r\n", boundary); if (!ssl_write_all_nb_mime(&ssl,lnb,l3,cfg_.timeout_ms)) goto cleanup;
      // Choose Content-Type for body based on content (JSON vs plain text)
      const char* p_ct = body; while (*p_ct==' '||*p_ct=='\t'||*p_ct=='\r'||*p_ct=='\n') ++p_ct;
      const char* ct_primary = (*p_ct=='{' || *p_ct=='[') ? "application/json; charset=UTF-8" : "text/plain; charset=UTF-8";
      if (!send_header_kv_mime(&ssl, "Content-Type", ct_primary, cfg_.timeout_ms)) goto cleanup;
      if (!send_header_kv_mime(&ssl, "Content-Transfer-Encoding", "base64", cfg_.timeout_ms)) goto cleanup;
      if (!send_crlf_mime(&ssl, cfg_.timeout_ms)) goto cleanup;
      const unsigned char* in=(const unsigned char*)body; size_t rem=strlen(body); unsigned char b64o[80]; size_t ol;
      while(rem>0){ size_t chunk= rem>57?57:rem; if(mbedtls_base64_encode(b64o,sizeof(b64o),&ol,in,chunk)!=0) goto cleanup; if(!ssl_write_all_nb_mime(&ssl,(const char*)b64o,(int)ol,cfg_.timeout_ms)) goto cleanup; if(!send_crlf_mime(&ssl, cfg_.timeout_ms)) goto cleanup; in+=chunk; rem-=chunk; }
      if (!send_crlf_mime(&ssl, cfg_.timeout_ms)) goto cleanup; }
    if (has_attachment) {
      char lnb[256]; int l4=snprintf(lnb,sizeof(lnb),"--%s\r\n", boundary); if (!ssl_write_all_nb_mime(&ssl,lnb,l4,cfg_.timeout_ms)) goto cleanup;
      char ct2[256]; snprintf(ct2,sizeof(ct2),"application/octet-stream; name=\"%s\"", attachment_name); if(!send_header_kv_mime(&ssl, "Content-Type", ct2, cfg_.timeout_ms)) goto cleanup;
      char cd[256]; snprintf(cd,sizeof(cd),"attachment; filename=\"%s\"", attachment_name); if(!send_header_kv_mime(&ssl, "Content-Disposition", cd, cfg_.timeout_ms)) goto cleanup;
      if (!send_header_kv_mime(&ssl, "Content-Transfer-Encoding", "base64", cfg_.timeout_ms)) goto cleanup;
      if (!send_crlf_mime(&ssl, cfg_.timeout_ms)) goto cleanup;
      const unsigned char* in2=(const unsigned char*)attachment_content; size_t rem2=strlen(attachment_content); unsigned char b64o2[80]; size_t ol2;
      while(rem2>0){ size_t chunk2= rem2>57?57:rem2; if(mbedtls_base64_encode(b64o2,sizeof(b64o2),&ol2,in2,chunk2)!=0) goto cleanup; if(!ssl_write_all_nb_mime(&ssl,(const char*)b64o2,(int)ol2,cfg_.timeout_ms)) goto cleanup; if(!send_crlf_mime(&ssl, cfg_.timeout_ms)) goto cleanup; in2+=chunk2; rem2-=chunk2; }
      if (!send_crlf_mime(&ssl, cfg_.timeout_ms)) goto cleanup;
    }
    { char endb[128]; int le=snprintf(endb,sizeof(endb),"--%s--\r\n", boundary); if(!ssl_write_all_nb_mime(&ssl,endb,le,cfg_.timeout_ms)) goto cleanup; }
    if (!ssl_write_all_nb_mime(&ssl, "\r\n.\r\n", 5, cfg_.timeout_ms)) goto cleanup;
    if (!ssl_read_line_nb_mime(&ssl, resp, sizeof(resp), cfg_.timeout_ms) || strncmp(resp,"250",3)!=0) goto cleanup;
    len = snprintf(resp, sizeof(resp), "QUIT\r\n"); ssl_write_all_nb_mime(&ssl, resp, len, cfg_.timeout_ms);
    mbedtls_ssl_close_notify(&ssl); mbedtls_net_free(&server_fd); mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf); mbedtls_ctr_drbg_free(&ctr_drbg); mbedtls_entropy_free(&entropy);
    return true;
cleanup:
    mbedtls_net_free(&server_fd); mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf); mbedtls_ctr_drbg_free(&ctr_drbg); mbedtls_entropy_free(&entropy);
    return false;
}
