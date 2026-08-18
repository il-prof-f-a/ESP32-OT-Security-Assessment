#include "provisioning_server.h"

#include <cstdio>
#include <cstring>

#include "../core/configuration_manager.h"
#include "../security/password_hasher.h"
#include "cJSON.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "ui/gen/provisioning_html_gen.hpp"


#ifndef ESP32_OT_WEB_HTTP_ONLY
#define ESP32_OT_WEB_HTTP_ONLY 0
#endif

namespace {
constexpr size_t kMaximumBodyBytes = 4096;

bool allowedUniqueKeys(cJSON* object, const char* const* allowed, size_t count) {
    if (!cJSON_IsObject(object)) return false;
    for (cJSON* item = object->child; item; item = item->next) {
        if (!item->string) return false;
        size_t matches = 0;
        for (size_t index = 0; index < count; ++index) {
            if (std::strcmp(item->string, allowed[index]) == 0) ++matches;
        }
        if (matches != 1) return false;
        for (cJSON* previous = object->child; previous != item; previous = previous->next) {
            if (previous->string && std::strcmp(previous->string, item->string) == 0) {
                return false;
            }
        }
    }
    return true;
}

esp_err_t sendJson(httpd_req_t* request, const char* status, const char* body) {
    ProvisioningServer::setSecurityHeaders(request);
    httpd_resp_set_status(request, status);
    httpd_resp_set_type(request, "application/json");
    return httpd_resp_sendstr(request, body);
}

const char* boardName() {
#if defined(BOARD_WAVESHARE_ESP32P4_ETH)
    return "waveshare-esp32p4-eth";
#elif defined(BOARD_ESP32_S3_ETH)
    return "esp32-s3-eth";
#else
    return "t-poe-pro";
#endif
}
}  // namespace


ProvisioningServer::ProvisioningServer(ConfigurationManager& config,
                                       ProvisioningStore& store,
                                       SetupSession& session)
    : config_(config), store_(store), session_(session) {}

ProvisioningServer::~ProvisioningServer() {
    stop();
}

ProvisioningServer* ProvisioningServer::from(httpd_req_t* request) {
    return request ? static_cast<ProvisioningServer*>(request->user_ctx) : nullptr;
}

void ProvisioningServer::setSecurityHeaders(httpd_req_t* request) {
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    httpd_resp_set_hdr(request, "Pragma", "no-cache");
    httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(request, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(
        request, "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'");
}

esp_err_t ProvisioningServer::handleRoot(httpd_req_t* request) {
    setSecurityHeaders(request);
    httpd_resp_set_type(request, "text/html; charset=utf-8");
    return httpd_resp_send(request, PROVISIONING_HTML_GEN,
                           PROVISIONING_HTML_GEN_SIZE);
}

esp_err_t ProvisioningServer::handleStatus(httpd_req_t* request) {
    ProvisioningServer* self = from(request);
    if (!self) return ESP_FAIL;
    char fingerprint[96] = {};
    self->tls_credentials_.sha256Fingerprint(fingerprint, sizeof(fingerprint));
    char response[384] = {};
    std::snprintf(
        response, sizeof(response),
        "{\"board\":\"%s\",\"network\":\"%s\",\"transport\":\"%s\",\"expires_in_ms\":%llu,\"tls_fingerprint_sha256\":\"%s\"}",
        boardName(),
#if defined(BOARD_WAVESHARE_ESP32P4_ETH)
        "ethernet",
#else
        "wifi-ap",
#endif
#if ESP32_OT_WEB_HTTP_ONLY
        "http",
#else
        "https",
#endif
        static_cast<unsigned long long>(self->session_.remainingMilliseconds()),
        fingerprint);
    return sendJson(request, "200 OK", response);
}

esp_err_t ProvisioningServer::handleComplete(httpd_req_t* request) {
    ProvisioningServer* self = from(request);
    if (!self) return ESP_FAIL;
    if (request->content_len <= 0 || request->content_len > kMaximumBodyBytes) {
        return sendJson(request, "413 Payload Too Large", "{\"error\":\"invalid_body_size\"}");
    }

    const size_t token_length = httpd_req_get_hdr_value_len(request, "X-Setup-Token");
    char token[33] = {};
    if (token_length != 32 ||
        httpd_req_get_hdr_value_str(request, "X-Setup-Token", token, sizeof(token)) != ESP_OK ||
        !self->session_.validateToken(token, token_length)) {
        std::memset(token, 0, sizeof(token));
        return sendJson(request,
                        self->session_.isLockedOut() ? "429 Too Many Requests" : "403 Forbidden",
                        "{\"error\":\"invalid_or_expired_setup_token\"}");
    }
    std::memset(token, 0, sizeof(token));

    char body[kMaximumBodyBytes + 1] = {};
    size_t received = 0;
    while (received < static_cast<size_t>(request->content_len)) {
        const int chunk = httpd_req_recv(
            request, body + received,
            static_cast<size_t>(request->content_len) - received);
        if (chunk <= 0) return sendJson(request, "400 Bad Request", "{\"error\":\"body_read_failed\"}");
        received += static_cast<size_t>(chunk);
    }
    if (std::memchr(body, '\0', received) != nullptr) {
        return sendJson(request, "400 Bad Request", "{\"error\":\"embedded_nul\"}");
    }

    cJSON* root = cJSON_ParseWithLength(body, received);
    static const char* const top_keys[] = {
        "admin_password", "admin_password_confirmation", "network"};
    static const char* const network_keys[] = {
        "wifi_enabled", "wifi_ssid", "wifi_password", "ethernet_dhcp"};
    cJSON* network = root ? cJSON_GetObjectItemCaseSensitive(root, "network") : nullptr;
    if (!root || !allowedUniqueKeys(root, top_keys, 3) ||
        !allowedUniqueKeys(network, network_keys, 4)) {
        if (root) cJSON_Delete(root);
        std::memset(body, 0, sizeof(body));
        return sendJson(request, "400 Bad Request", "{\"error\":\"invalid_or_unknown_json_keys\"}");
    }

    cJSON* password = cJSON_GetObjectItemCaseSensitive(root, "admin_password");
    cJSON* confirmation = cJSON_GetObjectItemCaseSensitive(root, "admin_password_confirmation");
    cJSON* wifi_enabled = cJSON_GetObjectItemCaseSensitive(network, "wifi_enabled");
    cJSON* wifi_ssid = cJSON_GetObjectItemCaseSensitive(network, "wifi_ssid");
    cJSON* wifi_password = cJSON_GetObjectItemCaseSensitive(network, "wifi_password");
    cJSON* ethernet_dhcp = cJSON_GetObjectItemCaseSensitive(network, "ethernet_dhcp");
    const bool fields_valid = cJSON_IsString(password) && cJSON_IsString(confirmation) &&
        cJSON_IsBool(wifi_enabled) && cJSON_IsString(wifi_ssid) &&
        cJSON_IsString(wifi_password) && cJSON_IsBool(ethernet_dhcp) &&
        password->valuestring && confirmation->valuestring &&
        std::strcmp(password->valuestring, confirmation->valuestring) == 0;
    if (!fields_valid || !PasswordHasher::validatePolicy(
            password && password->valuestring ? password->valuestring : nullptr,
            password && password->valuestring ? std::strlen(password->valuestring) : 0)) {
        cJSON_Delete(root);
        std::memset(body, 0, sizeof(body));
        return sendJson(request, "400 Bad Request", "{\"error\":\"invalid_administrator_password\"}");
    }

    const bool enable_wifi = cJSON_IsTrue(wifi_enabled);
#if defined(BOARD_WAVESHARE_ESP32P4_ETH)
    if (enable_wifi) {
        cJSON_Delete(root);
        std::memset(body, 0, sizeof(body));
        return sendJson(request, "400 Bad Request", "{\"error\":\"wifi_not_supported\"}");
    }
#endif
    const size_t ssid_length = std::strlen(wifi_ssid->valuestring);
    const size_t wifi_password_length = std::strlen(wifi_password->valuestring);
    if (enable_wifi && (ssid_length == 0 || ssid_length > 32 ||
                        wifi_password_length < 8 || wifi_password_length > 63)) {
        cJSON_Delete(root);
        std::memset(body, 0, sizeof(body));
        return sendJson(request, "400 Bad Request", "{\"error\":\"invalid_wifi_configuration\"}");
    }

    ProvisioningSubmission submission;
    submission.admin_password = PSRAMUtils::createPSRAMString(password->valuestring);
    submission.wifi_enabled = enable_wifi;
    submission.wifi_ssid = PSRAMUtils::createPSRAMString(wifi_ssid->valuestring);
    submission.wifi_password = PSRAMUtils::createPSRAMString(wifi_password->valuestring);
    submission.ethernet_dhcp = cJSON_IsTrue(ethernet_dhcp);
    psram_string admin_hash;
    const bool derived = PasswordHasher::derive(
        submission.admin_password.c_str(), submission.admin_password.size(), admin_hash);
    cJSON_Delete(root);
    std::memset(body, 0, sizeof(body));
    if (!derived || !self->store_.commit(submission, admin_hash, self->config_)) {
        submission.zeroizeSecrets();
        return sendJson(request, "500 Internal Server Error", "{\"error\":\"storage_transaction_failed\"}");
    }
    submission.zeroizeSecrets();
    self->session_.consume();
    self->scheduleReboot();
    return sendJson(request, "200 OK", "{\"status\":\"provisioned\",\"reboot_in_seconds\":2}");
}

void ProvisioningServer::rebootTimer(void*) {
    esp_restart();
}

bool ProvisioningServer::scheduleReboot() {
    if (!reboot_timer_) {
        const esp_timer_create_args_t arguments = {
            .callback = &ProvisioningServer::rebootTimer,
            .arg = nullptr,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "setup_reboot",
            .skip_unhandled_events = true,
        };
        if (esp_timer_create(&arguments, &reboot_timer_) != ESP_OK) return false;
    }
    return esp_timer_start_once(reboot_timer_, 2000000ULL) == ESP_OK;
}

bool ProvisioningServer::start(esp_netif_t*) {
    if (server_) return true;
#if ESP32_OT_WEB_HTTP_ONLY
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 3;
    if (httpd_start(&server_, &config) != ESP_OK) return false;
#else
    if (!tls_credentials_.ensurePresent()) return false;
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.server_port = 443;
    config.httpd.max_uri_handlers = 3;
    config.servercert = reinterpret_cast<const uint8_t*>(tls_credentials_.certificatePem());
    config.servercert_len = tls_credentials_.certificateLength() + 1;
    config.prvtkey_pem = reinterpret_cast<const uint8_t*>(tls_credentials_.privateKeyPem());
    config.prvtkey_len = tls_credentials_.privateKeyLength() + 1;
    if (httpd_ssl_start(&server_, &config) != ESP_OK) return false;
#endif

    const httpd_uri_t root = {"/", HTTP_GET, &ProvisioningServer::handleRoot, this};
    const httpd_uri_t status = {"/api/provisioning/status", HTTP_GET,
                                &ProvisioningServer::handleStatus, this};
    const httpd_uri_t complete = {"/api/provisioning/complete", HTTP_POST,
                                  &ProvisioningServer::handleComplete, this};
    if (httpd_register_uri_handler(server_, &root) != ESP_OK ||
        httpd_register_uri_handler(server_, &status) != ESP_OK ||
        httpd_register_uri_handler(server_, &complete) != ESP_OK) {
        stop();
        return false;
    }
    return true;
}

void ProvisioningServer::stop() {
    if (reboot_timer_) {
        esp_timer_stop(reboot_timer_);
        esp_timer_delete(reboot_timer_);
        reboot_timer_ = nullptr;
    }
    if (server_) {
#if ESP32_OT_WEB_HTTP_ONLY
        httpd_stop(server_);
#else
        httpd_ssl_stop(server_);
#endif
        server_ = nullptr;
    }
}
