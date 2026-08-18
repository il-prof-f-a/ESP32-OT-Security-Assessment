#pragma once

#include <cstddef>

#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_netif.h"

#include "../provisioning/provisioning_store.h"
#include "../provisioning/runtime_tls_credentials.h"
#include "../provisioning/setup_session.h"

class ConfigurationManager;


class ProvisioningServer {
public:
    ProvisioningServer(ConfigurationManager& config,
                       ProvisioningStore& store,
                       SetupSession& session);
    ~ProvisioningServer();
    bool start(esp_netif_t* interface = nullptr);
    void stop();
    bool tlsFingerprint(char* output, size_t output_size) const {
        return tls_credentials_.sha256Fingerprint(output, output_size);
    }
    static void setSecurityHeaders(httpd_req_t* request);

private:
    static esp_err_t handleRoot(httpd_req_t* request);
    static esp_err_t handleStatus(httpd_req_t* request);
    static esp_err_t handleComplete(httpd_req_t* request);
    static void rebootTimer(void* argument);
    static ProvisioningServer* from(httpd_req_t* request);
    bool scheduleReboot();

    ConfigurationManager& config_;
    ProvisioningStore& store_;
    SetupSession& session_;
    RuntimeTlsCredentials tls_credentials_;
    httpd_handle_t server_ = nullptr;
    esp_timer_handle_t reboot_timer_ = nullptr;
};
