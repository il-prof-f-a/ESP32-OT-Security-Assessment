#pragma once
#include <string>
#include <mutex>
extern "C" {
  #include "esp_http_client.h"
}

struct WebhookConfig {
    std::string url;
    std::string header;       // optional single header "Authorization: Bearer ..."
    std::string content_type = "text/plain";
    int timeout_ms = 3000;
};

class WebhookReporter {
public:
    bool init(const WebhookConfig& c);
    bool post(const std::string& payload);
private:
    WebhookConfig cfg_;
    std::mutex mtx_;
};
