#pragma once
#include <string>
#include <mutex>
#include <utility>
#include <vector>
extern "C" {
  #include "esp_http_client.h"
}

struct WebhookConfig {
    std::string url;
    std::string header;       // backward-compatible single header
    std::vector<std::pair<std::string, std::string>> headers;
    std::string content_type = "text/plain";
    int timeout_ms = 3000;
};

class WebhookReporter {
public:
    bool init(const WebhookConfig& c);
    bool post(const std::string& payload);
    bool post(const char* payload, size_t length);
private:
    WebhookConfig cfg_;
    std::mutex mtx_;
};
