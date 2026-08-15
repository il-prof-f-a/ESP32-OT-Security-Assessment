#include "webhook_reporter.h"
#include <cstring>

bool WebhookReporter::init(const WebhookConfig& c){
    cfg_ = c; return true;
}

bool WebhookReporter::post(const std::string& payload){
    std::lock_guard<std::mutex> lk(mtx_);
    if (cfg_.url.empty()) return false;
    esp_http_client_config_t cc = {};
    cc.url = cfg_.url.c_str();
    cc.timeout_ms = cfg_.timeout_ms;
    esp_http_client_handle_t h = esp_http_client_init(&cc);
    if (!h) return false;
    esp_http_client_set_method(h, HTTP_METHOD_POST);
    esp_http_client_set_header(h, "Content-Type", cfg_.content_type.c_str());
    if (!cfg_.header.empty()) {
        // split "Name: Value" once
        auto pos = cfg_.header.find(':');
        if (pos != std::string::npos) {
            std::string k = cfg_.header.substr(0,pos);
            std::string v = cfg_.header.substr(pos+1);
            // trim space
            while(!v.empty() && (v[0]==' '||v[0]=='\t')) v.erase(0,1);
            esp_http_client_set_header(h, k.c_str(), v.c_str());
        }
    }
    esp_http_client_set_post_field(h, payload.c_str(), (int)payload.size());
    esp_err_t e = esp_http_client_perform(h);
    int status = esp_http_client_get_status_code(h);
    esp_http_client_cleanup(h);
    return (e == ESP_OK && status>=200 && status<300);
}
