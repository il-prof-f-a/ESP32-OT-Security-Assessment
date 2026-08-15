#include "mqtt_reporter.h"
#include <cstring>

MQTTReporter::~MQTTReporter(){
    std::lock_guard<std::mutex> lk(mtx_);
    if (client_) { esp_mqtt_client_stop(client_); esp_mqtt_client_destroy(client_); client_ = nullptr; }
}

bool MQTTReporter::start(const MqttConfig& c){
    std::lock_guard<std::mutex> lk(mtx_);
    cfg_ = c;
    esp_mqtt_client_config_t mcfg = {};
    mcfg.broker.address.uri = cfg_.uri.c_str();
    if (!cfg_.client_id.empty()) mcfg.credentials.client_id = cfg_.client_id.c_str();
    if (!cfg_.ca_pem.empty())    mcfg.broker.verification.certificate = cfg_.ca_pem.c_str();
    client_ = esp_mqtt_client_init(&mcfg);
    if (!client_) return false;
    esp_err_t e = esp_mqtt_client_start(client_);
    return e == ESP_OK;
}

bool MQTTReporter::publish(const std::string& payload){
    std::lock_guard<std::mutex> lk(mtx_);
    if (!client_) return false;
    int mid = esp_mqtt_client_publish(client_, cfg_.topic.c_str(), payload.c_str(), (int)payload.size(), cfg_.qos, cfg_.retain);
    return mid >= 0;
}
