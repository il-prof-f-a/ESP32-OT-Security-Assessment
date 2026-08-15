#pragma once
#include <string>
#include <mutex>
extern "C" {
  #include "mqtt_client.h"
}

struct MqttConfig {
    std::string uri;       // e.g. mqtts://user:pass@host:8883
    std::string client_id; // optional
    std::string topic = "ics/events";
    int qos = 0;
    bool retain = false;
    // TLS CA pem (optional)
    std::string ca_pem;
};

class MQTTReporter {
public:
    MQTTReporter() = default;
    ~MQTTReporter();

    bool start(const MqttConfig& cfg);
    bool publish(const std::string& payload);

private:
    MqttConfig cfg_;
    esp_mqtt_client_handle_t client_ = nullptr;
    std::mutex mtx_;
};
