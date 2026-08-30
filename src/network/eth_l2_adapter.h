
#pragma once
#include <cstdint>
#include <string>
#include <atomic>
extern "C" {
  #include "esp_eth.h"
  #include "esp_netif.h"
  #include "esp_idf_version.h"
#if defined(CONFIG_ESP_NETIF_L2_TAP) && CONFIG_ESP_NETIF_L2_TAP
  #include "esp_vfs_l2tap.h"
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
#endif
}
class NetworkEngine;

// Wrap the Ethernet driver's input path to sniff L2 frames (IDF v5).
class EthL2Adapter {
public:
    bool attach(esp_eth_handle_t eth, NetworkEngine* engine);
    bool attach(esp_eth_handle_t eth, esp_netif_t* netif, NetworkEngine* engine);
    void detach();

    // Status methods
    bool isAttached() const { return eth_ != nullptr && eng_ != nullptr; }
    bool isPromiscuousModeEnabled() const { return promiscuous_enabled_; }

    // Utility function for MAC address formatting
    static std::string macToString(const uint8_t mac[6]) {
        char buffer[18];
        snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buffer);
    }

private:
    esp_eth_handle_t eth_ = nullptr;
    esp_netif_t* netif_ = nullptr;
    NetworkEngine* eng_ = nullptr;
    bool promiscuous_enabled_ = false;

#if defined(CONFIG_IDF_TARGET_ESP32P4) && defined(CONFIG_ESP_NETIF_L2_TAP) && CONFIG_ESP_NETIF_L2_TAP
    // ESP32-P4 uses the stock ESP-NETIF input path so that L2 TAP filtering
    // receives frames before lwIP. A dedicated task drains the PROFINET
    // EtherType queue and forwards complete Ethernet frames to NetworkEngine.
    int tap_fd_ = -1;
    TaskHandle_t tap_task_ = nullptr;
    std::atomic<bool> tap_running_{false};

    bool attachL2Tap();
    void detachL2Tap();
    static void tapTaskThunk(void* arg);
    void tapTask();
    static esp_err_t l2tapInputTrampoline(esp_eth_handle_t h, uint8_t* buffer,
                                          uint32_t length, void* priv, void* info);
#endif


    static esp_err_t input_trampoline(esp_eth_handle_t h, uint8_t* buffer, uint32_t length, void* priv);
    void dispatchFrameToEngine(const uint8_t* buffer, uint32_t length);
    bool enablePromiscuousMode();
};
