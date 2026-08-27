#pragma once

#include "soc/soc_caps.h"

#ifndef SOC_WIFI_SUPPORTED
#define SOC_WIFI_SUPPORTED 0
#endif

#define ESP32_OT_MGMT_WIFI_ONLY 1
#define ESP32_OT_MGMT_ETHERNET_ONLY 2

#ifndef ESP32_OT_WIFI_BACKEND_REMOTE
#define ESP32_OT_WIFI_BACKEND_REMOTE 0
#endif

#ifndef ESP32_OT_MGMT_POLICY
#error "ESP32_OT_MGMT_POLICY must be defined by the selected board profile"
#endif

#if ESP32_OT_MGMT_POLICY != ESP32_OT_MGMT_WIFI_ONLY && \
    ESP32_OT_MGMT_POLICY != ESP32_OT_MGMT_ETHERNET_ONLY
#error "ESP32_OT_MGMT_POLICY has an unsupported value"
#endif

#if ESP32_OT_MGMT_POLICY == ESP32_OT_MGMT_WIFI_ONLY && \
    !SOC_WIFI_SUPPORTED && !ESP32_OT_WIFI_BACKEND_REMOTE
#error "Wi-Fi management requires native Wi-Fi or ESP32_OT_WIFI_BACKEND_REMOTE"
#endif

#if (defined(BOARD_TPOE_PRO) + defined(BOARD_ESP32_S3_ETH) + \
     defined(BOARD_WAVESHARE_ESP32P4_ETH) + \
     defined(BOARD_GUITION_JC_ESP32P4_M3_DEV)) != 1
#error "Exactly one supported BOARD_* identity must be defined"
#endif

namespace NetworkPolicy {

enum class ManagementInterface {
    WiFi,
    Ethernet,
};

const char* boardName();
constexpr bool usesRemoteWiFi() { return ESP32_OT_WIFI_BACKEND_REMOTE == 1; }
constexpr bool hasWiFi() { return SOC_WIFI_SUPPORTED || usesRemoteWiFi(); }
constexpr ManagementInterface managementInterface() {
#if ESP32_OT_MGMT_POLICY == ESP32_OT_MGMT_WIFI_ONLY
    return ManagementInterface::WiFi;
#else
    return ManagementInterface::Ethernet;
#endif
}
constexpr bool managementUsesWiFi() {
    return managementInterface() == ManagementInterface::WiFi;
}
constexpr bool managementUsesEthernet() {
    return managementInterface() == ManagementInterface::Ethernet;
}
const char* managementInterfaceName();

}  // namespace NetworkPolicy
