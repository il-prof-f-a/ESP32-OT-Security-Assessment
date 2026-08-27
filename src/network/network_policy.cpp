#include "network_policy.h"

namespace NetworkPolicy {

const char* boardName() {
#if defined(BOARD_GUITION_JC_ESP32P4_M3_DEV)
    return "guition-jc-esp32p4-m3-dev";
#elif defined(BOARD_WAVESHARE_ESP32P4_ETH)
    return "waveshare-esp32p4-eth";
#elif defined(BOARD_ESP32_S3_ETH)
    return "esp32-s3-eth";
#else
    return "t-poe-pro";
#endif
}

const char* managementInterfaceName() {
    return managementUsesWiFi() ? "wifi" : "ethernet";
}

}  // namespace NetworkPolicy
