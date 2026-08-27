#include "provisioning_coordinator.h"

#include <cstdio>

#include "provisioning_store.h"
#include "setup_session.h"
#include "../core/configuration_manager.h"
#include "../network/ethernet_manager.h"
#include "../network/network_policy.h"
#include "../network/wifi_manager.h"
#include "../web/provisioning_server.h"

extern "C" {
#include "esp_efuse.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
}

#ifndef ESP32_OT_WEB_HTTP_ONLY
#define ESP32_OT_WEB_HTTP_ONLY 0
#endif

namespace {
void directSerialLine(const char* key, const char* value) {
    std::printf("%s=%s\n", key, value ? value : "");
    std::fflush(stdout);
}

[[noreturn]] void provisioningLoop(ConfigurationManager& config,
                                   ProvisioningStore& store) {
    uint8_t mac[6] = {};
    if (esp_efuse_mac_get_default(mac) != ESP_OK) {
        directSerialLine("PROVISIONING_ERROR", "MAC_UNAVAILABLE");
        while (true) vTaskDelay(pdMS_TO_TICKS(1000));
    }

    static SetupSession session;
    if (!session.begin(mac)) {
        directSerialLine("PROVISIONING_ERROR", "SESSION_CREATION_FAILED");
        while (true) vTaskDelay(pdMS_TO_TICKS(1000));
    }
    std::printf("BOOT_MODE=PROVISIONING\n");
    std::fflush(stdout);
    directSerialLine("SETUP_TOKEN", session.setupToken());

    esp_netif_t* interface = nullptr;
#if ESP32_OT_MGMT_POLICY == ESP32_OT_MGMT_ETHERNET_ONLY
    static EthernetManager ethernet(nullptr);
    while (true) {
        if (ethernet.initializeFromConfig()) {
            for (unsigned attempt = 0; attempt < 300; ++attempt) {
                if (ethernet.hasValidIP()) break;
                esp_task_wdt_reset();
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            if (ethernet.hasValidIP()) break;
        }
        ethernet.stop();
        directSerialLine("PROVISIONING_NETWORK", "WAITING_FOR_ETHERNET_DHCP");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    interface = ethernet.netif();
    char address[16] = {};
    if (ethernet.getIP(address, sizeof(address))) {
        directSerialLine("SETUP_ADDRESS", address);
    }
#else
    static WiFiManager wifi(nullptr);
    wifi.startAP(session.apSsid(), session.apPassword());
    interface = wifi.ap();
    directSerialLine("SETUP_AP_SSID", session.apSsid());
    directSerialLine("SETUP_AP_PASSWORD", session.apPassword());
    directSerialLine("SETUP_ADDRESS", "192.168.4.1");
#endif

    static ProvisioningServer server(config, store, session);
    if (!server.start(interface)) {
        directSerialLine("PROVISIONING_ERROR", "SERVER_START_FAILED");
        while (true) {
            esp_task_wdt_reset();
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
#if !ESP32_OT_WEB_HTTP_ONLY
    char fingerprint[96] = {};
    if (server.tlsFingerprint(fingerprint, sizeof(fingerprint))) {
        directSerialLine("SETUP_TLS_SHA256", fingerprint);
    }
#endif

    while (true) {
        if (session.isExpired()) {
            directSerialLine("PROVISIONING_SESSION", "EXPIRED_REBOOTING");
            esp_restart();
        }
        esp_task_wdt_reset();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
}  // namespace


bool ProvisioningCoordinator::continueOperationalBoot(ConfigurationManager& config) {
    static ProvisioningStore store;
    ProvisioningState state = store.inspect(config);
    if (state == ProvisioningState::LEGACY_MIGRATION_REQUIRED) {
        std::printf("BOOT_MODE=LEGACY_MIGRATION\n");
        std::fflush(stdout);
        if (!store.migrateLegacyIfValid(config)) {
            provisioningLoop(config, store);
        }
        state = store.inspect(config);
    }
    if (state == ProvisioningState::READY) {
        std::printf("BOOT_MODE=OPERATIONAL\n");
        std::fflush(stdout);
        return true;
    }
    if (store.commitEmbedded(config)) {
        std::printf("BOOT_MODE=OPERATIONAL\n");
        std::fflush(stdout);
        return true;
    }
    provisioningLoop(config, store);
}
