#pragma once

#include <cstdint>

#include "../core/psram_allocator.h"


enum class ProvisioningState : uint8_t {
    UNPROVISIONED,
    LEGACY_MIGRATION_REQUIRED,
    READY,
    CORRUPT,
};

struct ProvisioningSubmission {
    psram_string admin_password = PSRAMUtils::createPSRAMString("");
    psram_string wifi_ssid = PSRAMUtils::createPSRAMString("");
    psram_string wifi_password = PSRAMUtils::createPSRAMString("");
    psram_string ethernet_ip = PSRAMUtils::createPSRAMString("");
    psram_string ethernet_netmask = PSRAMUtils::createPSRAMString("");
    psram_string ethernet_gateway = PSRAMUtils::createPSRAMString("");
    bool wifi_enabled = false;
    bool ethernet_dhcp = true;

    void zeroizeSecrets() {
        for (char& value : admin_password) value = '\0';
        for (char& value : wifi_password) value = '\0';
        admin_password.clear();
        wifi_password.clear();
    }
};
