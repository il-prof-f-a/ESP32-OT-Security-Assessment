#pragma once

#include <cstddef>

#include "esp_core_dump.h"

// Read-only boundary around the ESP-IDF coredump image. It is deliberately
// independent from the panic path: the native panic handler writes the image,
// while app_main inspects it safely on the next boot after storage is ready.
struct CrashDumpInspection {
    esp_err_t image_status = ESP_ERR_NOT_FOUND;
    esp_err_t reason_status = ESP_ERR_NOT_FOUND;
    char panic_reason[200]{};

    bool hasPanicReason() const {
        return reason_status == ESP_OK && panic_reason[0] != '\0';
    }
};

class CrashDiagnostics {
public:
    static CrashDumpInspection inspectCoredump() {
        CrashDumpInspection inspection;
#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH
        inspection.image_status = esp_core_dump_image_check();
        if (inspection.image_status == ESP_OK) {
#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH && CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF
            inspection.reason_status = esp_core_dump_get_panic_reason(
                inspection.panic_reason, sizeof(inspection.panic_reason));
            if (inspection.reason_status != ESP_OK) {
                inspection.panic_reason[0] = '\0';
            }
#else
            // Keep builds made from an older/generated sdkconfig compilable. The
            // public defaults enable this path on a clean build; when a stale
            // profile still disables ELF coredumps, report that limitation rather
            // than referencing an API hidden by ESP-IDF's Kconfig guards.
            inspection.reason_status = ESP_ERR_NOT_SUPPORTED;
#endif
        }
#else
        // A previously generated profile may still select TO_NONE. ESP-IDF
        // declares the inspection APIs but omits their implementations then;
        // fail closed without creating an unresolved linker reference.
        inspection.image_status = ESP_ERR_NOT_SUPPORTED;
        inspection.reason_status = ESP_ERR_NOT_SUPPORTED;
#endif
        return inspection;
    }
};
