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
        inspection.image_status = esp_core_dump_image_check();
        if (inspection.image_status == ESP_OK) {
            inspection.reason_status = esp_core_dump_get_panic_reason(
                inspection.panic_reason, sizeof(inspection.panic_reason));
            if (inspection.reason_status != ESP_OK) {
                inspection.panic_reason[0] = '\0';
            }
        }
        return inspection;
    }
};
