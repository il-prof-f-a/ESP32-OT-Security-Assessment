#include "core/crash_diagnostics.h"

#include <cassert>
#include <cstring>
#include <cstdio>

namespace {
esp_err_t image_status = ESP_ERR_NOT_FOUND;
esp_err_t reason_status = ESP_OK;
bool reason_called = false;
const char* reason_text = "";
}

esp_err_t esp_core_dump_image_check() { return image_status; }

esp_err_t esp_core_dump_get_panic_reason(char* buffer, size_t size) {
    reason_called = true;
    if (reason_status != ESP_OK) return reason_status;
    std::snprintf(buffer, size, "%s", reason_text);
    return ESP_OK;
}

int main() {
    // No valid image: do not attempt to parse a panic reason.
    auto missing = CrashDiagnostics::inspectCoredump();
    assert(missing.image_status == ESP_ERR_NOT_FOUND);
    assert(missing.reason_status == ESP_ERR_NOT_FOUND);
    assert(!missing.hasPanicReason());
    assert(!reason_called);

    // A valid image is parsed and its bounded reason is exposed.
    image_status = ESP_OK;
    reason_text = "Guru Meditation Error: Core 1 panic'ed";
    auto valid = CrashDiagnostics::inspectCoredump();
    assert(valid.image_status == ESP_OK);
    assert(valid.reason_status == ESP_OK);
    assert(valid.hasPanicReason());
    assert(std::strstr(valid.panic_reason, "Guru Meditation") != nullptr);
    assert(reason_called);

    // A corrupt/invalid image is reported, without pretending parsing succeeded.
    reason_called = false;
    image_status = ESP_FAIL;
    auto corrupt = CrashDiagnostics::inspectCoredump();
    assert(corrupt.image_status == ESP_FAIL);
    assert(corrupt.reason_status == ESP_ERR_NOT_FOUND);
    assert(!corrupt.hasPanicReason());
    assert(!reason_called);

    // A parser failure remains visible to the caller.
    image_status = ESP_OK;
    reason_status = ESP_FAIL;
    auto parse_failed = CrashDiagnostics::inspectCoredump();
    assert(parse_failed.image_status == ESP_OK);
    assert(parse_failed.reason_status == ESP_FAIL);
    assert(!parse_failed.hasPanicReason());
    std::puts("Crash diagnostics coredump inspection: all scenarios passed");
}
