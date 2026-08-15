#include "memory_monitor.h"
#include "logging_system.h"
#include "format_utils.h"

extern "C" {
    #include "esp_heap_caps.h"
}

MemorySnapshot MemoryMonitor::capture() {
    MemorySnapshot snap{};
    snap.internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    snap.psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    return snap;
}

void MemoryMonitor::logDelta(const char* phase, const MemorySnapshot& before) {
    MemorySnapshot after = capture();
    long internal_delta = static_cast<long>(before.internal) - static_cast<long>(after.internal);
    long psram_delta = static_cast<long>(before.psram) - static_cast<long>(after.psram);

    LOG_INFOF("MEM_DELTA",
              "[%s] Internal delta=%ld B (free=%u KB) PSRAM delta=%ld B (free=%u KB)",
              phase ? phase : "unknown",
              internal_delta,
              static_cast<unsigned>(after.internal / 1024),
              psram_delta,
              static_cast<unsigned>(after.psram / 1024));
}

void MemoryMonitor::checkStatus(const char* phase, bool critical_check) {
    size_t internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    char mbbuf[32];
    fmt_bytes_mb(mbbuf, sizeof(mbbuf), static_cast<uint32_t>(psram_free), 1);
    LOG_INFOF("MEM_MONITOR", "[%s] Internal: %u KB, PSRAM: %s",
              phase ? phase : "unknown",
              static_cast<unsigned>(internal_free / 1024),
              mbbuf);

    if (internal_free < 15360) {
        LOG_ERRORF("MEM_MONITOR", "CRITICAL: Internal memory very low (%u bytes) at phase: %s",
                   static_cast<unsigned>(internal_free),
                   phase ? phase : "unknown");

        if (critical_check && internal_free < 8192) {
            LOG_ERROR("MEM_MONITOR", "FATAL: Internal memory critically low - system may crash");
            heap_caps_print_heap_info(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        }
    } else if (internal_free < 25600) {
        LOG_WARNINGF("MEM_MONITOR", "WARNING: Internal memory low (%u KB) at phase: %s",
                     static_cast<unsigned>(internal_free / 1024),
                     phase ? phase : "unknown");
    }
}
