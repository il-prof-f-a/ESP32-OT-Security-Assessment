#pragma once

#include <cstddef>

struct MemorySnapshot {
    size_t internal;
    size_t psram;
};

class MemoryMonitor {
public:
    static MemorySnapshot capture();
    static void logDelta(const char* phase, const MemorySnapshot& before);
    static void checkStatus(const char* phase, bool critical_check = false);
};
