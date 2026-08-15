#pragma once
#include <cstdint>
#include "psram_allocator.h"

// Common queue event structure used by both ReliableQueue and PSRAMReliableQueue
struct QueuedEvent {
    psram_string id;           // filename stem
    psram_string payload;      // already formatted string to send
    psram_string channel;      // reporter channel name ("mqtt","webhook","email","file")
    uint32_t attempts = 0;
    uint64_t next_attempt_ms = 0;
};