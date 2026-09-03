#pragma once
#include <cstdint>
#include "psram_allocator.h"

// A durable event can be delivered, retried after a transient failure, or held
// until its channel becomes available (for example while a network interface is
// still coming up after boot).
enum class QueueDeliveryResult : uint8_t {
    DELIVERED,
    RETRY,
    DEFERRED,
};

// Common queue event structure used by both ReliableQueue and PSRAMReliableQueue
struct QueuedEvent {
    psram_string id;           // filename stem
    psram_string payload;      // already formatted string to send
    psram_string channel;      // reporter channel name ("mqtt","webhook","email","file")
    uint32_t attempts = 0;
    uint64_t next_attempt_ms = 0;
};
