#pragma once

#include <stdint.h>

#include "esp_netif.h"
#include "lwip/inet.h"

namespace IcmpPing {

enum class Status : uint8_t {
    Success = 0,
    Timeout,
    Error,
};

struct Result {
    Status status = Status::Error;
    int32_t time_ms = -1;
    uint32_t replies = 0;
};

// Send one IPv4 ICMP Echo Request through the supplied netif.
// The caller owns the netif and must keep it valid until this function returns.
bool probe(uint32_t target_addr, esp_netif_t* netif, uint32_t timeout_ms, Result& result);

}  // namespace IcmpPing
