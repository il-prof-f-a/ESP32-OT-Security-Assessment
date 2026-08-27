#pragma once

#include "lwip/ip_addr.h"

namespace AssessmentInterface {

// Returns the current ETH_DEF IPv4 address. Assessment traffic must fail closed
// when Ethernet is unavailable; Wi-Fi is never an assessment fallback.
bool localAddress(ip_addr_t* address);

// Creates a socket and binds it to the current ETH_DEF IPv4 address. The socket
// is closed and -1 is returned when Ethernet is unavailable or binding fails.
int openBoundSocket(int domain, int type, int protocol);

}  // namespace AssessmentInterface
