#pragma once
#include <string>
#include <cstdint>
#include "sandbox_policy.h"

extern "C" {
  #include "lwip/sockets.h"
  #include "lwip/inet.h"
}

class NetGuard {
public:
    NetGuard(const SandboxPolicy* pol, SandboxStats* stats) : pol_(pol), stats_(stats) {}
    void setActor(const std::string& who){ actor_ = who; }
    // TCP connect with policy enforcement
    int tcpConnect(const std::string& ip, uint16_t port, uint32_t timeout_ms = 2000);
    // UDP broadcast sendto (enforces UDP_BROADCAST)
    int udpBroadcast(uint16_t port, const void* data, size_t len);
    // recv with accounting
    int recv(int sock, void* buf, size_t len, int flags);
    // send with accounting (+ rate)
    int send(int sock, const void* buf, size_t len, int flags);
private:
    const SandboxPolicy* pol_;
    std::string actor_;
    SandboxStats* stats_;
    uint64_t last_window_ms_ = 0;
    uint32_t win_pkts_ = 0;
    uint32_t win_bytes_= 0;
    bool checkRate(size_t plus_bytes);
    bool isPortAllowed(uint16_t port) const;
};
