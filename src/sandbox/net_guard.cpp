#include "../core/audit_manager.h"
#include "net_guard.h"
extern "C" {
  #include "esp_timer.h"
}

bool NetGuard::isPortAllowed(uint16_t port) const {
    if (!pol_) return false;
    for (auto p : pol_->allow_tcp_ports) if (p == port) return true;
    return false;
}

bool NetGuard::checkRate(size_t plus_bytes) {
    if (!pol_) return false;
    uint64_t now_ms = (uint64_t) (esp_timer_get_time()/1000ULL);
    if (last_window_ms_==0 || now_ms - last_window_ms_ > 60000ULL) {
        last_window_ms_ = now_ms; win_pkts_ = 0; win_bytes_ = 0;
    }
    if (win_pkts_ + 1 > pol_->max_packets_per_min) return false;
    if (win_bytes_ + plus_bytes > pol_->max_bytes_per_min) return false;
    win_pkts_++; win_bytes_ += (uint32_t)plus_bytes;
    return true;
}

int NetGuard::tcpConnect(const std::string& ip, uint16_t port, uint32_t timeout_ms) {
    if (!pol_ || !hasFlag(pol_->allowed, SandboxAction::NETWORK_ACTIVE)) { AuditManager::getInstance().logDenied(actor_.c_str(), "NETWORK_ACTIVE", "permission"); return -1; }
    if (!isPortAllowed(port)) { AuditManager::getInstance().logDenied(actor_.c_str(), "tcpConnect", "port_not_allowed"); return -1; }
    int s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    struct timeval tv{ .tv_sec=(int)(timeout_ms/1000), .tv_usec=(int)((timeout_ms%1000)*1000) };
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons(port);
    if (!::inet_aton(ip.c_str(), &sa.sin_addr)) { ::close(s); return -1; }
    if (::connect(s,(sockaddr*)&sa,sizeof(sa)) != 0) { ::close(s); return -1; }
    return s;
}

int NetGuard::udpBroadcast(uint16_t port, const void* data, size_t len) {
    if (!pol_) return -1;
    if (!hasFlag(pol_->allowed, SandboxAction::UDP_BROADCAST)) { AuditManager::getInstance().logDenied(actor_.c_str(), "udpBroadcast", "permission"); return -1; }
    if (!checkRate(len)) { AuditManager::getInstance().logRateLimit(actor_.c_str(), "udpBroadcast"); return -1; }
    int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int yes = 1; ::setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
    sockaddr_in dst{}; dst.sin_family=AF_INET; dst.sin_port=htons(port); dst.sin_addr.s_addr = htonl(0xFFFFFFFFu);
    int r = ::sendto(s, data, len, 0, (sockaddr*)&dst, sizeof(dst));
    ::close(s);
    if (stats_ && r>0) { stats_->tx_packets++; stats_->tx_bytes += (uint32_t)r; }
    return r;
}

int NetGuard::recv(int sock, void* buf, size_t len, int flags) {
    int n = ::recv(sock, buf, len, flags);
    if (stats_ && n>0) { stats_->rx_packets++; stats_->rx_bytes += (uint32_t)n; }
    return n;
}

int NetGuard::send(int sock, const void* buf, size_t len, int flags) {
    if (!pol_) return -1;
    if (!checkRate(len)) {
        AuditManager::getInstance().logRateLimit(actor_.c_str(), "send");
        return -1;
    }
    int n = ::send(sock, buf, len, flags);
    if (stats_ && n>0) { stats_->tx_packets++; stats_->tx_bytes += (uint32_t)n; }
    return n;
}
