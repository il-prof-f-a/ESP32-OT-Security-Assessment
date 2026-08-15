#include "../core/audit_manager.h"
#include "ethernet_tx_guard.h"
extern "C" {
  #include "esp_timer.h"
}

bool EthernetTxGuard::rawTx(const uint8_t* frame, size_t len) {
    if (!inner_ || !pol_) return false;
    if (!hasFlag(pol_->allowed, SandboxAction::RAW_ETH_TX)) {
        if (stats_) stats_->denied_ops++;
        AuditManager::getInstance().logDenied(actor_.c_str(), "RAW_ETH_TX", "permission");
        return false;
    }
    // Simple sliding window (per minute)
    uint64_t now_ms = (uint64_t) (esp_timer_get_time() / 1000ULL);
    if (last_window_ms_==0 || now_ms - last_window_ms_ > 60000ULL) {
        last_window_ms_ = now_ms; win_pkts_ = 0; win_bytes_ = 0;
    }
    if (win_pkts_ + 1 > pol_->max_packets_per_min){ AuditManager::getInstance().logRateLimit(actor_.c_str(), "rawTx"); return false; }
    if (win_bytes_ + len > pol_->max_bytes_per_min){ AuditManager::getInstance().logRateLimit(actor_.c_str(), "rawTx"); return false; }
    bool ok = inner_->rawTx(frame, len);
    if (ok) {
        win_pkts_++; win_bytes_ += (uint32_t)len;
        if (stats_) { stats_->tx_packets++; stats_->tx_bytes += (uint32_t)len; }
    }
    return ok;
}
