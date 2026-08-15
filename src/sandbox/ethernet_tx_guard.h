#pragma once
#include <cstdint>
#include <cstddef>
#include "../network/ethernet_tx_if.h"
#include "sandbox_policy.h"

class EthernetTxGuard : public EthernetTxIf {
public:
    EthernetTxGuard(EthernetTxIf* inner, const SandboxPolicy* pol, SandboxStats* stats)
    : inner_(inner), pol_(pol), stats_(stats) {}
    ~EthernetTxGuard() override = default;

    void setActor(const std::string& who){ actor_ = who; }

    bool rawTx(const uint8_t* frame, size_t len) override;
    bool getMac(uint8_t out6[6]) override { return inner_ ? inner_->getMac(out6) : false; }

private:
    std::string actor_;
    EthernetTxIf* inner_;
    const SandboxPolicy* pol_;
    SandboxStats* stats_;
    uint64_t last_window_ms_ = 0;
    uint32_t win_pkts_ = 0;
    uint32_t win_bytes_= 0;
};
