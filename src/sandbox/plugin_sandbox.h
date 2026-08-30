#pragma once
#include <string>
#include <memory>
#include <functional>
#include "../core/types.h"
#include "../protocols/base_plugin.h"
#include "sandbox_policy.h"
#include "ethernet_tx_guard.h"
#include "net_guard.h"

extern "C" {
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "esp_timer.h"
  #include "esp_task_wdt.h"
}

class PluginSandbox {
public:
    explicit PluginSandbox(const SandboxPolicy& pol) : policy_(pol) {}
    ~PluginSandbox() = default;

    // Run a callable inside a dedicated task with timeout and (optional) WDT
    bool runWithTimeout(const char* name, uint32_t timeout_ms, const std::function<bool()>& fn);

    const SandboxPolicy& policy() const { return policy_; }
    SandboxStats& stats() { return stats_; }
    const SandboxStats& stats() const { return stats_; }

private:
    SandboxPolicy policy_;
    SandboxStats  stats_;
};

// Wrapper that decorates a BasePlugin and enforces sandboxing on active operations.
class SandboxedPlugin : public BasePlugin {
public:
    SandboxedPlugin(std::unique_ptr<BasePlugin> inner, const SandboxPolicy& pol, EthernetTxIf* raw_tx=nullptr);

    bool initialize(ConfigurationManager* cfg, ReportingEngine* rep) override;
    void shutdown() override;
    std::string doVulnerabilityScan(const std::string& target) override;
    bool doVulnerabilityScanPSRAM(const psram_string& target, psram_string& out_report) override;
    std::string doNetworkDiscovery(const std::string& target_network, uint32_t timeout_ms = 300000) override;
    bool doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                 uint32_t timeout_ms,
                                 psram_string& out_report) override;
    bool isTargetPacket(const NetworkPacket& pkt) override { return inner_->isTargetPacket(pkt); }
    void loadIDSRules(const std::string& r) override { inner_->loadIDSRules(r); }

    ProtocolType protocol() const override { return inner_->protocol(); }
    const char* name()  const override { return inner_->name(); }
    const char* version() const override { return inner_->version(); }

    // Expose sandbox stats (optional for Web UI)
    const SandboxStats& sandboxStats() const { return box_.stats(); }
    const SandboxPolicy& sandboxPolicy() const { return box_.policy(); }

private:
    bool doPacketIDSAnalysisOfProtocol(const NetworkPacket& pkt) override;
    void processDiscoveryOfProtocol(const NetworkPacket& pkt) override;
    bool acceptsDiscoveryPacket(const NetworkPacket& pkt) override;

    std::unique_ptr<BasePlugin> inner_;
    PluginSandbox box_;
    std::unique_ptr<EthernetTxGuard> tx_guard_;
    std::unique_ptr<NetGuard> net_guard_;
    EthernetTxIf* raw_tx_ = nullptr;
};
