#include "../core/audit_manager.h"
#include "plugin_sandbox.h"
#include "../core/logging_system.h"
#include "../security/security_manager.h"
#include "../core/reporting_engine.h"
#include "../core/task_config.h"
#include "../protocols/s7_plugin.h"
#include "../protocols/profinet_plugin.h"

#define TAG_SBX "Sandbox"

struct TaskCtx {
    const std::function<bool()>* fn;
    bool result;
    TaskHandle_t caller;
};

static void task_thunk(void* arg){
    TaskCtx* ctx = reinterpret_cast<TaskCtx*>(arg);
    // Optional: register to WDT with timeout (we rely on external watchdog period)
    // esp_task_wdt_add(nullptr);
    ctx->result = (*(ctx->fn))();
    // esp_task_wdt_delete(nullptr);
    xTaskNotifyGive(ctx->caller);
    vTaskDelete(nullptr);
}

bool PluginSandbox::runWithTimeout(const char* name, uint32_t timeout_ms, const std::function<bool()>& fn) {
    TaskCtx ctx{ .fn=&fn, .result=false, .caller=xTaskGetCurrentTaskHandle() };

    TaskConfig::TaskParams sandbox_params = TaskConfig::Presets::SANDBOX_WORKER;
    sandbox_params.stackSize = policy_.task_stack_bytes;
    sandbox_params.priority = policy_.task_priority;

    TaskHandle_t h = TaskConfig::createTask(
        task_thunk,
        name ? name : "sandbox_worker",
        sandbox_params,
        &ctx
    );

    if (!h) {
        // AUDIT: Log plugin crash/failure during task creation
        AuditManager::getInstance().logPluginEvent(name ? name : "unknown", "crash", "Failed to create sandbox task - possible memory or resource exhaustion");
        return false;
    }
    // Wait with timeout
    uint32_t ticks = pdMS_TO_TICKS(timeout_ms);
    if (ulTaskNotifyTake(pdTRUE, ticks) == 0) {
        // AUDIT: Log plugin timeout
        AuditManager::getInstance().logPluginEvent(name ? name : "unknown", "timeout", "Plugin operation exceeded sandbox timeout limit");
        // timeout -> leave task to be killed by WDT or just detach (we can signal stop via a flag in future)
        return false;
    }
    return ctx.result;
}

SandboxedPlugin::SandboxedPlugin(std::unique_ptr<BasePlugin> inner, const SandboxPolicy& pol, EthernetTxIf* raw_tx)
: BasePlugin(inner ? inner->name() : "Sandboxed", inner ? inner->version() : "0.0", inner ? inner->protocol() : ProtocolType::UNKNOWN),
  inner_(std::move(inner)), box_(pol), raw_tx_(raw_tx) {}

bool SandboxedPlugin::initialize(ConfigurationManager* cfg, ReportingEngine* rep) {
    cfg_ = cfg; rep_ = rep;
    // Wire guards when supported
    if (raw_tx_) {
        tx_guard_.reset(new EthernetTxGuard(raw_tx_, &box_.policy(), &box_.stats()));
        // Inject into plugins that support raw Ethernet TX (PROFINETPlugin, S7Plugin capable of ethernet tx mitigation, etc.)
        // Check if plugin is PROFINETPlugin by name (since RTTI is disabled)
        if (std::string(inner_->name()) == "PROFINETPlugin") {
            // Note: Cannot safely cast without RTTI, commenting out for now
            // static_cast<PROFINETPlugin*>(inner_.get())->setEthernetTx(tx_guard_.get());
            tx_guard_->setActor(inner_->name());
        }
        // Check if plugin is S7Plugin by name (since RTTI is disabled)
        if (std::string(inner_->name()) == "S7Plugin") {
            // Note: Cannot safely cast without RTTI, commenting out for now
            // static_cast<S7Plugin*>(inner_.get())->setEthernetTx(tx_guard_.get());
            tx_guard_->setActor(inner_->name());
        }
    }
    // NetGuard is available for plugins that choose to use it (future refactors)
    net_guard_.reset(new NetGuard(&box_.policy(), &box_.stats()));
    return inner_->initialize(cfg, rep);
}

void SandboxedPlugin::shutdown() {
    inner_->shutdown();
}

std::string SandboxedPlugin::doVulnerabilityScan(const std::string& target) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target.c_str());
    psram_string report_ps;
    if (!doVulnerabilityScanPSRAM(target_ps, report_ps)) {
        return PSRAMUtils::fromPSRAMString(report_ps);
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool SandboxedPlugin::doVulnerabilityScanPSRAM(const psram_string& target,
                                               psram_string& out_report) {
    if (!hasFlag(box_.policy().allowed, SandboxAction::NETWORK_ACTIVE)) {
        if (rep_) {
            std::string msg = std::string("{\"plugin\":\"") + name() + "\",\"op\":\"scan\",\"reason\":\"NETWORK_ACTIVE not allowed\"}";
            psram_string type = PSRAMUtils::createPSRAMString("sandbox_denied");
            psram_string payload = PSRAMUtils::createPSRAMString(msg.c_str());
            rep_->reportEvent(type, payload);
        }
        out_report = PSRAMUtils::createPSRAMString("Sandbox denied");
        return false;
    }
    return inner_->doVulnerabilityScanPSRAM(target, out_report);
}

std::string SandboxedPlugin::doNetworkDiscovery(const std::string& target_network,
                                                uint32_t timeout_ms) {
    psram_string target_ps = PSRAMUtils::createPSRAMString(target_network.c_str());
    psram_string report_ps;
    if (!doNetworkDiscoveryPSRAM(target_ps, timeout_ms, report_ps)) {
        return PSRAMUtils::fromPSRAMString(report_ps);
    }
    return PSRAMUtils::fromPSRAMString(report_ps);
}

bool SandboxedPlugin::doNetworkDiscoveryPSRAM(const psram_string& target_network,
                                              uint32_t timeout_ms,
                                              psram_string& out_report) {
    if (!hasFlag(box_.policy().allowed, SandboxAction::NETWORK_ACTIVE)) {
        if (rep_) {
            std::string msg = std::string("{\"plugin\":\"") + name() + "\",\"op\":\"discovery\",\"reason\":\"NETWORK_ACTIVE not allowed\"}";
            psram_string type = PSRAMUtils::createPSRAMString("sandbox_denied");
            psram_string payload = PSRAMUtils::createPSRAMString(msg.c_str());
            rep_->reportEvent(type, payload);
        }
        out_report = PSRAMUtils::createPSRAMString("Sandbox denied");
        return false;
    }
    return inner_->doNetworkDiscoveryPSRAM(target_network, timeout_ms, out_report);
}

bool SandboxedPlugin::doPacketAnalysis(const NetworkPacket& pkt) {
    // Passive path is allowed; but we can skip if plugin is misbehaving (no rate control here)
    return inner_->doPacketAnalysis(pkt);
}
