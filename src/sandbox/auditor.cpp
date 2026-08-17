#include "auditor.h"
#include "../core/reporting_engine.h"
#include "../core/event_formatter.h"
#include "../core/logging_system.h"
extern "C" {
    #include "esp_timer.h"
}

SandboxAuditor& SandboxAuditor::get() {
    static SandboxAuditor inst;
    return inst;
}

void SandboxAuditor::init(ReportingEngine* rep, Logger* log) {
    rep_ = rep; log_ = log;
}

void SandboxAuditor::logDenied(const char* actor, const char* what, const char* reason) {
    counters_.denied++;
    if (rep_) {
        EventRecord ev; ev.channel="audit"; ev.type="sandbox_denied"; ev.name="Sandbox deny"; ev.severity="Medium";
        ev.ext = {{"actor", actor?actor:""},{"what", what?what:""},{"reason", reason?reason:""}};
        ev.channel = "audit";
        rep_->submit(ev);
    }
    // COMMENTED: Prefer structured audit via ReportingEngine over duplicate LOG_WARNING
    // if (log_) {
    //     char msg[256];
    //     snprintf(msg, sizeof(msg), "DENIED actor=%s what=%s reason=%s", actor?actor:"", what?what:"", reason?reason:"");
    //     LOG_WARNING("AUDIT", msg);
    // }
}

void SandboxAuditor::logTimeout(const char* actor, const char* op, uint32_t timeout_ms) {
    counters_.timeouts++;
    if (rep_) {
        EventRecord ev; ev.channel="audit"; ev.type="sandbox_timeout"; ev.name="Sandbox timeout"; ev.severity="Medium";
        // Convert timeout to stack buffer to avoid std::to_string allocation
        char timeout_buf[16];
        snprintf(timeout_buf, sizeof(timeout_buf), "%lu", (unsigned long)timeout_ms);
        ev.ext = {{"actor", actor?actor:""},{"op", op?op:""},{"timeout_ms", timeout_buf}};
        ev.channel = "audit";
        rep_->submit(ev);
    }
    // COMMENTED: Prefer structured audit via ReportingEngine over duplicate LOG_WARNING
    // if (log_) {
    //     char msg[256];
    //     snprintf(msg, sizeof(msg), "TIMEOUT actor=%s op=%s t=%lu", actor?actor:"", op?op:"", (unsigned long)timeout_ms);
    //     LOG_WARNING("AUDIT", msg);
    // }
}

void SandboxAuditor::logRateLimit(const char* actor, const char* op) {
    counters_.ratelimits++;
    if (rep_) {
        EventRecord ev; ev.channel="audit"; ev.type="sandbox_ratelimit"; ev.name="Sandbox rate-limit"; ev.severity="Low";
        ev.ext = {{"actor", actor?actor:""},{"op", op?op:""}};
        ev.channel = "audit";
        rep_->submit(ev);
    }
    // COMMENTED: Prefer structured audit via ReportingEngine over duplicate LOG_INFO
    // if (log_) {
    //     char msg[256];
    //     snprintf(msg, sizeof(msg), "RATELIMIT actor=%s op=%s", actor?actor:"", op?op:"");
    //     LOG_INFO("AUDIT", msg);
    // }
}

// ===== PHASE 2: SYSTEM AUDIT METHODS =====

void SandboxAuditor::logSystemReboot(const char* reason, const char* user, const char* client_ip) {
    if (rep_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "system_reboot";
        ev.name = "System Reboot";
        ev.severity = "High";
        ev.ext = {
            {"reason", reason ? reason : "unknown"},
            {"user", user ? user : "system"},
            {"client_ip", client_ip ? client_ip : ""}
        };
        rep_->submit(ev);
    }
}

void SandboxAuditor::logSystemStartup(const char* version, const char* build_date) {
    if (rep_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "system_startup";
        ev.name = "System Startup";
        ev.severity = "Medium";
        ev.ext = {
            {"version", version ? version : "unknown"},
            {"build_date", build_date ? build_date : ""},
            {"heap_free", ""},  // Will be filled with current heap
            {"psram_free", ""}  // Will be filled with current PSRAM
        };

        // Add current memory status to startup event
        char heap_buf[16], psram_buf[16];
        size_t heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        snprintf(heap_buf, sizeof(heap_buf), "%zu", heap_free);
        snprintf(psram_buf, sizeof(psram_buf), "%zu", psram_free);

        ev.ext["heap_free"] = heap_buf;
        ev.ext["psram_free"] = psram_buf;

        rep_->submit(ev);
    }
}

void SandboxAuditor::logServiceEvent(const char* service, const char* action, const char* details) {
    if (rep_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "service_event";
        ev.name = "Service Event";
        ev.severity = "Medium";
        ev.ext = {
            {"service", service ? service : "unknown"},
            {"action", action ? action : "unknown"},
            {"details", details ? details : ""}
        };
        rep_->submit(ev);
    }
}

void SandboxAuditor::logPluginEvent(const char* plugin, const char* action, const char* details) {
    if (rep_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "plugin_event";
        ev.name = "Plugin Event";
        ev.severity = "Medium";
        ev.ext = {
            {"plugin", plugin ? plugin : "unknown"},
            {"action", action ? action : "unknown"},
            {"details", details ? details : ""}
        };
        rep_->submit(ev);
    }
}

void SandboxAuditor::logSecurityEvent(const char* event_type, const char* user, const char* client_ip, const char* details) {
    if (rep_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "security_event";
        ev.name = "Security Event";
        ev.severity = "High";
        ev.ext = {
            {"event_type", event_type ? event_type : "unknown"},
            {"user", user ? user : "anonymous"},
            {"client_ip", client_ip ? client_ip : ""},
            {"details", details ? details : ""}
        };
        rep_->submit(ev);

        // Also emit a plain SECURITY log line for security.log routing
        uint64_t ts_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "event_type=%s user=%s ip=%s details=%s",
                 event_type ? event_type : "unknown",
                 user ? user : "anonymous",
                 client_ip ? client_ip : "",
                 details ? details : "");
        rep_->reportLogMessage(
            PSRAMUtils::createPSRAMString("SECURITY"),
            PSRAMUtils::createPSRAMString("WARNING"),
            PSRAMUtils::createPSRAMString(msg),
            ts_ms);
    }
}

void SandboxAuditor::logConfigChangeAudit(const char* config_type, const char* user, const char* client_ip, const char* details) {
    if (rep_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "config_change";
        ev.name = "Configuration Change";
        ev.severity = "Medium";
        ev.ext = {
            {"config_type", config_type ? config_type : "unknown"},
            {"user", user ? user : "anonymous"},
            {"client_ip", client_ip ? client_ip : ""},
            {"details", details ? details : ""}
        };
        rep_->submit(ev);
    }
}
