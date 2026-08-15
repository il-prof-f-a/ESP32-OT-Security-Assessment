#pragma once
#include <string>
#include <atomic>
#include <cstdint>

class ReportingEngine;
class Logger;

struct AuditCounters {
    std::atomic<uint32_t> denied{0};
    std::atomic<uint32_t> timeouts{0};
    std::atomic<uint32_t> ratelimits{0};
};

struct AuditSnapshot {
    uint32_t denied;
    uint32_t timeouts;
    uint32_t ratelimits;
};

class SandboxAuditor {
public:
    static SandboxAuditor& get();

    void init(ReportingEngine* rep, Logger* log);

    // Existing sandbox audit methods
    void logDenied(const char* actor, const char* what, const char* reason);
    void logTimeout(const char* actor, const char* op, uint32_t timeout_ms);
    void logRateLimit(const char* actor, const char* op);

    // New system audit methods (FASE 2)
    void logSystemReboot(const char* reason, const char* user = nullptr, const char* client_ip = nullptr);
    void logSystemStartup(const char* version, const char* build_date = nullptr);
    void logServiceEvent(const char* service, const char* action, const char* details = nullptr);
    void logPluginEvent(const char* plugin, const char* action, const char* details = nullptr);
    void logSecurityEvent(const char* event_type, const char* user = nullptr, const char* client_ip = nullptr, const char* details = nullptr);
    void logConfigChangeAudit(const char* config_type, const char* user = nullptr, const char* client_ip = nullptr, const char* details = nullptr);

    AuditSnapshot snapshot() const {
        AuditSnapshot snap;
        snap.denied = counters_.denied.load();
        snap.timeouts = counters_.timeouts.load();
        snap.ratelimits = counters_.ratelimits.load();
        return snap;
    }

private:
    SandboxAuditor() = default;
    ReportingEngine* rep_ = nullptr;
    Logger* log_ = nullptr;
    AuditCounters counters_;
};