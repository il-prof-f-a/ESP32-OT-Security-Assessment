#pragma once
#include <string>
#include <atomic>
#include <mutex>
#include <cstdint>
#include "psram_allocator.h"

class ReportingEngine;

// Local audit configuration structure (simplified from config manager)
struct AuditConfig {
    bool enabled = true;                    // Enable/disable audit manager
    bool log_denied = true;                 // Log denied operations
    bool log_timeouts = true;               // Log timeout events
    bool log_ratelimits = true;             // Log rate limit events
    bool log_system_events = true;          // Log system audit events
    bool log_security_events = true;        // Log security events
    bool log_config_changes = true;         // Log configuration changes
    uint32_t max_events_per_second = 50;    // Rate limiting for audit events
};

struct AuditCounters {
    std::atomic<uint32_t> denied{0};
    std::atomic<uint32_t> timeouts{0};
    std::atomic<uint32_t> ratelimits{0};
    std::atomic<uint32_t> system_events{0};
    std::atomic<uint32_t> security_events{0};
    std::atomic<uint32_t> config_changes{0};
};

struct AuditSnapshot {
    uint32_t denied;
    uint32_t timeouts;
    uint32_t ratelimits;
    uint32_t system_events;
    uint32_t security_events;
    uint32_t config_changes;
};

class AuditManager {
public:
    AuditManager();
    ~AuditManager();

    // Configuration and lifecycle
    bool start(const AuditConfig& config);
    void stop();
    bool isRunning() const { return running_; }

    // Configuration management
    void setConfig(const AuditConfig& config);
    AuditConfig getConfig() const;
    std::string getConfigJSON() const;
    bool loadConfigFromJSON(const std::string& json);

    // Existing sandbox audit methods
    void logDenied(const char* actor, const char* what, const char* reason);
    void logTimeout(const char* actor, const char* op, uint32_t timeout_ms);
    void logRateLimit(const char* actor, const char* op);

    // System audit methods
    void logSystemReboot(const char* reason, const char* user = nullptr, const char* client_ip = nullptr);
    void logSystemStartup(const char* version, const char* build_date = nullptr);
    void logServiceEvent(const char* service, const char* action, const char* details = nullptr);
    void logPluginEvent(const char* plugin, const char* action, const char* details = nullptr);
    void logSecurityEvent(const char* event_type, const char* user = nullptr, const char* client_ip = nullptr, const char* details = nullptr);
    void logConfigChangeAudit(const char* config_type, const char* user = nullptr, const char* client_ip = nullptr, const char* details = nullptr);

    // Status and monitoring
    AuditSnapshot getSnapshot() const;
    std::string getStatusJSON() const;

    // Singleton access for backward compatibility
    static AuditManager& getInstance();
    void init(ReportingEngine* rep);

private:
    mutable std::mutex config_mutex_;
    AuditConfig config_;
    std::atomic<bool> running_{false};
    ReportingEngine* reporting_engine_ = nullptr;
    AuditCounters counters_;

    // Rate limiting
    uint64_t last_rate_check_ms_ = 0;
    uint32_t events_this_second_ = 0;

    // Helper methods
    bool shouldLogEvent() const;
    bool checkRateLimit();
    uint64_t getCurrentTimeMs() const;
};