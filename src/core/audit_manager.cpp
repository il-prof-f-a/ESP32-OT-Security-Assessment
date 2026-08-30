#include "audit_manager.h"
#include "../core/reporting_engine.h"
#include "../core/event_formatter.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include <cJSON.h>
#include <cstdarg>
extern "C" {
    #include "esp_timer.h"
    #include "esp_heap_caps.h"
}

static const char* TAG = "AuditManager";

namespace {
// Audit is intentionally a classic line-oriented log.  Keeping this path on
// reportLogMessage gives every line the same timestamp policy and routes it to
// audit_events.log without also creating a structured EventRecord.
void emitAuditLine(ReportingEngine* reporting, const char* level,
                   const char* event, const char* format, ...) {
    if (!reporting || !event) return;
    char details[384] = {0};
    va_list args;
    va_start(args, format);
    vsnprintf(details, sizeof(details), format ? format : "", args);
    va_end(args);

    char message[512] = {0};
    snprintf(message, sizeof(message), "event=%s %s", event, details);
    reporting->reportLogMessage(
        PSRAMUtils::createPSRAMString("AUDIT"),
        PSRAMUtils::createPSRAMString(level ? level : "INFO"),
        PSRAMUtils::createPSRAMString(message),
        esp_timer_get_time() / 1000ULL);
}
}

AuditManager::AuditManager() {
}

AuditManager::~AuditManager() {
    stop();
}

AuditManager& AuditManager::getInstance() {
    static AuditManager instance;
    return instance;
}

void AuditManager::init(ReportingEngine* rep) {
    reporting_engine_ = rep;
}

bool AuditManager::start(const AuditConfig& config) {
    if (running_) {
        LOG_WARNING(TAG, "Sandbox Reporter already running");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        config_ = config;
    }

    if (!config_.enabled) {
        LOG_INFO(TAG, "Sandbox Reporter disabled in configuration");
        return true;
    }

    running_ = true;
    LOG_INFO(TAG, "Sandbox Reporter started successfully");
    return true;
}

void AuditManager::stop() {
    if (!running_) return;

    LOG_INFO(TAG, "Stopping Sandbox Reporter...");
    running_ = false;
    LOG_INFO(TAG, "Sandbox Reporter stopped");
}

void AuditManager::setConfig(const AuditConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
}

AuditConfig AuditManager::getConfig() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

std::string AuditManager::getConfigJSON() const {
    std::lock_guard<std::mutex> lock(config_mutex_);

    cJSON* root = cJSON_CreateObject();
    if (!root) return "{}";

    cJSON_AddBoolToObject(root, "enabled", config_.enabled);
    cJSON_AddBoolToObject(root, "log_denied", config_.log_denied);
    cJSON_AddBoolToObject(root, "log_timeouts", config_.log_timeouts);
    cJSON_AddBoolToObject(root, "log_ratelimits", config_.log_ratelimits);
    cJSON_AddBoolToObject(root, "log_system_events", config_.log_system_events);
    cJSON_AddBoolToObject(root, "log_security_events", config_.log_security_events);
    cJSON_AddBoolToObject(root, "log_config_changes", config_.log_config_changes);
    cJSON_AddNumberToObject(root, "max_events_per_second", config_.max_events_per_second);

    char* json_string = cJSON_PrintUnformatted(root);
    std::string result = json_string ? json_string : "{}";
    if (json_string) free(json_string);
    cJSON_Delete(root);

    return result;
}

bool AuditManager::loadConfigFromJSON(const std::string& json) {
    cJSON* root = cJSON_Parse(json.c_str());
    if (!root) return false;

    std::lock_guard<std::mutex> lock(config_mutex_);

    cJSON* item;
    if ((item = cJSON_GetObjectItem(root, "enabled")) && cJSON_IsBool(item)) {
        config_.enabled = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_denied")) && cJSON_IsBool(item)) {
        config_.log_denied = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_timeouts")) && cJSON_IsBool(item)) {
        config_.log_timeouts = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_ratelimits")) && cJSON_IsBool(item)) {
        config_.log_ratelimits = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_system_events")) && cJSON_IsBool(item)) {
        config_.log_system_events = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_security_events")) && cJSON_IsBool(item)) {
        config_.log_security_events = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "log_config_changes")) && cJSON_IsBool(item)) {
        config_.log_config_changes = cJSON_IsTrue(item);
    }
    if ((item = cJSON_GetObjectItem(root, "max_events_per_second")) && cJSON_IsNumber(item)) {
        config_.max_events_per_second = static_cast<uint32_t>(cJSON_GetNumberValue(item));
    }

    cJSON_Delete(root);
    return true;
}

bool AuditManager::shouldLogEvent() const {
    return running_ && config_.enabled;
}

bool AuditManager::checkRateLimit() {
    uint64_t now_ms = getCurrentTimeMs();

    if (now_ms - last_rate_check_ms_ >= 1000) {
        last_rate_check_ms_ = now_ms;
        events_this_second_ = 0;
    }

    if (events_this_second_ >= config_.max_events_per_second) {
        return false;
    }

    events_this_second_++;
    return true;
}

uint64_t AuditManager::getCurrentTimeMs() const {
    return esp_timer_get_time() / 1000;
}

AuditSnapshot AuditManager::getSnapshot() const {
    AuditSnapshot snap;
    snap.denied = counters_.denied.load();
    snap.timeouts = counters_.timeouts.load();
    snap.ratelimits = counters_.ratelimits.load();
    snap.system_events = counters_.system_events.load();
    snap.security_events = counters_.security_events.load();
    snap.config_changes = counters_.config_changes.load();
    return snap;
}

std::string AuditManager::getStatusJSON() const {
    cJSON* root = cJSON_CreateObject();
    if (!root) return "{}";

    cJSON_AddBoolToObject(root, "running", running_);
    cJSON_AddBoolToObject(root, "enabled", config_.enabled);

    // Add counters
    cJSON* counters = cJSON_CreateObject();
    cJSON_AddNumberToObject(counters, "denied", counters_.denied.load());
    cJSON_AddNumberToObject(counters, "timeouts", counters_.timeouts.load());
    cJSON_AddNumberToObject(counters, "ratelimits", counters_.ratelimits.load());
    cJSON_AddNumberToObject(counters, "system_events", counters_.system_events.load());
    cJSON_AddNumberToObject(counters, "security_events", counters_.security_events.load());
    cJSON_AddNumberToObject(counters, "config_changes", counters_.config_changes.load());
    cJSON_AddItemToObject(root, "counters", counters);

    char* json_string = cJSON_PrintUnformatted(root);
    std::string result = json_string ? json_string : "{}";
    if (json_string) free(json_string);
    cJSON_Delete(root);

    return result;
}

void AuditManager::logDenied(const char* actor, const char* what, const char* reason) {
    if (!shouldLogEvent() || !config_.log_denied || !checkRateLimit()) return;

    counters_.denied++;
    emitAuditLine(reporting_engine_, "WARNING", "sandbox_denied",
                  "actor=%s what=%s reason=%s", actor ? actor : "",
                  what ? what : "", reason ? reason : "");
}

void AuditManager::logTimeout(const char* actor, const char* op, uint32_t timeout_ms) {
    if (!shouldLogEvent() || !config_.log_timeouts || !checkRateLimit()) return;

    counters_.timeouts++;
    emitAuditLine(reporting_engine_, "WARNING", "sandbox_timeout",
                  "actor=%s op=%s timeout_ms=%lu", actor ? actor : "",
                  op ? op : "", (unsigned long)timeout_ms);
}

void AuditManager::logRateLimit(const char* actor, const char* op) {
    if (!shouldLogEvent() || !config_.log_ratelimits || !checkRateLimit()) return;

    counters_.ratelimits++;
    emitAuditLine(reporting_engine_, "INFO", "sandbox_ratelimit",
                  "actor=%s op=%s", actor ? actor : "", op ? op : "");
}

void AuditManager::logSystemReboot(const char* reason, const char* user, const char* client_ip) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    emitAuditLine(reporting_engine_, "ERROR", "system_reboot",
                  "reason=%s user=%s client_ip=%s", reason ? reason : "unknown",
                  user ? user : "system", client_ip ? client_ip : "");
}

void AuditManager::logSystemStartup(const char* version, const char* build_date) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    emitAuditLine(reporting_engine_, "INFO", "system_startup",
                  "version=%s build_date=%s heap_free=%zu psram_free=%zu",
                  version ? version : "unknown", build_date ? build_date : "",
                  heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                  heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}

void AuditManager::logServiceEvent(const char* service, const char* action, const char* details) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    emitAuditLine(reporting_engine_, "INFO", "service_event",
                  "service=%s action=%s details=%s", service ? service : "unknown",
                  action ? action : "unknown", details ? details : "");
}

void AuditManager::logPluginEvent(const char* plugin, const char* action, const char* details) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    emitAuditLine(reporting_engine_, "INFO", "plugin_event",
                  "plugin=%s action=%s details=%s", plugin ? plugin : "unknown",
                  action ? action : "unknown", details ? details : "");
}

void AuditManager::logSecurityEvent(const char* event_type, const char* user, const char* client_ip, const char* details) {
    if (!shouldLogEvent() || !config_.log_security_events) return;

    counters_.security_events++;
    emitAuditLine(reporting_engine_, "ERROR", "security_event",
                  "event_type=%s user=%s ip=%s details=%s",
                  event_type ? event_type : "unknown",
                  user ? user : "anonymous", client_ip ? client_ip : "",
                  details ? details : "");
}

void AuditManager::logConfigChangeAudit(const char* config_type, const char* user, const char* client_ip, const char* details) {
    if (!shouldLogEvent() || !config_.log_config_changes) return;

    counters_.config_changes++;
    emitAuditLine(reporting_engine_, "INFO", "config_change",
                  "config_type=%s user=%s client_ip=%s details=%s",
                  config_type ? config_type : "unknown",
                  user ? user : "anonymous", client_ip ? client_ip : "",
                  details ? details : "");
}
