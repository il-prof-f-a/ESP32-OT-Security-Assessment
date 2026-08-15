#include "audit_manager.h"
#include "../core/reporting_engine.h"
#include "../core/event_formatter.h"
#include "../core/logging_system.h"
#include "../core/configuration_manager.h"
#include <cJSON.h>
extern "C" {
    #include "esp_timer.h"
    #include "esp_heap_caps.h"
}

static const char* TAG = "AuditManager";

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
    if (reporting_engine_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "sandbox_denied";
        ev.name = "Sandbox deny";
        ev.severity = "Medium";
        ev.ext = {
            {"actor", actor ? actor : ""},
            {"what", what ? what : ""},
            {"reason", reason ? reason : ""}
        };
        reporting_engine_->submit(ev);
    }
}

void AuditManager::logTimeout(const char* actor, const char* op, uint32_t timeout_ms) {
    if (!shouldLogEvent() || !config_.log_timeouts || !checkRateLimit()) return;

    counters_.timeouts++;
    if (reporting_engine_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "sandbox_timeout";
        ev.name = "Sandbox timeout";
        ev.severity = "Medium";

        char timeout_buf[16];
        snprintf(timeout_buf, sizeof(timeout_buf), "%lu", (unsigned long)timeout_ms);
        ev.ext = {
            {"actor", actor ? actor : ""},
            {"op", op ? op : ""},
            {"timeout_ms", timeout_buf}
        };
        reporting_engine_->submit(ev);
    }
}

void AuditManager::logRateLimit(const char* actor, const char* op) {
    if (!shouldLogEvent() || !config_.log_ratelimits || !checkRateLimit()) return;

    counters_.ratelimits++;
    if (reporting_engine_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "sandbox_ratelimit";
        ev.name = "Sandbox rate-limit";
        ev.severity = "Low";
        ev.ext = {
            {"actor", actor ? actor : ""},
            {"op", op ? op : ""}
        };
        reporting_engine_->submit(ev);
    }
}

void AuditManager::logSystemReboot(const char* reason, const char* user, const char* client_ip) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    if (reporting_engine_) {
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
        reporting_engine_->submit(ev);
    }
}

void AuditManager::logSystemStartup(const char* version, const char* build_date) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    if (reporting_engine_) {
        EventRecord ev;
        ev.channel = "audit";
        ev.type = "system_startup";
        ev.name = "System Startup";
        ev.severity = "Medium";
        ev.ext = {
            {"version", version ? version : "unknown"},
            {"build_date", build_date ? build_date : ""}
        };

        char heap_buf[16], psram_buf[16];
        size_t heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        snprintf(heap_buf, sizeof(heap_buf), "%zu", heap_free);
        snprintf(psram_buf, sizeof(psram_buf), "%zu", psram_free);

        ev.ext["heap_free"] = heap_buf;
        ev.ext["psram_free"] = psram_buf;

        reporting_engine_->submit(ev);
    }
}

void AuditManager::logServiceEvent(const char* service, const char* action, const char* details) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    if (reporting_engine_) {
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
        reporting_engine_->submit(ev);
    }
}

void AuditManager::logPluginEvent(const char* plugin, const char* action, const char* details) {
    if (!shouldLogEvent() || !config_.log_system_events) return;

    counters_.system_events++;
    if (reporting_engine_) {
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
        reporting_engine_->submit(ev);
    }
}

void AuditManager::logSecurityEvent(const char* event_type, const char* user, const char* client_ip, const char* details) {
    if (!shouldLogEvent() || !config_.log_security_events) return;

    counters_.security_events++;
    if (reporting_engine_) {
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
        reporting_engine_->submit(ev);

        uint64_t ts_ms = getCurrentTimeMs();
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "event_type=%s user=%s ip=%s details=%s",
                 event_type ? event_type : "unknown",
                 user ? user : "anonymous",
                 client_ip ? client_ip : "",
                 details ? details : "");
        reporting_engine_->reportLogMessage(
            PSRAMUtils::createPSRAMString("SECURITY"),
            PSRAMUtils::createPSRAMString("WARNING"),
            PSRAMUtils::createPSRAMString(msg),
            ts_ms);
    }
}

void AuditManager::logConfigChangeAudit(const char* config_type, const char* user, const char* client_ip, const char* details) {
    if (!shouldLogEvent() || !config_.log_config_changes) return;

    counters_.config_changes++;
    if (reporting_engine_) {
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
        reporting_engine_->submit(ev);
    }
}
