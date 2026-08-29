#pragma once

#include <cctype>
#include "../security/security_manager.h"
#include "../security/api_key_rotation_manager.h"
#include "../core/configuration_manager.h"
#include "../core/async_storage_engine.h"
#include "../core/psram_allocator.h"
#include "rate_limiter.h"

extern "C" {
#include "cJSON.h"
}

// Forward declaration for global API key rotation manager
extern ApiKeyRotationManager* g_api_key_rotation_manager;

namespace SecurityAPI {

// GET /api/security/config
// Returns current security settings
inline cJSON* handleSecurityConfigGet(SecurityManager* sec_mgr, const SecurityConfig* cfg) {
    cJSON* response = cJSON_CreateObject();

    if (!sec_mgr) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Security manager not available");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);

    cJSON* config = cJSON_CreateObject();
    // Keep "fuzzing_allowed" as the persisted software toggle (backward compatible with the UI).
    cJSON_AddBoolToObject(config, "fuzzing_allowed", sec_mgr->isFuzzingAllowedConfig());
    // Expose effective status (includes optional physical GPIO gate).
    cJSON_AddBoolToObject(config, "fuzzing_allowed_effective", sec_mgr->isFuzzingAllowed());
    cJSON_AddStringToObject(config, "fuzzing_block_reason", sec_mgr->getFuzzingBlockReason());

    cJSON_AddBoolToObject(config, "fuzzing_gpio_gate_enabled", sec_mgr->isFuzzingGpioGateEnabled());
    cJSON_AddBoolToObject(config, "fuzzing_gpio_gate_required", sec_mgr->isFuzzingGpioGateRequired());
    cJSON_AddNumberToObject(config, "fuzzing_gpio_num", (double)sec_mgr->getFuzzingGpioNum());
    cJSON_AddBoolToObject(config, "fuzzing_gpio_active_high", sec_mgr->isFuzzingGpioActiveHigh());
    cJSON_AddNumberToObject(config, "fuzzing_gpio_pull_mode", (double)sec_mgr->getFuzzingGpioPullMode());
    cJSON_AddBoolToObject(config, "fuzzing_gpio_gate_state", sec_mgr->readFuzzingGpioGateState());
    cJSON* offensive = cJSON_CreateObject();
    if (offensive) {
        cJSON_AddBoolToObject(offensive, "software_enabled", sec_mgr->isFuzzingAllowedConfig());
        cJSON_AddBoolToObject(offensive, "effective", sec_mgr->isFuzzingAllowed());
        cJSON_AddStringToObject(offensive, "reason", sec_mgr->getFuzzingBlockReason());
        cJSON_AddStringToObject(offensive, "source", sec_mgr->getOffensiveTestingPolicySource());
        cJSON_AddBoolToObject(offensive, "gpio_asserted", sec_mgr->readFuzzingGpioGateState());
        cJSON_AddNumberToObject(offensive, "gpio", sec_mgr->getFuzzingGpioNum());
        cJSON_AddBoolToObject(offensive, "gpio_enabled", sec_mgr->isFuzzingGpioGateEnabled());
        cJSON_AddBoolToObject(offensive, "gpio_required", sec_mgr->isFuzzingGpioGateRequired());
        cJSON_AddItemToObject(config, "offensive_testing", offensive);
    }
    cJSON_AddBoolToObject(config, "secure_boot_enabled", sec_mgr->isSecureBootEnabled());
    cJSON_AddBoolToObject(config, "flash_encryption_enabled", sec_mgr->isFlashEncryptionEnabled());
    cJSON_AddBoolToObject(config, "temporary_admin_active", sec_mgr->isTemporaryAdminCredentialActive());

    bool secure_boot_required = cfg ? cfg->secure_boot : false;
    bool flash_required = cfg ? cfg->flash_encryption : false;
    bool certificate_required = cfg ? cfg->certificate_validation : true;
    bool opcua_enforced = cfg ? cfg->opcua_enforce_security : false;

    cJSON_AddBoolToObject(config, "secure_boot_required", secure_boot_required);
    cJSON_AddBoolToObject(config, "flash_encryption_required", flash_required);
    cJSON_AddBoolToObject(config, "certificate_validation_required", certificate_required);
    cJSON_AddBoolToObject(config, "opcua_enforce_security", opcua_enforced);

    if (cfg) {
        const SecurityAlertPolicy& policy = cfg->alert_policy;
        cJSON* policy_obj = cJSON_CreateObject();
        if (policy_obj) {
            cJSON* email_obj = cJSON_CreateObject();
            if (email_obj) {
                cJSON_AddBoolToObject(email_obj, "enabled", policy.email.enabled);
                cJSON_AddNumberToObject(email_obj, "throttle_minutes", static_cast<double>(policy.email.throttle_minutes));
                if (!policy.email.subject.empty()) {
                    cJSON_AddStringToObject(email_obj, "subject", policy.email.subject.c_str());
                }
                if (!policy.email.recipients.empty()) {
                    cJSON* recipients = cJSON_CreateArray();
                    if (recipients) {
                        for (const auto& addr : policy.email.recipients) {
                            cJSON_AddItemToArray(recipients, cJSON_CreateString(addr.c_str()));
                        }
                        cJSON_AddItemToObject(email_obj, "recipients", recipients);
                    }
                }
                cJSON_AddItemToObject(policy_obj, "email", email_obj);
            }

            cJSON* webhook_obj = cJSON_CreateObject();
            if (webhook_obj) {
                cJSON_AddBoolToObject(webhook_obj, "enabled", policy.webhook.enabled);
                if (!policy.webhook.url.empty()) {
                    cJSON_AddStringToObject(webhook_obj, "url", policy.webhook.url.c_str());
                }
                cJSON_AddItemToObject(policy_obj, "webhook", webhook_obj);
            }

            cJSON* gpio_obj = cJSON_CreateObject();
            if (gpio_obj) {
                cJSON_AddBoolToObject(gpio_obj, "enabled", policy.gpio.enabled);
                cJSON_AddNumberToObject(gpio_obj, "critical_pin", policy.gpio.critical_pin);
                cJSON_AddNumberToObject(gpio_obj, "warning_pin", policy.gpio.warning_pin);
                cJSON_AddNumberToObject(gpio_obj, "buzzer_pin", policy.gpio.buzzer_pin);
                cJSON_AddItemToObject(policy_obj, "gpio", gpio_obj);
            }

            cJSON_AddItemToObject(config, "alert_policy", policy_obj);
        }
    }

    cJSON_AddItemToObject(response, "config", config);

    ApiKeyMetrics metrics{};
    sec_mgr->getApiKeyMetrics(metrics);
    cJSON* metrics_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(metrics_obj, "total", metrics.total);
    cJSON_AddNumberToObject(metrics_obj, "enabled", metrics.enabled);
    cJSON_AddNumberToObject(metrics_obj, "rotation_required", metrics.rotation_required);
    cJSON_AddNumberToObject(metrics_obj, "disabled_pending_rotation", metrics.disabled_pending_rotation);
    cJSON_AddNumberToObject(metrics_obj, "newest_created_ms", (double)metrics.newest_created_ms);
    cJSON_AddNumberToObject(metrics_obj, "oldest_created_ms", (double)metrics.oldest_created_ms);
    cJSON_AddItemToObject(response, "api_key_metrics", metrics_obj);

    PSRAMAllocator<SecurityEventLog> alloc;
    psram_vector<SecurityEventLog> events(alloc);
    sec_mgr->getSecurityEvents(events);

    cJSON* alerts = cJSON_CreateArray();
    if (alerts) {
        for (const auto& ev : events) {
            cJSON* item = cJSON_CreateObject();
            if (!item) {
                continue;
            }
            if (!ev.id.empty()) {
                cJSON_AddStringToObject(item, "id", ev.id.c_str());
            }
            cJSON_AddStringToObject(item, "type", ev.type.c_str());
            cJSON_AddStringToObject(item, "severity", ev.severity.c_str());
            cJSON_AddStringToObject(item, "summary", ev.summary.c_str());
            if (!ev.detail_json.empty()) {
                cJSON_AddStringToObject(item, "detail", ev.detail_json.c_str());
            }
            cJSON_AddNumberToObject(item, "timestamp_ms", (double)ev.timestamp_ms);
            cJSON_AddBoolToObject(item, "acknowledged", ev.acknowledged);
            if (ev.ack_timestamp_ms) {
                cJSON_AddNumberToObject(item, "ack_timestamp_ms", (double)ev.ack_timestamp_ms);
            }
            if (!ev.acked_by.empty()) {
                cJSON_AddStringToObject(item, "acked_by", ev.acked_by.c_str());
            }
            cJSON_AddItemToArray(alerts, item);
        }
    }
    if (!alerts) {
        alerts = cJSON_CreateArray();
    }
    cJSON_AddItemToObject(response, "alerts", alerts);

    return response;
}

inline cJSON* handleSecurityEventAck(SecurityManager* sec_mgr,
                                    const char* json_data,
                                    size_t data_len) {
    cJSON* resp = cJSON_CreateObject();
    if (!resp) {
        return nullptr;
    }

    if (!sec_mgr) {
        cJSON_AddBoolToObject(resp, "success", false);
        cJSON_AddStringToObject(resp, "message", "Security manager not available");
        return resp;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(resp, "success", false);
        cJSON_AddStringToObject(resp, "message", "No data provided");
        return resp;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(resp, "success", false);
        cJSON_AddStringToObject(resp, "message", "Invalid JSON format");
        return resp;
    }

    cJSON* id_item = cJSON_GetObjectItem(request, "event_id");
    if (!id_item || !cJSON_IsString(id_item) || !id_item->valuestring || id_item->valuestring[0] == '\0') {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(resp, "success", false);
        cJSON_AddStringToObject(resp, "message", "Missing event_id");
        return resp;
    }

    cJSON* ack_item = cJSON_GetObjectItem(request, "ack");
    bool acknowledged = true;
    if (ack_item && cJSON_IsBool(ack_item)) {
        acknowledged = cJSON_IsTrue(ack_item);
    }

    cJSON* actor_item = cJSON_GetObjectItem(request, "actor");
    psram_string actor_ps = actor_item && cJSON_IsString(actor_item) && actor_item->valuestring
        ? PSRAMUtils::createPSRAMString(actor_item->valuestring)
        : PSRAMUtils::createPSRAMString("");

    psram_string event_id_ps = PSRAMUtils::createPSRAMString(id_item->valuestring);
    bool ok = sec_mgr->acknowledgeSecurityEvent(event_id_ps, actor_ps, acknowledged);
    cJSON_Delete(request);

    cJSON_AddBoolToObject(resp, "success", ok);
    cJSON_AddStringToObject(resp, "event_id", id_item->valuestring);
    cJSON_AddBoolToObject(resp, "acknowledged", acknowledged);
    if (!ok) {
        cJSON_AddStringToObject(resp, "message", "Event not found");
    }
    return resp;
}

// POST /api/security/config
// Update security settings
// Expected JSON: {"fuzzing_allowed": true/false, "alert_policy": {...}}
inline cJSON* handleSecurityConfigPost(SecurityManager* sec_mgr, const char* json_data, size_t data_len) {
    auto make_error = [](const char* msg) -> cJSON* {
        cJSON* obj = cJSON_CreateObject();
        if (!obj) {
            return nullptr;
        }
        cJSON_AddBoolToObject(obj, "success", false);
        if (msg) {
            cJSON_AddStringToObject(obj, "message", msg);
        }
        return obj;
    };

    if (!sec_mgr) {
        return make_error("Security manager not available");
    }

    if (!json_data || data_len == 0) {
        return make_error("No data provided");
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        return make_error("Invalid JSON format");
    }

    auto cleanup_and_error = [&](const char* msg) -> cJSON* {
        cJSON_Delete(request);
        return make_error(msg);
    };

    // Update fuzzing_allowed if present. Enabling offensive actions requires
    // administrator re-authentication; disabling remains an emergency action.
    cJSON* fuzzing_allowed = cJSON_GetObjectItem(request, "fuzzing_allowed");
    if (fuzzing_allowed && cJSON_IsBool(fuzzing_allowed)) {
        bool allow = cJSON_IsTrue(fuzzing_allowed);
        if (allow) {
            cJSON* password = cJSON_GetObjectItem(request, "admin_password");
            if (!password || !cJSON_IsString(password) || !password->valuestring ||
                !sec_mgr->verifyAdminPassword(password->valuestring)) {
                return cleanup_and_error("Administrator password required");
            }
        }
        sec_mgr->setFuzzingAllowed(allow);
    }

    // Optional physical GPIO gate configuration for unsafe fuzzing
    bool gate_cfg_updated = false;
    bool gate_enabled = sec_mgr->isFuzzingGpioGateEnabled();
    bool gate_required = sec_mgr->isFuzzingGpioGateRequired();
    int gate_gpio_num = sec_mgr->getFuzzingGpioNum();
    bool gate_active_high = sec_mgr->isFuzzingGpioActiveHigh();
    int gate_pull_mode = sec_mgr->getFuzzingGpioPullMode(); // 0 none, 1 pullup, 2 pulldown

    if (auto v = cJSON_GetObjectItem(request, "fuzzing_gpio_gate_enabled"); v && cJSON_IsBool(v)) {
        gate_enabled = cJSON_IsTrue(v);
        gate_cfg_updated = true;
    }
    if (auto v = cJSON_GetObjectItem(request, "fuzzing_gpio_gate_required"); v && cJSON_IsBool(v)) {
        gate_required = cJSON_IsTrue(v);
        gate_cfg_updated = true;
    }
    if (auto v = cJSON_GetObjectItem(request, "fuzzing_gpio_num"); v && cJSON_IsNumber(v)) {
        gate_gpio_num = (int)v->valuedouble;
        gate_cfg_updated = true;
    }
    if (auto v = cJSON_GetObjectItem(request, "fuzzing_gpio_active_high"); v && cJSON_IsBool(v)) {
        gate_active_high = cJSON_IsTrue(v);
        gate_cfg_updated = true;
    }
    if (auto v = cJSON_GetObjectItem(request, "fuzzing_gpio_pull_mode"); v && cJSON_IsNumber(v)) {
        gate_pull_mode = (int)v->valuedouble;
        gate_cfg_updated = true;
    }

    if (gate_cfg_updated) {
        cJSON* password = cJSON_GetObjectItem(request, "admin_password");
        if (!password || !cJSON_IsString(password) || !password->valuestring ||
            !sec_mgr->verifyAdminPassword(password->valuestring)) {
            return cleanup_and_error("Administrator password required");
        }
        if (!sec_mgr->configureFuzzingGpioGate(gate_enabled, gate_gpio_num,
                                               gate_active_high, gate_pull_mode,
                                               gate_required) ||
            !sec_mgr->persistOffensiveTestingPolicy()) {
            return cleanup_and_error("Invalid or failed offensive-testing policy");
        }
    }

    if (fuzzing_allowed && cJSON_IsBool(fuzzing_allowed) &&
        !sec_mgr->persistOffensiveTestingPolicy()) {
        return cleanup_and_error("Failed to save offensive-testing policy");
    }

    // Update alert policy if provided
    cJSON* alert_policy_obj = cJSON_GetObjectItem(request, "alert_policy");
    if (alert_policy_obj && cJSON_IsObject(alert_policy_obj)) {
        SecurityAlertPolicy policy_snapshot;
        sec_mgr->getAlertPolicy(policy_snapshot);

        cJSON* email_obj = cJSON_GetObjectItem(alert_policy_obj, "email");
        if (email_obj && cJSON_IsObject(email_obj)) {
            cJSON* en = cJSON_GetObjectItem(email_obj, "enabled");
            if (en && cJSON_IsBool(en)) {
                policy_snapshot.email.enabled = cJSON_IsTrue(en);
            }
            cJSON* subject = cJSON_GetObjectItem(email_obj, "subject");
            if (subject && cJSON_IsString(subject) && subject->valuestring) {
                bool has_visible = false;
                for (const char* ptr = subject->valuestring; *ptr; ++ptr) {
                    if (!std::isspace(static_cast<unsigned char>(*ptr))) {
                        has_visible = true;
                        break;
                    }
                }
                if (has_visible) {
                    policy_snapshot.email.subject = PSRAMUtils::createPSRAMString(subject->valuestring);
                } else {
                    policy_snapshot.email.subject = PSRAMUtils::createPSRAMString("");
                }
            }
            cJSON* throttle = cJSON_GetObjectItem(email_obj, "throttle_minutes");
            if (throttle && cJSON_IsNumber(throttle)) {
                double value = throttle->valuedouble;
                if (value < 0.0) value = 0.0;
                if (value > 1440.0) value = 1440.0;
                policy_snapshot.email.throttle_minutes = static_cast<uint32_t>(value);
            }
            cJSON* recipients = cJSON_GetObjectItem(email_obj, "recipients");
            if (recipients && cJSON_IsArray(recipients)) {
                PSRAMAllocator<psram_string> alloc;
                policy_snapshot.email.recipients = psram_string_vector(alloc);
                cJSON* entry = nullptr;
                cJSON_ArrayForEach(entry, recipients) {
                    if (entry && cJSON_IsString(entry) && entry->valuestring) {
                        policy_snapshot.email.recipients.push_back(
                            PSRAMUtils::createPSRAMString(entry->valuestring));
                    }
                }
            }
        }

        cJSON* webhook_obj = cJSON_GetObjectItem(alert_policy_obj, "webhook");
        if (webhook_obj && cJSON_IsObject(webhook_obj)) {
            cJSON* en = cJSON_GetObjectItem(webhook_obj, "enabled");
            if (en && cJSON_IsBool(en)) {
                policy_snapshot.webhook.enabled = cJSON_IsTrue(en);
            }
            cJSON* url = cJSON_GetObjectItem(webhook_obj, "url");
            if (url && cJSON_IsString(url) && url->valuestring) {
                policy_snapshot.webhook.url = PSRAMUtils::createPSRAMString(url->valuestring);
            } else if (url && cJSON_IsNull(url)) {
                policy_snapshot.webhook.url = PSRAMUtils::createPSRAMString("");
            }
            cJSON* token = cJSON_GetObjectItem(webhook_obj, "token");
            if (token && cJSON_IsString(token) && token->valuestring) {
                policy_snapshot.webhook.token = PSRAMUtils::createPSRAMString(token->valuestring);
            } else if (token && cJSON_IsNull(token)) {
                policy_snapshot.webhook.token = PSRAMUtils::createPSRAMString("");
            }
        }

        cJSON* gpio_obj = cJSON_GetObjectItem(alert_policy_obj, "gpio");
        if (gpio_obj && cJSON_IsObject(gpio_obj)) {
            cJSON* en = cJSON_GetObjectItem(gpio_obj, "enabled");
            if (en && cJSON_IsBool(en)) {
                policy_snapshot.gpio.enabled = cJSON_IsTrue(en);
            }
            auto clamp_pin = [](double value) -> uint8_t {
                if (value < 0.0) value = 0.0;
                if (value > 255.0) value = 255.0;
                return static_cast<uint8_t>(value);
            };
            cJSON* critical = cJSON_GetObjectItem(gpio_obj, "critical_pin");
            if (critical && cJSON_IsNumber(critical)) {
                policy_snapshot.gpio.critical_pin = clamp_pin(critical->valuedouble);
            }
            cJSON* warning = cJSON_GetObjectItem(gpio_obj, "warning_pin");
            if (warning && cJSON_IsNumber(warning)) {
                policy_snapshot.gpio.warning_pin = clamp_pin(warning->valuedouble);
            }
            cJSON* buzzer = cJSON_GetObjectItem(gpio_obj, "buzzer_pin");
            if (!buzzer) {
                buzzer = cJSON_GetObjectItem(gpio_obj, "buzzer");
            }
            if (buzzer && cJSON_IsNumber(buzzer)) {
                policy_snapshot.gpio.buzzer_pin = clamp_pin(buzzer->valuedouble);
            }
        }

        sec_mgr->setAlertPolicy(policy_snapshot);
    }

    cJSON_Delete(request);

    SecurityConfig cfg_snapshot;
    sec_mgr->getSecurityConfigSnapshot(cfg_snapshot);
    cJSON* response = handleSecurityConfigGet(sec_mgr, &cfg_snapshot);
    if (!response) {
        return make_error("Failed to build security configuration response");
    }

    cJSON_AddStringToObject(response, "message", "Security configuration updated");
    return response;
}

// Load fuzzing_allowed from NVS on boot
inline bool loadFuzzingAllowedFromNVS(SecurityManager* sec_mgr) {
    if (!sec_mgr) return false;
    return sec_mgr->loadOffensiveTestingPolicyFromStorage();
}

// GET /api/security/ratelimit
// Returns rate limiter configuration and statistics
inline cJSON* handleRateLimitGet() {
    cJSON* response = cJSON_CreateObject();

    if (!g_rate_limiter) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rate limiter not available");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);

    // Get configuration
    RateLimitConfig config = g_rate_limiter->getConfig();
    cJSON* config_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(config_obj, "max_requests_per_minute", config.max_requests_per_minute);
    cJSON_AddNumberToObject(config_obj, "auth_failure_threshold", config.auth_failure_threshold);
    cJSON_AddNumberToObject(config_obj, "block_duration_ms", config.block_duration_ms);
    cJSON_AddNumberToObject(config_obj, "cooldown_period_ms", config.cooldown_period_ms);
    cJSON_AddBoolToObject(config_obj, "enabled", config.enabled);
    cJSON_AddItemToObject(response, "config", config_obj);

    // Get statistics
    RateLimiter::Stats stats = g_rate_limiter->getStats();
    cJSON* stats_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(stats_obj, "total_clients", stats.total_clients);
    cJSON_AddNumberToObject(stats_obj, "blocked_clients", stats.blocked_clients);
    cJSON_AddNumberToObject(stats_obj, "total_blocks_issued", stats.total_blocks_issued);
    cJSON_AddNumberToObject(stats_obj, "total_requests_blocked", stats.total_requests_blocked);
    cJSON_AddItemToObject(response, "stats", stats_obj);

    return response;
}

// POST /api/security/ratelimit
// Update rate limiter configuration
// Expected JSON: {"max_requests_per_minute": 60, "auth_failure_threshold": 5, "enabled": true, ...}
inline cJSON* handleRateLimitPost(const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();

    if (!g_rate_limiter) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rate limiter not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    // Get current config
    RateLimitConfig config = g_rate_limiter->getConfig();

    // Update config from JSON
    cJSON* max_req = cJSON_GetObjectItem(request, "max_requests_per_minute");
    if (max_req && cJSON_IsNumber(max_req)) {
        config.max_requests_per_minute = (uint32_t)max_req->valuedouble;
    }

    cJSON* auth_threshold = cJSON_GetObjectItem(request, "auth_failure_threshold");
    if (auth_threshold && cJSON_IsNumber(auth_threshold)) {
        config.auth_failure_threshold = (uint32_t)auth_threshold->valuedouble;
    }

    cJSON* block_duration = cJSON_GetObjectItem(request, "block_duration_ms");
    if (block_duration && cJSON_IsNumber(block_duration)) {
        config.block_duration_ms = (uint32_t)block_duration->valuedouble;
    }

    cJSON* cooldown = cJSON_GetObjectItem(request, "cooldown_period_ms");
    if (cooldown && cJSON_IsNumber(cooldown)) {
        config.cooldown_period_ms = (uint32_t)cooldown->valuedouble;
    }

    cJSON* enabled = cJSON_GetObjectItem(request, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        config.enabled = cJSON_IsTrue(enabled);
    }

    cJSON_Delete(request);

    // Apply new configuration
    g_rate_limiter->updateConfig(config);

    // Save to NVS for persistence
    AsyncStorage::Global::nvsSet("security", "rl_max_req", config.max_requests_per_minute);
    AsyncStorage::Global::nvsSet("security", "rl_auth_threshold", config.auth_failure_threshold);
    AsyncStorage::Global::nvsSet("security", "rl_block_ms", config.block_duration_ms);
    AsyncStorage::Global::nvsSet("security", "rl_cooldown_ms", config.cooldown_period_ms);
    AsyncStorage::Global::nvsSet("security", "rl_enabled", (uint8_t)(config.enabled ? 1 : 0));

    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Rate limiter configuration updated");

    // Return updated config
    cJSON* config_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(config_obj, "max_requests_per_minute", config.max_requests_per_minute);
    cJSON_AddNumberToObject(config_obj, "auth_failure_threshold", config.auth_failure_threshold);
    cJSON_AddNumberToObject(config_obj, "block_duration_ms", config.block_duration_ms);
    cJSON_AddNumberToObject(config_obj, "cooldown_period_ms", config.cooldown_period_ms);
    cJSON_AddBoolToObject(config_obj, "enabled", config.enabled);
    cJSON_AddItemToObject(response, "config", config_obj);

    return response;
}

// POST /api/security/unblock
// Manually unblock a client
// Expected JSON: {"client_id": "192.168.1.100"}
inline cJSON* handleUnblockClient(const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();

    if (!g_rate_limiter) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rate limiter not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* client_id_obj = cJSON_GetObjectItem(request, "client_id");
    if (!client_id_obj || !cJSON_IsString(client_id_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid client_id");
        return response;
    }

    bool success = g_rate_limiter->unblockClient(client_id_obj->valuestring);
    cJSON_Delete(request);

    if (success) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "message", "Client unblocked successfully");
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Client not found or not blocked");
    }

    return response;
}

// Load rate limiter config from NVS on boot
inline bool loadRateLimitConfigFromNVS() {
    if (!g_rate_limiter) return false;

    RateLimitConfig config;

    // Load from NVS
    uint32_t u32_val;
    uint8_t u8_val;

    if (AsyncStorage::Global::nvsGet("security", "rl_max_req", u32_val) == ESP_OK) {
        config.max_requests_per_minute = u32_val;
    }

    if (AsyncStorage::Global::nvsGet("security", "rl_auth_threshold", u32_val) == ESP_OK) {
        config.auth_failure_threshold = u32_val;
    }

    if (AsyncStorage::Global::nvsGet("security", "rl_block_ms", u32_val) == ESP_OK) {
        config.block_duration_ms = u32_val;
    }

    if (AsyncStorage::Global::nvsGet("security", "rl_cooldown_ms", u32_val) == ESP_OK) {
        config.cooldown_period_ms = u32_val;
    }

    if (AsyncStorage::Global::nvsGet("security", "rl_enabled", u8_val) == ESP_OK) {
        config.enabled = (u8_val != 0);
    }

    g_rate_limiter->updateConfig(config);
    return true;
}

// ============================================================================
// API Key Rotation Endpoints
// ============================================================================

// GET /api/security/rotation/policy
// Returns the current API key rotation policy
inline cJSON* handleRotationPolicyGet() {
    cJSON* response = cJSON_CreateObject();

    if (!g_api_key_rotation_manager) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rotation manager not available");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);

    ApiKeyRotationPolicy policy;
    g_api_key_rotation_manager->getPolicy(policy);

    cJSON* policy_obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(policy_obj, "enabled", policy.enabled);
    cJSON_AddNumberToObject(policy_obj, "rotation_interval_days", policy.rotation_interval_days);
    cJSON_AddNumberToObject(policy_obj, "overlap_period_days", policy.overlap_period_days);
    cJSON_AddBoolToObject(policy_obj, "auto_revoke_old_keys", policy.auto_revoke_old_keys);
    cJSON_AddNumberToObject(policy_obj, "warning_days_before_rotation", policy.warning_days_before_rotation);
    cJSON_AddBoolToObject(policy_obj, "send_notifications", policy.send_notifications);
    cJSON_AddStringToObject(policy_obj, "notification_webhook", policy.notification_webhook.c_str());
    cJSON_AddStringToObject(policy_obj, "notification_email", policy.notification_email.c_str());
    cJSON_AddItemToObject(response, "policy", policy_obj);

    // Add stats
    ApiKeyRotationManager::RotationStats stats;
    g_api_key_rotation_manager->getStats(stats);

    cJSON* stats_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(stats_obj, "total_scheduled", stats.total_scheduled);
    cJSON_AddNumberToObject(stats_obj, "pending_warnings", stats.pending_warnings);
    cJSON_AddNumberToObject(stats_obj, "pending_creations", stats.pending_creations);
    cJSON_AddNumberToObject(stats_obj, "pending_revocations", stats.pending_revocations);
    cJSON_AddNumberToObject(stats_obj, "completed_rotations", stats.completed_rotations);
    cJSON_AddItemToObject(response, "stats", stats_obj);

    return response;
}

// POST /api/security/rotation/policy
// Update API key rotation policy
// Expected JSON: {"enabled": true, "rotation_interval_days": 90, "overlap_period_days": 7, ...}
inline cJSON* handleRotationPolicyPost(const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();

    if (!g_api_key_rotation_manager) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rotation manager not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    ApiKeyRotationPolicy policy;
    g_api_key_rotation_manager->getPolicy(policy); // Start with current policy

    // Update fields from request
    cJSON* enabled = cJSON_GetObjectItem(request, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        policy.enabled = cJSON_IsTrue(enabled);
    }

    cJSON* rotation_interval = cJSON_GetObjectItem(request, "rotation_interval_days");
    if (rotation_interval && cJSON_IsNumber(rotation_interval)) {
        policy.rotation_interval_days = (uint32_t)rotation_interval->valuedouble;
    }

    cJSON* overlap_period = cJSON_GetObjectItem(request, "overlap_period_days");
    if (overlap_period && cJSON_IsNumber(overlap_period)) {
        policy.overlap_period_days = (uint32_t)overlap_period->valuedouble;
    }

    cJSON* auto_revoke = cJSON_GetObjectItem(request, "auto_revoke_old_keys");
    if (auto_revoke && cJSON_IsBool(auto_revoke)) {
        policy.auto_revoke_old_keys = cJSON_IsTrue(auto_revoke);
    }

    cJSON* warning_days = cJSON_GetObjectItem(request, "warning_days_before_rotation");
    if (warning_days && cJSON_IsNumber(warning_days)) {
        policy.warning_days_before_rotation = (uint32_t)warning_days->valuedouble;
    }

    cJSON* send_notifications = cJSON_GetObjectItem(request, "send_notifications");
    if (send_notifications && cJSON_IsBool(send_notifications)) {
        policy.send_notifications = cJSON_IsTrue(send_notifications);
    }

    cJSON* webhook = cJSON_GetObjectItem(request, "notification_webhook");
    if (webhook && cJSON_IsString(webhook)) {
        policy.notification_webhook = PSRAMUtils::createPSRAMString(webhook->valuestring);
    }

    cJSON* email = cJSON_GetObjectItem(request, "notification_email");
    if (email && cJSON_IsString(email)) {
        policy.notification_email = PSRAMUtils::createPSRAMString(email->valuestring);
    }

    cJSON_Delete(request);

    // Apply new policy
    g_api_key_rotation_manager->setPolicy(policy);

    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Rotation policy updated successfully");

    // Return updated policy
    cJSON* policy_obj = cJSON_CreateObject();
    cJSON_AddBoolToObject(policy_obj, "enabled", policy.enabled);
    cJSON_AddNumberToObject(policy_obj, "rotation_interval_days", policy.rotation_interval_days);
    cJSON_AddNumberToObject(policy_obj, "overlap_period_days", policy.overlap_period_days);
    cJSON_AddBoolToObject(policy_obj, "auto_revoke_old_keys", policy.auto_revoke_old_keys);
    cJSON_AddNumberToObject(policy_obj, "warning_days_before_rotation", policy.warning_days_before_rotation);
    cJSON_AddBoolToObject(policy_obj, "send_notifications", policy.send_notifications);
    cJSON_AddStringToObject(policy_obj, "notification_webhook", policy.notification_webhook.c_str());
    cJSON_AddStringToObject(policy_obj, "notification_email", policy.notification_email.c_str());
    cJSON_AddItemToObject(response, "policy", policy_obj);

    return response;
}

// GET /api/security/rotation/scheduled
// List all scheduled rotations
inline cJSON* handleRotationScheduledGet() {
    cJSON* response = cJSON_CreateObject();

    if (!g_api_key_rotation_manager) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rotation manager not available");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);

    psram_vector<ApiKeyRotationEntry> rotations = g_api_key_rotation_manager->listScheduledRotations();

    cJSON* rotations_array = cJSON_CreateArray();
    for (const auto& rot : rotations) {
        cJSON* rot_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(rot_obj, "key_id", rot.key_id.c_str());
        cJSON_AddStringToObject(rot_obj, "key_label", rot.key_label.c_str());
        cJSON_AddStringToObject(rot_obj, "new_key_id", rot.new_key_id.c_str());
        cJSON_AddNumberToObject(rot_obj, "rotation_due_ms", (double)rot.rotation_due_ms);
        cJSON_AddNumberToObject(rot_obj, "warning_sent_ms", (double)rot.warning_sent_ms);
        cJSON_AddNumberToObject(rot_obj, "new_key_created_ms", (double)rot.new_key_created_ms);
        cJSON_AddNumberToObject(rot_obj, "old_key_revoke_ms", (double)rot.old_key_revoke_ms);
        cJSON_AddBoolToObject(rot_obj, "warning_sent", rot.warning_sent);
        cJSON_AddBoolToObject(rot_obj, "new_key_created", rot.new_key_created);
        cJSON_AddBoolToObject(rot_obj, "old_key_revoked", rot.old_key_revoked);
        cJSON_AddItemToArray(rotations_array, rot_obj);
    }

    cJSON_AddItemToObject(response, "rotations", rotations_array);
    cJSON_AddNumberToObject(response, "count", rotations.size());

    return response;
}

// POST /api/security/rotation/schedule
// Schedule a new key rotation
// Expected JSON: {"key_id": "uuid-here", "label": "Production API Key"}
inline cJSON* handleRotationSchedulePost(const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();

    if (!g_api_key_rotation_manager) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rotation manager not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* key_id_obj = cJSON_GetObjectItem(request, "key_id");
    cJSON* label_obj = cJSON_GetObjectItem(request, "label");

    if (!key_id_obj || !cJSON_IsString(key_id_obj) || !label_obj || !cJSON_IsString(label_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid key_id or label");
        return response;
    }

    bool success = g_api_key_rotation_manager->scheduleRotation(key_id_obj->valuestring, label_obj->valuestring);
    cJSON_Delete(request);

    if (success) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "message", "Rotation scheduled successfully");
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to schedule rotation (already scheduled or invalid key)");
    }

    return response;
}

// POST /api/security/rotation/cancel
// Cancel a scheduled rotation
// Expected JSON: {"key_id": "uuid-here"}
inline cJSON* handleRotationCancelPost(const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();

    if (!g_api_key_rotation_manager) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rotation manager not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* key_id_obj = cJSON_GetObjectItem(request, "key_id");
    if (!key_id_obj || !cJSON_IsString(key_id_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid key_id");
        return response;
    }

    bool success = g_api_key_rotation_manager->cancelRotation(key_id_obj->valuestring);
    cJSON_Delete(request);

    if (success) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "message", "Rotation canceled successfully");
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rotation not found or already completed");
    }

    return response;
}

// POST /api/security/rotation/trigger
// Manually trigger immediate rotation for a key
// Expected JSON: {"key_id": "uuid-here", "new_label": "Production API Key - Q1 2025"}
inline cJSON* handleRotationTriggerPost(const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();

    if (!g_api_key_rotation_manager) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Rotation manager not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* key_id_obj = cJSON_GetObjectItem(request, "key_id");
    cJSON* new_label_obj = cJSON_GetObjectItem(request, "new_label");

    if (!key_id_obj || !cJSON_IsString(key_id_obj) || !new_label_obj || !cJSON_IsString(new_label_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid key_id or new_label");
        return response;
    }

    bool success = g_api_key_rotation_manager->triggerImmediateRotation(key_id_obj->valuestring, new_label_obj->valuestring);
    cJSON_Delete(request);

    if (success) {
        cJSON_AddBoolToObject(response, "success", true);
        cJSON_AddStringToObject(response, "message", "Rotation triggered successfully - check logs for new token");
    } else {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to trigger rotation");
    }

    return response;
}

} // namespace SecurityAPI
