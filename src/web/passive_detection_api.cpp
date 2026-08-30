#include "web_server.h"
#include "../core/configuration_manager.h"
#include "../assessment/intrusion_detection_general.h"
#include "../assessment/signature_detector.h"
#include "cJSON.h"
#include <cmath>
#include <cstring>

namespace {
struct JsonOwner {
    cJSON* value;
    ~JsonOwner() { cJSON_Delete(value); }
};

// Promote legacy configuration by copying the entire section, not only its flag.
cJSON* section(cJSON* root, const char* name, const char* legacy = nullptr) {
    cJSON* ids = cJSON_GetObjectItemCaseSensitive(root, "ids");
    if (!ids) ids = cJSON_AddObjectToObject(root, "ids");
    if (!cJSON_IsObject(ids)) return nullptr;
    cJSON* result = cJSON_GetObjectItemCaseSensitive(ids, name);
    if (!result) {
        cJSON* old = legacy ? cJSON_GetObjectItemCaseSensitive(root, legacy) : nullptr;
        result = cJSON_IsObject(old) ? cJSON_Duplicate(old, true) : cJSON_CreateObject();
        if (!result) return nullptr;
        if (!cJSON_AddItemToObject(ids, name, result)) {
            cJSON_Delete(result);
            return nullptr;
        }
    }
    return cJSON_IsObject(result) ? result : nullptr;
}

bool replace(cJSON* object, const char* key, cJSON* value) {
    if (!object || !value) { cJSON_Delete(value); return false; }
    bool ok = cJSON_HasObjectItem(object, key)
        ? cJSON_ReplaceItemInObjectCaseSensitive(object, key, value)
        : cJSON_AddItemToObject(object, key, value);
    if (!ok) cJSON_Delete(value);
    return ok;
}

esp_err_t error(httpd_req_t* req, const char* status, const char* message) {
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    char body[160];
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}", message);
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

cJSON* snapshot(ConfigurationManager& cfg) {
    size_t length = 0;
    char* raw = cfg.getRawConfigInPSRAM(&length);
    cJSON* result = raw ? cJSON_ParseWithLength(raw, length) : nullptr;
    if (raw) heap_caps_free(raw);
    return result;
}

bool persist(ConfigurationManager& cfg, cJSON* root) {
    char* raw = cJSON_PrintUnformatted(root);
    if (!raw) return false;
    bool success = cfg.saveConfigJSON(PSRAMUtils::createPSRAMString(raw));
    cJSON_free(raw);
    return success;
}

bool validPresenceField(const cJSON* item) {
    if (!item->string) return false;
    const char* key = item->string;
    for (auto name : {"enabled", "learning_mode", "alert_unauthorized_writes",
                      "track_all_traffic", "enable_persistent_learning"})
        if (!strcmp(key, name)) return cJSON_IsBool(item);
    if (!strcmp(key, "whitelisted_devices")) {
        if (!cJSON_IsArray(item) || cJSON_GetArraySize(item) > 256) return false;
        const cJSON* entry = nullptr;
        cJSON_ArrayForEach(entry, item)
            if (!cJSON_IsString(entry) || !entry->valuestring ||
                strlen(entry->valuestring) > 128) return false;
        return true;
    }
    if (!cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) ||
        item->valuedouble < 0) return false;
    for (auto name : {"trust_threshold_score", "continuity_weight", "diversity_weight", "frequency_weight"})
        if (!strcmp(key, name)) return item->valuedouble <= 1.0;
    if (!strcmp(key, "min_observation_period_hours")) return item->valuedouble <= 87600;
    for (auto name : {"cleanup_interval_ms", "inactive_device_timeout_ms",
                      "activation_delay_minutes", "retention_days", "storage_sync_interval_ms"})
        if (!strcmp(key, name)) return item->valuedouble <= UINT32_MAX &&
            std::floor(item->valuedouble) == item->valuedouble;
    return false;
}
}

esp_err_t WebServer::h_passive_config_get(httpd_req_t* req) {
    if (!check_api_auth(req)) return error(req, "401 Unauthorized", "auth");
    if (!self_ || !self_->cfg_ || !self_->ids_)
        return error(req, "503 Service Unavailable", "passive_services_unavailable");
    auto lock = self_->cfg_->lockConfig();
    const auto flags = self_->cfg_->getPassiveDetectionFlags();
    const auto& detector = SignatureDetection::SignatureDetector::getInstance();
    char body[320];
    snprintf(body, sizeof(body),
        "{\"ids_enabled\":%s,\"signatures_enabled\":%s,\"network_presence_enabled\":%s,"
        "\"runtime\":{\"ids_enabled\":%s,\"signatures_enabled\":%s,\"network_presence_enabled\":%s}}",
        flags.ids_enabled ? "true" : "false", flags.signatures_enabled ? "true" : "false",
        flags.network_presence_enabled ? "true" : "false",
        self_->ids_->isActive() ? "true" : "false", detector.isEnabled() ? "true" : "false",
        self_->ids_->getNetworkPresenceTracker().isActive() ? "true" : "false");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

esp_err_t WebServer::h_passive_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return error(req, "401 Unauthorized", "auth");
    if (!self_ || !self_->cfg_ || !self_->ids_)
        return error(req, "503 Service Unavailable", "passive_services_unavailable");
    psram_string body;
    if (!read_body(req, body, 1024)) return error(req, "400 Bad Request", "invalid_body");
    JsonOwner request{cJSON_Parse(body.c_str())};
    if (!cJSON_IsObject(request.value)) return error(req, "400 Bad Request", "invalid_json");
    const char* keys[] = {"ids_enabled", "signatures_enabled", "network_presence_enabled"};
    for (auto key : keys)
        if (!cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(request.value, key)))
            return error(req, "400 Bad Request", "three_boolean_flags_required");
    if (cJSON_GetArraySize(request.value) != 3)
        return error(req, "400 Bad Request", "unknown_or_duplicate_flag");
    auto lock = self_->cfg_->lockConfig();
    JsonOwner config{snapshot(*self_->cfg_)};
    if (!cJSON_IsObject(config.value)) return error(req, "500 Internal Server Error", "config_unavailable");
    const char* sections[] = {"general", "signatures", "network_presence"};
    const char* legacy[] = {"advanced_ids", nullptr, "network_presence"};
    for (size_t i = 0; i < 3; ++i) {
        auto* target = section(config.value, sections[i], legacy[i]);
        if (!replace(target, "enabled", cJSON_Duplicate(
                cJSON_GetObjectItemCaseSensitive(request.value, keys[i]), false)))
            return error(req, "500 Internal Server Error", "config_update_failed");
    }
    if (!persist(*self_->cfg_, config.value))
        return error(req, "500 Internal Server Error", "config_save_failed");
    logConfigChange(req, "passive_detection", "Independent module enable flags updated");
    return h_passive_config_get(req);
}

esp_err_t WebServer::h_presence_config_post(httpd_req_t* req) {
    if (!check_api_auth(req)) return error(req, "401 Unauthorized", "auth");
    if (!self_ || !self_->cfg_ || !self_->ids_)
        return error(req, "503 Service Unavailable", "passive_services_unavailable");
    psram_string body;
    if (!read_body(req, body, 32768)) return error(req, "400 Bad Request", "invalid_body");
    JsonOwner request{cJSON_Parse(body.c_str())};
    if (!cJSON_IsObject(request.value)) return error(req, "400 Bad Request", "invalid_json");
    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, request.value)
        if (!validPresenceField(item)) return error(req, "400 Bad Request", "invalid_presence_field");
    auto lock = self_->cfg_->lockConfig();
    JsonOwner config{snapshot(*self_->cfg_)};
    if (!cJSON_IsObject(config.value)) return error(req, "500 Internal Server Error", "config_unavailable");
    cJSON* target = section(config.value, "network_presence", "network_presence");
    cJSON_ArrayForEach(item, request.value)
        if (!replace(target, item->string, cJSON_Duplicate(item, true)))
            return error(req, "500 Internal Server Error", "config_update_failed");
    if (!target || !persist(*self_->cfg_, config.value))
        return error(req, "500 Internal Server Error", "config_save_failed");
    logConfigChange(req, "network_presence", "Network presence configuration saved and applied");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
}
