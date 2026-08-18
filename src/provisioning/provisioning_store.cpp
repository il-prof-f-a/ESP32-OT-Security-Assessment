#include "provisioning_store.h"

#include <ctime>
#include <cstring>

#include "../core/configuration_manager.h"
#include "../core/async_storage_engine.h"
#include "../core/psram_json_parser.h"
#include "../security/password_hasher.h"

extern "C" {
#include "cJSON.h"
#include "esp_heap_caps.h"
#include "nvs.h"
}


namespace {
constexpr uint16_t kSchemaVersion = 1;

uint32_t crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t index = 0; index < length; ++index) {
        crc ^= data[index];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

bool currentConfig(ConfigurationManager& config, psram_string& output) {
    size_t length = 0;
    char* raw = config.getRawConfigInPSRAM(&length);
    if (!raw || length == 0) {
        if (raw) heap_caps_free(raw);
        return false;
    }
    output.assign(raw, length);
    heap_caps_free(raw);
    return true;
}

bool legacySha256(const psram_string& hash) {
    if (hash.size() != 64) return false;
    for (char value : hash) {
        const bool valid = (value >= '0' && value <= '9') ||
                           (value >= 'a' && value <= 'f') ||
                           (value >= 'A' && value <= 'F');
        if (!valid) return false;
    }
    return true;
}

bool readAdminHash(psram_string& output) {
    nvs_handle_t handle;
    if (nvs_open("security", NVS_READONLY, &handle) != ESP_OK) return false;
    size_t length = 0;
    esp_err_t error = nvs_get_str(handle, "admin_pwd", nullptr, &length);
    if (error != ESP_OK || length <= 1 || length > 256) {
        nvs_close(handle);
        return false;
    }
    char buffer[256] = {};
    error = nvs_get_str(handle, "admin_pwd", buffer, &length);
    nvs_close(handle);
    if (error != ESP_OK) return false;
    output = PSRAMUtils::createPSRAMString(buffer);
    std::memset(buffer, 0, sizeof(buffer));
    return true;
}

bool writeAdminHash(const psram_string& hash) {
    nvs_handle_t handle;
    if (nvs_open("security", NVS_READWRITE, &handle) != ESP_OK) return false;
    esp_err_t error = nvs_set_str(handle, "admin_pwd", hash.c_str());
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return error == ESP_OK;
}

bool replaceString(cJSON* object, const char* name, const char* value) {
    cJSON* replacement = cJSON_CreateString(value ? value : "");
    if (!replacement) return false;
    if (cJSON_HasObjectItem(object, name)) {
        cJSON_ReplaceItemInObjectCaseSensitive(object, name, replacement);
    } else {
        cJSON_AddItemToObject(object, name, replacement);
    }
    return true;
}

bool replaceBool(cJSON* object, const char* name, bool value) {
    cJSON* replacement = cJSON_CreateBool(value);
    if (!replacement) return false;
    if (cJSON_HasObjectItem(object, name)) {
        cJSON_ReplaceItemInObjectCaseSensitive(object, name, replacement);
    } else {
        cJSON_AddItemToObject(object, name, replacement);
    }
    return true;
}

bool buildProvisionedConfig(ConfigurationManager& config,
                            const ProvisioningSubmission& submission,
                            const psram_string& admin_hash,
                            psram_string& output) {
    psram_string current;
    if (!currentConfig(config, current)) return false;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(current.c_str(), current.size());
    if (!root) return false;

    cJSON* security = cJSON_GetObjectItemCaseSensitive(root, "security");
    cJSON* network = cJSON_GetObjectItemCaseSensitive(root, "network");
    cJSON* wifi = network ? cJSON_GetObjectItemCaseSensitive(network, "wifi") : nullptr;
    cJSON* ethernet = network ? cJSON_GetObjectItemCaseSensitive(network, "ethernet") : nullptr;
    bool valid = cJSON_IsObject(security) && cJSON_IsObject(network) &&
                 cJSON_IsObject(wifi) && cJSON_IsObject(ethernet);
    if (valid) {
        cJSON_DeleteItemFromObjectCaseSensitive(security, "admin_password");
        valid = replaceString(security, "admin_password_hash", admin_hash.c_str()) &&
                replaceBool(wifi, "enabled", submission.wifi_enabled) &&
                replaceString(wifi, "ssid", submission.wifi_ssid.c_str()) &&
                replaceString(wifi, "password", submission.wifi_password.c_str()) &&
                replaceBool(ethernet, "dhcp", submission.ethernet_dhcp);
    }
    char* rendered = valid ? cJSON_PrintUnformatted(root) : nullptr;
    const bool rendered_ok = rendered != nullptr;
    if (rendered) {
        output = PSRAMUtils::createPSRAMString(rendered);
        cJSON_free(rendered);
    }
    cJSON_Delete(root);
    return rendered_ok;
}

bool writeMetadata(uint32_t config_crc, uint64_t completed_at, bool complete) {
    nvs_handle_t handle;
    if (nvs_open("provisioning", NVS_READWRITE, &handle) != ESP_OK) return false;
    esp_err_t error = nvs_set_u8(handle, "complete_u8", 0);
    if (error == ESP_OK) error = nvs_set_u16(handle, "schema_u16", kSchemaVersion);
    if (error == ESP_OK) error = nvs_set_u32(handle, "config_crc_u32", config_crc);
    if (error == ESP_OK) error = nvs_set_u64(handle, "completed_at_u64", completed_at);
    if (error == ESP_OK) error = nvs_commit(handle);
    if (error == ESP_OK && complete) {
        error = nvs_set_u8(handle, "complete_u8", 1);
        if (error == ESP_OK) error = nvs_commit(handle);
    }
    nvs_close(handle);
    return error == ESP_OK;
}
}  // namespace


ProvisioningState ProvisioningStore::inspect(ConfigurationManager& config) const {
    psram_string hash;
    const bool has_hash = readAdminHash(hash);
    nvs_handle_t handle;
    const esp_err_t opened = nvs_open("provisioning", NVS_READONLY, &handle);
    if (opened == ESP_ERR_NVS_NOT_FOUND) {
        if (has_hash && PasswordHasher::isSupportedHash(hash)) {
            return ProvisioningState::LEGACY_MIGRATION_REQUIRED;
        }
        const SecurityConfig legacy = config.getSecurityConfig();
        return PasswordHasher::isSupportedHash(legacy.admin_password)
                   ? ProvisioningState::LEGACY_MIGRATION_REQUIRED
                   : ProvisioningState::UNPROVISIONED;
    }
    if (opened != ESP_OK) return ProvisioningState::CORRUPT;

    uint16_t schema = 0;
    uint8_t complete = 0;
    uint32_t stored_crc = 0;
    const bool metadata_ok =
        nvs_get_u16(handle, "schema_u16", &schema) == ESP_OK &&
        nvs_get_u8(handle, "complete_u8", &complete) == ESP_OK &&
        nvs_get_u32(handle, "config_crc_u32", &stored_crc) == ESP_OK;
    nvs_close(handle);
    if (!metadata_ok || schema != kSchemaVersion || complete != 1 ||
        !has_hash || !PasswordHasher::isSupportedHash(hash)) {
        return ProvisioningState::CORRUPT;
    }

    psram_string raw;
    if (!currentConfig(config, raw)) return ProvisioningState::CORRUPT;
    return crc32(reinterpret_cast<const uint8_t*>(raw.data()), raw.size()) == stored_crc
               ? ProvisioningState::READY
               : ProvisioningState::CORRUPT;
}

bool ProvisioningStore::migrateLegacyIfValid(ConfigurationManager& config) {
    if (inspect(config) != ProvisioningState::LEGACY_MIGRATION_REQUIRED) return false;
    psram_string hash;
    if (!readAdminHash(hash)) {
        hash = config.getSecurityConfig().admin_password;
        if (!PasswordHasher::isSupportedHash(hash) || !writeAdminHash(hash)) return false;
    }
    if (!PasswordHasher::isSupportedHash(hash) && !legacySha256(hash)) return false;
    psram_string raw;
    if (!currentConfig(config, raw)) return false;
    cJSON* parsed = PSRAMJsonParser::parseInPSRAM(raw.c_str(), raw.size());
    if (!parsed) return false;
    cJSON_Delete(parsed);
    const uint32_t checksum = crc32(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    return writeMetadata(checksum, 0, true);
}

bool ProvisioningStore::commit(const ProvisioningSubmission& submission,
                               const psram_string& admin_hash,
                               ConfigurationManager& config) {
    if (!PasswordHasher::isSupportedHash(admin_hash) || legacySha256(admin_hash)) return false;
    if (!clearCompletionMarker()) return false;

    psram_string rendered;
    if (!buildProvisionedConfig(config, submission, admin_hash, rendered) ||
        !config.saveConfigJSON(rendered) || shouldFail(FaultPoint::AFTER_CONFIG_WRITE)) {
        clearCompletionMarker();
        return false;
    }
    if (!writeAdminHash(admin_hash) || shouldFail(FaultPoint::AFTER_HASH_WRITE)) {
        clearCompletionMarker();
        return false;
    }

    psram_string readback;
    psram_string stored_hash;
    if (!currentConfig(config, readback) || !readAdminHash(stored_hash) ||
        stored_hash != admin_hash || shouldFail(FaultPoint::AFTER_READBACK)) {
        clearCompletionMarker();
        return false;
    }
    const uint32_t checksum = crc32(
        reinterpret_cast<const uint8_t*>(readback.data()), readback.size());
    const std::time_t now = std::time(nullptr);
    const uint64_t completed_at = now >= 1577836800 ? static_cast<uint64_t>(now) : 0;
    if (!writeMetadata(checksum, completed_at, false) ||
        shouldFail(FaultPoint::BEFORE_COMPLETE_MARKER)) {
        clearCompletionMarker();
        return false;
    }

    nvs_handle_t handle;
    if (nvs_open("provisioning", NVS_READWRITE, &handle) != ESP_OK) return false;
    esp_err_t error = nvs_set_u8(handle, "complete_u8", 1);
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return error == ESP_OK;
}

bool ProvisioningStore::clearCompletionMarker() {
    nvs_handle_t handle;
    const esp_err_t opened = nvs_open("provisioning", NVS_READWRITE, &handle);
    if (opened != ESP_OK) return false;
    esp_err_t error = nvs_set_u8(handle, "complete_u8", 0);
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return error == ESP_OK;
}

bool ProvisioningStore::factoryReset() {
    // Fail closed first: an interrupted reset must never resume operational mode.
    if (!clearCompletionMarker()) return false;

    const esp_err_t security = AsyncStorage::Global::nvsEraseAll("security");
    const esp_err_t config =
        AsyncStorage::Global::deleteFile("/data/config/config.json");
    const esp_err_t backup =
        AsyncStorage::Global::deleteFile("/data/config/config.json.bak");

    // Remove the metadata only after every destructive operation has started
    // from a persisted incomplete marker.
    const esp_err_t provisioning =
        AsyncStorage::Global::nvsEraseAll("provisioning");
    return security == ESP_OK &&
           (config == ESP_OK || config == ESP_ERR_NOT_FOUND) &&
           (backup == ESP_OK || backup == ESP_ERR_NOT_FOUND) &&
           provisioning == ESP_OK;
}
