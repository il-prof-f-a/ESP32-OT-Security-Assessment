#include "nvs_override.h"
#include "async_storage_engine.h"
#include "logging_system.h"

#include <map>
#include <set>
#include <string>
#include <cstring>

extern "C" {
    #include "esp_log.h"
    #include "nvs_flash.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"

    // Forward declarations for original functions (called via __real_*)
    esp_err_t __real_nvs_open(const char* name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle);
    esp_err_t __real_nvs_set_str(nvs_handle_t handle, const char* key, const char* value);
    esp_err_t __real_nvs_get_str(nvs_handle_t handle, const char* key, char* out_value, size_t* length);
    esp_err_t __real_nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length);
    esp_err_t __real_nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length);
    esp_err_t __real_nvs_set_u8(nvs_handle_t handle, const char* key, uint8_t value);
    esp_err_t __real_nvs_get_u8(nvs_handle_t handle, const char* key, uint8_t* out_value);
    esp_err_t __real_nvs_set_u16(nvs_handle_t handle, const char* key, uint16_t value);
    esp_err_t __real_nvs_get_u16(nvs_handle_t handle, const char* key, uint16_t* out_value);
    esp_err_t __real_nvs_set_u32(nvs_handle_t handle, const char* key, uint32_t value);
    esp_err_t __real_nvs_get_u32(nvs_handle_t handle, const char* key, uint32_t* out_value);
    esp_err_t __real_nvs_set_i8(nvs_handle_t handle, const char* key, int8_t value);
    esp_err_t __real_nvs_get_i8(nvs_handle_t handle, const char* key, int8_t* out_value);
    esp_err_t __real_nvs_set_i16(nvs_handle_t handle, const char* key, int16_t value);
    esp_err_t __real_nvs_get_i16(nvs_handle_t handle, const char* key, int16_t* out_value);
    esp_err_t __real_nvs_set_i32(nvs_handle_t handle, const char* key, int32_t value);
    esp_err_t __real_nvs_get_i32(nvs_handle_t handle, const char* key, int32_t* out_value);
    esp_err_t __real_nvs_set_i64(nvs_handle_t handle, const char* key, int64_t value);
    esp_err_t __real_nvs_get_i64(nvs_handle_t handle, const char* key, int64_t* out_value);
    esp_err_t __real_nvs_erase_key(nvs_handle_t handle, const char* key);
    esp_err_t __real_nvs_commit(nvs_handle_t handle);
    void __real_nvs_close(nvs_handle_t handle);
    esp_err_t __real_nvs_flash_erase();
    esp_err_t __real_nvs_flash_init();
}

static const char* TAG = "NVSOverride";

static bool is_cron_saver_task() {
    TaskHandle_t current = xTaskGetCurrentTaskHandle();
    if (!current) {
        return false;
    }
    const char* task_name = pcTaskGetName(current);
    return (task_name && strcmp(task_name, "CronSaver") == 0);
}

#define NVS_DEBUGF(fmt, ...) do {                    \
    if (!is_cron_saver_task()) {                     \
        LOG_DEBUGF(TAG, fmt, ##__VA_ARGS__);         \
    }                                                 \
} while (0)

// Global state
static bool override_enabled = false;
static std::map<nvs_handle_t, std::string> handle_to_namespace;
static std::set<nvs_handle_t> real_phy_handles; // Track real system handles (PHY/WiFi) that bypass everything
static nvs_handle_t next_handle = 1000; // Start with high number to avoid conflicts
static TaskHandle_t storage_worker_task = nullptr; // Track storage worker task

extern "C" {

void nvs_override_enable() {
    override_enabled = true;
    LOG_INFO(TAG, "NVS Override enabled - routing NVS calls through AsyncStorage");
}

void nvs_override_disable() {
    override_enabled = false;
    LOG_INFO(TAG, "NVS Override disabled - using native NVS");
}

bool nvs_override_is_enabled() {
    return override_enabled;
}

void nvs_override_set_worker_task(void* task_handle) {
    storage_worker_task = (TaskHandle_t)task_handle;
    NVS_DEBUGF("Storage worker task set: %p", task_handle);
}

// Check if current task is the storage worker (to avoid recursive calls)
static bool is_storage_worker_task() {
    TaskHandle_t current = xTaskGetCurrentTaskHandle();
    return (storage_worker_task != nullptr && current == storage_worker_task);
}

// Check if handle belongs to system namespace (pass through to real NVS)
static bool is_phy_handle(nvs_handle_t handle) {
    // Check if it's a tracked real system handle (PHY, WiFi, etc.)
    return real_phy_handles.find(handle) != real_phy_handles.end();
}

esp_err_t nvs_open_override(const char* name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle) {
    if (!override_enabled || is_storage_worker_task()) {
        return __real_nvs_open(name, open_mode, out_handle);
    }

    // BYPASS SYSTEM NAMESPACES: pass through to avoid timing/recursion issues
    if (name && (!strcmp(name, "phy") || !strcmp(name, "nvs.net80211") ||
                 !strcmp(name, "wifi_cfg") || !strcmp(name, "wifi"))) {
        NVS_DEBUGF("System namespace '%s' bypass: passing through to real NVS", name);
        esp_err_t result = __real_nvs_open(name, open_mode, out_handle);
        if (result == ESP_OK && out_handle) {
            real_phy_handles.insert(*out_handle); // Track this handle for bypass
            NVS_DEBUGF("System handle %u tracked for bypass", *out_handle);
        }
        return result;
    }

    // Create virtual handle and store namespace
    *out_handle = next_handle++;
    handle_to_namespace[*out_handle] = std::string(name);

    NVS_DEBUGF("NVS override: opened namespace '%s' with handle %u", name, *out_handle);
    return ESP_OK;
}

esp_err_t nvs_set_str_override(nvs_handle_t handle, const char* key, const char* value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_str(handle, key, value);
    }

    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        LOG_ERRORF(TAG, "Invalid handle %u in nvs_set_str_override", handle);
        return ESP_ERR_NVS_INVALID_HANDLE;
    }

    esp_err_t result = AsyncStorage::Global::nvsSet(it->second, key, std::string(value));
    NVS_DEBUGF("NVS override: set '%s:%s' = '%s' -> %s",
               it->second.c_str(), key, value, esp_err_to_name(result));
    return result;
}

esp_err_t nvs_get_str_override(nvs_handle_t handle, const char* key, char* out_value, size_t* length) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_str(handle, key, out_value, length);
    }

    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        LOG_ERRORF(TAG, "Invalid handle %u in nvs_get_str_override", handle);
        return ESP_ERR_NVS_INVALID_HANDLE;
    }

    std::string value;
    esp_err_t result = AsyncStorage::Global::nvsGet(it->second, key, value);

    if (result == ESP_OK) {
        if (out_value == nullptr) {
            // Just return the required length
            *length = value.length() + 1; // +1 for null terminator
        } else {
            // Copy the value
            if (*length >= value.length() + 1) {
                strcpy(out_value, value.c_str());
                *length = value.length() + 1;
            } else {
                // Buffer too small - return required length
                *length = value.length() + 1;
                result = ESP_ERR_NVS_INVALID_LENGTH;
            }
        }
    } else {
        // Key not found or other error - length should be 0
        if (length) *length = 0;
    }

    NVS_DEBUGF("NVS override: get '%s:%s' -> %s (len=%u)",
               it->second.c_str(), key, esp_err_to_name(result), length ? *length : 0);
    return result;
}

esp_err_t nvs_set_blob_override(nvs_handle_t handle, const char* key, const void* value, size_t length) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_blob(handle, key, value, length);
    }

    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        LOG_ERRORF(TAG, "Invalid handle %u in nvs_set_blob_override", handle);
        return ESP_ERR_NVS_INVALID_HANDLE;
    }

    esp_err_t result = AsyncStorage::Global::nvsSetBlob(it->second, key, value, length);
    NVS_DEBUGF("NVS override: set blob '%s:%s' (%u bytes) -> %s",
               it->second.c_str(), key, length, esp_err_to_name(result));
    return result;
}

esp_err_t nvs_get_blob_override(nvs_handle_t handle, const char* key, void* out_value, size_t* length) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_blob(handle, key, out_value, length);
    }

    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        LOG_ERRORF(TAG, "Invalid handle %u in nvs_get_blob_override", handle);
        return ESP_ERR_NVS_INVALID_HANDLE;
    }

    std::vector<uint8_t> blob_data;
    esp_err_t result = AsyncStorage::Global::nvsGetBlob(it->second, key, blob_data);

    if (result == ESP_OK) {
        if (out_value == nullptr) {
            // Just return the required length
            *length = blob_data.size();
        } else {
            // Copy the blob - ensure we don't overflow buffer
            if (*length >= blob_data.size()) {
                memcpy(out_value, blob_data.data(), blob_data.size());
                *length = blob_data.size();
            } else {
                // Buffer too small - just return required length
                *length = blob_data.size();
                result = ESP_ERR_NVS_INVALID_LENGTH;
            }
        }
    } else {
        // Key not found or other error - length should be 0
        if (length) *length = 0;
    }

    NVS_DEBUGF("NVS override: get blob '%s:%s' -> %s (len=%u)",
               it->second.c_str(), key, esp_err_to_name(result), length ? *length : 0);
    return result;
}

esp_err_t nvs_commit_override(nvs_handle_t handle) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_commit(handle);
    }

    // AsyncStorage commits automatically, so this is a no-op
    NVS_DEBUGF("NVS override: commit handle %u (no-op for AsyncStorage)", handle);
    return ESP_OK;
}

void nvs_close_override(nvs_handle_t handle) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        __real_nvs_close(handle);
        return;
    }

    // Check if it's a system handle - if so, pass through and remove tracking
    if (is_phy_handle(handle)) {
        NVS_DEBUGF("System handle %u closed, removing from bypass tracking", handle);
        real_phy_handles.erase(handle);
        __real_nvs_close(handle);
        return;
    }

    auto it = handle_to_namespace.find(handle);
    if (it != handle_to_namespace.end()) {
        NVS_DEBUGF("NVS override: closed namespace '%s' handle %u", it->second.c_str(), handle);
        handle_to_namespace.erase(it);
    }
}

// Linker wrapper functions - these are called by the linker when --wrap is used
// They replace the original NVS functions and route through our override system

esp_err_t __wrap_nvs_open(const char* name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle) {
    return nvs_open_override(name, open_mode, out_handle);
}

esp_err_t __wrap_nvs_set_str(nvs_handle_t handle, const char* key, const char* value) {
    return nvs_set_str_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_str(nvs_handle_t handle, const char* key, char* out_value, size_t* length) {
    return nvs_get_str_override(handle, key, out_value, length);
}

esp_err_t __wrap_nvs_set_blob(nvs_handle_t handle, const char* key, const void* value, size_t length) {
    return nvs_set_blob_override(handle, key, value, length);
}

esp_err_t __wrap_nvs_get_blob(nvs_handle_t handle, const char* key, void* out_value, size_t* length) {
    return nvs_get_blob_override(handle, key, out_value, length);
}

esp_err_t __wrap_nvs_commit(nvs_handle_t handle) {
    return nvs_commit_override(handle);
}

void __wrap_nvs_close(nvs_handle_t handle) {
    nvs_close_override(handle);
}

esp_err_t nvs_flash_erase_override() {
    // Always delegate to real function - nvs_flash_erase is idempotent
    // This ensures NVS structures are properly cleaned up
    return __real_nvs_flash_erase();
}

esp_err_t nvs_flash_init_override() {
    // Always delegate to real function - nvs_flash_init is idempotent
    // This ensures NVS is properly initialized before any usage
    return __real_nvs_flash_init();
}

esp_err_t __wrap_nvs_flash_erase() {
    return nvs_flash_erase_override();
}

esp_err_t __wrap_nvs_flash_init() {
    return nvs_flash_init_override();
}

// Numeric type overrides - route through AsyncStorage engine
esp_err_t nvs_set_u8_override(nvs_handle_t handle, const char* key, uint8_t value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_u8(handle, key, value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Global::nvsSet(it->second, key, value);
}

esp_err_t nvs_get_u8_override(nvs_handle_t handle, const char* key, uint8_t* out_value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_u8(handle, key, out_value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Global::nvsGet(it->second, key, *out_value);
}

esp_err_t nvs_set_u32_override(nvs_handle_t handle, const char* key, uint32_t value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_u32(handle, key, value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Global::nvsSet(it->second, key, value);
}

esp_err_t nvs_get_u32_override(nvs_handle_t handle, const char* key, uint32_t* out_value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_u32(handle, key, out_value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Global::nvsGet(it->second, key, *out_value);
}

esp_err_t nvs_erase_key_override(nvs_handle_t handle, const char* key) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_erase_key(handle, key);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Global::nvsEraseKey(it->second, key);
}

// Wrapper functions for numeric types
esp_err_t __wrap_nvs_set_u8(nvs_handle_t handle, const char* key, uint8_t value) {
    return nvs_set_u8_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_u8(nvs_handle_t handle, const char* key, uint8_t* out_value) {
    return nvs_get_u8_override(handle, key, out_value);
}

esp_err_t __wrap_nvs_set_u32(nvs_handle_t handle, const char* key, uint32_t value) {
    return nvs_set_u32_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_u32(nvs_handle_t handle, const char* key, uint32_t* out_value) {
    return nvs_get_u32_override(handle, key, out_value);
}

esp_err_t __wrap_nvs_erase_key(nvs_handle_t handle, const char* key) {
    return nvs_erase_key_override(handle, key);
}

// Implementations for remaining numeric types
esp_err_t nvs_set_u16_override(nvs_handle_t handle, const char* key, uint16_t value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_u16(handle, key, value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsSetU16(it->second, key, value);
}

esp_err_t nvs_get_u16_override(nvs_handle_t handle, const char* key, uint16_t* out_value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_u16(handle, key, out_value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsGetU16(it->second, key, *out_value);
}

esp_err_t nvs_set_i8_override(nvs_handle_t handle, const char* key, int8_t value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_i8(handle, key, value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsSetI8(it->second, key, value);
}

esp_err_t nvs_get_i8_override(nvs_handle_t handle, const char* key, int8_t* out_value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_i8(handle, key, out_value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsGetI8(it->second, key, *out_value);
}

esp_err_t nvs_set_i16_override(nvs_handle_t handle, const char* key, int16_t value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_i16(handle, key, value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsSetI16(it->second, key, value);
}

esp_err_t nvs_get_i16_override(nvs_handle_t handle, const char* key, int16_t* out_value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_i16(handle, key, out_value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsGetI16(it->second, key, *out_value);
}

esp_err_t nvs_set_i32_override(nvs_handle_t handle, const char* key, int32_t value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_i32(handle, key, value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsSetI32(it->second, key, value);
}

esp_err_t nvs_get_i32_override(nvs_handle_t handle, const char* key, int32_t* out_value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_i32(handle, key, out_value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsGetI32(it->second, key, *out_value);
}

esp_err_t nvs_set_i64_override(nvs_handle_t handle, const char* key, int64_t value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_set_i64(handle, key, value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsSetI64(it->second, key, value);
}

esp_err_t nvs_get_i64_override(nvs_handle_t handle, const char* key, int64_t* out_value) {
    if (!override_enabled || is_storage_worker_task() || is_phy_handle(handle)) {
        return __real_nvs_get_i64(handle, key, out_value);
    }
    auto it = handle_to_namespace.find(handle);
    if (it == handle_to_namespace.end()) {
        return ESP_ERR_NVS_INVALID_HANDLE;
    }
    return AsyncStorage::Engine::getInstance().nvsGetI64(it->second, key, *out_value);
}

// Wrapper functions
esp_err_t __wrap_nvs_set_u16(nvs_handle_t handle, const char* key, uint16_t value) {
    return nvs_set_u16_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_u16(nvs_handle_t handle, const char* key, uint16_t* out_value) {
    return nvs_get_u16_override(handle, key, out_value);
}

esp_err_t __wrap_nvs_set_i8(nvs_handle_t handle, const char* key, int8_t value) {
    return nvs_set_i8_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_i8(nvs_handle_t handle, const char* key, int8_t* out_value) {
    return nvs_get_i8_override(handle, key, out_value);
}

esp_err_t __wrap_nvs_set_i16(nvs_handle_t handle, const char* key, int16_t value) {
    return nvs_set_i16_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_i16(nvs_handle_t handle, const char* key, int16_t* out_value) {
    return nvs_get_i16_override(handle, key, out_value);
}

esp_err_t __wrap_nvs_set_i32(nvs_handle_t handle, const char* key, int32_t value) {
    return nvs_set_i32_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_i32(nvs_handle_t handle, const char* key, int32_t* out_value) {
    return nvs_get_i32_override(handle, key, out_value);
}

esp_err_t __wrap_nvs_set_i64(nvs_handle_t handle, const char* key, int64_t value) {
    return nvs_set_i64_override(handle, key, value);
}

esp_err_t __wrap_nvs_get_i64(nvs_handle_t handle, const char* key, int64_t* out_value) {
    return nvs_get_i64_override(handle, key, out_value);
}

} // extern "C"
