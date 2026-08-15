#pragma once

#include "esp_err.h"
#include "nvs.h"

extern "C" {

// NVS Override System - Intercepts NVS calls and routes them through AsyncStorage
// This prevents PSRAM stack crashes during flash operations from WiFi/system tasks

// Override NVS functions to route through AsyncStorage engine
esp_err_t nvs_open_override(const char* name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle);
esp_err_t nvs_set_str_override(nvs_handle_t handle, const char* key, const char* value);
esp_err_t nvs_get_str_override(nvs_handle_t handle, const char* key, char* out_value, size_t* length);
esp_err_t nvs_set_blob_override(nvs_handle_t handle, const char* key, const void* value, size_t length);
esp_err_t nvs_get_blob_override(nvs_handle_t handle, const char* key, void* out_value, size_t* length);
esp_err_t nvs_set_u8_override(nvs_handle_t handle, const char* key, uint8_t value);
esp_err_t nvs_get_u8_override(nvs_handle_t handle, const char* key, uint8_t* out_value);
esp_err_t nvs_set_u16_override(nvs_handle_t handle, const char* key, uint16_t value);
esp_err_t nvs_get_u16_override(nvs_handle_t handle, const char* key, uint16_t* out_value);
esp_err_t nvs_set_u32_override(nvs_handle_t handle, const char* key, uint32_t value);
esp_err_t nvs_get_u32_override(nvs_handle_t handle, const char* key, uint32_t* out_value);
esp_err_t nvs_set_i8_override(nvs_handle_t handle, const char* key, int8_t value);
esp_err_t nvs_get_i8_override(nvs_handle_t handle, const char* key, int8_t* out_value);
esp_err_t nvs_set_i16_override(nvs_handle_t handle, const char* key, int16_t value);
esp_err_t nvs_get_i16_override(nvs_handle_t handle, const char* key, int16_t* out_value);
esp_err_t nvs_set_i32_override(nvs_handle_t handle, const char* key, int32_t value);
esp_err_t nvs_get_i32_override(nvs_handle_t handle, const char* key, int32_t* out_value);
esp_err_t nvs_set_i64_override(nvs_handle_t handle, const char* key, int64_t value);
esp_err_t nvs_get_i64_override(nvs_handle_t handle, const char* key, int64_t* out_value);
esp_err_t nvs_erase_key_override(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit_override(nvs_handle_t handle);
void nvs_close_override(nvs_handle_t handle);
esp_err_t nvs_flash_erase_override();
esp_err_t nvs_flash_init_override();

// Enable/disable override system
void nvs_override_enable();
void nvs_override_disable();
bool nvs_override_is_enabled();

// Set storage worker task handle to avoid recursive calls
void nvs_override_set_worker_task(void* task_handle);

} // extern "C"