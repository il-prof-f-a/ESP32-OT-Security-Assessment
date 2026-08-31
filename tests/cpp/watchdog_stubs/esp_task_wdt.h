#pragma once
#include <cstdint>

// Only the ESP-IDF platform boundary is replaced. The production lifecycle
// header is compiled unchanged, and all calls must target the current task.
using esp_err_t = int;
using TaskHandle_t = void*;
constexpr esp_err_t ESP_OK = 0;
constexpr esp_err_t ESP_FAIL = -1;
constexpr esp_err_t ESP_ERR_NO_MEM = 0x101;
constexpr esp_err_t ESP_ERR_INVALID_ARG = 0x102;
constexpr esp_err_t ESP_ERR_INVALID_STATE = 0x103;
constexpr esp_err_t ESP_ERR_NOT_FOUND = 0x105;
struct esp_task_wdt_config_t {
    uint32_t timeout_ms;
    uint32_t idle_core_mask;
    bool trigger_panic;
};
esp_err_t esp_task_wdt_init(const esp_task_wdt_config_t*);
esp_err_t esp_task_wdt_reconfigure(const esp_task_wdt_config_t*);
esp_err_t esp_task_wdt_status(TaskHandle_t);
esp_err_t esp_task_wdt_add(TaskHandle_t);
esp_err_t esp_task_wdt_delete(TaskHandle_t);
esp_err_t esp_task_wdt_reset();
