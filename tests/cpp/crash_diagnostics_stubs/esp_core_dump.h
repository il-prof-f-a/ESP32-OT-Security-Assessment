#pragma once

#include <cstddef>

using esp_err_t = int;
constexpr esp_err_t ESP_OK = 0;
constexpr esp_err_t ESP_FAIL = -1;
constexpr esp_err_t ESP_ERR_NOT_FOUND = 0x105;

esp_err_t esp_core_dump_image_check();
esp_err_t esp_core_dump_get_panic_reason(char* reason_buffer, size_t buffer_size);
