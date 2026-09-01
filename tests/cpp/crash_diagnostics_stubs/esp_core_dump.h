#pragma once

#include <cstddef>

using esp_err_t = int;
constexpr esp_err_t ESP_OK = 0;
constexpr esp_err_t ESP_FAIL = -1;
constexpr esp_err_t ESP_ERR_NOT_FOUND = 0x105;
constexpr esp_err_t ESP_ERR_NOT_SUPPORTED = 0x106;

#ifndef CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH
#define CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH 1
#endif
#ifndef CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF
#define CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF 1
#endif

esp_err_t esp_core_dump_image_check();
esp_err_t esp_core_dump_get_panic_reason(char* reason_buffer, size_t buffer_size);
