#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "esp_log.h"

// C-compatible macros for the logging system
#define LOG_ERROR(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
#define LOG_WARNING(tag, fmt, ...) ESP_LOGW(tag, fmt, ##__VA_ARGS__)
#define LOG_INFO(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(tag, fmt, ...) ESP_LOGD(tag, fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(tag, fmt, ...) ESP_LOGV(tag, fmt, ##__VA_ARGS__)

// Versions with more complex format
#define LOG_ERRORF(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
#define LOG_WARNINGF(tag, fmt, ...) ESP_LOGW(tag, fmt, ##__VA_ARGS__)
#define LOG_INFOF(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)
#define LOG_DEBUGF(tag, fmt, ...) ESP_LOGD(tag, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif