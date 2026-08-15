#pragma once
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STACK_WORDS_FROM_BYTES(B) ((B) / sizeof(StackType_t))

TaskHandle_t create_task_core0_psram(TaskFunction_t fn,
                                     const char *name,
                                     uint32_t stack_words,
                                     void *arg,
                                     UBaseType_t prio);

TaskHandle_t create_task_core1_psram(TaskFunction_t fn,
                                     const char *name,
                                     uint32_t stack_words,
                                     void *arg,
                                     UBaseType_t prio);

#ifdef __cplusplus
}
#endif
