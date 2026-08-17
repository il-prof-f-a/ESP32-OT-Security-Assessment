#include "task_alloc_helpers.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "logging_macros_c.h"
#include <assert.h>

TaskHandle_t create_task_core0_psram(TaskFunction_t fn,
                                     const char *name,
                                     uint32_t stack_words,
                                     void *arg,
                                     UBaseType_t prio)
{
    // Stack in PSRAM, TCB in internal DRAM
    size_t stack_bytes = stack_words * sizeof(StackType_t);
    StackType_t *stack = (StackType_t*) heap_caps_malloc(stack_bytes,
                                                         MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
    StaticTask_t *tcb   = (StaticTask_t*) heap_caps_malloc(sizeof(StaticTask_t),
                                                          MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);

    if (!stack || !tcb) {
        size_t free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        size_t largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
        size_t free_int8 = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        size_t largest_int8 = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (!stack) {
            LOG_ERRORF("TASK_ALLOC", "PSRAM STACK allocation failed for %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)stack_bytes,
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }
        if (!tcb) {
            LOG_ERRORF("TASK_ALLOC", "TCB DRAM allocation failed for %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)sizeof(StaticTask_t),
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }

        // Emergency attempt: try cleanup/defrag and retry the TCB allocation
        if (!tcb) {
            extern bool TaskConfig_emergencyMemoryCleanup_proxy();
            extern void TaskConfig_forceHeapDefragmentation_proxy();
            TaskConfig_emergencyMemoryCleanup_proxy();
            TaskConfig_forceHeapDefragmentation_proxy();
            tcb = (StaticTask_t*) heap_caps_malloc(sizeof(StaticTask_t),
                                                  MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
        }

        if (stack && tcb) {
            // If after cleanup we have both allocations, create the task and return
            TaskHandle_t htmp = xTaskCreateStaticPinnedToCore(fn, name, stack_words, arg, prio, stack, tcb, 0);
            if (htmp) {
                return htmp;
            }
        }

        LOG_ERROR("TASK_ALLOC", "Allocation failed for %s (stack=%p, tcb=%p). Retrying in internal DRAM.", name, stack, tcb);
        if (stack) heap_caps_free(stack);
        if (tcb)   heap_caps_free(tcb);
        // Fallback: internal DRAM (so as not to block the system)
        TaskHandle_t hfallback = NULL;
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &hfallback, 0);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Task %s creation failed even in DRAM.", name);
            return NULL;
        }
        return hfallback;
    }

    TaskHandle_t h = xTaskCreateStaticPinnedToCore(fn, name, stack_words, arg, prio, stack, tcb, 0);
    if (!h) {
        size_t free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        size_t largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
        LOG_ERRORF("TASK_ALLOC", "xTaskCreateStaticPinnedToCore failed for %s (stack=%p, tcb=%p, stack_bytes=%u) | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u) - trying DRAM fallback",
                   name, stack, tcb, (unsigned)stack_bytes, (unsigned)free_iram, (unsigned)largest_iram, (unsigned)free_psram, (unsigned)largest_psram);
        // cleanup
        heap_caps_free(stack);
        heap_caps_free(tcb);
        // Fallback: dynamic creation in DRAM
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &h, 0);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Task %s creation failed even in DRAM.", name);
            return NULL;
        }
        return h;
    }
    return h;
}

TaskHandle_t create_task_core1_psram(TaskFunction_t fn,
                                     const char *name,
                                     uint32_t stack_words,
                                     void *arg,
                                     UBaseType_t prio)
{
    // Stack in PSRAM, TCB in internal DRAM
    size_t stack_bytes = stack_words * sizeof(StackType_t);
    StackType_t *stack = (StackType_t*) heap_caps_malloc(stack_bytes,
                                                         MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
    StaticTask_t *tcb   = (StaticTask_t*) heap_caps_malloc(sizeof(StaticTask_t),
                                                          MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);

    if (!stack || !tcb) {
        size_t free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        size_t largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
        size_t free_int8 = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        size_t largest_int8 = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (!stack) {
            LOG_ERRORF("TASK_ALLOC", "PSRAM STACK allocation failed for %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)stack_bytes,
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }
        if (!tcb) {
            LOG_ERRORF("TASK_ALLOC", "TCB DRAM allocation failed for %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)sizeof(StaticTask_t),
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }

        // Emergency attempt: try cleanup/defrag and retry the TCB allocation
        if (!tcb) {
            extern bool TaskConfig_emergencyMemoryCleanup_proxy();
            extern void TaskConfig_forceHeapDefragmentation_proxy();
            TaskConfig_emergencyMemoryCleanup_proxy();
            TaskConfig_forceHeapDefragmentation_proxy();
            tcb = (StaticTask_t*) heap_caps_malloc(sizeof(StaticTask_t),
                                                  MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
        }

        if (stack && tcb) {
            TaskHandle_t htmp = xTaskCreateStaticPinnedToCore(fn, name, stack_words, arg, prio, stack, tcb, 1);
            if (htmp) {
                return htmp;
            }
        }

        LOG_ERROR("TASK_ALLOC", "Allocation failed for %s (stack=%p, tcb=%p). Retrying in internal DRAM.", name, stack, tcb);
        if (stack) heap_caps_free(stack);
        if (tcb)   heap_caps_free(tcb);
        // Fallback: internal DRAM (so as not to block the system)
        TaskHandle_t hfallback = NULL;
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &hfallback, 1);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Task %s creation failed even in DRAM.", name);
            return NULL;
        }
        return hfallback;
    }

    TaskHandle_t h = xTaskCreateStaticPinnedToCore(fn, name, stack_words, arg, prio, stack, tcb, 1);
    if (!h) {
        size_t free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        size_t largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
        LOG_ERRORF("TASK_ALLOC", "xTaskCreateStaticPinnedToCore failed for %s (stack=%p, tcb=%p, stack_bytes=%u) | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u) - trying DRAM fallback",
                   name, stack, tcb, (unsigned)stack_bytes, (unsigned)free_iram, (unsigned)largest_iram, (unsigned)free_psram, (unsigned)largest_psram);
        // cleanup
        heap_caps_free(stack);
        heap_caps_free(tcb);
        // Fallback: dynamic creation in DRAM
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &h, 1);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Task %s creation failed even in DRAM.", name);
            return NULL;
        }
        return h;
    }
    return h;
}
