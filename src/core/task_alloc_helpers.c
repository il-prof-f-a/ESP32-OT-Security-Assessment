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
    // Stack in PSRAM, TCB in DRAM interna
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
            LOG_ERRORF("TASK_ALLOC", "Alloc STACK PSRAM fallita per %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)stack_bytes,
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }
        if (!tcb) {
            LOG_ERRORF("TASK_ALLOC", "Alloc TCB DRAM fallita per %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)sizeof(StaticTask_t),
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }

        // Tentativo di emergenza: prova cleanup/defrag e nuovo tentativo TCB
        if (!tcb) {
            extern bool TaskConfig_emergencyMemoryCleanup_proxy();
            extern void TaskConfig_forceHeapDefragmentation_proxy();
            TaskConfig_emergencyMemoryCleanup_proxy();
            TaskConfig_forceHeapDefragmentation_proxy();
            tcb = (StaticTask_t*) heap_caps_malloc(sizeof(StaticTask_t),
                                                  MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
        }

        if (stack && tcb) {
            // Se dopo il cleanup abbiamo entrambe le allocazioni, creiamo il task e ritorniamo
            TaskHandle_t htmp = xTaskCreateStaticPinnedToCore(fn, name, stack_words, arg, prio, stack, tcb, 0);
            if (htmp) {
                return htmp;
            }
        }

        LOG_ERROR("TASK_ALLOC", "Alloc fallita per %s (stack=%p, tcb=%p). Riprovo in DRAM interna.", name, stack, tcb);
        if (stack) heap_caps_free(stack);
        if (tcb)   heap_caps_free(tcb);
        // Fallback: DRAM interna (per non bloccare il sistema)
        TaskHandle_t hfallback = NULL;
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &hfallback, 0);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Creazione task %s fallita anche in DRAM.", name);
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
        LOG_ERRORF("TASK_ALLOC", "xTaskCreateStaticPinnedToCore fallita per %s (stack=%p, tcb=%p, stack_bytes=%u) | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u) - provo fallback DRAM",
                   name, stack, tcb, (unsigned)stack_bytes, (unsigned)free_iram, (unsigned)largest_iram, (unsigned)free_psram, (unsigned)largest_psram);
        // pulizia
        heap_caps_free(stack);
        heap_caps_free(tcb);
        // Fallback: creazione dinamica in DRAM
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &h, 0);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Creazione task %s fallita anche in DRAM.", name);
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
    // Stack in PSRAM, TCB in DRAM interna
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
            LOG_ERRORF("TASK_ALLOC", "Alloc STACK PSRAM fallita per %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)stack_bytes,
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }
        if (!tcb) {
            LOG_ERRORF("TASK_ALLOC", "Alloc TCB DRAM fallita per %s (bytes=%u) | DRAM int=%u (largest=%u) DRAM int 8bit=%u (largest=%u) PSRAM=%u (largest=%u)",
                       name, (unsigned)sizeof(StaticTask_t),
                       (unsigned)free_iram, (unsigned)largest_iram,
                       (unsigned)free_int8, (unsigned)largest_int8,
                       (unsigned)free_psram, (unsigned)largest_psram);
        }

        // Tentativo di emergenza: prova cleanup/defrag e nuovo tentativo TCB
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

        LOG_ERROR("TASK_ALLOC", "Alloc fallita per %s (stack=%p, tcb=%p). Riprovo in DRAM interna.", name, stack, tcb);
        if (stack) heap_caps_free(stack);
        if (tcb)   heap_caps_free(tcb);
        // Fallback: DRAM interna (per non bloccare il sistema)
        TaskHandle_t hfallback = NULL;
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &hfallback, 1);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Creazione task %s fallita anche in DRAM.", name);
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
        LOG_ERRORF("TASK_ALLOC", "xTaskCreateStaticPinnedToCore fallita per %s (stack=%p, tcb=%p, stack_bytes=%u) | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u) - provo fallback DRAM",
                   name, stack, tcb, (unsigned)stack_bytes, (unsigned)free_iram, (unsigned)largest_iram, (unsigned)free_psram, (unsigned)largest_psram);
        // pulizia
        heap_caps_free(stack);
        heap_caps_free(tcb);
        // Fallback: creazione dinamica in DRAM
        BaseType_t ok = xTaskCreatePinnedToCore(fn, name, stack_words, arg, prio, &h, 1);
        if (ok != pdPASS) {
            LOG_ERROR("TASK_ALLOC", "Creazione task %s fallita anche in DRAM.", name);
            return NULL;
        }
        return h;
    }
    return h;
}
