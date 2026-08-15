#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_psram.h"
#include "logging_macros_c.h"

static inline const char* mem_where(const void* p){
    if (!p) return "unknown";
    if (esp_ptr_external_ram(p)) return "PSRAM";
    if (esp_ptr_in_dram(p)) return "INTERNAL";
    return "unknown";
}

void task_audit_print_csv(void)
{
#if (configUSE_TRACE_FACILITY == 1)
    printf("TaskName,Priority,Affinity,StackMinFreeB,StackLocation,Handle\n");

    UBaseType_t num = uxTaskGetNumberOfTasks();
    TaskStatus_t *arr = (TaskStatus_t*) malloc(num * sizeof(TaskStatus_t));
    if(!arr){ LOG_ERROR("TASK_AUDIT","No mem for TaskStatus"); return; }

    UBaseType_t n = uxTaskGetSystemState(arr, num, NULL);
    for(UBaseType_t i=0;i<n;i++){
        TaskStatus_t *ts = &arr[i];

        TaskStatus_t ti;
        vTaskGetInfo(ts->xHandle, &ti, pdTRUE, eInvalid);
        size_t min_free = ti.usStackHighWaterMark * sizeof(StackType_t);
        void *stack_base = (void*) ts->pxStackBase;

        #if ( configNUM_CORES > 1 )
        BaseType_t core_id = xTaskGetCoreID(ts->xHandle);
        const char *affs = (core_id == tskNO_AFFINITY) ? "ANY" : (core_id==0 ? "CORE0" : (core_id==1 ? "CORE1" : "UNKNOWN"));
        #else
        const char *affs = "CORE0";
        #endif

        printf("%s,%u,%s,%u,%s,%p\n",
            ts->pcTaskName ? ts->pcTaskName : "-",
            (unsigned)ts->uxCurrentPriority,
            affs,
            (unsigned)min_free,
            mem_where(stack_base),
            ts->xHandle
        );
    }
    free(arr);
#else
    printf("Task audit requires configUSE_TRACE_FACILITY=1 in FreeRTOS config\n");
#endif

    #if (configGENERATE_RUN_TIME_STATS == 1)
    // Use PSRAM for larger buffer - more reliable and prevents DRAM fragmentation
    char* buf = NULL;
    size_t buf_size = 0;

    buf = (char*)heap_caps_malloc(8192, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (buf) {
        buf_size = 8192;
    } else {
        // Fallback to smaller DRAM buffer if PSRAM fails
        buf = (char*)heap_caps_malloc(2048, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        if (buf) {
            buf_size = 2048;
        }
    }

    if (buf && buf_size >= 1024) {
        extern void vTaskGetRunTimeStats(char *pcWriteBuffer);

        // Clear buffer to prevent garbage data - use known size instead of heap_caps_get_allocated_size
        memset(buf, 0, buf_size);

        vTaskGetRunTimeStats(buf);
        puts("\n# vTaskGetRunTimeStats()");
        puts(buf);

        heap_caps_free(buf);
    } else {
        if (buf) heap_caps_free(buf);
        printf("\n# vTaskGetRunTimeStats() - Memory allocation failed (8KB PSRAM + 2KB DRAM fallback)\n");
    }
    #endif
}

void task_audit_run(void){
    LOG_INFO("TASK_AUDIT","--- TASK AUDIT CSV ---");
    heap_caps_print_heap_info(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    task_audit_print_csv();
}
