// Thin C proxies to call C++ TaskConfig emergency helpers from C modules
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Declarations of C++ functions
bool TaskConfig_emergencyMemoryCleanup_impl(void);
void TaskConfig_forceHeapDefragmentation_impl(void);

// C-callable proxies
bool TaskConfig_emergencyMemoryCleanup_proxy(void) {
    return TaskConfig_emergencyMemoryCleanup_impl();
}

void TaskConfig_forceHeapDefragmentation_proxy(void) {
    TaskConfig_forceHeapDefragmentation_impl();
}

#ifdef __cplusplus
}
#endif
