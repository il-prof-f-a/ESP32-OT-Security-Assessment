// C++ side implementations mapped to TaskConfig helpers
#include "task_config.h"

extern "C" bool TaskConfig_emergencyMemoryCleanup_impl(void) {
    return TaskConfig::emergencyMemoryCleanup();
}

extern "C" void TaskConfig_forceHeapDefragmentation_impl(void) {
    TaskConfig::forceHeapDefragmentation();
}
