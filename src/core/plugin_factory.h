#pragma once

#include <memory>
extern "C" {
    #include "esp_heap_caps.h"
}

class BasePlugin;

// Custom deleter for PSRAM-allocated plugins
template<typename T>
struct PSRAMDeleter {
    void operator()(BasePlugin* ptr) const {
        if (ptr) {
            static_cast<T*>(ptr)->~T();
            heap_caps_free(ptr);
        }
    }
};

template<typename T, typename... Args>
std::unique_ptr<BasePlugin> createPluginInPSRAM(Args&&... args) {
    static_assert(std::is_base_of<BasePlugin, T>::value, "T must inherit from BasePlugin");

    // For now, use regular allocation to fix compilation
    // TODO: Optimize with PSRAM allocation in a future iteration
    return std::make_unique<T>(std::forward<Args>(args)...);
}