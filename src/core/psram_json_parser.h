#pragma once

#include <esp_heap_caps.h>
#include <cstring>
#include "cJSON.h"
#include "logging_system.h"

class PSRAMJsonParser {
private:
    static const char* TAG;

    // cJSON memory hooks for PSRAM allocation
    static void* psram_malloc(size_t size) {
        // PSRAM-only allocator for cJSON. No DRAM fallback to avoid fragmentation/crash.
        void* ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!ptr) {
            LOG_ERRORF(TAG, "cJSON PSRAM allocation failed for %u bytes (NO DRAM FALLBACK)", (unsigned)size);
        }
        return ptr;
    }

    static void psram_free(void* ptr) {
        if (ptr) {
            heap_caps_free(ptr);
        }
    }

    static bool hooks_initialized_;

public:
    // Initialize PSRAM hooks for cJSON - call before any JSON parsing
    static bool initializePSRAMHooks() {
        if (hooks_initialized_) return true;
        // Log memory state before installing hooks
        //size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        //size_t free_dram  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        //LOG_INFOF(TAG, "InitHooks: PSRAM free=%u, DRAM free=%u", (unsigned)free_psram, (unsigned)free_dram);

        // Set PSRAM hooks
        cJSON_Hooks psram_hooks;
        psram_hooks.malloc_fn = psram_malloc;
        psram_hooks.free_fn = psram_free;

        cJSON_InitHooks(&psram_hooks);
        hooks_initialized_ = true;

        //LOG_INFO(TAG, "PSRAM JSON hooks initialized (PSRAM-only)");
        return true;
    }

    // Restore original hooks (NULL hooks = default malloc/free)
    static void restoreOriginalHooks() {
        if (!hooks_initialized_) return;

        // Reset to default hooks (NULL = use malloc/free)
        cJSON_InitHooks(NULL);
        hooks_initialized_ = false;

        //LOG_INFO(TAG, "Original JSON hooks restored");
    }

    // Parse JSON using PSRAM allocation
    static cJSON* parseInPSRAM(const char* json_string) {
        if (!json_string) return nullptr;

        // Ensure PSRAM hooks are active
        if (!hooks_initialized_) {
            if (!initializePSRAMHooks()) return nullptr;
        }

        size_t json_len = strlen(json_string);
        //size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        //size_t free_dram  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);

        //LOG_INFOF(TAG, "Parsing JSON (%u bytes) - PSRAM free: %u, DRAM free: %u", (unsigned)json_len, (unsigned)free_psram, (unsigned)free_dram);

        // Prefer length-bounded parsing when available
        cJSON* root = cJSON_ParseWithLength(json_string, json_len);
        if (!root) {
            LOG_ERROR(TAG, "Failed to parse JSON in PSRAM");
            return nullptr;
        }

        //LOG_INFO(TAG, "JSON parsed successfully in PSRAM");
        return root;
    }

    // Explicit length-bounded variant for callers that know the size
    static cJSON* parseInPSRAM(const char* json_string, size_t json_len) {
        if (!json_string) return nullptr;

        if (!hooks_initialized_) {
            if (!initializePSRAMHooks()) return nullptr;
        }

        //size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        //size_t free_dram  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        //LOG_INFOF(TAG, "Parsing JSON (len=%u) - PSRAM free: %u, DRAM free: %u", (unsigned)json_len, (unsigned)free_psram, (unsigned)free_dram);

        cJSON* root = cJSON_ParseWithLength(json_string, json_len);
        if (!root) {
            LOG_ERROR(TAG, "Failed to parse JSON in PSRAM (len variant)");
            return nullptr;
        }
        //LOG_INFO(TAG, "JSON parsed successfully in PSRAM (len variant)");
        return root;
    }

    // RAII wrapper for automatic hook management
    class PSRAMContext {
    private:
        bool initialized_here_;

    public:
        PSRAMContext() : initialized_here_(false) {
            if (!hooks_initialized_) {
                initialized_here_ = initializePSRAMHooks();
            }
        }

        ~PSRAMContext() {
            if (initialized_here_) {
                restoreOriginalHooks();
            }
        }

        bool isValid() const { return hooks_initialized_; }
    };
};

namespace PSRAMJson {
    inline void ensureHooks() {
        PSRAMJsonParser::initializePSRAMHooks();
    }
}
