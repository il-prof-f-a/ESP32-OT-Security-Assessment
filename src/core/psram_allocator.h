#pragma once

#include <memory>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <limits>
#include <cstddef>
#include <cstring>
extern "C" {
    #include "esp_heap_caps.h"
    #include "esp_memory_utils.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "cJSON.h"
}
#include "logging_system.h"

// NOTE: task_config.h is included AFTER type definitions below to avoid circular dependency

// Emergency micro-pool definition placed before allocator to avoid incomplete type issues
namespace PSRAMUtils {
    struct EmergencyPool {
        static constexpr size_t kCapacity = 4096;    // 4 KB total
        static constexpr size_t kMaxAlloc = 256;     // max allocation allowed
        static inline uint8_t  buf[kCapacity];
        static inline size_t   off = 0;
        static inline portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

        static void* alloc(size_t nbytes);
        static bool owns(const void* p);
    };

    void logMemoryStatus(const char* context);
    void emergencyCleanup(const char* caller = "Unknown");

    // Prefer external RAM on boards that provide it, but keep core services
    // usable on profiles without CONFIG_SPIRAM.  heap_caps_malloc() requires
    // all requested capabilities and therefore cannot express this fallback.
    inline void* allocatePreferred(size_t bytes,
                                   uint32_t preferred_caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                   uint32_t fallback_caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) {
        if (bytes == 0) return nullptr;
        void* ptr = heap_caps_malloc(bytes, preferred_caps);
        if (!ptr && (preferred_caps & MALLOC_CAP_SPIRAM)) {
            ptr = heap_caps_malloc(bytes, fallback_caps);
        }
        return ptr;
    }
}

// PSRAM allocator for STL containers to reduce Internal RAM usage
// Automatically falls back to DRAM if PSRAM allocation fails
template<typename T>
class PSRAMAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    template<typename U>
    struct rebind {
        using other = PSRAMAllocator<U>;
    };

    PSRAMAllocator() = default;

    template<typename U>
    PSRAMAllocator(const PSRAMAllocator<U>&) noexcept {}

    T* allocate(size_type n) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
            LOG_ERRORF("PSRAMAllocator", "Invalid allocation size: %u elements", (unsigned)n);
            abort();
        }

        const size_type bytes = n * sizeof(T);

        void* ptr = PSRAMUtils::allocatePreferred(bytes);
        if (!ptr) {
            LOG_ERRORF("PSRAMAllocator", "External/internal allocation failed for %u bytes", (unsigned)bytes);
            PSRAMUtils::logMemoryStatus("PSRAMAllocator::allocate");
            PSRAMUtils::emergencyCleanup("PSRAMAllocator::allocate");
            ptr = PSRAMUtils::allocatePreferred(bytes);
            if (!ptr) {
                LOG_ERRORF("PSRAMAllocator", "Unable to allocate %u bytes after cleanup", (unsigned)bytes);
                abort();
            }
        }

        return static_cast<T*>(ptr);
    }
void deallocate(T* ptr, size_type n) noexcept {
        if (!ptr) return;

        // If the pointer comes from the emergency micro-pool, do not free it
        if (PSRAMUtils::EmergencyPool::owns(ptr)) return;

        // Free memory using ESP-IDF heap capabilities (handles PSRAM/internal regions)
        heap_caps_free(ptr);

        #ifdef DEBUG_PSRAM_ALLOC
        LOG_DEBUGF("PSRAMAllocator", "Freed %u bytes from PSRAM at %p",
                  (unsigned)(n * sizeof(T)), (void*)ptr);
        #endif
    }

    template<typename U>
    bool operator==(const PSRAMAllocator<U>&) const noexcept { return true; }

    template<typename U>
    bool operator!=(const PSRAMAllocator<U>&) const noexcept { return false; }

private:
    static void logMemoryStatus(const char* context) {
        size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

        unsigned frag_pct = 0;
        if (free_internal > 0) {
            size_t used_vs_largest = (free_internal > largest_block) ? (free_internal - largest_block) : 0;
            frag_pct = (unsigned)((used_vs_largest * 100U) / free_internal);
        }
        LOG_INFOF("PSRAMAllocator", "💾 %s - PSRAM: %u KB, DRAM: %u bytes, Largest: %u bytes, Frag: %u%%",
                 context, (unsigned)(free_psram/1024), (unsigned)free_internal,
                 (unsigned)largest_block, (unsigned)frag_pct);
    }
};

// Type aliases for commonly used PSRAM containers
template<typename T>
using psram_vector = std::vector<T, PSRAMAllocator<T>>;

template<typename K, typename V>
using psram_map = std::map<K, V, std::less<K>, PSRAMAllocator<std::pair<const K, V>>>;

template<typename T>
using psram_set = std::set<T, std::less<T>, PSRAMAllocator<T>>;

using psram_string = std::basic_string<char, std::char_traits<char>, PSRAMAllocator<char>>;
using psram_string_map = psram_map<psram_string, psram_string>;
using psram_string_vector = psram_vector<psram_string>;
using psram_string_set = psram_set<psram_string>;

// Include task_config.h AFTER psram type definitions to avoid circular dependency
#include "task_config.h"

// Task-specific PSRAM data structures
namespace TaskData {

    // Import psram_vector into TaskData namespace for compatibility
    template<typename T>
    using psram_vector = ::psram_vector<T>;

    // Network packet buffer for task communication (in PSRAM to reduce DRAM pressure)
    template<typename PacketType>
    using packet_buffer = psram_vector<PacketType>;

    // Log message queue for async processing (in PSRAM)
    using log_message_queue = psram_vector<psram_string>;

    // Event report queue for async processing (in PSRAM)
    struct EventReport {
        psram_string event_type;
        psram_string event_data;
        uint32_t timestamp;
        uint32_t priority;
    };
    using event_report_queue = psram_vector<EventReport>;

    // Analysis results for security tasks (in PSRAM)
    struct AnalysisResult {
        psram_string source_ip;
        psram_string target_ip;
        uint16_t port;
        psram_string protocol;
        psram_string verdict;
        psram_string details;
        uint32_t timestamp;
    };
    using analysis_results = psram_vector<AnalysisResult>;

    // Vulnerability scan results (in PSRAM)
    struct VulnResult {
        psram_string target;
        psram_string vulnerability_type;
        psram_string severity;
        psram_string description;
        uint32_t timestamp;
    };
    using vuln_results = psram_vector<VulnResult>;

    // Fuzzing test cases and results (in PSRAM)
    struct FuzzTestCase {
        psram_string protocol;
        psram_string payload;
        psram_string expected_response;
        uint32_t test_id;
    };
    using fuzz_test_cases = psram_vector<FuzzTestCase>;

    struct FuzzResult {
        uint32_t test_id;
        psram_string actual_response;
        psram_string verdict;
        uint32_t response_time_us;
        uint32_t timestamp;
    };
    using fuzz_results = psram_vector<FuzzResult>;

    // Network presence tracking data (in PSRAM)
    struct DeviceInfo {
        psram_string ip_address;
        psram_string mac_address;
        psram_string device_type;
        psram_string last_seen;
        uint32_t confidence_score;
        uint32_t packet_count;
    };
    using device_registry = psram_vector<DeviceInfo>;

    // Protocol statistics for monitoring (in PSRAM)
    struct ProtocolStats {
        psram_string protocol_name;
        uint32_t packet_count;
        uint32_t error_count;
        uint32_t bytes_processed;
        uint32_t last_activity;
    };
    using protocol_statistics = psram_vector<ProtocolStats>;
}

// Helper macros for task memory allocation
#define PSRAM_ALLOCATE(type, count) \
    static_cast<type*>(heap_caps_malloc((count) * sizeof(type), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT))

#define PSRAM_ALLOCATE_FALLBACK(type, count) \
    [](size_t n) -> type* { \
        void* ptr = heap_caps_malloc(n * sizeof(type), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT); \
        if (!ptr) { \
            ptr = heap_caps_malloc(n * sizeof(type), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT); \
        } \
        return static_cast<type*>(ptr); \
    }(count)

#define PSRAM_FREE(ptr) heap_caps_free(ptr)

// Utility functions for memory management and monitoring
namespace PSRAMUtils {

    inline psram_string concat(const psram_string& a, const psram_string& b) {
        psram_string out;
        out.reserve(a.size() + b.size());
        out.append(a);
        out.append(b);
        return out;
    }

    // Check if we're in a critical memory situation
    inline bool isCriticalMemory() {
        size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        return free_internal < 15000;  // Less than 15KB is critical
    }

    // Convert std::string to psram_string safely (no exceptions in ESP-IDF)
    inline psram_string toPSRAMString(const std::string& str) {
        // Check memory before attempting conversion
        if (isCriticalMemory()) {
            LOG_ERROR("PSRAMUtils", "â Cannot convert std::string to psram_string - critical memory");
            return psram_string{};
        }
        return psram_string(str.begin(), str.end());
    }

    // Convert psram_string to std::string safely
    inline std::string fromPSRAMString(const psram_string& pstr) {
        // EMERGENCY: Skip conversion if memory is critically low
        size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t needed_memory = pstr.size() + 32; // String size + overhead

        if (free_heap < (needed_memory + 5000)) { // Need buffer for safety
            // Not enough memory - return empty string to avoid crash
            return std::string{};
        }

        // Check if we can get a large enough contiguous block
        size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        if (largest_block < needed_memory) {
            // Fragmentation too high - return empty string
            return std::string{};
        }

        // Safe to allocate
        return std::string(pstr.begin(), pstr.end());
    }
    // Create a PSRAM string directly from C string
    inline psram_string createPSRAMString(const char* data, size_t length) {
        if (!data || length == 0) {
            return psram_string{};
        }
        if (isCriticalMemory()) {
            LOG_ERRORF("PSRAMUtils", "Cannot create psram_string (%u bytes) - critical memory", (unsigned)length);
            return psram_string{};
        }
        return psram_string(data, data + length);
    }

    inline psram_string createPSRAMString(const char* cstr) {
        if (!cstr) {
            return psram_string{};
        }
        return createPSRAMString(cstr, std::strlen(cstr));
    }


    // Get current memory status for debugging
    inline void logMemoryStatus(const char* context) {
        size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

        unsigned frag_pct2 = 0;
        if (free_internal > 0) {
            size_t used_vs_largest2 = (free_internal > largest_block) ? (free_internal - largest_block) : 0;
            frag_pct2 = (unsigned)((used_vs_largest2 * 100U) / free_internal);
        }
        LOG_INFOF("PSRAMUtils", "💾 %s - PSRAM: %u KB, DRAM: %u bytes, Largest: %u bytes, Frag: %u%%",
                 context, (unsigned)(free_psram/1024), (unsigned)free_internal,
                 (unsigned)largest_block, (unsigned)frag_pct2);

        if (free_internal < 10000) {  // Less than 10KB DRAM
            LOG_WARNING("PSRAMUtils", "💾 CRITICAL: DRAM below 10KB threshold!");
        } else if (free_internal < 30000) {  // Less than 50KB DRAM
            LOG_WARNING("PSRAMUtils", "💾  WARNING: DRAM below 30KB threshold");
        }
    }

    // Emergency memory cleanup - force garbage collection
    inline void emergencyCleanup(const char* caller ) {
        LOG_WARNINGF("PSRAMUtils", "💾 Emergency memory cleanup triggered by %s", caller);

        // Log current state
        logMemoryStatus("Before Emergency Cleanup");

        // Force heap info dump for debugging
        heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);

        // Brief delay to allow system cleanup
        vTaskDelay(pdMS_TO_TICKS(50));

        logMemoryStatus("After Emergency Cleanup");
    }

    // Emergency micro-pool for small allocations declared above

    // Force allocation in PSRAM (for critical systems with low DRAM)
    template<typename T>
    inline T* allocatePSRAMOnly(size_t count) {
        void* ptr = heap_caps_malloc(count * sizeof(T), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!ptr) {
            LOG_ERRORF("PSRAMUtils", "â PSRAM-only allocation failed for %u bytes", (unsigned)(count * sizeof(T)));
            return nullptr;
        }
        return static_cast<T*>(ptr);
    }

    class ScopedBuffer {
    public:
        explicit ScopedBuffer(size_t size_bytes,
                              uint32_t caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
            : size_(size_bytes), caps_(caps), ptr_(nullptr) {
            if (size_ == 0) {
                return;
            }
            ptr_ = static_cast<char*>(heap_caps_malloc(size_, caps_));
            if (!ptr_ && (caps_ & MALLOC_CAP_SPIRAM)) {
                ptr_ = static_cast<char*>(heap_caps_malloc(
                    size_, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
            }
            if (ptr_) {
                ptr_[0] = '\0';
            }
        }

        ~ScopedBuffer() {
            if (ptr_) {
                heap_caps_free(ptr_);
            }
        }

        char* get() const { return ptr_; }
        size_t size() const { return size_; }
        bool valid() const { return ptr_ != nullptr; }

    private:
        size_t size_;
        uint32_t caps_;
        char* ptr_;
    };

    struct PSRAMStringView {
        const char* data;
        size_t length;

        PSRAMStringView() : data(nullptr), length(0) {}
        PSRAMStringView(const char* cstr, size_t len) : data(cstr), length(len) {}

        static PSRAMStringView fromPSRAMString(const psram_string& str) {
            return PSRAMStringView(str.data(), str.size());
        }
    };

    inline bool copyToStackBuffer(char* dest, size_t dest_len, const psram_string& src) {
        if (!dest || dest_len == 0) {
            return false;
        }
        size_t to_copy = src.size();
        if (to_copy >= dest_len) {
            to_copy = dest_len - 1;
        }
        if (to_copy > 0) {
            memcpy(dest, src.data(), to_copy);
        }
        dest[to_copy] = '\0';
        return true;
    }

    class InternalCopyGuard {
    public:
        InternalCopyGuard(const void* src, size_t len,
                          uint32_t caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT,
                          bool force_copy = false)
            : src_ptr_(src),
              size_(len),
              caps_(caps),
              owned_copy_(false),
              copy_ptr_(nullptr) {
            if (!src_ptr_ || size_ == 0) {
                return;
            }
        if (!force_copy && esp_ptr_internal(src_ptr_)) {
            copy_ptr_ = const_cast<void*>(src_ptr_);
            return;
        }

        copy_ptr_ = heap_caps_malloc(size_, caps_);
        if (!copy_ptr_) {
            constexpr size_t DEFRAG_THRESHOLD = 256;
            bool defrag_attempted = false;

            if (!force_copy && size_ >= DEFRAG_THRESHOLD) {
                size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
                if (largest_block < size_) {
                    defrag_attempted = true;
                    // TaskConfig::forceHeapDefragmentation(); // Temporarily disabled to avoid circular dependency
                    copy_ptr_ = heap_caps_malloc(size_, caps_);
                }
            }

            if (!copy_ptr_ && !defrag_attempted && !force_copy && size_ >= (DEFRAG_THRESHOLD / 2)) {
                // TaskConfig::forceHeapDefragmentation(); // Temporarily disabled to avoid circular dependency
                copy_ptr_ = heap_caps_malloc(size_, caps_);
                defrag_attempted = true;
            }

            if (!copy_ptr_) {
                //LOG_DEBUGF("PSRAMUtils", "InternalCopyGuard failed for %u bytes (defrag=%d)", (unsigned)size_, defrag_attempted ? 1 : 0);
                return;
            }
        }
            memcpy(copy_ptr_, src_ptr_, size_);
            owned_copy_ = true;
        }

        ~InternalCopyGuard() {
            if (owned_copy_ && copy_ptr_) {
                heap_caps_free(copy_ptr_);
            }
        }

        void* data() { return copy_ptr_; }
        const void* data() const { return copy_ptr_; }
        size_t size() const { return size_; }
        bool available() const { return copy_ptr_ != nullptr; }
        bool ownsCopy() const { return owned_copy_; }

    private:
        const void* src_ptr_;
        size_t size_;
        uint32_t caps_;
        bool owned_copy_;
        void* copy_ptr_;
    };

    namespace detail {
        inline void* cjson_psram_malloc(size_t size) {
            void* ptr = allocatePreferred(size);
            if (!ptr) {
                LOG_DEBUGF("PSRAMUtils", "cJSON PSRAM malloc failed for %u bytes", (unsigned)size);
            }
            return ptr;
        }

        inline void cjson_psram_free(void* ptr) {
            if (ptr) {
                heap_caps_free(ptr);
            }
        }
    } // namespace detail

    inline void initializeCJSONHooks() {
        static bool initialized = false;
        if (initialized) {
            return;
        }

        cJSON_Hooks hooks;
        hooks.malloc_fn = detail::cjson_psram_malloc;
        hooks.free_fn = detail::cjson_psram_free;
        cJSON_InitHooks(&hooks);

        initialized = true;
        LOG_INFO("PSRAMUtils", "cJSON hooks initialized to use PSRAM");
    }
}

// Inline definitions for EmergencyPool methods
inline void* PSRAMUtils::EmergencyPool::alloc(size_t nbytes) {
    if (nbytes == 0 || nbytes > kMaxAlloc) return nullptr;
    void* out = nullptr;
    taskENTER_CRITICAL(&mux);
    size_t aligned = (nbytes + 7) & ~size_t(7);
    if (off + aligned <= kCapacity) {
        out = buf + off;
        off += aligned;
    }
    taskEXIT_CRITICAL(&mux);
    if (out) {
        LOG_WARNINGF("PSRAMAllocator", "EmergencyPool used: %u bytes (used=%u/%u)",
                     (unsigned)nbytes, (unsigned)off, (unsigned)kCapacity);
    }
    return out;
}

inline bool PSRAMUtils::EmergencyPool::owns(const void* p) {
    const uint8_t* up = static_cast<const uint8_t*>(p);
    const uint8_t* b  = buf;
    return (up >= b) && (up < b + kCapacity);
}


// Safe JSON string operations using PSRAM
namespace PSRAMJson {

    // Create JSON string safely in PSRAM
    inline psram_string createJsonString(const char* json_cstr) {
        if (!json_cstr) {
            return PSRAMUtils::createPSRAMString("{}");
        }

        // Check if we're in critical memory before large string operations
        if (PSRAMUtils::isCriticalMemory()) {
            PSRAMUtils::emergencyCleanup("PSRAMJson::createJsonString");
        }

        return PSRAMUtils::createPSRAMString(json_cstr);
    }

    // Convert JSON to std::string only when absolutely necessary
    inline std::string extractJsonString(const psram_string& json_pstr) {
        if (PSRAMUtils::isCriticalMemory()) {
            LOG_WARNING("PSRAMJson", "â ï¸  Extracting JSON during critical memory situation");
        }

        return PSRAMUtils::fromPSRAMString(json_pstr);
    }

}
