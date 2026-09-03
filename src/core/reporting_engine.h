#pragma once
#include <string>
#include <utility>
#include <type_traits>
#include <new>
#include <map>
#include <memory>
#include <vector>
#include <cstdint>
#include <cstring>
#include <regex>
#include "event_formatter.h"
#include "psram_reliable_queue.h"
#include "psram_allocator.h"
#include "psram_json_parser.h"
extern "C" {
    #include "cJSON.h"
    #include "esp_system.h"
}
enum class VerbosityLevel {
    REPORTS_ONLY = 0,  // Only tool-generated events in chosen format
    VERBOSE = 1        // LOG_* messages + formatted reports with delimiters
};
class ReportingEngine {
public:
    struct ChannelConfig {
        EventFormat format = EventFormat::JSON;
        bool enabled = true;
        VerbosityLevel verbosity = VerbosityLevel::REPORTS_ONLY;
        // Regex filters for content filtering (PSRAM-based)
        psram_string_vector include_filters;  // Log passes if matches at least one include pattern
        psram_string_vector exclude_filters;  // Log rejected if matches any exclude pattern
        bool filters_enabled = false;         // Enable/disable regex filtering
        bool case_sensitive = false;          // Case sensitivity for regex matching
        // destination specifics (MQTT topic/url/etc) are abstracted by reporter
    };
    struct SenderFn {
        using Callback = bool(*)(void*, const psram_string&);
        using DestroyFn = void(*)(void*);
        using CloneFn = void*(*)(void*);
        void* ctx = nullptr;
        Callback fn = nullptr;
        DestroyFn destroy = nullptr;
        CloneFn clone = nullptr;
        SenderFn() = default;
        SenderFn(void* context, Callback cb, DestroyFn d, CloneFn c) : ctx(context), fn(cb), destroy(d), clone(c) {}
        SenderFn(const SenderFn& other) {
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = nullptr;
            if (other.ctx) {
                if (clone) {
                    ctx = clone(other.ctx);
                    if (!ctx) {
                        fn = nullptr;
                        destroy = nullptr;
                        clone = nullptr;
                    }
                } else {
                    ctx = other.ctx;
                }
            }
        }
        SenderFn& operator=(const SenderFn& other) {
            if (this == &other) {
                return *this;
            }
            reset();
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = nullptr;
            if (other.ctx) {
                if (clone) {
                    ctx = clone(other.ctx);
                    if (!ctx) {
                        fn = nullptr;
                        destroy = nullptr;
                        clone = nullptr;
                    }
                } else {
                    ctx = other.ctx;
                }
            }
            return *this;
        }
        SenderFn(SenderFn&& other) noexcept {
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = other.ctx;
            other.fn = nullptr;
            other.destroy = nullptr;
            other.clone = nullptr;
            other.ctx = nullptr;
        }
        SenderFn& operator=(SenderFn&& other) noexcept {
            if (this == &other) {
                return *this;
            }
            reset();
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = other.ctx;
            other.fn = nullptr;
            other.destroy = nullptr;
            other.clone = nullptr;
            other.ctx = nullptr;
            return *this;
        }
        ~SenderFn() {
            reset();
        }
        bool valid() const { return fn != nullptr; }
        explicit operator bool() const { return valid(); }
        bool operator()(const psram_string& payload) const { return fn ? fn(ctx, payload) : false; }
        void reset() {
            if (destroy && ctx) {
                destroy(ctx);
            }
            ctx = nullptr;
            fn = nullptr;
            destroy = nullptr;
            clone = nullptr;
        }
        static SenderFn fromCallback(Callback cb, void* context = nullptr) {
            return SenderFn(context, cb, nullptr, nullptr);
        }
        template<typename Callable>
        static SenderFn fromCallable(Callable&& callable) {
            using Functor = std::decay_t<Callable>;
            struct Wrapper {
                Functor fun;
            };
            using Alloc = PSRAMAllocator<Wrapper>;
            Alloc allocator;
            Wrapper* storage = allocator.allocate(1);
            if (!storage) {
                return SenderFn{};
            }
            new (storage) Wrapper{std::forward<Callable>(callable)};
            Callback cb = [](void* ctx, const psram_string& payload) -> bool {
                auto* wrapper = static_cast<Wrapper*>(ctx);
                return wrapper->fun(payload);
            };
            DestroyFn destroy_fn = [](void* ctx) {
                if (!ctx) return;
                auto* wrapper = static_cast<Wrapper*>(ctx);
                using AllocInner = PSRAMAllocator<Wrapper>;
                AllocInner inner_alloc;
                wrapper->~Wrapper();
                inner_alloc.deallocate(wrapper, 1);
            };
            CloneFn clone_fn = [](void* ctx) -> void* {
                if (!ctx) return nullptr;
                auto* wrapper = static_cast<Wrapper*>(ctx);
                using AllocInner = PSRAMAllocator<Wrapper>;
                AllocInner inner_alloc;
                Wrapper* copy = inner_alloc.allocate(1);
                if (!copy) {
                    return nullptr;
                }
                new (copy) Wrapper(*wrapper);
                return copy;
            };
            return SenderFn(storage, cb, destroy_fn, clone_fn);
        }
    };
    struct SenderRaw {
        using Callback = bool(*)(void*, const char*, size_t);
        using DestroyFn = void(*)(void*);
        using CloneFn = void*(*)(void*);
        void* ctx = nullptr;
        Callback fn = nullptr;
        DestroyFn destroy = nullptr;
        CloneFn clone = nullptr;
        SenderRaw() = default;
        SenderRaw(void* context, Callback cb, DestroyFn d, CloneFn c) : ctx(context), fn(cb), destroy(d), clone(c) {}
        SenderRaw(const SenderRaw& other) {
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = nullptr;
            if (other.ctx) {
                if (clone) {
                    ctx = clone(other.ctx);
                    if (!ctx) {
                        fn = nullptr;
                        destroy = nullptr;
                        clone = nullptr;
                    }
                } else {
                    ctx = other.ctx;
                }
            }
        }
        SenderRaw& operator=(const SenderRaw& other) {
            if (this == &other) {
                return *this;
            }
            reset();
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = nullptr;
            if (other.ctx) {
                if (clone) {
                    ctx = clone(other.ctx);
                    if (!ctx) {
                        fn = nullptr;
                        destroy = nullptr;
                        clone = nullptr;
                    }
                } else {
                    ctx = other.ctx;
                }
            }
            return *this;
        }
        SenderRaw(SenderRaw&& other) noexcept {
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = other.ctx;
            other.fn = nullptr;
            other.destroy = nullptr;
            other.clone = nullptr;
            other.ctx = nullptr;
        }
        SenderRaw& operator=(SenderRaw&& other) noexcept {
            if (this == &other) {
                return *this;
            }
            reset();
            fn = other.fn;
            destroy = other.destroy;
            clone = other.clone;
            ctx = other.ctx;
            other.fn = nullptr;
            other.destroy = nullptr;
            other.clone = nullptr;
            other.ctx = nullptr;
            return *this;
        }
        ~SenderRaw() {
            reset();
        }
        bool valid() const { return fn != nullptr; }
        explicit operator bool() const { return valid(); }
        bool operator()(const char* data, size_t len) const { return fn ? fn(ctx, data, len) : false; }
        void reset() {
            if (destroy && ctx) {
                destroy(ctx);
            }
            ctx = nullptr;
            fn = nullptr;
            destroy = nullptr;
            clone = nullptr;
        }
        static SenderRaw fromCallback(Callback cb, void* context = nullptr) {
            return SenderRaw(context, cb, nullptr, nullptr);
        }
        template<typename Callable>
        static SenderRaw fromCallable(Callable&& callable) {
            using Functor = std::decay_t<Callable>;
            struct Wrapper {
                Functor fun;
            };
            using Alloc = PSRAMAllocator<Wrapper>;
            Alloc allocator;
            Wrapper* storage = allocator.allocate(1);
            if (!storage) {
                return SenderRaw{};
            }
            new (storage) Wrapper{std::forward<Callable>(callable)};
            Callback cb = [](void* ctx, const char* data, size_t len) -> bool {
                auto* wrapper = static_cast<Wrapper*>(ctx);
                return wrapper->fun(data, len);
            };
            DestroyFn destroy_fn = [](void* ctx) {
                if (!ctx) return;
                auto* wrapper = static_cast<Wrapper*>(ctx);
                using AllocInner = PSRAMAllocator<Wrapper>;
                AllocInner inner_alloc;
                wrapper->~Wrapper();
                inner_alloc.deallocate(wrapper, 1);
            };
            CloneFn clone_fn = [](void* ctx) -> void* {
                if (!ctx) return nullptr;
                auto* wrapper = static_cast<Wrapper*>(ctx);
                using AllocInner = PSRAMAllocator<Wrapper>;
                AllocInner inner_alloc;
                Wrapper* copy = inner_alloc.allocate(1);
                if (!copy) {
                    return nullptr;
                }
                new (copy) Wrapper(*wrapper);
                return copy;
            };
            return SenderRaw(storage, cb, destroy_fn, clone_fn);
        }
    };
    ReportingEngine();
    ~ReportingEngine();
    bool initialize(class ConfigurationManager* cfg, class SecurityManager* security);
    void shutdown();
    bool isRunning() const { return worker_ != nullptr && queue_ != nullptr; }
    void setChannel(const psram_string& name, const ChannelConfig& cfg, SenderFn&& sender);
    template<typename Callable, typename = std::enable_if_t<!std::is_same_v<std::decay_t<Callable>, SenderFn>>>
    void setChannel(const psram_string& name, const ChannelConfig& cfg, Callable&& callable) {
        SenderFn sender = SenderFn::fromCallable(std::forward<Callable>(callable));
        setChannel(name, cfg, std::move(sender));
    }
    void setChannelRaw(const psram_string& name, const ChannelConfig& cfg, SenderRaw&& sender);
    template<typename Callable, typename = std::enable_if_t<!std::is_same_v<std::decay_t<Callable>, SenderRaw>>>
    void setChannelRaw(const psram_string& name, const ChannelConfig& cfg, Callable&& callable) {
        SenderRaw sender = SenderRaw::fromCallable(std::forward<Callable>(callable));
        setChannelRaw(name, cfg, std::move(sender));
    }
    void enableQueue(const PSRAMQueueConfig& qcfg, uint32_t flush_interval_ms = 3000);
    void reportSystemBootEvent(esp_reset_reason_t reset_reason);
    static void populateChannelFiltersFromJSON(cJSON* channel_json, ChannelConfig& cfg);
    // High level: build EventRecord and send to ALL active channels
    void reportEvent(const psram_string& type, const psram_string& raw_json);
    // Compatibility overloads
    void reportEvent(const char* type, const char* raw_json) {
        reportEvent(PSRAMUtils::createPSRAMString(type), PSRAMUtils::createPSRAMString(raw_json));
    }
    void reportEvent(const std::string& type, const std::string& raw_json) {
        reportEvent(PSRAMUtils::createPSRAMString(type.c_str()), PSRAMUtils::createPSRAMString(raw_json.c_str()));
    }
    void reportEvent(const char* type, const std::string& raw_json) {
        reportEvent(PSRAMUtils::createPSRAMString(type), PSRAMUtils::createPSRAMString(raw_json.c_str()));
    }
    // Legacy: build EventRecord and send to specific channel (for backward compatibility)
    void reportEventToChannel(const psram_string& channel, const psram_string& type, const psram_string& raw_json);
    // Advanced: build from EventRecord and send to ALL active channels
    void submit(const EventRecord& ev);
    // Advanced: build from EventRecord and send to specific channel
    void submitToChannel(const psram_string& channel, const EventRecord& ev);
    // CRITICAL: Direct submission methods to avoid EventRecord std::string allocations
    void submitDirect(const psram_string& channel_override, const psram_string& type, const psram_string& raw_json, uint64_t timestamp_ms);
    void submitDirectToChannel(const psram_string& channel, const psram_string& type, const psram_string& raw_json, uint64_t timestamp_ms);
    // Log message handling for VERBOSE channels
    void reportLogMessage(const psram_string& tag, const psram_string& level, const psram_string& message, uint64_t timestamp_ms);
    // Compatibility overloads
    void reportLogMessage(const std::string& tag, const std::string& level, const std::string& message, uint64_t timestamp_ms) {
        reportLogMessage(PSRAMUtils::createPSRAMString(tag.c_str()), PSRAMUtils::createPSRAMString(level.c_str()), PSRAMUtils::createPSRAMString(message.c_str()), timestamp_ms);
    }
    // Manual flush (REST)
    uint32_t flushNow();
    // Queue stats
    uint32_t queuedCount() const { return queue_ ? queue_->size() : 0; }
    bool getQueueStats(PSRAMQueueStats& out_stats) const;
public:
    psram_string getChannelsJSON() const;
    bool setChannelFormat(const psram_string& name, EventFormat fmt, bool enabled);
    bool setChannelVerbosity(const psram_string& name, VerbosityLevel verbosity);
    bool setChannelEnabled(const psram_string& name, bool enabled);
    // Regex filter management (PSRAM-based)
    bool setChannelFilters(const psram_string& name, const psram_string_vector& include_filters,
                          const psram_string_vector& exclude_filters, bool enabled, bool case_sensitive);
    bool addChannelIncludeFilter(const psram_string& name, const psram_string& pattern);
    bool addChannelExcludeFilter(const psram_string& name, const psram_string& pattern);
    bool removeChannelFilter(const psram_string& name, const psram_string& pattern, bool is_include);
    bool setChannelFiltersEnabled(const psram_string& name, bool enabled);
    psram_string getChannelFiltersJSON(const psram_string& name) const;
private:
    struct Chan {
        ChannelConfig cfg;
        SenderFn send;
        SenderRaw send_raw;
    };
    psram_map<psram_string, Chan> chans_;
    std::unique_ptr<PSRAMReliableQueue> queue_;
    uint32_t flush_interval_ms_ = 3000;
    TaskHandle_t worker_ = nullptr;
    static void workerThunk(void* arg);
    void workerLoop();
    bool trySend(const psram_string& ch, const psram_string& payload);
    QueueDeliveryResult tryDeliverQueuedEvent(const QueuedEvent& event);
    psram_string formatEventDirect(const psram_string& channel,
                                   const psram_string& type,
                                   const psram_string& raw_json,
                                   uint64_t timestamp_ms,
                                   EventFormat format);
    // Regex filtering helper methods
    bool shouldSendToChannel(const ChannelConfig& cfg, const psram_string& content) const;
    bool matchesRegexPattern(const psram_string& content, const psram_string& pattern, bool case_sensitive) const;
};
// Global reporting engine pointer for web interface access
extern ReportingEngine* g_reporting;
// Register only the Email reporter from configuration (for WiFi-on-connect activation)
