#include "reporting_engine.h"
#include "task_alloc_helpers.h"
#include "task_config.h"
#include "psram_allocator.h"
#include "psram_json_parser.h"
#include "filesystem_task_delegate.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <utility>
extern "C" {
  #include "esp_psram.h"
  #include "esp_system.h"
  #include "esp_log.h"
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "esp_timer.h"
  #include "esp_heap_caps.h"
  #include "esp_rom_sys.h"
  #include <time.h>
  #include <sys/time.h>
}
// NOTE: <sstream> and <iomanip> removed - all formatting now uses PSRAM-safe snprintf

static inline void dump_heap_stage(const char* stage, const psram_string& type) {
    (void)stage;
    (void)type;
}

static inline void dump_heap_stage_channel(const char* stage, const psram_string& type, const psram_string& channel) {
    (void)stage;
    (void)type;
    (void)channel;
}

static inline void serial_mem_probe(const char* stage) {
    (void)stage;
}

struct IRAMTraceSnapshot {
    size_t free_before;
    size_t min_before;
};

static inline IRAMTraceSnapshot iram_trace_capture() {
    IRAMTraceSnapshot snap;
    snap.free_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    snap.min_before = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    return snap;
}

static inline void iram_trace_report(const char* label, const IRAMTraceSnapshot& before) {
    (void)label;
    (void)before;
}
static void append_json_escaped(const psram_string& src, psram_string& out) {
    for (unsigned char uc : src) {
        switch (uc) {
            case '\\':
                out += "\\\\";
                break;
            case '\"':
                out += "\\\"";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (uc < 0x20) {
                    static const char hex[] = "0123456789abcdef";
                    char buf[6];
                    buf[0] = '\\';
                    buf[1] = 'u';
                    buf[2] = '0';
                    buf[3] = '0';
                    buf[4] = hex[(uc >> 4) & 0x0F];
                    buf[5] = hex[uc & 0x0F];
                    out.append(buf, buf + sizeof(buf));
                } else {
                    out.push_back(static_cast<char>(uc));
                }
                break;
        }
    }
}

static void append_int_to_psram(psram_string& out, int value) {
    char buf[16];
    int len = snprintf(buf, sizeof(buf), "%d", value);
    if (len > 0) {
        if (len >= static_cast<int>(sizeof(buf))) {
            len = static_cast<int>(sizeof(buf)) - 1;
        }
        out.append(buf, buf + len);
    }
}

namespace {
const char* resetReasonToString(esp_reset_reason_t reason) {
    switch (reason) {
        case ESP_RST_POWERON:   return "POWER_ON";
        case ESP_RST_EXT:       return "EXTERNAL_PIN";
        case ESP_RST_SW:        return "SOFTWARE_RESTART";
        case ESP_RST_PANIC:     return "PANIC_CRASH";
        case ESP_RST_INT_WDT:   return "INTERRUPT_WATCHDOG";
        case ESP_RST_TASK_WDT:  return "TASK_WATCHDOG";
        case ESP_RST_WDT:       return "OTHER_WATCHDOG";
        case ESP_RST_DEEPSLEEP: return "DEEP_SLEEP_WAKEUP";
        case ESP_RST_BROWNOUT:  return "BROWNOUT_RESET";
        case ESP_RST_SDIO:      return "SDIO_RESET";
        default:                return "UNKNOWN";
    }
}

bool isAbnormalReset(esp_reset_reason_t reason) {
    switch (reason) {
        case ESP_RST_PANIC:
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT:
        case ESP_RST_BROWNOUT:
            return true;
        default:
            return false;
    }
}
}

// Cached timestamp utility for performance
struct CachedTimestamp {
    // Get timestamp using the specific timestamp_ms from log generation time
    static void getTimestampFromLog(uint64_t log_timestamp_ms, struct tm& timeinfo, bool& has_real_time) {
        static time_t cached_real_time = 0;
        static uint64_t cached_boot_time_ms = 0;
        static bool has_ntp_time = false;
        static uint64_t last_sync_ms = 0;
        const uint64_t SYNC_INTERVAL_MS = 3ULL * 60 * 60 * 1000; // 3 hours

        uint64_t current_boot_ms = esp_timer_get_time() / 1000ULL;

        // Check if we need to update the cached time
        if (cached_real_time == 0 || (current_boot_ms - last_sync_ms) > SYNC_INTERVAL_MS) {
            time_t now;
            time(&now);

            // Check if we have a reasonable timestamp (after year 2020)
            has_ntp_time = (now > 1577836800); // 1 Jan 2020 00:00:00 UTC

            if (has_ntp_time) {
                cached_real_time = now;
                cached_boot_time_ms = current_boot_ms;
            }
            last_sync_ms = current_boot_ms;
        }

        has_real_time = has_ntp_time;
        if (has_ntp_time && cached_real_time > 0) {
            // Calculate real time for the specific log timestamp (not current time)
            uint64_t elapsed_since_cache = log_timestamp_ms - cached_boot_time_ms;
            time_t log_real_time = cached_real_time + (elapsed_since_cache / 1000);
            localtime_r(&log_real_time, &timeinfo);
        } else {
            // Return empty timeinfo - caller should handle fallback
            memset(&timeinfo, 0, sizeof(timeinfo));
        }
    }

    // Backwards compatibility method
    static void getCurrentTimestamp(struct tm& timeinfo, bool& has_real_time) {
        uint64_t current_boot_ms = esp_timer_get_time() / 1000ULL;
        getTimestampFromLog(current_boot_ms, timeinfo, has_real_time);
    }
};

ReportingEngine::ReportingEngine() {
    // Initialize PSRAM hooks for JSON operations
    PSRAMJsonParser::initializePSRAMHooks();
    LOG_INFO("ReportingEngine", "Initialized with PSRAM allocation hooks");
}
ReportingEngine::~ReportingEngine() {
    shutdown();
}

bool ReportingEngine::initialize(ConfigurationManager* cfg, SecurityManager* security) {
    // Basic initialization - can be extended later
    (void)cfg; (void)security; // suppress unused warnings
    return true;
}

void ReportingEngine::shutdown() {
    if (worker_) {
        vTaskDelete(worker_);
        worker_ = nullptr;
    }
    // The queue owns the filesystem delegate reference and can flush during
    // destruction.  Release it while the delegate is still alive during boot
    // rollback; reset() is idempotent and also makes repeated shutdown safe.
    queue_.reset();
}

void ReportingEngine::setChannel(const psram_string& name, const ChannelConfig& cfg, SenderFn&& sender) {
    Chan chan;
    chan.cfg = cfg;
    chan.send = std::move(sender);
    chan.send_raw = SenderRaw{};
    auto it = chans_.find(name);
    if (it != chans_.end()) {
        it->second = std::move(chan);
    } else {
        chans_.emplace(name, std::move(chan));
    }
}

void ReportingEngine::setChannelRaw(const psram_string& name, const ChannelConfig& cfg, SenderRaw&& sender) {
    Chan chan;
    chan.cfg = cfg;
    chan.send = SenderFn{};
    chan.send_raw = std::move(sender);
    auto it = chans_.find(name);
    if (it != chans_.end()) {
        it->second = std::move(chan);
    } else {
        chans_.emplace(name, std::move(chan));
    }
}

void ReportingEngine::enableQueue(const PSRAMQueueConfig& qcfg, uint32_t flush_interval_ms) {
    flush_interval_ms_ = flush_interval_ms;
    queue_.reset(new PSRAMReliableQueue(qcfg));

    // Initialize PSRAMReliableQueue with FilesystemTaskDelegate
    if (queue_) {
        if (!queue_->initialize(&FilesystemTaskDelegate::getInstance())) {
            LOG_ERROR("ReportingEngine", "Failed to initialize PSRAMReliableQueue");
            queue_.reset();
        }
    }
    // Use the centralized configuration for the report_flush task (with priority included)
    worker_ = TaskConfig::createTask(&ReportingEngine::workerThunk,
                                   "report_flush",
                                   TaskConfig::Presets::REPORT_FLUSH,
                                   this, 1);
}

void ReportingEngine::reportSystemBootEvent(esp_reset_reason_t reset_reason) {
    if (PSRAMUtils::isCriticalMemory()) {
        LOG_WARNING("ReportingEngine", "System boot event skipped due to critical memory");
        return;
    }

    PSRAMJsonParser::PSRAMContext ctx;
    if (!ctx.isValid()) {
        // Hooks already installed elsewhere, continue even if not initialized here
    }

    cJSON* event = cJSON_CreateObject();
    if (!event) {
        LOG_ERROR("ReportingEngine", "Failed to allocate JSON object for boot event");
        return;
    }

    cJSON_AddStringToObject(event, "event_type", "system_boot");
    cJSON_AddStringToObject(event, "reset_reason", resetReasonToString(reset_reason));
    bool crash = isAbnormalReset(reset_reason);
    cJSON_AddBoolToObject(event, "abnormal_restart", crash);
    cJSON_AddNumberToObject(event, "uptime_ms", 0);

    size_t free_heap = esp_get_free_heap_size();
    size_t min_free_heap = esp_get_minimum_free_heap_size();
    cJSON_AddNumberToObject(event, "free_heap_bytes", free_heap);
    cJSON_AddNumberToObject(event, "min_free_heap_bytes", min_free_heap);

#ifdef CONFIG_SPIRAM
    size_t psram_size = esp_psram_get_size();
    if (psram_size > 0) {
        size_t spiram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        cJSON_AddNumberToObject(event, "psram_total_bytes", psram_size);
        cJSON_AddNumberToObject(event, "psram_free_bytes", spiram_free);
    }
#endif

    char* json_str = cJSON_PrintUnformatted(event);
    psram_string payload = PSRAMUtils::createPSRAMString(json_str ? json_str : "{}");
    if (json_str) {
        free(json_str);
    }
    cJSON_Delete(event);

    if (payload.empty()) {
        LOG_WARNING("ReportingEngine", "Boot event payload allocation failed");
        return;
    }

    const char* type_literal = crash ? "intrusion_detected" : "system_status";
    psram_string type = PSRAMUtils::createPSRAMString(type_literal);
    if (type.empty()) {
        LOG_WARNING("ReportingEngine", "Boot event type allocation failed");
        return;
    }

    reportEvent(type, payload);
}


void ReportingEngine::workerThunk(void* arg) {
    reinterpret_cast<ReportingEngine*>(arg)->workerLoop();
}

void ReportingEngine::workerLoop() {
    uint64_t last_mem_maint_ms = 0;
    uint64_t last_cleanup_ms = 0;
    const uint32_t MEM_CHECK_PERIOD_MS = 5000;   // check every 5s
    const uint32_t CLEANUP_PERIOD_MS = 300000;   // cleanup every 5 minutes
    const uint32_t DRAM_THRESHOLD_BYTES = 30 * 1024; // 50KB
    const uint32_t DRAM_LARGEST_MIN = 8 * 1024;  // 8KB minimum contiguous block

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(flush_interval_ms_));
        flushNow();

        uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000ULL);

        // Periodic cleanup of orphan files - much less frequent than flush
        if (queue_ && (now_ms - last_cleanup_ms >= CLEANUP_PERIOD_MS)) {
            last_cleanup_ms = now_ms;
            queue_->cleanup_orphan_files();
        }

        // Periodic memory maintenance to combat fragmentation from sockets and JSON activity
        if (now_ms - last_mem_maint_ms >= MEM_CHECK_PERIOD_MS) {
            last_mem_maint_ms = now_ms;

            size_t free_dram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
            size_t largest_dram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

            if (free_dram < DRAM_THRESHOLD_BYTES || largest_dram < DRAM_LARGEST_MIN) {
                //LOGINFO: LOG_INFOF("ReportingEngine", "[MEM_IRAM] maintenance: DRAM free=%uB largest=%uB -> defrag",
                //          (unsigned)free_dram, (unsigned)largest_dram);
                TaskConfig::forceHeapDefragmentation();
            }

            // CRITICAL: PSRAM monitoring DISABLED - heap corruption causes guru meditation error
            // size_t largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM); // CRASH!
            // if (largest_psram < PSRAM_LARGEST_MIN) {
            //     LOG_INFOF("ReportingEngine", "PSRAM maintenance: largest=%u -> defrag",
            //               (unsigned)largest_psram);
            //     TaskConfig::forcePSRAMDefragmentation();
            // }
        }
    }
}

bool ReportingEngine::trySend(const psram_string& ch, const psram_string& payload) {
    // CRITICAL: Defensive check to prevent crashes during intensive fuzzing
    if (ch.empty() || payload.empty()) {
        return false;
    }

    // Memory safety check during fuzzing stress
    size_t free_dram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (free_dram < 20 * 1024) {  // Less than 20KB DRAM
        // Skip reporting to prevent crash during low memory
        return false;
    }

    // Additional safety: check PSRAM pointers validity
    if (!ch.data() || !payload.data()) {
        return false;
    }

    // PSRAM pointer safety check
    if (!esp_ptr_external_ram(ch.data()) && !esp_ptr_internal(ch.data())) {
        // Invalid pointer - skip to prevent crash
        return false;
    }

    char channel_buf[32];
    PSRAMUtils::copyToStackBuffer(channel_buf, sizeof(channel_buf), ch);
    bool is_serial_channel = (std::strcmp(channel_buf, "serial") == 0);

    auto it = chans_.find(ch);
    if (it==chans_.end()) return false;
    if (!it->second.cfg.enabled) return false;
    if (it->second.send_raw) {
        // Send raw without additional allocations
        if (is_serial_channel) {
            serial_mem_probe("serial_send_raw_begin");
            bool result = it->second.send_raw(payload.data(), payload.size());
            serial_mem_probe("serial_send_raw_end");
            return result;
        }
        return it->second.send_raw(payload.data(), payload.size());
    }
    if (it->second.send) {
        if (is_serial_channel) {
            serial_mem_probe("serial_send_begin");
            bool result = it->second.send(payload);
            serial_mem_probe("serial_send_end");
            return result;
        }
        return it->second.send(payload);
    }
    return false;
}

QueueDeliveryResult ReportingEngine::tryDeliverQueuedEvent(const QueuedEvent& event) {
    // A channel can be registered later in the boot sequence (notably email
    // after the network becomes available) or after a live configuration save.
    // Hold durable records in that state without treating it as a transport
    // failure.  They remain available for the next configured sender.
    auto it = chans_.find(event.channel);
    if (it == chans_.end() || !it->second.cfg.enabled ||
        (!it->second.send && !it->second.send_raw)) {
        return QueueDeliveryResult::DEFERRED;
    }

    return trySend(event.channel, event.payload)
        ? QueueDeliveryResult::DELIVERED
        : QueueDeliveryResult::RETRY;
}

uint32_t ReportingEngine::flushNow() {
    if (!queue_) return 0;
    uint64_t now = (uint64_t)(esp_timer_get_time()/1000ULL);

    // Cleanup moved to workerLoop() with separate timing to avoid delegate spam

    return queue_->flush(now, [&](const QueuedEvent& ev)->QueueDeliveryResult{
        return tryDeliverQueuedEvent(ev);
    });
}

bool ReportingEngine::getQueueStats(PSRAMQueueStats& out_stats) const {
    out_stats = PSRAMQueueStats();
    out_stats.flush_interval_ms = flush_interval_ms_;
    if (!queue_) {
        return false;
    }
    queue_->getStats(out_stats);
    out_stats.flush_interval_ms = flush_interval_ms_;
    return true;
}

// NEW: Send event to ALL active channels
void ReportingEngine::reportEvent(const psram_string& type, const psram_string& raw_json) {
    char type_buf_scope[32];
    PSRAMUtils::copyToStackBuffer(type_buf_scope, sizeof(type_buf_scope), type);

    dump_heap_stage("reportEvent_begin", type);

    size_t iram_free_begin = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t iram_min_begin = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    //LOGINFO: LOG_INFOF("ReportingEngine",
    //          "[MEM_IRAM] reportEvent begin type='%s' payload=%uB free=%uB min=%uB",
    //          type.c_str(),
    //          (unsigned)raw_json.size(),
    //          (unsigned)iram_free_begin,
    //          (unsigned)iram_min_begin);

    // === CRITICAL FIX: Memory pressure check before JSON processing ===
    if (PSRAMUtils::isCriticalMemory()) {
        PSRAMUtils::logMemoryStatus("ReportingEngine::reportEvent BEFORE emergency cleanup");
        PSRAMUtils::emergencyCleanup("ReportingEngine::reportEvent");

        size_t iram_free_after_cleanup = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t iram_min_after_cleanup = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        //LOGINFO: LOG_WARNINGF("ReportingEngine",
        //             "[MEM_IRAM] reportEvent post-cleanup type='%s' free=%uB min=%uB",
        //             type.c_str(),
        //             (unsigned)iram_free_after_cleanup,
        //             (unsigned)iram_min_after_cleanup);

        // If still critical after cleanup, skip the event to avoid crash
        if (PSRAMUtils::isCriticalMemory()) {
            //LOGINFO: LOG_ERROR("ReportingEngine", "[MEM_IRAM] Event dropped due to critical memory");
            return;
        }
    }

    uint64_t timestamp_ms = (uint64_t)(esp_timer_get_time()/1000ULL);

    if (!PSRAMUtils::isCriticalMemory()) {
        IRAMTraceSnapshot submit_snapshot = iram_trace_capture();
        submitDirect(psram_string{}, type, raw_json, timestamp_ms);
        char trace_label[128];
        snprintf(trace_label, sizeof(trace_label),
                 "reportEvent submitDirect type=%s",
                 type_buf_scope);
        iram_trace_report(trace_label, submit_snapshot);

        size_t iram_free_after_submit = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t iram_min_after_submit = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        long consumed_total = (long)iram_free_begin - (long)iram_free_after_submit;
        long consumed_min = (long)iram_min_begin - (long)iram_min_after_submit;
        if (consumed_total > 0 || consumed_min > 0) {
            snprintf(trace_label, sizeof(trace_label),
                     "reportEvent total type=%s",
                     type_buf_scope);
            IRAMTraceSnapshot begin_snapshot{iram_free_begin, iram_min_begin};
            iram_trace_report(trace_label, begin_snapshot);
        }

        dump_heap_stage("reportEvent_after_submit", type);
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM] reportEvent end type='%s' free=%uB delta=%ldB min=%uB",
        //          type.c_str(),
        //          (unsigned)iram_free_after_submit,
        //          -consumed_total,
        //          (unsigned)iram_min_after_submit);
    } else {
        //LOGINFO: LOG_WARNING("ReportingEngine", "[MEM_IRAM] Event submit skipped - memory became critical during processing");
    }
}

// LEGACY: Send event to specific channel (backward compatibility)
void ReportingEngine::reportEventToChannel(const psram_string& channel, const psram_string& type, const psram_string& raw_json) {
    uint64_t timestamp_ms = (uint64_t)(esp_timer_get_time()/1000ULL);
    submitDirectToChannel(channel, type, raw_json, timestamp_ms);
}

// CRITICAL: Direct submit to ALL channels without EventRecord std::string allocation
void ReportingEngine::submitDirect(const psram_string& channel_override, const psram_string& type, const psram_string& raw_json, uint64_t timestamp_ms) {
    char type_buf_scope[32];
    PSRAMUtils::copyToStackBuffer(type_buf_scope, sizeof(type_buf_scope), type);

    char override_buf[32];
    if (channel_override.empty()) {
        override_buf[0] = '<';
        override_buf[1] = 'a';
        override_buf[2] = 'l';
        override_buf[3] = 'l';
        override_buf[4] = '>';
        override_buf[5] = '\0';
    } else {
        PSRAMUtils::copyToStackBuffer(override_buf, sizeof(override_buf), channel_override);
    }

    dump_heap_stage("submitDirect_begin", type);

    size_t iram_free_entry = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t iram_min_entry = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    size_t iram_largest_entry = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    IRAMTraceSnapshot total_snapshot{iram_free_entry, iram_min_entry};

    //LOGINFO: LOG_INFOF("ReportingEngine",
    //          "[MEM_IRAM] submitDirect start type='%s' override='%s' free=%uB min=%uB largest=%uB",
    //          type.c_str(),
    //          override_buf,
    //          (unsigned)iram_free_entry,
    //          (unsigned)iram_min_entry,
    //          (unsigned)iram_largest_entry);

    if (PSRAMUtils::isCriticalMemory()) {
        PSRAMUtils::logMemoryStatus("ReportingEngine::submitDirect critical entry");
        //LOGINFO: LOG_WARNING("ReportingEngine", "[MEM_IRAM] submitDirect aborted due to critical memory");
        return;
    }

    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    unsigned frag_pct = 0;
    if (free_heap > 0 && free_heap > largest_block) {
        size_t used_vs_largest = free_heap - largest_block;
        frag_pct = (unsigned)((used_vs_largest * 100U) / free_heap);
    }

    if (free_heap < 20000 || frag_pct > 85U) {
        //LOGINFO: LOG_WARNINGF("ReportingEngine",
        //             "[MEM_IRAM] submitDirect throttled: free=%uB largest=%uB frag=%u%%",
        //             (unsigned)free_heap,
        //             (unsigned)largest_block,
        //             (unsigned)frag_pct);
        return;
    }

    psram_string filter_content = PSRAMUtils::createPSRAMString("");
    if (!type.empty()) {
        filter_content = type;
        if (!raw_json.empty()) {
            psram_string separator = PSRAMUtils::createPSRAMString(" ");
            psram_string combined = PSRAMUtils::concat(filter_content, separator);
            filter_content = PSRAMUtils::concat(combined, raw_json);
        }
    } else {
        filter_content = raw_json;
    }

    for (auto& chan_pair : chans_) {
        const psram_string& chan_name = chan_pair.first;
        Chan& chan = chan_pair.second;

        if (!chan.cfg.enabled || (!chan.send && !chan.send_raw)) {
            continue;
        }

        if (!channel_override.empty() && chan_name != channel_override) {
            continue;
        }

        char chan_name_buf[32];
        PSRAMUtils::copyToStackBuffer(chan_name_buf, sizeof(chan_name_buf), chan_name);

        bool is_file_channel = (std::strcmp(chan_name_buf, "file") == 0);
        bool is_serial_channel = (std::strcmp(chan_name_buf, "serial") == 0);

        if (!is_file_channel) {
            dump_heap_stage_channel("submitDirect_channel_begin", type, chan_name);
        }

        size_t heap_before_filter = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        if (!shouldSendToChannel(chan.cfg, filter_content)) {
            if (is_serial_channel) {
                serial_mem_probe("serial_filtered_skip");
            } else if (!is_file_channel) {
            //LOGINFO: LOG_INFOF("ReportingEngine",
            //          "[MEM_IRAM] channel='%s' filtered skip (free=%uB)",
            //          chan_name_buf,
            //          (unsigned)heap_before_filter);
            }
            continue;
        }

        size_t heap_before_format = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t min_before_format = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        if (is_serial_channel) {
            char stage_buf[96];
            snprintf(stage_buf, sizeof(stage_buf),
                     "serial_pre_format payload=%u", (unsigned)raw_json.size());
            serial_mem_probe(stage_buf);
        }
        if (heap_before_format < 1536) {
            //LOGINFO: LOG_WARNINGF("ReportingEngine",
            //             "[MEM_IRAM] channel='%s' skip format (free=%uB <1536B)",
            //             chan_name_buf,
            //             (unsigned)heap_before_format);
            continue;
        }

        if (!is_file_channel) {
            dump_heap_stage_channel("submitDirect_before_format", type, chan_name);
        }
        IRAMTraceSnapshot format_snapshot = iram_trace_capture();
        psram_string payload = formatEventDirect(chan_name,
                                                 type,
                                                 raw_json,
                                                 timestamp_ms,
                                                 chan.cfg.format);
        char trace_label[160];
        snprintf(trace_label, sizeof(trace_label),
                 "submitDirect format channel=%s type=%s",
                 chan_name_buf,
                 type_buf_scope);
        iram_trace_report(trace_label, format_snapshot);
        size_t heap_after_format = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t min_after_format = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        long format_delta = (long)heap_after_format - (long)heap_before_format;
        if (is_serial_channel) {
            char stage_buf[128];
            snprintf(stage_buf, sizeof(stage_buf),
                     "serial_post_format delta=%ld payload=%u",
                     format_delta,
                     (unsigned)payload.size());
            serial_mem_probe(stage_buf);
        } else if (!is_file_channel) {
            //LOGINFO: LOG_INFOF("ReportingEngine",
            //          "[MEM_IRAM] channel='%s' format delta=%ldB free=%uB->%uB min=%uB->%uB payload=%uB",
            //          chan_name_buf,
            //          format_delta,
            //          (unsigned)heap_before_format,
            //          (unsigned)heap_after_format,
            //          (unsigned)min_before_format,
            //          (unsigned)min_after_format,
            //          (unsigned)payload.size());
        }

        if (payload.empty() && !raw_json.empty()) {
            //LOGINFO: LOG_WARNINGF("ReportingEngine",
            //             "[MEM_IRAM] channel='%s' payload allocation failed (raw=%uB)",
            //             chan_name_buf,
            //             (unsigned)raw_json.size());
            continue;
        }

        if (chan.cfg.verbosity == VerbosityLevel::VERBOSE && !is_file_channel) {
            size_t heap_before_verbose = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
            if (heap_before_verbose >= 512) {
                IRAMTraceSnapshot verbose_snapshot = iram_trace_capture();
                const char* format_name;
                switch (chan.cfg.format) {
                    case EventFormat::CEE:  format_name = "CEE"; break;
                    case EventFormat::LEEF: format_name = "LEEF"; break;
                    case EventFormat::CEF:  format_name = "CEF"; break;
                    case EventFormat::JSON:
                    default: format_name = "JSON"; break;
                }
                psram_string wrapped_payload = PSRAMUtils::createPSRAMString("---");
                wrapped_payload += PSRAMUtils::createPSRAMString(format_name);
                wrapped_payload += PSRAMUtils::createPSRAMString("---\n");
                wrapped_payload += payload;
                wrapped_payload += PSRAMUtils::createPSRAMString("\n---END ");
                wrapped_payload += PSRAMUtils::createPSRAMString(format_name);
                wrapped_payload += PSRAMUtils::createPSRAMString("---");
                if (!wrapped_payload.empty()) {
                    payload = std::move(wrapped_payload);
                    snprintf(trace_label, sizeof(trace_label),
                             "submitDirect verbose_wrap channel=%s type=%s",
                             chan_name_buf,
                             type_buf_scope);
                    iram_trace_report(trace_label, verbose_snapshot);
                }
            } else {
                //LOGINFO: LOG_WARNINGF("ReportingEngine",
                //             "[MEM_IRAM] channel='%s' verbose wrapper skipped (free=%uB)",
                //             chan_name_buf,
                //             (unsigned)heap_before_verbose);
            }
        }

        size_t heap_before_send = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t min_before_send = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        if (!is_file_channel) {
            dump_heap_stage_channel("submitDirect_before_send", type, chan_name);
        }
        if (is_serial_channel) {
            size_t largest_before_send = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
            //LOGINFO: LOG_INFOF("ReportingEngine",
            //          "[MEM_IRAM][serial] pre-send free=%uB min=%uB largest=%uB payload=%uB",
            //          (unsigned)heap_before_send,
            //            (unsigned)min_before_send,
            //            (unsigned)largest_before_send,
            //            (unsigned)payload.size());
        }
        IRAMTraceSnapshot send_snapshot{heap_before_send, min_before_send};
        bool sent = trySend(chan_name, payload);
        snprintf(trace_label, sizeof(trace_label),
                 "submitDirect send channel=%s type=%s",
                 chan_name_buf,
                 type_buf_scope);
        iram_trace_report(trace_label, send_snapshot);
        size_t heap_after_send = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t min_after_send = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        long send_delta = (long)heap_after_send - (long)heap_before_send;

        if (sent) {
            if (!is_file_channel && !is_serial_channel) {
                //LOGINFO: LOG_INFOF("ReportingEngine",
                //          "[MEM_IRAM] channel='%s' send ok payload=%uB free=%uB delta=%ldB min=%uB",
                //          chan_name_buf,
                //          (unsigned)payload.size(),
                //          (unsigned)heap_after_send,
                //          send_delta,
                //          (unsigned)min_after_send);
            }
            continue;
        }

        if (!is_file_channel && !is_serial_channel) {
            //LOGINFO: LOG_WARNINGF("ReportingEngine",
            //             "[MEM_IRAM] channel='%s' send failed delta=%ldB free=%uB min=%uB",
            //             chan_name_buf,
            //             send_delta,
            //             (unsigned)heap_after_send,
            //             (unsigned)min_after_send);
        }

        if (queue_) {
            size_t psram_before_queue = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
            if (psram_before_queue > 1024) {
                if (!is_file_channel) {
                    dump_heap_stage_channel("submitDirect_queue_before", type, chan_name);
                }
                psram_string ps_chan = PSRAMUtils::createPSRAMString(chan_name_buf);
                bool queued = queue_->enqueue_psram(ps_chan, raw_json);
                size_t psram_after_queue = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
                long psram_delta = (long)psram_after_queue - (long)psram_before_queue;

                if (!is_file_channel) {
                    if (is_serial_channel) {
                        char stage_buf[128];
                        snprintf(stage_buf, sizeof(stage_buf),
                                 "serial_queue_enq result=%s psram_delta=%ld",
                                 queued ? "ok" : "fail",
                                 psram_delta);
                        serial_mem_probe(stage_buf);
                    } else {
                        LOG_INFOF("ReportingEngine",
                                  "[MEM_PSRAM] channel='%s' enqueue %s free=%uB delta=%ldB",
                                  chan_name_buf,
                                  queued ? "ok" : "failed",
                                  (unsigned)psram_after_queue,
                                  psram_delta);
                        dump_heap_stage_channel("submitDirect_queue_after", type, chan_name);
                    }
                }
            } else {
                if (!is_file_channel) {
                    if (is_serial_channel) {
                        serial_mem_probe("serial_queue_skipped");
                    } else {
                        LOG_WARNINGF("ReportingEngine",
                                     "[MEM_PSRAM] channel='%s' enqueue skipped psram_free=%uB",
                                     chan_name_buf,
                                     (unsigned)psram_before_queue);
                    }
                }
            }
        }
    }

    size_t iram_free_end = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t iram_min_end = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    long total_delta = (long)iram_free_end - (long)iram_free_entry;
    char total_label[160];
    snprintf(total_label, sizeof(total_label),
             "submitDirect total type=%s override=%s",
             type_buf_scope,
             override_buf);
    iram_trace_report(total_label, total_snapshot);

    dump_heap_stage("submitDirect_end", type);
    //LOGINFO: LOG_INFOF("ReportingEngine",
    //          "[MEM_IRAM] submitDirect end type='%s' free=%uB delta=%ldB min=%uB",
    //          type.c_str(),
    //          (unsigned)iram_free_end,
    //          total_delta,
    //          (unsigned)iram_min_end);
}
// CRITICAL: Direct submit to specific channel without EventRecord std::string allocation
void ReportingEngine::submitDirectToChannel(const psram_string& channel, const psram_string& type, const psram_string& raw_json, uint64_t timestamp_ms) {
    char channel_buf[32];
    PSRAMUtils::copyToStackBuffer(channel_buf, sizeof(channel_buf), channel);
    char type_buf_scope[32];
    PSRAMUtils::copyToStackBuffer(type_buf_scope, sizeof(type_buf_scope), type);

    auto it = chans_.find(channel);
    if (it == chans_.end()) {
        //LOGINFO: LOG_WARNINGF("ReportingEngine",
        //             "[MEM_IRAM] submitDirectToChannel missing channel '%s'",
        //             channel_buf);
        return;
    }

    bool is_file_channel = (std::strcmp(channel_buf, "file") == 0);
    bool is_serial_channel = (std::strcmp(channel_buf, "serial") == 0);
    Chan& chan = it->second;

    if (!is_file_channel) {
        dump_heap_stage_channel("submitDirectToChannel_begin", type, channel);
    }

    size_t iram_free_start = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t iram_min_start = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    IRAMTraceSnapshot total_snapshot{iram_free_start, iram_min_start};
    if (is_serial_channel) {
        size_t largest_start = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM][serial] submitToChannel start free=%uB min=%uB largest=%uB",
        //          (unsigned)iram_free_start,
        //          (unsigned)iram_min_start,
        //          (unsigned)largest_start);
    } else if (!is_file_channel) {
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM] submitDirectToChannel start channel='%s' type='%s' free=%uB min=%uB",
        //          channel_buf,
        //          type.c_str(),
        //          (unsigned)iram_free_start,
        //          (unsigned)iram_min_start);
    }

    psram_string filter_content = PSRAMUtils::createPSRAMString("");
    if (!type.empty()) {
        filter_content = type;
        if (!raw_json.empty()) {
            psram_string separator = PSRAMUtils::createPSRAMString(" ");
            psram_string combined = PSRAMUtils::concat(filter_content, separator);
            filter_content = PSRAMUtils::concat(combined, raw_json);
        }
    } else {
        filter_content = raw_json;
    }

    if (!shouldSendToChannel(chan.cfg, filter_content)) {
        if (is_serial_channel) {
            //LOGINFO: LOG_INFOF("ReportingEngine",
            //          "[MEM_IRAM][serial] submitToChannel filtered free=%uB",
            //          (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        } else if (!is_file_channel) {
            //LOGINFO: LOG_INFOF("ReportingEngine",
            //          "[MEM_IRAM] submitDirectToChannel filtered channel='%s' free=%uB",
            //          channel_buf,
            //          (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        }
        return;
    }

    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    const size_t MIN_HEAP_REQUIRED = 2048;
    if (free_heap < MIN_HEAP_REQUIRED) {
        if (!is_file_channel || is_serial_channel) {
            //LOGINFO: LOG_WARNINGF("ReportingEngine",
            //             "[MEM_IRAM]%s submitDirectToChannel skipped channel='%s' free=%uB (<%uB)",
            //             is_serial_channel ? "[serial]" : "",
            //             channel_buf,
            //             (unsigned)free_heap,
            //             (unsigned)MIN_HEAP_REQUIRED);
        }
        return;
    }

    if (!is_file_channel) {
        dump_heap_stage_channel("submitDirectToChannel_before_format", type, channel);
    }
    size_t heap_before_format = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t min_before_format = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    IRAMTraceSnapshot format_snapshot = iram_trace_capture();
    psram_string payload = formatEventDirect(channel,
                                             type,
                                             raw_json,
                                             timestamp_ms,
                                             chan.cfg.format);
    char trace_label[160];
    snprintf(trace_label, sizeof(trace_label),
             "submitDirectToChannel format channel=%s type=%s",
             channel_buf,
             type_buf_scope);
    iram_trace_report(trace_label, format_snapshot);
    size_t heap_after_format = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t min_after_format = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    long format_delta = (long)heap_after_format - (long)heap_before_format;

    if (is_serial_channel) {
        size_t largest_after_format = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM][serial] submitToChannel format delta=%ldB free=%uB->%uB min=%uB->%uB largest=%uB payload=%uB",
        //          format_delta,
        //          (unsigned)heap_before_format,
        //          (unsigned)heap_after_format,
        //          (unsigned)min_before_format,
        //          (unsigned)min_after_format,
        //          (unsigned)largest_after_format,
        //          (unsigned)payload.size());
    } else if (!is_file_channel) {
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM] submitDirectToChannel format channel='%s' delta=%ldB free=%uB->%uB min=%uB payload=%uB",
        //          channel_buf,
        //          format_delta,
        //          (unsigned)heap_before_format,
        //          (unsigned)heap_after_format,
        //          (unsigned)min_after_format,
        //          (unsigned)payload.size());
    }

    if (payload.empty() && !raw_json.empty()) {
        if (!is_file_channel || is_serial_channel) {
            //LOGINFO: LOG_WARNINGF("ReportingEngine",
            //             "[MEM_IRAM]%s submitDirectToChannel payload allocation failed channel='%s' raw=%uB",
            //             is_serial_channel ? "[serial]" : "",
            //             channel_buf,
            //             (unsigned)raw_json.size());
        }
        return;
    }

    size_t heap_before_send = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t min_before_send = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    if (!is_file_channel) {
        dump_heap_stage_channel("submitDirectToChannel_before_send", type, channel);
    }
    if (is_serial_channel) {
        size_t largest_before_send = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM][serial] submitToChannel pre-send free=%uB min=%uB largest=%uB payload=%uB",
        //          (unsigned)heap_before_send,
        //          (unsigned)min_before_send,
        //          (unsigned)largest_before_send,
        //          (unsigned)payload.size());
    }
    IRAMTraceSnapshot send_snapshot{heap_before_send, min_before_send};
        bool sent = trySend(channel, payload);
    snprintf(trace_label, sizeof(trace_label),
             "submitDirectToChannel send channel=%s type=%s",
             channel_buf,
             type_buf_scope);
    iram_trace_report(trace_label, send_snapshot);
    size_t heap_after_send = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t min_after_send = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    long send_delta = (long)heap_after_send - (long)heap_before_send;

    if (is_serial_channel) {
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM][serial] submitToChannel send %s payload=%uB free=%uB delta=%ldB min=%uB",
        //          sent ? "ok" : "fail",
        //          (unsigned)payload.size(),
        //          (unsigned)heap_after_send,
        //          send_delta,
        //          (unsigned)min_after_send);
    } else if (sent && !is_file_channel) {
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM] submitDirectToChannel sent channel='%s' payload=%uB free=%uB delta=%ldB min=%uB",
        //          channel_buf,
        //          (unsigned)payload.size(),
        //          (unsigned)heap_after_send,
        //          send_delta,
        //          (unsigned)min_after_send);
    } else if (!sent && !is_file_channel) {
        //LOGINFO: LOG_WARNINGF("ReportingEngine",
        //             "[MEM_IRAM] submitDirectToChannel send failed channel='%s' delta=%ldB free=%uB min=%uB",
        //             channel_buf,
        //             send_delta,
        //             (unsigned)heap_after_send,
        //             (unsigned)min_after_send);
    }

    if (!sent && queue_) {
        size_t heap_before_queue = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        if (heap_before_queue > 1024) {
            if (!is_file_channel) {
                dump_heap_stage_channel("submitDirectToChannel_queue_before", type, channel);
            }
            char chan_buffer[64];
            size_t chan_size = std::min(channel.size(), sizeof(chan_buffer) - 1);
            std::memcpy(chan_buffer, channel.data(), chan_size);
            chan_buffer[chan_size] = '\0';
            bool queued = queue_->enqueue_psram(PSRAMUtils::createPSRAMString(chan_buffer), raw_json);
            size_t heap_after_queue = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
            long psram_delta = (long)heap_after_queue - (long)heap_before_queue;
            if (is_serial_channel) {
                LOG_INFOF("ReportingEngine",
                          "[MEM_PSRAM][serial] enqueue %s free=%uB delta=%ldB",
                          queued ? "ok" : "failed",
                          (unsigned)heap_after_queue,
                          psram_delta);
            } else if (!is_file_channel) {
                LOG_INFOF("ReportingEngine",
                          "[MEM_PSRAM] submitDirectToChannel enqueue channel='%s' %s free=%uB delta=%ldB",
                          channel_buf,
                          queued ? "ok" : "failed",
                          (unsigned)heap_after_queue,
                          psram_delta);
            }
            if (!is_file_channel) {
                dump_heap_stage_channel("submitDirectToChannel_queue_after", type, channel);
            }
        } else if (!is_file_channel) {
            LOG_WARNINGF("ReportingEngine",
                         "[MEM_PSRAM] submitDirectToChannel queue skipped channel='%s' psram_free=%uB",
                         channel_buf,
                         (unsigned)heap_before_queue);
        }
    }

    size_t iram_free_end = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t iram_min_end = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    long total_delta = (long)iram_free_end - (long)iram_free_start;
    snprintf(trace_label, sizeof(trace_label),
             "submitDirectToChannel total channel=%s type=%s",
             channel_buf,
             type_buf_scope);
    iram_trace_report(trace_label, total_snapshot);

    if (!is_file_channel) {
        dump_heap_stage_channel("submitDirectToChannel_end", type, channel);
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM] submitDirectToChannel end channel='%s' free=%uB delta=%ldB min=%uB",
        //          channel_buf,
        //          (unsigned)iram_free_end,
        //          total_delta,
        //          (unsigned)iram_min_end);
    } else if (is_serial_channel) {
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM][serial] submitToChannel end free=%uB min=%uB",
        //          (unsigned)iram_free_end,
        //          (unsigned)iram_min_end);
    }
}
// Helper method to format events directly from PSRAM strings
psram_string ReportingEngine::formatEventDirect(const psram_string& channel,
                                               const psram_string& type,
                                               const psram_string& raw_json,
                                               uint64_t timestamp_ms,
                                               EventFormat format) {
    char channel_buf[32];
    char type_buf[32];
    PSRAMUtils::copyToStackBuffer(channel_buf, sizeof(channel_buf), channel);
    PSRAMUtils::copyToStackBuffer(type_buf, sizeof(type_buf), type);

    bool is_file_channel = (std::strcmp(channel_buf, "file") == 0);
    bool is_serial_channel = (std::strcmp(channel_buf, "serial") == 0);

    if (!is_file_channel) {
        dump_heap_stage_channel("formatEventDirect_begin", type, channel);
    }

    size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t min_before = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    IRAMTraceSnapshot begin_snapshot{heap_before, min_before};
    if (is_serial_channel) {
        char stage_buf[128];
        snprintf(stage_buf, sizeof(stage_buf),
                 "serial_format_begin raw=%u format=%d",
                 (unsigned)raw_json.size(),
                 (int)format);
        serial_mem_probe(stage_buf);
    } else if (!is_file_channel) {
        //LOGINFO: LOG_INFOF("ReportingEngine",
        //          "[MEM_IRAM] formatEventDirect begin channel='%s' type='%s' raw=%uB free=%uB min=%uB format=%d",
        //          channel_buf,
        //          type_buf,
        //          (unsigned)raw_json.size(),
        //          (unsigned)heap_before,
        //         (unsigned)min_before,
        //         (int)format);
    }

    auto log_return = [&](psram_string result, const char* stage_label) -> psram_string {
        size_t heap_after = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        size_t min_after = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        long delta = (long)heap_after - (long)heap_before;
        long consumed_free = (long)heap_before - (long)heap_after;
        long consumed_min = (long)min_before - (long)min_after;
        if (is_serial_channel) {
            char stage_buf[128];
            snprintf(stage_buf, sizeof(stage_buf),
                     "serial_format_%s payload=%u delta=%ld",
                     stage_label,
                     (unsigned)result.size(),
                     delta);
            serial_mem_probe(stage_buf);
        } else if (!is_file_channel) {
            //LOGINFO: LOG_INFOF("ReportingEngine",
            //          "[MEM_IRAM] %s channel='%s' type='%s' payload=%uB free=%uB delta=%ldB min=%uB",
            //          stage_label,
            //          channel_buf,
            //          type_buf,
            //          (unsigned)result.size(),
            //          (unsigned)heap_after,
            //          delta,
            //          (unsigned)min_after);
        }
        if (consumed_free > 0 || consumed_min > 0) {
            char trace_label[160];
            snprintf(trace_label, sizeof(trace_label),
                     "formatEventDirect %s channel=%s type=%s",
                     stage_label,
                     channel_buf,
                     type_buf);
            iram_trace_report(trace_label, begin_snapshot);
        }
        if (!is_file_channel) {
            dump_heap_stage_channel(stage_label, type, channel);
        }
        return result;
    };

    if (format == EventFormat::JSON) {
        if (std::strcmp(channel_buf, "file") == 0) {
            const char* raw_ptr = raw_json.data();
            size_t raw_len = raw_json.size();

            if (raw_len >= 2 && raw_ptr[0] == '{') {
                bool has_additional_fields = false;
                for (size_t i = 1; i + 1 < raw_len; ++i) {
                    unsigned char ch = static_cast<unsigned char>(raw_ptr[i]);
                    if (!std::isspace(ch)) {
                        has_additional_fields = (raw_ptr[i] != '}');
                        break;
                    }
                }

                constexpr const char kPrefix[] = "{\"channel\":\"";
                constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
                constexpr const char kSuffixWithComma[] = "\",";
                constexpr size_t kSuffixWithCommaLen = sizeof(kSuffixWithComma) - 1;
                constexpr const char kSuffixOnlyChannel[] = "\"}";
                constexpr size_t kSuffixOnlyChannelLen = sizeof(kSuffixOnlyChannel) - 1;

                size_t type_len = type.size();

                if (has_additional_fields) {
                    size_t needed = kPrefixLen + type_len + kSuffixWithCommaLen + (raw_len - 1);
                    psram_string wrapped;
                    wrapped.reserve(needed);
                    wrapped.append(kPrefix, kPrefixLen);
                    wrapped.append(type.data(), type_len);
                    wrapped.append(kSuffixWithComma, kSuffixWithCommaLen);
                    wrapped.append(raw_ptr + 1, raw_len - 1);
                    return log_return(std::move(wrapped), "formatEventDirect_file_wrapped");
                } else {
                    size_t needed = kPrefixLen + type_len + kSuffixOnlyChannelLen;
                    psram_string wrapped;
                    wrapped.reserve(needed);
                    wrapped.append(kPrefix, kPrefixLen);
                    wrapped.append(type.data(), type_len);
                    wrapped.append(kSuffixOnlyChannel, kSuffixOnlyChannelLen);
                    return log_return(std::move(wrapped), "formatEventDirect_file_channel_only");
                }
            }

            return log_return(raw_json, "formatEventDirect_file_passthrough");
        }

        char timestamp_buffer[32];
        snprintf(timestamp_buffer, sizeof(timestamp_buffer), "%llu", (unsigned long long)timestamp_ms);

        const size_t MAX_OUTPUT = 65536;
        static char* json_buffer = nullptr;
        if (!json_buffer) {
            json_buffer = (char*)heap_caps_malloc(MAX_OUTPUT, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!json_buffer) {
                //LOGINFO: LOG_WARNING("ReportingEngine", "[MEM_IRAM] formatEventDirect JSON buffer allocation failed");
                return log_return(psram_string(), "formatEventDirect_json_alloc_fail");
            }
        }

        char type_buffer[64];
        char channel_buffer[64];

        size_t type_size = std::min(type.size(), sizeof(type_buffer) - 1);
        size_t channel_size = std::min(channel.size(), sizeof(channel_buffer) - 1);

        std::memcpy(type_buffer, type.data(), type_size);
        type_buffer[type_size] = '\0';
        std::memcpy(channel_buffer, channel.data(), channel_size);
        channel_buffer[channel_size] = '\0';

        if (is_serial_channel) {
            serial_mem_probe("serial_json_before_snprintf");
        }

        IRAMTraceSnapshot snprintf_snapshot = iram_trace_capture();
        int written = snprintf(json_buffer, MAX_OUTPUT,
            "{\"timestamp\":%s,\"type\":\"%s\",\"channel\":\"%s\",\"data\":%.*s}",
            timestamp_buffer, type_buffer, channel_buffer,
            (int)std::min(raw_json.size(), MAX_OUTPUT - 256), raw_json.data());
        char trace_detail[160];
        snprintf(trace_detail, sizeof(trace_detail),
                 "formatEventDirect snprintf channel=%s type=%s",
                 channel_buf,
                 type_buf);
        iram_trace_report(trace_detail, snprintf_snapshot);

        if (is_serial_channel) {
            serial_mem_probe("serial_json_after_snprintf");
        }

        if (written > 0 && written < (int)MAX_OUTPUT) {
            if (is_serial_channel) {
                serial_mem_probe("serial_json_before_create_psram");
            }
            IRAMTraceSnapshot assign_snapshot = iram_trace_capture();
            psram_string formatted = PSRAMUtils::createPSRAMString(json_buffer);
            snprintf(trace_detail, sizeof(trace_detail),
                     "formatEventDirect assign channel=%s type=%s",
                     channel_buf,
                     type_buf);
            iram_trace_report(trace_detail, assign_snapshot);
            if (is_serial_channel) {
                serial_mem_probe("serial_json_after_create_psram");
                serial_mem_probe("serial_json_before_return");
            }
            if (!formatted.empty()) {
                return log_return(std::move(formatted), "formatEventDirect_json_wrapped");
            }
        }

        if (is_serial_channel) {
            serial_mem_probe("serial_json_snprintf_fail");
        }
        //LOGINFO: LOG_WARNING("ReportingEngine", "[MEM_IRAM] formatEventDirect JSON wrapper snprintf failed");
        return log_return(raw_json, "formatEventDirect_json_passthrough");
    }

    return log_return(psram_string(), "formatEventDirect_default_empty");
}

// NEW: Submit to ALL active channels (ENHANCED with PSRAM memory monitoring)
void ReportingEngine::submit(const EventRecord& ev) {
    uint64_t timestamp_ms = (uint64_t)(esp_timer_get_time()/1000ULL);
    submitDirect(psram_string{}, ev.type, ev.raw_json, timestamp_ms);
}

// LEGACY: Submit to specific channel (backward compatibility)
void ReportingEngine::submitToChannel(const psram_string& channel, const EventRecord& ev) {
    uint64_t timestamp_ms = (uint64_t)(esp_timer_get_time()/1000ULL);
    submitDirectToChannel(channel, ev.type, ev.raw_json, timestamp_ms);
}

#include "cJSON.h"

psram_string ReportingEngine::getChannelsJSON() const {
    psram_string result;
    result.reserve((chans_.size() * 48) + 2);
    result.push_back('{');

    bool first = true;
    for (const auto& kv : chans_) {
        const psram_string& name = kv.first;
        const auto& ch = kv.second;

        if (!first) {
            result.push_back(',');
        }
        first = false;

        result.push_back('"');
        append_json_escaped(name, result);
        result += "\":{\"enabled\":";
        result += ch.cfg.enabled ? "true" : "false";
        result += ",\"format\":";
        append_int_to_psram(result, static_cast<int>(ch.cfg.format));
        result += ",\"verbosity\":";
        append_int_to_psram(result, static_cast<int>(ch.cfg.verbosity));
        result.push_back('}');
    }

    result.push_back('}');
    return result;
}

bool ReportingEngine::setChannelFormat(const psram_string& name, EventFormat fmt, bool enabled) {
    auto it = chans_.find(name);
    if (it==chans_.end()) return false;
    it->second.cfg.format = fmt;
    it->second.cfg.enabled = enabled;
    return true;
}

bool ReportingEngine::setChannelVerbosity(const psram_string& name, VerbosityLevel verbosity) {
    auto it = chans_.find(name);
    if (it==chans_.end()) return false;
    it->second.cfg.verbosity = verbosity;
    return true;
}

bool ReportingEngine::setChannelEnabled(const psram_string& name, bool enabled) {
    auto it = chans_.find(name);
    if (it==chans_.end()) return false;
    it->second.cfg.enabled = enabled;
    return true;
}
void ReportingEngine::reportLogMessage(const psram_string& tag, const psram_string& level, const psram_string& message, uint64_t timestamp_ms) {

    // Check available heap before attempting any memory allocations
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    const size_t MIN_HEAP_REQUIRED = 2048; // Require at least 2KB free heap

    if (free_heap < MIN_HEAP_REQUIRED) {
        // Skip logging if heap is critically low to prevent crash
        return;
    }


    // Send LOG messages to VERBOSE channels AND to "file" channel for persistent logging
    size_t chan_index = 0;
    for (const auto& chan_pair : chans_) {
        chan_index++;

        const psram_string& chan_name = chan_pair.first;
        const Chan& chan = chan_pair.second;


        if (!chan.cfg.enabled) {
            continue;
        }

        // Send to console channels (VERBOSE) AND to file channel for persistent logging
        bool is_file_channel = (chan_name.size() == 4 &&
                                chan_name[0] == 'f' &&
                                chan_name[1] == 'i' &&
                                chan_name[2] == 'l' &&
                                chan_name[3] == 'e');
        bool is_verbose_channel = (chan.cfg.verbosity == VerbosityLevel::VERBOSE);


        // Skip if neither file nor verbose channel
        if (!is_file_channel && !is_verbose_channel) {
            continue;
        }

        // Skip if no sender configured
        if (!chan.send && !chan.send_raw) {
            continue;
        }

        // Use PSRAM buffer instead of ostringstream to avoid internal RAM allocation
        thread_local char* log_buffer = nullptr;
        const size_t LOG_BUFFER_SIZE = 512;
        if (!log_buffer) {
            log_buffer = (char*)heap_caps_malloc(LOG_BUFFER_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!log_buffer) {
                continue; // Skip this channel if no PSRAM available
            }
        }

        // Use cached timestamp utility with the exact log generation timestamp
        struct tm timeinfo;
        bool has_real_time;
        CachedTimestamp::getTimestampFromLog(timestamp_ms, timeinfo, has_real_time);

        // Fallback to boot time if NTP not available
        // Use the exact timestamp from when the log was generated (not current time)
        if (!has_real_time) {
            uint64_t seconds = timestamp_ms / 1000;
            uint32_t hours = (seconds / 3600) % 24;
            uint32_t minutes = (seconds / 60) % 60;
            uint32_t secs = seconds % 60;

            // Create timeinfo structure for boot time
            memset(&timeinfo, 0, sizeof(timeinfo));
            timeinfo.tm_hour = hours;
            timeinfo.tm_min = minutes;
            timeinfo.tm_sec = secs;
            timeinfo.tm_year = 70; // 1970 (indicates boot time)
            timeinfo.tm_mon = 0;   // January
            timeinfo.tm_mday = 1;  // 1st
        }

        // Format directly to buffer using snprintf (no dynamic allocation) - use stack buffers for PSRAM strings
        char level_buffer[32];
        char tag_buffer[64];
        char message_buffer[256];

        // Copy PSRAM strings to stack buffers safely
        size_t level_size = std::min(level.size(), sizeof(level_buffer) - 1);
        size_t tag_size = std::min(tag.size(), sizeof(tag_buffer) - 1);
        size_t message_size = std::min(message.size(), sizeof(message_buffer) - 1);

        std::memcpy(level_buffer, level.data(), level_size);
        level_buffer[level_size] = '\0';
        std::memcpy(tag_buffer, tag.data(), tag_size);
        tag_buffer[tag_size] = '\0';
        std::memcpy(message_buffer, message.data(), message_size);
        message_buffer[message_size] = '\0';

        int written;
        if (has_real_time) {
            // Format with real timestamp: yyyy.mm.dd hh:mm:ss
            written = snprintf(log_buffer, LOG_BUFFER_SIZE,
                "%04d.%02d.%02d %02d:%02d:%02d %s %s: %s",
                timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec,
                level_buffer, tag_buffer, message_buffer);
        } else {
            // Fallback format with boot time: [HH:MM:SS] (boot time)
            uint64_t milliseconds = timestamp_ms % 1000;
            written = snprintf(log_buffer, LOG_BUFFER_SIZE,
                "[%02d:%02d:%02d.%03lu] %s %s: %s (boot time)",
                timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, (unsigned long)milliseconds,
                level_buffer, tag_buffer, message_buffer);
        }

        if (written < 0 || written >= (int)LOG_BUFFER_SIZE) {
            // Buffer overflow - truncate message
            log_buffer[LOG_BUFFER_SIZE-1] = '\0';
            written = LOG_BUFFER_SIZE - 1;
        }

        // NOTE: FileReporter adds '\n' automatically, so we don't add it here
        // to avoid double newlines in log files

        // For file channel with send_raw, send directly to avoid PSRAM string allocation
        bool sent = false;
        if (is_file_channel && chan.send_raw && chan.send_raw.fn) {
            sent = chan.send_raw.fn(chan.send_raw.ctx, log_buffer, written);
        }
        // For console/other channels with send callback, convert to PSRAM string
        else if (chan.send && chan.send.fn) {
            psram_string psram_log_buffer = PSRAMUtils::createPSRAMString(log_buffer);
            if (!psram_log_buffer.empty()) {
                sent = trySend(chan_name, psram_log_buffer);
            } else {
            }
        }

        if (!sent) {

            if (queue_) {
                // CRITICAL: Check memory more aggressively before queue operations
                size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
                if (free_heap > 50000) { // Need much more memory for queue operations
                    // Use stack-based conversion to avoid heap allocation failures
                    char chan_name_buffer[64]; // Stack buffer for channel name
                    size_t chan_name_size = std::min(chan_name.size(), sizeof(chan_name_buffer) - 1);
                    std::memcpy(chan_name_buffer, chan_name.data(), chan_name_size);
                    chan_name_buffer[chan_name_size] = '\0';

                    // Use existing log_buffer directly (already on stack)
                    // Double-check memory before final allocation
                    size_t final_heap_check = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
                    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);

                    if (final_heap_check > 50000 && largest_block > 2000) {
                        // TODO(post-test): consider raising this guard to 60–70KB and
                        // consolidating with other enqueue guards.
                        psram_string ps_chan = PSRAMUtils::createPSRAMString(chan_name_buffer);
                        psram_string ps_pay  = PSRAMUtils::createPSRAMString(log_buffer);
                        queue_->enqueue_psram(ps_chan, ps_pay);
                    }
                } else {
                    // Memory too low - skip queueing to prevent crash
                }
            }
        }

    }


}
