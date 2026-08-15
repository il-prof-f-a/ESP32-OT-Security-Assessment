#include "cron_scheduler.h"
#include "logging_system.h"
#include "async_storage_engine.h"
#include "../assessment/vulnerability_scanner.h"
#include "../assessment/discovery_manager.h"
#include "psram_allocator.h"
#include <cstring>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <cstdlib>
#include <vector>

extern "C" {
    #include "esp_timer.h"
    #include "esp_heap_caps.h"
    #include "nvs.h"
    #include "nvs_flash.h"
}

static const char* TAG_CRON = "CronScheduler";
static const uint32_t CHECK_INTERVAL_MS = 60000; // Check every minute
static const uint8_t CRON_SAVER_CMD_SAVE = 1;
static const uint8_t CRON_SAVER_CMD_SHUTDOWN = 2;
static const UBaseType_t CRON_SAVER_QUEUE_LENGTH = 4;
static const uint32_t CRON_SAVER_STACK_WORDS = 4096;
static const UBaseType_t CRON_SAVER_TASK_PRIORITY = tskIDLE_PRIORITY + 3;

namespace {

std::string trimCopy(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string toLowerCopy(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

ProtocolType protocolFromToken(const std::string& token) {
    const std::string low = toLowerCopy(trimCopy(token));
    if (low == "modbus" || low == "modbus-tcp" || low == "modbus_tcp") {
        return ProtocolType::MODBUS_TCP;
    }
    if (low == "s7" || low == "s7comm" || low == "s7_comm" || low == "siemens") {
        return ProtocolType::S7_COMM;
    }
    if (low == "opcua" || low == "opc-ua" || low == "opc") {
        return ProtocolType::OPC_UA;
    }
    if (low == "ethernetip" || low == "ethernet-ip" || low == "cip") {
        return ProtocolType::ETHERNET_IP;
    }
    if (low == "profinet" || low == "pn") {
        return ProtocolType::PROFINET;
    }
    if (low == "general" || low == "generic" || low == "multi") {
        return ProtocolType::UNKNOWN;
    }
    return ProtocolType::UNKNOWN;
}

bool parseBoolToken(const std::string& value, bool default_val) {
    const std::string low = toLowerCopy(trimCopy(value));
    if (low == "true" || low == "1" || low == "yes" || low == "y" || low == "on") {
        return true;
    }
    if (low == "false" || low == "0" || low == "no" || low == "n" || low == "off") {
        return false;
    }
    return default_val;
}

bool parseUintToken(const std::string& value, uint32_t& out) {
    std::string trimmed = trimCopy(value);
    if (trimmed.empty()) {
        return false;
    }
    const char* cstr = trimmed.c_str();
    char* end_ptr = nullptr;
    unsigned long long base = strtoull(cstr, &end_ptr, 10);
    if (end_ptr == cstr) {
        return false;
    }
    std::string suffix = trimCopy(std::string(end_ptr));
    std::string suffix_low = toLowerCopy(suffix);
    if (!suffix_low.empty()) {
        if (suffix_low == "ms" || suffix_low == "millis" || suffix_low == "millisecond" || suffix_low == "milliseconds") {
            // already milliseconds
        } else if (suffix_low == "s" || suffix_low == "sec" || suffix_low == "secs" ||
                   suffix_low == "second" || suffix_low == "seconds") {
            base *= 1000ULL;
        } else if (suffix_low == "m" || suffix_low == "min" || suffix_low == "mins" ||
                   suffix_low == "minute" || suffix_low == "minutes") {
            base *= 60000ULL;
        }
    }
    if (base > UINT32_MAX) {
        base = UINT32_MAX;
    }
    out = static_cast<uint32_t>(base);
    return true;
}

using KeyValuePairs = std::vector<std::pair<std::string, std::string>>;

KeyValuePairs parseKeyValuePairs(const std::string& text, size_t& consumed) {
    KeyValuePairs pairs;
    consumed = 0;
    const size_t n = text.size();

    while (consumed < n) {
        size_t pos = consumed;
        while (pos < n && std::isspace(static_cast<unsigned char>(text[pos]))) {
            ++pos;
        }
        if (pos >= n) {
            consumed = pos;
            break;
        }
        size_t eq = text.find('=', pos);
        if (eq == std::string::npos) {
            consumed = pos;
            break;
        }

        size_t key_end = eq;
        while (key_end > pos && std::isspace(static_cast<unsigned char>(text[key_end - 1]))) {
            --key_end;
        }
        std::string key = text.substr(pos, key_end - pos);

        size_t value_start = eq + 1;
        while (value_start < n && std::isspace(static_cast<unsigned char>(text[value_start]))) {
            ++value_start;
        }

        bool in_quotes = false;
        size_t value_end = value_start;
        while (value_end < n) {
            char c = text[value_end];
            if (c == '"' || c == '\'') {
                in_quotes = !in_quotes;
                ++value_end;
                continue;
            }
            if (!in_quotes && (c == ';' || c == ',' || c == '|')) {
                break;
            }
            if (!in_quotes && std::isspace(static_cast<unsigned char>(c))) {
                break;
            }
            ++value_end;
        }

        std::string value = text.substr(value_start, value_end - value_start);
        if (!key.empty()) {
            pairs.emplace_back(trimCopy(key), trimCopy(value));
        }

        consumed = value_end;
        if (consumed < n && (text[consumed] == ';' || text[consumed] == ',' || text[consumed] == '|')) {
            ++consumed;
        }
    }

    return pairs;
}

ProtocolType inferProtocolFromContext(const ScheduledScan& schedule,
                                      const std::string& target_hint,
                                      ProtocolType current) {
    if (current != ProtocolType::UNKNOWN) {
        return current;
    }

    const std::string name_low = toLowerCopy(PSRAMUtils::fromPSRAMString(schedule.name));
    if (name_low.find("modbus") != std::string::npos) return ProtocolType::MODBUS_TCP;
    if (name_low.find("s7") != std::string::npos || name_low.find("siemens") != std::string::npos) return ProtocolType::S7_COMM;
    if (name_low.find("opc") != std::string::npos) return ProtocolType::OPC_UA;
    if (name_low.find("ethernet") != std::string::npos || name_low.find("cip") != std::string::npos) return ProtocolType::ETHERNET_IP;
    if (name_low.find("profinet") != std::string::npos) return ProtocolType::PROFINET;

    const std::string target_low = toLowerCopy(target_hint);
    if (target_low.find("modbus") != std::string::npos) return ProtocolType::MODBUS_TCP;
    if (target_low.find("s7") != std::string::npos || target_low.find("siemens") != std::string::npos) return ProtocolType::S7_COMM;
    if (target_low.find("opc") != std::string::npos) return ProtocolType::OPC_UA;
    if (target_low.find("ethernetip") != std::string::npos || target_low.find("ethernet-ip") != std::string::npos ||
        target_low.find("cip") != std::string::npos) return ProtocolType::ETHERNET_IP;
    if (target_low.find("profinet") != std::string::npos) return ProtocolType::PROFINET;

    // Port-based heuristic
    size_t colon = target_hint.rfind(':');
    if (colon != std::string::npos && colon + 1 < target_hint.size()) {
        std::string port_token = trimCopy(target_hint.substr(colon + 1));
        uint32_t port_val = 0;
        if (parseUintToken(port_token, port_val)) {
            if (port_val == 502) return ProtocolType::MODBUS_TCP;
            if (port_val == 102) return ProtocolType::S7_COMM;
            if (port_val == 4840) return ProtocolType::OPC_UA;
            if (port_val == 44818 || port_val == 2222) return ProtocolType::ETHERNET_IP;
        }
    }

    return ProtocolType::UNKNOWN;
}

struct ScheduleExecParams {
    bool ok = false;
    ProtocolType protocol = ProtocolType::UNKNOWN;
    std::string target;
    uint32_t timeout_ms = 60000;
    bool is_general = false;
    BasePlugin::GeneralDiscoveryConfig general_cfg;
    std::string error;
};

ScheduleExecParams parseScheduleDescriptor(const ScheduledScan& schedule) {
    ScheduleExecParams params;
    params.protocol = schedule.protocol;
    params.general_cfg = BasePlugin::GeneralDiscoveryConfig();

    const std::string raw_descriptor = trimCopy(PSRAMUtils::fromPSRAMString(schedule.target));
    if (raw_descriptor.empty()) {
        params.error = "Error: empty schedule target";
        return params;
    }

    std::string working = raw_descriptor;
    std::string prefix_proto;
    const size_t scheme_pos = working.find("://");
    if (scheme_pos != std::string::npos) {
        prefix_proto = working.substr(0, scheme_pos);
        working = working.substr(scheme_pos + 3);
    }

    size_t consumed = 0;
    KeyValuePairs kv = parseKeyValuePairs(working, consumed);
    std::string leftover = trimCopy(working.substr(consumed));
    if (kv.empty() && leftover.empty()) {
        // No key/value pairs, use remaining string as target
        leftover = trimCopy(working);
    }

    // Resolve protocol hints
    if (params.protocol == ProtocolType::UNKNOWN && !prefix_proto.empty()) {
        params.protocol = protocolFromToken(prefix_proto);
    }
    for (const auto& pair : kv) {
        const std::string key_low = toLowerCopy(pair.first);
        if (key_low == "proto" || key_low == "protocol") {
            params.protocol = protocolFromToken(pair.second);
        }
    }

    // Determine timeout if provided
    for (const auto& pair : kv) {
        const std::string key_low = toLowerCopy(pair.first);
        uint32_t parsed = 0;
        if ((key_low == "timeout" || key_low == "timeout_ms") && parseUintToken(pair.second, parsed)) {
            params.timeout_ms = parsed;
        } else if ((key_low == "timeout_s" || key_low == "timeout_sec" || key_low == "timeout_seconds") &&
                   parseUintToken(pair.second, parsed)) {
            params.timeout_ms = parsed * 1000U;
        }
    }

    std::string target_value;
    for (const auto& pair : kv) {
        const std::string key_low = toLowerCopy(pair.first);
        if (key_low == "target" || key_low == "host" || key_low == "range") {
            target_value = trimCopy(pair.second);
            break;
        }
    }
    if (target_value.empty()) {
        target_value = leftover;
    }
    if (target_value.empty()) {
        target_value = raw_descriptor;
    }

    params.protocol = inferProtocolFromContext(schedule, target_value, params.protocol);

    // Identify general discovery mode
    bool explicit_general = false;
    if (!prefix_proto.empty()) {
        const std::string low_prefix = toLowerCopy(prefix_proto);
        if (low_prefix == "general" || low_prefix == "generic") {
            explicit_general = true;
        }
    }
    for (const auto& pair : kv) {
        const std::string key_low = toLowerCopy(pair.first);
        if ((key_low == "proto" || key_low == "protocol") &&
            protocolFromToken(pair.second) == ProtocolType::UNKNOWN &&
            toLowerCopy(trimCopy(pair.second)) == "general") {
            explicit_general = true;
        }
    }

    params.is_general = (schedule.type == ScheduledScanType::DISCOVERY_SCAN) && explicit_general;

    if (params.is_general) {
        params.general_cfg.target = PSRAMUtils::createPSRAMString(target_value.c_str());
        params.general_cfg.total_timeout_ms = params.timeout_ms;
        params.general_cfg.mode_label = PSRAMUtils::createPSRAMString("ping");
        params.general_cfg.ping_scan = true;
        params.general_cfg.port_scan = false;

        for (const auto& pair : kv) {
            const std::string key_low = toLowerCopy(pair.first);
            if (key_low == "mode" || key_low == "scan") {
                const std::string mode_low = toLowerCopy(pair.second);
                if (mode_low.find("port") != std::string::npos) {
                    params.general_cfg.port_scan = true;
                    params.general_cfg.ping_scan = false;
                    params.general_cfg.mode_label = PSRAMUtils::createPSRAMString("ports");
                } else if (mode_low.find("ping") != std::string::npos) {
                    params.general_cfg.ping_scan = true;
                    params.general_cfg.port_scan = false;
                    params.general_cfg.mode_label = PSRAMUtils::createPSRAMString("ping");
                } else {
                    params.general_cfg.mode_label = PSRAMUtils::createPSRAMString(mode_low.c_str());
                }
            } else if (key_low == "ping") {
                params.general_cfg.ping_scan = parseBoolToken(pair.second, params.general_cfg.ping_scan);
            } else if (key_low == "port_scan") {
                params.general_cfg.port_scan = parseBoolToken(pair.second, params.general_cfg.port_scan);
            } else if (key_low == "ports") {
                PSRAMAllocator<uint16_t> alloc;
                psram_vector<uint16_t> parsed_ports(alloc);
                std::stringstream ss(pair.second);
                std::string token;
                while (std::getline(ss, token, ',')) {
                    uint32_t port_val = 0;
                    if (parseUintToken(token, port_val)) {
                        parsed_ports.push_back(static_cast<uint16_t>(std::min<uint32_t>(port_val, 65535U)));
                    }
                }
                if (!parsed_ports.empty()) {
                    params.general_cfg.ports = parsed_ports;
                }
            } else if (key_low == "per_host_timeout" || key_low == "per_host_timeout_ms") {
                uint32_t per_host = 0;
                if (parseUintToken(pair.second, per_host)) {
                    params.general_cfg.per_host_timeout_ms = per_host;
                }
            } else if (key_low == "connect_timeout" || key_low == "connect_timeout_ms") {
                uint32_t connect_to = 0;
                if (parseUintToken(pair.second, connect_to)) {
                    params.general_cfg.connect_timeout_ms = connect_to;
                }
            } else if (key_low == "batch_size") {
                uint32_t value = 0;
                if (parseUintToken(pair.second, value) && value > 0U) {
                    params.general_cfg.batch_size = value;
                }
            } else if (key_low == "batch_delay" || key_low == "batch_delay_ms") {
                uint32_t value = 0;
                if (parseUintToken(pair.second, value)) {
                    params.general_cfg.batch_delay_ms = value;
                }
            } else if (key_low == "max_hosts") {
                uint32_t value = 0;
                if (parseUintToken(pair.second, value) && value > 0U) {
                    params.general_cfg.max_hosts = value;
                }
            } else if (key_low == "emit_progress") {
                params.general_cfg.emit_progress_events = parseBoolToken(pair.second, true);
            }
        }

        if (params.general_cfg.target.empty()) {
            params.general_cfg.target = PSRAMUtils::createPSRAMString(target_value.c_str());
        }
        params.target = target_value;
        params.ok = true;
        return params;
    }

    if (params.protocol == ProtocolType::UNKNOWN &&
        schedule.type == ScheduledScanType::VULNERABILITY_SCAN) {
        params.error = "Error: protocol not specified for vulnerability scan";
        return params;
    }

    if (!params.is_general &&
        schedule.type == ScheduledScanType::DISCOVERY_SCAN &&
        params.protocol == ProtocolType::UNKNOWN) {
        params.error = "Error: protocol not specified for discovery scan";
        return params;
    }

    if (target_value.empty()) {
        params.error = "Error: target not specified";
        return params;
    }

    params.target = target_value;
    params.ok = true;
    return params;
}

} // namespace
CronScheduler::CronScheduler()
    : vuln_scanner_(nullptr)
    , discovery_mgr_(nullptr)
    , mutex_(nullptr)
    , timer_(nullptr)
    , initialized_(false)
    , saver_task_(nullptr)
    , saver_queue_(nullptr)
{
    PSRAMAllocator<ScheduledScan> alloc;
    schedules_ = psram_vector<ScheduledScan>(alloc);
}

CronScheduler::~CronScheduler() {
    shutdown();

    destroySaverTask();
}

bool CronScheduler::initialize(VulnerabilityScanner* vuln_scanner, DiscoveryManager* discovery_mgr) {
    if (initialized_) {
        LOG_WARNING(TAG_CRON, "CronScheduler already initialized");
        return true;
    }

    if (!vuln_scanner || !discovery_mgr) {
        LOG_ERROR(TAG_CRON, "Invalid scanner or discovery manager reference");
        return false;
    }

    vuln_scanner_ = vuln_scanner;
    discovery_mgr_ = discovery_mgr;

    // Create mutex
    mutex_ = xSemaphoreCreateMutex();
    if (!mutex_) {
        LOG_ERROR(TAG_CRON, "Failed to create mutex");
        return false;
    }

    // Load schedules from NVS
    loadSchedulesFromNVS();

    // Create FreeRTOS timer (periodic, 1 minute interval)
    timer_ = xTimerCreate("CronTimer", pdMS_TO_TICKS(CHECK_INTERVAL_MS), pdTRUE, this, timerCallback);
    if (!timer_) {
        LOG_ERROR(TAG_CRON, "Failed to create FreeRTOS timer");
        vSemaphoreDelete(mutex_);
        mutex_ = nullptr;
        return false;
    }

    // Start timer
    if (xTimerStart(timer_, 0) != pdPASS) {
        LOG_ERROR(TAG_CRON, "Failed to start timer");
        xTimerDelete(timer_, 0);
        timer_ = nullptr;
        vSemaphoreDelete(mutex_);
        mutex_ = nullptr;
        return false;
    }

    initializeSaverTask();

    if (!saver_task_) {
        LOG_ERROR(TAG_CRON, "Saver task unavailable, aborting CronScheduler initialization");
        destroySaverTask();
        xTimerStop(timer_, 0);
        xTimerDelete(timer_, 0);
        timer_ = nullptr;
        vSemaphoreDelete(mutex_);
        mutex_ = nullptr;
        return false;
    }

    initialized_ = true;
    LOG_INFOF(TAG_CRON, "CronScheduler initialized with %zu schedules", schedules_.size());
    return true;
}

void CronScheduler::requestSaveSchedules() {
    if (!initialized_) {
        return;
    }

    if (!saver_queue_) {
        initializeSaverTask();
    }

    if (!saver_queue_) {
        LOG_ERROR(TAG_CRON, "Saver queue unavailable, unable to enqueue save request");
        return;
    }

    const uint8_t command = CRON_SAVER_CMD_SAVE;
    if (xQueueSendToBack(saver_queue_, &command, 0) != pdTRUE) {
        // Queue already holds a pending save; this is acceptable because il worker la processerà a breve.
        LOG_DEBUG(TAG_CRON, "Save request queue full, keeping existing pending request");
    }
}

void CronScheduler::initializeSaverTask() {
    if (saver_task_) {
        return;
    }

    // Allocate queue storage in PSRAM
    if (!saver_queue_storage_) {
        const size_t queue_storage_bytes = CRON_SAVER_QUEUE_LENGTH * sizeof(uint8_t);
        saver_queue_storage_ = static_cast<uint8_t*>(heap_caps_malloc(queue_storage_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (!saver_queue_storage_) {
            LOG_ERROR(TAG_CRON, "Failed to allocate saver queue storage in PSRAM");
            destroySaverTask();
            return;
        }
        memset(saver_queue_storage_, 0, queue_storage_bytes);
    }

    if (!saver_queue_struct_) {
        saver_queue_struct_ = static_cast<StaticQueue_t*>(heap_caps_malloc(sizeof(StaticQueue_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (!saver_queue_struct_) {
            LOG_ERROR(TAG_CRON, "Failed to allocate saver queue control block in PSRAM");
            destroySaverTask();
            return;
        }
        memset(saver_queue_struct_, 0, sizeof(StaticQueue_t));
    }

    if (!saver_queue_) {
        saver_queue_ = xQueueCreateStatic(
            CRON_SAVER_QUEUE_LENGTH,
            sizeof(uint8_t),
            saver_queue_storage_,
            saver_queue_struct_
        );
        if (!saver_queue_) {
            LOG_ERROR(TAG_CRON, "Failed to create saver queue");
            destroySaverTask();
            return;
        }
    }

    // Allocate task structures (stack in INTERNAL RAM because this task touches NVS/flash paths)
    if (!saver_stack_) {
        saver_stack_ = static_cast<StackType_t*>(heap_caps_malloc(
            CRON_SAVER_STACK_WORDS * sizeof(StackType_t),
            MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        if (!saver_stack_) {
            LOG_ERROR(TAG_CRON, "Failed to allocate saver task stack in INTERNAL RAM");
            destroySaverTask();
            return;
        }
        memset(saver_stack_, 0, CRON_SAVER_STACK_WORDS * sizeof(StackType_t));
    }

    if (!saver_tcb_) {
        saver_tcb_ = static_cast<StaticTask_t*>(heap_caps_malloc(sizeof(StaticTask_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        if (!saver_tcb_) {
            LOG_ERROR(TAG_CRON, "Failed to allocate saver task control block");
            destroySaverTask();
            return;
        }
        memset(saver_tcb_, 0, sizeof(StaticTask_t));
    }

    saver_task_active_ = false;
    saver_task_ = xTaskCreateStaticPinnedToCore(
        saverTaskEntry,
        "CronSaver",
        CRON_SAVER_STACK_WORDS,
        this,
        CRON_SAVER_TASK_PRIORITY,
        saver_stack_,
        saver_tcb_,
        tskNO_AFFINITY
    );

    if (!saver_task_) {
        LOG_ERROR(TAG_CRON, "Failed to create saver task");
        destroySaverTask();
        return;
    }

    saver_task_active_ = true;
    LOG_INFO(TAG_CRON, "CronScheduler saver task initialized in INTERNAL RAM");
}

void CronScheduler::destroySaverTask() {
    if (saver_task_) {
        const uint8_t command = CRON_SAVER_CMD_SHUTDOWN;
        if (saver_queue_) {
            if (xQueueSendToBack(saver_queue_, &command, pdMS_TO_TICKS(200)) != pdTRUE) {
                LOG_WARNING(TAG_CRON, "Saver queue busy during shutdown, forcing reset");
                xQueueReset(saver_queue_);
                xQueueSendToBack(saver_queue_, &command, pdMS_TO_TICKS(50));
            }
        }

        TickType_t waited = 0;
        const TickType_t step = pdMS_TO_TICKS(20);
#if (INCLUDE_xTaskGetSchedulerState == 1)
        const BaseType_t scheduler_running = xTaskGetSchedulerState() == taskSCHEDULER_RUNNING;
#else
        const BaseType_t scheduler_running = pdTRUE;
#endif
        while (saver_task_ && saver_task_active_ && waited < pdMS_TO_TICKS(500)) {
            if (!scheduler_running) {
                break;
            }
            vTaskDelay(step);
            waited += step;
        }

        if (saver_task_) {
            LOG_WARNING(TAG_CRON, "Saver task did not exit gracefully, forcing deletion");
            vTaskDelete(saver_task_);
            saver_task_ = nullptr;
            saver_task_active_ = false;
        }
    }

    if (saver_queue_) {
        vQueueDelete(saver_queue_);
        saver_queue_ = nullptr;
    }

    if (saver_queue_struct_) {
        heap_caps_free(saver_queue_struct_);
        saver_queue_struct_ = nullptr;
    }

    if (saver_queue_storage_) {
        heap_caps_free(saver_queue_storage_);
        saver_queue_storage_ = nullptr;
    }

    if (saver_stack_) {
        heap_caps_free(saver_stack_);
        saver_stack_ = nullptr;
    }

    if (saver_tcb_) {
        heap_caps_free(saver_tcb_);
        saver_tcb_ = nullptr;
    }

    LOG_INFO(TAG_CRON, "CronScheduler saver task resources released");
}

void CronScheduler::saverTaskEntry(void* arg) {
    CronScheduler* self = static_cast<CronScheduler*>(arg);
    if (self) {
        self->saverTaskLoop();
    }
    vTaskDelete(nullptr);
}

void CronScheduler::saverTaskLoop() {
    LOG_INFO(TAG_CRON, "CronScheduler saver task started");
    uint32_t save_counter = 0;

    while (true) {
        uint8_t command = 0;
        if (xQueueReceive(saver_queue_, &command, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        if (command == CRON_SAVER_CMD_SHUTDOWN) {
            break;
        }

        if (command != CRON_SAVER_CMD_SAVE) {
            continue;
        }

        if (!mutex_) {
            LOG_WARNING(TAG_CRON, "Saver task received save request without mutex available");
            continue;
        }

        if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(5000)) != pdTRUE) {
            LOG_WARNING(TAG_CRON, "Saver task could not acquire mutex, re-queueing save request");
            const uint8_t retry_command = CRON_SAVER_CMD_SAVE;
            xQueueSendToBack(saver_queue_, &retry_command, 0);
            continue;
        }

        const bool saved = saveSchedulesToNVS();
        xSemaphoreGive(mutex_);

        save_counter++;

        if (!saved) {
            LOG_ERROR(TAG_CRON, "Failed to persist schedules to NVS");
        }
    }

    saver_task_active_ = false;
    saver_task_ = nullptr;
    LOG_INFO(TAG_CRON, "CronScheduler saver task stopping");
}

void CronScheduler::shutdown() {
    if (!initialized_) {
        return;
    }

    // Stop and delete timer
    if (timer_) {
        xTimerStop(timer_, portMAX_DELAY);
        xTimerDelete(timer_, portMAX_DELAY);
        timer_ = nullptr;
    }

    destroySaverTask();

    // Delete mutex
    if (mutex_) {
        vSemaphoreDelete(mutex_);
        mutex_ = nullptr;
    }

    schedules_.clear();
    initialized_ = false;
    LOG_INFO(TAG_CRON, "CronScheduler shutdown complete");
}

void CronScheduler::timerCallback(TimerHandle_t timer) {
    CronScheduler* self = static_cast<CronScheduler*>(pvTimerGetTimerID(timer));
    if (self) {
        self->checkAndRunSchedules();
    }
}

void CronScheduler::checkAndRunSchedules() {
    if (!initialized_ || !mutex_) {
        return;
    }

    uint64_t now_ms = esp_timer_get_time() / 1000;

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_CRON, "Failed to acquire mutex for schedule check");
        return;
    }

    bool schedules_changed = false;
    for (auto& schedule : schedules_) {
        if (!schedule.enabled) {
            continue;
        }

        // Check if it's time to run
        if (now_ms >= schedule.next_run_ms) {
            LOG_INFOF(TAG_CRON, "Triggering scheduled scan: %s", schedule.name.c_str());
            executeSchedule(schedule);

            // Calculate next run time
            schedule.next_run_ms = calculateNextRun(schedule, now_ms);
            schedules_changed = true;
        }
    }

    xSemaphoreGive(mutex_);

    // Save only when something really changed (reduces NVS and CronSaver load)
    if (schedules_changed) {
        requestSaveSchedules();
    }
}

void CronScheduler::executeSchedule(ScheduledScan& schedule) {
    schedule.last_run_ms = esp_timer_get_time() / 1000;

    ScheduleExecParams params = parseScheduleDescriptor(schedule);
    if (!params.ok) {
        schedule.last_result = PSRAMUtils::createPSRAMString(params.error.c_str());
        LOG_WARNINGF(TAG_CRON, "Skipping schedule %s: %s", schedule.name.c_str(), params.error.c_str());
        return;
    }

    if (schedule.type == ScheduledScanType::VULNERABILITY_SCAN && vuln_scanner_) {
        schedule.protocol = params.protocol;
        psram_string target_ps = PSRAMUtils::createPSRAMString(params.target.c_str());
        uint32_t job_id = vuln_scanner_->runOnce(params.protocol, target_ps);
        if (job_id == 0) {
            schedule.last_result = PSRAMUtils::createPSRAMString("Error: failed to enqueue vulnerability scan");
            LOG_WARNINGF(TAG_CRON, "Vulnerability scan launch failed for %s", schedule.name.c_str());
        } else {
            char msg[192];
            snprintf(msg, sizeof(msg), "Vulnerability job %lu queued for %s",
                     static_cast<unsigned long>(job_id), params.target.c_str());
            schedule.last_result = PSRAMUtils::createPSRAMString(msg);
            LOG_INFOF(TAG_CRON, "Scheduled vulnerability job %lu for %s",
                      static_cast<unsigned long>(job_id), schedule.name.c_str());
        }
    } else if (schedule.type == ScheduledScanType::DISCOVERY_SCAN && discovery_mgr_) {
        schedule.protocol = params.protocol;
        psram_string discovery_id;
        if (params.is_general) {
            if (params.general_cfg.target.empty() && !params.target.empty()) {
                params.general_cfg.target = PSRAMUtils::createPSRAMString(params.target.c_str());
            }
            discovery_id = discovery_mgr_->startGeneralDiscovery(params.general_cfg);
        } else {
            discovery_id = discovery_mgr_->startDiscovery(params.protocol, params.target.c_str(), params.timeout_ms);
        }

        if (discovery_id.empty()) {
            schedule.last_result = PSRAMUtils::createPSRAMString("Error: discovery launch failed");
            LOG_WARNINGF(TAG_CRON, "Discovery start failed for schedule %s", schedule.name.c_str());
        } else {
            char msg[192];
            snprintf(msg, sizeof(msg), "Discovery %s started (target=%s)",
                     discovery_id.c_str(), params.target.c_str());
            schedule.last_result = PSRAMUtils::createPSRAMString(msg);
            LOG_INFOF(TAG_CRON, "Started discovery %s for schedule %s",
                      discovery_id.c_str(), schedule.name.c_str());
        }
    } else {
        schedule.last_result = PSRAMUtils::createPSRAMString("Error: invalid configuration (missing engine)");
        LOG_WARNINGF(TAG_CRON, "Cannot execute schedule %s: invalid type or missing engine", schedule.name.c_str());
    }
}

psram_string CronScheduler::addSchedule(const ScheduledScan& schedule) {
    if (!initialized_ || !mutex_) {
        return PSRAMUtils::createPSRAMString("");
    }

    ScheduledScan new_schedule = schedule;
    new_schedule.id = generateScheduleId();

    // Calculate next run time
    uint64_t now_ms = esp_timer_get_time() / 1000;
    new_schedule.next_run_ms = calculateNextRun(new_schedule, now_ms);

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERROR(TAG_CRON, "Failed to acquire mutex for adding schedule");
        return PSRAMUtils::createPSRAMString("");
    }

    schedules_.push_back(new_schedule);
    xSemaphoreGive(mutex_);

    requestSaveSchedules();

    LOG_INFOF(TAG_CRON, "Added schedule: %s (ID: %s)", new_schedule.name.c_str(), new_schedule.id.c_str());
    return new_schedule.id;
}

bool CronScheduler::updateSchedule(const psram_string& id, const ScheduledScan& schedule) {
    if (!initialized_ || !mutex_) {
        return false;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERROR(TAG_CRON, "Failed to acquire mutex for updating schedule");
        return false;
    }

    bool found = false;
    for (auto& s : schedules_) {
        if (s.id == id) {
            // Preserve ID and history
            psram_string old_id = s.id;
            uint64_t old_last_run = s.last_run_ms;
            psram_string old_result = s.last_result;

            s = schedule;
            s.id = old_id;
            s.last_run_ms = old_last_run;
            s.last_result = old_result;

            // Recalculate next run
            uint64_t now_ms = esp_timer_get_time() / 1000;
            s.next_run_ms = calculateNextRun(s, now_ms);

            found = true;
            LOG_INFOF(TAG_CRON, "Updated schedule: %s", s.name.c_str());
            break;
        }
    }

    xSemaphoreGive(mutex_);

    if (found) {
        requestSaveSchedules();
    }

    return found;
}

bool CronScheduler::removeSchedule(const psram_string& id) {
    if (!initialized_ || !mutex_) {
        return false;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERROR(TAG_CRON, "Failed to acquire mutex for removing schedule");
        return false;
    }

    bool found = false;
    for (auto it = schedules_.begin(); it != schedules_.end(); ++it) {
        if (it->id == id) {
            LOG_INFOF(TAG_CRON, "Removing schedule: %s", it->name.c_str());
            schedules_.erase(it);
            found = true;
            break;
        }
    }

    xSemaphoreGive(mutex_);

    if (found) {
        requestSaveSchedules();
    }

    return found;
}

bool CronScheduler::enableSchedule(const psram_string& id, bool enabled) {
    if (!initialized_ || !mutex_) {
        return false;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERROR(TAG_CRON, "Failed to acquire mutex for enabling/disabling schedule");
        return false;
    }

    bool found = false;
    for (auto& s : schedules_) {
        if (s.id == id) {
            s.enabled = enabled;
            found = true;
            LOG_INFOF(TAG_CRON, "Schedule %s %s", s.name.c_str(), enabled ? "enabled" : "disabled");
            break;
        }
    }

    xSemaphoreGive(mutex_);

    if (found) {
        requestSaveSchedules();
    }

    return found;
}

psram_vector<ScheduledScan> CronScheduler::listSchedules() const {
    PSRAMAllocator<ScheduledScan> alloc;
    psram_vector<ScheduledScan> result(alloc);

    if (!initialized_ || !mutex_) {
        return result;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_CRON, "Failed to acquire mutex for listing schedules");
        return result;
    }

    result = schedules_;
    xSemaphoreGive(mutex_);

    return result;
}

bool CronScheduler::getSchedule(const psram_string& id, ScheduledScan& out) const {
    if (!initialized_ || !mutex_) {
        return false;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_WARNING(TAG_CRON, "Failed to acquire mutex for getting schedule");
        return false;
    }

    bool found = false;
    for (const auto& s : schedules_) {
        if (s.id == id) {
            out = s;
            found = true;
            break;
        }
    }

    xSemaphoreGive(mutex_);
    return found;
}

bool CronScheduler::triggerSchedule(const psram_string& id) {
    if (!initialized_ || !mutex_) {
        return false;
    }

    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(1000)) != pdTRUE) {
        LOG_ERROR(TAG_CRON, "Failed to acquire mutex for triggering schedule");
        return false;
    }

    bool found = false;
    for (auto& s : schedules_) {
        if (s.id == id) {
            LOG_INFOF(TAG_CRON, "Manually triggering schedule: %s", s.name.c_str());
            executeSchedule(s);
            found = true;
            break;
        }
    }

    xSemaphoreGive(mutex_);

    if (found) {
        requestSaveSchedules();
    }

    return found;
}

uint64_t CronScheduler::calculateNextRun(const ScheduledScan& schedule, uint64_t after_time_ms) {
    // Convert ms to seconds for time_t
    time_t after_time = after_time_ms / 1000;
    struct tm timeinfo;
    localtime_r(&after_time, &timeinfo);

    // Start from next minute
    timeinfo.tm_sec = 0;
    timeinfo.tm_min++;
    mktime(&timeinfo); // Normalize

    // Search for next matching time (max 366 days ahead)
    for (int days = 0; days < 366; days++) {
        for (int hours = 0; hours < 24; hours++) {
            for (int minutes = 0; minutes < 60; minutes++) {
                if (matchesCronExpression(schedule, timeinfo)) {
                    time_t next_time = mktime(&timeinfo);
                    return (uint64_t)next_time * 1000;
                }

                timeinfo.tm_min++;
                mktime(&timeinfo); // Normalize
            }
        }
    }

    // If no match found in 366 days, return 1 year from now
    return after_time_ms + (366ULL * 24 * 60 * 60 * 1000);
}

bool CronScheduler::matchesCronExpression(const ScheduledScan& schedule, const struct tm& time) {
    // Check minute
    if (schedule.minute >= 0 && schedule.minute != time.tm_min) {
        return false;
    }

    // Check hour
    if (schedule.hour >= 0 && schedule.hour != time.tm_hour) {
        return false;
    }

    // Check day of month
    if (schedule.day_of_month >= 1 && schedule.day_of_month != time.tm_mday) {
        return false;
    }

    // Check month (tm_mon is 0-11, schedule.month is 1-12)
    if (schedule.month >= 1 && (schedule.month - 1) != time.tm_mon) {
        return false;
    }

    // Check day of week
    if (schedule.day_of_week >= 0 && schedule.day_of_week != time.tm_wday) {
        return false;
    }

    return true;
}

psram_string CronScheduler::generateScheduleId() {
    uint32_t random = esp_timer_get_time() & 0xFFFFFFFF;
    char id_buf[16];
    snprintf(id_buf, sizeof(id_buf), "sched_%08lx", (unsigned long)random);
    return PSRAMUtils::createPSRAMString(id_buf);
}

bool CronScheduler::loadSchedulesFromNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cron", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        LOG_INFOF(TAG_CRON, "No existing schedules in NVS: %s", esp_err_to_name(err));
        return false;
    }

    // Get number of schedules
    uint32_t count = 0;
    err = nvs_get_u32(handle, "count", &count);
    if (err != ESP_OK || count == 0) {
        nvs_close(handle);
        LOG_INFO(TAG_CRON, "No schedules found in NVS");
        return false;
    }

    schedules_.clear();

    // Load each schedule
    for (uint32_t i = 0; i < count && i < 50; i++) { // Max 50 schedules
        char prefix[16];
        snprintf(prefix, sizeof(prefix), "s%lu_", (unsigned long)i);

        ScheduledScan schedule;

        // Load string fields
        char key[32];
        size_t len;

        // ID
        snprintf(key, sizeof(key), "%sid", prefix);
        if (nvs_get_str(handle, key, NULL, &len) == ESP_OK && len > 0) {
            char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
            if (buf) {
                nvs_get_str(handle, key, buf, &len);
                schedule.id = PSRAMUtils::createPSRAMString(buf);
                heap_caps_free(buf);
            }
        }

        // Name
        snprintf(key, sizeof(key), "%sname", prefix);
        if (nvs_get_str(handle, key, NULL, &len) == ESP_OK && len > 0) {
            char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
            if (buf) {
                nvs_get_str(handle, key, buf, &len);
                schedule.name = PSRAMUtils::createPSRAMString(buf);
                heap_caps_free(buf);
            }
        }

        // Target
        snprintf(key, sizeof(key), "%stgt", prefix);
        if (nvs_get_str(handle, key, NULL, &len) == ESP_OK && len > 0) {
            char* buf = (char*)heap_caps_malloc(len, MALLOC_CAP_SPIRAM);
            if (buf) {
                nvs_get_str(handle, key, buf, &len);
                schedule.target = PSRAMUtils::createPSRAMString(buf);
                heap_caps_free(buf);
            }
        }

        // Load integer fields
        uint8_t u8_val;
        int8_t i8_val;
        uint64_t u64_val;

        snprintf(key, sizeof(key), "%stype", prefix);
        if (nvs_get_u8(handle, key, &u8_val) == ESP_OK) {
            schedule.type = static_cast<ScheduledScanType>(u8_val);
        }

        snprintf(key, sizeof(key), "%sproto", prefix);
        if (nvs_get_u8(handle, key, &u8_val) == ESP_OK) {
            if (u8_val <= static_cast<uint8_t>(ProtocolType::CUSTOM)) {
                schedule.protocol = static_cast<ProtocolType>(u8_val);
            } else {
                schedule.protocol = ProtocolType::UNKNOWN;
            }
        }

        snprintf(key, sizeof(key), "%senabled", prefix);
        if (nvs_get_u8(handle, key, &u8_val) == ESP_OK) {
            schedule.enabled = (u8_val != 0);
        }

        snprintf(key, sizeof(key), "%smin", prefix);
        if (nvs_get_i8(handle, key, &i8_val) == ESP_OK) {
            schedule.minute = i8_val;
        }

        snprintf(key, sizeof(key), "%shour", prefix);
        if (nvs_get_i8(handle, key, &i8_val) == ESP_OK) {
            schedule.hour = i8_val;
        }

        snprintf(key, sizeof(key), "%sdom", prefix);
        if (nvs_get_i8(handle, key, &i8_val) == ESP_OK) {
            schedule.day_of_month = i8_val;
        }

        snprintf(key, sizeof(key), "%smon", prefix);
        if (nvs_get_i8(handle, key, &i8_val) == ESP_OK) {
            schedule.month = i8_val;
        }

        snprintf(key, sizeof(key), "%sdow", prefix);
        if (nvs_get_i8(handle, key, &i8_val) == ESP_OK) {
            schedule.day_of_week = i8_val;
        }

        snprintf(key, sizeof(key), "%slast", prefix);
        if (nvs_get_u64(handle, key, &u64_val) == ESP_OK) {
            schedule.last_run_ms = u64_val;
        }

        snprintf(key, sizeof(key), "%snext", prefix);
        if (nvs_get_u64(handle, key, &u64_val) == ESP_OK) {
            schedule.next_run_ms = u64_val;
        }

        schedules_.push_back(schedule);
    }

    nvs_close(handle);
    LOG_INFOF(TAG_CRON, "Loaded %zu schedules from NVS", schedules_.size());
    return true;
}

bool CronScheduler::saveSchedulesToNVS() {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("cron", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG_CRON, "Failed to open NVS for writing: %s", esp_err_to_name(err));
        return false;
    }

    // Clear all old data
    nvs_erase_all(handle);

    // Save count
    uint32_t count = (uint32_t)schedules_.size();
    err = nvs_set_u32(handle, "count", count);
    if (err != ESP_OK) {
        nvs_close(handle);
        LOG_ERRORF(TAG_CRON, "Failed to write schedule count: %s", esp_err_to_name(err));
        return false;
    }

    // Save each schedule
    for (size_t i = 0; i < schedules_.size(); i++) {
        const ScheduledScan& s = schedules_[i];
        char prefix[16];
        snprintf(prefix, sizeof(prefix), "s%zu_", i);

        char key[32];

        // Save strings
        snprintf(key, sizeof(key), "%sid", prefix);
        nvs_set_str(handle, key, s.id.c_str());

        snprintf(key, sizeof(key), "%sname", prefix);
        nvs_set_str(handle, key, s.name.c_str());

        snprintf(key, sizeof(key), "%stgt", prefix);
        nvs_set_str(handle, key, s.target.c_str());

        // Save integers
        snprintf(key, sizeof(key), "%stype", prefix);
        nvs_set_u8(handle, key, static_cast<uint8_t>(s.type));

        snprintf(key, sizeof(key), "%sproto", prefix);
        nvs_set_u8(handle, key, static_cast<uint8_t>(s.protocol));

        snprintf(key, sizeof(key), "%senabled", prefix);
        nvs_set_u8(handle, key, s.enabled ? 1 : 0);

        snprintf(key, sizeof(key), "%smin", prefix);
        nvs_set_i8(handle, key, s.minute);

        snprintf(key, sizeof(key), "%shour", prefix);
        nvs_set_i8(handle, key, s.hour);

        snprintf(key, sizeof(key), "%sdom", prefix);
        nvs_set_i8(handle, key, s.day_of_month);

        snprintf(key, sizeof(key), "%smon", prefix);
        nvs_set_i8(handle, key, s.month);

        snprintf(key, sizeof(key), "%sdow", prefix);
        nvs_set_i8(handle, key, s.day_of_week);

        snprintf(key, sizeof(key), "%slast", prefix);
        nvs_set_u64(handle, key, s.last_run_ms);

        snprintf(key, sizeof(key), "%snext", prefix);
        nvs_set_u64(handle, key, s.next_run_ms);
    }

    err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        LOG_ERRORF(TAG_CRON, "Failed to commit NVS: %s", esp_err_to_name(err));
        return false;
    }

    return true;
}
