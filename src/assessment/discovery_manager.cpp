#include "discovery_manager.h"
#include "../core/types.h"
#include "../core/plugin_manager.h"
#include "../core/logging_system.h"
#include "../core/psram_allocator.h"
#include "../core/task_config.h"
#include "../core/reporting_engine.h"

extern "C" {
    #include "esp_task_wdt.h"
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "esp_random.h"
}

static portMUX_TYPE g_discovery_job_lock = portMUX_INITIALIZER_UNLOCKED;
static psram_map<TaskHandle_t, DiscoveryJob*> g_discovery_job_by_task;
static constexpr size_t kMaxRunningDiscoveriesTotal = 2;
static constexpr size_t kMaxRunningDiscoveriesPerProtocol = 1;
static constexpr size_t kMaxRunningGeneralDiscoveries = 1;

static inline void dm_registerCurrentJob(DiscoveryJob* job) {
    TaskHandle_t h = xTaskGetCurrentTaskHandle();
    portENTER_CRITICAL(&g_discovery_job_lock);
    g_discovery_job_by_task[h] = job;
    portEXIT_CRITICAL(&g_discovery_job_lock);
}

static inline void dm_unregisterCurrentJob() {
    TaskHandle_t h = xTaskGetCurrentTaskHandle();
    portENTER_CRITICAL(&g_discovery_job_lock);
    g_discovery_job_by_task.erase(h);
    portEXIT_CRITICAL(&g_discovery_job_lock);
}

static inline DiscoveryJob* dm_getCurrentJob() {
    TaskHandle_t h = xTaskGetCurrentTaskHandle();
    DiscoveryJob* job = nullptr;
    portENTER_CRITICAL(&g_discovery_job_lock);
    auto it = g_discovery_job_by_task.find(h);
    if (it != g_discovery_job_by_task.end()) {
        job = it->second;
    }
    portEXIT_CRITICAL(&g_discovery_job_lock);
    return job;
}

psram_string DiscoveryManager::startDiscovery(ProtocolType protocol, const char* target, uint32_t timeout_ms) {
    std::lock_guard<std::mutex> lock(discoveries_mutex_);

    if (!plugins_) {
        LOG_ERROR("DISCOVERY_MGR", "Plugin manager not available");
        return PSRAMUtils::createPSRAMString("");
    }

    // Pre-check plugin availability and log environment before spawning the task
    const char* proto_name = getProtocolName(protocol);
    BasePlugin* pre_plugin = plugins_->findByProtocol(protocol);
    size_t free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    size_t largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    LOG_INFOF("DISCOVERY_MGR", "Prep discovery for %s target %s (timeout=%u) | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u)",
              proto_name, target?target:"(null)", (unsigned)timeout_ms,
              (unsigned)free_iram, (unsigned)largest_iram, (unsigned)free_psram, (unsigned)largest_psram);
    if (!pre_plugin) {
        LOG_WARNINGF("DISCOVERY_MGR", "No plugin available for protocol %s - aborting", proto_name);
        return PSRAMUtils::createPSRAMString("");
    }

    size_t running_total = 0;
    size_t running_same_protocol = 0;
    for (const auto& pair : discoveries_) {
        const DiscoveryJob* existing = pair.second.get();
        if (!existing || existing->status != DiscoveryStatus::RUNNING) {
            continue;
        }
        running_total++;
        if (!existing->is_general && existing->protocol == protocol) {
            running_same_protocol++;
        }
    }
    if (running_total >= kMaxRunningDiscoveriesTotal) {
        LOG_WARNINGF("DISCOVERY_MGR",
                     "Reject discovery for %s: too many active jobs (%u/%u)",
                     getProtocolName(protocol),
                     (unsigned)running_total,
                     (unsigned)kMaxRunningDiscoveriesTotal);
        return "";
    }
    if (running_same_protocol >= kMaxRunningDiscoveriesPerProtocol) {
        LOG_WARNINGF("DISCOVERY_MGR",
                     "Reject discovery for %s: same protocol already running (%u/%u)",
                     getProtocolName(protocol),
                     (unsigned)running_same_protocol,
                     (unsigned)kMaxRunningDiscoveriesPerProtocol);
        return "";
    }

    // Generate unique ID for this discovery
    psram_string discovery_id = generateDiscoveryId();

    // Create new discovery job
    auto job = std::make_unique<DiscoveryJob>();
    job->id = discovery_id;
    job->protocol = protocol;
    job->target = PSRAMUtils::createPSRAMString(target);
    job->timeout_ms = timeout_ms;
    job->status = DiscoveryStatus::RUNNING;
    job->start_time_ms = getCurrentTimeMs();
    job->progress_percent = 0.0f;

    // Store the job
    discoveries_[discovery_id] = std::move(job);

    // Start background task for this discovery
    DiscoveryJob* job_ptr = discoveries_[discovery_id].get();

    // Use INTERNAL RAM stack for discovery tasks to satisfy lwIP/TLS requirements
    TaskHandle_t task_handle = TaskConfig::createTask(
        discoveryTask,
        "discovery_task",
        TaskConfig::Presets::DISCOVERY_PROTOCOL,
        job_ptr,
        1
    );

    if (!task_handle) {
        discoveries_.erase(discovery_id);
        // Log another snapshot to help diagnose allocation issues
        free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
        LOG_ERRORF("DISCOVERY_MGR", "Failed to create discovery task | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u)",
                   (unsigned)free_iram, (unsigned)largest_iram, (unsigned)free_psram, (unsigned)largest_psram);
        return "";
    }

    LOG_INFOF("DISCOVERY_MGR", "Started discovery %s for %s target %s",
              discovery_id.c_str(), getProtocolName(protocol), target);

    return discovery_id;
}

psram_string DiscoveryManager::startGeneralDiscovery(const BasePlugin::GeneralDiscoveryConfig& cfg) {
    std::lock_guard<std::mutex> lock(discoveries_mutex_);

    size_t running_total = 0;
    size_t running_general = 0;
    for (const auto& pair : discoveries_) {
        const DiscoveryJob* existing = pair.second.get();
        if (!existing || existing->status != DiscoveryStatus::RUNNING) {
            continue;
        }
        running_total++;
        if (existing->is_general) {
            running_general++;
        }
    }
    if (running_total >= kMaxRunningDiscoveriesTotal) {
        LOG_WARNINGF("DISCOVERY_MGR",
                     "Reject general discovery: too many active jobs (%u/%u)",
                     (unsigned)running_total,
                     (unsigned)kMaxRunningDiscoveriesTotal);
        return "";
    }
    if (running_general >= kMaxRunningGeneralDiscoveries) {
        LOG_WARNINGF("DISCOVERY_MGR",
                     "Reject general discovery: another general job is active (%u/%u)",
                     (unsigned)running_general,
                     (unsigned)kMaxRunningGeneralDiscoveries);
        return "";
    }

    size_t free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    size_t largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    const char* mode_label = cfg.mode_label.empty() ? (cfg.port_scan ? "ports" : "ping") : cfg.mode_label.c_str();
    const char* target_c = cfg.target.empty() ? "(null)" : cfg.target.c_str();

    LOG_INFOF("DISCOVERY_MGR", "Prep general discovery (mode=%s) target %s | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u)",
              mode_label,
              target_c,
              (unsigned)free_iram, (unsigned)largest_iram,
              (unsigned)free_psram, (unsigned)largest_psram);

    psram_string discovery_id = generateDiscoveryId();

    auto job = std::make_unique<DiscoveryJob>();
    job->id = discovery_id;
    job->protocol = ProtocolType::UNKNOWN;
    job->is_general = true;
    job->custom_protocol_name = PSRAMUtils::createPSRAMString("General Discovery");
    if (!cfg.mode_label.empty()) {
        job->mode_label = cfg.mode_label;
    } else {
        job->mode_label = PSRAMUtils::createPSRAMString(cfg.port_scan ? "ports" : "ping");
    }
    job->target = cfg.target.empty() ? PSRAMUtils::createPSRAMString("") : cfg.target;
    job->timeout_ms = cfg.total_timeout_ms;
    job->status = DiscoveryStatus::RUNNING;
    job->start_time_ms = getCurrentTimeMs();
    job->progress_percent = 0.0f;
    job->general_config = cfg;

    discoveries_[discovery_id] = std::move(job);
    DiscoveryJob* job_ptr = discoveries_[discovery_id].get();

    TaskHandle_t task_handle = TaskConfig::createTask(
        generalDiscoveryTask,
        "gen_discovery_task",
        TaskConfig::Presets::DISCOVERY_GENERAL,
        job_ptr,
        1
    );

    if (!task_handle) {
        discoveries_.erase(discovery_id);
        free_iram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        largest_iram = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        largest_psram = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
        LOG_ERRORF("DISCOVERY_MGR", "Failed to create general discovery task | IRAM free=%u (largest=%u) PSRAM free=%u (largest=%u)",
                   (unsigned)free_iram, (unsigned)largest_iram,
                   (unsigned)free_psram, (unsigned)largest_psram);
        return "";
    }

    LOG_INFOF("DISCOVERY_MGR", "Started general discovery %s (mode=%s) target %s",
              discovery_id.c_str(),
              mode_label,
              target_c);

    return discovery_id;
}

cJSON* DiscoveryManager::getDiscoveryStatus(const char* discovery_id) {
    std::lock_guard<std::mutex> lock(discoveries_mutex_);

    auto it = discoveries_.find(discovery_id);
    if (it == discoveries_.end()) {
        cJSON* response = cJSON_CreateObject();
        cJSON_AddBoolToObject(response, "found", false);
        cJSON_AddStringToObject(response, "message", "Discovery not found");
        return response;
    }

    return jobToJson(*it->second);
}

cJSON* DiscoveryManager::getAllDiscoveries() {
    std::lock_guard<std::mutex> lock(discoveries_mutex_);

    // Cleanup old discoveries first
    cleanupOldDiscoveries();

    cJSON* response = cJSON_CreateObject();
    cJSON* discoveries = cJSON_CreateArray();

    for (const auto& pair : discoveries_) {
        cJSON* job_json = jobToJson(*pair.second);
        cJSON_AddItemToArray(discoveries, job_json);
    }

    cJSON_AddItemToObject(response, "discoveries", discoveries);
    cJSON_AddNumberToObject(response, "total", cJSON_GetArraySize(discoveries));

    return response;
}

bool DiscoveryManager::cancelDiscovery(const char* discovery_id) {
    std::lock_guard<std::mutex> lock(discoveries_mutex_);

    auto it = discoveries_.find(discovery_id);
    if (it == discoveries_.end() || it->second->status != DiscoveryStatus::RUNNING) {
        return false;
    }

    it->second->status = DiscoveryStatus::CANCELLED;
    it->second->end_time_ms = getCurrentTimeMs();
    LOG_INFOF("DISCOVERY_MGR", "Cancelled discovery %s", discovery_id);

    return true;
}

void DiscoveryManager::cleanupOldDiscoveries() {
    uint64_t current_time = getCurrentTimeMs();
    const uint64_t TEN_MINUTES_MS = 10 * 60 * 1000;

    auto it = discoveries_.begin();
    while (it != discoveries_.end()) {
        const auto& job = it->second;

        // Remove completed/failed discoveries older than 10 minutes
        if ((job->status == DiscoveryStatus::COMPLETED ||
             job->status == DiscoveryStatus::FAILED ||
             job->status == DiscoveryStatus::CANCELLED) &&
            (current_time - job->end_time_ms > TEN_MINUTES_MS)) {

            LOG_DEBUGF("DISCOVERY_MGR", "Cleaning up old discovery %s", job->id.c_str());
            it = discoveries_.erase(it);
        } else {
            ++it;
        }
    }
}

void DiscoveryManager::discoveryTask(void* pvParameters) {
    DiscoveryJob* job = static_cast<DiscoveryJob*>(pvParameters);
    if (!job) {
        vTaskDelete(nullptr);
        return;
    }

    auto& manager = DiscoveryManager::getInstance();

    // Register this job for the current task for progress updates
    dm_registerCurrentJob(job);

    // Add to watchdog
    esp_task_wdt_add(nullptr);

    // Find the appropriate plugin

    LOG_INFOF("DISCOVERY_MGR", "Finding protocol %s", manager.getProtocolName(job->protocol));

    BasePlugin* plugin = manager.plugins_->findByProtocol(job->protocol);
    if (!plugin) {
        {
            std::lock_guard<std::mutex> lock(manager.discoveries_mutex_);
            job->status = DiscoveryStatus::FAILED;
            job->error_message = PSRAMUtils::createPSRAMString("Plugin not found");
            job->end_time_ms = manager.getCurrentTimeMs();
        }
        LOG_WARNINGF("DISCOVERY_MGR", "Plugin not found for protocol %s",
                    manager.getProtocolName(job->protocol));
    } else {
        LOG_INFOF("DISCOVERY_MGR", "Starting discovery for %s on target %s",
                 manager.getProtocolName(job->protocol), job->target.c_str());

        psram_string discovery_report;
        bool success = plugin->doNetworkDiscoveryPSRAM(job->target, job->timeout_ms, discovery_report);

        // Update job with results
        if (success && !discovery_report.empty()) {
            {
                std::lock_guard<std::mutex> lock(manager.discoveries_mutex_);
                job->status = DiscoveryStatus::COMPLETED;
                job->final_results = discovery_report;
                job->progress_percent = 100.0f;
            }

            // Send results to reporter
            if (manager.reporter_) {
                char event_name[128];
                snprintf(event_name, sizeof(event_name), "%s_async_discovery_result", manager.getProtocolName(job->protocol));
                manager.reporter_->reportEvent(PSRAMUtils::createPSRAMString(event_name), discovery_report);
            }

            LOG_INFOF("DISCOVERY_MGR", "Discovery %s completed successfully", job->id.c_str());
        } else {
            {
                std::lock_guard<std::mutex> lock(manager.discoveries_mutex_);
                job->status = DiscoveryStatus::FAILED;
                job->error_message = PSRAMUtils::createPSRAMString("No results returned");
            }

            LOG_WARNINGF("DISCOVERY_MGR", "Discovery %s failed - no results", job->id.c_str());
        }
    }

    {
        std::lock_guard<std::mutex> lock(manager.discoveries_mutex_);
        job->end_time_ms = manager.getCurrentTimeMs();
    }

    // Remove from watchdog
    esp_task_wdt_delete(nullptr);
    // Unregister from job tracking
    dm_unregisterCurrentJob();
    vTaskDelete(nullptr);
}

void DiscoveryManager::generalDiscoveryTask(void* pvParameters) {
    DiscoveryJob* job = static_cast<DiscoveryJob*>(pvParameters);
    if (!job) {
        vTaskDelete(nullptr);
        return;
    }

    auto& manager = DiscoveryManager::getInstance();

    dm_registerCurrentJob(job);
    esp_task_wdt_add(nullptr);

    const char* mode = job->mode_label.empty() ? "general" : job->mode_label.c_str();
    LOG_INFOF("DISCOVERY_MGR", "General discovery %s (mode=%s) starting on %s",
              job->id.c_str(), mode, job->target.c_str());

    std::string result = BasePlugin::runGeneralDiscovery(job->general_config, manager.reporter_, manager.cfg_);
    if (!result.empty()) {
        {
            std::lock_guard<std::mutex> lock(manager.discoveries_mutex_);
            job->status = DiscoveryStatus::COMPLETED;
            job->final_results = PSRAMUtils::createPSRAMString(result.c_str());
            job->progress_percent = 100.0f;
        }
        if (manager.reporter_) {
            psram_string type = PSRAMUtils::createPSRAMString("general_discovery_result");
            psram_string payload = PSRAMUtils::createPSRAMString(result.c_str());
            manager.reporter_->reportEvent(type, payload);
        }
        LOG_INFOF("DISCOVERY_MGR", "General discovery %s completed", job->id.c_str());
    } else {
        {
            std::lock_guard<std::mutex> lock(manager.discoveries_mutex_);
            if (job->status != DiscoveryStatus::CANCELLED) {
                job->status = DiscoveryStatus::FAILED;
                job->error_message = PSRAMUtils::createPSRAMString("No results returned");
            }
        }
        LOG_WARNINGF("DISCOVERY_MGR", "General discovery %s produced no output", job->id.c_str());
    }

    {
        std::lock_guard<std::mutex> lock(manager.discoveries_mutex_);
        job->end_time_ms = manager.getCurrentTimeMs();
    }

    esp_task_wdt_delete(nullptr);
    dm_unregisterCurrentJob();
    vTaskDelete(nullptr);
}

psram_string DiscoveryManager::generateDiscoveryId() {
    uint32_t random = esp_random();
    uint64_t timestamp = getCurrentTimeMs();

    char id_buffer[32];
    snprintf(id_buffer, sizeof(id_buffer), "disc_%08lx_%08lx",
             (unsigned long)(timestamp & 0xFFFFFFFF), (unsigned long)random);

    return PSRAMUtils::createPSRAMString(id_buffer);
}

uint64_t DiscoveryManager::getCurrentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

const char* DiscoveryManager::getProtocolName(ProtocolType protocol) {
    switch (protocol) {
        case ProtocolType::MODBUS_TCP: return "Modbus TCP";
        case ProtocolType::S7_COMM: return "S7 Comm";
        case ProtocolType::PROFINET: return "PROFINET";
        case ProtocolType::ETHERNET_IP: return "EtherNet/IP";
        case ProtocolType::OPC_UA: return "OPC UA";
        default: return "Unknown";
    }
}

cJSON* DiscoveryManager::jobToJson(const DiscoveryJob& job) {
    cJSON* json = cJSON_CreateObject();

    cJSON_AddStringToObject(json, "id", job.id.c_str());
    const char* proto_name = job.custom_protocol_name.empty() ? getProtocolName(job.protocol) : job.custom_protocol_name.c_str();
    cJSON_AddStringToObject(json, "protocol", proto_name);
    cJSON_AddStringToObject(json, "job_type", job.is_general ? "general" : "protocol");
    if (job.is_general && !job.mode_label.empty()) {
        cJSON_AddStringToObject(json, "mode", job.mode_label.c_str());
    }
    cJSON_AddStringToObject(json, "target", job.target.c_str());
    cJSON_AddNumberToObject(json, "timeout_ms", job.timeout_ms);

    const char* status_str = "unknown";
    switch (job.status) {
        case DiscoveryStatus::RUNNING: status_str = "running"; break;
        case DiscoveryStatus::COMPLETED: status_str = "completed"; break;
        case DiscoveryStatus::FAILED: status_str = "failed"; break;
        case DiscoveryStatus::CANCELLED: status_str = "cancelled"; break;
    }
    cJSON_AddStringToObject(json, "status", status_str);

    cJSON_AddNumberToObject(json, "start_time_ms", job.start_time_ms);
    cJSON_AddNumberToObject(json, "end_time_ms", job.end_time_ms);
    cJSON_AddNumberToObject(json, "progress_percent", job.progress_percent);

    // Live metrics (optional)
    if (job.hosts_enumerated > 0 || job.hosts_scanned > 0) {
        cJSON* live = cJSON_CreateObject();
        cJSON_AddNumberToObject(live, "hosts_enumerated", job.hosts_enumerated);
        cJSON_AddNumberToObject(live, "hosts_scanned", job.hosts_scanned);
        cJSON_AddNumberToObject(live, "hosts_connected", job.hosts_connected);
        cJSON_AddNumberToObject(live, "responses_mei", job.responses_mei);
        cJSON_AddNumberToObject(live, "responses_probe", job.responses_probe);
        if (!job.last_ip.empty()) cJSON_AddStringToObject(live, "ip_in_scansione", job.last_ip.c_str());
        cJSON_AddItemToObject(json, "live", live);
    }

    if (!job.partial_results.empty()) {
        // Try to parse partial results as JSON, fallback to string
        cJSON* partial = cJSON_Parse(job.partial_results.c_str());
        if (partial) {
            cJSON_AddItemToObject(json, "partial_results", partial);
        } else {
            cJSON_AddStringToObject(json, "partial_results", job.partial_results.c_str());
        }
    }

    if (!job.final_results.empty()) {
        // Try to parse final results as JSON, fallback to string
        cJSON* results = cJSON_Parse(job.final_results.c_str());
        if (results) {
            cJSON_AddItemToObject(json, "results", results);
        } else {
            cJSON_AddStringToObject(json, "results", job.final_results.c_str());
        }
    }

    if (!job.error_message.empty()) {
        cJSON_AddStringToObject(json, "error", job.error_message.c_str());
    }

    // Calculate duration
    uint64_t duration_ms = (job.end_time_ms > 0) ?
                          (job.end_time_ms - job.start_time_ms) :
                          (getCurrentTimeMs() - job.start_time_ms);
    cJSON_AddNumberToObject(json, "duration_ms", duration_ms);

    return json;
}



// Initialize totals for the current discovery task (TLS-bound)
void DiscoveryManager::initTotalsTLS(uint32_t total_hosts) {
    DiscoveryJob* job = dm_getCurrentJob();
    if (!job) return;
    std::lock_guard<std::mutex> lock(discoveries_mutex_);
    job->hosts_enumerated = total_hosts;
    job->hosts_scanned = 0;
    job->hosts_connected = 0;
    job->responses_mei = 0;
    job->responses_probe = 0;
    job->progress_percent = 0.0f;
}

// Update live progress (TLS-bound)
void DiscoveryManager::updateProgressTLS(const char* ip,
                                         uint32_t scanned,
                                         uint32_t connected,
                                         uint32_t mei,
                                         uint32_t probe) {
    DiscoveryJob* job = dm_getCurrentJob();
    if (!job) return;

    uint32_t hosts_enumerated = 0;
    psram_string last_ip_snapshot;
    float progress_percent = 0.0f;

    {
        std::lock_guard<std::mutex> lock(discoveries_mutex_);
        job->hosts_scanned = scanned;
        job->hosts_connected = connected;
        job->responses_mei = mei;
        job->responses_probe = probe;
        if (ip && *ip) {
            job->last_ip = PSRAMUtils::createPSRAMString(ip);
        }

        if (job->hosts_enumerated > 0) {
            float pct = (100.0f * (float)job->hosts_scanned) / (float)job->hosts_enumerated;
            if (pct > 100.0f) pct = 100.0f;
            job->progress_percent = pct;
        }

        hosts_enumerated = job->hosts_enumerated;
        last_ip_snapshot = job->last_ip;
        progress_percent = job->progress_percent;
    }

    // Build compact partial_results JSON outside the shared manager lock.
    cJSON* pr = cJSON_CreateObject();
    cJSON_AddNumberToObject(pr, "hosts_enumerated", hosts_enumerated);
    cJSON_AddNumberToObject(pr, "hosts_scanned", scanned);
    cJSON_AddNumberToObject(pr, "hosts_connected", connected);
    cJSON_AddNumberToObject(pr, "responses_mei", mei);
    cJSON_AddNumberToObject(pr, "responses_probe", probe);
    cJSON_AddNumberToObject(pr, "progress_percent", progress_percent);
    if (!last_ip_snapshot.empty()) {
        cJSON_AddStringToObject(pr, "ip_in_scansione", last_ip_snapshot.c_str());
    }
    char* js = cJSON_PrintUnformatted(pr);
    cJSON_Delete(pr);

    if (js) {
        std::lock_guard<std::mutex> lock(discoveries_mutex_);
        job->partial_results = PSRAMUtils::createPSRAMString(js);
        cJSON_free(js);
    }
}
