#include "fuzzing_engine.h"
#include "../core/logging_system.h"
#include "../core/reporting_engine.h"
#include "../core/plugin_manager.h"
#include "../protocols/base_plugin.h"
#include "../core/task_config.h"
#include "../security/security_manager.h"
#include "../core/detailed_report_builder.h"
extern "C" {
    #include "esp_random.h"
    #include "esp_timer.h"
}

#include <algorithm>
#include <random>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <map>


// Global fuzzing engine instance
FuzzingEngine* g_fuzz = nullptr;

#define TAG_FUZZ "FuzzingEngine"

// Note: fuzzResultToString removed - result descriptions are now handled inline with emoji

FuzzingEngine::FuzzingEngine(ReportingEngine* rep, SecurityManager* sec, Logger* log, PluginManager* pm)
: rep_(rep), sec_(sec), logger_(log), plugin_manager_(pm) {
    q_run_ = xQueueCreate(4, sizeof(uint32_t));
    worker_ = TaskConfig::createTask(&FuzzingEngine::workerTaskThunk,
                                   "fuzz_worker",
                                   TaskConfig::Presets::FUZZING_ENGINE,
                                   this, 1);
}

FuzzingEngine::~FuzzingEngine() {
    stop_flag_ = true;
    if (worker_) vTaskDelete(worker_);
    if (q_run_) vQueueDelete(q_run_);
}

// Helper function to convert ProtocolType to string
std::string FuzzingEngine::getProtocolName(ProtocolType proto) {
    switch (proto) {
        case ProtocolType::MODBUS_TCP: return "Modbus-TCP";
        case ProtocolType::S7_COMM: return "S7-Communication";
        case ProtocolType::OPC_UA: return "OPC-UA";
        case ProtocolType::ETHERNET_IP: return "EtherNet/IP";
        case ProtocolType::PROFINET: return "PROFINET";
        case ProtocolType::CUSTOM: return "Custom";
        default: return "Unknown";
    }
}

namespace {
struct OpcuaFuzzAttackMetadata {
    const char* attack_id;
    const char* category;
    const char* risk_domain;
    const char* expected_severity;
    int risk_rank;                 // 1=info, 2=low, 3=medium, 4=high, 5=critical
    const char* cwe_list;          // "|" separated
    const char* cve_list;          // "|" separated
    const char* references;        // "|" separated
};

static const OpcuaFuzzAttackMetadata* getOpcuaFuzzAttackMetadata(const char* attack_id) {
    if (!attack_id || !*attack_id) {
        return nullptr;
    }
    static const OpcuaFuzzAttackMetadata kMeta[] = {
        {"default",             "baseline",        "protocol_surface",      "info",     1, "", "", "OPC UA Part 6 UA-TCP"},
        {"anonymous_access",    "authentication",  "access_control",        "high",     4, "CWE-306|CWE-862", "", "OPC UA Part 4 Sessions"},
        {"weak_security_policies","crypto",        "transport_security",    "high",     4, "CWE-326|CWE-327", "", "OPC UA SecurityPolicy guidance"},
        {"certificate_bypass",  "crypto",          "pkix_validation",       "high",     4, "CWE-295", "CVE-2020-6069", "RFC 5280|OPC UA Part 6 Certificates"},
        {"session_hijacking",   "session",         "auth_session_integrity","high",     4, "CWE-287|CWE-384", "", "OPC UA SecureChannel/Session model"},
        {"browse_flooding",     "availability",    "resource_exhaustion",   "high",     4, "CWE-400|CWE-674", "CVE-2019-13585", "OPC UA Browse service limits"},
        {"chunk_exhaustion",    "availability",    "resource_exhaustion",   "critical", 5, "CWE-400", "CVE-2019-6575", "OPC UA chunk reassembly hardening"},
        {"protocol_violations", "protocol_parser", "state_machine",         "medium",   3, "CWE-20|CWE-444", "CVE-2017-12069|CVE-2017-15396", "OPC UA Binary Encoding (Part 6)"},
        {"string_attacks",      "input_validation","string_handling",       "medium",   3, "CWE-20|CWE-116|CWE-120", "CVE-2018-7559", "Secure coding for OPC UA parsers"},
        {"cve_based",           "regression_cve",  "known_exploits",        "high",     4, "CWE-400|CWE-295|CWE-120", "CVE-2019-6575|CVE-2018-7559|CVE-2017-12069|CVE-2017-15396|CVE-2018-7551|CVE-2019-13585|CVE-2020-6069|CVE-2020-10239", "CVE corpus from OPCUAFuzzingSeeds"},
        {"comprehensive",       "composite",       "multi_domain",          "critical", 5, "CWE-20|CWE-400|CWE-295|CWE-120", "CVE-2019-6575|CVE-2018-7559|CVE-2017-12069|CVE-2017-15396|CVE-2018-7551|CVE-2019-13585|CVE-2020-6069|CVE-2020-10239", "Full OPC UA fuzz campaign"}
    };

    for (size_t i = 0; i < (sizeof(kMeta) / sizeof(kMeta[0])); ++i) {
        if (strcmp(kMeta[i].attack_id, attack_id) == 0) {
            return &kMeta[i];
        }
    }
    return nullptr;
}

static void addDelimitedStringArray(cJSON* parent, const char* key, const char* delimited) {
    if (!parent || !key || !delimited || !*delimited) {
        return;
    }
    cJSON* arr = cJSON_CreateArray();
    if (!arr) {
        return;
    }

    const char* cur = delimited;
    while (*cur) {
        while (*cur == '|') {
            ++cur;
        }
        if (!*cur) {
            break;
        }
        const char* begin = cur;
        while (*cur && *cur != '|') {
            ++cur;
        }
        size_t len = static_cast<size_t>(cur - begin);
        if (len == 0U) {
            continue;
        }

        char token[196];
        if (len >= sizeof(token)) {
            len = sizeof(token) - 1U;
        }
        memcpy(token, begin, len);
        token[len] = '\0';
        cJSON_AddItemToArray(arr, cJSON_CreateString(token));
    }

    cJSON_AddItemToObject(parent, key, arr);
}

static void appendOpcuaAttackMetadata(cJSON* obj, const char* attack_id) {
    if (!obj || !attack_id || !*attack_id) {
        return;
    }
    const OpcuaFuzzAttackMetadata* meta = getOpcuaFuzzAttackMetadata(attack_id);
    if (!meta) {
        cJSON_AddStringToObject(obj, "attack_id", attack_id);
        cJSON_AddStringToObject(obj, "category", "unknown");
        cJSON_AddStringToObject(obj, "risk_domain", "unknown");
        cJSON_AddStringToObject(obj, "expected_severity", "info");
        return;
    }

    cJSON_AddStringToObject(obj, "attack_id", meta->attack_id);
    cJSON_AddStringToObject(obj, "category", meta->category);
    cJSON_AddStringToObject(obj, "risk_domain", meta->risk_domain);
    cJSON_AddStringToObject(obj, "expected_severity", meta->expected_severity);
    addDelimitedStringArray(obj, "cwe", meta->cwe_list);
    addDelimitedStringArray(obj, "cve", meta->cve_list);
    addDelimitedStringArray(obj, "references", meta->references);
}

struct EnipFuzzAttackMetadata {
    const char* attack_id;
    const char* category;
    const char* risk_domain;
    const char* expected_severity;
    int risk_rank;          // 1=info, 2=low, 3=medium, 4=high, 5=critical
    const char* cwe_list;   // "|" separated
    const char* cve_list;   // "|" separated
    const char* references; // "|" separated
};

static const EnipFuzzAttackMetadata* getEnipFuzzAttackMetadata(const char* attack_id) {
    if (!attack_id || !*attack_id) {
        return nullptr;
    }

    // Backward-compatible aliases.
    if (strcmp(attack_id, "session_flooding") == 0) attack_id = "session_handle_anomalies";
    if (strcmp(attack_id, "encapsulation_bypass") == 0) attack_id = "encap_malformed_headers";
    if (strcmp(attack_id, "identity_spoofing") == 0) attack_id = "cpf_item_confusion";
    if (strcmp(attack_id, "cip_attribute_manipulation") == 0) attack_id = "unauthorized_writes";

    static const EnipFuzzAttackMetadata kMeta[] = {
        {"default",                        "baseline",             "protocol_surface",       "info",     1, "", "", "ODVA EtherNet/IP specification"},
        {"encap_malformed_headers",        "protocol_parser",      "input_validation",       "medium",   3, "CWE-20|CWE-444", "", "ODVA Encapsulation Protocol"},
        {"cpf_item_confusion",             "protocol_parser",      "input_validation",       "medium",   3, "CWE-20|CWE-1284", "", "ODVA Common Packet Format"},
        {"cip_path_boundary",              "path_validation",      "input_validation",       "medium",   3, "CWE-20|CWE-125", "", "CIP Path Segment Encoding"},
        {"cip_service_mutation",           "service_validation",   "authorization",          "medium",   3, "CWE-693|CWE-285", "", "CIP Services and Object Model"},
        {"session_handle_anomalies",       "session_management",   "state_integrity",        "high",     4, "CWE-384|CWE-664", "", "ENIP Session Handle Semantics"},
        {"io_udp_2222_anomalies",          "io_channel",           "availability",           "high",     4, "CWE-400", "", "ENIP I/O transport UDP/2222"},
        {"connection_manager_forward_open","connection_management","availability_integrity", "high",     4, "CWE-306|CWE-284", "", "CIP Connection Manager (ForwardOpen)"},
        {"unauthorized_writes",            "unauthorized_control", "integrity",              "critical", 5, "CWE-284|CWE-285", "", "CIP SetAttributeSingle"},
        {"device_reset_attempt",           "unauthorized_control", "availability",           "critical", 5, "CWE-306|CWE-284", "", "CIP Reset service"}
    };

    for (size_t i = 0; i < (sizeof(kMeta) / sizeof(kMeta[0])); ++i) {
        if (strcmp(kMeta[i].attack_id, attack_id) == 0) {
            return &kMeta[i];
        }
    }
    return nullptr;
}

static void appendEnipAttackMetadata(cJSON* obj, const char* attack_id) {
    if (!obj || !attack_id || !*attack_id) {
        return;
    }
    const EnipFuzzAttackMetadata* meta = getEnipFuzzAttackMetadata(attack_id);
    if (!meta) {
        cJSON_AddStringToObject(obj, "attack_id", attack_id);
        cJSON_AddStringToObject(obj, "category", "unknown");
        cJSON_AddStringToObject(obj, "risk_domain", "unknown");
        cJSON_AddStringToObject(obj, "expected_severity", "info");
        return;
    }

    cJSON_AddStringToObject(obj, "attack_id", meta->attack_id);
    cJSON_AddStringToObject(obj, "category", meta->category);
    cJSON_AddStringToObject(obj, "risk_domain", meta->risk_domain);
    cJSON_AddStringToObject(obj, "expected_severity", meta->expected_severity);
    addDelimitedStringArray(obj, "cwe", meta->cwe_list);
    addDelimitedStringArray(obj, "cve", meta->cve_list);
    addDelimitedStringArray(obj, "references", meta->references);
}
} // namespace

uint32_t FuzzingEngine::addJob(const FuzzJob& j) {
    uint32_t id = next_id_++;
    FuzzJob c = j; c.id = id;
    jobs_[id] = c;

    // Centralized logging for fuzzing activities
    std::string protocol_name = getProtocolName(c.protocol);
    LOG_INFOF("FUZZING_ENGINE", "Job created: ID=%lu, Protocol=%s, Target=%s, Profile=%s, SafeMode=%s",
              (unsigned long)id, protocol_name.c_str(), c.target.c_str(),
              c.profile.empty() ? "default" : c.profile.c_str(),
              c.safe_mode ? "true" : "false");

    // Report to system events
    if (rep_) {
        char event_data[512];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"job_created\",\"job_id\":%lu,\"protocol\":\"%s\",\"target\":\"%s\",\"target_ip\":\"%s\",\"profile\":\"%s\",\"safe_mode\":%s,\"rate_per_sec\":%lu,\"max_cases\":%lu,\"duration_ms\":%lu}",
                 (unsigned long)id, protocol_name.c_str(), c.target.c_str(),
                 c.target.c_str(), c.profile.empty() ? "default" : c.profile.c_str(),
                 c.safe_mode ? "true" : "false",
                 (unsigned long)c.rate_per_sec, (unsigned long)c.max_cases, (unsigned long)c.duration_ms);
        psram_string type = PSRAMUtils::createPSRAMString("fuzzing_job_lifecycle");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        rep_->reportEvent(type, payload);
    }

    return id;
}

bool FuzzingEngine::removeJob(uint32_t id) {
    auto it = jobs_.find(id);
    if (it != jobs_.end()) {
        LOG_INFOF("FUZZING_ENGINE", "Job removed: ID=%lu, Protocol=%s, Target=%s",
                  (unsigned long)id, getProtocolName(it->second.protocol).c_str(), it->second.target.c_str());

        if (rep_) {
            char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"job_removed\",\"job_id\":%lu,\"protocol\":\"%s\",\"target\":\"%s\",\"target_ip\":\"%s\"}",
                 (unsigned long)id, getProtocolName(it->second.protocol).c_str(), it->second.target.c_str(), it->second.target.c_str());
            psram_string type = PSRAMUtils::createPSRAMString("fuzzing_job_lifecycle");
            psram_string payload = PSRAMUtils::createPSRAMString(event_data);
            rep_->reportEvent(type, payload);
        }

        jobs_.erase(it);
        return true;
    }
    return false;
}

std::vector<FuzzJob> FuzzingEngine::listJobs() const {
    std::vector<FuzzJob> v;
    for (auto const& kv : jobs_) v.push_back(kv.second);
    std::sort(v.begin(), v.end(), [](auto&a, auto&b){return a.id<b.id;});
    return v;
}

bool FuzzingEngine::runNow(uint32_t id) {
    auto it = jobs_.find(id);
    if (it == jobs_.end()) return false;

    LOG_INFOF("FUZZING_ENGINE", "Job started: ID=%lu, Protocol=%s, Target=%s, Profile=%s",
              (unsigned long)id, getProtocolName(it->second.protocol).c_str(), it->second.target.c_str(),
              it->second.profile.empty() ? "default" : it->second.profile.c_str());

    if (rep_) {
        char event_data[512];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"job_started\",\"job_id\":%lu,\"protocol\":\"%s\",\"target\":\"%s\",\"profile\":\"%s\",\"safe_mode\":%s,\"rate_per_sec\":%lu,\"max_cases\":%lu,\"duration_ms\":%lu}",
                 (unsigned long)id, getProtocolName(it->second.protocol).c_str(), it->second.target.c_str(),
                 it->second.profile.empty() ? "default" : it->second.profile.c_str(),
                 it->second.safe_mode ? "true" : "false",
                 (unsigned long)it->second.rate_per_sec, (unsigned long)it->second.max_cases, (unsigned long)it->second.duration_ms);
        psram_string type = PSRAMUtils::createPSRAMString("fuzzing_job_execution");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        rep_->reportEvent(type, payload);
    }

    return xQueueSend(q_run_, &id, 0) == pdTRUE;
}

bool FuzzingEngine::stopAll() {
    stop_flag_ = true;

    LOG_INFO("FUZZING_ENGINE", "All fuzzing jobs stopped by user request");

    if (rep_) {
        char event_data[256];
        snprintf(event_data, sizeof(event_data),
                 "{\"action\":\"all_jobs_stopped\",\"active_jobs\":%zu,\"reason\":\"user_request\"}",
                 jobs_.size());
        psram_string type = PSRAMUtils::createPSRAMString("fuzzing_job_execution");
        psram_string payload = PSRAMUtils::createPSRAMString(event_data);
        rep_->reportEvent(type, payload);
    }

    return true;
}


void FuzzingEngine::workerTaskThunk(void* arg) {
    reinterpret_cast<FuzzingEngine*>(arg)->workerTask();
}

void FuzzingEngine::workerTask() {
    LOG_INFO(TAG_FUZZ, "worker started");
    while (!stop_flag_) {
        uint32_t id = 0;
        if (xQueueReceive(q_run_, &id, pdMS_TO_TICKS(200)) != pdTRUE) continue;
        if (!jobs_.count(id)) continue;
        runJobInternal(jobs_[id]);
    }
    LOG_INFO(TAG_FUZZ, "worker exit");
}

void FuzzingEngine::mutateOne(FuzzTestCase& io) {
    if (io.payload.empty()) return;
    static std::minstd_rand rng((unsigned)esp_random());
    std::uniform_int_distribution<int> pick(0,3);
    int m = pick(rng);

    // Track the mutation description
    char mut_desc[128];

    if (m==0) { // bit flip
        size_t idx = (size_t)(esp_random() % io.payload.size());
        uint8_t bit = (uint8_t)(esp_random() % 8);
        uint8_t old_val = io.payload[idx];
        io.payload[idx] ^= (uint8_t)(1u << bit);
        snprintf(mut_desc, sizeof(mut_desc), "Bit flip at offset %zu bit %u (0x%02X -> 0x%02X)",
                 idx, bit, old_val, io.payload[idx]);
        io.mutation_description = mut_desc;
        if (io.attack_type.empty()) {
            io.attack_type = "Bit Flip Mutation";
        }
    } else if (m==1) { // byte set edge
        static const uint8_t edges[] = {0x00,0x01,0x7F,0x80,0xFF};
        size_t idx = (size_t)(esp_random() % io.payload.size());
        uint8_t old_val = io.payload[idx];
        io.payload[idx] = edges[esp_random()%sizeof(edges)];
        snprintf(mut_desc, sizeof(mut_desc), "Edge value at offset %zu (0x%02X -> 0x%02X)",
                 idx, old_val, io.payload[idx]);
        io.mutation_description = mut_desc;
        if (io.attack_type.empty()) {
            io.attack_type = "Edge Value Mutation";
        }
    } else if (m==2 && io.payload.size()<1500) { // insert
        uint8_t val = (uint8_t)(esp_random() & 0xFF);
        size_t pos = (size_t)(esp_random() % (io.payload.size()+1));
        io.payload.insert(io.payload.begin()+pos, val);
        snprintf(mut_desc, sizeof(mut_desc), "Byte insertion at offset %zu (value 0x%02X)", pos, val);
        io.mutation_description = mut_desc;
        if (io.attack_type.empty()) {
            io.attack_type = "Byte Insertion Mutation";
        }
    } else { // erase
        if (io.payload.size()>1) {
            size_t pos = (size_t)(esp_random() % io.payload.size());
            uint8_t deleted_val = io.payload[pos];
            io.payload.erase(io.payload.begin()+pos);
            snprintf(mut_desc, sizeof(mut_desc), "Byte deletion at offset %zu (removed 0x%02X)", pos, deleted_val);
            io.mutation_description = mut_desc;
            if (io.attack_type.empty()) {
                io.attack_type = "Byte Deletion Mutation";
            }
        }
    }

    io.mutation_id++;
}

void FuzzingEngine::rateSleep(uint32_t per_sec) {
    if (per_sec == 0) per_sec = 1;
    uint32_t ms = 1000 / per_sec;
    vTaskDelay(pdMS_TO_TICKS(ms));
}

bool FuzzingEngine::runJobInternal(const FuzzJob& j) {
    // Initialize job statistics
    current_job_stats_.reset();
    current_job_stats_.job_start_time = esp_timer_get_time() / 1000ULL;
    active_job_id_.store(j.id, std::memory_order_relaxed);
    auto clear_active = [&]() { active_job_id_.store(0, std::memory_order_relaxed); };

    LOG_INFOF(TAG_FUZZ, "🚀 STARTING fuzzing job %lu for protocol %s (max_cases: %lu, duration: %lums)",
             (unsigned long)j.id, getProtocolName(j.protocol).c_str(),
             (unsigned long)j.max_cases, (unsigned long)j.duration_ms);

    if (!j.safe_mode && (!sec_ || !sec_->isFuzzingAllowed())) {
        LOG_WARNINGF(TAG_FUZZ, "fuzzing blocked by SecurityManager: reason=%s",
                     sec_ ? sec_->getFuzzingBlockReason() : "security_manager_unavailable");
        clear_active();
        return false;
    }

    // Get plugin from PluginManager
    if (!plugin_manager_) {
        LOG_ERROR(TAG_FUZZ, "❌ No PluginManager available for fuzzing");
        clear_active();
        return false;
    }

    BasePlugin* plugin = plugin_manager_->findByProtocol(j.protocol);
    if (!plugin) {
        LOG_WARNINGF(TAG_FUZZ, "❌ No plugin found for protocol %s", getProtocolName(j.protocol).c_str());
        clear_active();
        return false;
    }

    LOG_INFOF(TAG_FUZZ, "✅ Using plugin for fuzzing: %s", plugin->name());

    LOG_INFOF(TAG_FUZZ, "📋 GENERATING seed corpus for job %lu", (unsigned long)j.id);

    // seed corpus
    std::vector<FuzzTestCase> seeds;
    bool seed_success = plugin->generateSeedCorpus(j, seeds);

    if (!seed_success || seeds.empty()) {
        LOG_WARNINGF(TAG_FUZZ, "❌ No seeds generated for protocol %d", (int)j.protocol);
        clear_active();
        return false;
    }

    LOG_INFOF(TAG_FUZZ, "run job id=%lu seeds=%u rate=%lu/s max_cases=%lu duration_ms=%lu",
        (unsigned long)j.id, (unsigned)seeds.size(), (unsigned long)j.rate_per_sec, (unsigned long)j.max_cases, (unsigned long)j.duration_ms);

    uint64_t start = esp_timer_get_time()/1000ULL;
    uint32_t cases = 0;
    stop_flag_ = false;
    bool have_first_success = false;
    uint32_t first_success_case_id = 0;
    std::string first_success_sent;
    std::string first_success_received;
    std::string first_success_details;
    std::string first_success_attack_type;
    uint32_t first_success_duration_ms = 0;

    // Track which attack types actually ran inside this job (useful when a profile expands to multiple seed families).
    std::map<std::string, uint32_t> attack_type_counts;

    while (!stop_flag_) {
        if (j.max_cases && cases >= j.max_cases) break;
        if (j.duration_ms && ((esp_timer_get_time()/1000ULL) - start) >= j.duration_ms) break;

        // pick a seed, mutate, fixup, execute
        FuzzTestCase tc = seeds[esp_random() % seeds.size()];
        const bool single_shot_profile =
            (j.protocol == ProtocolType::S7_COMM) &&
            (j.profile == "unauthorized_write" || j.profile == "plc_stop");
        if (!single_shot_profile) {
            mutateOne(tc);
        }
        FuzzTestCase fx;

        bool fixup_success = plugin->fixup(j, tc, fx);
        if (!fixup_success) continue;

        // Calculate progress
        float progress_percent = j.max_cases > 0 ? (100.0f * cases / j.max_cases) : 0.0f;

        LOG_INFOF(TAG_FUZZ, "🎯 EXECUTING test case %lu [%lu/%lu] (%.1f%% complete)",
                 (unsigned long)fx.seed_id, (unsigned long)(cases + 1), (unsigned long)j.max_cases, progress_percent);

        // Track execution timing
        uint64_t test_start_time = esp_timer_get_time() / 1000ULL;
        std::string sent_hex, received_hex, status_details;
        FuzzResult result;
        if (!j.safe_mode && (!sec_ || !sec_->isFuzzingAllowed())) {
            status_details = "blocked_by_offensive_policy:" +
                std::string(sec_ ? sec_->getFuzzingBlockReason() : "security_manager_unavailable");
            LOG_WARNINGF(TAG_FUZZ, "unsafe fuzz case blocked immediately before send: job=%lu reason=%s",
                         (unsigned long)j.id, status_details.c_str());
            result = FuzzResult::SEND_FAILED;
            stop_flag_ = true;
        } else {
            result = plugin->execute(j, fx, sent_hex, received_hex, status_details);
        }
        uint64_t test_execution_time = (esp_timer_get_time() / 1000ULL) - test_start_time;
        bool ok = (result == FuzzResult::SUCCESS);

        {
            // Prefer per-test attack_type, fallback to job profile, then "default".
            const std::string at =
                !fx.attack_type.empty() ? fx.attack_type :
                (!j.profile.empty() ? j.profile : std::string("default"));
            attack_type_counts[at]++;
        }

        // Update statistics
        current_job_stats_.total_sent++;
        if (!received_hex.empty()) {
            current_job_stats_.total_responses++;
        }
        if (ok) {
            current_job_stats_.success_count++;
            current_job_stats_.total_execution_time_ms += test_execution_time;
            if (!have_first_success) {
                have_first_success = true;
                first_success_case_id = fx.seed_id;
                first_success_sent = sent_hex;
                first_success_received = received_hex;
                first_success_details = status_details;
                first_success_attack_type = fx.attack_type;
                first_success_duration_ms = (uint32_t)test_execution_time;
            }
        } else {
            // Update failure counters based on result type
            switch (result) {
                case FuzzResult::TIMEOUT:
                    current_job_stats_.timeout_count++;
                    break;
                case FuzzResult::EXCEPTION_RESPONSE:
                    current_job_stats_.exception_count++;
                    break;
                case FuzzResult::SOCKET_ERROR:
                    current_job_stats_.socket_error_count++;
                    break;
                case FuzzResult::INVALID_RESPONSE:
                    current_job_stats_.invalid_response_count++;
                    break;
                case FuzzResult::CONNECTION_FAILED:
                    current_job_stats_.connection_failed_count++;
                    break;
                case FuzzResult::SEND_FAILED:
                    current_job_stats_.send_failed_count++;
                    break;
                default:
                    break;
            }
        }

        // Enhanced logging with colorful emoji based on result type
        const char* result_emoji;
        const char* result_description;
        switch (result) {
            case FuzzResult::SUCCESS:
                result_emoji = "✅";
                result_description = "SUCCESS";
                break;
            case FuzzResult::TIMEOUT:
                result_emoji = "⏰";
                result_description = "TIMEOUT";
                break;
            case FuzzResult::EXCEPTION_RESPONSE:
                result_emoji = "⚠️";
                result_description = "EXCEPTION";
                break;
            case FuzzResult::CONNECTION_FAILED:
                result_emoji = "🔌";
                result_description = "NO_CONNECTION";
                break;
            case FuzzResult::SOCKET_ERROR:
                result_emoji = "🔗";
                result_description = "SOCKET_ERROR";
                break;
            case FuzzResult::SEND_FAILED:
                result_emoji = "📤";
                result_description = "SEND_FAILED";
                break;
            case FuzzResult::INVALID_RESPONSE:
                result_emoji = "❓";
                result_description = "INVALID_RESPONSE";
                break;
            default:
                result_emoji = "❌";
                result_description = "UNKNOWN_ERROR";
                break;
        }

        LOG_INFOF(TAG_FUZZ, "%s RESULT [%lums] case=%lu sent=%s received=%s %s",
            result_emoji, (unsigned long)test_execution_time, (unsigned long)fx.seed_id,
            sent_hex.c_str(),
            received_hex.empty() ? "none" : received_hex.c_str(),
            status_details.empty() ? result_description : status_details.c_str());

        // Show live statistics every 5 tests or on success
        if ((cases + 1) % 5 == 0 || ok) {
            float current_success_rate = current_job_stats_.getSuccessRate();
            float avg_response_time = current_job_stats_.getAvgResponseTime();
            LOG_INFOF(TAG_FUZZ, "📊 STATS: Success %.1f%% (%lu/%lu) | Avg: %.1fms | Responses: %lu",
                     current_success_rate, (unsigned long)current_job_stats_.success_count,
                     (unsigned long)current_job_stats_.total_sent, avg_response_time,
                     (unsigned long)current_job_stats_.total_responses);
        }

        if (!ok) {
            // Handle different error types based on FuzzResult
            const char* error_detail;
            switch (result) {
                case FuzzResult::CONNECTION_FAILED:
                    error_detail = "connection_failed";
                    break;
                case FuzzResult::TIMEOUT:
                    error_detail = "timeout_or_no_response";
                    break;
                case FuzzResult::EXCEPTION_RESPONSE:
                    error_detail = "protocol_exception";
                    break;
                case FuzzResult::SEND_FAILED:
                    error_detail = "send_failed";
                    break;
                case FuzzResult::SOCKET_ERROR:
                    error_detail = "socket_error";
                    break;
                case FuzzResult::INVALID_RESPONSE:
                    error_detail = "invalid_response";
                    break;
                default:
                    error_detail = "unknown_error";
                    break;
            }

            // Log with detailed status information if available
            if (!status_details.empty()) {
                LOG_INFOF(TAG_FUZZ, "📊 Target execute result: FAILED %s (%s) (case %lu)", error_detail, status_details.c_str(), (unsigned long)fx.seed_id);
            } else {
                LOG_INFOF(TAG_FUZZ, "📊 Target execute result: FAILED %s (case %lu)", error_detail, (unsigned long)fx.seed_id);
            }
        } else {
            if (!status_details.empty()) {
                LOG_INFOF(TAG_FUZZ, "📊 Target execute result: OK (%s) (case %lu)", status_details.c_str(), (unsigned long)fx.seed_id);
            } else {
                LOG_INFOF(TAG_FUZZ, "📊 Target execute result: OK (case %lu)", (unsigned long)fx.seed_id);
            }
        }

        // Always report result (ok or not) as a detailed fuzzing event
        if (rep_) {
            // Generate detailed report using the new builder
            FuzzTestReportBuilder builder;

            // Set common fields
            char session_buf[64];
            snprintf(session_buf, sizeof(session_buf), "fuzz_session_%lu", (unsigned long)j.id);
            builder.setSessionId(PSRAMUtils::createPSRAMString(session_buf));

            // Set test information with progress tracking
            builder.setTestInfo(j.id, fx.mutation_id, fx.mutation_id, fx.seed_id);
            builder.setTestType(PSRAMUtils::createPSRAMString("protocol_fuzzing"));
            builder.setProtocol(PSRAMUtils::createPSRAMString(getProtocolName(j.protocol).c_str()));

            // Note: Progress information will be included in the final report structure

            // Parse target (format: "host:port" or just "host")
            const char* colon_pos = strchr(j.target.c_str(), ':');
            uint16_t target_port = 502; // Default Modbus port

            if (colon_pos) {
                // Extract host part
                size_t host_len = colon_pos - j.target.c_str();
                char host_buf[64];
                if (host_len < sizeof(host_buf)) {
                    strncpy(host_buf, j.target.c_str(), host_len);
                    host_buf[host_len] = '\0';
                    target_port = static_cast<uint16_t>(atoi(colon_pos + 1));
                    builder.setTarget(PSRAMUtils::createPSRAMString(host_buf), target_port);
                } else {
                    builder.setTarget(PSRAMUtils::createPSRAMString(j.target.c_str()), target_port);
                }
            } else {
                builder.setTarget(PSRAMUtils::createPSRAMString(j.target.c_str()), target_port);
            }

            // Set packet data with protocol parsing
            if (!sent_hex.empty()) {
                // Convert hex string back to bytes for parsing
                std::vector<uint8_t> sent_bytes;
                for (size_t i = 0; i < sent_hex.length(); i += 2) {
                    if (i + 1 < sent_hex.length()) {
                        char byte_str[3] = {sent_hex[i], sent_hex[i+1], '\0'};
                        uint8_t byte_val = static_cast<uint8_t>(strtol(byte_str, nullptr, 16));
                        sent_bytes.push_back(byte_val);
                    }
                }

                cJSON* sent_structure = nullptr;
                if (j.protocol == ProtocolType::MODBUS_TCP && sent_bytes.size() >= 8) {
                    sent_structure = parseModbusPacket(sent_bytes.data(), sent_bytes.size());
                } else if (j.protocol == ProtocolType::ETHERNET_IP && sent_bytes.size() >= 24) {
                    sent_structure = parseEtherNetIPPacket(sent_bytes.data(), sent_bytes.size());
                }

                builder.setSentPacket(PSRAMUtils::createPSRAMString(sent_hex.c_str()), sent_bytes.size(), sent_structure);
            }

            // Always set received packet info (even if empty)
            if (!received_hex.empty()) {
                // Convert hex string back to bytes for parsing
                std::vector<uint8_t> received_bytes;
                for (size_t i = 0; i < received_hex.length(); i += 2) {
                    if (i + 1 < received_hex.length()) {
                        char byte_str[3] = {received_hex[i], received_hex[i+1], '\0'};
                        uint8_t byte_val = static_cast<uint8_t>(strtol(byte_str, nullptr, 16));
                        received_bytes.push_back(byte_val);
                    }
                }

                cJSON* received_structure = nullptr;
                if (j.protocol == ProtocolType::MODBUS_TCP && received_bytes.size() >= 6) {
                    received_structure = parseModbusPacket(received_bytes.data(), received_bytes.size());
                } else if (j.protocol == ProtocolType::ETHERNET_IP && received_bytes.size() >= 24) {
                    received_structure = parseEtherNetIPPacket(received_bytes.data(), received_bytes.size());
                }

                builder.setReceivedPacket(PSRAMUtils::createPSRAMString(received_hex.c_str()), received_bytes.size(), received_structure);
            } else {
                // Set empty received packet to ensure field is always present in JSON
                builder.setReceivedPacket(PSRAMUtils::createPSRAMString(""), 0, nullptr);
            }

            // Set test result with enhanced information
            TestResult test_result;

            // Set detailed status based on result
            switch (result) {
                case FuzzResult::SUCCESS:
                    test_result.status = PSRAMUtils::createPSRAMString("success");
                    break;
                case FuzzResult::TIMEOUT:
                    test_result.status = PSRAMUtils::createPSRAMString("timeout");
                    break;
                case FuzzResult::EXCEPTION_RESPONSE:
                    test_result.status = PSRAMUtils::createPSRAMString("exception");
                    break;
                case FuzzResult::CONNECTION_FAILED:
                    test_result.status = PSRAMUtils::createPSRAMString("connection_failed");
                    break;
                case FuzzResult::SEND_FAILED:
                    test_result.status = PSRAMUtils::createPSRAMString("send_failed");
                    break;
                case FuzzResult::SOCKET_ERROR:
                    test_result.status = PSRAMUtils::createPSRAMString("socket_error");
                    break;
                case FuzzResult::INVALID_RESPONSE:
                    test_result.status = PSRAMUtils::createPSRAMString("invalid_response");
                    break;
                default:
                    test_result.status = PSRAMUtils::createPSRAMString(ok ? "success" : "failure");
                    break;
            }

            test_result.result_code = static_cast<int>(result);
            test_result.execution_time_ms = static_cast<uint32_t>(test_execution_time);

            // Enhanced result description with response analysis
            std::string enhanced_description;
            if (!status_details.empty()) {
                enhanced_description = status_details;
            } else if (ok && !received_hex.empty()) {
                enhanced_description = "Valid response received (";
                enhanced_description += std::to_string(received_hex.length() / 2);
                enhanced_description += " bytes)";
            } else if (ok && received_hex.empty()) {
                enhanced_description = "Request successful (no response received)";
            } else {
                enhanced_description = result_description;
            }
            test_result.description = PSRAMUtils::createPSRAMString(enhanced_description.c_str());

            // Response analysis information is embedded in the enhanced description

            // Analyze for potential vulnerabilities
            if (!ok) {
                switch (result) {
                    case FuzzResult::EXCEPTION_RESPONSE:
                        test_result.vulnerability_found = true;
                        test_result.vulnerability_type = PSRAMUtils::createPSRAMString("exception_handling");
                        test_result.severity = PSRAMUtils::createPSRAMString("medium");
                        test_result.cvss_score = 5.3f;
                        test_result.recommendation = PSRAMUtils::createPSRAMString("Implement proper input validation to prevent exception responses");
                        break;
                    case FuzzResult::TIMEOUT:
                        test_result.vulnerability_found = true;
                        test_result.vulnerability_type = PSRAMUtils::createPSRAMString("dos_potential");
                        test_result.severity = PSRAMUtils::createPSRAMString("high");
                        test_result.cvss_score = 7.5f;
                        test_result.recommendation = PSRAMUtils::createPSRAMString("Implement request timeouts and rate limiting");
                        break;
                    case FuzzResult::INVALID_RESPONSE:
                        test_result.vulnerability_found = true;
                        test_result.vulnerability_type = PSRAMUtils::createPSRAMString("protocol_compliance");
                        test_result.severity = PSRAMUtils::createPSRAMString("low");
                        test_result.cvss_score = 3.1f;
                        test_result.recommendation = PSRAMUtils::createPSRAMString("Ensure protocol compliance and proper error handling");
                        break;
                    default:
                        test_result.vulnerability_found = false;
                        test_result.severity = PSRAMUtils::createPSRAMString("info");
                        break;
                }
            } else {
                test_result.vulnerability_found = false;
                test_result.severity = PSRAMUtils::createPSRAMString("info");
            }

            builder.setResult(test_result);

            // Set metrics (execution time would need to be measured separately)
            builder.setMetrics(0, 0, ok ? 1.0f : 0.0f);

            // Build and report the detailed JSON
            psram_string detailed_report = builder.build();

            // Report both old format (for backward compatibility) and new detailed format
            // Use PSRAM buffer instead of std::stringstream to avoid IRAM allocation
            PSRAMUtils::ScopedBuffer event_buf(2048);
            if (!event_buf.valid()) {
                LOG_ERROR(TAG_FUZZ, "Failed to allocate PSRAM for fuzzing event");
            } else {
                char* p = event_buf.get();
                size_t remaining = event_buf.size();
                int written = 0;

                // Start JSON object
                written = snprintf(p, remaining, "{\"job\":%lu,\"ok\":%s,\"len\":%zu",
                                  (unsigned long)j.id, ok ? "true" : "false", fx.payload.size());
                if (written > 0 && written < (int)remaining) {
                    p += written;
                    remaining -= written;

                    // Add attack_type and mutation_description from FuzzTestCase
                    if (!fx.attack_type.empty() && remaining > fx.attack_type.length() + 20) {
                        written = snprintf(p, remaining, ",\"attack_type\":\"%s\"", fx.attack_type.c_str());
                        if (written > 0 && written < (int)remaining) {
                            p += written;
                            remaining -= written;
                        }
                    }
                    if (!fx.mutation_description.empty() && remaining > fx.mutation_description.length() + 30) {
                        written = snprintf(p, remaining, ",\"mutation_description\":\"%s\"", fx.mutation_description.c_str());
                        if (written > 0 && written < (int)remaining) {
                            p += written;
                            remaining -= written;
                        }
                    }

                    // Add sent packet hex
                    if (!sent_hex.empty() && remaining > sent_hex.length() + 25) {
                        written = snprintf(p, remaining, ",\"packet_sent_hex\":\"%s\"", sent_hex.c_str());
                        if (written > 0 && written < (int)remaining) {
                            p += written;
                            remaining -= written;
                        }
                    }

                    // Add received packet hex
                    if (!received_hex.empty() && remaining > received_hex.length() + 30) {
                        written = snprintf(p, remaining, ",\"packet_received_hex\":\"%s\"", received_hex.c_str());
                        if (written > 0 && written < (int)remaining) {
                            p += written;
                            remaining -= written;
                        }
                    }

                    // Add status details
                    if (!status_details.empty() && remaining > status_details.length() + 25) {
                        written = snprintf(p, remaining, ",\"status_details\":\"%s\"", status_details.c_str());
                        if (written > 0 && written < (int)remaining) {
                            p += written;
                            remaining -= written;
                        }
                    }

                    // Add result code
                    written = snprintf(p, remaining, ",\"result_code\":%d", static_cast<int>(result));
                    if (written > 0 && written < (int)remaining) {
                        p += written;
                        remaining -= written;
                    }

                    // Add device response analysis for EtherNet/IP
                    if (j.protocol == ProtocolType::ETHERNET_IP && !received_hex.empty() && remaining > 200) {
                        std::vector<uint8_t> rx_bytes;
                        for (size_t i = 0; i < received_hex.length(); i += 2) {
                            if (i + 1 < received_hex.length()) {
                                char byte_str[3] = {received_hex[i], received_hex[i+1], '\0'};
                                rx_bytes.push_back(static_cast<uint8_t>(strtol(byte_str, nullptr, 16)));
                            }
                        }
                        if (rx_bytes.size() >= 24) {
                            uint32_t encap_status = (rx_bytes[11] << 24) | (rx_bytes[10] << 16) | (rx_bytes[9] << 8) | rx_bytes[8];
                            const char* device_analysis = nullptr;
                            char status_buf[128];
                            if (encap_status == 0) {
                                device_analysis = "Device accepted packet and responded successfully";
                            } else if (encap_status == 0x00000003) {
                                device_analysis = "Device correctly rejected malformed packet (Error 0x00000003: Invalid or unsupported command)";
                            } else {
                                snprintf(status_buf, sizeof(status_buf), "Device returned error status 0x%08lX", (unsigned long)encap_status);
                                device_analysis = status_buf;
                            }
                            written = snprintf(p, remaining, ",\"device_response_analysis\":\"%s\"", device_analysis);
                            if (written > 0 && written < (int)remaining) {
                                p += written;
                                remaining -= written;
                            }
                        }
                    }

                    // Add target IP and close JSON
                    written = snprintf(p, remaining, ",\"target_ip\":\"%s\"}", j.target.c_str());
                    if (written > 0 && written < (int)remaining) {
                        // Report old format for backward compatibility
                        psram_string type = PSRAMUtils::createPSRAMString("case");
                        psram_string payload = PSRAMUtils::createPSRAMString(event_buf.get());
                        rep_->reportEvent(type, payload);
                    }
                }
            }

            // Report new detailed format
            rep_->reportEvent(PSRAMUtils::createPSRAMString("fuzz_test_detailed"), detailed_report);
        }
        ++cases;

        // Log progress every 10 test cases
        if (cases % 10 == 0) {
            LOG_INFOF(TAG_FUZZ, "⏳ Job %lu: executed %lu test cases", (unsigned long)j.id, (unsigned long)cases);
        }

        rateSleep(j.rate_per_sec);
    }
    // Log job completion with detailed metrics
    uint64_t duration_actual = (esp_timer_get_time()/1000ULL) - start;
    const char* stopped_by = stop_flag_ ? "user_stop" : (cases >= j.max_cases ? "max_cases" : "timeout");

    // Enhanced completion logging with full statistics
    float final_success_rate = current_job_stats_.getSuccessRate();
    float final_avg_response_time = current_job_stats_.getAvgResponseTime();

    LOG_INFOF(TAG_FUZZ, "🏁 JOB COMPLETED: ID=%lu Protocol=%s Target=%s",
              (unsigned long)j.id, getProtocolName(j.protocol).c_str(), j.target.c_str());
    LOG_INFOF(TAG_FUZZ, "📊 FINAL STATS: %lu tests | %.1f%% success | %.1fms avg | %lu responses",
              (unsigned long)cases, final_success_rate, final_avg_response_time, (unsigned long)current_job_stats_.total_responses);
    LOG_INFOF(TAG_FUZZ, "📈 BREAKDOWN: ✅%lu ⏰%lu ⚠️%lu 🔌%lu 🔗%lu 📤%lu ❓%lu",
              (unsigned long)current_job_stats_.success_count, (unsigned long)current_job_stats_.timeout_count,
              (unsigned long)current_job_stats_.exception_count, (unsigned long)current_job_stats_.connection_failed_count,
              (unsigned long)current_job_stats_.socket_error_count, (unsigned long)current_job_stats_.send_failed_count,
              (unsigned long)current_job_stats_.invalid_response_count);
    LOG_INFOF(TAG_FUZZ, "⏱️ DURATION: %llums | STOPPED BY: %s", (unsigned long long)duration_actual, stopped_by);

    // Report enhanced job completion with detailed statistics
    if (rep_) {
        // Use cJSON for proper formatting of complex statistics
        cJSON* job_completion = cJSON_CreateObject();

        // Basic job information
        cJSON_AddStringToObject(job_completion, "action", "job_completed");
        cJSON_AddNumberToObject(job_completion, "job_id", j.id);
        cJSON_AddStringToObject(job_completion, "protocol", getProtocolName(j.protocol).c_str());
        cJSON_AddStringToObject(job_completion, "target", j.target.c_str());
        cJSON_AddStringToObject(job_completion, "target_ip", j.target.c_str());
        cJSON_AddStringToObject(job_completion, "attack_profile", (!j.profile.empty() ? j.profile.c_str() : "default"));
        cJSON_AddBoolToObject(job_completion, "safe_mode", j.safe_mode ? 1 : 0);
        cJSON_AddNumberToObject(job_completion, "cases_executed", cases);
        cJSON_AddNumberToObject(job_completion, "duration_ms", duration_actual);
        cJSON_AddStringToObject(job_completion, "stopped_by", stopped_by);

        // Detailed statistics object
        cJSON* statistics = cJSON_CreateObject();
        cJSON_AddNumberToObject(statistics, "total_sent", current_job_stats_.total_sent);
        cJSON_AddNumberToObject(statistics, "total_responses", current_job_stats_.total_responses);
        cJSON_AddNumberToObject(statistics, "success_count", current_job_stats_.success_count);
        cJSON_AddNumberToObject(statistics, "success_rate_percent", final_success_rate);
        cJSON_AddNumberToObject(statistics, "avg_response_time_ms", final_avg_response_time);

        // Which attacks actually ran (and how many cases per type).
        cJSON* atk_types = cJSON_CreateArray();
        cJSON* atk_counts = cJSON_CreateObject();
        for (const auto& kv : attack_type_counts) {
            cJSON_AddItemToArray(atk_types, cJSON_CreateString(kv.first.c_str()));
            cJSON_AddNumberToObject(atk_counts, kv.first.c_str(), (double)kv.second);
        }
        cJSON_AddItemToObject(statistics, "attack_types_executed", atk_types);
        cJSON_AddItemToObject(statistics, "attack_type_case_counts", atk_counts);

        if (j.protocol == ProtocolType::OPC_UA || j.protocol == ProtocolType::ETHERNET_IP) {
            // Add per-attack metadata (CWE/CVE/risk domains) for protocols with rich metadata mapping.
            cJSON* atk_meta = cJSON_CreateObject();
            const char* highest_risk_attack = "none";
            int highest_risk_rank = 0;
            for (const auto& kv : attack_type_counts) {
                const char* atk_id = kv.first.empty() ? "default" : kv.first.c_str();
                cJSON* one = cJSON_CreateObject();
                int rank = 0;
                if (j.protocol == ProtocolType::OPC_UA) {
                    appendOpcuaAttackMetadata(one, atk_id);
                    const OpcuaFuzzAttackMetadata* meta = getOpcuaFuzzAttackMetadata(atk_id);
                    if (meta) rank = meta->risk_rank;
                } else {
                    appendEnipAttackMetadata(one, atk_id);
                    const EnipFuzzAttackMetadata* meta = getEnipFuzzAttackMetadata(atk_id);
                    if (meta) rank = meta->risk_rank;
                }
                cJSON_AddNumberToObject(one, "cases", (double)kv.second);
                cJSON_AddItemToObject(atk_meta, atk_id, one);
                if (rank > highest_risk_rank) {
                    highest_risk_rank = rank;
                    highest_risk_attack = atk_id;
                }
            }
            cJSON_AddItemToObject(statistics, "attack_types_metadata", atk_meta);

            const char* profile_id = (!j.profile.empty() ? j.profile.c_str() : "default");
            cJSON* profile_meta = cJSON_CreateObject();
            if (j.protocol == ProtocolType::OPC_UA) {
                appendOpcuaAttackMetadata(profile_meta, profile_id);
            } else {
                appendEnipAttackMetadata(profile_meta, profile_id);
            }
            cJSON_AddItemToObject(job_completion, "attack_profile_metadata", profile_meta);

            const char* overall_risk = "info";
            switch (highest_risk_rank) {
                case 5: overall_risk = "critical"; break;
                case 4: overall_risk = "high"; break;
                case 3: overall_risk = "medium"; break;
                case 2: overall_risk = "low"; break;
                default: overall_risk = "info"; break;
            }
            cJSON* risk = cJSON_CreateObject();
            cJSON_AddStringToObject(risk, "overall_risk", overall_risk);
            cJSON_AddStringToObject(risk, "highest_risk_attack_type", highest_risk_attack);
            cJSON_AddItemToObject(job_completion, "risk_assessment", risk);
        }

        // Failure breakdown object
        cJSON* failure_breakdown = cJSON_CreateObject();
        cJSON_AddNumberToObject(failure_breakdown, "timeouts", current_job_stats_.timeout_count);
        cJSON_AddNumberToObject(failure_breakdown, "exceptions", current_job_stats_.exception_count);
        cJSON_AddNumberToObject(failure_breakdown, "socket_errors", current_job_stats_.socket_error_count);
        cJSON_AddNumberToObject(failure_breakdown, "invalid_responses", current_job_stats_.invalid_response_count);
        cJSON_AddNumberToObject(failure_breakdown, "connection_failures", current_job_stats_.connection_failed_count);
        cJSON_AddNumberToObject(failure_breakdown, "send_failures", current_job_stats_.send_failed_count);
        cJSON_AddItemToObject(statistics, "failure_breakdown", failure_breakdown);

        cJSON_AddItemToObject(job_completion, "statistics", statistics);

        if (have_first_success) {
            cJSON* fs = cJSON_CreateObject();
            cJSON_AddNumberToObject(fs, "case_id", first_success_case_id);
            if (!first_success_attack_type.empty()) {
                cJSON_AddStringToObject(fs, "attack_type", first_success_attack_type.c_str());
            }
            cJSON_AddNumberToObject(fs, "duration_ms", first_success_duration_ms);
            cJSON_AddStringToObject(fs, "packet_sent_hex", first_success_sent.c_str());
            cJSON_AddStringToObject(fs, "packet_received_hex", first_success_received.c_str());
            if (!first_success_details.empty()) {
                cJSON_AddStringToObject(fs, "status_details", first_success_details.c_str());
            }
            if (j.protocol == ProtocolType::OPC_UA || j.protocol == ProtocolType::ETHERNET_IP) {
                const char* fs_attack =
                    !first_success_attack_type.empty() ? first_success_attack_type.c_str()
                                                       : (!j.profile.empty() ? j.profile.c_str() : "default");
                cJSON* fs_meta = cJSON_CreateObject();
                if (j.protocol == ProtocolType::OPC_UA) {
                    appendOpcuaAttackMetadata(fs_meta, fs_attack);
                } else {
                    appendEnipAttackMetadata(fs_meta, fs_attack);
                }
                cJSON_AddItemToObject(fs, "attack_metadata", fs_meta);
            }
            cJSON_AddItemToObject(job_completion, "first_success", fs);
        }

        // Convert to string and send
        char* json_string = cJSON_PrintUnformatted(job_completion);
        if (json_string) {
            psram_string type = PSRAMUtils::createPSRAMString("fuzzing_job_execution");
            psram_string payload = PSRAMUtils::createPSRAMString(json_string);
            rep_->reportEvent(type, payload);
            {
                std::lock_guard<std::mutex> lk(results_mtx_);
                last_job_result_json_[j.id] = payload;
                last_job_result_time_ms_[j.id] = (uint64_t)(esp_timer_get_time() / 1000ULL);
            }
            cJSON_free(json_string);
        }
        cJSON_Delete(job_completion);
    }

    clear_active();
    return true;
}

bool FuzzingEngine::getLastJobResult(uint32_t id, psram_string& out_json) const {
    std::lock_guard<std::mutex> lk(results_mtx_);
    auto it = last_job_result_json_.find(id);
    if (it == last_job_result_json_.end()) return false;
    out_json = it->second;
    return true;
}

bool FuzzingEngine::isJobRunning(uint32_t id) const {
    return active_job_id_.load(std::memory_order_relaxed) == id;
}
