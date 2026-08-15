#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <map>
#include <atomic>
#include <memory>
#include <mutex>

extern "C" {
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "freertos/queue.h"
}

#include "../core/types.h" // ProtocolType
#include "../core/psram_allocator.h"
class ReportingEngine;
class SecurityManager;
class Logger;
class PluginManager;

// A single fuzz test-case
struct FuzzTestCase {
    std::vector<uint8_t> payload;
    uint32_t seed_id = 0;
    uint32_t mutation_id = 0;
    std::string attack_type;          // Literal description of attack type (e.g., "Malformed CIP Path Size")
    std::string mutation_description;  // Description of applied mutations (e.g., "Byte corruption at offset 10")
};

struct FuzzJob {
    uint32_t id = 0;
    ProtocolType protocol = ProtocolType::UNKNOWN;
    std::string target;            // ip[:port] or iface (for L2)
    bool safe_mode = true;         // restrict to read-only/non-state-changing templates
    uint32_t rate_per_sec = 20;    // rate limiting
    uint32_t duration_ms = 5000;   // stop after this time (0 = until max_cases)
    uint32_t max_cases = 500;      // hard limit of cases per run
    std::string profile;           // optional profile name ("light","aggr",...)
    std::string extra_config;      // optional JSON string with protocol-specific configuration
};


// The FuzzingEngine runs jobs with rate-limiting and basic mutators.
class FuzzingEngine {
public:
    FuzzingEngine(ReportingEngine* rep, SecurityManager* sec, Logger* log, PluginManager* pm);
    ~FuzzingEngine();

    uint32_t addJob(const FuzzJob& j);        // returns id
    bool removeJob(uint32_t id);
    std::vector<FuzzJob> listJobs() const;
    bool runNow(uint32_t id);                 // enqueue immediate run
    bool stopAll();                           // stops current run
    bool getLastJobResult(uint32_t id, psram_string& out_json) const;
    bool isJobRunning(uint32_t id) const;

    // Set plugin manager (replaces registerTarget)
    void setPluginManager(PluginManager* pm) { plugin_manager_ = pm; }


private:
    static void workerTaskThunk(void* arg);
    void workerTask();

    bool runJobInternal(const FuzzJob& j);
    void mutateOne(FuzzTestCase& io);
    void rateSleep(uint32_t per_sec);
    std::string getProtocolName(ProtocolType proto);

    ReportingEngine* rep_ = nullptr;
    SecurityManager* sec_ = nullptr;
    Logger* logger_ = nullptr;
    PluginManager* plugin_manager_ = nullptr;

    psram_map<uint32_t, FuzzJob> jobs_;
    std::atomic<bool> stop_flag_{false};
    TaskHandle_t worker_ = nullptr;
    QueueHandle_t q_run_ = nullptr; // queue of job ids to run
    uint32_t next_id_ = 1;

    // Job execution statistics
    struct JobStats {
        uint32_t total_sent = 0;
        uint32_t total_responses = 0;
        uint32_t success_count = 0;
        uint32_t timeout_count = 0;
        uint32_t exception_count = 0;
        uint32_t socket_error_count = 0;
        uint32_t invalid_response_count = 0;
        uint32_t connection_failed_count = 0;
        uint32_t send_failed_count = 0;
        uint64_t total_execution_time_ms = 0;
        uint64_t job_start_time = 0;

        void reset() {
            total_sent = total_responses = success_count = 0;
            timeout_count = exception_count = socket_error_count = 0;
            invalid_response_count = connection_failed_count = send_failed_count = 0;
            total_execution_time_ms = job_start_time = 0;
        }

        float getSuccessRate() const {
            return total_sent > 0 ? (100.0f * success_count / total_sent) : 0.0f;
        }

        float getAvgResponseTime() const {
            return success_count > 0 ? (float(total_execution_time_ms) / success_count) : 0.0f;
        }
    } current_job_stats_;

    // Last completed result JSON per job (for UI/API retrieval).
    mutable std::mutex results_mtx_;
    psram_map<uint32_t, psram_string> last_job_result_json_;
    psram_map<uint32_t, uint64_t> last_job_result_time_ms_;
    std::atomic<uint32_t> active_job_id_{0};
};

// Global fuzzing engine instance
extern FuzzingEngine* g_fuzz;
