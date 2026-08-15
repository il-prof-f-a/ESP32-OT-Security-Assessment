#pragma once

#include <string>
#include <vector>
#include <functional>
#include <ctime>
#include "psram_allocator.h"
#include "types.h"

extern "C" {
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "freertos/timers.h"
    #include "freertos/queue.h"
}

// Scheduled scan types
enum class ScheduledScanType {
    VULNERABILITY_SCAN,
    DISCOVERY_SCAN
};

// Scheduled scan configuration stored in PSRAM
struct ScheduledScan {
    psram_string id;              // Unique ID for the schedule
    psram_string name;            // Human-readable name
    ScheduledScanType type;       // Type of scan
    ProtocolType protocol;        // Protocol hint (for targeted scans)
    psram_string target;          // Target IP or range (e.g., "192.168.1.0/24" or "192.168.1.100")
    bool enabled;                 // Whether the schedule is active

    // Cron-style scheduling
    int minute;                   // 0-59 or -1 for "any"
    int hour;                     // 0-23 or -1 for "any"
    int day_of_month;             // 1-31 or -1 for "any"
    int month;                    // 1-12 or -1 for "any"
    int day_of_week;              // 0-6 (0=Sunday) or -1 for "any"

    uint64_t last_run_ms;         // Timestamp of last execution
    uint64_t next_run_ms;         // Timestamp of next execution
    psram_string last_result;     // Last execution result/status

    ScheduledScan() {
        PSRAMAllocator<char> alloc;
        id = psram_string(alloc);
        name = psram_string(alloc);
        target = psram_string(alloc);
        last_result = psram_string(alloc);
        type = ScheduledScanType::VULNERABILITY_SCAN;
        protocol = ProtocolType::UNKNOWN;
        enabled = true;
        minute = -1;
        hour = -1;
        day_of_month = -1;
        month = -1;
        day_of_week = -1;
        last_run_ms = 0;
        next_run_ms = 0;
    }
};

class VulnerabilityScanner;
class DiscoveryManager;

class CronScheduler {
public:
    CronScheduler();
    ~CronScheduler();

    // Initialize scheduler with scanner and discovery manager references
    bool initialize(VulnerabilityScanner* vuln_scanner, DiscoveryManager* discovery_mgr);
    void shutdown();

    // Schedule management
    psram_string addSchedule(const ScheduledScan& schedule);
    bool updateSchedule(const psram_string& id, const ScheduledScan& schedule);
    bool removeSchedule(const psram_string& id);
    bool enableSchedule(const psram_string& id, bool enabled);

    // Query schedules
    psram_vector<ScheduledScan> listSchedules() const;
    bool getSchedule(const psram_string& id, ScheduledScan& out) const;

    // Persistence
    bool loadSchedulesFromNVS();
    void requestSaveSchedules();
    void initializeSaverTask();
    void destroySaverTask();
    bool saveSchedulesToNVS();

    // Manual trigger
    bool triggerSchedule(const psram_string& id);

private:
    // FreeRTOS timer callback
    static void timerCallback(TimerHandle_t timer);
    void checkAndRunSchedules();

    // Execute a specific schedule
    void executeSchedule(ScheduledScan& schedule);

    // Calculate next run time based on cron expression
    uint64_t calculateNextRun(const ScheduledScan& schedule, uint64_t after_time_ms);
    bool matchesCronExpression(const ScheduledScan& schedule, const struct tm& time);

    // Generate unique ID
    psram_string generateScheduleId();

    static void saverTaskEntry(void* arg);
    void saverTaskLoop();

    VulnerabilityScanner* vuln_scanner_;
    DiscoveryManager* discovery_mgr_;

    psram_vector<ScheduledScan> schedules_;
    mutable SemaphoreHandle_t mutex_;

    TimerHandle_t timer_;
    bool initialized_;
    TaskHandle_t saver_task_ = nullptr;
    QueueHandle_t saver_queue_ = nullptr;
    StaticTask_t* saver_tcb_ = nullptr;
    StackType_t* saver_stack_ = nullptr;
    StaticQueue_t* saver_queue_struct_ = nullptr;
    uint8_t* saver_queue_storage_ = nullptr;
    volatile bool saver_task_active_ = false;
};
