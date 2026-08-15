#pragma once
#include <cstdint>
#include <string>

struct LogRetentionConfig {
    std::string dir = "/data/logs";
    uint32_t max_mb = 2;   // aggressive total quota - 2MB max
    uint32_t max_days = 3; // aggressive age limit - 3 days max
    uint32_t period_min = 5; // frequent scan - every 5 minutes
};

class LogRetentionManager {
public:
    void init(const LogRetentionConfig& cfg);
    void startTask();
    void runOnce();

    // glue to config
    static LogRetentionConfig fromJSON(const std::string& s);
    static std::string toJSON(const LogRetentionConfig& c);

private:
    LogRetentionConfig cfg_;
    static void taskThunk(void* arg);
    void loop();
};
