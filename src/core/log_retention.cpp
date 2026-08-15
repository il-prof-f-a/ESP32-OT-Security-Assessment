#include <time.h>
#include "log_retention.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include "task_config.h"
extern "C" {
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "esp_timer.h"
}
struct Entry { std::string path; off_t size; time_t mtime; };

static bool list_files(const std::string& dir, std::vector<Entry>& out){
    out.clear();
    DIR* d = opendir(dir.c_str()); if (!d) return false;
    struct dirent* e;
    while ((e=readdir(d))){
        std::string pth = dir + std::string("/") + e->d_name;
        struct stat st{};
        if (stat(pth.c_str(), &st)==0 && S_ISREG(st.st_mode)) {
            out.push_back(Entry{pth, st.st_size, st.st_mtime});
        }
    }
    closedir(d);
    return true;
}

void LogRetentionManager::init(const LogRetentionConfig& c){ cfg_ = c; }
void LogRetentionManager::startTask(){
    TaskHandle_t th = TaskConfig::createTask(
        &LogRetentionManager::taskThunk,
        "log_retention",
        TaskConfig::Presets::LOG_RETENTION,
        this,
        1
    );
    (void)th; // Suppress unused warning
}
void LogRetentionManager::taskThunk(void* arg){ reinterpret_cast<LogRetentionManager*>(arg)->loop(); }

void LogRetentionManager::loop(){
    while (true){
        runOnce();
        vTaskDelay(pdMS_TO_TICKS(cfg_.period_min * 60 * 1000));
    }
}

void LogRetentionManager::runOnce(){
    std::vector<Entry> v; if (!list_files(cfg_.dir, v)) return;
    // age
    time_t now = time(nullptr);
    for (auto const& e : v){
        double days = difftime(now, e.mtime) / 86400.0;
        if (cfg_.max_days>0 && days > cfg_.max_days) unlink(e.path.c_str());
    }
    // size quota
    v.clear(); if (!list_files(cfg_.dir, v)) return;
    long long quota = (long long)cfg_.max_mb * 1024LL * 1024LL;
    long long total = 0; for (auto const& e : v) total += e.size;
    if (quota>0 && total > quota) {
        std::sort(v.begin(), v.end(), [](const Entry& a, const Entry& b){ return a.mtime < b.mtime; }); // oldest first
        for (auto const& e : v){
            if (total <= quota) break;
            unlink(e.path.c_str());
            total -= e.size;
        }
    }
}

#include "cJSON.h"
LogRetentionConfig LogRetentionManager::fromJSON(const std::string& s){
    LogRetentionConfig c;
    cJSON* o = cJSON_Parse(s.c_str()); if (!o) return c;
    cJSON* v=nullptr;
    if ((v=cJSON_GetObjectItem(o,"dir")) && cJSON_IsString(v)) c.dir=v->valuestring;
    if ((v=cJSON_GetObjectItem(o,"max_mb")) && cJSON_IsNumber(v)) c.max_mb=(uint32_t)v->valuedouble;
    if ((v=cJSON_GetObjectItem(o,"max_days")) && cJSON_IsNumber(v)) c.max_days=(uint32_t)v->valuedouble;
    if ((v=cJSON_GetObjectItem(o,"period_min")) && cJSON_IsNumber(v)) c.period_min=(uint32_t)v->valuedouble;
    cJSON_Delete(o); return c;
}
std::string LogRetentionManager::toJSON(const LogRetentionConfig& c){
    cJSON* o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "dir", c.dir.c_str());
    cJSON_AddNumberToObject(o, "max_mb", c.max_mb);
    cJSON_AddNumberToObject(o, "max_days", c.max_days);
    cJSON_AddNumberToObject(o, "period_min", c.period_min);
    char* s = cJSON_PrintUnformatted(o);
    std::string out = s? s:"{}"; if (s) free(s); cJSON_Delete(o); return out;
}
