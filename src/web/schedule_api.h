#pragma once

#include "../core/cron_scheduler.h"
#include "../core/psram_allocator.h"

extern "C" {
#include "cJSON.h"
}

namespace ScheduleAPI {

// Helper: Convert ScheduledScan to JSON
inline cJSON* scheduledScanToJSON(const ScheduledScan& scan) {
    cJSON* obj = cJSON_CreateObject();
    if (!obj) return nullptr;

    cJSON_AddStringToObject(obj, "id", scan.id.c_str());
    cJSON_AddStringToObject(obj, "name", scan.name.c_str());
    cJSON_AddStringToObject(obj, "target", scan.target.c_str());
    cJSON_AddStringToObject(obj, "type",
        scan.type == ScheduledScanType::VULNERABILITY_SCAN ? "vulnerability" : "discovery");
    cJSON_AddBoolToObject(obj, "enabled", scan.enabled);

    // Cron fields
    cJSON_AddNumberToObject(obj, "minute", scan.minute);
    cJSON_AddNumberToObject(obj, "hour", scan.hour);
    cJSON_AddNumberToObject(obj, "day_of_month", scan.day_of_month);
    cJSON_AddNumberToObject(obj, "month", scan.month);
    cJSON_AddNumberToObject(obj, "day_of_week", scan.day_of_week);

    // Timestamps
    cJSON_AddNumberToObject(obj, "last_run_ms", (double)scan.last_run_ms);
    cJSON_AddNumberToObject(obj, "next_run_ms", (double)scan.next_run_ms);
    cJSON_AddStringToObject(obj, "last_result", scan.last_result.c_str());

    return obj;
}

// Helper: Parse JSON to ScheduledScan
inline bool JSONToScheduledScan(const cJSON* json, ScheduledScan& scan) {
    if (!json) return false;

    // Parse name
    cJSON* name = cJSON_GetObjectItem(json, "name");
    if (name && cJSON_IsString(name)) {
        scan.name = PSRAMUtils::createPSRAMString(name->valuestring);
    }

    // Parse target
    cJSON* target = cJSON_GetObjectItem(json, "target");
    if (target && cJSON_IsString(target)) {
        scan.target = PSRAMUtils::createPSRAMString(target->valuestring);
    }

    // Parse type
    cJSON* type = cJSON_GetObjectItem(json, "type");
    if (type && cJSON_IsString(type)) {
        if (strcmp(type->valuestring, "vulnerability") == 0) {
            scan.type = ScheduledScanType::VULNERABILITY_SCAN;
        } else if (strcmp(type->valuestring, "discovery") == 0) {
            scan.type = ScheduledScanType::DISCOVERY_SCAN;
        }
    }

    // Parse enabled
    cJSON* enabled = cJSON_GetObjectItem(json, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        scan.enabled = cJSON_IsTrue(enabled);
    }

    // Parse cron fields
    cJSON* minute = cJSON_GetObjectItem(json, "minute");
    if (minute && cJSON_IsNumber(minute)) {
        scan.minute = (int)minute->valuedouble;
    }

    cJSON* hour = cJSON_GetObjectItem(json, "hour");
    if (hour && cJSON_IsNumber(hour)) {
        scan.hour = (int)hour->valuedouble;
    }

    cJSON* day_of_month = cJSON_GetObjectItem(json, "day_of_month");
    if (day_of_month && cJSON_IsNumber(day_of_month)) {
        scan.day_of_month = (int)day_of_month->valuedouble;
    }

    cJSON* month = cJSON_GetObjectItem(json, "month");
    if (month && cJSON_IsNumber(month)) {
        scan.month = (int)month->valuedouble;
    }

    cJSON* day_of_week = cJSON_GetObjectItem(json, "day_of_week");
    if (day_of_week && cJSON_IsNumber(day_of_week)) {
        scan.day_of_week = (int)day_of_week->valuedouble;
    }

    return true;
}

// GET /api/schedule/list
// Returns all scheduled scans
inline cJSON* handleScheduleList(CronScheduler* scheduler) {
    cJSON* response = cJSON_CreateObject();
    if (!response) return nullptr;

    if (!scheduler) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Scheduler not available");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);

    cJSON* schedules_array = cJSON_CreateArray();
    if (!schedules_array) {
        cJSON_Delete(response);
        return nullptr;
    }

    psram_vector<ScheduledScan> schedules = scheduler->listSchedules();
    for (const auto& scan : schedules) {
        cJSON* scan_obj = scheduledScanToJSON(scan);
        if (scan_obj) {
            cJSON_AddItemToArray(schedules_array, scan_obj);
        }
    }

    cJSON_AddItemToObject(response, "schedules", schedules_array);
    cJSON_AddNumberToObject(response, "count", schedules.size());

    return response;
}

// POST /api/schedule/create
// Creates a new scheduled scan
// Expected JSON: {"name": "...", "target": "...", "type": "vulnerability|discovery", "minute": -1, "hour": -1, ...}
inline cJSON* handleScheduleCreate(CronScheduler* scheduler, const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();
    if (!response) return nullptr;

    if (!scheduler) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Scheduler not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    ScheduledScan scan;
    if (!JSONToScheduledScan(request, scan)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid schedule data");
        return response;
    }

    psram_string id = scheduler->addSchedule(scan);
    cJSON_Delete(request);

    if (id.empty()) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to create schedule");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Schedule created successfully");
    cJSON_AddStringToObject(response, "id", id.c_str());

    return response;
}

// POST /api/schedule/update
// Updates an existing scheduled scan
// Expected JSON: {"id": "...", "name": "...", "target": "...", ...}
inline cJSON* handleScheduleUpdate(CronScheduler* scheduler, const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();
    if (!response) return nullptr;

    if (!scheduler) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Scheduler not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* id_obj = cJSON_GetObjectItem(request, "id");
    if (!id_obj || !cJSON_IsString(id_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid ID");
        return response;
    }

    psram_string id = PSRAMUtils::createPSRAMString(id_obj->valuestring);

    ScheduledScan scan;
    if (!JSONToScheduledScan(request, scan)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid schedule data");
        return response;
    }

    bool success = scheduler->updateSchedule(id, scan);
    cJSON_Delete(request);

    if (!success) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to update schedule");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Schedule updated successfully");

    return response;
}

// POST /api/schedule/delete
// Deletes a scheduled scan
// Expected JSON: {"id": "..."}
inline cJSON* handleScheduleDelete(CronScheduler* scheduler, const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();
    if (!response) return nullptr;

    if (!scheduler) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Scheduler not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* id_obj = cJSON_GetObjectItem(request, "id");
    if (!id_obj || !cJSON_IsString(id_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid ID");
        return response;
    }

    psram_string id = PSRAMUtils::createPSRAMString(id_obj->valuestring);
    cJSON_Delete(request);

    bool success = scheduler->removeSchedule(id);

    if (!success) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to delete schedule");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Schedule deleted successfully");

    return response;
}

// POST /api/schedule/toggle
// Enables/disables a scheduled scan
// Expected JSON: {"id": "...", "enabled": true/false}
inline cJSON* handleScheduleToggle(CronScheduler* scheduler, const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();
    if (!response) return nullptr;

    if (!scheduler) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Scheduler not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* id_obj = cJSON_GetObjectItem(request, "id");
    cJSON* enabled_obj = cJSON_GetObjectItem(request, "enabled");

    if (!id_obj || !cJSON_IsString(id_obj) || !enabled_obj || !cJSON_IsBool(enabled_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid parameters");
        return response;
    }

    psram_string id = PSRAMUtils::createPSRAMString(id_obj->valuestring);
    bool enabled = cJSON_IsTrue(enabled_obj);
    cJSON_Delete(request);

    bool success = scheduler->enableSchedule(id, enabled);

    if (!success) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to toggle schedule");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", enabled ? "Schedule enabled" : "Schedule disabled");

    return response;
}

// POST /api/schedule/trigger
// Manually triggers a scheduled scan
// Expected JSON: {"id": "..."}
inline cJSON* handleScheduleTrigger(CronScheduler* scheduler, const char* json_data, size_t data_len) {
    cJSON* response = cJSON_CreateObject();
    if (!response) return nullptr;

    if (!scheduler) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Scheduler not available");
        return response;
    }

    if (!json_data || data_len == 0) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "No data provided");
        return response;
    }

    cJSON* request = cJSON_ParseWithLength(json_data, data_len);
    if (!request) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Invalid JSON format");
        return response;
    }

    cJSON* id_obj = cJSON_GetObjectItem(request, "id");
    if (!id_obj || !cJSON_IsString(id_obj)) {
        cJSON_Delete(request);
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Missing or invalid ID");
        return response;
    }

    psram_string id = PSRAMUtils::createPSRAMString(id_obj->valuestring);
    cJSON_Delete(request);

    bool success = scheduler->triggerSchedule(id);

    if (!success) {
        cJSON_AddBoolToObject(response, "success", false);
        cJSON_AddStringToObject(response, "message", "Failed to trigger schedule");
        return response;
    }

    cJSON_AddBoolToObject(response, "success", true);
    cJSON_AddStringToObject(response, "message", "Schedule triggered successfully");

    return response;
}

} // namespace ScheduleAPI
