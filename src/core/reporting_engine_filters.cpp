#include "reporting_engine.h"
#include "logging_system.h"
#include <algorithm>
#include <cctype>

void ReportingEngine::populateChannelFiltersFromJSON(cJSON* channel_json, ChannelConfig& cfg) {
    cfg.include_filters.clear();
    cfg.exclude_filters.clear();
    cfg.filters_enabled = false;
    cfg.case_sensitive = false;

    if (!channel_json) {
        return;
    }

    cJSON* filters = cJSON_GetObjectItem(channel_json, "filters");
    if (!(filters && cJSON_IsObject(filters))) {
        return;
    }

    cJSON* enabled = cJSON_GetObjectItem(filters, "enabled");
    if (enabled && cJSON_IsBool(enabled)) {
        cfg.filters_enabled = cJSON_IsTrue(enabled);
    }

    cJSON* case_sensitive = cJSON_GetObjectItem(filters, "case_sensitive");
    if (case_sensitive && cJSON_IsBool(case_sensitive)) {
        cfg.case_sensitive = cJSON_IsTrue(case_sensitive);
    }

    cJSON* include_filters = cJSON_GetObjectItem(filters, "include");
    if (include_filters && cJSON_IsArray(include_filters)) {
        cJSON* pattern = nullptr;
        cJSON_ArrayForEach(pattern, include_filters) {
            if (cJSON_IsString(pattern) && pattern->valuestring) {
                psram_string pattern_ps = PSRAMUtils::createPSRAMString(pattern->valuestring);
                if (!pattern_ps.empty()) {
                    cfg.include_filters.push_back(std::move(pattern_ps));
                }
            }
        }
    }

    cJSON* exclude_filters = cJSON_GetObjectItem(filters, "exclude");
    if (exclude_filters && cJSON_IsArray(exclude_filters)) {
        cJSON* pattern = nullptr;
        cJSON_ArrayForEach(pattern, exclude_filters) {
            if (cJSON_IsString(pattern) && pattern->valuestring) {
                psram_string pattern_ps = PSRAMUtils::createPSRAMString(pattern->valuestring);
                if (!pattern_ps.empty()) {
                    cfg.exclude_filters.push_back(std::move(pattern_ps));
                }
            }
        }
    }
}

// ============================================================================
// REGEX FILTER IMPLEMENTATION (ESP-IDF Compatible - No Exceptions)
// ============================================================================

bool ReportingEngine::shouldSendToChannel(const ChannelConfig& cfg, const psram_string& content) const {
    // If filters not enabled, always send
    if (!cfg.filters_enabled) {
        return true;
    }

    // Check exclude filters first (blacklist - highest priority)
    for (const auto& exclude_pattern : cfg.exclude_filters) {
        if (matchesRegexPattern(content, exclude_pattern, cfg.case_sensitive)) {
            return false; // Excluded if matches any exclude pattern
        }
    }

    // If no include filters specified, allow everything (that didn't match exclude)
    if (cfg.include_filters.empty()) {
        return true;
    }

    // Check include filters (whitelist)
    for (const auto& include_pattern : cfg.include_filters) {
        if (matchesRegexPattern(content, include_pattern, cfg.case_sensitive)) {
            return true; // Included if matches any include pattern
        }
    }

    // Doesn't match any include pattern = exclude
    return false;
}

bool ReportingEngine::matchesRegexPattern(const psram_string& content, const psram_string& pattern, bool case_sensitive) const {
    // Convert PSRAM strings to std::string for regex (avoid if memory critical)
    if (PSRAMUtils::isCriticalMemory()) {
        return true; // Skip filtering during critical memory to avoid crashes
    }

    std::string content_str = PSRAMUtils::fromPSRAMString(content);
    std::string pattern_str = PSRAMUtils::fromPSRAMString(pattern);

    if (content_str.empty() && !content.empty()) {
        return true; // Memory pressure - skip filtering
    }
    if (pattern_str.empty() && !pattern.empty()) {
        return true; // Memory pressure - skip filtering
    }

    // Simple pattern matching without exceptions
    if (pattern_str.empty()) {
        return true; // Empty pattern matches everything
    }

    // Case sensitivity handling
    std::string search_content = content_str;
    std::string search_pattern = pattern_str;

    if (!case_sensitive) {
        std::transform(search_content.begin(), search_content.end(), search_content.begin(), ::tolower);
        std::transform(search_pattern.begin(), search_pattern.end(), search_pattern.begin(), ::tolower);
    }

    // For now, implement basic substring search instead of full regex
    // This avoids regex exceptions and compilation issues in ESP-IDF
    // TODO: Can be enhanced with proper wildcard matching later
    return search_content.find(search_pattern) != std::string::npos;
}

bool ReportingEngine::setChannelFilters(const psram_string& name, const psram_string_vector& include_filters,
                                       const psram_string_vector& exclude_filters, bool enabled, bool case_sensitive) {
    auto it = chans_.find(name);
    if (it == chans_.end()) {
        return false; // Channel not found
    }

    it->second.cfg.include_filters = include_filters;
    it->second.cfg.exclude_filters = exclude_filters;
    it->second.cfg.filters_enabled = enabled;
    it->second.cfg.case_sensitive = case_sensitive;

    return true;
}

bool ReportingEngine::addChannelIncludeFilter(const psram_string& name, const psram_string& pattern) {
    auto it = chans_.find(name);
    if (it == chans_.end()) {
        return false;
    }

    it->second.cfg.include_filters.push_back(pattern);
    return true;
}

bool ReportingEngine::addChannelExcludeFilter(const psram_string& name, const psram_string& pattern) {
    auto it = chans_.find(name);
    if (it == chans_.end()) {
        return false;
    }

    it->second.cfg.exclude_filters.push_back(pattern);
    return true;
}

bool ReportingEngine::removeChannelFilter(const psram_string& name, const psram_string& pattern, bool is_include) {
    auto it = chans_.find(name);
    if (it == chans_.end()) {
        return false;
    }

    auto& filters = is_include ? it->second.cfg.include_filters : it->second.cfg.exclude_filters;
    auto filter_it = std::find(filters.begin(), filters.end(), pattern);

    if (filter_it != filters.end()) {
        filters.erase(filter_it);
        return true;
    }

    return false;
}

bool ReportingEngine::setChannelFiltersEnabled(const psram_string& name, bool enabled) {
    auto it = chans_.find(name);
    if (it == chans_.end()) {
        return false;
    }

    it->second.cfg.filters_enabled = enabled;
    return true;
}

psram_string ReportingEngine::getChannelFiltersJSON(const psram_string& name) const {
    auto it = chans_.find(name);
    if (it == chans_.end()) {
        return PSRAMUtils::createPSRAMString("{}");
    }

    const auto& cfg = it->second.cfg;

    cJSON* root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "enabled", cfg.filters_enabled);
    cJSON_AddBoolToObject(root, "case_sensitive", cfg.case_sensitive);

    // Include filters array
    cJSON* include_array = cJSON_CreateArray();
    for (const auto& pattern : cfg.include_filters) {
        std::string pattern_str = PSRAMUtils::fromPSRAMString(pattern);
        if (!pattern_str.empty()) {
            cJSON_AddItemToArray(include_array, cJSON_CreateString(pattern_str.c_str()));
        }
    }
    cJSON_AddItemToObject(root, "include", include_array);

    // Exclude filters array
    cJSON* exclude_array = cJSON_CreateArray();
    for (const auto& pattern : cfg.exclude_filters) {
        std::string pattern_str = PSRAMUtils::fromPSRAMString(pattern);
        if (!pattern_str.empty()) {
            cJSON_AddItemToArray(exclude_array, cJSON_CreateString(pattern_str.c_str()));
        }
    }
    cJSON_AddItemToObject(root, "exclude", exclude_array);

    char* json_str = cJSON_PrintUnformatted(root);
    psram_string result = json_str ? PSRAMUtils::createPSRAMString(json_str) : PSRAMUtils::createPSRAMString("{}");

    if (json_str) free(json_str);
    cJSON_Delete(root);

    return result;
}
