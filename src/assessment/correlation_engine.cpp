#include "correlation_engine.h"
#include "../core/logging_system.h"
#include <algorithm>

extern "C" {
    #include "esp_timer.h"
}

static const char* TAG = "CorrelationEngine";

CorrelationEngine::CorrelationEngine() {
    PSRAMAllocator<CorrelationEvent> alloc;
    events_ = psram_vector<CorrelationEvent>(alloc);
    last_cleanup_ms_ = esp_timer_get_time() / 1000;
}

void CorrelationEngine::setConfig(const CorrelationConfig& cfg) {
    config_ = cfg;
    LOG_INFOF(TAG, "Config updated: time_window=%ums, min_events=%u, max_tracked=%u",
              config_.time_window_ms, config_.min_events_for_correlation, config_.max_events_tracked);
}

void CorrelationEngine::recordEvent(const CorrelationEvent& event) {
    if (!config_.enabled) {
        return;
    }

    // Check severity threshold
    if (event.severity < config_.severity_threshold) {
        return;
    }

    // Check event limit
    if (events_.size() >= config_.max_events_tracked) {
        // Remove the oldest event
        events_.erase(events_.begin());
    }

    events_.push_back(event);
    total_events_processed_++;

    // Periodic cleanup every 30s
    uint64_t now_ms = esp_timer_get_time() / 1000;
    if (now_ms - last_cleanup_ms_ > 30000) {
        cleanupOldEvents();
        last_cleanup_ms_ = now_ms;
    }
}

uint32_t CorrelationEngine::analyzeCorrelations(psram_vector<CorrelatedAttack>& out_attacks) {
    if (!config_.enabled || events_.size() < config_.min_events_for_correlation) {
        return 0;
    }

    uint64_t now_ms = esp_timer_get_time() / 1000;
    uint64_t window_start = now_ms - config_.time_window_ms;

    // Filter events in the time window
    PSRAMAllocator<CorrelationEvent> alloc;
    psram_vector<CorrelationEvent> recent_events(alloc);

    for (const auto& event : events_) {
        if (event.timestamp_ms >= window_start) {
            recent_events.push_back(event);
        }
    }

    if (recent_events.size() < config_.min_events_for_correlation) {
        return 0;
    }

    uint32_t detected_count = 0;

    // Pattern 1: Distributed Scan
    CorrelatedAttack scan_attack;
    if (detectDistributedScan(recent_events, scan_attack)) {
        out_attacks.push_back(scan_attack);
        detected_count++;
        total_correlated_attacks_++;
    }

    // Pattern 2: Coordinated Flood
    CorrelatedAttack flood_attack;
    if (detectCoordinatedFlood(recent_events, flood_attack)) {
        out_attacks.push_back(flood_attack);
        detected_count++;
        total_correlated_attacks_++;
    }

    // Pattern 3: Distributed Brute-Force
    CorrelatedAttack bruteforce_attack;
    if (detectBruteForceDistributed(recent_events, bruteforce_attack)) {
        out_attacks.push_back(bruteforce_attack);
        detected_count++;
        total_correlated_attacks_++;
    }

    if (detected_count > 0) {
        LOG_WARNINGF(TAG, "Detected %u correlated attack patterns from %zu events",
                     detected_count, recent_events.size());
    }

    return detected_count;
}

bool CorrelationEngine::detectDistributedScan(const psram_vector<CorrelationEvent>& events,
                                              CorrelatedAttack& out_attack) const {
    // Group events by target
    PSRAMAllocator<psram_string> str_alloc;
    PSRAMAllocator<psram_vector<CorrelationEvent>> vec_alloc;
    PSRAMAllocator<std::pair<const psram_string, psram_vector<CorrelationEvent>>> map_alloc;
    psram_map<psram_string, psram_vector<CorrelationEvent>> by_target{std::less<psram_string>(), map_alloc};

    groupEventsByTarget(events, by_target);

    // Look for targets with multiple different sources (distributed scan)
    for (const auto& pair : by_target) {
        psram_vector<psram_string> unique_sources(str_alloc);

        for (const auto& event : pair.second) {
            bool found = false;
            for (const auto& src : unique_sources) {
                if (src == event.source_ip) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                unique_sources.push_back(event.source_ip);
            }
        }

        // Detect if >=3 different sources attack the same target
        if (unique_sources.size() >= 3 && pair.second.size() >= config_.min_events_for_correlation) {
            out_attack.attack_pattern = PSRAMUtils::createPSRAMString("distributed_port_scan");
            out_attack.involved_sources = unique_sources;
            out_attack.involved_targets.push_back(pair.first);
            out_attack.event_count = pair.second.size();
            out_attack.first_seen_ms = pair.second.front().timestamp_ms;
            out_attack.last_seen_ms = pair.second.back().timestamp_ms;

            // Calculate combined severity
            float total_severity = 0.0f;
            for (const auto& event : pair.second) {
                total_severity += event.severity;
            }
            out_attack.combined_severity = std::min(1.0f, total_severity / unique_sources.size());

            LOG_WARNINGF(TAG, "Distributed scan detected: %zu sources → %s (%u events)",
                        unique_sources.size(), pair.first.c_str(), out_attack.event_count);

            return true;
        }
    }

    return false;
}

bool CorrelationEngine::detectCoordinatedFlood(const psram_vector<CorrelationEvent>& events,
                                               CorrelatedAttack& out_attack) const {
    // Group events by target
    PSRAMAllocator<psram_string> str_alloc;
    PSRAMAllocator<std::pair<const psram_string, psram_vector<CorrelationEvent>>> map_alloc;
    psram_map<psram_string, psram_vector<CorrelationEvent>> by_target{std::less<psram_string>(), map_alloc};

    groupEventsByTarget(events, by_target);

    // Look for multiple "flooding" events toward the same target
    for (const auto& pair : by_target) {
        uint32_t flood_count = 0;
        psram_vector<psram_string> flood_sources(str_alloc);

        for (const auto& event : pair.second) {
            if (event.attack_type.find("flood") != psram_string::npos) {
                flood_count++;

                bool found = false;
                for (const auto& src : flood_sources) {
                    if (src == event.source_ip) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    flood_sources.push_back(event.source_ip);
                }
            }
        }

        // Detect if >=2 flood sources toward the same target
        if (flood_count >= config_.min_events_for_correlation && flood_sources.size() >= 2) {
            out_attack.attack_pattern = PSRAMUtils::createPSRAMString("coordinated_flooding");
            out_attack.involved_sources = flood_sources;
            out_attack.involved_targets.push_back(pair.first);
            out_attack.event_count = flood_count;

            uint64_t min_ts = UINT64_MAX;
            uint64_t max_ts = 0;
            float total_severity = 0.0f;

            for (const auto& event : pair.second) {
                if (event.attack_type.find("flood") != psram_string::npos) {
                    if (event.timestamp_ms < min_ts) min_ts = event.timestamp_ms;
                    if (event.timestamp_ms > max_ts) max_ts = event.timestamp_ms;
                    total_severity += event.severity;
                }
            }

            out_attack.first_seen_ms = min_ts;
            out_attack.last_seen_ms = max_ts;
            out_attack.combined_severity = std::min(1.0f, total_severity / flood_sources.size());

            LOG_WARNINGF(TAG, "Coordinated flood detected: %zu sources → %s (%u events)",
                        flood_sources.size(), pair.first.c_str(), flood_count);

            return true;
        }
    }

    return false;
}

bool CorrelationEngine::detectBruteForceDistributed(const psram_vector<CorrelationEvent>& events,
                                                   CorrelatedAttack& out_attack) const {
    // Group events by target
    PSRAMAllocator<psram_string> str_alloc;
    PSRAMAllocator<std::pair<const psram_string, psram_vector<CorrelationEvent>>> map_alloc;
    psram_map<psram_string, psram_vector<CorrelationEvent>> by_target{std::less<psram_string>(), map_alloc};

    groupEventsByTarget(events, by_target);

    // Look for multiple failed authentication attempts from different sources
    for (const auto& pair : by_target) {
        uint32_t auth_fail_count = 0;
        psram_vector<psram_string> attack_sources(str_alloc);

        for (const auto& event : pair.second) {
            if (event.attack_type.find("brute") != psram_string::npos ||
                event.attack_type.find("auth") != psram_string::npos) {
                auth_fail_count++;

                bool found = false;
                for (const auto& src : attack_sources) {
                    if (src == event.source_ip) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    attack_sources.push_back(event.source_ip);
                }
            }
        }

        // Detect if >=3 different sources attempt auth toward the same target
        if (auth_fail_count >= config_.min_events_for_correlation && attack_sources.size() >= 2) {
            out_attack.attack_pattern = PSRAMUtils::createPSRAMString("distributed_brute_force");
            out_attack.involved_sources = attack_sources;
            out_attack.involved_targets.push_back(pair.first);
            out_attack.event_count = auth_fail_count;

            uint64_t min_ts = UINT64_MAX;
            uint64_t max_ts = 0;
            float total_severity = 0.0f;

            for (const auto& event : pair.second) {
                if (event.attack_type.find("brute") != psram_string::npos ||
                    event.attack_type.find("auth") != psram_string::npos) {
                    if (event.timestamp_ms < min_ts) min_ts = event.timestamp_ms;
                    if (event.timestamp_ms > max_ts) max_ts = event.timestamp_ms;
                    total_severity += event.severity;
                }
            }

            out_attack.first_seen_ms = min_ts;
            out_attack.last_seen_ms = max_ts;
            out_attack.combined_severity = std::min(1.0f, total_severity / attack_sources.size());

            LOG_WARNINGF(TAG, "Distributed brute-force detected: %zu sources → %s (%u events)",
                        attack_sources.size(), pair.first.c_str(), auth_fail_count);

            return true;
        }
    }

    return false;
}

void CorrelationEngine::groupEventsByTarget(const psram_vector<CorrelationEvent>& events,
                                           psram_map<psram_string, psram_vector<CorrelationEvent>>& out_groups) const {
    PSRAMAllocator<CorrelationEvent> alloc;

    for (const auto& event : events) {
        auto it = out_groups.find(event.dest_ip);
        if (it == out_groups.end()) {
            psram_vector<CorrelationEvent> vec(alloc);
            vec.push_back(event);
            out_groups[event.dest_ip] = vec;
        } else {
            it->second.push_back(event);
        }
    }
}

void CorrelationEngine::groupEventsBySource(const psram_vector<CorrelationEvent>& events,
                                           psram_map<psram_string, psram_vector<CorrelationEvent>>& out_groups) const {
    PSRAMAllocator<CorrelationEvent> alloc;

    for (const auto& event : events) {
        auto it = out_groups.find(event.source_ip);
        if (it == out_groups.end()) {
            psram_vector<CorrelationEvent> vec(alloc);
            vec.push_back(event);
            out_groups[event.source_ip] = vec;
        } else {
            it->second.push_back(event);
        }
    }
}

void CorrelationEngine::cleanupOldEvents() {
    if (events_.empty()) {
        return;
    }

    uint64_t now_ms = esp_timer_get_time() / 1000;
    uint64_t retention_cutoff = now_ms - config_.event_retention_ms;

    size_t before = events_.size();

    // Remove events beyond the retention period
    events_.erase(
        std::remove_if(events_.begin(), events_.end(),
            [retention_cutoff](const CorrelationEvent& e) {
                return e.timestamp_ms < retention_cutoff;
            }),
        events_.end()
    );

    size_t removed = before - events_.size();
    if (removed > 0) {
        LOG_INFOF(TAG, "Cleaned up %zu old events (retained: %zu)", removed, events_.size());
    }
}

void CorrelationEngine::reset() {
    events_.clear();
    total_events_processed_ = 0;
    total_correlated_attacks_ = 0;
    last_cleanup_ms_ = esp_timer_get_time() / 1000;
    LOG_INFO(TAG, "Correlation engine reset");
}
