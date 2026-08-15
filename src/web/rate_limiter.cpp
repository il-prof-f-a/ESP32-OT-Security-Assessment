#include "rate_limiter.h"
#include "../core/logging_system.h"
#include "../core/psram_allocator.h"
#include <algorithm>
#include <cstring>

extern "C" {
    #include "esp_http_server.h"
    #include "esp_netif.h"
    #include "lwip/sockets.h"
    #include "lwip/inet.h"
}

static const char* TAG_RL = "RateLimiter";

// Global instance
RateLimiter* g_rate_limiter = nullptr;

RateLimiter::RateLimiter()
    : total_blocks_issued_(0)
    , total_requests_blocked_(0)
    , initialized_(false)
{
    PSRAMAllocator<std::pair<const psram_string, ClientInfo>> alloc;
    clients_ = psram_map<psram_string, ClientInfo>(alloc);
}

RateLimiter::~RateLimiter() {
    clients_.clear();
}

void RateLimiter::initialize(const RateLimitConfig& config) {
    config_ = config;
    initialized_ = true;
    LOG_INFOF(TAG_RL, "RateLimiter initialized: max_rate=%u/min, auth_threshold=%u, block_duration=%ums",
              config_.max_requests_per_minute, config_.auth_failure_threshold, config_.block_duration_ms);
}

bool RateLimiter::allowRequest(const char* client_id) {
    if (!initialized_ || !config_.enabled || !client_id) {
        return true; // Allow if not initialized or disabled
    }

    std::lock_guard<std::mutex> lock(mutex_);

    ClientInfo* client = getClientInfo(client_id);
    if (!client) {
        LOG_WARNINGF(TAG_RL, "Failed to get client info for %s", client_id);
        return true; // Allow on error
    }

    uint64_t now_ms = esp_timer_get_time() / 1000;

    // Check if client is blocked
    if (client->is_blocked && now_ms < client->blocked_until_ms) {
        total_requests_blocked_++;
        LOG_INFOF(TAG_RL, "Blocked request from %s (blocked until %llu)",
                  client_id, client->blocked_until_ms);
        return false;
    }

    // Unblock if block duration expired
    if (client->is_blocked && now_ms >= client->blocked_until_ms) {
        client->is_blocked = false;
        LOG_INFOF(TAG_RL, "Client %s block expired", client_id);
    }

    // Check cooldown period - reset rate limit if cooldown successful
    if (isInCooldown(*client)) {
        uint64_t cooldown_elapsed = now_ms - client->cooldown_start_ms;
        if (cooldown_elapsed >= config_.cooldown_period_ms) {
            // Cooldown successful - reset to initial rate
            resetClientLimits(*client);
            LOG_INFOF(TAG_RL, "Client %s completed cooldown, rate limit reset to %u/min",
                      client_id, client->current_rate_limit);
        }
    }

    // Reset counter if new minute started
    uint64_t minute_elapsed = now_ms - client->minute_start_ms;
    if (minute_elapsed >= 60000) { // 1 minute in ms
        client->minute_start_ms = now_ms;
        client->request_count = 0;
    }

    // Check rate limit
    client->request_count++;

    if (client->request_count > client->current_rate_limit) {
        // Rate limit exceeded
        client->violation_count++;
        client->last_violation_ms = now_ms;

        // Halve the rate limit
        uint32_t old_limit = client->current_rate_limit;
        client->current_rate_limit = std::max<uint32_t>(1u, client->current_rate_limit / 2);

        // Block for 10 minutes
        blockClient(*client, "Rate limit exceeded");

        LOG_WARNINGF(TAG_RL, "Client %s exceeded rate limit (%u > %u). Violations: %u, New limit: %u/min, Blocked for %ums",
                     client_id, client->request_count, old_limit,
                     client->violation_count, client->current_rate_limit, config_.block_duration_ms);

        // Start cooldown period if not already started
        if (client->cooldown_start_ms == 0) {
            client->cooldown_start_ms = now_ms;
        }

        total_requests_blocked_++;
        return false;
    }

    return true;
}

void RateLimiter::recordAuthFailure(const char* client_id) {
    if (!initialized_ || !config_.enabled || !client_id) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    ClientInfo* client = getClientInfo(client_id);
    if (!client) {
        return;
    }

    client->auth_failures++;

    LOG_WARNINGF(TAG_RL, "Auth failure for %s (total: %u)", client_id, client->auth_failures);

    if (client->auth_failures >= config_.auth_failure_threshold) {
        blockClient(*client, "Too many authentication failures");
        LOG_ERRORF(TAG_RL, "Client %s blocked due to %u auth failures",
                   client_id, client->auth_failures);
    }
}

bool RateLimiter::isBlocked(const char* client_id, uint64_t& blocked_until_ms, psram_string& reason) {
    if (!initialized_ || !config_.enabled || !client_id) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = clients_.find(PSRAMUtils::createPSRAMString(client_id));
    if (it == clients_.end()) {
        return false;
    }

    const ClientInfo& client = it->second;
    uint64_t now_ms = esp_timer_get_time() / 1000;

    if (client.is_blocked && now_ms < client.blocked_until_ms) {
        blocked_until_ms = client.blocked_until_ms;

        // Generate reason message
        char reason_buf[256];
        if (client.auth_failures >= config_.auth_failure_threshold) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "Too many authentication failures (%lu). Blocked until %llu ms",
                     static_cast<unsigned long>(client.auth_failures),
                     static_cast<unsigned long long>(blocked_until_ms));
        } else {
            snprintf(reason_buf, sizeof(reason_buf),
                     "Rate limit exceeded. Current limit: %lu req/min. Blocked until %llu ms",
                     static_cast<unsigned long>(client.current_rate_limit),
                     static_cast<unsigned long long>(blocked_until_ms));
        }
        reason = PSRAMUtils::createPSRAMString(reason_buf);
        return true;
    }

    return false;
}

uint32_t RateLimiter::getCurrentRateLimit(const char* client_id) {
    if (!initialized_ || !client_id) {
        return config_.max_requests_per_minute;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = clients_.find(PSRAMUtils::createPSRAMString(client_id));
    if (it == clients_.end()) {
        return config_.max_requests_per_minute;
    }

    return it->second.current_rate_limit;
}

bool RateLimiter::unblockClient(const char* client_id) {
    if (!initialized_ || !client_id) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = clients_.find(PSRAMUtils::createPSRAMString(client_id));
    if (it == clients_.end()) {
        return false;
    }

    ClientInfo& client = it->second;
    if (client.is_blocked) {
        client.is_blocked = false;
        client.blocked_until_ms = 0;
        client.auth_failures = 0;
        LOG_INFOF(TAG_RL, "Client %s manually unblocked", client_id);
        return true;
    }

    return false;
}

RateLimiter::Stats RateLimiter::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Stats stats;
    stats.total_clients = clients_.size();
    stats.blocked_clients = 0;
    stats.total_blocks_issued = total_blocks_issued_;
    stats.total_requests_blocked = total_requests_blocked_;

    uint64_t now_ms = esp_timer_get_time() / 1000;
    for (const auto& pair : clients_) {
        if (pair.second.is_blocked && now_ms < pair.second.blocked_until_ms) {
            stats.blocked_clients++;
        }
    }

    return stats;
}

void RateLimiter::updateConfig(const RateLimitConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    LOG_INFOF(TAG_RL, "Configuration updated: max_rate=%u/min, auth_threshold=%u",
              config_.max_requests_per_minute, config_.auth_failure_threshold);
}

RateLimitConfig RateLimiter::getConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

void RateLimiter::cleanup() {
    if (!initialized_) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t now_ms = esp_timer_get_time() / 1000;
    const uint64_t MAX_IDLE_TIME = 3600000; // 1 hour

    // Remove clients that haven't been active for over 1 hour and are not blocked
    auto it = clients_.begin();
    while (it != clients_.end()) {
        const ClientInfo& client = it->second;
        uint64_t last_activity = std::max(client.minute_start_ms, client.last_violation_ms);

        bool can_remove = false;
        if (!client.is_blocked && (now_ms - last_activity) > MAX_IDLE_TIME) {
            can_remove = true;
        } else if (client.is_blocked && now_ms > client.blocked_until_ms + MAX_IDLE_TIME) {
            can_remove = true;
        }

        if (can_remove) {
            it = clients_.erase(it);
        } else {
            ++it;
        }
    }

    LOG_INFOF(TAG_RL, "Cleanup completed. Active clients: %zu", clients_.size());
}

ClientInfo* RateLimiter::getClientInfo(const char* client_id) {
    psram_string id = PSRAMUtils::createPSRAMString(client_id);

    auto it = clients_.find(id);
    if (it != clients_.end()) {
        return &(it->second);
    }

    // Create new client info
    ClientInfo new_client;
    new_client.identifier = id;
    new_client.current_rate_limit = config_.max_requests_per_minute;
    new_client.minute_start_ms = esp_timer_get_time() / 1000;

    auto result = clients_.insert(std::make_pair(id, new_client));
    if (result.second) {
        return &(result.first->second);
    }

    return nullptr;
}

bool RateLimiter::isInCooldown(const ClientInfo& client) {
    return client.cooldown_start_ms > 0 && client.violation_count > 0;
}

void RateLimiter::resetClientLimits(ClientInfo& client) {
    client.current_rate_limit = config_.max_requests_per_minute;
    client.violation_count = 0;
    client.cooldown_start_ms = 0;
    client.last_violation_ms = 0;
    client.request_count = 0;
}

void RateLimiter::blockClient(ClientInfo& client, const char* reason) {
    uint64_t now_ms = esp_timer_get_time() / 1000;
    client.is_blocked = true;
    client.blocked_until_ms = now_ms + config_.block_duration_ms;
    total_blocks_issued_++;
}

// Helper functions implementation
namespace RateLimiterHelper {

psram_string getClientIdentifier(const void* req) {
    if (!req) {
        return PSRAMUtils::createPSRAMString("unknown");
    }

    httpd_req_t* r = (httpd_req_t*)req;

    // Try to get client IP address
    char ip_str[32] = {0};

    // Get socket file descriptor
    int sockfd = httpd_req_to_sockfd(r);
    if (sockfd >= 0) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);

        memset(&addr, 0, sizeof(addr));
        if (getpeername(sockfd, (struct sockaddr*)&addr, &addr_len) == 0) {
            inet_ntoa_r(addr.sin_addr, ip_str, sizeof(ip_str) - 1);
        }
    }

    if (ip_str[0] != '\0') {
        return PSRAMUtils::createPSRAMString(ip_str);
    }

    // Fallback to "unknown"
    return PSRAMUtils::createPSRAMString("unknown");
}

RequestCheckResult checkRequest(const void* req) {
    RequestCheckResult result;
    result.status = RequestStatus::ALLOWED;
    result.blocked_until_ms = 0;
    result.current_rate_limit = 60;

    if (!g_rate_limiter) {
        return result;
    }

    psram_string client_id = getClientIdentifier(req);

    // Check if blocked
    psram_string block_reason;
    if (g_rate_limiter->isBlocked(client_id.c_str(), result.blocked_until_ms, block_reason)) {
        // Determine block reason
        if (block_reason.find("authentication") != psram_string::npos) {
            result.status = RequestStatus::BLOCKED_AUTH_FAILURES;
        } else {
            result.status = RequestStatus::BLOCKED_RATE_LIMIT;
        }
        result.message = block_reason;
        result.current_rate_limit = g_rate_limiter->getCurrentRateLimit(client_id.c_str());
        return result;
    }

    // Check rate limit
    if (!g_rate_limiter->allowRequest(client_id.c_str())) {
        result.status = RequestStatus::BLOCKED_RATE_LIMIT;
        g_rate_limiter->isBlocked(client_id.c_str(), result.blocked_until_ms, result.message);
        result.current_rate_limit = g_rate_limiter->getCurrentRateLimit(client_id.c_str());
    } else {
        result.current_rate_limit = g_rate_limiter->getCurrentRateLimit(client_id.c_str());
    }

    return result;
}

void sendBlockedResponse(const void* req, const RequestCheckResult& result) {
    if (!req) return;

    httpd_req_t* r = (httpd_req_t*)req;

    // Calculate remaining block time in seconds
    uint64_t now_ms = esp_timer_get_time() / 1000;
    uint64_t remaining_ms = (result.blocked_until_ms > now_ms) ?
                            (result.blocked_until_ms - now_ms) : 0;
    uint32_t remaining_seconds = remaining_ms / 1000;
    uint32_t remaining_minutes = remaining_seconds / 60;

    // Build JSON response
    char response[512];
    if (result.status == RequestStatus::BLOCKED_AUTH_FAILURES) {
        snprintf(response, sizeof(response),
                 "{\"error\":\"Too many authentication failures\","
                 "\"message\":\"Your IP has been blocked due to too many failed login attempts. "
                 "Please try again in %lu minutes.\","
                 "\"blocked_until\":%llu,"
                 "\"retry_after\":%lu}",
                 static_cast<unsigned long>(remaining_minutes),
                 static_cast<unsigned long long>(result.blocked_until_ms),
                 static_cast<unsigned long>(remaining_seconds));
    } else {
        snprintf(response, sizeof(response),
                 "{\"error\":\"Rate limit exceeded\","
                 "\"message\":\"Too many requests. Your current rate limit is %lu requests per minute. "
                 "Please try again in %lu minutes.\","
                 "\"current_limit\":%lu,"
                 "\"blocked_until\":%llu,"
                 "\"retry_after\":%lu}",
                 static_cast<unsigned long>(result.current_rate_limit),
                 static_cast<unsigned long>(remaining_minutes),
                 static_cast<unsigned long>(result.current_rate_limit),
                 static_cast<unsigned long long>(result.blocked_until_ms),
                 static_cast<unsigned long>(remaining_seconds));
    }

    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_status(r, "429 Too Many Requests");

    // Add Retry-After header
    char retry_header[32];
    snprintf(retry_header, sizeof(retry_header), "%lu", static_cast<unsigned long>(remaining_seconds));
    httpd_resp_set_hdr(r, "Retry-After", retry_header);

    httpd_resp_send(r, response, strlen(response));
}

} // namespace RateLimiterHelper
