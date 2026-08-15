#pragma once

#include <map>
#include <string>
#include <cstdint>
#include <mutex>
#include "../core/psram_allocator.h"

extern "C" {
    #include "esp_timer.h"
}

// Rate limiting and IP blocking configuration
struct RateLimitConfig {
    uint32_t max_requests_per_minute;       // Initial rate limit
    uint32_t auth_failure_threshold;        // Failed auth attempts before block
    uint32_t block_duration_ms;             // 10 minutes in ms
    uint32_t cooldown_period_ms;            // 6 hours in ms
    bool enabled;

    RateLimitConfig()
        : max_requests_per_minute(60)       // Default: 60 req/min
        , auth_failure_threshold(5)         // Default: 5 failed attempts
        , block_duration_ms(600000)         // 10 minutes
        , cooldown_period_ms(21600000)      // 6 hours
        , enabled(true)
    {}
};

// Client tracking information stored in PSRAM
struct ClientInfo {
    psram_string identifier;                // IP or MAC address
    uint32_t request_count;                 // Requests in current minute
    uint32_t auth_failures;                 // Failed authentication attempts
    uint32_t current_rate_limit;            // Current max rate (can be reduced)
    uint64_t minute_start_ms;               // Start of current minute window
    uint64_t blocked_until_ms;              // Timestamp when block expires
    uint64_t last_violation_ms;             // Last time rate limit was violated
    uint64_t cooldown_start_ms;             // Start of cooldown period
    uint32_t violation_count;               // Number of rate limit violations
    bool is_blocked;

    ClientInfo() {
        PSRAMAllocator<char> alloc;
        identifier = psram_string(alloc);
        request_count = 0;
        auth_failures = 0;
        current_rate_limit = 60;
        minute_start_ms = 0;
        blocked_until_ms = 0;
        last_violation_ms = 0;
        cooldown_start_ms = 0;
        violation_count = 0;
        is_blocked = false;
    }
};

class RateLimiter {
public:
    RateLimiter();
    ~RateLimiter();

    // Initialize with configuration
    void initialize(const RateLimitConfig& config);

    // Check if request should be allowed
    bool allowRequest(const char* client_id);

    // Record authentication failure
    void recordAuthFailure(const char* client_id);

    // Get block information for client
    bool isBlocked(const char* client_id, uint64_t& blocked_until_ms, psram_string& reason);

    // Get current rate limit for client
    uint32_t getCurrentRateLimit(const char* client_id);

    // Manually unblock a client (admin function)
    bool unblockClient(const char* client_id);

    // Get statistics for monitoring
    struct Stats {
        uint32_t total_clients;
        uint32_t blocked_clients;
        uint32_t total_blocks_issued;
        uint32_t total_requests_blocked;
    };
    Stats getStats() const;

    // Configuration management
    void updateConfig(const RateLimitConfig& config);
    RateLimitConfig getConfig() const;

    // Cleanup old entries (call periodically)
    void cleanup();

private:
    // Get or create client info
    ClientInfo* getClientInfo(const char* client_id);

    // Check if client is in cooldown period
    bool isInCooldown(const ClientInfo& client);

    // Reset client rate limit after successful cooldown
    void resetClientLimits(ClientInfo& client);

    // Block client for specified duration
    void blockClient(ClientInfo& client, const char* reason);

    RateLimitConfig config_;
    psram_map<psram_string, ClientInfo> clients_;
    mutable std::mutex mutex_;

    // Statistics
    uint32_t total_blocks_issued_;
    uint32_t total_requests_blocked_;

    bool initialized_;
};

// Global rate limiter instance
extern RateLimiter* g_rate_limiter;

// Helper functions for web server integration
namespace RateLimiterHelper {

// Extract client identifier from HTTP request (IP or MAC)
psram_string getClientIdentifier(const void* req);

// Check request and return appropriate HTTP status/message
enum class RequestStatus {
    ALLOWED,
    BLOCKED_AUTH_FAILURES,
    BLOCKED_RATE_LIMIT
};

struct RequestCheckResult {
    RequestStatus status;
    psram_string message;
    uint64_t blocked_until_ms;
    uint32_t current_rate_limit;
};

RequestCheckResult checkRequest(const void* req);

// Generate appropriate HTTP error response
void sendBlockedResponse(const void* req, const RequestCheckResult& result);

} // namespace RateLimiterHelper
