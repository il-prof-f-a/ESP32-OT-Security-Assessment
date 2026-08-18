#include "setup_session.h"

#include <cstdio>
#include <cstring>

extern "C" {
#include "esp_random.h"
#include "esp_timer.h"
}


namespace {
constexpr uint64_t kSessionLifetimeMs = 15ULL * 60ULL * 1000ULL;
constexpr uint64_t kFailureWindowMs = 60ULL * 1000ULL;
constexpr uint64_t kLockoutMs = 60ULL * 1000ULL;
constexpr uint8_t kMaximumFailures = 5;

void secureZero(void* pointer, size_t length) {
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(pointer);
    while (length-- > 0) *bytes++ = 0;
}

void randomHex(char* output, size_t random_bytes) {
    uint8_t random[16] = {};
    esp_fill_random(random, random_bytes);
    for (size_t index = 0; index < random_bytes; ++index) {
        std::snprintf(output + index * 2, 3, "%02x", random[index]);
    }
    secureZero(random, sizeof(random));
}
}  // namespace


uint64_t SetupSession::nowMilliseconds() {
    return static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
}

bool SetupSession::begin(const uint8_t mac[6]) {
    if (!mac) return false;
    zeroize();
    randomHex(token_, 16);
    randomHex(ap_password_, 12);
    const int written = std::snprintf(
        ap_ssid_, sizeof(ap_ssid_), "ESP32-OT-Setup-%02X%02X%02X",
        mac[3], mac[4], mac[5]);
    if (written <= 0 || static_cast<size_t>(written) >= sizeof(ap_ssid_)) {
        zeroize();
        return false;
    }
    started_ms_ = nowMilliseconds();
    failure_window_ms_ = started_ms_;
    active_ = true;
    return true;
}

bool SetupSession::validateToken(const char* candidate, size_t length) {
    const uint64_t now = nowMilliseconds();
    if (!active_ || isExpired() || !candidate || length != sizeof(token_) - 1 ||
        now < locked_until_ms_) {
        return false;
    }
    if (now - failure_window_ms_ >= kFailureWindowMs) {
        failure_window_ms_ = now;
        failures_in_window_ = 0;
    }
    volatile uint8_t difference = 0;
    for (size_t index = 0; index < length; ++index) {
        difference |= static_cast<uint8_t>(candidate[index] ^ token_[index]);
    }
    if (difference == 0) {
        failures_in_window_ = 0;
        return true;
    }
    if (++failures_in_window_ >= kMaximumFailures) {
        locked_until_ms_ = now + kLockoutMs;
        failures_in_window_ = 0;
        failure_window_ms_ = now;
    }
    return false;
}

bool SetupSession::isLockedOut() const {
    return active_ && nowMilliseconds() < locked_until_ms_;
}

bool SetupSession::isExpired() const {
    return !active_ || nowMilliseconds() - started_ms_ >= kSessionLifetimeMs;
}

uint64_t SetupSession::remainingMilliseconds() const {
    if (isExpired()) return 0;
    return kSessionLifetimeMs - (nowMilliseconds() - started_ms_);
}

void SetupSession::consume() {
    zeroize();
}

void SetupSession::zeroize() {
    secureZero(token_, sizeof(token_));
    secureZero(ap_password_, sizeof(ap_password_));
    secureZero(ap_ssid_, sizeof(ap_ssid_));
    started_ms_ = 0;
    failure_window_ms_ = 0;
    locked_until_ms_ = 0;
    failures_in_window_ = 0;
    active_ = false;
}
