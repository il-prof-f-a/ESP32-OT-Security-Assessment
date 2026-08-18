#pragma once

#include <cstddef>
#include <cstdint>


class SetupSession {
public:
    SetupSession() = default;
    ~SetupSession() { zeroize(); }
    SetupSession(const SetupSession&) = delete;
    SetupSession& operator=(const SetupSession&) = delete;

    bool begin(const uint8_t mac[6]);
    bool validateToken(const char* candidate, size_t length);
    bool isLockedOut() const;
    bool isExpired() const;
    uint64_t remainingMilliseconds() const;
    void consume();
    void zeroize();
    const char* setupToken() const { return token_; }
    const char* apSsid() const { return ap_ssid_; }
    const char* apPassword() const { return ap_password_; }

private:
    static uint64_t nowMilliseconds();
    char token_[33] = {};
    char ap_ssid_[33] = {};
    char ap_password_[25] = {};
    uint64_t started_ms_ = 0;
    uint64_t failure_window_ms_ = 0;
    uint64_t locked_until_ms_ = 0;
    uint8_t failures_in_window_ = 0;
    bool active_ = false;
};
