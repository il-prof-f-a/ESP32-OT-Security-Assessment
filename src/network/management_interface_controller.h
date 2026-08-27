#pragma once

#include <cstdint>

class EthernetManager;
class WebServer;
class WiFiManager;

enum class ManagementInterfaceState {
    WAITING_FOR_INTERFACE,
    ACTIVE_WIFI,
    ACTIVE_ETHERNET,
    BLOCKED_SUBNET_OVERLAP,
    BLOCKED_INTERFACE_LOST,
    START_FAILED,
};

enum class ManagementInterfaceAction {
    None,
    Start,
    Stop,
};

enum class ManagementRuntimePolicy {
    WifiOnly,
    EthernetOnly,
};

// Addresses and masks in this platform-independent model use host byte order.
struct ManagementInterfaceSnapshot {
    bool ready = false;
    uint32_t address = 0;
    uint32_t netmask = 0;
};

struct ManagementRuntimeInput {
    ManagementRuntimePolicy policy = ManagementRuntimePolicy::WifiOnly;
    ManagementInterfaceSnapshot wifi{};
    ManagementInterfaceSnapshot ethernet{};
    bool server_running = false;
    bool interface_was_active = false;
    uint32_t active_address = 0;
};

struct ManagementRuntimeDecision {
    ManagementInterfaceState state = ManagementInterfaceState::WAITING_FOR_INTERFACE;
    ManagementInterfaceAction action = ManagementInterfaceAction::None;
    uint32_t allowed_address = 0;
};

constexpr bool ipv4NetmaskIsContiguous(uint32_t netmask) {
    const uint32_t host_bits = ~netmask;
    return (host_bits & (host_bits + 1U)) == 0U;
}

constexpr bool ipv4SnapshotIsUsable(const ManagementInterfaceSnapshot& value) {
    return value.ready && value.address != 0U && ipv4NetmaskIsContiguous(value.netmask);
}

constexpr bool ipv4SubnetsOverlap(const ManagementInterfaceSnapshot& left,
                                  const ManagementInterfaceSnapshot& right) {
    if (!ipv4SnapshotIsUsable(left) || !ipv4SnapshotIsUsable(right)) return false;
    const uint32_t left_first = left.address & left.netmask;
    const uint32_t left_last = left_first | ~left.netmask;
    const uint32_t right_first = right.address & right.netmask;
    const uint32_t right_last = right_first | ~right.netmask;
    return left_first <= right_last && right_first <= left_last;
}

constexpr ManagementRuntimeDecision evaluateManagementRuntime(
    const ManagementRuntimeInput& input) {
    const bool wifi_policy = input.policy == ManagementRuntimePolicy::WifiOnly;
    const ManagementInterfaceSnapshot& allowed = wifi_policy ? input.wifi : input.ethernet;

    if (wifi_policy && ipv4SubnetsOverlap(input.wifi, input.ethernet)) {
        return {ManagementInterfaceState::BLOCKED_SUBNET_OVERLAP,
                input.server_running ? ManagementInterfaceAction::Stop
                                     : ManagementInterfaceAction::None,
                0};
    }

    if (!ipv4SnapshotIsUsable(allowed)) {
        return {input.interface_was_active || input.server_running
                    ? ManagementInterfaceState::BLOCKED_INTERFACE_LOST
                    : ManagementInterfaceState::WAITING_FOR_INTERFACE,
                input.server_running ? ManagementInterfaceAction::Stop
                                     : ManagementInterfaceAction::None,
                0};
    }

    const ManagementInterfaceState active_state =
        wifi_policy ? ManagementInterfaceState::ACTIVE_WIFI
                    : ManagementInterfaceState::ACTIVE_ETHERNET;
    if (input.server_running && input.active_address != allowed.address) {
        return {ManagementInterfaceState::BLOCKED_INTERFACE_LOST,
                ManagementInterfaceAction::Stop,
                0};
    }
    return {active_state,
            input.server_running ? ManagementInterfaceAction::None
                                 : ManagementInterfaceAction::Start,
            allowed.address};
}

const char* managementInterfaceStateName(ManagementInterfaceState state);
ManagementInterfaceState currentManagementInterfaceState();
bool managementInterfaceIsDegraded();

class ManagementInterfaceController {
public:
    ManagementInterfaceController(WebServer& web,
                                  EthernetManager& ethernet,
                                  WiFiManager& wifi);

    void tick();
    ManagementInterfaceState state() const { return state_; }
    uint32_t activeAddressHostOrder() const { return active_address_; }

private:
    void transitionTo(ManagementInterfaceState next);

    WebServer& web_;
    EthernetManager& ethernet_;
    WiFiManager& wifi_;
    ManagementInterfaceState state_ = ManagementInterfaceState::WAITING_FOR_INTERFACE;
    uint32_t active_address_ = 0;
    uint64_t next_start_attempt_us_ = 0;
    bool interface_was_active_ = false;
};
