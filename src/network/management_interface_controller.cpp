#include "management_interface_controller.h"

#include <arpa/inet.h>
#include <atomic>

#include "ethernet_manager.h"
#include "network_policy.h"
#include "wifi_manager.h"
#include "../core/logging_system.h"
#include "../web/web_server.h"

extern "C" {
#include "esp_netif.h"
#include "esp_timer.h"
}

namespace {
constexpr uint64_t kStartRetryDelayUs = 5ULL * 1000ULL * 1000ULL;
std::atomic<ManagementInterfaceState> g_management_state{
    ManagementInterfaceState::WAITING_FOR_INTERFACE};

ManagementInterfaceSnapshot snapshotFor(esp_netif_t* netif) {
    if (!netif) return {};
    esp_netif_ip_info_t info{};
    if (esp_netif_get_ip_info(netif, &info) != ESP_OK || info.ip.addr == 0U) return {};
    ManagementInterfaceSnapshot result{};
    result.ready = true;
    result.address = ntohl(info.ip.addr);
    result.netmask = ntohl(info.netmask.addr);
    if (!ipv4SnapshotIsUsable(result)) return {};
    return result;
}

esp_netif_t* preferredWifiNetif(WiFiManager& wifi) {
    if (ipv4SnapshotIsUsable(snapshotFor(wifi.sta()))) return wifi.sta();
    if (ipv4SnapshotIsUsable(snapshotFor(wifi.ap()))) return wifi.ap();
    return nullptr;
}
}  // namespace

const char* managementInterfaceStateName(ManagementInterfaceState state) {
    switch (state) {
        case ManagementInterfaceState::WAITING_FOR_INTERFACE: return "WAITING_FOR_INTERFACE";
        case ManagementInterfaceState::ACTIVE_WIFI: return "ACTIVE_WIFI";
        case ManagementInterfaceState::ACTIVE_ETHERNET: return "ACTIVE_ETHERNET";
        case ManagementInterfaceState::BLOCKED_SUBNET_OVERLAP: return "BLOCKED_SUBNET_OVERLAP";
        case ManagementInterfaceState::BLOCKED_INTERFACE_LOST: return "BLOCKED_INTERFACE_LOST";
        case ManagementInterfaceState::START_FAILED: return "START_FAILED";
    }
    return "UNKNOWN";
}

ManagementInterfaceState currentManagementInterfaceState() {
    return g_management_state.load(std::memory_order_acquire);
}

bool managementInterfaceIsDegraded() {
    const ManagementInterfaceState state = currentManagementInterfaceState();
    return state != ManagementInterfaceState::ACTIVE_WIFI &&
           state != ManagementInterfaceState::ACTIVE_ETHERNET;
}

ManagementInterfaceController::ManagementInterfaceController(WebServer& web,
                                                             EthernetManager& ethernet,
                                                             WiFiManager& wifi)
    : web_(web), ethernet_(ethernet), wifi_(wifi) {
    LOG_INFOF("ManagementPolicy", "Board=%s management=%s WiFi-backend=%s",
              NetworkPolicy::boardName(),
              NetworkPolicy::managementInterfaceName(),
              NetworkPolicy::usesRemoteWiFi() ? "remote" : "native-or-unavailable");
}

void ManagementInterfaceController::transitionTo(ManagementInterfaceState next) {
    if (state_ == next) return;
    state_ = next;
    g_management_state.store(next, std::memory_order_release);
    LOG_INFOF("ManagementPolicy", "Management state=%s",
              managementInterfaceStateName(state_));
}

void ManagementInterfaceController::tick() {
    esp_netif_t* wifi_netif = preferredWifiNetif(wifi_);
    const ManagementInterfaceSnapshot wifi_snapshot = snapshotFor(wifi_netif);
    const ManagementInterfaceSnapshot ethernet_snapshot = snapshotFor(ethernet_.netif());

    ManagementRuntimeInput input{};
    input.policy = NetworkPolicy::managementUsesWiFi()
                       ? ManagementRuntimePolicy::WifiOnly
                       : ManagementRuntimePolicy::EthernetOnly;
    input.wifi = wifi_snapshot;
    input.ethernet = ethernet_snapshot;
    input.server_running = web_.isRunning();
    input.interface_was_active = interface_was_active_;
    input.active_address = active_address_;

    const ManagementRuntimeDecision decision = evaluateManagementRuntime(input);
    if (decision.action == ManagementInterfaceAction::Stop) {
        web_.clearAllowedManagementAddress();
        web_.shutdown();
        active_address_ = 0;
        transitionTo(decision.state);
        return;
    }

    if (decision.action == ManagementInterfaceAction::Start) {
        const uint64_t now = static_cast<uint64_t>(esp_timer_get_time());
        if (now < next_start_attempt_us_) return;

        esp_netif_t* allowed_netif = NetworkPolicy::managementUsesWiFi()
                                         ? wifi_netif
                                         : ethernet_.netif();
        if (!allowed_netif) {
            transitionTo(ManagementInterfaceState::WAITING_FOR_INTERFACE);
            return;
        }

        web_.setAllowedManagementAddress(htonl(decision.allowed_address));
        if (web_.startWithTask(443, allowed_netif)) {
            active_address_ = decision.allowed_address;
            interface_was_active_ = true;
            next_start_attempt_us_ = 0;
            transitionTo(decision.state);
        } else {
            web_.clearAllowedManagementAddress();
            active_address_ = 0;
            next_start_attempt_us_ = now + kStartRetryDelayUs;
            transitionTo(ManagementInterfaceState::START_FAILED);
        }
        return;
    }

    transitionTo(decision.state);
}
