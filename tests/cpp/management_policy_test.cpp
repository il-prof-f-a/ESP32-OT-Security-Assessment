#include <cassert>
#include <cstdint>

#include "network/management_interface_controller.h"

namespace {

constexpr uint32_t ip(unsigned a, unsigned b, unsigned c, unsigned d) {
    return (a << 24U) | (b << 16U) | (c << 8U) | d;
}

constexpr ManagementInterfaceSnapshot interfaceAt(uint32_t address,
                                                    uint32_t netmask) {
    return {true, address, netmask};
}

}  // namespace

int main() {
    static_assert(ipv4NetmaskIsContiguous(0x00000000U));  // /0
    static_assert(ipv4NetmaskIsContiguous(0xfffffffeU));  // /31
    static_assert(ipv4NetmaskIsContiguous(0xffffffffU));  // /32
    static_assert(!ipv4NetmaskIsContiguous(0xff00ff00U));

    assert(ipv4SubnetsOverlap(interfaceAt(ip(10, 1, 2, 3), 0x00000000U),
                              interfaceAt(ip(192, 168, 4, 1), 0xffffff00U)));
    assert(ipv4SubnetsOverlap(interfaceAt(ip(10, 0, 0, 0), 0xfffffffeU),
                              interfaceAt(ip(10, 0, 0, 1), 0xfffffffeU)));
    assert(!ipv4SubnetsOverlap(interfaceAt(ip(10, 0, 0, 0), 0xffffffffU),
                               interfaceAt(ip(10, 0, 0, 1), 0xffffffffU)));
    assert(ipv4SubnetsOverlap(interfaceAt(ip(10, 20, 1, 15), 0xffffff00U),
                              interfaceAt(ip(10, 20, 1, 200), 0xffffff00U)));
    assert(!ipv4SubnetsOverlap(interfaceAt(ip(10, 20, 1, 15), 0xffffff00U),
                               interfaceAt(ip(10, 20, 2, 15), 0xffffff00U)));
    assert(!ipv4SubnetsOverlap({}, interfaceAt(ip(10, 20, 1, 15), 0xffffff00U)));

    ManagementRuntimeInput input{};
    input.policy = ManagementRuntimePolicy::WifiOnly;
    auto decision = evaluateManagementRuntime(input);
    assert(decision.state == ManagementInterfaceState::WAITING_FOR_INTERFACE);
    assert(decision.action == ManagementInterfaceAction::None);

    input.wifi = interfaceAt(ip(10, 2, 239, 10), 0xffffff00U);
    input.ethernet = interfaceAt(ip(192, 168, 10, 20), 0xffffff00U);
    decision = evaluateManagementRuntime(input);
    assert(decision.state == ManagementInterfaceState::ACTIVE_WIFI);
    assert(decision.action == ManagementInterfaceAction::Start);
    assert(decision.allowed_address == ip(10, 2, 239, 10));

    input.server_running = true;
    input.active_address = input.wifi.address;
    decision = evaluateManagementRuntime(input);
    assert(decision.state == ManagementInterfaceState::ACTIVE_WIFI);
    assert(decision.action == ManagementInterfaceAction::None);

    input.ethernet = interfaceAt(ip(10, 2, 239, 200), 0xffffff00U);
    decision = evaluateManagementRuntime(input);
    assert(decision.state == ManagementInterfaceState::BLOCKED_SUBNET_OVERLAP);
    assert(decision.action == ManagementInterfaceAction::Stop);

    input.wifi = {};
    input.ethernet = interfaceAt(ip(192, 168, 10, 20), 0xffffff00U);
    input.interface_was_active = true;
    decision = evaluateManagementRuntime(input);
    assert(decision.state == ManagementInterfaceState::BLOCKED_INTERFACE_LOST);
    assert(decision.action == ManagementInterfaceAction::Stop);

    input = {};
    input.policy = ManagementRuntimePolicy::EthernetOnly;
    input.wifi = interfaceAt(ip(192, 168, 10, 50), 0xffffff00U);
    input.ethernet = interfaceAt(ip(192, 168, 10, 20), 0xffffff00U);
    decision = evaluateManagementRuntime(input);
    assert(decision.state == ManagementInterfaceState::ACTIVE_ETHERNET);
    assert(decision.action == ManagementInterfaceAction::Start);

    return 0;
}
