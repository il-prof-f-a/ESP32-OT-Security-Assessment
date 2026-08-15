#pragma once
#include "sandbox_policy.h"
#include "../core/types.h"

inline SandboxPolicy defaultSandboxFor(ProtocolType p) {
    SandboxPolicy pol;
    pol.allowed = SandboxAction::FILE_READ | SandboxAction::FILE_WRITE; // logging + cache by default
    pol.task_stack_bytes = 8192;
    pol.task_priority = 6;
    pol.call_timeout_ms = 3000;
    pol.max_packets_per_min = 180;
    pol.max_bytes_per_min   = 128*1024;
    switch (p) {
        case ProtocolType::PROFINET:
            pol.allowed |= SandboxAction::RAW_ETH_TX; // only DCP Identify TX via guard
            break;
        case ProtocolType::S7_COMM:
            pol.allowed |= SandboxAction::NETWORK_ACTIVE; // limited TCP
            pol.allow_tcp_ports = {102};
            break;
        case ProtocolType::MODBUS_TCP:
            pol.allowed |= SandboxAction::NETWORK_ACTIVE;
            pol.allow_tcp_ports = {502};
            break;
        case ProtocolType::ETHERNET_IP:
            pol.allowed |= SandboxAction::NETWORK_ACTIVE | SandboxAction::UDP_BROADCAST;
            pol.allow_tcp_ports = {44818};
            break;
        case ProtocolType::OPC_UA:
            pol.allowed |= SandboxAction::NETWORK_ACTIVE;
            pol.allow_tcp_ports = {4840};
            break;
        default: break;
    }
    return pol;
}
