#pragma once
#include <cstdint>
#include <string>
#include <vector>

enum class SandboxAction : uint32_t {
    NONE            = 0,
    NETWORK_ACTIVE  = 1u<<0,   // open sockets / active scans
    UDP_BROADCAST   = 1u<<1,
    RAW_ETH_TX      = 1u<<2,
    FILE_READ       = 1u<<3,
    FILE_WRITE      = 1u<<4,
};

inline SandboxAction operator|(SandboxAction a, SandboxAction b){ return (SandboxAction)((uint32_t)a | (uint32_t)b); }
inline SandboxAction& operator|=(SandboxAction& a, SandboxAction b){ a = a|b; return a; }
inline bool hasFlag(SandboxAction mask, SandboxAction f){ return (((uint32_t)mask) & ((uint32_t)f)) != 0; }

struct SandboxPolicy {
    SandboxAction allowed = SandboxAction::NONE;
    // Network
    std::vector<uint16_t> allow_tcp_ports;    // e.g. {102, 502, 44818, 4840}
    bool allow_list_identity_broadcast = false;
    uint32_t max_packets_per_min = 200;       // rate limit
    uint32_t max_bytes_per_min   = 256*1024;
    // Execution
    uint32_t call_timeout_ms     = 3000;      // per operation (scan, init, etc.)
    uint32_t task_stack_bytes    = 8192;      // sandbox worker
    uint32_t task_priority       = 6;         // lower than system
    // FS
    std::string fs_base;                      // e.g. "/data/plugins/s7/"
    uint32_t max_file_size       = 32*1024;
};

struct SandboxStats {
    uint32_t tx_packets = 0;
    uint32_t tx_bytes   = 0;
    uint32_t rx_packets = 0;
    uint32_t rx_bytes   = 0;
    uint32_t denied_ops = 0;
};
