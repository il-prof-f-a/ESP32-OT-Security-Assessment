
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>

// Protocols of interest
enum class ProtocolType : uint8_t {
    UNKNOWN = 0,
    MODBUS_TCP,     // TCP/502
    S7_COMM,        // TCP/102
    OPC_UA,         // TCP/4840
    ETHERNET_IP,    // TCP/44818, UDP/2222 (CIP)
    PROFINET,       // DCP EtherType 0x8892 (L2)
    CUSTOM
};

// Lightweight L2/L3 packet view (buffer owned by engine)
struct NetworkPacket {
    uint64_t ts_ms = 0;
    // L2
    uint8_t src_mac[6] {0};
    uint8_t dst_mac[6] {0};
    uint16_t ether_type = 0; // network byte order
    // L3/L4 (if IP)
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    bool is_tcp = false;
    bool is_udp = false;
    // Payload
    const uint8_t* data = nullptr;
    uint32_t length = 0;
    // Protocol inference (best-effort)
    ProtocolType proto = ProtocolType::UNKNOWN;
};

using PacketCallback = std::function<void(const NetworkPacket&)>;

struct DebugConfig {
    int level = 1;   // 0=DEBUG,1=INFO,2=WARN,3=ERROR
    bool color = true;
};

enum class LogLevel : uint8_t {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};