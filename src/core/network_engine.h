
#pragma once
#include <vector>
#include <atomic>
#include <mutex>
#include "types.h"

extern "C" {
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "freertos/semphr.h"
  #include "esp_timer.h"
  #include "lwip/ip_addr.h"
  #include "lwip/inet.h"
  #include "lwip/udp.h"
  #include "lwip/tcp.h"
}

struct esp_netif; // forward

// Configurable ring
struct NetRingConfig {
    uint16_t slots = 256;
    uint16_t buf_size = 1600;
};

class NetworkEngine {
public:
    NetworkEngine() = default;
    ~NetworkEngine();

    bool initialize(esp_netif* netif = nullptr, const NetRingConfig& rcfg = {});
    void shutdown();
    void registerPacketCallback(const PacketCallback& cb);
    void unregisterAllCallbacks();
    void setReportingEngine(class ReportingEngine* rep) { rep_ = rep; }

    // Feeders (from adapters/hook)
    void ingestIP(bool tcp, const char* src_ip, uint16_t sport,
                  const char* dst_ip, uint16_t dport,
                  const uint8_t* payload, uint16_t len);

    void ingestL2(const uint8_t src_mac[6], const uint8_t dst_mac[6], uint16_t ethertype,
                  const uint8_t* payload, uint16_t len);

    // Optional: simulate for tests
    void simulateIncomingPacket(const NetworkPacket& pkt);

    // Enable built-in lwIP raw taps for TCP/UDP ports of interest (L3 only)
    bool enableRawTaps();
    bool enableRawTaps(const std::vector<class BasePlugin*>& plugins);

    struct Stats { uint64_t ingested=0, dropped=0, dispatched=0; uint32_t ring_slots=0; uint32_t items_in_ring=0; };
    Stats getStats() const;
    void reportNetworkStats();

private:
    struct Slot {
        uint32_t len;
        uint8_t* buf;
        NetworkPacket meta;
    };

    // Capacity of each Slot::buf. Used to avoid buffer overflows and hard crashes.
    uint16_t slot_buf_size_ = 0;

    // ring
    std::vector<Slot> ring_;
    std::atomic<uint32_t> wr_{0};
    std::atomic<uint32_t> rd_{0};
    SemaphoreHandle_t sem_items_ = nullptr;
    SemaphoreHandle_t sem_space_ = nullptr;

    std::atomic<uint64_t> cnt_ingested_{0};
    std::atomic<uint64_t> cnt_dropped_{0};
    std::atomic<uint64_t> cnt_dispatched_{0};

    // tasks
    TaskHandle_t th_cap_ = nullptr;
    TaskHandle_t th_ana_ = nullptr;
    static void capTaskThunk(void* arg);
    static void anaTaskThunk(void* arg);
    void capLoop();
    void anaLoop();

    // callbacks
    std::mutex cb_mtx_;
    std::vector<PacketCallback> callbacks_;

    // lwIP raw pcbs - dynamic allocation based on plugin ports
    struct RawTap {
        std::vector<struct udp_pcb*> udp_pcbs;  // Dynamic UDP PCBs for each monitored port
        std::vector<struct tcp_pcb*> tcp_pcbs;  // Dynamic TCP PCBs for each monitored port
        std::vector<uint16_t> udp_ports;        // Ports being monitored via UDP
        std::vector<uint16_t> tcp_ports;        // Ports being monitored via TCP
    } tap_;

    static err_t tcp_recv_cb(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err);
    static err_t tcp_accept_cb(void* arg, struct tcp_pcb* newpcb, err_t err);
    static void udp_recv_cb(void* arg, struct udp_pcb* upcb, struct pbuf* p,
                            const ip_addr_t* addr, u16_t port);

    void dispatchFromPbuf(bool is_tcp, const ip_addr_t* src, u16_t sport,
                          const ip_addr_t* dst, u16_t dport, const uint8_t* data, uint16_t len);

    static ProtocolType infer_proto(bool is_tcp, uint16_t sport, uint16_t dport, uint16_t ethertype);

    // Statistics reporting
    class ReportingEngine* rep_ = nullptr;
    uint64_t last_stats_report_ms_ = 0;

    // PSRAM packet buffers to avoid stack allocation in callbacks
    uint8_t* packet_buffer_udp_ = nullptr;
    uint8_t* packet_buffer_tcp_ = nullptr;
    SemaphoreHandle_t buffer_mutex_ = nullptr;  // Protect shared buffers
};
