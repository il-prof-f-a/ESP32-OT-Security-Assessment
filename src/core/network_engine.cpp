
#include "network_engine.h"
#include "reporting_engine.h"
#include "event_formatter.h"
#include "plugin_manager.h"
#include "../protocols/base_plugin.h"
#include <cstring>
#include <sstream>
#include <set>
#include "logging_system.h"
#include "task_alloc_helpers.h"
#include "task_config.h"
#include "psram_allocator.h"
#include "../network/assessment_interface.h"

extern "C" {
    #include "esp_heap_caps.h"
}


NetworkEngine::~NetworkEngine(){
    shutdown();
}

bool NetworkEngine::initialize(esp_netif* /*netif*/, const NetRingConfig& rcfg){
    LOG_INFOF("NetEngine", "Starting initialization with %u slots, %u buf_size", rcfg.slots, rcfg.buf_size);

    slot_buf_size_ = rcfg.buf_size;

    // build ring
    ring_.resize(rcfg.slots);
    //LOG_INFOF("NetEngine", "Ring resized to %u slots", (unsigned)ring_.size());

    // Debug PSRAM availability before allocation
    //size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    //size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    //LOG_INFOF("NetEngine", "Memory before allocation - PSRAM: %u bytes, Internal: %u bytes", (unsigned)free_psram, (unsigned)free_internal);

    for (size_t i = 0; i < ring_.size(); i++) {
        auto& s = ring_[i];
        s.buf = (uint8_t*)heap_caps_malloc(rcfg.buf_size, MALLOC_CAP_SPIRAM);
        if (!s.buf) {
            // Fallback: try with 8BIT capability
            s.buf = (uint8_t*)heap_caps_malloc(rcfg.buf_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        }
        if (!s.buf) {
            // Last resort: any external memory
            s.buf = (uint8_t*)heap_caps_malloc(rcfg.buf_size, MALLOC_CAP_DEFAULT);
        }
        if (!s.buf) {
            size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
            size_t free_8bit = heap_caps_get_free_size(MALLOC_CAP_8BIT);
            LOG_ERRORF("NetEngine", "Failed to allocate %u bytes for ring buffer %u/%u - PSRAM: %u, 8BIT: %u", rcfg.buf_size, (unsigned)i, (unsigned)ring_.size(), (unsigned)free_psram, (unsigned)free_8bit);
            // Clean up previously allocated buffers
            for (size_t j = 0; j < i; j++) {
                if (ring_[j].buf) {
                    free(ring_[j].buf);
                    ring_[j].buf = nullptr;
                }
            }
            ring_.clear();
            return false;
        }
        s.len = 0;
        s.meta = NetworkPacket{};
    }
    //LOG_INFOF("NetEngine", "Ring buffers allocated in PSRAM (%u slots x %u bytes = %u KB)",  (unsigned)ring_.size(), rcfg.buf_size, (unsigned)(ring_.size() * rcfg.buf_size / 1024));

    // Allocate PSRAM packet buffers for callbacks to avoid stack allocation
    packet_buffer_udp_ = (uint8_t*)PSRAMUtils::allocatePreferred(1600);
    packet_buffer_tcp_ = (uint8_t*)PSRAMUtils::allocatePreferred(1600);
    buffer_mutex_ = xSemaphoreCreateMutex();

    if (!packet_buffer_udp_ || !packet_buffer_tcp_ || !buffer_mutex_) {
        LOG_ERROR("NetEngine", "Failed to allocate PSRAM packet buffers");
        if (packet_buffer_udp_) { heap_caps_free(packet_buffer_udp_); packet_buffer_udp_ = nullptr; }
        if (packet_buffer_tcp_) { heap_caps_free(packet_buffer_tcp_); packet_buffer_tcp_ = nullptr; }
        if (buffer_mutex_) { vSemaphoreDelete(buffer_mutex_); buffer_mutex_ = nullptr; }
        ring_.clear();
        return false;
    }
    //LOG_INFO("NetEngine", "PSRAM packet buffers allocated (UDP: 1600 bytes, TCP: 1600 bytes)");

    sem_items_ = xSemaphoreCreateCounting(rcfg.slots, 0);
    if (!sem_items_) {
        LOG_ERROR("NetEngine", "Failed to create items semaphore");
        return false;
    }
    sem_space_ = xSemaphoreCreateCounting(rcfg.slots, rcfg.slots);
    if (!sem_space_) {
        LOG_ERROR("NetEngine", "Failed to create space semaphore");
        return false;
    }
    //LOG_INFO("NetEngine", "Semaphores created");

    // tasks: cap (idle feeder) on core 0; analysis on core 1 - PERFORMANCE CRITICAL in internal memory
    // Use centralized configuration for net_cap task
    th_cap_ = TaskConfig::createTask(&NetworkEngine::capTaskThunk, "net_cap",
                                    TaskConfig::Presets::NET_CAP,
                                    this, 0);
    BaseType_t cap_result = (th_cap_ != nullptr) ? pdPASS : pdFAIL;
    if (cap_result != pdPASS) {
        LOG_ERROR("NetEngine", "Failed to create capture task");
        return false;
    }
    // Use centralized configuration for net_ana task
    th_ana_ = TaskConfig::createTask(&NetworkEngine::anaTaskThunk, "net_ana",
                                    TaskConfig::Presets::NET_ANA,
                                    this, 1);
    BaseType_t ana_result = (th_ana_ != nullptr) ? pdPASS : pdFAIL;
    if (ana_result != pdPASS) {
        LOG_ERROR("NetEngine", "Failed to create analysis task");
        return false;
    }
    LOG_INFO("NetEngine", "Tasks created successfully");
    //LOG_INFOF("NetEngine","initialized (slots=%u)", (unsigned)rcfg.slots);
    return true;
}

void NetworkEngine::shutdown(){
    if (th_cap_) { vTaskDelete(th_cap_); th_cap_ = nullptr; }
    if (th_ana_) { vTaskDelete(th_ana_); th_ana_ = nullptr; }

    // Clean up dynamic raw taps
    for (auto* pcb : tap_.udp_pcbs) {
        if (pcb) udp_remove(pcb);
    }
    for (auto* pcb : tap_.tcp_pcbs) {
        if (pcb) tcp_close(pcb);
    }
    tap_.udp_pcbs.clear();
    tap_.tcp_pcbs.clear();
    tap_.udp_ports.clear();
    tap_.tcp_ports.clear();

    if (sem_items_) { vSemaphoreDelete(sem_items_); sem_items_=nullptr; }
    if (sem_space_) { vSemaphoreDelete(sem_space_); sem_space_=nullptr; }

    // Clean up PSRAM packet buffers
    if (packet_buffer_udp_) { heap_caps_free(packet_buffer_udp_); packet_buffer_udp_ = nullptr; }
    if (packet_buffer_tcp_) { heap_caps_free(packet_buffer_tcp_); packet_buffer_tcp_ = nullptr; }
    if (buffer_mutex_) { vSemaphoreDelete(buffer_mutex_); buffer_mutex_ = nullptr; }

    for (auto& s : ring_) { if (s.buf) free(s.buf); s.buf=nullptr; }
    ring_.clear();
    LOG_INFO("NetEngine","shutdown");
}

void NetworkEngine::registerPacketCallback(const PacketCallback& cb){
    LOG_INFO("NetEngine", "Registering packet callback");
    std::lock_guard<std::mutex> lk(cb_mtx_);
    callbacks_.push_back(cb);
    LOG_INFOF("NetEngine", "Callback registered, total callbacks: %u", (unsigned)callbacks_.size());
}

void NetworkEngine::unregisterAllCallbacks(){
    std::lock_guard<std::mutex> lk(cb_mtx_);
    callbacks_.clear();
}

void NetworkEngine::simulateIncomingPacket(const NetworkPacket& pkt){
    std::lock_guard<std::mutex> lk(cb_mtx_);
    for (auto& cb : callbacks_) cb(pkt);
}

void NetworkEngine::ingestIP(bool tcp, const char* src_ip, uint16_t sport,
                             const char* dst_ip, uint16_t dport,
                             const uint8_t* payload, uint16_t len){
    if (!payload || !len) return;
    if (xSemaphoreTake(sem_space_, 0) != pdTRUE) { cnt_dropped_.fetch_add(1); return; } // drop if full
    uint32_t w = wr_.fetch_add(1);
    Slot& s = ring_[w % ring_.size()];
    const uint32_t cap = slot_buf_size_ ? slot_buf_size_ : 0;
    const uint32_t copy_len = (cap > 0 && len > cap) ? cap : (uint32_t)len;
    // copy (bounded)
    s.len = copy_len;
    if (copy_len > 0) {
        memcpy(s.buf, payload, copy_len);
    }
    // meta
    s.meta = NetworkPacket{};
    s.meta.ts_ms = (uint64_t)(esp_timer_get_time()/1000ULL);
    s.meta.src_ip = src_ip? src_ip:"";
    s.meta.dst_ip = dst_ip? dst_ip:"";
    s.meta.src_port = sport;
    s.meta.dst_port = dport;
    s.meta.is_tcp = tcp;
    s.meta.is_udp = !tcp;
    s.meta.data = s.buf;
    s.meta.length = copy_len;
    s.meta.proto = infer_proto(tcp, sport, dport, 0);
    xSemaphoreGive(sem_items_);
    cnt_ingested_.fetch_add(1);
}

void NetworkEngine::ingestL2(const uint8_t src_mac[6], const uint8_t dst_mac[6], uint16_t ethertype,
                             const uint8_t* payload, uint16_t len){
    //if (!payload || !len) return;
    //LOG_INFO("NetworkEngine", "ingestL2 before semaphore");
    if (xSemaphoreTake(sem_space_, 0) != pdTRUE) { cnt_dropped_.fetch_add(1); return; }
    //LOG_INFO("NetworkEngine", "ingestL2 after semaphore");
    uint32_t w = wr_.fetch_add(1);
    Slot& s = ring_[w % ring_.size()];
    const uint32_t cap = slot_buf_size_ ? slot_buf_size_ : 0;
    const uint32_t copy_len = (cap > 0 && len > cap) ? cap : (uint32_t)len;
    s.len = copy_len;
    if (copy_len > 0) {
        memcpy(s.buf, payload, copy_len);
    }
    s.meta = NetworkPacket{};
    s.meta.ts_ms = (uint64_t)(esp_timer_get_time()/1000ULL);
    if (src_mac) memcpy(s.meta.src_mac, src_mac, 6);
    if (dst_mac) memcpy(s.meta.dst_mac, dst_mac, 6);

    // VLAN-aware parsing: if 802.1Q is present, expose inner EtherType and strip VLAN header.
    uint16_t effective_ethertype = ethertype;
    const uint8_t* effective_payload = s.buf;
    uint32_t effective_len = s.len;
    if (ethertype == 0x8100 && s.len >= 4) {
        effective_ethertype = (uint16_t)((s.buf[2] << 8) | s.buf[3]); // inner EtherType
        effective_payload = s.buf + 4;
        effective_len = s.len - 4;
    }

    // Keep NetworkPacket::ether_type in network byte order.
    s.meta.ether_type = PP_HTONS(effective_ethertype);
    s.meta.data = effective_payload;
    s.meta.length = effective_len;

    // Parse IP/TCP/UDP to populate complete NetworkPacket (like ingestIP)
    if (effective_ethertype == 0x0800 && effective_len >= 20) { // IPv4
        const uint8_t* ip = effective_payload;
        uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl >= 20 && effective_len >= ihl) {
            // Extract IP addresses
            char sip[16], dip[16];
            snprintf(sip, sizeof(sip), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
            snprintf(dip, sizeof(dip), "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);
            s.meta.src_ip = sip;
            s.meta.dst_ip = dip;

            uint8_t ip_proto = ip[9];
            const uint8_t* l4 = ip + ihl;
            uint16_t l4len = (uint16_t)(effective_len - ihl);

            if (ip_proto == 6 && l4len >= 20) { // TCP
                s.meta.is_tcp = true;
                s.meta.is_udp = false;
                s.meta.src_port = (l4[0] << 8) | l4[1];
                s.meta.dst_port = (l4[2] << 8) | l4[3];
                s.meta.proto = infer_proto(true, s.meta.src_port, s.meta.dst_port, s.meta.ether_type);

                // Log TCP packets for industrial protocols
                if (s.meta.proto != ProtocolType::UNKNOWN) {
                    /*LOG_INFOF("NetworkEngine", "🔍 TCP Packet: %s:%u → %s:%u [%s]",
                             sip, s.meta.src_port, dip, s.meta.dst_port, PluginManager::protocolTypeToString(s.meta.proto));*/
                }
            } else if (ip_proto == 17 && l4len >= 8) { // UDP
                s.meta.is_tcp = false;
                s.meta.is_udp = true;
                s.meta.src_port = (l4[0] << 8) | l4[1];
                s.meta.dst_port = (l4[2] << 8) | l4[3];
                s.meta.proto = infer_proto(false, s.meta.src_port, s.meta.dst_port, s.meta.ether_type);

                // Log UDP packets for industrial protocols
                if (s.meta.proto != ProtocolType::UNKNOWN) {
                    /*LOG_INFOF("NetworkEngine", "🔍 UDP Packet: %s:%u → %s:%u [%s]",
                             sip, s.meta.src_port, dip, s.meta.dst_port, PluginManager::protocolTypeToString(s.meta.proto));*/
                }
            } else {
                s.meta.proto = infer_proto(false, 0, 0, s.meta.ether_type);
            }
        } else {
            s.meta.proto = infer_proto(false, 0, 0, s.meta.ether_type);
        }
    } else if (effective_ethertype == 0x8892) { // PROFINET DCP (L2)
        s.meta.proto = ProtocolType::PROFINET;
        ///LOG_INFO("NetworkEngine", "🔍 PROFINET DCP Packet detected");
    } else if (effective_ethertype == 0x88CC) { // LLDP (often used for PROFINET topology discovery)
        s.meta.proto = ProtocolType::PROFINET;
    } else {
        s.meta.proto = infer_proto(false, 0, 0, s.meta.ether_type);
    }
    xSemaphoreGive(sem_items_);
    cnt_ingested_.fetch_add(1);
}

void NetworkEngine::capTaskThunk(void* arg){ reinterpret_cast<NetworkEngine*>(arg)->capLoop(); }
void NetworkEngine::anaTaskThunk(void* arg){ reinterpret_cast<NetworkEngine*>(arg)->anaLoop(); }

void NetworkEngine::capLoop(){
    // If raw taps are enabled, they will call ingestIP() from lwIP callbacks.
    // Here we simply sleep; external adapters (WiFi promisc / EMAC hook) can also call ingestL2().
    for(;;){
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

void NetworkEngine::anaLoop(){
    //uint64_t last_report_ms = 0;
    for(;;){
        if (xSemaphoreTake(sem_items_, portMAX_DELAY) == pdTRUE){

            //LOG_INFO("NetworkEngine", "anaLoop: retrieving the data from the ring buffer");
            uint32_t r = rd_.fetch_add(1);
            Slot& s = ring_[r % ring_.size()];
            // Dispatch to callbacks
            {
                std::lock_guard<std::mutex> lk(cb_mtx_);
                for (auto& cb : callbacks_) cb(s.meta);
            }

            // free slot
            xSemaphoreGive(sem_space_);
            cnt_dispatched_.fetch_add(1);

            /*
            // Report stats every 30 seconds
            uint64_t now_ms = (uint64_t)(esp_timer_get_time()/1000ULL);
            if (last_report_ms == 0 || (now_ms - last_report_ms) >= 30000) {
                last_report_ms = now_ms;
                reportNetworkStats();
            }*/
        }
    }
}


ProtocolType NetworkEngine::infer_proto(bool is_tcp, uint16_t sport, uint16_t dport, uint16_t ethertype){
    if (ethertype == PP_HTONS(0x8892) || ethertype == PP_HTONS(0x88CC)) return ProtocolType::PROFINET; // DCP / LLDP
    if (is_tcp){
        if (sport==102 || dport==102) return ProtocolType::S7_COMM;
        if (sport==502 || dport==502) return ProtocolType::MODBUS_TCP;
        if (sport==4840|| dport==4840) return ProtocolType::OPC_UA;
        if (sport==44818|| dport==44818) return ProtocolType::ETHERNET_IP;
    } else {
        // UDP
        if (sport==2222 || dport==2222) return ProtocolType::ETHERNET_IP;
    }
    return ProtocolType::UNKNOWN;
}

bool NetworkEngine::enableRawTaps(){
    // Legacy method - use basic hardcoded ports for backward compatibility
    // UDP taps - temporarily disabled due to callback crash
    // TODO: Debug callback pointer corruption issue
    // TCP "any": we cannot easily hook all, but we could create raw pcb (not public). For now, skip.
    LOG_INFO("NetEngine","Raw UDP/TCP taps disabled (debugging).");
    return true;
}

bool NetworkEngine::enableRawTaps(const std::vector<BasePlugin*>& plugins){
    ip_addr_t assessment_address{};
    if (!AssessmentInterface::localAddress(&assessment_address)) {
        LOG_ERROR("NetEngine", "Ethernet is not ready; raw assessment taps remain disabled");
        return false;
    }

    // Dynamic port discovery from plugins
    std::set<uint16_t> all_ports;

    // Collect all monitored ports from plugins
    for (const auto& plugin : plugins) {
        if (!plugin) continue;
        auto ports = plugin->getMonitoredPorts();
        for (uint16_t port : ports) {
            all_ports.insert(port);
        }
    }

    if (all_ports.empty()) {
        LOG_INFO("NetEngine", "No ports to monitor from plugins");
        return true;
    }

    LOG_INFOF("NetEngine", "Setting up raw taps for %zu ports", all_ports.size());

    // Clear existing taps
    for (auto* pcb : tap_.udp_pcbs) {
        if (pcb) udp_remove(pcb);
    }
    for (auto* pcb : tap_.tcp_pcbs) {
        if (pcb) tcp_close(pcb);
    }
    tap_.udp_pcbs.clear();
    tap_.tcp_pcbs.clear();
    tap_.udp_ports.clear();
    tap_.tcp_ports.clear();

    // Create UDP and TCP raw taps for each port
    for (uint16_t port : all_ports) {
        // UDP tap
        struct udp_pcb* u_pcb = udp_new();
        if (u_pcb) {
            if (udp_bind(u_pcb, &assessment_address, port) == ERR_OK) {
                udp_recv(u_pcb, &NetworkEngine::udp_recv_cb, this);
                tap_.udp_pcbs.push_back(u_pcb);
                tap_.udp_ports.push_back(port);
                LOG_INFOF("NetEngine", "UDP tap enabled on port %u", port);
            } else {
                udp_remove(u_pcb);
                LOG_ERRORF("NetEngine", "Failed to bind UDP port %u", port);
            }
        }

        // TCP tap - Listen on port and intercept connections
        struct tcp_pcb* t_pcb = tcp_new();
        if (t_pcb) {
            if (tcp_bind(t_pcb, &assessment_address, port) == ERR_OK) {
                struct tcp_pcb* listening_pcb = tcp_listen(t_pcb);
                if (listening_pcb) {
                    // Set callbacks for connection handling
                    tcp_accept(listening_pcb, &NetworkEngine::tcp_accept_cb);
                    tcp_arg(listening_pcb, this);
                    tap_.tcp_pcbs.push_back(listening_pcb);
                    tap_.tcp_ports.push_back(port);
                    LOG_INFOF("NetEngine", "TCP tap enabled on port %u", port);
                } else {
                    tcp_close(t_pcb);
                    LOG_ERRORF("NetEngine", "Failed to listen on TCP port %u", port);
                }
            } else {
                tcp_close(t_pcb);
                LOG_ERRORF("NetEngine", "Failed to bind TCP port %u", port);
            }
        }
    }

    LOG_INFOF("NetEngine", "Raw taps setup complete: %zu UDP, %zu TCP listeners",
              tap_.udp_pcbs.size(), tap_.tcp_pcbs.size());
    return true;
}

void NetworkEngine::udp_recv_cb(void* arg, struct udp_pcb* upcb, struct pbuf* p,
                                const ip_addr_t* addr, u16_t port){
    (void)upcb;
    NetworkEngine* self = reinterpret_cast<NetworkEngine*>(arg);
    if (!self || !p || !self->packet_buffer_udp_ || !self->buffer_mutex_) {
        if (p) pbuf_free(p);
        return;
    }

    // Use PSRAM buffer with mutex protection
    if (xSemaphoreTake(self->buffer_mutex_, pdMS_TO_TICKS(10)) != pdPASS) {
        pbuf_free(p);
        return;
    }

    ip_addr_t dst; // Not provided by callback; assume local (0.0.0.0)
    IP_SET_TYPE_VAL(dst, IPADDR_TYPE_V4);
#if CONFIG_LWIP_IPV6
    dst.u_addr.ip4.addr = 0;
#else
    dst.addr = 0;
#endif

    // Collate pbuf chain using PSRAM buffer
    uint16_t off=0;
    for (struct pbuf* q=p; q && off+q->len <= 1600; q=q->next){
        memcpy(self->packet_buffer_udp_+off, q->payload, q->len); off+=q->len;
    }
    char sip[16], dip[16];
    ipaddr_ntoa_r(addr, sip, sizeof(sip));
    ipaddr_ntoa_r(&dst,  dip, sizeof(dip));
    self->ingestIP(false, sip, port, dip, 0, self->packet_buffer_udp_, off);

    xSemaphoreGive(self->buffer_mutex_);
    pbuf_free(p);
}

err_t NetworkEngine::tcp_accept_cb(void* arg, struct tcp_pcb* newpcb, err_t err){
    if (err != ERR_OK || !newpcb) return ERR_VAL;

    NetworkEngine* self = reinterpret_cast<NetworkEngine*>(arg);
    if (!self) return ERR_VAL;

    // Set up the new connection for data reception
    tcp_arg(newpcb, self);
    tcp_recv(newpcb, &NetworkEngine::tcp_recv_cb);

    // Optional: Set other callbacks for connection management
    // tcp_sent(newpcb, tcp_sent_cb);
    // tcp_err(newpcb, tcp_error_cb);

    LOG_INFOF("NetEngine", "TCP connection accepted from %s:%u to port %u",
             ipaddr_ntoa(&newpcb->remote_ip), newpcb->remote_port, newpcb->local_port);

    return ERR_OK;
}

err_t NetworkEngine::tcp_recv_cb(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err){
    (void)err;
    NetworkEngine* self = reinterpret_cast<NetworkEngine*>(arg);
    if (!self || !p || !self->packet_buffer_tcp_ || !self->buffer_mutex_) {
        tcp_recved(tpcb, 0);
        if (p) pbuf_free(p);
        return ERR_OK;
    }

    // Use PSRAM buffer with mutex protection
    if (xSemaphoreTake(self->buffer_mutex_, pdMS_TO_TICKS(10)) != pdPASS) {
        tcp_recved(tpcb, 0);
        pbuf_free(p);
        return ERR_OK;
    }

    // Gather pbuf chain using PSRAM buffer
    uint16_t off=0;
    for (struct pbuf* q=p; q && off+q->len <= 1600; q=q->next){
        memcpy(self->packet_buffer_tcp_+off, q->payload, q->len); off+=q->len;
    }
    char sip[16], dip[16];
    ipaddr_ntoa_r(&tpcb->local_ip, dip, sizeof(dip));
    ipaddr_ntoa_r(&tpcb->remote_ip, sip, sizeof(sip));
    self->ingestIP(true, sip, tpcb->remote_port, dip, tpcb->local_port, self->packet_buffer_tcp_, off);

    xSemaphoreGive(self->buffer_mutex_);
    tcp_recved(tpcb, off);
    pbuf_free(p);
    return ERR_OK;
}


NetworkEngine::Stats NetworkEngine::getStats() const {
    Stats st;
    st.ingested   = cnt_ingested_.load();
    st.dropped    = cnt_dropped_.load();
    st.dispatched = cnt_dispatched_.load();
    st.ring_slots = ring_.size();
    // items in ring ~ wr - rd, but we don't expose wr/rd directly; approximate with semaphore counts
    if (sem_items_) st.items_in_ring = uxSemaphoreGetCount(sem_items_);
    return st;
}

void NetworkEngine::reportNetworkStats() {
    if (!rep_) return;

    Stats st = getStats();

    // Calculate processing rate (packets per second over last 30 seconds)
    static uint64_t last_dispatched = 0;
    uint64_t pps = 0;
    if (last_dispatched > 0 && st.dispatched > last_dispatched) {
        pps = (st.dispatched - last_dispatched) / 30; // 30 second interval
    }
    last_dispatched = st.dispatched;

    // Calculate ring buffer utilization percentage
    double ring_utilization = (st.ring_slots > 0) ?
        (double)st.items_in_ring / (double)st.ring_slots * 100.0 : 0.0;

    // Create event record
    EventRecord ev;
    ev.channel = "network";
    ev.type = "statistics";
    ev.protocol = "network";
    ev.name = "packet_processing";
    ev.timestamp_ms = (uint64_t)(esp_timer_get_time()/1000ULL);
    ev.severity = "Low";

    std::stringstream json;
    json << "{\"ingested\":" << st.ingested
         << ",\"dropped\":" << st.dropped
         << ",\"dispatched\":" << st.dispatched
         << ",\"ring_slots\":" << st.ring_slots
         << ",\"items_in_ring\":" << st.items_in_ring
         << ",\"ring_utilization_percent\":" << ring_utilization
         << ",\"packets_per_second\":" << pps << "}";

    ev.raw_json = json.str();

    ev.channel = "network";
    rep_->submit(ev);
}
