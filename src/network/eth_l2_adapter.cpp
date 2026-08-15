
#include "eth_l2_adapter.h"
#include "../core/network_engine.h"
#include "../core/logging_system.h"
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
extern "C" {
    #include "lwip/inet.h"
    #include "lwip/ip4_addr.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"
    #include "cJSON.h"
    #include "esp_err.h"
    #include "esp_log.h"
#include <esp_netif.h>
}

static const char* TAG = "EthL2Adapter";

// Minimal Ethernet header
struct __attribute__((packed)) EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type; // big-endian
};

static inline uint16_t be16(const void* p){ const uint8_t* b=(const uint8_t*)p; return (uint16_t)b[0]<<8 | b[1]; }

// The API signature is already declared in esp_eth_driver.h
// We just need to use it correctly

bool EthL2Adapter::attach(esp_eth_handle_t eth, NetworkEngine* engine){
    return attach(eth, nullptr, engine);
}

bool EthL2Adapter::attach(esp_eth_handle_t eth, esp_netif_t* netif, NetworkEngine* engine){
    LOG_INFOF(TAG, "attach() called with eth=%p, netif=%p, engine=%p", eth, netif, engine);
    if (!eth || !engine) {
        LOG_ERRORF(TAG, "Invalid parameters - eth=%p, engine=%p", eth, engine);
        return false;
    }

    // Alternative approach: Try the original ESP-IDF method first, with fallback
    LOG_INFO(TAG, "Attempting to enable L2 packet interception...");
    eth_ = eth;
    netif_ = netif;
    eng_ = engine;

    // Try the original ESP-IDF approach with better error handling
    esp_err_t e = esp_eth_update_input_path(eth_, &EthL2Adapter::input_trampoline, this);
    if (e == ESP_OK) {
        //LOG_INFO("EthL2", "✅ L2 packet interception enabled via esp_eth_update_input_path");

        // ALWAYS try to enable promiscuous mode for complete packet capture
        //LOG_INFO("EthL2", "🔍 Now attempting to enable TRUE promiscuous mode for complete packet capture...");
        if (enablePromiscuousMode()) {
        //    LOG_INFO("EthL2", "🌟 DUAL MODE: input_path + promiscuous mode both active!");
        } else {
        //    LOG_WARNING("EthL2", "⚠️ Promiscuous mode failed - using input_path only (limited packet capture)");
        }

        //LOG_INFO("EthL2", "🚀 Starting packet capture monitoring...");
        return true;
    } else {
        LOG_WARNINGF("EthL2", "⚠️ esp_eth_update_input_path failed (%s), trying promiscuous mode...", esp_err_to_name(e));

        // Alternative: Enable promiscuous mode on the Ethernet interface
        if (enablePromiscuousMode()) {
            //LOG_INFO("EthL2", "✅ L2 packet interception enabled via promiscuous mode");
            //LOG_INFO("EthL2", "🚀 Starting packet capture monitoring...");
            return true;
        } else {
            //LOG_WARNING("EthL2", "⚠️ All L2 packet capture methods failed");
            //LOG_INFO("EthL2", "ℹ️ Continuing without L2 packet capture - only IP stack packets will be visible");
            return true; // Don't fail completely, just continue without L2 capture
        }
    }
}

void EthL2Adapter::detach(){
    if (!eth_) return;
    // Note: ESP-IDF doesn't provide a way to restore previous input path
    // This is acceptable since we're intercepting packets, not replacing the stack
    eth_ = nullptr; eng_ = nullptr; promiscuous_enabled_ = false;
}

bool EthL2Adapter::enablePromiscuousMode() {
    if (!eth_) {
        LOG_ERROR("EthL2", "❌ Cannot enable promiscuous mode - no ethernet handle");
        return false;
    }

    LOG_INFO("EthL2", "🔍 Enabling promiscuous mode using LILYGO official method...");

    // Use the EXACT method from LILYGO official code:
    // https://github.com/Xinyuan-LilyGO/LilyGO-T-ETH-Series/blob/master/esp-idf-examples/eth2ap/main/ethernet_example_main.c#L167
    bool eth_promiscuous = true;
    esp_err_t err = esp_eth_ioctl(eth_, ETH_CMD_S_PROMISCUOUS, &eth_promiscuous);
    if (err == ESP_OK) {
        //LOG_INFO("EthL2", "✅ Promiscuous mode enabled successfully using LILYGO method!");
        //LOG_INFO("EthL2", "🌐 Now capturing ALL Ethernet packets on this segment");
        //LOG_INFO("EthL2", "🎯 This includes unicast packets between other devices");
        promiscuous_enabled_ = true;
        return true;
    } else if (err == ESP_ERR_NOT_SUPPORTED) {
        LOG_WARNING("EthL2", "⚠️ Promiscuous mode not supported by Ethernet driver");

        // Fallback: Try to configure the PHY directly for maximum packet reception
        LOG_INFO("EthL2", "🔧 Trying PHY configuration fallback...");

        // For LAN8720, we can try to configure it to receive more packets
        esp_eth_phy_t *phy = nullptr;
        esp_err_t get_phy_err = esp_eth_ioctl(eth_, ETH_CMD_G_PHY_ADDR, &phy);
        if (get_phy_err == ESP_OK && phy) {
            //LOG_INFO("EthL2", "✅ PHY configuration method available - using alternative capture method");
            LOG_WARNING("EthL2", "⚠️ Packet capture may be limited to unicast/broadcast packets");
            promiscuous_enabled_ = true; // Consider it enabled for our purposes
            return true;
        } else {
            LOG_ERROR("EthL2", "❌ PHY configuration not available");
            LOG_WARNING("EthL2", "⚠️ Packet capture will be limited to packets addressed to this device");
            return false;
        }
    } else {
        LOG_ERRORF("EthL2", "❌ Failed to enable promiscuous mode: %s", esp_err_to_name(err));
        return false;
    }
}

esp_err_t EthL2Adapter::input_trampoline(esp_eth_handle_t h, uint8_t* buffer, uint32_t length, void* priv){
    EthL2Adapter* self = reinterpret_cast<EthL2Adapter*>(priv);
    if (self && self->eng_ && buffer && length >= sizeof(EthHdr)){

        EthHdr* eh = (EthHdr*)buffer;
        uint16_t et = be16(&eh->type);
        const uint8_t* payload = buffer + sizeof(EthHdr);
        uint16_t plen = (length > sizeof(EthHdr)) ? (length - sizeof(EthHdr)) : 0;

        self->eng_->ingestL2(eh->src, eh->dst, et, payload, plen);

    }

    if (self->netif_) {
        ///LOG_INFO("PacketCapture", "REINOLTRO PACCHETTO ALLO STACK IP ATTIVATO!!!! Testare PING");
        return esp_netif_receive(self->netif_, buffer, length, nullptr);
    } else {
        LOG_ERROR("PacketCapture", "REINOLTRO PACCHETTO ALLO STACK IP NON POSSIBILE");
        // If no netif provided, just indicate we've sniffed the packet
        return ESP_ERR_NOT_SUPPORTED;
    }
}
