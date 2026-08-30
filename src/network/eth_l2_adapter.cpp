
#include "eth_l2_adapter.h"
#include "../core/network_engine.h"
#include "../core/logging_system.h"
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
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

#if defined(CONFIG_IDF_TARGET_ESP32P4) && defined(CONFIG_ESP_NETIF_L2_TAP) && CONFIG_ESP_NETIF_L2_TAP
    // Do not replace the ESP-NETIF callback on ESP32-P4. The stock glue
    // callback feeds ESP-NETIF's L2 TAP filter; replacing it bypasses that
    // filter and leaves non-IP frames invisible to the application.
    if (attachL2Tap()) {
        if (!enablePromiscuousMode()) {
            LOG_WARNING(TAG, "L2 TAP attached but promiscuous mode could not be enabled");
        }
        LOG_INFO(TAG, "ESP32-P4 L2 capture attached through ESP-NETIF TAP");
        return true;
    }
    LOG_WARNING(TAG, "ESP32-P4 L2 TAP unavailable; falling back to input callback");
#endif

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
#if defined(CONFIG_IDF_TARGET_ESP32P4) && defined(CONFIG_ESP_NETIF_L2_TAP) && CONFIG_ESP_NETIF_L2_TAP
    detachL2Tap();
#endif
    // Note: ESP-IDF doesn't provide a way to restore previous input path
    // This is acceptable since we're intercepting packets, not replacing the stack
    eth_ = nullptr; eng_ = nullptr; promiscuous_enabled_ = false;
}

#if defined(CONFIG_IDF_TARGET_ESP32P4) && defined(CONFIG_ESP_NETIF_L2_TAP) && CONFIG_ESP_NETIF_L2_TAP
bool EthL2Adapter::attachL2Tap() {
    // Registration is process-wide. ESP_ERR_INVALID_STATE means another
    // component already registered the default VFS, which is safe to reuse.
    const esp_err_t reg = esp_vfs_l2tap_intf_register(nullptr);
    if (reg != ESP_OK && reg != ESP_ERR_INVALID_STATE) {
        LOG_WARNINGF(TAG, "L2 TAP VFS registration failed: %s", esp_err_to_name(reg));
        return false;
    }

    tap_fd_ = ::open(L2TAP_VFS_DEFAULT_PATH, O_NONBLOCK);
    if (tap_fd_ < 0) {
        LOG_WARNINGF(TAG, "Opening %s failed: errno=%d", L2TAP_VFS_DEFAULT_PATH, errno);
        tap_fd_ = -1;
        return false;
    }

    if (::ioctl(tap_fd_, L2TAP_S_DEVICE_DRV_HNDL,
                static_cast<l2tap_iodriver_handle>(eth_)) < 0) {
        LOG_WARNINGF(TAG, "Binding L2 TAP to Ethernet driver failed: errno=%d", errno);
        ::close(tap_fd_);
        tap_fd_ = -1;
        return false;
    }

    // ioctl expects the host-order EtherType; the frame itself remains
    // network byte order (0x8892 on the wire).
    uint16_t filter = 0x8892;
    if (::ioctl(tap_fd_, L2TAP_S_RCV_FILTER, &filter) < 0) {
        LOG_WARNINGF(TAG, "Setting PROFINET EtherType filter failed: errno=%d", errno);
        ::close(tap_fd_);
        tap_fd_ = -1;
        return false;
    }

    // Install the same L2-TAP-aware input path used by ESP-NETIF's Ethernet
    // glue.  Some P4 Ethernet integrations replace the callback during start,
    // so relying only on the glue-installed callback can leave the TAP queue
    // empty even though the TAP fd is valid.
    const esp_err_t path_err = esp_eth_update_input_path_info(
        eth_, &EthL2Adapter::l2tapInputTrampoline, this);
    if (path_err != ESP_OK) {
        LOG_WARNINGF(TAG, "Installing L2 TAP Ethernet input path failed: %s",
                     esp_err_to_name(path_err));
        ::close(tap_fd_);
        tap_fd_ = -1;
        return false;
    }

    tap_running_.store(true);
    if (xTaskCreate(&EthL2Adapter::tapTaskThunk, "profinet_l2tap", 4096, this,
                    tskIDLE_PRIORITY + 2, &tap_task_) != pdPASS) {
        LOG_WARNING(TAG, "Creating L2 TAP reader task failed");
        tap_running_.store(false);
        ::close(tap_fd_);
        tap_fd_ = -1;
        tap_task_ = nullptr;
        return false;
    }
    return true;
}

esp_err_t EthL2Adapter::l2tapInputTrampoline(esp_eth_handle_t h, uint8_t* buffer,
                                             uint32_t length, void* priv, void* info) {
    auto* self = static_cast<EthL2Adapter*>(priv);
    size_t filtered_length = length;
    const esp_err_t filter_err = esp_vfs_l2tap_eth_filter_frame(
        h, buffer, &filtered_length, info);
    (void)filter_err;
    if (filtered_length == 0) {
        return ESP_OK;
    }
    if (!self || !self->netif_) {
        free(buffer);
        return ESP_ERR_INVALID_STATE;
    }
    // The TAP consumes the configured EtherType (currently PROFINET DCP).
    // Every other frame remains on the normal netif path, but must still be
    // observed by NetworkEngine so P4 has the same L2 coverage as the legacy
    // Ethernet callback.  ingestL2 copies synchronously before lwIP ownership
    // is transferred, so the driver buffer is never retained by the engine.
    self->dispatchFrameToEngine(buffer, static_cast<uint32_t>(filtered_length));
    return esp_netif_receive(self->netif_, buffer, filtered_length, nullptr);
}

void EthL2Adapter::detachL2Tap() {
    tap_running_.store(false);
    for (int i = 0; i < 100 && tap_task_ != nullptr; ++i) {
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (tap_task_ != nullptr) {
        vTaskDelete(tap_task_);
        tap_task_ = nullptr;
    }
    if (tap_fd_ >= 0) {
        ::close(tap_fd_);
        tap_fd_ = -1;
    }
}

void EthL2Adapter::tapTaskThunk(void* arg) {
    auto* self = static_cast<EthL2Adapter*>(arg);
    if (self) self->tapTask();
    vTaskDelete(nullptr);
}

void EthL2Adapter::tapTask() {
    uint8_t frame[1600];
    while (tap_running_.load()) {
        const ssize_t n = ::read(tap_fd_, frame, sizeof(frame));
        if (n >= static_cast<ssize_t>(sizeof(EthHdr)) && eng_) {
            dispatchFrameToEngine(frame, static_cast<uint32_t>(n));
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_WARNINGF(TAG, "L2 TAP read failed: errno=%d", errno);
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    tap_running_.store(false);
    tap_task_ = nullptr;
}
#endif

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

void EthL2Adapter::dispatchFrameToEngine(const uint8_t* buffer, uint32_t length) {
    if (!eng_ || !buffer || length < sizeof(EthHdr)) return;
    const auto* eh = reinterpret_cast<const EthHdr*>(buffer);
    const uint16_t et = be16(&eh->type);
    const uint16_t plen = static_cast<uint16_t>(length - sizeof(EthHdr));
    eng_->ingestL2(eh->src, eh->dst, et, buffer + sizeof(EthHdr), plen);
}

esp_err_t EthL2Adapter::input_trampoline(esp_eth_handle_t h, uint8_t* buffer, uint32_t length, void* priv){
    EthL2Adapter* self = reinterpret_cast<EthL2Adapter*>(priv);
    if (self && buffer && length >= sizeof(EthHdr)) {
        self->dispatchFrameToEngine(buffer, length);
    }

    if (self && self->netif_) {
        ///LOG_INFO("PacketCapture", "FORWARDING PACKET TO IP STACK ENABLED!!!! Test PING");
        return esp_netif_receive(self->netif_, buffer, length, nullptr);
    } else {
        LOG_ERROR("PacketCapture", "FORWARDING PACKET TO IP STACK NOT POSSIBLE");
        // If no netif provided, just indicate we've sniffed the packet
        return ESP_ERR_NOT_SUPPORTED;
    }
}
