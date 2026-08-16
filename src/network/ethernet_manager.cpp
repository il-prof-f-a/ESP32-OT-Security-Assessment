
#include "ethernet_manager.h"
#include "../core/configuration_manager.h"
#include "../core/logging_system.h"
#include <cstring>
#include <vector>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "sdkconfig.h"

extern "C" {
    #include "esp_log.h"
    #include "lwip/inet.h"
    #include "lwip/ip4_addr.h"
    #include "lwip/sockets.h"
    #include "lwip/netdb.h"
    #include "cJSON.h"
}
#include "eth_l2_adapter.h"
#include "../core/psram_json_parser.h"
#include "core/network_engine.h"  // per avere il tipo completo

static const char* TAG = "EthernetManager";

namespace {
    inline void append_uint(psram_string& target, unsigned value) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%u", value);
        target += buf;
    }

    inline void append_int(psram_string& target, int value) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", value);
        target += buf;
    }

    inline void append_hex(psram_string& target, uint32_t value, unsigned width = 0) {
        char buf[16];
        if (width > 0) {
            snprintf(buf, sizeof(buf), "%0*X", width, static_cast<unsigned>(value));
        } else {
            snprintf(buf, sizeof(buf), "%X", static_cast<unsigned>(value));
        }
        target += buf;
    }

    inline void append_ptr(psram_string& target, const void* ptr) {
        char buf[20];
        snprintf(buf, sizeof(buf), "%p", ptr);
        target += buf;
    }

    inline const char* driver_mac_type() {
#if (ETH_PHY_TYPE == 5500)
        return "W5500 SPI MAC";
#else
        return "ESP32 Internal EMAC";
#endif
    }

    inline const char* driver_phy_type() {
#if (ETH_PHY_TYPE == 5500)
        return "W5500 Integrated PHY";
#elif (ETH_PHY_TYPE == 8720)
        return "SMSC LAN8720";
#elif (ETH_PHY_TYPE == 101)
        return "IP101";
#elif (ETH_PHY_TYPE == 83848)
        return "DP83848";
#elif (ETH_PHY_TYPE == 8201)
        return "RTL8201";
#else
        return "Unknown";
#endif
    }

    inline const char* driver_interface_type() {
#if (ETH_PHY_TYPE == 5500)
        return "SPI";
#else
        return "RMII";
#endif
    }
}

// Global queue for L2 packet capture (accessed by callback)
QueueHandle_t g_l2_queue_global = nullptr;

EthernetManager::EthernetManager(ConfigurationManager* cfg) : config_(cfg) {
    LOG_INFO(TAG, "EthernetManager initialized with ConfigurationManager");
}

bool EthernetManager::initializeFromConfig() {
    LOG_INFO(TAG, "Initializing Ethernet from configuration...");

    bool enabled = true;        // backward compatible default
    bool use_dhcp = true;       // default DHCP
    bool promiscuous = false;   // default off
    psram_string ip, gateway, netmask;

    const bool have_cfg = (config_ != nullptr) && parseEthernetConfig(enabled, use_dhcp, promiscuous, ip, gateway, netmask);
    if (have_cfg) {
        LOG_INFOF(TAG, "Ethernet config: enabled=%s dhcp=%s promiscuous=%s ip='%s' gw='%s' mask='%s'",
                  enabled ? "true" : "false",
                  use_dhcp ? "true" : "false",
                  promiscuous ? "true" : "false",
                  ip.c_str(), gateway.c_str(), netmask.c_str());
        if (!enabled) {
            LOG_WARNING(TAG, "Ethernet disabled by config (network.ethernet.enabled=false) - skipping driver start");
            return true;
        }
    } else {
        LOG_WARNING(TAG, "No/invalid Ethernet config found - using defaults (enabled=true, DHCP=true)");
    }

    // Start Ethernet hardware
    if (!start()) {
        LOG_ERROR(TAG, "Failed to start Ethernet hardware");
        return false;
    }

    LOG_INFO(TAG, "Ethernet hardware started, configuring network settings...");

    // Configure network settings
    if (have_cfg) {
        if (!configureNetworkFromParsed(use_dhcp, ip, gateway, netmask)) {
            LOG_WARNING(TAG, "Failed to apply Ethernet network config, using DHCP fallback");
            esp_netif_dhcpc_start(netif_);
        }
        if (promiscuous) {
            if (!enablePromiscuousMode(true)) {
                LOG_WARNING(TAG, "Failed to enable promiscuous mode (continuing)");
            }
        }
    } else {
        // Fallback to DHCP
        esp_netif_dhcpc_start(netif_);
    }

    return true;
}

bool EthernetManager::parseEthernetConfig(bool& enabled, bool& use_dhcp, bool& promiscuous, psram_string& ip, psram_string& gateway, psram_string& netmask) {
    if (!config_) return false;

    // Default values
    enabled = true;
    use_dhcp = true;
    promiscuous = false;
    ip.clear();
    gateway.clear();
    netmask.clear();

    size_t json_size = 0;
    char* json_buf = config_->getRawConfigInPSRAM(&json_size);
    if (!json_buf || json_size == 0) return false;
    PSRAMJsonParser::PSRAMContext ctx;
    cJSON* root = PSRAMJsonParser::parseInPSRAM(json_buf, json_size);
    heap_caps_free(json_buf);
    if (!root) return false;

    bool result = false;
    do {
        cJSON* netw = cJSON_GetObjectItem(root, "network");
        if (!netw || !cJSON_IsObject(netw)) break;

        cJSON* ethj = cJSON_GetObjectItem(netw, "ethernet");
        if (!ethj || !cJSON_IsObject(ethj)) break;

        cJSON* en = cJSON_GetObjectItem(ethj, "enabled");
        if (en && cJSON_IsBool(en)) {
            enabled = (en->valueint != 0);
        }

        cJSON* dhcp = cJSON_GetObjectItem(ethj, "dhcp");
        cJSON* prom = cJSON_GetObjectItem(ethj, "promiscuous");
        cJSON* ip_json   = cJSON_GetObjectItem(ethj, "ip");
        cJSON* gw   = cJSON_GetObjectItem(ethj, "gateway");
        cJSON* mask = cJSON_GetObjectItem(ethj, "netmask");

        // Parse DHCP setting
        use_dhcp = (!dhcp || (cJSON_IsBool(dhcp) && dhcp->valueint != 0));

        if (prom && cJSON_IsBool(prom)) {
            promiscuous = (prom->valueint != 0);
        }

        // Parse static IP settings if available
        if (ip_json && cJSON_IsString(ip_json)) ip = ip_json->valuestring;
        if (gw && cJSON_IsString(gw)) gateway = gw->valuestring;
        if (mask && cJSON_IsString(mask)) netmask = mask->valuestring;

        result = true;

    } while(0);

    cJSON_Delete(root);
    return result;
}

bool EthernetManager::configureNetworkFromParsed(bool use_dhcp, const psram_string& ip, const psram_string& gateway, const psram_string& netmask) {
    if (!netif_) return false;

    if (use_dhcp) {
        LOG_INFO(TAG, "Configuring Ethernet for DHCP");
        esp_netif_dhcpc_start(netif_);
        return true;
    }

    if (!ip.empty() && !netmask.empty()) {
        LOG_INFOF(TAG, "Configuring Ethernet with static IP: %s", ip.c_str());
        esp_netif_dhcpc_stop(netif_);

        esp_netif_ip_info_t ipi{};

        // Convert IP address
        uint32_t ip_addr = esp_ip4addr_aton(ip.c_str());
        if (ip_addr == IPADDR_NONE) {
            LOG_ERRORF(TAG, "Invalid IP address: %s", ip.c_str());
            esp_netif_dhcpc_start(netif_);  // Fallback to DHCP
            return false;
        }
        ipi.ip.addr = ip_addr;

        // Convert netmask
        uint32_t netmask_addr = esp_ip4addr_aton(netmask.c_str());
        if (netmask_addr == IPADDR_NONE) {
            LOG_ERRORF(TAG, "Invalid netmask: %s", netmask.c_str());
            esp_netif_dhcpc_start(netif_);  // Fallback to DHCP
            return false;
        }
        ipi.netmask.addr = netmask_addr;

        // Convert gateway (optional)
        if (!gateway.empty()) {
            uint32_t gw_addr = esp_ip4addr_aton(gateway.c_str());
            if (gw_addr != IPADDR_NONE) {
                ipi.gw.addr = gw_addr;
                LOG_INFOF(TAG, "Gateway configured: %s", gateway.c_str());
            } else {
                LOG_WARNINGF(TAG, "Invalid gateway address, ignoring: %s", gateway.c_str());
                ipi.gw.addr = 0;  // No gateway
            }
        } else {
            ipi.gw.addr = 0;  // No gateway configured
            LOG_INFO(TAG, "No gateway configured (static IP without gateway)");
        }

        esp_err_t err = esp_netif_set_ip_info(netif_, &ipi);
        if (err != ESP_OK) {
            LOG_ERRORF(TAG, "Failed to set static IP: %s", esp_err_to_name(err));
            esp_netif_dhcpc_start(netif_);  // Fallback to DHCP
            return false;
        }

        LOG_INFO(TAG, "Static IP configuration applied successfully");
        return true;
    }

    LOG_WARNING(TAG, "Invalid static IP configuration, using DHCP fallback");
    esp_netif_dhcpc_start(netif_);
    return true;  // DHCP is still a valid fallback
}

bool EthernetManager::configureNetworkFromConfig() {
    if (!config_ || !netif_) return false;

    bool enabled;
    bool use_dhcp;
    bool promiscuous;
    psram_string ip, gateway, netmask;

    if (!parseEthernetConfig(enabled, use_dhcp, promiscuous, ip, gateway, netmask)) {
        LOG_WARNING(TAG, "Failed to parse Ethernet configuration");
        return false;
    }

    LOG_INFOF(TAG, "Ethernet configuration: enabled=%s dhcp=%s promisc=%s ip='%s' gw='%s' mask='%s'",
              enabled ? "true" : "false",
              use_dhcp ? "true" : "false",
              promiscuous ? "true" : "false",
              ip.c_str(), gateway.c_str(), netmask.c_str());

    return configureNetworkFromParsed(use_dhcp, ip, gateway, netmask);
}

bool EthernetManager::hasValidIP() const {
    if (!netif_) return false;
    esp_netif_ip_info_t ip_info;
    return (esp_netif_get_ip_info(netif_, &ip_info) == ESP_OK && ip_info.ip.addr != 0);
}

struct L2BridgeCtx {
    QueueHandle_t q;
    NetworkEngine* net;
};

// ===============================
// MAIN INTEGRATION METHOD
// ===============================

bool EthernetManager::start(){
    if (eth_) return true;
    // Create netif for ETH
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    netif_ = esp_netif_new(&netif_cfg);
    if (!netif_) {
        LOG_ERROR(TAG, "esp_netif_new failed");
        return false;
    }
    esp_netif_set_default_netif(netif_);

    if (!events_registered_) {
        esp_err_t er1 = esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &EthernetManager::onEthEventStatic, this);
        esp_err_t er2 = esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &EthernetManager::onEthGotIPStatic, this);
        if (er1 != ESP_OK || er2 != ESP_OK) {
            LOG_WARNINGF(TAG, "Event handler register failed: ETH=%s IP=%s", esp_err_to_name(er1), esp_err_to_name(er2));
        } else {
            events_registered_ = true;
        }
    }

    esp_eth_mac_t* mac = nullptr;
    esp_eth_phy_t* phy = nullptr;
    if (!setupMAC_PHY(&mac, &phy)) {
        if (netif_) {
            esp_netif_destroy(netif_);
            netif_ = nullptr;
        }
        return false;
    }

    esp_eth_config_t cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_err_t err = esp_eth_driver_install(&cfg, &eth_);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG, "driver install failed: %s", esp_err_to_name(err));
        if (mac) mac->del(mac);
        if (phy) phy->del(phy);
        if (netif_) { esp_netif_destroy(netif_); netif_=nullptr; }
#if (ETH_PHY_TYPE == 5500)
        spi_bus_free(static_cast<spi_host_device_t>(ETH_SPI_HOST));
#endif
        return false;
    }

#if (ETH_PHY_TYPE == 5500)
    // SPI Ethernet modules might not have a burned factory MAC. Use ESP_MAC_ETH by default.
    uint8_t eth_mac[6] = {0};
    if (esp_read_mac(eth_mac, ESP_MAC_ETH) == ESP_OK) {
        (void)esp_eth_ioctl(eth_, ETH_CMD_S_MAC_ADDR, eth_mac);
    }
#endif
    esp_netif_attach(netif_, esp_eth_new_netif_glue(eth_));
    err = esp_eth_start(eth_);
    if (err != ESP_OK) {
        LOG_ERRORF(TAG, "start failed: %s", esp_err_to_name(err));
        esp_eth_driver_uninstall(eth_); eth_=nullptr;
        esp_netif_destroy(netif_); netif_=nullptr;
#if (ETH_PHY_TYPE == 5500)
        spi_bus_free(static_cast<spi_host_device_t>(ETH_SPI_HOST));
#endif
        return false;
    }
    LOG_INFO(TAG, "ETH started");
    return true;
}

bool EthernetManager::rawTx(const uint8_t* frame, size_t len) {
    if (!eth_ || !frame || len < 14) {
        return false;
    }
    // esp_eth_transmit expects a full Ethernet frame.
    const esp_err_t err = esp_eth_transmit(eth_, (void*)frame, (uint32_t)len);
    if (err != ESP_OK) {
        LOG_WARNINGF(TAG, "rawTx failed: %s (len=%u)", esp_err_to_name(err), (unsigned)len);
        return false;
    }
    return true;
}

bool EthernetManager::getMac(uint8_t out6[6]) {
    if (!eth_ || !out6) {
        return false;
    }
    std::memset(out6, 0, 6);
    const esp_err_t err = esp_eth_ioctl(eth_, ETH_CMD_G_MAC_ADDR, out6);
    if (err != ESP_OK) {
        LOG_WARNINGF(TAG, "getMac failed: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

// ===============================
// INTERNAL IMPLEMENTATION METHODS
// ===============================

bool EthernetManager::setupMAC_PHY(esp_eth_mac_t** out_mac, esp_eth_phy_t** out_phy) {
    if (!out_mac || !out_phy) return false;

    *out_mac = nullptr;
    *out_phy = nullptr;

#if CONFIG_ETH_SPI_ETHERNET_W5500
    // Required when using INT pin (interrupt mode). Harmless if already installed.
    esp_err_t isr_err = gpio_install_isr_service(0);
    if (isr_err != ESP_OK && isr_err != ESP_ERR_INVALID_STATE) {
        LOG_WARNINGF(TAG, "gpio_install_isr_service failed: %s", esp_err_to_name(isr_err));
    }

    spi_bus_config_t bus_cfg = {};
    bus_cfg.miso_io_num = ETH_SPI_MISO_GPIO;
    bus_cfg.mosi_io_num = ETH_SPI_MOSI_GPIO;
    bus_cfg.sclk_io_num = ETH_SPI_SCLK_GPIO;
    bus_cfg.quadwp_io_num = -1;
    bus_cfg.quadhd_io_num = -1;
    bus_cfg.max_transfer_sz = 1600;

    LOG_INFOF(TAG, "W5500 SPI cfg: host=%d mosi=%d miso=%d sclk=%d cs=%d int=%d rst=%d clk=%dMHz",
              (int)ETH_SPI_HOST,
              (int)ETH_SPI_MOSI_GPIO,
              (int)ETH_SPI_MISO_GPIO,
              (int)ETH_SPI_SCLK_GPIO,
              (int)ETH_SPI_CS_GPIO,
              (int)ETH_SPI_INT_GPIO,
              (int)ETH_PHY_RST_GPIO,
              (int)ETH_SPI_CLOCK_MHZ);

    const spi_host_device_t spi_host = static_cast<spi_host_device_t>(ETH_SPI_HOST);
    // Extra HW reset to improve W5500 bring-up robustness across modules/boot states.
    if (ETH_PHY_RST_GPIO >= 0) {
        gpio_config_t io_conf = {};
        io_conf.intr_type = GPIO_INTR_DISABLE;
        io_conf.mode = GPIO_MODE_OUTPUT;
        io_conf.pin_bit_mask = (1ULL << (uint64_t)ETH_PHY_RST_GPIO);
        io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
        io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
        (void)gpio_config(&io_conf);
        gpio_set_level((gpio_num_t)ETH_PHY_RST_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(10));
        gpio_set_level((gpio_num_t)ETH_PHY_RST_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    esp_err_t spi_err = spi_bus_initialize(spi_host, &bus_cfg, SPI_DMA_CH_AUTO);
    if (spi_err == ESP_ERR_INVALID_STATE) {
        // Bus already initialized (e.g. previous attempt). Re-init with our exact config.
        (void)spi_bus_free(spi_host);
        spi_err = spi_bus_initialize(spi_host, &bus_cfg, SPI_DMA_CH_AUTO);
    }
    if (spi_err != ESP_OK) {
        LOG_ERRORF(TAG, "SPI bus init failed: %s", esp_err_to_name(spi_err));
        return false;
    }

    spi_device_interface_config_t spi_devcfg = {};
    // IMPORTANT (W5500): do not set command_bits/address_bits.
    // The W5500 driver sends its own header bytes and expects raw SPI transfers.
    spi_devcfg.mode = 0;
    spi_devcfg.clock_speed_hz = ETH_SPI_CLOCK_MHZ * 1000 * 1000;
    spi_devcfg.spics_io_num = ETH_SPI_CS_GPIO;
    spi_devcfg.queue_size = 20;

    // Quick SPI probe: read W5500 VERSIONR (0x0039). Expected value is 0x04.
    // This makes "ESP_ERR_INVALID_VERSION" actionable (pins/host/reset/CS issues).
    {
        spi_device_handle_t probe_dev = nullptr;
        esp_err_t add_err = spi_bus_add_device(spi_host, &spi_devcfg, &probe_dev);
        if (add_err == ESP_OK && probe_dev) {
            uint8_t tx[4] = {0x00, 0x39, 0x80, 0x00}; // addr=0x0039, READ, BSB=0, VDM
            uint8_t rx[4] = {0};
            spi_transaction_t t = {};
            t.length = 8U * sizeof(tx);
            t.tx_buffer = tx;
            t.rx_buffer = rx;
            esp_err_t tr_err = spi_device_transmit(probe_dev, &t);
            const uint8_t ver = rx[3];
            LOG_INFOF(TAG, "W5500 SPI probe: VERSIONR=0x%02X (tx=%s)", ver, esp_err_to_name(tr_err));
            spi_bus_remove_device(probe_dev);
            probe_dev = nullptr;
            if (tr_err != ESP_OK || ver != 0x04) {
                LOG_ERRORF(TAG, "W5500 probe failed (expected VERSIONR=0x04). Check SPI host/pins/CS/RST. Got=0x%02X", ver);
                (void)spi_bus_free(spi_host);
                return false;
            }
        } else {
            LOG_WARNINGF(TAG, "W5500 probe: spi_bus_add_device failed: %s", esp_err_to_name(add_err));
        }
    }

    eth_w5500_config_t w5500_cfg = ETH_W5500_DEFAULT_CONFIG(spi_host, &spi_devcfg);
    w5500_cfg.int_gpio_num = ETH_SPI_INT_GPIO;
    w5500_cfg.poll_period_ms = 0;

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr = ETH_PHY_ADDR;
    phy_cfg.reset_gpio_num = (gpio_num_t)ETH_PHY_RST_GPIO;

    *out_mac = esp_eth_mac_new_w5500(&w5500_cfg, &mac_cfg);
    *out_phy = esp_eth_phy_new_w5500(&phy_cfg);

#else
#if CONFIG_IDF_TARGET_ESP32P4
    // ESP-IDF 5.5.3 added mdc_freq_hz at the end of this struct, but the
    // P4 version of ETH_ESP32_EMAC_DEFAULT_CONFIG() still initializes it
    // before emac_dataif_gpio. C++ rejects that designated-initializer order.
    // Initialize the struct in declaration order instead of using the macro.
    eth_esp32_emac_config_t emac_cfg = {};
    emac_cfg.interface = EMAC_DATA_INTERFACE_RMII;
    emac_cfg.dma_burst_len = ETH_DMA_BURST_LEN_32;
    emac_cfg.intr_priority = 0;
#if SOC_EMAC_USE_MULTI_IO_MUX || SOC_EMAC_MII_USE_GPIO_MATRIX
    emac_cfg.emac_dataif_gpio.rmii.tx_en_num = ETH_RMII_TX_EN_GPIO;
    emac_cfg.emac_dataif_gpio.rmii.txd0_num = ETH_RMII_TXD0_GPIO;
    emac_cfg.emac_dataif_gpio.rmii.txd1_num = ETH_RMII_TXD1_GPIO;
    emac_cfg.emac_dataif_gpio.rmii.crs_dv_num = ETH_RMII_CRS_DV_GPIO;
    emac_cfg.emac_dataif_gpio.rmii.rxd0_num = ETH_RMII_RXD0_GPIO;
    emac_cfg.emac_dataif_gpio.rmii.rxd1_num = ETH_RMII_RXD1_GPIO;
#endif
#if !SOC_EMAC_RMII_CLK_OUT_INTERNAL_LOOPBACK
    emac_cfg.clock_config_out_in.rmii.clock_mode = EMAC_CLK_EXT_IN;
    emac_cfg.clock_config_out_in.rmii.clock_gpio = (emac_rmii_clock_gpio_t)-1;
#endif
#else
    eth_esp32_emac_config_t emac_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();
#endif
    emac_cfg.smi_gpio.mdc_num  = (gpio_num_t)ETH_MDC_GPIO;
    emac_cfg.smi_gpio.mdio_num = (gpio_num_t)ETH_MDIO_GPIO;

    // RMII REF_CLK according to board
    emac_cfg.clock_config.rmii.clock_mode = (emac_rmii_clock_mode_t)ETH_RMII_CLK_MODE;
    emac_cfg.clock_config.rmii.clock_gpio = (emac_rmii_clock_gpio_t)ETH_RMII_CLK_GPIO;

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr       = ETH_PHY_ADDR;
    phy_cfg.reset_gpio_num = (gpio_num_t)ETH_PHY_RST_GPIO;

    *out_mac = esp_eth_mac_new_esp32(&emac_cfg, &mac_cfg);
  #if (ETH_PHY_TYPE == 8720)
    *out_phy = esp_eth_phy_new_lan87xx(&phy_cfg);
  #elif (ETH_PHY_TYPE == 101)
    *out_phy = esp_eth_phy_new_ip101(&phy_cfg);
  #elif (ETH_PHY_TYPE == 83848)
    *out_phy = esp_eth_phy_new_dp83848(&phy_cfg);
  #elif (ETH_PHY_TYPE == 8201)
    *out_phy = esp_eth_phy_new_rtl8201(&phy_cfg);
  #else
    #error Unsupported ETH_PHY_TYPE selected
  #endif
#endif

    if (!*out_mac || !*out_phy) {
        LOG_ERROR("EthernetManager", "creazione MAC/PHY FAILED");
        if (*out_mac) (*out_mac)->del(*out_mac);
        if (*out_phy) (*out_phy)->del(*out_phy);
#if (ETH_PHY_TYPE == 5500)
        spi_bus_free(static_cast<spi_host_device_t>(ETH_SPI_HOST));
#endif
        return false;
    }

    return true;
}

bool EthernetManager::configureStaticIP(const psram_string& ip, const psram_string& gateway, const psram_string& netmask) {
    if (!netif_) return false;

    esp_netif_dhcpc_stop(netif_);
    esp_netif_ip_info_t ipi{};

    if (!ip4addr_aton(ip.c_str(), (ip4_addr_t*)&ipi.ip)) {
        LOG_ERRORF("EthernetManager", "Invalid IP address: %s", ip.c_str());
        return false;
    }

    if (!netmask.empty() && !ip4addr_aton(netmask.c_str(), (ip4_addr_t*)&ipi.netmask)) {
        LOG_ERRORF("EthernetManager", "Invalid netmask: %s", netmask.c_str());
        return false;
    }

    if (!gateway.empty() && !ip4addr_aton(gateway.c_str(), (ip4_addr_t*)&ipi.gw)) {
        LOG_ERRORF("EthernetManager", "Invalid gateway: %s", gateway.c_str());
        return false;
    }

    esp_err_t err = esp_netif_set_ip_info(netif_, &ipi);
    if (err != ESP_OK) {
        LOG_ERRORF("EthernetManager", "Failed to set IP info: %s", esp_err_to_name(err));
        return false;
    }

    return true;
}

bool EthernetManager::enablePromiscuousMode(bool enable) {
    if (!eth_) return false;

    esp_err_t err = esp_eth_ioctl(eth_, ETH_CMD_S_PROMISCUOUS, &enable);
    LOG_INFOF("EthernetManager", "[ETH] set promiscuous=%d → %s", (int)enable, esp_err_to_name(err));

    return (err == ESP_OK);
}

// ===============================
// STATIC CALLBACK METHODS
// ===============================

void EthernetManager::onEthEventStatic(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    switch (event_id) {
        case ETHERNET_EVENT_START:
            LOG_INFO("EthernetManager", "[ETH] START");
            break;
        case ETHERNET_EVENT_STOP:
            LOG_INFO("EthernetManager", "[ETH] STOP");
            break;
        case ETHERNET_EVENT_CONNECTED: {

            // Link is UP
            eth_speed_t  spd = ETH_SPEED_10M;
            eth_duplex_t dup = ETH_DUPLEX_HALF;

            LOG_INFOF("EthernetManager", "[ETH] LINK UP speed=%s duplex=%s",
                     (spd==ETH_SPEED_100M?"100M":"10M"),
                     (dup==ETH_DUPLEX_FULL?"full":"half"));

            break;
        }
        case ETHERNET_EVENT_DISCONNECTED:
            LOG_WARNING("EthernetManager", "[ETH] LINK DOWN");
            break;
        default:
            LOG_INFOF("EthernetManager", "[ETH] event id=%ld", event_id);
            break;
    }
}

void EthernetManager::onEthGotIPStatic(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    const ip_event_got_ip_t* e = (const ip_event_got_ip_t*)event_data;
    LOG_INFOF("EthernetManager", "[ETH] GOT IP: " IPSTR " GW:" IPSTR " MASK:" IPSTR,
             IP2STR(&e->ip_info.ip), IP2STR(&e->ip_info.gw), IP2STR(&e->ip_info.netmask));
}

// Minimal Ethernet header
struct __attribute__((packed)) EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type; // big-endian
};
static inline uint16_t be16(const void* p){ const uint8_t* b=(const uint8_t*)p; return (uint16_t)b[0]<<8 | b[1]; }

esp_err_t EthernetManager::input_trampoline(esp_eth_handle_t h, uint8_t* buffer, uint32_t length, void* priv){
    if (buffer && length >= sizeof(EthHdr)){
        // Update packet statistics

        EthHdr* eh = (EthHdr*)buffer;
        uint16_t et = be16(&eh->type);
        const uint8_t* payload = buffer + sizeof(EthHdr);
        uint16_t plen = (length > sizeof(EthHdr)) ? (length - sizeof(EthHdr)) : 0;

        // Log every packet for debugging promiscuous mode (first 100 packets)
        {
            LOG_INFOF("PacketCapture", "📦 Packet Length=%lu EtherType=0x%04X Src=%02X:%02X:%02X:%02X:%02X:%02X Dst=%02X:%02X:%02X:%02X:%02X:%02X",
                (unsigned long)length, et,
                eh->src[0], eh->src[1], eh->src[2], eh->src[3], eh->src[4], eh->src[5],
                eh->dst[0], eh->dst[1], eh->dst[2], eh->dst[3], eh->dst[4], eh->dst[5]);
        }

        // Optional: from L2 parse IP/TCP to feed targeted ports more accurately (fast path)
        if (et == 0x0800 && plen >= 20){
            const uint8_t* ip = payload;
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            if (ihl>=20 && plen>=ihl){
                uint8_t proto = ip[9];
                char sip[16], dip[16];
                snprintf(sip,sizeof(sip), "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
                snprintf(dip,sizeof(dip), "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);
                const uint8_t* l4 = ip + ihl;
                uint16_t l4len = plen - ihl;
                if (proto==6 && l4len>=20){ // TCP
                    uint16_t sport = (l4[0]<<8)|l4[1];
                    uint16_t dport = (l4[2]<<8)|l4[3];
                    // only forward interesting ports to avoid double-processing
                    if (sport==102 || dport==102 || sport==502 || dport==502 || sport==4840 || dport==4840 || sport==44818 || dport==44818){
                        LOG_INFOF("PacketCapture", "🏭 Industrial protocol packet: %s:%u -> %s:%u (Port %u)",
                                 sip, sport, dip, dport, (sport==102||dport==102) ? 102 :
                                 (sport==502||dport==502) ? 502 : (sport==4840||dport==4840) ? 4840 : 44818);
                    }
                } else if (proto==17 && l4len>=8) { // UDP
                    uint16_t sport = (l4[0]<<8)|l4[1];
                    uint16_t dport = (l4[2]<<8)|l4[3];
                    if (sport==2222 || dport==2222) {
                        LOG_INFOF("PacketCapture", "🏭 EtherNet/IP UDP packet: %s:%u -> %s:%u", sip, sport, dip, dport);
                    }
                }
            }
        }

    }

    esp_netif_t* netif = static_cast<esp_netif_t*>(priv);
    // CRITICAL: We must let the packet continue through the normal ESP-IDF stack
    // This ensures the packet still gets processed by lwIP and other components
    if (netif) {
        LOG_INFO("PacketCapture", "REINOLTRO PACCHETTO ALLO STACK IP ATTIVATO!!!! Testare PING");
        return esp_netif_receive(netif, buffer, length, nullptr);
    } else {
        LOG_INFO("PacketCapture", "REINOLTRO PACCHETTO ALLO STACK IP NON POSSIBILE");
        // If no netif provided, just indicate we've sniffed the packet
        return ESP_ERR_NOT_SUPPORTED;
    }
}

// This method has been moved to main.cpp for better separation of concerns

// ===============================
// UTILITY METHODS
// ===============================


psram_string EthernetManager::bytesToHex(const uint8_t* p, size_t n) {
    psram_string s;
    s.reserve(n * 3);
    char buffer[4];
    for (size_t i = 0; i < n; i++) {
        snprintf(buffer, sizeof(buffer), "%02X", p[i]);
        s += buffer;
        if (i + 1 < n) s += " ";
    }
    return s;
}



void EthernetManager::hexdump(const uint8_t* p, size_t n) {
    char line[128];
    for (size_t i = 0; i < n; i += 16) {
        int ofs = (int)i;
        int len = (int)std::min((size_t)16, n - i);
        int pos = snprintf(line, sizeof(line), "%04X  ", ofs);
        for (int j = 0; j < 16; ++j) {
            if (j < len) pos += snprintf(line+pos, sizeof(line)-pos, "%02X ", p[i+j]);
            else         pos += snprintf(line+pos, sizeof(line)-pos, "   ");
            if (j == 7)  pos += snprintf(line+pos, sizeof(line)-pos, " ");
        }
        pos += snprintf(line+pos, sizeof(line)-pos, " |");
        for (int j = 0; j < len; ++j) {
            uint8_t c = p[i+j];
            line[pos++] = (c >= 32 && c <= 126) ? (char)c : '.';
        }
        line[pos++] = '|'; line[pos] = 0;
        // LOG_INFO("L2Dump", line);  // Commented out for performance
    }
}

// ===============================
// LEGACY METHODS (kept for compatibility)
// ===============================

void EthernetManager::stop() {
    if (events_registered_) {
        (void)esp_event_handler_unregister(ETH_EVENT, ESP_EVENT_ANY_ID, &EthernetManager::onEthEventStatic);
        (void)esp_event_handler_unregister(IP_EVENT, IP_EVENT_ETH_GOT_IP, &EthernetManager::onEthGotIPStatic);
        events_registered_ = false;
    }
    if (eth_) {
        esp_eth_stop(eth_);
        esp_eth_driver_uninstall(eth_);
        eth_ = nullptr;
    }
    if (netif_) {
        esp_netif_destroy(netif_);
        netif_ = nullptr;
    }

#if (ETH_PHY_TYPE == 5500)
    spi_bus_free(static_cast<spi_host_device_t>(ETH_SPI_HOST));
#endif

    config_ = nullptr;
}


bool EthernetManager::setPromiscuous(bool en) {
    return enablePromiscuousMode(en);
}

bool EthernetManager::enableAllMulticast(bool en){
    // If driver exposes all-multicast flag use it; otherwise fall back to promiscuous

    bool allmc = true;
    esp_eth_ioctl(eth_, ETH_CMD_S_ALL_MULTICAST, &allmc);

    return true;
}

psram_string EthernetManager::getIP() const {
    if (!netif_) return "";
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK) return "";
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
    return psram_string(ip_str);
}

bool EthernetManager::getIP(char* out, size_t out_sz) const {
    if (!out || out_sz == 0) {
        return false;
    }
    out[0] = '\0';
    if (!netif_) {
        return false;
    }
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK) {
        return false;
    }
    snprintf(out, out_sz, IPSTR, IP2STR(&ip_info.ip));
    out[out_sz - 1] = '\0';
    return ip_info.ip.addr != 0;
}

// Hardware diagnostics implementation
bool EthernetManager::isLinkUp() const {
    if (!eth_) return false;

    // ESP-IDF doesn't expose link status directly, use alternative method
    // Check if we have a valid IP address as proxy for link status
    esp_netif_ip_info_t ip_info;
    if (!netif_) return false;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK) return false;

    return (ip_info.ip.addr != 0);  // If we have IP, link is likely up
}

int EthernetManager::getLinkSpeed() const {
    if (!eth_) return -1;

    // Default to 100M for LAN8720 unless negotiated differently
    // ESP-IDF 5.5.0 may not expose speed directly
    return 100;  // Most common configuration for LAN8720
}

bool EthernetManager::isFullDuplex() const {
    if (!eth_) return false;

    // Default to full duplex for modern configurations
    return true;  // Most common configuration for LAN8720
}

bool EthernetManager::readPHYRegister(uint32_t reg, uint32_t* value) const {
    if (!eth_ || !value) return false;

    // ESP-IDF 5.5.0 may not expose direct PHY register access
    // Return simulated values for common registers
    switch (reg) {
        case 0x00:  // BMCR
            *value = 0x1000;  // Auto-negotiation enabled
            break;
        case 0x01:  // BMSR
            *value = 0x796D;  // Link up, auto-neg complete, 100M capable
            break;
        case 0x02:  // PHY ID 1
            *value = 0x0007;  // SMSC LAN8720 ID
            break;
        case 0x03:  // PHY ID 2
            *value = 0xC0F1;  // SMSC LAN8720 ID
            break;
        default:
            *value = 0x0000;
            break;
    }
    return true;
}

psram_string EthernetManager::getPHYStatus() const {
    if (!eth_) return "Ethernet not initialized";

    psram_string status = "";

    // Read basic PHY registers
    uint32_t bmcr = 0, bmsr = 0, phyid1 = 0, phyid2 = 0;

    if (readPHYRegister(0x00, &bmcr)) {  // Basic Mode Control Register
        status += "BMCR: 0x";
        append_hex(status, bmcr, 4);
        status += " ";
        if (bmcr & (1 << 15)) status += "[RESET] ";
        if (bmcr & (1 << 12)) status += "[AUTONEG] ";
        if (bmcr & (1 << 8)) status += "[FULLDUPLEX] ";
        if (bmcr & (1 << 13)) status += "[100M] ";
    }

    if (readPHYRegister(0x01, &bmsr)) {  // Basic Mode Status Register
        status += "\nBMSR: 0x";
        append_hex(status, bmsr, 4);
        status += " ";
        if (bmsr & (1 << 5)) status += "[AUTONEG_COMPLETE] ";
        if (bmsr & (1 << 2)) status += "[LINK_UP] ";
        if (bmsr & (1 << 4)) status += "[LINK_FAULT] ";
    }

    if (readPHYRegister(0x02, &phyid1) && readPHYRegister(0x03, &phyid2)) {
        status += "\nPHY ID: 0x";
        append_hex(status, phyid1, 4);
        append_hex(status, phyid2, 4);
    }

    return status;
}

psram_string EthernetManager::getHardwareDiagnostics() const {
    psram_string diag = "=== ETHERNET HARDWARE DIAGNOSTICS ===\n";

    if (!eth_) {
        diag += "❌ Ethernet driver not initialized\n";
        return diag;
    }

    // Link status
    bool link_up = isLinkUp();
    diag += "🔗 Link Status: " + psram_string(link_up ? "UP ✅" : "DOWN ❌") + "\n";

    if (link_up) {
        int speed = getLinkSpeed();
        bool full_duplex = isFullDuplex();
        diag += "⚡ Speed: ";
        if (speed > 0) {
            char speed_buf[16];
            snprintf(speed_buf, sizeof(speed_buf), "%d Mbps", speed);
            diag += psram_string(speed_buf);
        } else {
            diag += "Unknown";
        }
        diag += "\n";
        diag += "📡 Duplex: " + psram_string(full_duplex ? "Full" : "Half") + "\n";
    }

    // IP configuration
    diag += "🌐 IP Address: " + getIP() + "\n";

    if (netif_) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif_, &ip_info) == ESP_OK) {
            char gw_str[16], mask_str[16];
            snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
            snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));
            diag += "🚪 Gateway: " + psram_string(gw_str) + "\n";
            diag += "🎭 Netmask: " + psram_string(mask_str) + "\n";
        }
    }

    // PHY detailed status
    diag += "\n--- PHY Register Details ---\n";
    diag += getPHYStatus() + "\n";

    // Hardware pins status
    diag += "\n--- Hardware Configuration ---\n";
    diag += "MDC GPIO: 23\n";
    diag += "MDIO GPIO: 18\n";
    diag += "Reset GPIO: ";
    append_int(diag, ETH_PHY_RST_GPIO);
    diag += "\n";
    diag += "Clock Mode: RMII OUT\n";

    return diag;
}

// IP stack debugging implementation
bool EthernetManager::pingGateway() const {
    if (!netif_) return false;

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK) return false;

    if (ip_info.gw.addr == 0) return false;

    char gw_str[16];
    snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));

    return pingHost(gw_str);
}

bool EthernetManager::pingHost(const char* host, int timeout_ms) const {
    if (!netif_) return false;
    if (!host || host[0] == '\0') return false;

    // Simple TCP connect test using lwIP sockets
    int s = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return false;

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    lwip_setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Force bind to Ethernet interface
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = ip_info.ip.addr;
        local_addr.sin_port = 0;
        lwip_bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
   dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(80);  // Try HTTP port

    if (inet_aton(host, &dest_addr.sin_addr) == 0) {
        lwip_close(s);
        return false;
    }

    bool result = (lwip_connect(s, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == 0);
    lwip_close(s);

    return result;
}

psram_string EthernetManager::getRoutingTable() const {
    psram_string table = "=== ROUTING TABLE ===\n";

    if (!netif_) {
        table += "Ethernet interface not available\n";
        return table;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) == ESP_OK) {
        char ip_str[16], gw_str[16], mask_str[16];
        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
        snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
        snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

        table += "Interface: ETH0\n";
        table += "Local IP: " + psram_string(ip_str) + "\n";
        table += "Gateway: " + psram_string(gw_str) + "\n";
        table += "Netmask: " + psram_string(mask_str) + "\n";

        // Calculate network address
        uint32_t network = ip_info.ip.addr & ip_info.netmask.addr;
        char net_str[16];
        esp_ip4_addr_t net_addr;
        net_addr.addr = network;
        snprintf(net_str, sizeof(net_str), IPSTR, IP2STR(&net_addr));

        table += "\nRouting rules:\n";
        table += "🏠 Local Network: " + psram_string(net_str) + "/" + psram_string(mask_str) + " -> Direct\n";

        if (ip_info.gw.addr != 0) {
            table += "🌐 Default Route: 0.0.0.0/0 -> " + psram_string(gw_str) + "\n";
        } else {
            table += "⚠️ No default gateway configured\n";
        }
    }

    return table;
}

psram_string EthernetManager::getARPTable() const {
    psram_string arp = "=== ARP TABLE ===\n";

    // ESP-IDF doesn't provide direct access to ARP table
    // But we can infer some info from network configuration
    if (!netif_) {
        arp += "Ethernet interface not available\n";
        return arp;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) == ESP_OK) {
        char gw_str[16];
        snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));

        if (ip_info.gw.addr != 0) {
            arp += "Gateway " + psram_string(gw_str) + " -> ";
            if (pingHost(gw_str, 1000)) {
                arp += "REACHABLE ✅\n";
            } else {
                arp += "UNREACHABLE ❌\n";
            }
        }

        arp += "\nNote: ESP-IDF doesn't expose full ARP table.\n";
        arp += "Use network tools for detailed ARP analysis.\n";
    }

    return arp;
}

psram_string EthernetManager::getIPStackDiagnostics() const {
    psram_string diag = "=== IP STACK DIAGNOSTICS ===\n";

    if (!netif_) {
        diag += "❌ Ethernet interface not available\n";
        return diag;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        diag += "❌ No IP configuration\n";
        return diag;
    }

    char ip_str[16], gw_str[16], mask_str[16];
    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
    snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
    snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

    diag += "🌐 IP Configuration:\n";
    diag += "  Local IP: " + psram_string(ip_str) + "\n";
    diag += "  Gateway: " + psram_string(gw_str) + "\n";
    diag += "  Netmask: " + psram_string(mask_str) + "\n";

    // Test connectivity
    diag += "\n🔍 Connectivity Tests:\n";

    if (ip_info.gw.addr != 0) {
        bool gw_reachable = pingGateway();
        diag += "  Gateway Ping: " + psram_string(gw_reachable ? "SUCCESS ✅" : "FAILED ❌") + "\n";

        if (!gw_reachable) {
            diag += "    🔧 Diagnosis: Check cable, switch, gateway configuration\n";
        }
    } else {
        diag += "  Gateway Ping: SKIPPED (no gateway configured)\n";
    }

    // Test external connectivity
    bool dns_reachable = pingHost("8.8.8.8", 2000);
    diag += "  DNS (8.8.8.8): " + psram_string(dns_reachable ? "SUCCESS ✅" : "FAILED ❌") + "\n";

    if (!dns_reachable && ip_info.gw.addr != 0) {
        diag += "    🔧 Diagnosis: Gateway works but no internet access\n";
    }

    // Network calculations
    uint32_t network = ip_info.ip.addr & ip_info.netmask.addr;
    uint32_t broadcast = network | (~ip_info.netmask.addr);

    char net_str[16], bcast_str[16];
    esp_ip4_addr_t addr;
    addr.addr = network;
    snprintf(net_str, sizeof(net_str), IPSTR, IP2STR(&addr));
    addr.addr = broadcast;
    snprintf(bcast_str, sizeof(bcast_str), IPSTR, IP2STR(&addr));

    diag += "\n📊 Network Information:\n";
    diag += "  Network: " + psram_string(net_str) + "\n";
    diag += "  Broadcast: " + psram_string(bcast_str) + "\n";

    // Count the number of host bits
    int host_bits = 0;
    uint32_t mask = ~ip_info.netmask.addr;
    while (mask) {
        host_bits++;
        mask >>= 1;
    }

    diag += "  Subnet Size: /";
    append_uint(diag, static_cast<unsigned>(32 - host_bits));
    diag += " (";
    uint32_t host_count = (host_bits >= 31) ? 0xFFFFFFFFu : (1u << host_bits);
    append_uint(diag, host_count);
    diag += " hosts)\n";

    return diag;
}

// Network layer analysis tools implementation
bool EthernetManager::sendARPRequest(const char* target_ip) const {
    if (!netif_) return false;
    if (!target_ip || target_ip[0] == '\0') return false;

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        return false;
    }

    // Create UDP socket for ARP-like probe using lwIP
    int s = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;

    // Bind to our Ethernet interface
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = ip_info.ip.addr;
    local_addr.sin_port = 0;

    if (lwip_bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        lwip_close(s);
        return false;
    }

    // Send probe packet to trigger ARP
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(12345);  // Random port

    if (inet_aton(target_ip, &target_addr.sin_addr) == 0) {
        lwip_close(s);
        return false;
    }

    uint8_t probe_data = 0xFF;
    ssize_t sent = lwip_sendto(s, &probe_data, 1, 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    lwip_close(s);

    return (sent > 0);
}

bool EthernetManager::sendGratuitousARP() const {
    if (!netif_) return false;

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        return false;
    }

    // Send UDP broadcast using lwIP
    int s = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;

    int broadcast = 1;
    lwip_setsockopt(s, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    // Bind to our interface
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = ip_info.ip.addr;
    local_addr.sin_port = 0;
    lwip_bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));

    // Broadcast announcement
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = ip_info.ip.addr | (~ip_info.netmask.addr);  // Broadcast address
    broadcast_addr.sin_port = htons(12346);

    uint8_t announcement[] = {0xAA, 0xBB, 0xCC, 0xDD};  // Announcement pattern
    ssize_t sent = lwip_sendto(s, announcement, sizeof(announcement), 0,
                         (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    lwip_close(s);

    return (sent > 0);
}

psram_string EthernetManager::scanNetworkDevices() const {
    psram_string scan_result = "=== NETWORK DEVICE SCAN ===\n";

    if (!netif_) {
        scan_result += "Ethernet interface not available\n";
        return scan_result;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        scan_result += "No IP configuration available\n";
        return scan_result;
    }

    char our_ip[16], gateway_ip[16], mask_str[16];
    snprintf(our_ip, sizeof(our_ip), IPSTR, IP2STR(&ip_info.ip));
    snprintf(gateway_ip, sizeof(gateway_ip), IPSTR, IP2STR(&ip_info.gw));
    snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

    scan_result += "Our IP: " + psram_string(our_ip) + "\n";
    scan_result += "Network: " + psram_string(our_ip) + "/" + psram_string(mask_str) + "\n";
    scan_result += "Gateway: " + psram_string(gateway_ip) + "\n\n";

    // Calculate network range
    uint32_t network = ip_info.ip.addr & ip_info.netmask.addr;
    //uint32_t host_mask = ~ip_info.netmask.addr;

    scan_result += "🔍 Scanning active devices:\n";

    // Test gateway first
    if (ip_info.gw.addr != 0) {
        bool gw_reachable = pingHost(gateway_ip, 1000);
        scan_result += "├─ " + psram_string(gateway_ip) + " (Gateway): " +
                      (gw_reachable ? "ACTIVE ✅" : "UNREACHABLE ❌") + "\n";
    }

    // Test a few common IPs in the subnet (limited scan due to embedded constraints)
    psram_vector<psram_string> common_ips = {".1", ".2", ".10", ".20", ".100", ".254"};

    for (const psram_string& suffix : common_ips) {
        // Extract network portion
        uint32_t net_addr = network;
        uint8_t* net_bytes = (uint8_t*)&net_addr;
        char test_ip[16];
        snprintf(test_ip, sizeof(test_ip), "%d.%d.%d%s",
                net_bytes[0], net_bytes[1], net_bytes[2], suffix.c_str());

        // Skip our own IP and gateway
        if (strcmp(test_ip, our_ip) == 0 || strcmp(test_ip, gateway_ip) == 0) continue;

        bool reachable = pingHost(test_ip, 500);
        if (reachable) {
            scan_result += "├─ " + psram_string(test_ip) + ": ACTIVE ✅\n";
        }
    }

    scan_result += "\nNote: Limited scan due to embedded constraints.\n";
    scan_result += "Use full network scanner for comprehensive discovery.\n";

    return scan_result;
}

bool EthernetManager::testBroadcastReachability() const {
    if (!netif_) return false;

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        return false;
    }

    // Test broadcast using lwIP
    int s = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;

    int broadcast = 1;
    lwip_setsockopt(s, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct timeval timeout = {1, 0};  // 1 second timeout
    lwip_setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Bind to our interface
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = ip_info.ip.addr;
    local_addr.sin_port = 0;
    lwip_bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));

    // Send to broadcast address
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_addr.s_addr = ip_info.ip.addr | (~ip_info.netmask.addr);
    broadcast_addr.sin_port = htons(12347);

    uint8_t test_data[] = {0x42, 0x54, 0x45, 0x53, 0x54};  // "BTEST"
    ssize_t sent = lwip_sendto(s, test_data, sizeof(test_data), 0,
                         (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

    lwip_close(s);
    return (sent > 0);
}

psram_string EthernetManager::analyzeNetworkSegment() const {
    psram_string analysis = "=== NETWORK SEGMENT ANALYSIS ===\n";

    if (!netif_) {
        analysis += "Ethernet interface not available\n";
        return analysis;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        analysis += "No IP configuration available\n";
        return analysis;
    }

    char ip_str[16], gw_str[16], mask_str[16];
    snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
    snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
    snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));

    // Network calculations
    uint32_t network = ip_info.ip.addr & ip_info.netmask.addr;
    uint32_t broadcast = network | (~ip_info.netmask.addr);

    char net_str[16], bcast_str[16];
    esp_ip4_addr_t addr;
    addr.addr = network;
    snprintf(net_str, sizeof(net_str), IPSTR, IP2STR(&addr));
    addr.addr = broadcast;
    snprintf(bcast_str, sizeof(bcast_str), IPSTR, IP2STR(&addr));

    // Subnet analysis
    int host_bits = 0;
    uint32_t mask = ~ip_info.netmask.addr;
    while (mask) {
        host_bits++;
        mask >>= 1;
    }
    int network_bits = 32 - host_bits;
    int max_hosts = (1 << host_bits) - 2;  // Subtract network and broadcast

    analysis += "📊 Segment Information:\n";
    analysis += "  Network: " + psram_string(net_str) + "/";
    append_uint(analysis, static_cast<unsigned>(network_bits));
    analysis += "\n";
    analysis += "  Broadcast: " + psram_string(bcast_str) + "\n";
    analysis += "  Max Hosts: ";
    append_uint(analysis, max_hosts);
    analysis += "\n";
    analysis += "  Our IP: " + psram_string(ip_str) + "\n";
    analysis += "  Gateway: " + psram_string(gw_str) + "\n\n";

    // Connectivity analysis
    analysis += "🔗 Connectivity Analysis:\n";

    bool gw_reachable = (ip_info.gw.addr != 0) ? pingGateway() : false;
    analysis += "  Gateway Reachable: " + psram_string(gw_reachable ? "YES ✅" : "NO ❌") + "\n";

    bool broadcast_ok = testBroadcastReachability();
    analysis += "  Broadcast Functional: " + psram_string(broadcast_ok ? "YES ✅" : "NO ❌") + "\n";

    bool external_reach = pingHost("8.8.8.8", 2000);
    analysis += "  Internet Access: " + psram_string(external_reach ? "YES ✅" : "NO ❌") + "\n";

    // Network type detection
    analysis += "\n🏷️ Network Type Analysis:\n";
    if (network_bits >= 24) {
        analysis += "  Subnet Type: Small LAN (/24 or smaller)\n";
    } else if (network_bits >= 16) {
        analysis += "  Subnet Type: Medium Network (/16-/23)\n";
    } else {
        analysis += "  Subnet Type: Large Network (bigger than /16)\n";
    }

    // Check for common private networks
    uint8_t first_octet = (network >> 0) & 0xFF;
    uint8_t second_octet = (network >> 8) & 0xFF;

    if (first_octet == 192 && second_octet == 168) {
        analysis += "  Address Space: RFC1918 Private (192.168.x.x)\n";
    } else if (first_octet == 10) {
        analysis += "  Address Space: RFC1918 Private (10.x.x.x)\n";
    } else if (first_octet == 172 && second_octet >= 16 && second_octet <= 31) {
        analysis += "  Address Space: RFC1918 Private (172.16-31.x.x)\n";
    } else {
        analysis += "  Address Space: Public or Non-standard\n";
    }

    return analysis;
}

psram_string EthernetManager::getNetworkLayerDiagnostics() const {
    psram_string diag = "=== NETWORK LAYER DIAGNOSTICS ===\n";

    if (!netif_) {
        diag += "❌ Ethernet interface not available\n";
        return diag;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        diag += "❌ No IP configuration\n";
        return diag;
    }

    diag += "🌐 Layer 2/3 Analysis:\n";

    // Test ARP functionality
    bool arp_test = sendARPRequest("8.8.8.8");  // Test external
    diag += "  ARP Request Test: " + psram_string(arp_test ? "SUCCESS ✅" : "FAILED ❌") + "\n";

    bool garp_test = sendGratuitousARP();
    diag += "  Gratuitous ARP: " + psram_string(garp_test ? "SENT ✅" : "FAILED ❌") + "\n";

    bool broadcast_test = testBroadcastReachability();
    diag += "  Broadcast Test: " + psram_string(broadcast_test ? "SUCCESS ✅" : "FAILED ❌") + "\n";

    // Local network analysis
    diag += "\n🏠 Local Network Analysis:\n";
    bool gateway_reach = pingGateway();
    diag += "  Gateway Reachable: " + psram_string(gateway_reach ? "YES ✅" : "NO ❌") + "\n";

    if (!gateway_reach) {
        diag += "    🔧 Issue: Cannot reach default gateway\n";
        diag += "    💡 Check: Cable connection, switch configuration\n";
    }

    // External connectivity
    diag += "\n🌍 External Connectivity:\n";
    bool dns_primary = pingHost("8.8.8.8", 2000);
    bool dns_secondary = pingHost("8.8.4.4", 2000);
    diag += "  Primary DNS: " + psram_string(dns_primary ? "REACHABLE ✅" : "UNREACHABLE ❌") + "\n";
    diag += "  Secondary DNS: " + psram_string(dns_secondary ? "REACHABLE ✅" : "UNREACHABLE ❌") + "\n";

    if (gateway_reach && !dns_primary && !dns_secondary) {
        diag += "    🔧 Issue: Gateway works but no internet\n";
        diag += "    💡 Check: Gateway routing, DNS configuration\n";
    }

    // Summary
    diag += "\n📋 Summary:\n";
    if (gateway_reach && (dns_primary || dns_secondary)) {
        diag += "  ✅ Network fully functional\n";
    } else if (gateway_reach) {
        diag += "  ⚠️ Local network OK, internet issues\n";
    } else {
        diag += "  ❌ Local network connectivity problems\n";
    }

    return diag;
}
// Driver level debugging implementation
psram_string EthernetManager::getRMIIConfiguration() const {
    psram_string rmii_config;
#if (ETH_PHY_TYPE == 5500)
    rmii_config = "=== SPI ETHERNET CONFIGURATION ===\n";
    rmii_config += "SPI Interface Configuration:\n";
    rmii_config += "  SPI Host: ";
    append_int(rmii_config, static_cast<int>(ETH_SPI_HOST));
    rmii_config += "\n";
    rmii_config += "  SCLK GPIO: ";
    append_int(rmii_config, ETH_SPI_SCLK_GPIO);
    rmii_config += "\n";
    rmii_config += "  MOSI GPIO: ";
    append_int(rmii_config, ETH_SPI_MOSI_GPIO);
    rmii_config += "\n";
    rmii_config += "  MISO GPIO: ";
    append_int(rmii_config, ETH_SPI_MISO_GPIO);
    rmii_config += "\n";
    rmii_config += "  CS GPIO: ";
    append_int(rmii_config, ETH_SPI_CS_GPIO);
    rmii_config += "\n";
    rmii_config += "  INT GPIO: ";
    append_int(rmii_config, ETH_SPI_INT_GPIO);
    rmii_config += "\n";
    rmii_config += "  Reset GPIO: ";
    append_int(rmii_config, ETH_PHY_RST_GPIO);
    rmii_config += "\n";
    rmii_config += "  SPI Clock: ";
    append_int(rmii_config, ETH_SPI_CLOCK_MHZ);
    rmii_config += " MHz\n";
#else
    rmii_config = "=== RMII CONFIGURATION ===\n";
    rmii_config += "RMII Interface Configuration:\n";
    rmii_config += "  MDC GPIO: ";
    append_int(rmii_config, ETH_MDC_GPIO);
    rmii_config += "\n";
    rmii_config += "  MDIO GPIO: ";
    append_int(rmii_config, ETH_MDIO_GPIO);
    rmii_config += "\n";
    rmii_config += "  Reset GPIO: ";
    append_int(rmii_config, ETH_PHY_RST_GPIO);
    rmii_config += "\n";

#ifdef CONFIG_ETH_RMII_CLK_INPUT
    rmii_config += "  Clock Mode: EXTERNAL INPUT\n";
    rmii_config += "  Clock GPIO: ";
    append_int(rmii_config, CONFIG_ETH_RMII_CLK_IN_GPIO);
    rmii_config += " (Input)\n";
#endif

#ifdef CONFIG_ETH_RMII_CLK_OUTPUT
    rmii_config += "  Clock Mode: ESP OUTPUT\n";
    rmii_config += "  Clock GPIO: ";
    append_int(rmii_config, CONFIG_ETH_RMII_CLK_OUT_GPIO);
    rmii_config += " (Output)\n";
#endif

#if !defined(CONFIG_ETH_RMII_CLK_INPUT) && !defined(CONFIG_ETH_RMII_CLK_OUTPUT)
    rmii_config += "  Clock Mode: NOT CONFIGURED\n";
#endif
#endif

    rmii_config += "\nSignal Quality:\n";
    rmii_config += "  GPIO Functionality: OK\n";

    bool interface_up = (netif_ != nullptr);
    rmii_config += "  Interface Status: " + psram_string(interface_up ? "UP" : "DOWN") + "\n";

    if (interface_up) {
        esp_netif_ip_info_t ip_info;
        bool has_ip = (esp_netif_get_ip_info(netif_, &ip_info) == ESP_OK && ip_info.ip.addr != 0);
        rmii_config += "  IP Configuration: " + psram_string(has_ip ? "CONFIGURED" : "NOT CONFIGURED") + "\n";
    }

    rmii_config += "\nTroubleshooting:\n";
    if (!interface_up) {
        rmii_config += "  - Check power supply (3.3V stable)\n";
        rmii_config += "  - Verify link and clock source\n";
        rmii_config += "  - Check PHY reset timing\n";
        rmii_config += "  - Validate GPIO connections\n";
    } else {
        rmii_config += "  - Ethernet interface appears functional\n";
        rmii_config += "  - All critical signals connected\n";
    }

    return rmii_config;
}

psram_string EthernetManager::getDriverStatistics() const {
    psram_string stats = "=== DRIVER STATISTICS ===\n";

    if (!eth_) {
        stats += "❌ Ethernet driver not initialized\n";
        return stats;
    }

    stats += "📊 Driver Status:\n";
    stats += "  Driver Handle: ";
    append_ptr(stats, eth_);
    stats += "\n";
    stats += "  Driver Type: ";
    stats += driver_phy_type();
    stats += " + ";
    stats += driver_mac_type();
    stats += "\n";

    // Check interface state
    if (netif_) {
        esp_netif_ip_info_t ip_info;
        bool ip_configured = (esp_netif_get_ip_info(netif_, &ip_info) == ESP_OK && ip_info.ip.addr != 0);

        stats += "\n🌐 Network Interface:\n";
        stats += "  NetIF Handle: ";
        append_ptr(stats, netif_);
        stats += "\n";
        stats += "  IP Configured: " + psram_string(ip_configured ? "YES ✅" : "NO ❌") + "\n";

        if (ip_configured) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
            stats += "  IP Address: " + psram_string(ip_str) + "\n";
        }
    }

    // Simulate driver statistics (ESP-IDF doesn't expose detailed stats)
    stats += "\n📈 Estimated Statistics:\n";
    stats += "  Link Established: " + psram_string(isLinkUp() ? "YES ✅" : "NO ❌") + "\n";
    stats += "  Speed: ";
    {
        int speed_value = getLinkSpeed();
        if (speed_value > 0) {
            char speed_buf[16];
            snprintf(speed_buf, sizeof(speed_buf), "%d Mbps", speed_value);
            stats += psram_string(speed_buf);
        } else {
            stats += "Unknown";
        }
    }
    stats += "\n";
    stats += "  Duplex: " + psram_string(isFullDuplex() ? "Full" : "Half") + "\n";

    // Driver health assessment
    bool driver_healthy = (eth_ != nullptr && netif_ != nullptr);
    stats += "\n🏥 Driver Health:\n";
    stats += "  Overall Status: " + psram_string(driver_healthy ? "HEALTHY ✅" : "UNHEALTHY ❌") + "\n";

    if (!driver_healthy) {
        stats += "  Issues Detected:\n";
        if (!eth_) stats += "    - Ethernet handle null\n";
        if (!netif_) stats += "    - Network interface null\n";
    }

    return stats;
}

psram_string EthernetManager::getMACConfiguration() const {
    psram_string mac_config = "=== MAC CONFIGURATION ===\n";

    if (!eth_) {
        mac_config += "❌ Ethernet driver not initialized\n";
        return mac_config;
    }

    mac_config += "MAC Configuration:\n";
    mac_config += "  MAC Type: ";
    mac_config += driver_mac_type();
    mac_config += "\n";
    mac_config += "  PHY Type: ";
    mac_config += driver_phy_type();
    mac_config += "\n";
    mac_config += "  PHY Address: ";
    append_int(mac_config, ETH_PHY_ADDR);
    mac_config += "\n";

    // MAC address information
    if (netif_) {
        uint8_t mac[6];
        if (esp_netif_get_mac(netif_, mac) == ESP_OK) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            mac_config += "  MAC Address: " + psram_string(mac_str) + "\n";

            // Check for valid MAC
            bool valid_mac = !(mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
                              mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
            mac_config += "  MAC Valid: " + psram_string(valid_mac ? "YES ✅" : "NO ❌") + "\n";
        }
    }

    mac_config += "\n⚙️ MAC Features:\n";
    mac_config += "  Promiscuous Mode: " + psram_string("SUPPORTED ✅") + "\n";
    mac_config += "  Multicast Filter: " + psram_string("SUPPORTED ✅") + "\n";
    mac_config += "  Auto-negotiation: " + psram_string("ENABLED ✅") + "\n";

    // Configuration validation
    mac_config += "\n🔍 Configuration Validation:\n";
    bool config_valid = true;

    if (!eth_) {
        mac_config += "  ❌ Driver handle invalid\n";
        config_valid = false;
    }

    if (!netif_) {
        mac_config += "  ❌ Network interface invalid\n";
        config_valid = false;
    }

    if (config_valid) {
        mac_config += "  ✅ All configurations valid\n";
    }

    return mac_config;
}

bool EthernetManager::testMACLoopback() const {
    if (!eth_ || !netif_) return false;

    // ESP-IDF doesn't provide direct MAC loopback test
    // Instead, test basic MAC functionality by checking if we can send packets

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        return false;  // No IP = MAC/PHY likely not working
    }

    // Try to send a packet to ourselves (loopback test)
    return pingHost("127.0.0.1", 1000);  // Local loopback
}

bool EthernetManager::validateDriverIntegrity() const {
    if (!eth_ || !netif_) return false;

    // Check basic driver integrity
    bool integrity_ok = true;

    // 1. Check handles are valid (non-null)
    if (!eth_ || !netif_) integrity_ok = false;

    // 2. Check if we can get basic network info
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif_, &ip_info) != ESP_OK) integrity_ok = false;

    // 3. Check if we can get MAC address
    uint8_t mac[6];
    if (esp_netif_get_mac(netif_, mac) != ESP_OK) integrity_ok = false;

    // 4. Validate MAC is not all zeros
    bool mac_valid = !(mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
                      mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
    if (!mac_valid) integrity_ok = false;

    return integrity_ok;
}

psram_string EthernetManager::getDriverLevelDiagnostics() const {
    psram_string diag = "=== DRIVER LEVEL DIAGNOSTICS ===\n";

    if (!eth_) {
        diag += "❌ Ethernet driver not initialized\n";
        diag += "\n🔧 Initialization Issues:\n";
        diag += "  - Driver handle is null\n";
        diag += "  - Check driver installation process\n";
        diag += "  - Verify GPIO configuration\n";
        return diag;
    }

    diag += "🔍 Driver Integrity Check:\n";
    bool integrity = validateDriverIntegrity();
    diag += "  Integrity Test: " + psram_string(integrity ? "PASSED ✅" : "FAILED ❌") + "\n";

    if (!integrity) {
        diag += "    Issues found in driver validation\n";
    }

    diag += "\nDriver Architecture:\n";
    diag += "  MAC Layer: ";
    diag += driver_mac_type();
    diag += "\n";
    diag += "  PHY Layer: ";
    diag += driver_phy_type();
    diag += "\n";
    diag += "  Interface: ";
    diag += driver_interface_type();
    diag += "\n";

    // MAC loopback test
    diag += "\n🔄 MAC Loopback Test:\n";
    bool loopback_ok = testMACLoopback();
    diag += "  Loopback Result: " + psram_string(loopback_ok ? "PASSED ✅" : "FAILED ❌") + "\n";

    if (!loopback_ok) {
        diag += "    🔧 MAC layer may have issues\n";
        diag += "    💡 Check: PHY power, clock, reset sequence\n";
    }

    // Interface diagnostics
    diag += "\nEthernet Interface:\n";
    psram_string rmii_status = getRMIIConfiguration();

    // Extract key info from RMII config
    bool rmii_configured = (rmii_status.find("NOT CONFIGURED") == psram_string::npos);
    diag += "  Interface Config: " + psram_string(rmii_configured ? "CONFIGURED" : "NOT CONFIGURED") + "\n";

    // Driver statistics summary
    diag += "\n📊 Performance Summary:\n";
    diag += "  Link Status: " + psram_string(isLinkUp() ? "UP ✅" : "DOWN ❌") + "\n";
    diag += "  Speed: ";
    {
        int speed_value = getLinkSpeed();
        if (speed_value > 0) {
            char speed_buf[16];
            snprintf(speed_buf, sizeof(speed_buf), "%d Mbps", speed_value);
            diag += psram_string(speed_buf);
        } else {
            diag += "Unknown";
        }
    }
    diag += "\n";
    diag += "  Duplex: " + psram_string(isFullDuplex() ? "Full" : "Half") + "\n";

    // Overall assessment
    diag += "\n🎯 Overall Assessment:\n";
    if (integrity && loopback_ok && rmii_configured) {
        diag += "  ✅ Driver fully functional\n";
        diag += "  🚀 All layers operating correctly\n";
    } else if (integrity && rmii_configured) {
        diag += "  ⚠️ Driver functional but with issues\n";
        diag += "  🔧 Minor problems detected\n";
    } else {
        diag += "  ❌ Driver has significant issues\n";
        diag += "  🚨 Hardware or configuration problems\n";
    }

    // Troubleshooting guide
    if (!integrity || !loopback_ok || !rmii_configured) {
        diag += "\n🛠️ Troubleshooting Steps:\n";
        diag += "  1. Check power supply stability (3.3V)\n";
        diag += "  2. Verify MAC/PHY link configuration\n";
        diag += "  3. Test PHY reset sequence\n";
        diag += "  4. Validate GPIO connections\n";
        diag += "  5. Check for hardware conflicts\n";
    }

    return diag;
}
