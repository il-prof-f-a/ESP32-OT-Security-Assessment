
#pragma once
#include "../core/psram_allocator.h"
#include "ethernet_tx_if.h"
#include <cstddef>
#include <cstdint>
extern "C" {
  #include "esp_netif.h"
  #include "esp_event.h"
  #include "esp_eth.h"
  #include "esp_eth_mac.h"
  #include "esp_eth_mac_spi.h"
  #include "esp_eth_phy.h"
  #include "esp_mac.h"
  #include "driver/gpio.h"
  #include "driver/spi_master.h"
  #include "lwip/ip4_addr.h"
  #include "freertos/FreeRTOS.h"
  #include "freertos/queue.h"
}

// Forward declarations
class ConfigurationManager;
class NetworkEngine;

// Board selection and hardware configuration
// Select via PlatformIO build_flags, e.g.:
//  -D BOARD_TPOE_PRO   or   -D BOARD_WAVESHARE_ESP32P4_ETH or -D BOARD_ESP32_S3_ETH

// Backward compatibility with existing flag
#if defined(LILYGO_T_ETH_POE_PRO) && !defined(BOARD_TPOE_PRO)
#define BOARD_TPOE_PRO 1
#endif

// Default pin/PHY configuration per board
	#if defined(BOARD_ESP32_S3_ETH)
	  // Waveshare ESP32-S3-ETH (ESP32-S3 + W5500 over SPI)
	  // Reference mapping:
	  //   MISO=GPIO12, MOSI=GPIO11, SCLK=GPIO13, CS=GPIO14, RST=GPIO9, INT=GPIO10
	  #ifndef ETH_PHY_TYPE
	    #define ETH_PHY_TYPE            5500  // W5500 integrated MAC+PHY
	  #endif
	  #ifndef ETH_PHY_RST_GPIO
	    #define ETH_PHY_RST_GPIO        9
	  #endif
	  #ifndef ETH_PHY_ADDR
	    #define ETH_PHY_ADDR            1
	  #endif
  #ifndef ETH_SPI_HOST
    #define ETH_SPI_HOST            SPI2_HOST
  #endif
	  #ifndef ETH_SPI_SCLK_GPIO
	    #define ETH_SPI_SCLK_GPIO       13
	  #endif
  #ifndef ETH_SPI_MOSI_GPIO
    #define ETH_SPI_MOSI_GPIO       11
  #endif
  #ifndef ETH_SPI_MISO_GPIO
    #define ETH_SPI_MISO_GPIO       12
  #endif
  #ifndef ETH_SPI_CS_GPIO
    #define ETH_SPI_CS_GPIO         14
  #endif
  #ifndef ETH_SPI_INT_GPIO
    #define ETH_SPI_INT_GPIO        10
  #endif
  #ifndef ETH_SPI_CLOCK_MHZ
    #define ETH_SPI_CLOCK_MHZ       20
  #endif

#elif defined(BOARD_WAVESHARE_ESP32P4_ETH)
  // Waveshare ESP32-P4-ETH (ESP32-P4 internal EMAC + IP101GRI PHY over RMII)
  // Pin mapping per Waveshare docs (ESP32-P4 family):
  //  TXD0/1: GPIO34/35, RXD0/1: GPIO30/29, TX_EN: GPIO49, CRS_DV: GPIO28
  //  REF_CLK: GPIO50 (50 MHz from PHY), MDIO: GPIO52, MDC: GPIO31, PHY RESET: GPIO51
  #ifndef ETH_PHY_ADDR
    #define ETH_PHY_ADDR            1
  #endif
  #ifndef ETH_PHY_RST_GPIO
    #define ETH_PHY_RST_GPIO        51
  #endif
  #ifndef ETH_MDC_GPIO
    #define ETH_MDC_GPIO            31
  #endif
  #ifndef ETH_MDIO_GPIO
    #define ETH_MDIO_GPIO           52
  #endif
  // External 50MHz REF_CLK input to MAC on GPIO50
  #ifndef ETH_RMII_CLK_MODE
    #define ETH_RMII_CLK_MODE       EMAC_CLK_EXT_IN
  #endif
  #ifndef ETH_RMII_CLK_GPIO
    #define ETH_RMII_CLK_GPIO       ((emac_rmii_clock_gpio_t)50)
  #endif
  #ifndef ETH_PHY_TYPE
    #define ETH_PHY_TYPE            101  // 8720=LAN8720, 101=IP101, 83848=DP83848, 8201=RTL8201
  #endif
  #ifndef ETH_RMII_TX_EN_GPIO
    #define ETH_RMII_TX_EN_GPIO      49
  #endif
  #ifndef ETH_RMII_TXD0_GPIO
    #define ETH_RMII_TXD0_GPIO       34
  #endif
  #ifndef ETH_RMII_TXD1_GPIO
    #define ETH_RMII_TXD1_GPIO       35
  #endif
  #ifndef ETH_RMII_CRS_DV_GPIO
    #define ETH_RMII_CRS_DV_GPIO     28
  #endif
  #ifndef ETH_RMII_RXD0_GPIO
    #define ETH_RMII_RXD0_GPIO       29
  #endif
  #ifndef ETH_RMII_RXD1_GPIO
    #define ETH_RMII_RXD1_GPIO       30
  #endif

#elif defined(BOARD_TPOE_PRO)
  // LilyGO T-POE Pro (ESP32 internal EMAC + LAN8720)
  #ifndef ETH_PHY_ADDR
    #define ETH_PHY_ADDR            0
  #endif
  #ifndef ETH_PHY_RST_GPIO
    #define ETH_PHY_RST_GPIO        5
  #endif
  #ifndef ETH_MDC_GPIO
    #define ETH_MDC_GPIO           23
  #endif
  #ifndef ETH_MDIO_GPIO
    #define ETH_MDIO_GPIO          18
  #endif
  #ifndef ETH_RMII_CLK_MODE
    #define ETH_RMII_CLK_MODE      EMAC_CLK_OUT
  #endif
  #ifndef ETH_RMII_CLK_GPIO
    #define ETH_RMII_CLK_GPIO      (emac_rmii_clock_gpio_t)0  // GPIO0 outputs 50MHz REF_CLK
  #endif
  #ifndef ETH_PHY_TYPE
    #define ETH_PHY_TYPE           8720
  #endif

#else
  // Generic defaults (LAN8720 on classic ESP32 dev)
  #ifndef ETH_PHY_ADDR
    #define ETH_PHY_ADDR            0
  #endif
  #ifndef ETH_PHY_RST_GPIO
    #define ETH_PHY_RST_GPIO       (-1)
  #endif
  #ifndef ETH_MDC_GPIO
    #define ETH_MDC_GPIO           23
  #endif
  #ifndef ETH_MDIO_GPIO
    #define ETH_MDIO_GPIO          18
  #endif
  #ifndef ETH_RMII_CLK_MODE
    #define ETH_RMII_CLK_MODE      EMAC_CLK_EXT_IN
  #endif
  #ifndef ETH_RMII_CLK_GPIO
    #define ETH_RMII_CLK_GPIO      (emac_rmii_clock_gpio_t)0
  #endif
  #ifndef ETH_PHY_TYPE
    #define ETH_PHY_TYPE           8720
  #endif
#endif

// Promiscuous mode commands fallback
#ifndef ETH_CMD_S_PROMISCUOUS
  #define ETH_CMD_S_PROMISCUOUS   (esp_eth_io_cmd_t)0x10
#endif
#ifndef ETH_CMD_G_PROMISCUOUS
  #define ETH_CMD_G_PROMISCUOUS   (esp_eth_io_cmd_t)0x11
#endif

// L2 packet structure for queue
#define SNIFF_COPY_BYTES 128      // bytes to copy for logging
#define SNIFF_QUEUE_LEN   32      // frames in queue

typedef struct {
  uint32_t len;
  uint16_t ethertype;
  uint8_t  dst[6];
  uint8_t  src[6];
  uint8_t  data[SNIFF_COPY_BYTES];
} l2_snap_t;

// Global queue for L2 packet capture (accessed by callback)
 extern QueueHandle_t g_l2_queue_global;

class EthernetManager : public EthernetTxIf {
public:
    // Constructor with ConfigurationManager dependency injection
    explicit EthernetManager(ConfigurationManager* cfg = nullptr);
    ~EthernetManager() { stop(); }

    // High-level method to initialize Ethernet with automatic configuration
    bool initializeFromConfig();

    // Legacy methods (kept for compatibility)
    bool setPromiscuous(bool en);
    bool enableAllMulticast(bool en);
    bool start();
    void stop();

    esp_netif_t* netif() const { return netif_; }
    esp_eth_handle_t handle() const { return eth_; }

    // EthernetTxIf (raw L2 transmit) - used by protocols like PROFINET DCP
    bool rawTx(const uint8_t* frame, size_t len) override;
    bool getMac(uint8_t out6[6]) override;

    // Static event handlers for ESP-IDF callbacks
    static void onEthEventStatic(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);
    static void onEthGotIPStatic(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data);

    // Static L2 logger task
    // l2LoggerTaskStatic moved to main.cpp for better separation of concerns

    // Network info
    psram_string getIP() const;
    bool getIP(char* out, size_t out_sz) const;

    // Status methods for checking current state
    bool hasValidIP() const;
    bool isConfiguredFromConfig() const { return config_ != nullptr; }

    // Hardware diagnostics
    bool isLinkUp() const;
    int getLinkSpeed() const;  // Returns 10, 100, or -1 if unknown
    bool isFullDuplex() const;
    bool readPHYRegister(uint32_t reg, uint32_t* value) const;
    psram_string getPHYStatus() const;
    psram_string getHardwareDiagnostics() const;

    // IP stack debugging
    bool pingGateway() const;
    bool pingHost(const char* host, int timeout_ms = 3000) const;
    psram_string getRoutingTable() const;
    psram_string getARPTable() const;
    psram_string getIPStackDiagnostics() const;

    // Network layer analysis tools
    bool sendARPRequest(const char* target_ip) const;
    bool sendGratuitousARP() const;
    psram_string scanNetworkDevices() const;
    bool testBroadcastReachability() const;
    psram_string analyzeNetworkSegment() const;
    psram_string getNetworkLayerDiagnostics() const;

    // Driver level debugging
    psram_string getRMIIConfiguration() const;
    psram_string getDriverStatistics() const;
    psram_string getMACConfiguration() const;
    bool testMACLoopback() const;
    bool validateDriverIntegrity() const;
    psram_string getDriverLevelDiagnostics() const;

    // L2 sniffer callback for promiscuous packet capture
    static esp_err_t input_trampoline(esp_eth_handle_t hdl, uint8_t* buffer, uint32_t length, void* priv);

private:
    esp_netif_t* netif_ = nullptr;
    esp_eth_handle_t eth_ = nullptr;
    ConfigurationManager* config_ = nullptr;
    bool events_registered_ = false;

    // Internal methods
    bool setupMAC_PHY(esp_eth_mac_t** out_mac, esp_eth_phy_t** out_phy);
    bool configureStaticIP(const psram_string& ip, const psram_string& gateway, const psram_string& netmask);
    bool enablePromiscuousMode(bool enable);
    bool configureNetworkFromParsed(bool use_dhcp, const psram_string& ip, const psram_string& gateway, const psram_string& netmask);

    // Configuration parsing methods
    bool parseEthernetConfig(bool& enabled, bool& use_dhcp, bool& promiscuous, psram_string& ip, psram_string& gateway, psram_string& netmask);
    bool configureNetworkFromConfig();

    // Utility methods
    static psram_string bytesToHex(const uint8_t* p, size_t n);
    static void hexdump(const uint8_t* p, size_t n);

    static const char* ethertypeName(uint16_t et) {
        switch (et) {
            case 0x0800: return "IPv4";
            case 0x0806: return "ARP";
            case 0x86DD: return "IPv6";
            case 0x8100: return "802.1Q";
            case 0x8892: return "PROFINET DCP";
            case 0x88CC: return "LLDP";
            case 0x8899: return "Realtek L2 (RRCP/RLDP/tag)"; // <—
            default:     return "UNK";
        }
    }

};
