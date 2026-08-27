# GUITION JC-ESP32P4-M3-DEV

> Status: **experimental, build-validated only**. The target has not completed the physical validation matrix on the purchased PCB revision.

![GUITION JC-ESP32P4-M3-DEV](../assets/hardware/guition-jc-esp32p4-m3-dev-photo.webp)

The board combines an ESP32-P4, 32 MB package PSRAM, 16 MB NOR flash, an IP101 100 Mbit/s Ethernet PHY, and an ESP32-C6 radio connected through SDIO. In this project the P4 runs the security-assessment firmware while the C6 runs the pinned ESP-Hosted `3.0.6` coprocessor image.

![Network pinout used by the firmware](../assets/hardware/guition-jc-esp32p4-m3-dev-network-pinout.svg)

| Function | P4 GPIO | Firmware role |
| --- | ---: | --- |
| IP101 MDC | 31 | Ethernet management data clock |
| IP101 MDIO | 52 | Ethernet management data |
| IP101 power/reset | 51 | PHY enable/reset |
| RMII external clock | 50 | Ethernet reference clock |
| C6 reset | 54 | ESP-Hosted coprocessor reset |
| C6 SDIO CMD / CLK | 19 / 18 | Remote Wi-Fi command and clock |
| C6 SDIO D0–D3 | 14 / 15 / 16 / 17 | Remote Wi-Fi data bus |

The C6-side SDIO GPIO numbers differ from the P4-side numbers. Do not transpose them when building or debugging the coprocessor image.

## Network policy

- Assessment, discovery, fuzzing and IDS traffic is bound to `ETH_DEF` and fails closed when Ethernet has no address.
- Management is Wi-Fi-only through the ESP32-C6. The firmware does not fall back to Ethernet.
- Management is blocked when the Wi-Fi and Ethernet IPv4 ranges overlap.
- The HTTPS connection gate checks the accepted socket's local destination address. This prevents an application request through Ethernet, but the underlying wildcard listener may still answer a TCP SYN; see [Network isolation and residual exposure](../security/network-isolation.md).

## References and purchasing

- [GUITION manufacturer product page](https://www.guition.com/esp32p4-display-module/esp32p4-display-module)
- [GUITION English specification PDF](https://www.guition.com/icms/upload/fb081940d6fc11f09850077a33e1404f/file/productmanager-productfile/1d8749eb4c444726b7b85189aee66af3/Directory/JC-ESP32P4-M3-DEV%20Specifications-EN_1776241973799.pdf)
- [Community pinout and configuration reference](https://devices.esphome.io/devices/guition-esp32-p4-m3-dev/)
- [Purchase listing for the documented model](https://www.aliexpress.com/item/1005009511796128.html)

Seller listings and PCB revisions can change without notice. Compare the silkscreen, flash size, PHY and SDIO wiring before flashing.
