# Waveshare ESP32-S3-ETH

> Status: **experimental, partially hardware-validated**. The current firmware is functional on a limited set of tested networks. Broader network compatibility and sustained-load testing remain open.

![Waveshare ESP32-S3-ETH](../assets/hardware/waveshare-esp32-s3-eth-photo.jpg)

## Hardware summary

| Property               | Documented value                                   | Project relevance                                                                                                                   |
| ---------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Module                 | ESP32-S3R8                                         | ESP-IDF target with Wi-Fi and SPI Ethernet.                                                                                         |
| CPU                    | Dual-core 32-bit Xtensa LX7, up to 240 MHz         | Provides the management and protocol-processing cores.                                                                              |
| SoC GPIO               | 45                                                 | Actual available pins are reduced by the W5500, flash/PSRAM and onboard functions.                                                  |
| Internal memory / IRAM | 512 KB shared internal SRAM                        | ESP-IDF can allocate the shared pool between IRAM and DRAM; benchmark records must report the build-specific free IRAM/DRAM result. |
| PSRAM                  | 8 MB                                               | Available to the firmware for suitable dynamic allocations.                                                                         |
| Flash                  | 16 MB                                              | Used with the project partition table.                                                                                              |
| Ethernet               | W5500 SPI Ethernet, 10/100 Mbit/s                  | The dedicated OT assessment interface.                                                                                              |
| Wireless               | 2.4 GHz Wi-Fi and Bluetooth 5 LE                   | Wi-Fi is the management interface.                                                                                                  |
| Storage expansion      | Onboard TF card slot                               | Hardware is present, but SD logging/configuration support is not yet implemented.                                                   |
| Physical integration   | No native 24 V input; no GPIO screw-terminal block | Consider external power conversion and field wiring before industrial installation.                                                 |

## Project wiring and network policy

![Waveshare ESP32-S3-ETH pinout](../assets/hardware/waveshare-esp32-s3-eth-pinout.png)

| Function               | GPIO         | Firmware role                 |
| ---------------------- | ------------:| ----------------------------- |
| W5500 reset            | 9            | Ethernet-controller reset     |
| W5500 interrupt        | 10           | Ethernet-controller interrupt |
| SPI MOSI / MISO / SCLK | 11 / 12 / 13 | W5500 SPI data and clock      |
| W5500 chip select      | 14           | W5500 SPI select              |

Assessment, discovery, fuzzing and IDS traffic use Ethernet only. The management UI is Wi-Fi-only and uses a per-device self-signed HTTPS certificate. The firmware blocks management when the Wi-Fi and Ethernet IPv4 networks overlap. This is application-level isolation, not a substitute for a VLAN or firewall ACL; see [network isolation and residual exposure](../security/network-isolation.md) and the [offensive-testing interlock](../security/offensive-testing-interlock.md).

## Photos, documents and purchase

- [Official Waveshare wiki and pinout](https://www.waveshare.com/wiki/ESP32-S3-ETH)
- [Manufacturer product page and purchase link](https://www.waveshare.com/esp32-s3-eth.htm)
- [Image attribution](../assets/hardware/SOURCES.md)

The board offers a camera connector, Pico-compatible expansion and optional PoE hardware. None of those peripherals is enabled by this firmware unless explicitly stated in a future board profile.

## Benchmark record

No comparable benchmark has been published for this target yet.

| Required field                             | Current record |
| ------------------------------------------ | -------------- |
| Firmware release and git commit            | Not measured   |
| Test topology and Ethernet link            | Not measured   |
| Number of emulated/observed OT nodes       | Not measured   |
| Offered network load and packet mix        | Not measured   |
| Analysed packets per second and drop rate  | Not measured   |
| Detection/reporting configuration          | Not measured   |
| p50/p95 processing latency                 | Not measured   |
| Free/minimum internal DRAM, IRAM and PSRAM | Not measured   |

A valid record must include W5500 link settings, Wi-Fi-management state, protocol mix, queue drops and memory low-water marks. The planned telemetry must be collected over a fixed capture interval and exported with the firmware revision so boards and releases can be compared honestly.
