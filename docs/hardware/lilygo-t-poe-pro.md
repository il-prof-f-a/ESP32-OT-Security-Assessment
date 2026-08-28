# LILYGO T-POE Pro

> Status: **experimental, initially hardware-validated**. The firmware starts and operates in the current laboratory tests. HTTPS is not stable on this target, so the management server is deliberately **HTTP only**. Do not use its management path where confidentiality or integrity of browser traffic is required.

![LILYGO T-POE Pro](../assets/hardware/lilygo-t-poe-pro-photo.jpg)

## Hardware summary

| Property               | Documented value                                    | Project relevance                                                                                                                                 |
| ---------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Module                 | ESP32-WROVER-E                                      | Classic ESP32 target compiled with ESP-IDF.                                                                                                       |
| CPU                    | Dual-core 32-bit Xtensa LX6, up to 240 MHz          | Suitable for the current protocol and web-management feature set.                                                                                 |
| SoC GPIO               | 34                                                  | This is not the number of free header pins. Ethernet, PSRAM, boot straps and module functions constrain usable pins.                              |
| Internal memory / IRAM | 520 KB shared internal SRAM                         | The exact IRAM/DRAM split and free IRAM are build-dependent; record them with benchmark telemetry rather than treating 520 KB as executable IRAM. |
| PSRAM                  | 8 MB                                                | Enabled by the board profile for larger runtime allocations.                                                                                      |
| Flash                  | 16 MB                                               | The public profile uses the project partition table.                                                                                              |
| Ethernet               | LAN8720, 10/100 Mbit/s RMII                         | Used exclusively for assessment, discovery and IDS traffic.                                                                                       |
| Wi-Fi / BLE            | 2.4 GHz 802.11 b/g/n; Bluetooth 4.2                 | Wi-Fi is the intended management path, subject to the HTTP-only limitation.                                                                       |
| Power                  | 5 V PoE module, IEEE 802.3af/at input range 44–57 V | Useful for lab placement near an OT switch; verify the actual PoE hardware revision.                                                              |
| SD expansion           | No onboard SD/TF slot confirmed                     | External SD wiring is possible only after a pin-conflict and electrical review. It is not supported by the firmware.                              |

## Project wiring and network policy

![LILYGO T-POE Pro pinout](../assets/hardware/lilygo-t-poe-pro-pinout.jpg)

| Function             | GPIO | Firmware role             |
| -------------------- | ----:| ------------------------- |
| LAN8720 reset        | 5    | Ethernet PHY reset        |
| RMII MDC             | 23   | Ethernet management clock |
| RMII MDIO            | 18   | Ethernet management data  |
| RMII reference clock | 0    | Clock output to the PHY   |

The firmware binds assessment, discovery, fuzzing and IDS traffic to Ethernet. Management is Wi-Fi-only in policy and must not fall back to Ethernet. The server is started only on a non-overlapping Wi-Fi IPv4 network, but this target remains unsuitable for a confidential management network because it uses HTTP. See [network isolation and residual exposure](../security/network-isolation.md).

## Photos, documents and purchase

- [LILYGO product page and official purchase link](https://lilygo.cc/products/t-poe-pro)
- [LILYGO T-ETH-Series pin maps and schematics](https://github.com/Xinyuan-LilyGO/LilyGO-T-ETH-Series)
- [Image attribution](../assets/hardware/SOURCES.md)

Check the module marking, LAN8720 wiring and PoE revision before flashing. Board revisions and seller listings can differ from the test board.

## Benchmark record

No comparable benchmark has been published for this target yet. Do not infer packet-processing throughput from CPU frequency or dashboard counters.

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

The future telemetry record must identify the firmware revision, capture period and measurement method, and distinguish received packets from packets accepted by the analysis pipeline. It must also capture queue drops and memory low-water marks. This makes results repeatable across boards and prevents a high UI counter from being mistaken for lossless inspection.
