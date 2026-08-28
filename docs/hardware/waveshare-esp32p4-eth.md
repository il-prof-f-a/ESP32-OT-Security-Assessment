# Waveshare ESP32-P4-ETH

> Status: **experimental, initially hardware-validated**. This is the strongest current functional result, but ESP32-P4 has no integrated Wi-Fi. The management UI and OT assessment interface therefore use the same Ethernet subnet, which does not meet the preferred management/OT separation requirement.

![Waveshare ESP32-P4-ETH](../assets/hardware/waveshare-esp32-p4-eth-photo.jpg)

## Hardware summary

| Property                     | Documented value                                                                      | Project relevance                                                                                                                                |
| ---------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Processor                    | Dual-core 32-bit RISC-V HP system, up to 360 MHz; single-core LP system, up to 40 MHz | Higher-performance P4 profile built with the pinned ESP32-P4-capable toolchain.                                                                  |
| SoC GPIO / expansion         | 55 SoC GPIO; 27 remaining programmable pins on the board headers                      | Ethernet, SD/MMC and board functions consume pins; check the pinout before assigning GPIO alerts or interlocks.                                  |
| Internal memory / IRAM model | 768 KB HP L2 memory, 32 KB LP SRAM and 8 KB TCM                                       | P4 executable/internal-memory availability depends on cache and build configuration. Report measured IRAM/DRAM rather than a static “IRAM size”. |
| PSRAM / flash                | 32 MB PSRAM / 32 MB NOR flash                                                         | The board profile enables PSRAM and the 32 MB flash layout.                                                                                      |
| Ethernet                     | IP101GRI RMII PHY, 10/100 Mbit/s                                                      | The only management and assessment network path on this target.                                                                                  |
| Wireless                     | No integrated Wi-Fi                                                                   | This is the reason for the Ethernet management exception.                                                                                        |
| Storage expansion            | Onboard TF card slot, SDIO 3.0                                                        | Hardware is present, but no SD logging or encrypted configuration support is implemented yet.                                                    |
| Other board resources        | USB 2.0 OTG, MIPI CSI/DSI, audio, 40-pin headers                                      | Not enabled by the current security-assessment firmware.                                                                                         |

## Project wiring and network policy

![Waveshare ESP32-P4-ETH pinout](../assets/hardware/waveshare-esp32-p4-eth-pinout.jpg)

| Function             | GPIO | Firmware role                     |
| -------------------- | ----:| --------------------------------- |
| IP101 reset          | 51   | Ethernet PHY reset/enable         |
| RMII MDC             | 31   | Ethernet management clock         |
| RMII MDIO            | 52   | Ethernet management data          |
| RMII reference clock | 50   | External Ethernet reference clock |

The board uses HTTPS with a per-device self-signed certificate, but it has no separate management transport. Keep the device in a controlled OT test subnet, or place it behind an external firewall or VLAN boundary. See [network isolation and residual exposure](../security/network-isolation.md).

## Photos, documents and purchase

- [Official Waveshare wiki and pinout](https://www.waveshare.com/wiki/ESP32-P4-ETH)
- [Manufacturer product page and purchase link](https://www.waveshare.com/esp32-p4-eth.htm)
- [Image attribution](../assets/hardware/SOURCES.md)

The public PlatformIO profile targets pre-v3 P4 silicon and pins the toolchain revision used for testing. Verify the chip revision and installed flash size before building a factory image.

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

Benchmark telemetry must identify whether management traffic was present on the same link, the Ethernet link state and the exact memory configuration. Results must separately report packets received, packets accepted by the analysis pipeline and packets dropped before/inside that pipeline.
