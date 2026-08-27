# ESP32-C6 Wi-Fi Coprocessor

The experimental Guition `JC-ESP32P4-M3-DEV` target uses its ESP32-C6 as a
remote Wi-Fi radio. The ESP32-P4 application and the ESP32-C6 coprocessor are
separate firmware images and must be built and flashed separately.

This project pins ESP-Hosted `3.0.6`, uses the RPC v2 protocol, and selects the
SDIO software-aggregation transport expected by the P4 host firmware. The C6
SDIO pins are fixed by the silicon: CMD 18, CLK 19, D0 20, D1 21, D2 22, and
D3 23. These are not the GPIO numbers used on the P4 side of the same bus.

Build from the repository root:

```powershell
./scripts/build_c6_coprocessor.ps1
```

The script prints the artifact directory. Use an explicit C6 serial port when
flashing; never assume that the P4 and C6 expose the same programming port.

```powershell
./scripts/build_c6_coprocessor.ps1 -Port COM12 -Upload -Monitor
```

## GUITION C6 UART wiring and power safety

For the tested `JC-ESP32P4-M3-DEV` board, power and program the P4 through the USB port nearest
the RJ45 connector. Connect the CH340-class UART adapter to the C6 header only as follows:

| Adapter | C6-labelled board pin |
| --- | --- |
| TXD | `C6_U0RXD` |
| RXD | `C6_U0TXD` |
| GND | GND |

**Do not connect the adapter's 3.3 V, 5 V or VCC pin.** The board is powered from the P4 USB
connection; a second supply can back-power and damage USB circuitry or either board.

Initial C6 Wi-Fi operation has passed on the laboratory board. Do not flash this image to the P4.
The target still requires broader network, recovery and soak testing before it can be considered
production-ready.
