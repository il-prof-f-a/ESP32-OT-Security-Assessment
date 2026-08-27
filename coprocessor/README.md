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

The 4 MB C6 flash profile and the board interconnect remain provisional until
they are verified on the purchased PCB revision. Do not flash this image to the
P4, and do not describe the Guition target as tested until the physical
validation matrix has passed.
