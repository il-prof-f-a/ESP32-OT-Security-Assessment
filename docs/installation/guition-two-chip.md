# GUITION two-chip build and flashing

The `guition-jc-esp32p4-m3-dev` target contains two independently programmable chips. The ESP32-P4 application and ESP32-C6 ESP-Hosted firmware use different chip identifiers, binaries and serial connections. Never guess which port belongs to which chip. Both images must be flashed for Wi-Fi management to work.

## Build both images

From the repository root:

```powershell
pio run -e guition-jc-esp32p4-m3-dev
./scripts/build_c6_coprocessor.ps1
```

The P4 target uses 16 MB flash. The C6 project pins ESP-Hosted `3.0.6`, ESP-IDF `5.5.3`, RPC v2 and a 4 MB flash profile.

## Connect the programming interfaces safely

Use the two connections simultaneously, with separate COM ports:

- **P4 and board power:** connect the **first USB port nearest the RJ45 Ethernet connector** to the
  host. This is the P4 programming connection and it supplies the board.
- **C6 programming UART:** connect a CH340-class USB-to-UART adapter to the C6-labelled pins:

  | CH340 adapter pin | Board pin | Required action |
  | --- | --- | --- |
  | TXD | `C6_U0RXD` | Connect (crossed UART TX/RX) |
  | RXD | `C6_U0TXD` | Connect (crossed UART TX/RX) |
  | GND | GND | Connect |
  | 3.3 V / VCC | — | **Do not connect** |
  | 5 V / VCC | — | **Do not connect** |

> **Electrical safety warning:** do not connect either CH340 power output. The P4 USB already
> powers the board; connecting 3.3 V or 5 V from the adapter can back-power the USB circuit and can
> damage the computer USB port, CH340 adapter or board.

The board labels needed for this connection are shown below.

![GUITION C6 UART and boot-control header labels](../assets/hardware/guition-jc-esp32p4-m3-dev-c6-uart-pinout.jpg)

Disconnect the board, list serial ports, connect only the P4 USB and record its port. Then connect
the CH340 adapter and record its distinct C6 port. The guarded workflow refuses to use one port for
both chips.

The guarded workflow refuses to use one port for both chips:

```powershell
./scripts/guition_two_chip.ps1 -P4Port COM10 -C6Port COM12 -FlashC6 -FlashP4
```

You can flash one chip at a time:

```powershell
./scripts/build_c6_coprocessor.ps1 -Port COM12 -Upload -Monitor
python scripts/flash_esptool.py --target guition-jc-esp32p4-m3-dev --port COM10
```

Release manifests contain the authoritative offsets and SHA-256 checksums. The Guition release is rejected during packaging if the matching C6 build is missing.

## C6 download mode

Normally the C6 uploader resets the coprocessor automatically. If it cannot connect, use the
board's exposed controls: hold `C6_IO9` at GND, pull `C6_CHIP_PU` low and release it, start the
upload, then release `C6_IO9` after the serial tool connects. Keep the CH340 power pins
disconnected throughout this procedure.

## Recovery

1. Put only the intended chip into its ROM download mode.
2. Confirm the command says `esp32p4` for the P4 or `esp32c6` for the C6.
3. Flash the board-specific factory image from the release manifest.
4. Power-cycle both chips and capture the complete serial boot log.

Initial Ethernet, remote Wi-Fi, management-isolation and provisioning checks have passed on the
laboratory board. The Guition target remains experimental until broader network compatibility,
reconnect behavior, failure recovery and soak testing pass on real hardware.
