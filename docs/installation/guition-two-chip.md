# GUITION two-chip build and flashing

The `guition-jc-esp32p4-m3-dev` target contains two independently programmable chips. The ESP32-P4 application and ESP32-C6 ESP-Hosted firmware use different chip identifiers, binaries and serial connections. Never guess which port belongs to which chip.

## Build both images

From the repository root:

```powershell
pio run -e guition-jc-esp32p4-m3-dev
./scripts/build_c6_coprocessor.ps1
```

The P4 target uses 16 MB flash. The C6 project pins ESP-Hosted `3.0.6`, ESP-IDF `5.5.3`, RPC v2 and a 4 MB flash profile.

## Identify the ports

Disconnect the board, list serial ports, connect only the P4 programming USB interface and record the new port. Repeat for the C6 programming interface. Stop if the C6 programming pins or USB bridge cannot be identified from the exact PCB revision.

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

## Recovery

1. Put only the intended chip into its ROM download mode.
2. Confirm the command says `esp32p4` for the P4 or `esp32c6` for the C6.
3. Flash the board-specific factory image from the release manifest.
4. Power-cycle both chips and capture the complete serial boot log.

The Guition target remains experimental until Ethernet, remote Wi-Fi, management isolation, reconnect behavior and soak testing pass on real hardware.
