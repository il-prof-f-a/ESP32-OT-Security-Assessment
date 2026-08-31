# Network Diagnostics — Phased Troubleshooting

![Phased Network Diagnostics page](assets/diagnostics.png)

This page runs structured Ethernet troubleshooting. Its current text is oriented toward T-POE Pro,
but the returned data depends on the selected board and driver.

## Phase 1: Hardware Diagnostics

**Run Hardware Diagnostics** reads hardware-level information such as PHY registers, link status
and low-level connectivity. Use it first when Ethernet does not establish link.

## Phase 2: IP Stack Debugging

**Run IP Stack Diagnostics** inspects IP-layer state such as addresses, routing, ARP and reachability
tests. Run it after physical link is present but communication still fails.

## Phase 3: Network Layer Analysis

**Run Network Analysis** collects discovery/ARP/broadcast information. **Scan Type** selects Device
Discovery or Segment Analysis, and **Network Scan** starts the selected operation. These functions
generate traffic and should be used only on an authorized segment.

## Phase 4: Driver Level Debugging

**Run Driver Diagnostics** reports driver and interface internals useful when hardware and IP
results disagree or the interface repeatedly resets.

## Quick Actions and summary

- **Run All Diagnostics** executes the phases as a combined troubleshooting sequence.
- **Clear Results** clears the displayed diagnostic output.
- **Export Results** downloads the collected data. It may contain internal network topology and
  should be treated as sensitive.
- **Diagnostics Summary** condenses phase outcomes into status indicators; inspect each phase's
  raw detail before drawing a conclusion.

Diagnostics observe and probe the interface but do not repair cabling, power, PHY configuration or
network policy. Use serial boot logs and the board schematic alongside these results.

## Crash diagnostics at the next boot

The firmware captures the reset reason immediately at startup, then waits until NVS and the
asynchronous storage engine are initialized before reading any persistent crash metadata. This
ordering is important: storage reads are not valid during the earliest boot phase.

All supported firmware profiles enable the native ESP-IDF panic handler with an ELF coredump stored
in the dedicated `coredump` flash partition. The application does not replace that emergency path
with a custom handler: panic code must not allocate memory, wait for an asynchronous task, or write
through the normal storage queue. On the next boot, an abnormal reset causes the serial log to
report whether the coredump image passed its CRC check and, when available, its native panic reason.

Expected messages include:

- `ABNORMAL RESTART DETECTED: ...` — reset reason reported by the ROM/ESP-IDF reset API.
- `Previous ESP-IDF coredump image is valid` — a recoverable coredump was found in flash.
- `No previous coredump image found` — the partition is empty (for example after first boot or
  after the image was erased).
- `Previous coredump image failed integrity check: ...` — the image is present but must not be
  decoded as trustworthy data.

To decode a downloaded flash image offline, use the matching ESP-IDF toolchain and application ELF
file, for example `idf.py coredump-info -coredump-file <raw-coredump.bin>`. Keep coredumps private:
registers, stack contents and application data may contain
network topology or credentials. The 64 KiB partition is a bounded diagnostic area; it is not a
general log store and is not erased automatically during normal boot.

[Back to the guide index](README.md)
