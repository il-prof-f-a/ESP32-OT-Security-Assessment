# Offensive testing interlock

The offensive-testing policy is a two-part authorization gate for state-changing or disruptive assessment operations. An operation is allowed only when both conditions are true:

1. the software policy is enabled and persisted by an authenticated administrator; and
2. the configured physical GPIO interlock is asserted (when the gate is required).

The policy fails closed. A missing `SecurityManager`, invalid GPIO, corrupt policy record, open contact or failed NVS write blocks the operation. The gate is re-evaluated immediately before every unsafe fuzz case and by protocol-specific active probes.

This policy is different from IDS `allowed_writers`: `allowed_writers` identifies traffic sources that IDS may classify as authorized writers, while this interlock authorizes the assessment appliance itself to transmit active tests. It is also different from job **Safe Mode**: Safe Mode keeps a job read-only; disabling Safe Mode does not bypass the global policy.

## Enabling the policy

Open **Security → Fuzzing & Testing Controls** or the **Scanner & Fuzzing** controls. Enabling the software switch requires the administrator password. A required physical gate remains ineffective while its contact is open. Disabling the switch takes effect immediately and is persisted.

The API exposes the effective state, reason, source (`config_seed`, `nvs`, `force_config`, or a fail-closed state), selected GPIO and GPIO assertion state through `/api/security/config`. Passwords are never returned or logged.

## Board wiring

The public build selects one default input per board. The input is active-low with an internal pull-up: leave the contact open for **OFF** and connect the selected GPIO directly to an adjacent board GND for **ON**. Use a dry contact or jumper only; do not inject an external voltage into the input.

| Board | Default GPIO | Wiring note |
| --- | ---: | --- |
| LILYGO T-POE Pro | 15 | GPIO15 is a boot-strapping pin on some revisions. Keep the contact open during reset and power-up unless the board profile and hardware test explicitly accept the closed state. |
| Waveshare ESP32-S3-ETH | 16 | Use the exposed header pin and a neighbouring GND. Confirm the exact board revision before permanent wiring. |
| Waveshare ESP32-P4-ETH | 16 | Use the exposed header pin and a neighbouring GND. Ethernet remains the management and assessment transport on this board. |
| GUITION JC-ESP32P4-M3-DEV | 1 | Use the exposed P4 header pin and a neighbouring GND. Do not use the C6 USB power pin as a GPIO supply. |

The selected pin is a compile-time board profile and is also emitted in the generated public configuration. Validation rejects GPIOs reserved for Ethernet RMII, flash/PSRAM, console/UART, SDIO, boot straps or other board peripherals. An exposed-looking pin is not automatically safe.

### GUITION two-chip warning

The P4 is powered and programmed through the USB connector nearest the RJ45. The C6 is programmed through a separate CH340-class UART: **TX → C6 UART RX, RX → C6 UART TX, GND → GND only**. Keep both the CH340 3.3 V and 5 V wires disconnected while the P4 USB power path is attached. Connecting two 3.3 V supplies can damage the USB interface or either board.

## Configuration and persistence

The default public configuration is fail-closed:

```json
"offensive_testing": {
  "software_enabled": false,
  "boot_policy": "seed_if_absent",
  "gpio_gate": {
    "enabled": true,
    "required": true,
    "gpio": 16,
    "active_high": false,
    "pull_mode": 1
  }
}
```

`seed_if_absent` uses the board defaults only when no valid policy record exists. Runtime changes are stored as a CRC-protected, versioned NVS blob. A corrupt or incompatible blob is ignored and replaced by a fail-closed seed. `force_config` is reserved for an explicitly authorized development build and applies the file configuration across reboot; it must never be used in a public release.

For local development only, the embedded configuration path can be enabled deliberately:

```powershell
$env:ESP32_OT_EMBEDDED_CONFIG='1'
pio run -e t-poe-pro
Remove-Item Env:ESP32_OT_EMBEDDED_CONFIG
```

The build system rejects an embedded configuration that enables software authorization or weakens the GPIO requirement unless the developer sets `ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE=1` for that one build. Clear both variables before creating release artifacts. A production/public release must never ship with software authorization forced on, `force_config`, a disabled required gate or an unvalidated GPIO.

## Operational behavior

- Read-only discovery and passive IDS continue while offensive authorization is blocked.
- Modbus write-capability probes, S7 control/write operations, EtherNet/IP SetAttribute/Reset probes, OPC UA active resilience/DoS checks and PROFINET disruptive fuzz profiles are blocked until the policy is effective.
- Opening the contact blocks the next unsafe case without a reboot; closing it allows a previously software-authorized policy to become effective.
- Every blocked operation reports a non-secret reason such as `gpio_not_asserted`, `disabled_in_security_config` or `security_manager_unavailable`.

Hardware acceptance must verify open/closed boot behavior, immediate runtime transitions, wrong-password rejection and persistence after reboot on each board. Until those checks are recorded, treat the profile as experimental.
