# Web Interface User Guide

This guide covers the operational web interface of ESP32 OT Security Assessment `v0.1.0`. It is
based on the interface served by a running test device and on the corresponding HTML, JavaScript
and HTTP handlers in the firmware source.

> **Experimental software:** controls and results may change, and some functions are incomplete.
> Use discovery, vulnerability scanning and fuzzing only on systems you own or are explicitly
> authorized to test. Prefer an isolated laboratory network.

## Before you begin

- Complete first-time provisioning as described in the main [README](../../README.md#first-boot-provisioning).
- Keep the administrator password and one-time setup token private.
- Treat the `sid` query parameter created after login as a temporary credential. Do not publish,
  copy into tickets, or include it in screenshots.
- LILYGO T-POE Pro currently serves the management interface over HTTP only. Anyone able to
  observe that network may read or alter management traffic.
- ESP32-S3-ETH and ESP32-P4-ETH use a per-device self-signed HTTPS certificate. Verify the
  certificate fingerprint against the value printed on the serial console.
- Screenshots show the page layout. Runtime counters, feature availability and field values vary
  with hardware, configuration and traffic.

## Guide map

### Access and overview

- [Login](login.md)
- [Dashboard](dashboard.md)

### Configure and assess OT protocols

- [Protocol Configuration](protocol-configuration.md)
- [Protocol Discovery](protocol-discovery.md)
- [Vulnerability Scanner](vulnerability-scanner.md)
- [Fuzzing](fuzzing.md)

### Detection and trust

- [Intrusion Detection System](intrusion-detection-system.md)
- [CVE Signature Detection Engine](cve-signatures.md)
- [NetworkPresence Device Learning & Trust](network-presence.md)
- [Audit Manager Configuration](audit-manager.md)
- [Security Settings](security-settings.md)

### Output and hardware integration

- [Reporting Configuration](reporting.md)
- [Log File Management](logging.md)
- [GPIO Reporter Configuration](gpio-reporter.md)
- [Serial Monitor](serial-monitor.md)

### Connectivity and troubleshooting

- [Network Tools](network-tools.md)
- [Phased Network Diagnostics](diagnostics.md)

## Common interface behavior

Most pages use **Dashboard** to return to the home page while preserving the active session.
Buttons named **Load**, **Reload** or **Refresh** read current runtime state. **Save** changes the
relevant configuration through an authenticated API. A successful API response does not always
mean the underlying interface has restarted; when a page displays a restart warning, reboot the
device during a controlled maintenance window.

Destructive controls such as **Delete**, **Clear**, **Reset Learning**, **Stop All** and **Reboot**
should be used deliberately. Export current data first when the page offers an export function.

## Result interpretation

The project is an assessment aid, not a safety controller or a complete vulnerability management
platform. An alert is evidence that a configured rule matched observed traffic; it is not proof of
compromise. A clean scan is not proof that a target is secure. Correlate results with packet
captures, device logs, asset inventory and vendor guidance.
