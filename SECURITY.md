# Security policy

## Experimental status

This research firmware is under active development, has not received a complete independent
audit, and must not be treated as a production security boundary. Use active assessment features
only on systems you own or are explicitly authorized to test.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/il-prof-f-a/ESP32-OT-Security-Assessment/security/advisories/new).
Include the affected version, target board, impact and a minimal reproducer. Redact passwords,
tokens, keys, internal addresses, identifiers and proprietary OT traffic.

## Provisioning threat model

- Fresh and factory-reset devices are intentionally reachable through a minimal setup server.
- The one-time setup token and temporary AP password are printed only on UART, expire after 15
  minutes, are rate-limited and must be protected from physical observers.
- Five invalid token attempts per minute trigger a 60-second lockout.
- S3/P4 create a per-device self-signed ECDSA certificate. Verify its UART SHA-256 fingerprint
  before sending setup data; a self-signed warning alone does not prove identity.
- The per-device TLS private key is stored on the LittleFS partition without flash encryption
  (Secure Boot and Flash Encryption are not enabled yet). An attacker with physical access to the
  flash can extract it and impersonate the device or decrypt captured HTTPS traffic. Protect the
  hardware and re-provision after any suspected physical compromise.
- T-POE Pro management is currently unencrypted HTTP. Passwords and sessions can be observed or
  modified by an attacker on that management network. Use an isolated, trusted lab network.
- The provisioning completion marker is committed last. Interrupted setup remains fail-closed and
  does not start operational capture, scanning, fuzzing or the full web application.

There are no universal credentials and no shared default administrator password. Password hashes,
setup values and private TLS keys are created on the device, not embedded in release firmware.

## Recovery and credential loss

An authenticated administrator can call `POST /api/config/reset`. It clears the completion marker
before deleting configuration, security state and TLS identity, then reboots to setup mode.

A forgotten administrator password requires physical serial access:

```bash
python scripts/flash_esptool.py --target t-poe-pro --port COM10 --factory-reset
```

The command erases only the NVS and LittleFS regions after explicit confirmation. `--erase-all`
is a separate full-chip operation. Factory reset destroys local configuration and identities; it
cannot recover the old password.

If any credential or private key may have been exposed, factory-reset the affected device and
provision it again on a trusted network.
