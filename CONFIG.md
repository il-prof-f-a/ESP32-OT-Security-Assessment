# Configuration reference (device-config.json)

device-config.json is a gitignored, per-device build-time override file in the
repository root. It is read only when the embedded-config mode is enabled
(ESP32_OT_EMBEDDED_CONFIG=1). Release/CI builds ignore it and use the
interactive provisioning portal instead.

## Merge rule

The file is deep-merged over the built-in defaults:

- A key present in device-config.json REPLACES the default value.
- A key absent from device-config.json keeps the DEFAULT value.
- Nested objects merge recursively (key by key); scalars and arrays replace.
- Keys starting with "_" (e.g. "_comment") are ignored.

## Special keys

- admin_password (top-level, required): the administrator password, at least 16
  bytes. It is never stored in plaintext: only its PBKDF2-HMAC-SHA256 hash is
  embedded. Any admin_password nested elsewhere (e.g. inside security) is stripped.
- _comment (optional): ignored; a convenient way to leave notes in the file.

## Default configuration

The authoritative defaults live in scripts/build_assets.py (_public_defaults()).
The complete default JSON is:

    {
      "audit": {
        "enabled": true,
        "logging": {
          "log_config_changes": true,
          "log_denied": true,
          "log_ratelimits": true,
          "log_security_events": true,
          "log_system_events": true,
          "log_timeouts": true
        },
        "rate_limiting": { "max_events_per_second": 100 }
      },
      "debug": { "color": true, "level": 2 },
      "ids": {
        "general": {
          "enabled": true,
          "max_per_sec_enip": 100,
          "max_per_sec_modbus": 100,
          "max_per_sec_opcua": 100,
          "max_per_sec_pn": 100,
          "max_per_sec_s7": 100,
          "replay_window_ms": 5000
        }
      },
      "network": {
        "ethernet": {
          "dhcp": true,
          "enabled": true,
          "gateway": "",
          "ip": "",
          "netmask": "",
          "promiscuous": true
        },
        "wifi": {
          "connect_timeout_sec": 20,
          "dhcp": true,
          "dns": "",
          "enabled": false,
          "gateway": "",
          "http_time_sync": "",
          "ip": "",
          "netmask": "",
          "ntp": "pool.ntp.org",
          "password": "",
          "scan_on_fail": false,
          "ssid": "",
          "time_sync": "ntp"
        }
      },
      "plugins": {
        "ethernetip": { "enabled": true },
        "modbus": { "enabled": true },
        "opcua": { "enabled": true },
        "profinet": { "enabled": true },
        "s7": { "enabled": true }
      },
      "reporting": {
        "email": { "configuration": {}, "enabled": false },
        "file": { "configuration": {}, "enabled": true },
        "gpio": { "configuration": {}, "enabled": false },
        "mqtt": { "configuration": {}, "enabled": false },
        "serial": { "configuration": {}, "enabled": true },
        "webhook": { "configuration": {}, "enabled": false }
      },
      "scanner": {
        "default_timeout_ms": 2000,
        "enabled": false,
        "jobs": [],
        "max_parallel": 1,
        "rate_limit_per_min": 30,
        "scheduling": { "enabled": false }
      },
      "security": {
        "alert_policy": {
          "email": {
            "enabled": false,
            "recipients": [],
            "subject": "ICS security alert",
            "throttle_minutes": 5
          },
          "gpio": {
            "buzzer_pin": -1,
            "critical_pin": -1,
            "enabled": false,
            "warning_pin": -1
          },
          "webhook": { "enabled": false, "token": "", "url": "" }
        },
        "certificate_validation": true,
        "flash_encryption": false,
        "opcua_enforce_security": true,
        "policy": { "block_s7_plc_stop": true },
        "secure_boot": false
      },
      "watchdog": {
        "enabled": true,
        "monitor_idle_cores": false,
        "panic_on_timeout": false,
        "timeout_seconds": 30
      }
    }

## Static Ethernet example (ESP32-P4)

    {
      "admin_password": "your-fixed-password-here",
      "network": {
        "ethernet": {
          "dhcp": false,
          "ip": "192.168.1.253",
          "gateway": "192.168.1.1",
          "netmask": "255.255.255.0"
        }
      }
    }

If network is omitted, the default is dhcp=true (DHCP). See device-config.json.example.

## TLS certificates

See the README "Embedded config" section. To seed a fixed certificate (so the
browser stops warning), create data/certs/server.crt and data/certs/server.key in the
repository (gitignored via *.crt / *.key); pio run -t buildfs flashes them to
/data/certs and the firmware uses them instead of generating a per-device pair.
