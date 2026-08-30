"""Generate deterministic, secret-free firmware build assets.

When the environment variable ESP32_OT_EMBEDDED_CONFIG=1, an administrator
password and optional overrides are read from (or generated into) the gitignored
device-config.json, deep-merged into the public defaults, and the PBKDF2
hash is embedded so the device self-provisions at first boot, skipping the setup
portal. Release/CI builds leave the variable unset, so published firmware always
uses the interactive provisioning flow.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import tempfile

from check_release_secrets import scan_paths


@dataclass(frozen=True)
class BuildAssetsResult:
    header_path: Path


_BOARD_OFFENSIVE_GPIO = {
    "t-poe-pro": 15,
    "esp32-s3-eth": 16,
    "waveshare-esp32p4-eth": 16,
    "guition-jc-esp32p4-m3-dev": 1,
}


def _public_defaults(board: str | None = None) -> dict:
    """Return conservative defaults for the selected supported target."""

    default_gpio = _BOARD_OFFENSIVE_GPIO.get(board or "", -1)

    return {
        "audit": {
            "enabled": True,
            "logging": {
                "log_config_changes": True,
                "log_denied": True,
                "log_ratelimits": True,
                "log_security_events": True,
                "log_system_events": True,
                "log_timeouts": True,
            },
            "rate_limiting": {"max_events_per_second": 100},
        },
        "debug": {"color": True, "level": 2},
        "ids": {
            "general": {
                "enabled": True,
                "max_per_sec_enip": 100,
                "max_per_sec_modbus": 100,
                "max_per_sec_opcua": 100,
                "max_per_sec_pn": 100,
                "max_per_sec_s7": 100,
                "replay_window_ms": 5000,
            }
        },
        "network": {
            "ethernet": {
                "dhcp": True,
                "enabled": True,
                "gateway": "",
                "ip": "",
                "netmask": "",
                "promiscuous": True,
            },
            "wifi": {
                "connect_timeout_sec": 20,
                "dhcp": True,
                "dns": "",
                "enabled": False,
                "gateway": "",
                "http_time_sync": "",
                "ip": "",
                "netmask": "",
                "ntp": "pool.ntp.org",
                "password": "",
                "scan_on_fail": False,
                "ssid": "",
                "time_sync": "ntp",
            },
        },
        "plugins": {
            "ethernetip": {"enabled": True},
            "modbus": {"enabled": True},
            "opcua": {"enabled": True},
            "profinet": {"enabled": True},
            "s7": {"enabled": True},
        },
        "reporting": {
            "email": {"configuration": {}, "enabled": False},
            "file": {"configuration": {}, "enabled": True},
            "gpio": {"configuration": {}, "enabled": False},
            "mqtt": {"configuration": {}, "enabled": False},
            "serial": {"configuration": {}, "enabled": True},
            "webhook": {"configuration": {}, "enabled": False},
        },
        "scanner": {
            "default_timeout_ms": 2000,
            "enabled": False,
            "jobs": [],
            "max_parallel": 1,
            "rate_limit_per_min": 30,
            "scheduling": {"enabled": False},
        },
        "security": {
            "alert_policy": {
                "email": {
                    "enabled": False,
                    "recipients": [],
                    "subject": "ICS security alert",
                    "throttle_minutes": 5,
                },
                "gpio": {
                    "buzzer_pin": -1,
                    "critical_pin": -1,
                    "enabled": False,
                    "warning_pin": -1,
                },
                "webhook": {"enabled": False, "token": "", "url": ""},
            },
            "certificate_validation": True,
            "flash_encryption": False,
            "opcua_enforce_security": True,
            "offensive_testing": {
                "software_enabled": False,
                "boot_policy": "seed_if_absent",
                "gpio_gate": {
                    "enabled": True,
                    "required": True,
                    "gpio": default_gpio,
                    "active_high": False,
                    "pull_mode": 1,
                },
            },
            "policy": {"block_s7_plc_stop": True},
            "secure_boot": False,
        },
        "watchdog": {
            "enabled": True,
            "monitor_idle_cores": False,
            "panic_on_timeout": False,
            "timeout_seconds": 30,
        },
    }


def _deep_merge(default: dict, override: dict) -> dict:
    """Recursively merge override into default.

    Nested dictionaries merge key by key; a scalar or array in override replaces the
    default value. This is the documented rule: a present key replaces, an absent key
    keeps the default. Keys starting with "_" (e.g. "_comment") are ignored.
    """
    result = dict(default)
    for key, value in override.items():
        if key.startswith("_"):
            continue
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _strip_admin_password(value):
    """Recursively drop admin_password so plaintext never reaches the config."""
    if isinstance(value, dict):
        return {
            key: _strip_admin_password(item)
            for key, item in value.items()
            if key != "admin_password"
        }
    if isinstance(value, list):
        return [_strip_admin_password(item) for item in value]
    return value


def _generate_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(20))


def _pbkdf2_hash(password: str) -> str:
    """Match the firmware PasswordHasher format: pbkdf2:<salt_b64>:100000:<hash_b64>.

    The salt is derived deterministically from the password so clean builds stay
    byte-for-byte reproducible. A per-build random salt adds no real entropy here:
    the salt is embedded in the firmware next to the hash, so it is public to anyone
    who extracts the image anyway.
    """
    salt = hashlib.sha256(
        b"esp32-ot:embedded-config:v1:" + password.encode("utf-8")
    ).digest()[:16]
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)
    return (
        "pbkdf2:"
        + base64.b64encode(salt).decode("ascii")
        + ":100000:"
        + base64.b64encode(digest).decode("ascii")
    )


def _device_config_path(project_dir: Path) -> Path:
    return Path(project_dir).resolve() / "device-config.json"


def _validate_littlefs_seed(project_dir: Path) -> None:
    """Reject local credentials before PlatformIO can copy them into LittleFS."""

    data_dir = Path(project_dir).resolve() / "data"
    if not data_dir.is_dir():
        return
    findings = scan_paths([data_dir])
    if not findings:
        return
    safe_findings = ", ".join(
        f"{Path(finding.path).relative_to(project_dir)} ({finding.rule})"
        for finding in findings
    )
    raise ValueError(
        "LittleFS seed contains credential material; move it outside the public "
        f"repository before building: {safe_findings}"
    )


def _load_device_config(project_dir: Path) -> dict:
    """Return device-config.json (creating it with a generated password if missing)."""
    path = _device_config_path(project_dir)
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as error:
            raise ValueError(f"invalid device-config.json: {error}") from error
    data = {"admin_password": _generate_password()}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def _embedded_requested(project_dir: Path, board: str) -> bool:
    """Return True when embedded config should be generated.

    An explicitly set ESP32_OT_EMBEDDED_CONFIG environment variable wins
    (CI forces "0" so releases use provisioning); otherwise the per-environment
    -DESP32_OT_EMBEDDED_CONFIG=1 flag in platformio.ini is used.
    """
    explicit = os.environ.get("ESP32_OT_EMBEDDED_CONFIG")
    if explicit is not None:
        return explicit == "1"
    if not board:
        return False
    platformio = Path(project_dir).resolve() / "platformio.ini"
    try:
        content = platformio.read_text(encoding="utf-8")
    except OSError:
        return False
    start = content.find(f"[env:{board}]")
    if start < 0:
        return False
    end = content.find("\n[env:", start + 1)
    block = content[start:] if end < 0 else content[start:end]
    return "-DESP32_OT_EMBEDDED_CONFIG=1" in block


def _embedded_admin_hash(config: dict) -> str:
    """Return the PBKDF2 hash of the configured admin password."""
    password = config.get("admin_password", "")
    if not isinstance(password, str) or not password:
        raise ValueError("device-config.json must contain a non-empty admin_password")
    if len(password) < 16 or len(password) > 128:
        raise ValueError("admin_password must be 16-128 bytes")
    return _pbkdf2_hash(password)


def _validate_offensive_override(config: dict) -> None:
    """Reject permissive embedded offensive settings unless explicitly opted in."""

    if os.environ.get("ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE") == "1":
        return
    policy = (config.get("security") or {}).get("offensive_testing") or {}
    gate = policy.get("gpio_gate") or {}
    if (
        policy.get("software_enabled") is True
        or policy.get("boot_policy") not in (None, "seed_if_absent")
        or gate.get("enabled") is False
        or gate.get("required") is False
    ):
        raise ValueError(
            "offensive-testing embedded overrides are disabled by default; set "
            "ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE=1 only for an authorized "
            "development build"
        )


def _header_bytes(
    config: dict,
    admin_hash: str,
    ethernet_dhcp: bool,
    offensive_interlock_bypass_authorized: bool,
) -> bytes:
    rendered = json.dumps(
        config, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    dhcp = "true" if ethernet_dhcp else "false"
    header = (
        "// Generated by scripts/build_assets.py. Do not edit.\n"
        "#pragma once\n\n"
        "namespace esp32_ot_build {\n"
        "static constexpr char kEmbeddedPublicConfigJson[] = "
        f'R"ESP32CFG({rendered})ESP32CFG";\n'
        'static constexpr char kEmbeddedAdminPasswordHash[] = "'
        f'{admin_hash}";\n'
        f"static constexpr bool kEmbeddedEthernetDhcp = {dhcp};\n"
        "static constexpr bool kOffensiveInterlockBypassAuthorized = "
        f"{'true' if offensive_interlock_bypass_authorized else 'false'};\n"
        "}  // namespace esp32_ot_build\n"
    )
    return header.encode("utf-8")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_bytes() == content:
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content)
    temporary.replace(path)


def generate_build_assets(
    project_dir: Path | str, build_dir: Path | str, board: str | None = None
) -> BuildAssetsResult:
    """Generate public assets; board is accepted for a stable build interface."""

    project_dir = Path(project_dir).resolve(strict=True)
    Path(build_dir).resolve().mkdir(parents=True, exist_ok=True)
    if board is not None and not isinstance(board, str):
        raise TypeError("board must be a string or None")

    _validate_littlefs_seed(project_dir)

    admin_hash = ""
    ethernet_dhcp = True
    embedded_requested = _embedded_requested(project_dir, board or "")
    offensive_interlock_bypass_authorized = embedded_requested and (
        os.environ.get("ESP32_OT_ALLOW_OFFENSIVE_CONFIG_OVERRIDE") == "1"
    )
    config = _public_defaults(board)
    if embedded_requested:
        device_config = _load_device_config(project_dir)
        admin_hash = _embedded_admin_hash(device_config)
        overrides = {
            key: _strip_admin_password(value)
            for key, value in device_config.items()
            if key not in ("admin_password", "_comment")
        }
        config = _deep_merge(_public_defaults(board), overrides)
        _validate_offensive_override(config)
        ethernet_dhcp = bool(config["network"]["ethernet"].get("dhcp", True))

    header_path = Path(build_dir).resolve() / "generated" / "esp32_ot_build_assets.h"
    legacy_header = header_path.parent / "esp32_ot_generated_credentials.h"
    if legacy_header.exists():
        legacy_header.unlink()
    _atomic_write(
        header_path,
        _header_bytes(
            config,
            admin_hash,
            ethernet_dhcp,
            offensive_interlock_bypass_authorized,
        ),
    )
    return BuildAssetsResult(header_path=header_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--board", default="")
    args = parser.parse_args()
    result = generate_build_assets(args.project_dir, args.build_dir, args.board)
    print(f"Public build assets ready: {result.header_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
