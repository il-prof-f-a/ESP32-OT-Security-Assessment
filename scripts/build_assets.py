"""Generate deterministic, secret-free firmware build assets.

When the environment variable ESP32_OT_EMBEDDED_CREDENTIALS=1, an administrator
password is read from (or generated into) the gitignored credentials.json and its
PBKDF2 hash is embedded so the device self-provisions at first boot, skipping the
setup portal. Release/CI builds leave the variable unset, so published firmware
always uses the interactive provisioning flow.
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


@dataclass(frozen=True)
class BuildAssetsResult:
    header_path: Path


def _public_defaults() -> dict:
    """Return conservative defaults suitable for every supported target."""

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


def _generate_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(20))


def _pbkdf2_hash(password: str) -> str:
    """Match the firmware PasswordHasher format: pbkdf2:<salt_b64>:100000:<hash_b64>."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)
    return (
        "pbkdf2:"
        + base64.b64encode(salt).decode("ascii")
        + ":100000:"
        + base64.b64encode(digest).decode("ascii")
    )


def _embedded_requested(project_dir: Path, board: str) -> bool:
    """Return True when embedded credentials should be generated.

    An explicitly set ESP32_OT_EMBEDDED_CREDENTIALS environment variable wins
    (CI forces "0" so releases use provisioning); otherwise the per-environment
    -DESP32_OT_EMBEDDED_CREDENTIALS=1 flag in platformio.ini is used.
    """
    explicit = os.environ.get("ESP32_OT_EMBEDDED_CREDENTIALS")
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
    return "-DESP32_OT_EMBEDDED_CREDENTIALS=1" in block


def _embedded_admin_hash(project_dir: Path, board: str) -> str:
    """Return the embedded admin PBKDF2 hash, or "" when the feature is disabled."""
    if not _embedded_requested(project_dir, board):
        return ""
    credentials_path = Path(project_dir).resolve() / "credentials.json"
    if credentials_path.is_file():
        try:
            data = json.loads(credentials_path.read_text(encoding="utf-8"))
            password = data.get("admin_password", "")
        except (json.JSONDecodeError, OSError) as error:
            raise ValueError(f"invalid credentials.json: {error}") from error
    else:
        password = _generate_password()
        credentials_path.write_text(
            json.dumps({"admin_password": password}, indent=2) + "\n",
            encoding="utf-8",
        )
    if not isinstance(password, str) or not password:
        raise ValueError("credentials.json must contain a non-empty admin_password")
    if len(password) < 16 or len(password) > 128:
        raise ValueError("admin_password must be 16-128 bytes")
    return _pbkdf2_hash(password)


def _header_bytes(embedded_admin_hash: str) -> bytes:
    config = json.dumps(
        _public_defaults(), ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    header = (
        "// Generated by scripts/build_assets.py. Do not edit.\n"
        "#pragma once\n\n"
        "namespace esp32_ot_build {\n"
        "static constexpr char kEmbeddedPublicConfigJson[] = "
        f'R"ESP32CFG({config})ESP32CFG";\n'
        'static constexpr char kEmbeddedAdminPasswordHash[] = "'
        f'{embedded_admin_hash}";\n'
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

    Path(project_dir).resolve(strict=True)
    Path(build_dir).resolve().mkdir(parents=True, exist_ok=True)
    if board is not None and not isinstance(board, str):
        raise TypeError("board must be a string or None")
    embedded_admin_hash = _embedded_admin_hash(project_dir, board or "")
    header_path = Path(build_dir).resolve() / "generated" / "esp32_ot_build_assets.h"
    legacy_header = header_path.parent / "esp32_ot_generated_credentials.h"
    if legacy_header.exists():
        legacy_header.unlink()
    _atomic_write(header_path, _header_bytes(embedded_admin_hash))
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
