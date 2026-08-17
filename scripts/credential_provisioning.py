"""First-build credential and self-signed TLS provisioning.

This module intentionally depends only on the Python standard library because PlatformIO's
isolated Python environment does not guarantee third-party cryptography packages.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
from typing import Mapping


SCHEMA_VERSION = 1
COMMON_NAME = "esp32-ot-security.local"
ENV_CREDENTIALS_DIR = "ESP32_OT_CREDENTIALS_DIR"


@dataclass(frozen=True)
class ProvisioningResult:
    credentials_dir: Path
    manifest_path: Path
    config_path: Path
    certificate_path: Path
    private_key_path: Path
    header_path: Path


def resolve_credentials_dir(
    project_dir: Path | str, environ: Mapping[str, str] | None = None
) -> Path:
    """Resolve persistent secret storage without writing anything."""

    project = Path(project_dir).resolve()
    environment = os.environ if environ is None else environ
    override = environment.get(ENV_CREDENTIALS_DIR, "").strip()
    if override:
        candidate = Path(override).expanduser()
        if not candidate.is_absolute():
            candidate = project / candidate
        return candidate.resolve()

    private_credentials = project.parent / "credentials"
    if private_credentials.is_dir():
        return private_credentials.resolve()

    return (project / ".credentials").resolve()


def _atomic_write(path: Path, data: bytes, private: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_bytes() == data:
        return

    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if private:
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        if private:
            os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _new_password() -> str:
    return secrets.token_urlsafe(32)


def _new_manifest() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "admin": {"username": "admin", "password": _new_password()},
        "access_point": {
            "ssid": f"ESP32-OT-Setup-{secrets.token_hex(3).upper()}",
            "password": _new_password(),
        },
        "tls": {
            "common_name": COMMON_NAME,
            "certificate": "server.crt",
            "private_key": "server.key",
        },
    }


def _validate_manifest(manifest: object) -> dict:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported or malformed credential manifest")
    try:
        admin_password = manifest["admin"]["password"]
        ap_ssid = manifest["access_point"]["ssid"]
        ap_password = manifest["access_point"]["password"]
    except (KeyError, TypeError) as exc:
        raise ValueError("Credential manifest is missing required fields") from exc
    if not all(isinstance(value, str) and value for value in (admin_password, ap_ssid, ap_password)):
        raise ValueError("Credential manifest contains empty fields")
    if len(admin_password) < 24 or len(ap_password) < 24:
        raise ValueError("Credential manifest passwords do not meet the minimum length")
    return manifest


def _load_or_create_manifest(path: Path) -> dict:
    if path.is_file():
        try:
            return _validate_manifest(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Credential manifest is not valid JSON: {path}") from exc

    manifest = _new_manifest()
    _atomic_write(path, _json_bytes(manifest))
    return manifest


def _default_config(admin_password: str) -> dict:
    """Return conservative defaults with all external integrations disabled."""

    return {
        "debug": {"level": 2, "color": True},
        "security": {
            "secure_boot": False,
            "flash_encryption": False,
            "certificate_validation": True,
            "opcua_enforce_security": True,
            "admin_password": admin_password,
            "admin_password_hash": "",
            "policy": {"block_s7_plc_stop": True},
            "alert_policy": {
                "email": {"enabled": False, "recipients": [], "subject": "ICS security alert", "throttle_minutes": 5},
                "webhook": {"enabled": False, "url": "", "token": ""},
                "gpio": {"enabled": False, "critical_pin": -1, "warning_pin": -1, "buzzer_pin": -1},
            },
        },
        "network": {
            "ethernet": {
                "enabled": True,
                "dhcp": True,
                "promiscuous": True,
                "ip": "",
                "gateway": "",
                "netmask": "",
            },
            "wifi": {
                "enabled": False,
                "dhcp": True,
                "ssid": "",
                "password": "",
                "ip": "",
                "gateway": "",
                "netmask": "",
                "dns": "",
                "ntp": "pool.ntp.org",
                "time_sync": "ntp",
                "http_time_sync": "",
                "connect_timeout_sec": 20,
                "scan_on_fail": False,
            },
        },
        "ip_whitelist": {
            "enabled": False,
            "action": "alert",
            "ip": [],
            "mac": [],
            "per_protocol": {
                protocol: {"ip": [], "mac": []}
                for protocol in ("MODBUS_TCP", "s7", "opcua", "profinet", "ethernetip")
            },
        },
        "ids": {
            "general": {
                "enabled": True,
                "max_per_sec_modbus": 100,
                "max_per_sec_s7": 100,
                "max_per_sec_enip": 100,
                "max_per_sec_pn": 100,
                "max_per_sec_opcua": 100,
                "replay_window_ms": 5000,
            },
            "anomaly": {
                "flooding_pps_threshold": 1000.0,
                "requests_per_second_threshold": 100.0,
                "request_response_high_ratio": 10.0,
                "request_response_low_ratio": 0.1,
                "malformed_packets_normalizer": 1.0,
                "reactive_fuzzing_cooldown_ms": 60000,
                "reactive_fuzzing_retention_ms": 300000,
            },
            "network_presence": {
                "enabled": True,
                "learning_mode": True,
                "alert_unauthorized_writes": True,
                "track_all_traffic": True,
                "cleanup_interval_ms": 60000,
                "inactive_device_timeout_ms": 3600000,
                "activation_delay_minutes": 5,
                "retention_days": 30,
                "trust_threshold_score": 0.75,
                "min_observation_period_hours": 24.0,
                "continuity_weight": 0.4,
                "diversity_weight": 0.3,
                "frequency_weight": 0.3,
                "enable_persistent_learning": True,
                "storage_sync_interval_ms": 300000,
                "whitelisted_devices": [],
            },
            "protocol_specific": {
                "profinet": {
                    "detect_dcp_spoofing": True,
                    "detect_config_changes": True,
                    "detect_topology_changes": True,
                    "max_devices_per_sec": 50,
                },
                "modbus": {"alert_broadcast_write": True},
            },
        },
        "plugins": {
            "modbus": {
                "enabled": True,
                "unit_id": 1,
                "connect_timeout_ms": 1000,
                "io_timeout_ms": 1000,
                "default_unit_id": 1,
                "discovery_unit_ids": "1-10",
                "discovery_connect_timeout_ms": 500,
                "discovery_io_timeout_ms": 500,
                "discovery_request_retries": 1,
                "discovery_connect_retries": 1,
                "discovery_prescan_enabled": False,
                "discovery_prescan_timeout_ms": 500,
                "discovery_probe_coils_max": 16,
                "allowed_writers": "",
            },
            "opcua": {
                "enabled": True,
                "port": 4840,
                "connect_timeout_ms": 2000,
                "session_timeout_ms": 5000,
                "enable_discovery": True,
                "allowed_writers": "",
            },
            "s7": {
                "enabled": True,
                "port": 102,
                "connect_timeout_ms": 2000,
                "pdu_size": 480,
                "enable_plc_control": False,
                "allowed_writers": "",
            },
            "profinet": {
                "enabled": True,
                "dcp_multicast": "01:0E:CF:00:00:00",
                "enable_topology_discovery": True,
                "discovery_timeout_ms": 2000,
                "security_assessment": {
                    "check_default_names": True,
                    "check_security_class": True,
                    "check_unencrypted_comm": True,
                    "default_name_patterns": ["plc", "device", "station", "pnio"],
                },
                "allowed_writers": "",
            },
            "ethernetip": {
                "enabled": True,
                "tcp_port": 44818,
                "udp_port": 44818,
                "connect_timeout_ms": 2000,
                "enable_cip_discovery": True,
                "allowed_writers": "",
            },
        },
        "watchdog": {
            "enabled": True,
            "timeout_seconds": 30,
            "panic_on_timeout": False,
            "monitor_idle_cores": False,
        },
        "scanner": {
            "enabled": False,
            "scheduling": {"enabled": False},
            "max_parallel": 1,
            "rate_limit_per_min": 30,
            "default_timeout_ms": 2000,
            "jobs": [],
        },
        "audit": {
            "enabled": True,
            "logging": {
                "log_denied": True,
                "log_timeouts": True,
                "log_ratelimits": True,
                "log_system_events": True,
                "log_security_events": True,
                "log_config_changes": True,
            },
            "rate_limiting": {"max_events_per_second": 100},
        },
        "reporting": {
            "serial": {"enabled": True, "format": "json", "verbosity": "info", "configuration": {}, "filters": {"enabled": False}},
            "file": {"enabled": True, "format": "json", "verbosity": "info", "files": {}},
            "mqtt": {"enabled": False, "format": "json", "verbosity": "info", "filters": {"enabled": False}, "configuration": {"broker": "", "port": 8883, "topic_prefix": "esp32-ot", "client_id": "esp32-ot-security", "username": "", "password": "", "qos": 1, "retain": False, "timeout_ms": 5000, "reconnect_interval_ms": 10000}},
            "webhook": {"enabled": False, "format": "json", "verbosity": "info", "configuration": {"url": "", "headers": {}, "timeout_ms": 5000}},
            "email": {"enabled": False, "format": "json", "verbosity": "info", "filters": {"enabled": False}, "configuration": {"smtp_server": "", "smtp_port": 465, "use_tls": True, "use_ssl": True, "username": "", "password": "", "to_addresses": [], "from_address": "", "subject_prefix": "[ESP32 OT]", "timeout_ms": 5000, "retry_attempts": 1}},
            "gpio": {"enabled": False, "format": "json", "verbosity": "info", "configuration": {"pins": {}, "behavior": {}}, "filters": {"enabled": False}},
        },
    }


def _board_config_candidates(config_dir: Path, board: str | None) -> list[Path]:
    """Return config candidates in priority order: per-board, then shared."""
    candidates = [config_dir / "config.json"]
    if board:
        candidates.insert(0, config_dir / f"config.{board}.json")
    return candidates


def _read_config_preserving_admin(path: Path, admin_password: str) -> bytes:
    """Read an existing config verbatim, injecting the admin credential if absent."""
    raw = path.read_bytes()
    try:
        config = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Config file is not valid JSON: {path}") from exc
    if not isinstance(config, dict):
        raise ValueError(f"Config file must contain a JSON object: {path}")

    security = config.get("security")
    if not isinstance(security, dict):
        security = {}
        config["security"] = security
    if not security.get("admin_password") and not security.get("admin_password_hash"):
        security["admin_password"] = admin_password
        raw = _json_bytes(config)
        _atomic_write(path, raw)
    return raw


def _load_or_create_config(
    config_dir: Path, board: str | None, admin_password: str
) -> tuple[Path, bytes]:
    """Return (path, bytes) of the runtime configuration to embed.

    credentials/config.<board>.json is the per-board reference configuration
    and credentials/config.json is the shared fallback. The first existing
    candidate is used verbatim, so manual edits (for example a static Ethernet
    address, or switching to DHCP) survive every subsequent build. Only when
    no candidate exists is a conservative default generated into the
    board-specific file (or the shared file when no board is set).

    The administrator credential is always guaranteed: an existing file lacking
    both security.admin_password and security.admin_password_hash gets the
    manifest password injected.
    """
    candidates = _board_config_candidates(config_dir, board)
    for path in candidates:
        if path.is_file():
            return path, _read_config_preserving_admin(path, admin_password)

    path = candidates[0]
    config = _json_bytes(_default_config(admin_password))
    _atomic_write(path, config)
    return path, config


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("DER integer must be non-negative")
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der(0x02, encoded)


def _der_sequence(*values: bytes) -> bytes:
    return _der(0x30, b"".join(values))


def _der_set(*values: bytes) -> bytes:
    return _der(0x31, b"".join(values))


def _der_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    if len(parts) < 2 or parts[0] > 2 or parts[1] >= 40:
        raise ValueError(f"Invalid OID: {oid}")
    encoded = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunks = [part & 0x7F]
        part >>= 7
        while part:
            chunks.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(reversed(chunks))
    return _der(0x06, bytes(encoded))


def _is_probable_prime(candidate: int, rounds: int = 32) -> bool:
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    for prime in small_primes:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False
    exponent = candidate - 1
    power_of_two = 0
    while exponent % 2 == 0:
        power_of_two += 1
        exponent //= 2
    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        value = pow(base, exponent, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(power_of_two - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int, exponent: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if math.gcd(candidate - 1, exponent) == 1 and _is_probable_prime(candidate):
            return candidate


def _pem(label: str, der: bytes) -> bytes:
    import base64

    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n").encode("ascii")


def _algorithm_identifier(oid: str) -> bytes:
    return _der_sequence(_der_oid(oid), _der(0x05, b""))


def _generate_self_signed_certificate(common_name: str) -> tuple[bytes, bytes]:
    exponent = 65537
    prime_p = _generate_prime(1024, exponent)
    prime_q = _generate_prime(1024, exponent)
    while prime_p == prime_q:
        prime_q = _generate_prime(1024, exponent)
    modulus = prime_p * prime_q
    phi = (prime_p - 1) * (prime_q - 1)
    private_exponent = pow(exponent, -1, phi)

    private_key_der = _der_sequence(
        _der_integer(0),
        _der_integer(modulus),
        _der_integer(exponent),
        _der_integer(private_exponent),
        _der_integer(prime_p),
        _der_integer(prime_q),
        _der_integer(private_exponent % (prime_p - 1)),
        _der_integer(private_exponent % (prime_q - 1)),
        _der_integer(pow(prime_q, -1, prime_p)),
    )

    utf8_name = _der(0x0C, common_name.encode("utf-8"))
    distinguished_name = _der_sequence(
        _der_set(_der_sequence(_der_oid("2.5.4.3"), utf8_name))
    )
    rsa_public_key = _der_sequence(_der_integer(modulus), _der_integer(exponent))
    public_key_info = _der_sequence(
        _algorithm_identifier("1.2.840.113549.1.1.1"),
        _der(0x03, b"\x00" + rsa_public_key),
    )

    now = datetime.now(timezone.utc).replace(microsecond=0)
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(days=825)
    validity = _der_sequence(
        _der(0x17, not_before.strftime("%y%m%d%H%M%SZ").encode("ascii")),
        _der(0x17, not_after.strftime("%y%m%d%H%M%SZ").encode("ascii")),
    )
    subject_alt_name = _der(0x82, common_name.encode("ascii"))
    extensions = _der(
        0xA3,
        _der_sequence(
            _der_sequence(
                _der_oid("2.5.29.17"),
                _der(0x04, _der_sequence(subject_alt_name)),
            )
        ),
    )
    signature_algorithm = _algorithm_identifier("1.2.840.113549.1.1.11")
    tbs_certificate = _der_sequence(
        _der(0xA0, _der_integer(2)),
        _der_integer(secrets.randbits(127) | 1),
        signature_algorithm,
        distinguished_name,
        validity,
        distinguished_name,
        public_key_info,
        extensions,
    )

    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(tbs_certificate).digest()
    modulus_bytes = (modulus.bit_length() + 7) // 8
    padding_length = modulus_bytes - len(digest_info) - 3
    encoded_message = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded_message, "big"), private_exponent, modulus).to_bytes(modulus_bytes, "big")
    certificate_der = _der_sequence(
        tbs_certificate,
        signature_algorithm,
        _der(0x03, b"\x00" + signature),
    )
    return _pem("CERTIFICATE", certificate_der), _pem("RSA PRIVATE KEY", private_key_der)


def _cpp_raw_string(value: str, delimiter: str) -> str:
    if f"){delimiter}\"" in value:
        raise ValueError("Generated content collides with the C++ raw-string delimiter")
    return f'R"{delimiter}({value}){delimiter}"'


def _build_header(config: bytes, certificate: bytes, private_key: bytes, manifest: dict) -> bytes:
    config_text = config.decode("utf-8")
    certificate_text = certificate.decode("ascii")
    private_key_text = private_key.decode("ascii")
    ap_ssid = json.dumps(manifest["access_point"]["ssid"])
    ap_password = json.dumps(manifest["access_point"]["password"])
    content = f"""// Generated automatically. Do not commit or share this file.
#pragma once

namespace esp32_ot_generated {{
static constexpr char kEmbeddedConfigJson[] = {_cpp_raw_string(config_text, "ESP32CFG")};
static constexpr char kServerCertificatePem[] = {_cpp_raw_string(certificate_text, "ESP32CRT")};
static constexpr char kServerPrivateKeyPem[] = {_cpp_raw_string(private_key_text, "ESP32KEY")};
static constexpr char kProvisioningApSsid[] = {ap_ssid};
static constexpr char kProvisioningApPassword[] = {ap_password};
}}  // namespace esp32_ot_generated
"""
    return content.encode("utf-8")


def provision(
    project_dir: Path | str,
    build_dir: Path | str,
    environ: Mapping[str, str] | None = None,
    board: str | None = None,
) -> ProvisioningResult:
    project = Path(project_dir).resolve()
    build = Path(build_dir).resolve()
    credentials = resolve_credentials_dir(project, environ)
    credentials.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(credentials, 0o700)

    manifest_path = credentials / "credentials.json"
    certificate_path = credentials / "server.crt"
    private_key_path = credentials / "server.key"
    header_path = build / "generated" / "esp32_ot_generated_credentials.h"

    manifest = _load_or_create_manifest(manifest_path)
    config_path, config = _load_or_create_config(
        credentials, board, manifest["admin"]["password"]
    )

    if not certificate_path.is_file() or not private_key_path.is_file():
        certificate, private_key = _generate_self_signed_certificate(
            manifest.get("tls", {}).get("common_name", COMMON_NAME)
        )
        _atomic_write(certificate_path, certificate)
        _atomic_write(private_key_path, private_key)

    certificate = certificate_path.read_bytes()
    private_key = private_key_path.read_bytes()
    header = _build_header(config, certificate, private_key, manifest)
    _atomic_write(header_path, header)

    return ProvisioningResult(
        credentials_dir=credentials,
        manifest_path=manifest_path,
        config_path=config_path,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        header_path=header_path,
    )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, default=Path.cwd())
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--credentials-dir", type=Path)
    parser.add_argument("--board", type=str, default=None)
    arguments = parser.parse_args()
    environment = dict(os.environ)
    if arguments.credentials_dir:
        environment[ENV_CREDENTIALS_DIR] = str(arguments.credentials_dir)
    result = provision(
        arguments.project_dir,
        arguments.build_dir,
        environment,
        board=arguments.board or None,
    )
    print(f"Credential material ready in {result.credentials_dir}")
    print(f"Generated build header: {result.header_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
