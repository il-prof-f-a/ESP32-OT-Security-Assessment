#!/usr/bin/env python3
"""Build and flash an ESP32-OT-Security-Assessment firmware image."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PARTITIONS = PROJECT_ROOT / "partitions.csv"
DEFAULT_PROJECT_NAME = "ESP32-OT-Security-Assessment"


class TargetConfig:
    __slots__ = ("chip", "environment")

    def __init__(self, *, chip: str, environment: str) -> None:
        self.chip = chip
        self.environment = environment


TARGETS = {
    "t-poe-pro": TargetConfig(chip="esp32", environment="t-poe-pro"),
    "esp32-s3-eth": TargetConfig(chip="esp32s3", environment="esp32-s3-eth"),
    "waveshare-esp32p4-eth": TargetConfig(
        chip="esp32p4", environment="waveshare-esp32p4-eth"
    ),
    "guition-jc-esp32p4-m3-dev": TargetConfig(
        chip="esp32p4", environment="guition-jc-esp32p4-m3-dev"
    ),
}


def target_config(target: str) -> TargetConfig:
    """Return the esptool settings for a PlatformIO environment."""
    try:
        return TARGETS[target]
    except KeyError as exc:
        supported = ", ".join(sorted(TARGETS))
        raise ValueError(f"Unknown target {target!r}; choose one of: {supported}") from exc


def parse_application_offset(partitions_path: Path) -> int:
    """Read the factory/first application offset from a PlatformIO CSV."""
    application_rows: list[Sequence[str]] = []
    with Path(partitions_path).open("r", encoding="utf-8", newline="") as stream:
        for row in csv.reader(stream):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            if len(row) >= 5 and row[1].strip().lower() == "app":
                application_rows.append(row)
    if not application_rows:
        raise ValueError(f"No application partition found in {partitions_path}")
    row = next(
        (item for item in application_rows if item[2].strip().lower() in {"factory", "ota_0"}),
        application_rows[0],
    )
    try:
        return int(row[3].strip(), 0)
    except ValueError as exc:
        raise ValueError(f"Invalid partition offset {row[3]!r} in row {row!r}") from exc


def parse_recovery_regions(partitions_path: Path) -> list[tuple[str, int, int]]:
    """Return the exact NVS and LittleFS regions used for physical recovery."""
    regions: list[tuple[str, int, int]] = []
    with Path(partitions_path).open("r", encoding="utf-8", newline="") as stream:
        for row in csv.reader(stream):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            if len(row) < 5:
                continue
            name = row[0].strip().lower()
            subtype = row[2].strip().lower()
            if name == "nvs" or subtype == "littlefs":
                try:
                    regions.append((name, int(row[3].strip(), 0), int(row[4].strip(), 0)))
                except ValueError as exc:
                    raise ValueError(f"Invalid recovery region in row {row!r}") from exc
    if {name for name, _, _ in regions} != {"nvs", "storage"}:
        raise ValueError(f"Expected nvs and storage recovery regions in {partitions_path}")
    return regions


def build_factory_reset_commands(
    *,
    target: str,
    port: str,
    partitions_path: Path,
    esptool_command: Iterable[str] | None = None,
) -> list[list[str]]:
    """Build narrowly scoped erase commands for NVS and LittleFS."""
    config = target_config(target)
    prefix = list(esptool_command or [_python_command(), "-m", "esptool"])
    return [
        [
            *prefix,
            "--chip",
            config.chip,
            "--port",
            port,
            "erase-region",
            hex(offset),
            hex(size),
        ]
        for _, offset, size in parse_recovery_regions(partitions_path)
    ]


def _artifact(build_dir: Path, name: str) -> Path:
    path = Path(build_dir) / name
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing {name} in {build_dir}. Run the PlatformIO build first."
        )
    return path


def _resolve_flash_file(build_dir: Path, configured: str) -> Path:
    direct = build_dir / configured
    if direct.is_file():
        return direct
    basename = Path(configured).name
    aliases = {
        "bootloader.bin": "bootloader.bin",
        "partition-table.bin": "partitions.bin",
        "esp32_ot_security_assessment.bin": "firmware.bin",
        "storage.bin": "littlefs.bin",
    }
    return _artifact(build_dir, aliases.get(basename, basename))


def _load_flash_manifest(build_dir: Path) -> tuple[str, str, str, str, list[tuple[int, Path]]]:
    manifest_path = build_dir / "flasher_args.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(
            f"Missing {manifest_path}. Run both the firmware and filesystem builds first."
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    settings = manifest.get("flash_settings", {})
    chip = manifest.get("extra_esptool_args", {}).get("chip")
    mode = settings.get("flash_mode")
    size = settings.get("flash_size")
    frequency = settings.get("flash_freq")
    flash_files = manifest.get("flash_files")
    if not chip or not mode or not size or not frequency or not isinstance(flash_files, dict):
        raise ValueError("flasher_args.json is missing chip, flash settings or flash_files")
    entries = sorted(
        (int(offset, 0), _resolve_flash_file(build_dir, configured))
        for offset, configured in flash_files.items()
    )
    if not entries:
        raise ValueError("flasher_args.json contains no flash files")
    return chip, mode, size, frequency, entries


def build_flash_command(
    *,
    target: str,
    port: str,
    build_dir: Path,
    esptool_command: Iterable[str] | None = None,
    baud: int = 921600,
    partitions_path: Path | None = None,
) -> list[str]:
    """Build an explicit esptool write-flash command for a target."""
    config = target_config(target)
    if not port.strip():
        raise ValueError("A serial port is required (for example COM10 or /dev/ttyUSB0)")
    build_dir = Path(build_dir)
    chip, mode, size, frequency, entries = _load_flash_manifest(build_dir)
    if chip != config.chip:
        raise ValueError(
            f"Build manifest chip {chip!r} does not match target chip {config.chip!r}"
        )
    command = list(esptool_command or [_python_command(), "-m", "esptool"])
    result = [
        *command,
        "--chip",
        chip,
        "--port",
        port,
        "--baud",
        str(baud),
        "write-flash",
        "--no-progress",
        "--flash-mode",
        mode,
        "--flash-freq",
        frequency,
        "--flash-size",
        size,
    ]
    for offset, artifact in entries:
        result.extend((hex(offset), str(artifact)))
    return result


def _venv_python() -> Path | None:
    candidates = (
        PROJECT_ROOT / ".venv" / "Scripts" / "python.exe",
        PROJECT_ROOT / ".venv" / "bin" / "python",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _python_command() -> str:
    configured = os.environ.get("ESP32_OT_PYTHON")
    if configured:
        return configured
    venv_python = _venv_python()
    if venv_python and Path(sys.executable).resolve() != venv_python.resolve():
        return str(venv_python)
    return sys.executable


def _platformio_command() -> list[str]:
    configured = os.environ.get("ESP32_OT_PLATFORMIO")
    if configured:
        return [configured]
    executable = shutil.which("pio") or shutil.which("platformio")
    if executable:
        return [executable]
    return [_python_command(), "-m", "platformio"]


def default_build_dir(project_dir: Path, target: str) -> Path:
    """Return the build directory used by the repository's PlatformIO config."""
    configured = os.environ.get("PLATFORMIO_BUILD_DIR")
    if configured:
        return Path(configured).expanduser() / target
    profile = os.environ.get("USERPROFILE") or os.environ.get("HOME")
    if profile:
        return Path(profile).expanduser() / ".platformio" / "build" / DEFAULT_PROJECT_NAME / target
    return Path(project_dir) / ".pio" / "build" / target


def _run(command: Sequence[str], *, cwd: Path) -> None:
    print("$ " + " ".join(str(part) for part in command), flush=True)
    environment = dict(os.environ)
    environment.setdefault("PYTHONUTF8", "1")
    subprocess.run(list(command), cwd=cwd, check=True, env=environment)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--port", required=True, help="Serial port, e.g. COM10 or /dev/ttyUSB0")
    parser.add_argument("--baud", type=int, default=921600)
    parser.add_argument("--project-dir", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--no-build", action="store_true", help="Flash existing artifacts")
    parser.add_argument(
        "--erase-flash",
        action="store_true",
        help="Erase the complete chip before installing the built firmware",
    )
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument(
        "--factory-reset",
        action="store_true",
        help="Erase only NVS and LittleFS; firmware is preserved",
    )
    recovery.add_argument(
        "--erase-all",
        action="store_true",
        help="Erase the complete chip without installing firmware",
    )
    parser.add_argument("--yes", action="store_true", help="Confirm a destructive erase")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    project_dir = args.project_dir.resolve()
    build_dir = (args.build_dir or default_build_dir(project_dir, args.target)).resolve()
    config = target_config(args.target)
    commands: list[list[str]] = []
    recovery_only = args.factory_reset or args.erase_all
    if recovery_only and args.erase_flash:
        parser.error("--erase-flash cannot be combined with a recovery-only operation")
    if not args.no_build and not recovery_only:
        commands.append([*_platformio_command(), "run", "-e", config.environment])
        commands.append(
            [*_platformio_command(), "run", "-e", config.environment, "-t", "buildfs"]
        )
    if args.factory_reset:
        regions = parse_recovery_regions(project_dir / "partitions.csv")
        print(f"Physical factory reset: chip={config.chip}, port={args.port}")
        for name, offset, size in regions:
            print(f"  {name}: offset={hex(offset)}, size={hex(size)}")
        if not args.dry_run and not args.yes:
            confirmation = input("Type RESET to erase NVS and LittleFS: ").strip()
            if confirmation != "RESET":
                print("Factory reset cancelled.")
                return 2
        commands.extend(
            build_factory_reset_commands(
                target=args.target,
                port=args.port,
                partitions_path=project_dir / "partitions.csv",
            )
        )
    elif args.erase_all:
        print(f"Full-chip erase: chip={config.chip}, port={args.port}")
        if not args.dry_run and not args.yes:
            confirmation = input("Type ERASE-ALL to erase the complete chip: ").strip()
            if confirmation != "ERASE-ALL":
                print("Full erase cancelled.")
                return 2
        commands.append(
            [
                _python_command(), "-m", "esptool", "--chip", config.chip,
                "--port", args.port, "erase-flash",
            ]
        )
    else:
        if args.erase_flash:
            if not args.dry_run and not args.yes:
                confirmation = input("Type INSTALL to erase the chip and install firmware: ").strip()
                if confirmation != "INSTALL":
                    print("Factory installation cancelled.")
                    return 2
            commands.append(
                [
                    _python_command(), "-m", "esptool", "--chip", config.chip,
                    "--port", args.port, "erase-flash",
                ]
            )
        commands.append(
            build_flash_command(
                target=args.target,
                port=args.port,
                build_dir=build_dir,
                baud=args.baud,
                partitions_path=project_dir / "partitions.csv",
            )
        )
    for command in commands:
        if args.dry_run:
            print("$ " + " ".join(str(part) for part in command))
        else:
            _run(command, cwd=project_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
