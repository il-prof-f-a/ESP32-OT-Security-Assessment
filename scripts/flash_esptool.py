#!/usr/bin/env python3
"""Build and flash an ESP32-OT-Security-Assessment firmware image."""

from __future__ import annotations

import argparse
import csv
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


def _artifact(build_dir: Path, name: str) -> Path:
    path = Path(build_dir) / name
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing {name} in {build_dir}. Run the PlatformIO build first."
        )
    return path


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
    bootloader = _artifact(build_dir, "bootloader.bin")
    partitions = _artifact(build_dir, "partitions.bin")
    firmware = _artifact(build_dir, "firmware.bin")
    app_offset = parse_application_offset(partitions_path or DEFAULT_PARTITIONS)
    command = list(esptool_command or [_python_command(), "-m", "esptool"])
    return [
        *command,
        "--chip",
        config.chip,
        "--port",
        port,
        "--baud",
        str(baud),
        "write-flash",
        "--flash-mode",
        "dio",
        "--flash-freq",
        "40m",
        "--flash-size",
        "detect",
        "0x1000",
        str(bootloader),
        "0x8000",
        str(partitions),
        hex(app_offset),
        str(firmware),
    ]


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
    subprocess.run(list(command), cwd=cwd, check=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--port", required=True, help="Serial port, e.g. COM10 or /dev/ttyUSB0")
    parser.add_argument("--baud", type=int, default=921600)
    parser.add_argument("--project-dir", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--no-build", action="store_true", help="Flash existing artifacts")
    parser.add_argument("--erase-flash", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    project_dir = args.project_dir.resolve()
    build_dir = (args.build_dir or default_build_dir(project_dir, args.target)).resolve()
    config = target_config(args.target)
    commands: list[list[str]] = []
    if not args.no_build:
        commands.append([*_platformio_command(), "run", "-e", config.environment])
    if args.erase_flash:
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
