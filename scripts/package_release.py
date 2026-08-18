#!/usr/bin/env python3
"""Create deterministic, manifest-driven firmware release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Callable, NamedTuple, Sequence
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")


class ReleaseProducts(NamedTuple):
    factory: Path
    app: Path
    bundle: Path
    manifest: Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    candidate = build_dir / aliases.get(basename, basename)
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(f"Missing flash file {configured!r} in {build_dir}")


def _default_merge_runner(command: list[str], destination: Path) -> None:
    subprocess.run(command, check=True)
    if not destination.is_file():
        raise RuntimeError(f"esptool did not create {destination}")


def _write_deterministic_zip(destination: Path, files: list[Path]) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source in sorted(files, key=lambda item: item.name):
            info = zipfile.ZipInfo(source.name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, source.read_bytes())


def package_release(
    *,
    environment: str,
    build_dir: Path,
    version: str,
    output_dir: Path,
    merge_runner: Callable[[list[str], Path], None] | None = None,
) -> ReleaseProducts:
    if not SEMVER.fullmatch(version):
        raise ValueError(f"Invalid semantic version: {version!r}")
    build_dir = Path(build_dir).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    flasher_path = build_dir / "flasher_args.json"
    if not flasher_path.is_file():
        raise FileNotFoundError(f"Missing {flasher_path}")
    flasher = json.loads(flasher_path.read_text(encoding="utf-8"))
    settings = flasher.get("flash_settings", {})
    chip = flasher.get("extra_esptool_args", {}).get("chip")
    mode = settings.get("flash_mode")
    size = settings.get("flash_size")
    frequency = settings.get("flash_freq")
    flash_files = flasher.get("flash_files")
    if not chip or not mode or not size or not frequency or not isinstance(flash_files, dict):
        raise ValueError("flasher_args.json is missing chip, flash settings or flash_files")

    entries: list[tuple[int, Path]] = []
    for offset_text, configured_path in flash_files.items():
        entries.append((int(offset_text, 0), _resolve_flash_file(build_dir, configured_path)))
    entries.sort(key=lambda entry: entry[0])
    firmware = next((path for _, path in entries if path.name == "firmware.bin"), None)
    if firmware is None:
        raise ValueError("flash_files does not identify firmware.bin")

    prefix = f"esp32-ot-security-{environment}-v{version}"
    factory = output_dir / f"{prefix}-factory.bin"
    app = output_dir / f"{prefix}-app.bin"
    bundle = output_dir / f"{prefix}-flash-bundle.zip"
    manifest_path = output_dir / f"{prefix}-manifest.json"
    shutil.copyfile(firmware, app)

    merge_command = [
        sys.executable,
        "-m",
        "esptool",
        "--chip",
        chip,
        "merge_bin",
        "-o",
        str(factory),
        "--flash_mode",
        mode,
        "--flash_size",
        size,
        "--flash_freq",
        frequency,
    ]
    for offset, source in entries:
        merge_command.extend((hex(offset), str(source)))
    (merge_runner or _default_merge_runner)(merge_command, factory)

    manifest = {
        "schema": 1,
        "project": "ESP32-OT-Security-Assessment",
        "version": version,
        "environment": environment,
        "chip": chip,
        "flash_mode": mode,
        "flash_size": size,
        "flash_frequency": frequency,
        "factory_requires_erase": True,
        "factory": {"name": factory.name, "sha256": _sha256(factory)},
        "app": {"name": app.name, "sha256": _sha256(app)},
        "files": [
            {"name": source.name, "offset": offset, "sha256": _sha256(source)}
            for offset, source in entries
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    _write_deterministic_zip(bundle, [source for _, source in entries] + [manifest_path])
    return ReleaseProducts(factory=factory, app=app, bundle=bundle, manifest=manifest_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    repository_version = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if args.version != repository_version:
        parser.error(
            f"version drift: --version={args.version!r}, VERSION={repository_version!r}"
        )
    package_release(
        environment=args.environment,
        build_dir=args.build_dir,
        version=args.version,
        output_dir=args.output_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
