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


SUPPORTED_ENVIRONMENTS = {
    "t-poe-pro",
    "esp32-s3-eth",
    "waveshare-esp32p4-eth",
    "guition-jc-esp32p4-m3-dev",
}
GUITION_ENVIRONMENT = "guition-jc-esp32p4-m3-dev"
COPROCESSOR_VERSION = "esp-hosted-3.0.6-idf-5.5.3"


class ReleaseProducts(NamedTuple):
    factory: Path
    app: Path
    bundle: Path
    manifest: Path
    coprocessor_factory: Path | None
    coprocessor_app: Path | None


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
        "esp32_ot_esp32c6_coprocessor.bin": "firmware.bin",
        "storage.bin": "littlefs.bin",
    }
    candidate = build_dir / aliases.get(basename, basename)
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(f"Missing flash file {configured!r} in {build_dir}")


def _load_flash_manifest(build_dir: Path) -> tuple[str, str, str, str, list[tuple[int, Path]]]:
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
    entries = sorted(
        (int(offset, 0), _resolve_flash_file(build_dir, configured))
        for offset, configured in flash_files.items()
    )
    return chip, mode, size, frequency, entries


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
    c6_build_dir: Path | None = None,
    merge_runner: Callable[[list[str], Path], None] | None = None,
) -> ReleaseProducts:
    if not SEMVER.fullmatch(version):
        raise ValueError(f"Invalid semantic version: {version!r}")
    if environment not in SUPPORTED_ENVIRONMENTS:
        raise ValueError(f"Unsupported release environment: {environment!r}")
    if environment == GUITION_ENVIRONMENT and c6_build_dir is None:
        raise FileNotFoundError("Guition releases require the matching ESP32-C6 build directory")
    if environment != GUITION_ENVIRONMENT and c6_build_dir is not None:
        raise ValueError("An ESP32-C6 image is valid only for the Guition release")
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
        "merge-bin",
        "-o",
        str(factory),
        "--flash-mode",
        mode,
        "--flash-size",
        size,
        "--flash-freq",
        frequency,
    ]
    for offset, source in entries:
        merge_command.extend((hex(offset), str(source)))
    (merge_runner or _default_merge_runner)(merge_command, factory)

    bundle_files = [source for _, source in entries]
    coprocessor_factory = None
    coprocessor_app = None
    coprocessor_manifest = None
    if c6_build_dir is not None:
        c6_build_dir = Path(c6_build_dir).resolve()
        c6_chip, c6_mode, c6_size, c6_frequency, c6_entries = _load_flash_manifest(c6_build_dir)
        if c6_chip != "esp32c6":
            raise ValueError(f"Guition coprocessor manifest must target esp32c6, not {c6_chip!r}")
        c6_firmware = next((path for _, path in c6_entries if path.name == "firmware.bin"), None)
        if c6_firmware is None:
            raise ValueError("ESP32-C6 flash_files does not identify firmware.bin")

        coprocessor_factory = output_dir / f"{prefix}-c6-factory.bin"
        coprocessor_app = output_dir / f"{prefix}-c6-app.bin"
        shutil.copyfile(c6_firmware, coprocessor_app)
        c6_merge_command = [
            sys.executable, "-m", "esptool", "--chip", c6_chip,
            "merge-bin", "-o", str(coprocessor_factory),
            "--flash-mode", c6_mode, "--flash-size", c6_size,
            "--flash-freq", c6_frequency,
        ]
        c6_packaged_entries = []
        for offset, source in c6_entries:
            c6_merge_command.extend((hex(offset), str(source)))
            packaged = output_dir / f"{prefix}-c6-{offset:#x}-{source.name}"
            shutil.copyfile(source, packaged)
            c6_packaged_entries.append(
                {"name": packaged.name, "offset": offset, "sha256": _sha256(packaged)}
            )
            bundle_files.append(packaged)
        (merge_runner or _default_merge_runner)(c6_merge_command, coprocessor_factory)
        bundle_files.extend((coprocessor_factory, coprocessor_app))
        coprocessor_manifest = {
            "chip": c6_chip,
            "version_pair": COPROCESSOR_VERSION,
            "transport": "sdio-rpc-v2",
            "flash_mode": c6_mode,
            "flash_size": c6_size,
            "flash_frequency": c6_frequency,
            "factory": {
                "name": coprocessor_factory.name,
                "sha256": _sha256(coprocessor_factory),
            },
            "app": {"name": coprocessor_app.name, "sha256": _sha256(coprocessor_app)},
            "files": c6_packaged_entries,
        }

    manifest = {
        "schema": 1,
        "project": "ESP32-OT-Security-Assessment",
        "version": version,
        "environment": environment,
        "board_id": environment,
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
    if coprocessor_manifest is not None:
        manifest["coprocessor"] = coprocessor_manifest
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    _write_deterministic_zip(bundle, bundle_files + [manifest_path])
    return ReleaseProducts(
        factory=factory,
        app=app,
        bundle=bundle,
        manifest=manifest_path,
        coprocessor_factory=coprocessor_factory,
        coprocessor_app=coprocessor_app,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--c6-build-dir", type=Path)
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
        c6_build_dir=args.c6_build_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
