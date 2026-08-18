#!/usr/bin/env python3
"""Fail when repository or release artifacts contain credential material."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
from typing import Iterable, NamedTuple, Sequence
import zipfile


class Finding(NamedTuple):
    path: str
    rule: str
    offset: int

    def safe_description(self) -> str:
        return f"{self.path}: rule={self.rule}, byte_offset={self.offset}"


RULES = (
    ("private-key-pem", re.compile(
        br"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\r\n]+"
        br"[A-Za-z0-9+/=\r\n]{1,4096}?"
        br"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    )),
    ("removed-generated-symbol", re.compile(
        br"kProvisioningApPassword|kServerPrivateKeyPem|ESP32_OT_CREDENTIALS_DIR"
    )),
    ("nonempty-admin-password", re.compile(
        br'"admin_password"\s*:\s*"(?=[^"\\])'
    )),
    ("private-windows-path", re.compile(
        br"[A-Za-z]:\\(?:Users|Documents and Settings)\\[^\\\x00\r\n]+"
    )),
)

IGNORED_DIRECTORIES = {".git", ".pio", ".venv", "__pycache__", "test-results"}
SELF = Path(__file__).resolve()


def _scan_bytes(path: str, content: bytes, denylist: Sequence[bytes]) -> list[Finding]:
    findings: list[Finding] = []
    for rule, pattern in RULES:
        findings.extend(Finding(path, rule, match.start()) for match in pattern.finditer(content))
    for index, denied in enumerate(denylist, start=1):
        if not denied:
            continue
        offset = content.find(denied)
        while offset >= 0:
            findings.append(Finding(path, f"private-denylist-{index}", offset))
            offset = content.find(denied, offset + 1)
    return findings


def _iter_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        path = Path(path)
        if path.is_file():
            yield path
            continue
        if path.is_dir():
            for candidate in path.rglob("*"):
                if not candidate.is_file():
                    continue
                if any(part in IGNORED_DIRECTORIES for part in candidate.parts):
                    continue
                if candidate.resolve() == SELF:
                    continue
                if "tests" in candidate.parts:
                    continue
                yield candidate


def scan_paths(paths: Iterable[Path], denylist: Sequence[bytes] = ()) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_files(paths):
        if path.name.lower() in {"device-config.json", "server.key"}:
            findings.append(Finding(str(path), "secret-filename", 0))
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"Cannot scan {path}: {exc}") from exc
        findings.extend(_scan_bytes(str(path), content, denylist))
        if path.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for member in sorted(archive.infolist(), key=lambda item: item.filename):
                        if member.is_dir():
                            continue
                        member_path = f"{path}!{member.filename}"
                        if Path(member.filename).name.lower() in {"device-config.json", "server.key"}:
                            findings.append(Finding(member_path, "secret-filename", 0))
                        findings.extend(_scan_bytes(member_path, archive.read(member), denylist))
            except zipfile.BadZipFile as exc:
                raise RuntimeError(f"Invalid ZIP artifact {path}: {exc}") from exc
    return sorted(findings)


def _read_denylist(path: Path | None) -> list[bytes]:
    if path is None or not path.is_file():
        return []
    return [
        line.strip().encode("utf-8")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--path", type=Path, action="append", default=[])
    parser.add_argument("--denylist", type=Path)
    args = parser.parse_args(argv)
    paths = list(args.path)
    if args.repository:
        paths.append(args.repository)
    if not paths:
        parser.error("provide --repository or at least one --path")
    findings = scan_paths(paths, _read_denylist(args.denylist))
    for finding in findings:
        print(finding.safe_description())
    if findings:
        print(f"Secret scan failed: {len(findings)} finding(s); values were not printed.")
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
