#!/usr/bin/env python3
"""Fail when repository or release artifacts contain credential material."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
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

ADMIN_PASSWORD_VALUE_PATTERN = re.compile(
    br'"admin_password"\s*:\s*"((?:\\.|[^"\\])*)"'
)
REPOSITORY_ADMIN_PASSWORD_EXCEPTIONS = {
    "README.md": {b"your-fixed-password-here": 1},
    "CONFIG.md": {b"your-fixed-password-here": 1},
}

IGNORED_DIRECTORIES = {".git", ".pio", ".venv", "__pycache__", "test-results"}
SELF = Path(__file__).resolve()


def _allowed_admin_password_offsets(
    repository_path: str | None,
    content: bytes,
) -> set[int]:
    exceptions = REPOSITORY_ADMIN_PASSWORD_EXCEPTIONS.get(repository_path or "", {})
    allowed_offsets: set[int] = set()
    for placeholder, maximum_occurrences in exceptions.items():
        matching_offsets = [
            match.start()
            for match in ADMIN_PASSWORD_VALUE_PATTERN.finditer(content)
            if match.group(1) == placeholder
        ]
        allowed_offsets.update(matching_offsets[:maximum_occurrences])
    return allowed_offsets


def _scan_bytes(
    path: str,
    content: bytes,
    denylist: Sequence[bytes],
    repository_path: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    allowed_admin_password_offsets = _allowed_admin_password_offsets(
        repository_path,
        content,
    )
    for rule, pattern in RULES:
        for match in pattern.finditer(content):
            if (
                rule == "nonempty-admin-password"
                and match.start() in allowed_admin_password_offsets
            ):
                continue
            findings.append(Finding(path, rule, match.start()))
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


def _iter_publishable_repository_files(repository_root: Path) -> Iterable[Path]:
    """Yield tracked and non-ignored untracked files from a Git repository.

    A non-Git directory falls back to the recursive behavior used by unit tests
    and exported source archives. Explicit --path scans always remain exhaustive.
    """
    root = Path(repository_root).resolve()
    try:
        result = subprocess.run(
            [
                "git", "-C", str(root), "ls-files", "-z", "--cached",
                "--others", "--exclude-standard",
            ],
            check=False,
            capture_output=True,
        )
    except OSError:
        result = None

    if result is None or result.returncode != 0:
        yield from _iter_files([root])
        return

    for raw_relative in result.stdout.split(b"\0"):
        if not raw_relative:
            continue
        relative = Path(raw_relative.decode("utf-8", errors="surrogateescape"))
        candidate = root / relative
        if not candidate.is_file():
            continue
        if any(part in IGNORED_DIRECTORIES for part in relative.parts):
            continue
        if "tests" in relative.parts:
            continue
        if candidate.resolve() == SELF:
            continue
        yield candidate


def scan_paths(
    paths: Iterable[Path],
    denylist: Sequence[bytes] = (),
    repository_root: Path | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    resolved_repository_root = repository_root.resolve() if repository_root else None
    for path in _iter_files(paths):
        repository_path = None
        if resolved_repository_root is not None:
            try:
                repository_path = path.resolve().relative_to(
                    resolved_repository_root
                ).as_posix()
            except ValueError:
                pass
        if path.name.lower() in {"device-config.json", "server.key"}:
            findings.append(Finding(str(path), "secret-filename", 0))
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"Cannot scan {path}: {exc}") from exc
        findings.extend(
            _scan_bytes(str(path), content, denylist, repository_path)
        )
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
        paths.extend(_iter_publishable_repository_files(args.repository))
    if not paths:
        parser.error("provide --repository or at least one --path")
    findings = scan_paths(
        paths,
        _read_denylist(args.denylist),
        repository_root=args.repository,
    )
    for finding in findings:
        print(finding.safe_description())
    if findings:
        print(f"Secret scan failed: {len(findings)} finding(s); values were not printed.")
        return 1
    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
