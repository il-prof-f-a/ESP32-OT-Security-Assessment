#!/usr/bin/env python3
"""Local release helper: bump VERSION, regenerate CHANGELOG.md, commit, push, tag and push the tag.

The actual firmware build, packaging and GitHub release publication happen in CI
(.github/workflows/release.yml), triggered by pushing the tag created here.

CHANGELOG.md is regenerated with git-cliff (optional). Install:
    scoop install git-cliff     # or:  winget install git-cliff
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = PROJECT_ROOT / "VERSION"
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def run(command: list[str]) -> None:
    print(f"  $ {' '.join(command)}")
    result = subprocess.run(command, cwd=PROJECT_ROOT, text=True)
    if result.returncode != 0:
        fail(f"command failed: {' '.join(command)}")


def current_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def next_version(version: str, part: str) -> str:
    match = SEMVER.fullmatch(version)
    if not match:
        fail(f"VERSION '{version}' is not valid SemVer")
    major, minor, patch = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    if part == "major":
        major, minor, patch = major + 1, 0, 0
    elif part == "minor":
        minor, patch = minor + 1, 0
    else:
        patch += 1
    return f"{major}.{minor}.{patch}"


def git_clean() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"], cwd=PROJECT_ROOT, capture_output=True, text=True
    )
    return result.stdout.strip() == ""


def generate_changelog(tag: str) -> bool:
    cliff = shutil.which("git-cliff") or shutil.which("git-cliff.exe")
    if not cliff:
        print("warning: git-cliff not found; CHANGELOG.md not regenerated")
        print("         install it with: scoop install git-cliff  (or winget install git-cliff)")
        return False
    print("regenerating CHANGELOG.md with git-cliff...")
    run([cliff, "--config", "cliff.toml", "--tag", tag, "--output", "CHANGELOG.md"])
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--major", action="store_true", help="bump the major version")
    parser.add_argument("--minor", action="store_true", help="bump the minor version")
    parser.add_argument("--version", help="set an explicit version, e.g. 0.2.0")
    parser.add_argument("--current", action="store_true", help="tag the current version without bumping (first release)")
    parser.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    parser.add_argument("--no-push", action="store_true", help="commit and tag locally, do not push")
    parser.add_argument("--skip-tests", action="store_true", help="skip the host test suite")
    parser.add_argument("--skip-changelog", action="store_true", help="do not regenerate CHANGELOG.md")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    args = parser.parse_args(argv)

    current = current_version()
    if args.current:
        target = current
    elif args.version:
        target = args.version.strip()
    else:
        part = "major" if args.major else ("minor" if args.minor else "patch")
        target = next_version(current, part)

    if not SEMVER.fullmatch(target):
        fail(f"'{target}' is not a valid semantic version")
    if target == current and not args.current:
        fail(f"target version '{target}' equals the current version (use --current to tag it)")

    print(f"current version : {current}")
    print(f"target version  : {target}")
    print(f"tag             : v{target}")

    if args.dry_run:
        print("dry-run: nothing written, committed or pushed")
        return 0

    if not args.yes:
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("aborted")
            return 0

    if not git_clean():
        fail("working tree is not clean; commit or stash changes first")

    if not args.skip_tests:
        print("running host tests...")
        run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"])

    if target == current:
        print(f"no version bump ({target} is already the current version)")
    else:
        print(f"writing VERSION = {target}")
        VERSION_FILE.write_text(target + "\n", encoding="utf-8")
        run(["git", "add", "VERSION"])

        if not args.skip_changelog:
            if generate_changelog(f"v{target}"):
                run(["git", "add", "CHANGELOG.md"])

        run(["git", "commit", "-m", f"chore: release v{target}"])

    if not args.no_push:
        run(["git", "push"])
    run(["git", "tag", "-a", f"v{target}", "-m", f"Release v{target}"])
    if not args.no_push:
        run(["git", "push", "origin", f"v{target}"])

    print(f"\nDone. Pushed tag v{target}; CI will build, package and publish the release.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
