# Releasing

## Version source of truth

The single source of truth is the file VERSION at the repository root, holding a semantic
version (currently 0.1.0).

- CMakeLists.txt reads VERSION into PROJECT_VER before project(), so the firmware reports the
  official version at boot (the "App version" line) and in the startup audit event.
- scripts/package_release.py rejects any --version that does not match VERSION, so a tag and the
  packaged artifacts can never drift.

## How to release

Prerequisite (for the automatic changelog): git-cliff. Install with
"scoop install git-cliff" or "winget install git-cliff". Without it the helper
still works but leaves CHANGELOG.md unchanged (or pass --skip-changelog).

Run the local helper from the repository root:

    python scripts/release.py

It will:

1. read the current VERSION and propose the next patch version (last digit + 1);
2. ask for confirmation, or accept --minor / --major / --version 0.2.0;
3. run the host test suite (skip with --skip-tests);
4. regenerate CHANGELOG.md from conventional commits via git-cliff (skip with --skip-changelog);
5. write VERSION + CHANGELOG.md, commit, push, create an annotated tag vX.Y.Z and push it.

Safety flags:

    --dry-run        print the plan without changing anything
    --no-push        commit and tag locally, do not push
    --yes            skip the interactive confirmation (for scripting)
    --skip-changelog do not regenerate CHANGELOG.md

## What CI does after the tag

Pushing a tag v* triggers .github/workflows/release.yml, which:

- builds all three targets (t-poe-pro, esp32-s3-eth, waveshare-esp32p4-eth);
- packages, per board, a factory image, an app image, a flash bundle and a manifest via
  scripts/package_release.py (reading offsets/chip/mode/size from flasher_args.json);
- scans artifacts for secrets and generates a sorted SHA256SUMS.txt;
- attests build provenance and publishes a prerelease with all assets.

## Rules

- Release only from a clean tree on main; the helper refuses a dirty tree.
- The tag must equal "v" + VERSION; both the helper and CI enforce this.
- Do not hand-edit VERSION in a release commit; use the helper.
- 0.x releases are marked prerelease. A failed build, checksum, scan or attestation prevents
  publication.
