"""PlatformIO pre-build hook for deterministic public build assets."""

import os
from pathlib import Path
import sys


Import("env")  # type: ignore[name-defined]  # Provided by PlatformIO/SCons.


_MARKER = "ESP32_OT_EMBEDDED_CREDENTIALS"


def _embedded_enabled(build_env) -> bool:
    """Return True when embedded credentials should be generated.

    An explicitly set ESP32_OT_EMBEDDED_CREDENTIALS environment variable wins
    (CI forces "0" so releases always use provisioning); otherwise fall back to
    the -D build flag so it can be enabled from platformio.ini in VSCode.
    """
    explicit = os.environ.get("ESP32_OT_EMBEDDED_CREDENTIALS")
    if explicit is not None:
        return explicit == "1"
    defines = build_env.get("CPPDEFINES") or []
    for item in defines:
        if isinstance(item, (tuple, list)) and item:
            if str(item[0]) == _MARKER and str(item[1]) == "1":
                return True
        elif isinstance(item, str) and f"{_MARKER}=1" in item:
            return True
    cflags = build_env.get("CCFLAGS") or []
    for item in cflags:
        if isinstance(item, str) and f"-D{_MARKER}=1" in item:
            return True
    return False


if _embedded_enabled(env):  # type: ignore[name-defined]
    os.environ["ESP32_OT_EMBEDDED_CREDENTIALS"] = "1"

project_dir = Path(env.subst("$PROJECT_DIR")).resolve()  # type: ignore[name-defined]
scripts_dir = project_dir / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from build_assets import generate_build_assets


result = generate_build_assets(
    project_dir, Path(env.subst("$BUILD_DIR")), board=env.subst("$PIOENV")
)  # type: ignore[name-defined]
env.Append(CPPPATH=[str(result.header_path.parent)])  # type: ignore[name-defined]
print(f"Public build assets ready: {result.header_path}")
