"""PlatformIO pre-build hook for deterministic public build assets."""

from pathlib import Path
import sys


Import("env")  # type: ignore[name-defined]  # Provided by PlatformIO/SCons.


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
