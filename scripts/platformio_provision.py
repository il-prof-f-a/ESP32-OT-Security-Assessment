"""PlatformIO pre-build hook for private credential provisioning."""

from pathlib import Path
import sys

Import("env")  # type: ignore[name-defined]  # Provided by PlatformIO/SCons.

project_dir = Path(env.subst("$PROJECT_DIR")).resolve()  # type: ignore[name-defined]
scripts_dir = project_dir / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from credential_provisioning import provision


result = provision(project_dir, Path(env.subst("$BUILD_DIR")))  # type: ignore[name-defined]
env.Append(CPPPATH=[str(result.header_path.parent)])  # type: ignore[name-defined]
print(f"Credential provisioning ready: {result.credentials_dir}")
