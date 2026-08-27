import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT_ROOT / "tests/cpp/management_policy_test.cpp"


def _visual_studio_compiler():
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if not program_files_x86:
        return None
    vswhere = Path(program_files_x86) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if not vswhere.is_file():
        return None
    result = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    root = Path(result.stdout.strip())
    vcvars = root / "VC/Auxiliary/Build/vcvars64.bat"
    return vcvars if vcvars.is_file() else None


class ManagementPolicyCppTests(unittest.TestCase):
    def test_policy_transition_table_and_ipv4_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / ("management_policy_test.exe" if os.name == "nt" else "management_policy_test")
            include = PROJECT_ROOT / "src"
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run(
                    [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", f"-I{include}", str(SOURCE), "-o", str(output)],
                    check=True,
                )
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                object_file = Path(tmp) / "management_policy_test.obj"
                command = (
                    f'call "{vcvars}" >nul && cl /nologo /std:c++17 /W4 /WX '
                    f'/I"{include}" "{SOURCE}" /Fo:"{object_file}" /Fe:"{output}"'
                )
                compile_script = Path(tmp) / "compile-management-policy.cmd"
                compile_script.write_text("@echo off\n" + command + "\n", encoding="utf-8")
                subprocess.run(["cmd", "/d", "/c", str(compile_script)], check=True)
            else:
                self.fail("A C++17 host compiler is required for the policy contract test")

            subprocess.run([str(output)], check=True)


if __name__ == "__main__":
    unittest.main()
