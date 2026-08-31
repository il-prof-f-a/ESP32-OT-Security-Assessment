"""Host execution of the production coredump-inspection boundary."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_management_policy_cpp import _visual_studio_compiler

ROOT = Path(__file__).resolve().parents[1]


class CrashDiagnosticsTests(unittest.TestCase):
    def test_native_coredump_inspection_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            output = work / ("crash_diagnostics.exe" if os.name == "nt" else "crash_diagnostics")
            source = ROOT / "tests/cpp/crash_diagnostics_test.cpp"
            includes = [ROOT / "tests/cpp/crash_diagnostics_stubs", ROOT / "src"]
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run(
                    [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                     *[f"-I{path}" for path in includes], str(source), "-o", str(output)],
                    check=True,
                )
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                include_flags = " ".join(f'/I"{path}"' for path in includes)
                script = work / "compile-crash-diagnostics.cmd"
                script.write_text(
                    f'@echo off\ncall "{vcvars}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX '
                    f'{include_flags} "{source}" /Fo:"{work / "crash_diagnostics.obj"}" '
                    f'/Fe:"{output}"\n',
                    encoding="utf-8",
                )
                subprocess.run(["cmd", "/d", "/c", str(script)], check=True)
            else:
                self.fail("A C++17 host compiler is required for coredump tests")
            subprocess.run([str(output)], check=True)


if __name__ == "__main__":
    unittest.main()
