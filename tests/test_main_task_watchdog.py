"""Regression and host execution of the firmware's main-task TWDT lifecycle."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_management_policy_cpp import _visual_studio_compiler

ROOT = Path(__file__).resolve().parents[1]


class MainTaskWatchdogTests(unittest.TestCase):
    def test_main_does_not_register_unconditionally(self):
        source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"if\s*\(\s*true\s*\|\|\s*wdt_cfg\.enabled", source),
                          "app_main must not bypass watchdog.enabled when subscribing")

    def test_firmware_watchdog_lifecycle(self):
        self.assertTrue((ROOT / "src/core/main_task_watchdog.h").is_file(),
                        "The main-task watchdog lifecycle must be executable on the host")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            output = work / ("watchdog_test.exe" if os.name == "nt" else "watchdog_test")
            includes = [ROOT / "tests/cpp/watchdog_stubs", ROOT / "src"]
            source = ROOT / "tests/cpp/main_task_watchdog_test.cpp"
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                                *[f"-I{p}" for p in includes], str(source), "-o", str(output)],
                               check=True)
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                include_flags = " ".join(f'/I"{p}"' for p in includes)
                script = work / "compile-watchdog.cmd"
                script.write_text(
                    f'@echo off\ncall "{vcvars}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX '
                    f'{include_flags} "{source}" /Fo:"{work / "watchdog.obj"}" /Fe:"{output}"\n',
                    encoding="utf-8")
                # MSVC's persistent helper processes can retain cwd after cl
                # exits. Keep cwd outside the temporary directory so cleanup
                # does not fail with WinError 32; all outputs have explicit paths.
                subprocess.run(["cmd", "/d", "/c", str(script)], check=True)
            else:
                self.fail("A C++17 host compiler is required for watchdog lifecycle tests")
            subprocess.run([str(output)], check=True)


if __name__ == "__main__":
    unittest.main()
