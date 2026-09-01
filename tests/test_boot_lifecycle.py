"""Regression tests for startup rollback and service lifetime ownership."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_management_policy_cpp import _visual_studio_compiler


ROOT = Path(__file__).resolve().parents[1]


class BootLifecycleTests(unittest.TestCase):
    def test_rollback_owner_is_executable_and_idempotent(self):
        source = ROOT / "tests/cpp/boot_services_test.cpp"
        implementation = ROOT / "src/core/boot_services.cpp"
        self.assertTrue(source.is_file())
        self.assertTrue(implementation.is_file())
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            output = work / ("boot_services_test.exe" if os.name == "nt" else "boot_services_test")
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run(
                    [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                     f"-I{ROOT / 'src'}", str(source), str(implementation), "-o", str(output)],
                    check=True,
                )
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                include_flags = f'/I"{ROOT / "src"}"'
                script = work / "compile-boot-services.cmd"
                script.write_text(
                    f'@echo off\ncall "{vcvars}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX /c '
                    f'{include_flags} "{source}" /Fo:"{work / "boot_services_test.obj"}" && '
                    f'cl /nologo /std:c++17 /EHsc /W4 /WX /c {include_flags} "{implementation}" '
                    f'/Fo:"{work / "boot_services.obj"}" && '
                    f'link /OUT:"{output}" "{work / "boot_services_test.obj"}" "{work / "boot_services.obj"}"\n',
                    encoding="utf-8")
                subprocess.run(["cmd", "/d", "/c", str(script)], check=True)
            else:
                self.fail("A C++17 host compiler is required for boot rollback tests")
            subprocess.run([str(output)], check=True)

    def test_app_main_routes_failures_through_rollback(self):
        source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.assertIn("BootRollback startup_rollback", source)
        self.assertIn("rollback_startup", source)
        self.assertIn("startup_rollback.track", source)
        self.assertNotIn("return; // Stop initialization", source)
        self.assertIn("rollback_network", source)
        self.assertIn("network->shutdown", source)
        self.assertIn("TimeManager::clearWiFiAutoSync", source)

    def test_lifetime_sensitive_shutdowns_release_dependants(self):
        reporting = (ROOT / "src/core/reporting_engine.cpp").read_text(encoding="utf-8")
        filesystem = (ROOT / "src/core/filesystem_task_delegate.cpp").read_text(encoding="utf-8")
        self.assertIn("queue_.reset()", reporting)
        self.assertIn("const bool had_resources", filesystem)


if __name__ == "__main__":
    unittest.main()
