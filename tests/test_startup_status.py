"""Host regression tests for derived startup service readiness."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    from test_management_policy_cpp import _visual_studio_compiler
except ImportError:  # pragma: no cover - direct invocation outside test discovery
    try:
        from tests.test_management_policy_cpp import _visual_studio_compiler
    except ImportError:
        _visual_studio_compiler = lambda: None


class StartupStatusTests(unittest.TestCase):
    def test_state_model_derives_global_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / ("startup_status.exe" if os.name == "nt" else "startup_status")
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run(
                    [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                     f"-I{ROOT / 'src'}", str(ROOT / "tests/cpp/startup_status_test.cpp"),
                     "-o", str(output)], check=True)
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                script = Path(tmp) / "compile-startup-status.cmd"
                obj = Path(tmp) / "startup_status.obj"
                script.write_text(
                    f'@echo off\ncall "{vcvars}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX '
                    f'/I"{ROOT / "src"}" /c "{ROOT / "tests/cpp/startup_status_test.cpp"}" '
                    f'/Fo:"{obj}" && link /OUT:"{output}" "{obj}"\n',
                    encoding="utf-8")
                subprocess.run(["cmd", "/d", "/c", str(script)], check=True)
            else:
                self.fail("A C++17 host compiler is required for startup status tests")
            subprocess.run([str(output)], check=True)

    def test_main_no_longer_emits_static_fully_operational_service_list(self):
        source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.assertIn("StartupStatusSnapshot", source)
        self.assertIn("startupSnapshotGlobalState", source)
        self.assertNotIn('"status":"fully_operational","services":["network_engine"', source)


if __name__ == "__main__":
    unittest.main()
