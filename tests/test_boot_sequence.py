"""Regression contract for the injectable SDK-independent boot sequence."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    from test_management_policy_cpp import _visual_studio_compiler
except ImportError:  # pragma: no cover - direct invocation outside discovery
    from tests.test_management_policy_cpp import _visual_studio_compiler


ROOT = Path(__file__).resolve().parents[1]


class BootSequenceTests(unittest.TestCase):
    def test_injected_boot_operations_have_deterministic_failure_cleanup(self):
        source = ROOT / "tests/cpp/boot_sequence_test.cpp"
        implementation = ROOT / "src/core/boot_sequence.cpp"
        self.assertTrue((ROOT / "src/core/boot_sequence.h").is_file())
        self.assertTrue(implementation.is_file())

        # MSVC/Windows Defender can retain the just-linked fixture briefly after
        # it exits.  Test behavior is already asserted before cleanup; do not
        # turn that transient temporary-file lock into a suite failure.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            work = Path(tmp)
            output = work / ("boot_sequence_test.exe" if os.name == "nt" else "boot_sequence_test")
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run(
                    [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                     f"-I{ROOT / 'src'}", str(source),
                     str(ROOT / "src/core/boot_services.cpp"), str(implementation),
                     "-o", str(output)],
                    check=True,
                )
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                script = work / "compile-boot-sequence.cmd"
                script.write_text(
                    f'@echo off\npushd "{work}" && call "{vcvars}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX '
                    f'/I"{ROOT / "src"}" "{source}" "{ROOT / "src/core/boot_services.cpp"}" '
                    f'"{implementation}" /Fe:"{output}" && popd\n',
                    encoding="utf-8",
                )
                subprocess.run(["cmd", "/d", "/c", str(script)], check=True)
            else:
                self.fail("A C++17 host compiler is required for boot sequence tests")
            subprocess.run([str(output)], check=True)

    def test_app_main_exposes_named_essential_boot_phases(self):
        source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.assertIn("BootSequence startup_sequence", source)
        for phase in ("async_storage", "filesystem_delegate", "reporting_engine", "network_engine"):
            self.assertIn(f'"{phase}"', source)


if __name__ == "__main__":
    unittest.main()
