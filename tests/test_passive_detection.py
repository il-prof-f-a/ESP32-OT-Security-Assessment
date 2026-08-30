"""Compile and execute the exact passive dispatch used by the firmware."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_management_policy_cpp import _visual_studio_compiler

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PassiveDetectionTests(unittest.TestCase):
    def test_independent_runtime_contract_is_wired_once(self):
        main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")
        config = (PROJECT_ROOT / "src/core/configuration_manager.cpp").read_text(encoding="utf-8")
        api = (PROJECT_ROOT / "src/web/passive_detection_api.cpp").read_text(encoding="utf-8")
        server = (PROJECT_ROOT / "src/web/web_server.cpp").read_text(encoding="utf-8")
        main = (PROJECT_ROOT / "src/main.cpp").read_text(encoding="utf-8")
        ui = (PROJECT_ROOT / "src/web/ui/passive_detection.html").read_text(encoding="utf-8")
        self.assertEqual(main.count("trackPacket(pkt)"), 1)
        self.assertEqual(main.count("analyzePacketWithReport(pkt"), 1)
        self.assertIn("PassiveDetection::dispatch", main)
        self.assertIn("loadFlags", config)
        self.assertIn("/api/passive-detection/config", server)
        self.assertIn("Presence never grants authorization on its own", main)
        for key in ("ids_enabled", "signatures_enabled", "network_presence_enabled"):
            self.assertGreaterEqual(ui.count(key), 1)

    def test_legacy_aliases_and_safe_signature_database_contract(self):
        config = (PROJECT_ROOT / "src/core/configuration_manager.cpp").read_text(encoding="utf-8")
        detector = (PROJECT_ROOT / "src/assessment/signature_detector.cpp").read_text(encoding="utf-8")
        self.assertIn('advanced_ids', config)
        self.assertIn('network_presence', config)
        self.assertIn('if (!isEnabled() || !payload', detector)
        self.assertIn("setEnabled", detector)

    def test_all_eight_module_combinations_and_live_transitions(self):
        source = PROJECT_ROOT / "tests/cpp/passive_detection_policy_test.cpp"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / ("passive-test.exe" if os.name == "nt" else "passive-test")
            include = PROJECT_ROOT / "src"
            cxx = shutil.which("g++") or shutil.which("clang++")
            if cxx:
                subprocess.run([cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                                f"-I{include}", str(source), "-o", str(output)], check=True)
            elif os.name == "nt" and (vcvars := _visual_studio_compiler()):
                script = Path(tmp) / "compile.cmd"
                script.write_text(
                    f'@echo off\ncall "{vcvars}" >nul && cl /nologo /std:c++17 /EHsc /W4 /WX '
                    f'/I"{include}" "{source}" /Fo:"{Path(tmp) / "test.obj"}" '
                    f'/Fe:"{output}"\n', encoding="utf-8")
                subprocess.run(["cmd", "/d", "/c", str(script)], check=True)
            else:
                self.fail("A C++17 compiler is required to test the actual dispatch policy")
            subprocess.run([str(output)], check=True)


if __name__ == "__main__":
    unittest.main()
