from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "p4_sdkconfig.py"


def load_helper():
    spec = spec_from_file_location("p4_sdkconfig_test", HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {HELPER}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P4SdkconfigNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdkconfig = load_helper()

    def test_waveshare_profile_normalizes_a_stale_16mb_sdkconfig_to_32mb(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sdkconfig.waveshare-esp32p4-eth"
            path.write_text(
                "CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y\n"
                "# CONFIG_ESPTOOLPY_FLASHSIZE_32MB is not set\n",
                encoding="utf-8",
            )

            changed = self.sdkconfig.normalize_p4_sdkconfig(
                "waveshare-esp32p4-eth", path
            )

            self.assertTrue(changed)
            content = path.read_text(encoding="utf-8")
            self.assertIn("# CONFIG_ESPTOOLPY_FLASHSIZE_16MB is not set", content)
            self.assertIn("CONFIG_ESPTOOLPY_FLASHSIZE_32MB=y", content)

    def test_guition_profile_leaves_its_16mb_sdkconfig_unchanged(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sdkconfig.guition-jc-esp32p4-m3-dev"
            original = (
                "CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y\n"
                "# CONFIG_ESPTOOLPY_FLASHSIZE_32MB is not set\n"
            )
            path.write_text(original, encoding="utf-8")

            changed = self.sdkconfig.normalize_p4_sdkconfig(
                "guition-jc-esp32p4-m3-dev", path
            )

            self.assertFalse(changed)
            self.assertEqual(path.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
