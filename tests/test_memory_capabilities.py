"""Contracts for the optional-PSRAM startup and allocation profile."""
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class MemoryCapabilityContractTests(unittest.TestCase):
    def test_boot_does_not_apply_psram_threshold_without_config_spiram(self):
        source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        section_start = source.index("size_t pre_async_internal_free")
        section_end = source.index("TaskConfig::forceHeapDefragmentation", section_start)
        section = source[section_start:section_end]
        threshold = section.index("if (psram_free < 65536)")
        guard = section.rfind("#ifdef CONFIG_SPIRAM", 0, threshold)
        self.assertGreaterEqual(guard, 0)
        self.assertGreater(section.index("#else", guard), threshold)
        self.assertIn("PSRAM support disabled; AsyncStorage will use internal RAM fallback", source)

    def test_psram_allocator_is_external_first_with_internal_fallback(self):
        allocator = (ROOT / "src/core/psram_allocator.h").read_text(encoding="utf-8")
        self.assertIn("allocatePreferred", allocator)
        self.assertIn("MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT", allocator)
        self.assertIn("Unable to allocate %u bytes after cleanup", allocator)

    def test_psram_critical_checks_are_noops_without_external_heap(self):
        task_config = (ROOT / "src/core/task_config.cpp").read_text(encoding="utf-8")
        guard = "if (heap_caps_get_total_size(MALLOC_CAP_SPIRAM) == 0)"
        self.assertGreaterEqual(task_config.count(guard), 2)
        self.assertIn("PSRAM_RING_SIZE = 16 * 1024", (ROOT / "src/core/filesystem_task_delegate.h").read_text(encoding="utf-8"))

    def test_boot_critical_allocators_use_common_fallback(self):
        paths = [
            ROOT / "src/core/async_storage_engine.h",
            ROOT / "src/core/async_storage_engine.cpp",
            ROOT / "src/core/configuration_manager.cpp",
            ROOT / "src/core/filesystem_task_delegate.cpp",
            ROOT / "src/core/logging_system.cpp",
            ROOT / "src/core/network_engine.cpp",
        ]
        for path in paths:
            self.assertIn("PSRAMUtils::allocatePreferred", path.read_text(encoding="utf-8"), path)

    def test_raw_storage_buffers_do_not_require_psram(self):
        source = (ROOT / "src/core/async_storage_engine.cpp").read_text(encoding="utf-8")
        self.assertNotIn("heap_caps_malloc(size, MALLOC_CAP_SPIRAM", source)
        self.assertNotIn("heap_caps_malloc(plen+1, MALLOC_CAP_SPIRAM", source)


if __name__ == "__main__":
    unittest.main()
