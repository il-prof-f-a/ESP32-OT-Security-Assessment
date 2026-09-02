"""Small, dependency-free normalization helpers for persistent P4 sdkconfig files."""

from pathlib import Path
import re


_FLASH_SIZES = ("2MB", "4MB", "8MB", "16MB", "32MB", "64MB", "128MB")
_PROFILE_FLASH_SIZE = {
    "waveshare-esp32p4-eth": "32MB",
    "guition-jc-esp32p4-m3-dev": "16MB",
}


def normalize_p4_sdkconfig(environment: str, path: Path) -> bool:
    """Keep a persistent P4 sdkconfig aligned with its selected board profile.

    PlatformIO keeps sdkconfig.<environment> in the project directory after the
    first ESP-IDF configuration. It takes precedence over sdkconfig defaults on
    later builds, so only the mutually-exclusive flash-size symbols are updated.
    """
    expected_size = _PROFILE_FLASH_SIZE.get(environment)
    if expected_size is None or not path.is_file():
        return False

    original = path.read_text(encoding="utf-8")
    normalized = original
    for size in _FLASH_SIZES:
        symbol = f"CONFIG_ESPTOOLPY_FLASHSIZE_{size}"
        replacement = f"{symbol}=y" if size == expected_size else f"# {symbol} is not set"
        normalized = re.sub(
            rf"(?m)^(?:# )?{re.escape(symbol)}(?:=y| is not set)$",
            replacement,
            normalized,
        )

    if normalized == original:
        return False

    path.write_text(normalized, encoding="utf-8")
    return True
