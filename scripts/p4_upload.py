"""PlatformIO extra_script: route the ESP32-P4 upload through flash_esptool.py.

The stock `pio run -t upload` for this target hangs on get_cmake_code_model
when the project path contains spaces, and its bootloader offset (0x1000) is
wrong for the ESP32-P4 (which uses 0x2000). flash_esptool.py flashes
bootloader/partitions/firmware at the correct offsets and forces UTF-8 so the
esptool progress bar does not crash under cp1252.

PlatformIO runs the upload target only after a successful build, so we pass
--no-build.
"""
Import("env")

env.Replace(
    UPLOADCMD='$PYTHONEXE "$PROJECT_DIR/scripts/flash_esptool.py" '
              '--target waveshare-esp32p4-eth --port $UPLOAD_PORT --no-build'
)
