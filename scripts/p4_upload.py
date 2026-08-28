"""PlatformIO extra_script: route the ESP32-P4 upload through flash_esptool.py.

The stock `pio run -t upload` for this target hangs on get_cmake_code_model
when the project path contains spaces, and its bootloader offset (0x1000) is
wrong for the ESP32-P4 (which uses 0x2000). flash_esptool.py reads every
offset and flash setting from flasher_args.json, including LittleFS, and forces
UTF-8 so the esptool progress bar does not crash under cp1252.

PlatformIO's upload target does not build LittleFS. Ordinary updates must
preserve the on-device filesystem, so flash_esptool.py rebuilds the firmware
but intentionally excludes the LittleFS manifest entry unless a factory
installation explicitly requests it.
"""
Import("env")

env.Replace(
    # The pioarduino combined-image hook otherwise falls back to 0x10000 even
    # though partitions.csv and flasher_args.json place this app at 0x200000.
    ESP32_APP_OFFSET="0x200000",
    UPLOADCMD='$PYTHONEXE "$PROJECT_DIR/scripts/flash_esptool.py" '
              '--target $PIOENV --port $UPLOAD_PORT'
)
