# src/CMakeLists.txt

# Collect every C and C++ source under src/.
file(GLOB_RECURSE app_sources
     "*.c"
     "*.cpp")

idf_component_register(
  SRCS ${app_sources}
  INCLUDE_DIRS
    "."
    "${ESP32_OT_GENERATED_INCLUDE_DIR}"
  REQUIRES             # ESP-IDF components used by the application
    esp_wifi
    esp_netif
    esp_event
    nvs_flash
    esp_http_server
    esp_http_client
    esp_https_server
    app_update
    espcoredump
    esp_eth
    json
    esp_timer
    esp_common
    esp_psram
    esp_littlefs
    efuse
    esp-tls
    freertos
    vfs
    spiffs
    mbedtls
    mqtt
  PRIV_REQUIRES        # Link/runtime-only dependencies
    lwip
    driver
)
