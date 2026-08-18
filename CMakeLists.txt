cmake_minimum_required(VERSION 3.16.0)

# Keep generated configuration beside other build artifacts. PlatformIO may
# provide its own SDKCONFIG path on the command line, which takes precedence.
if(NOT DEFINED SDKCONFIG)
  set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Select sdkconfig defaults per PlatformIO environment or ESP-IDF target before project().
if(DEFINED ENV{PIOENV})
  set(_PIO_ENV "$ENV{PIOENV}")
else()
  set(_PIO_ENV "")
endif()

if(DEFINED IDF_TARGET)
  set(_IDF_TGT "${IDF_TARGET}")
elseif(DEFINED ENV{IDF_TARGET})
  set(_IDF_TGT "$ENV{IDF_TARGET}")
else()
  set(_IDF_TGT "")
endif()

if("${_PIO_ENV}" STREQUAL "esp32-s3-eth")
  set(SDKCONFIG_DEFAULTS "sdkconfig.esp32s3eth.defaults")
elseif("${_IDF_TGT}" STREQUAL "esp32s3")
  set(SDKCONFIG_DEFAULTS "sdkconfig.esp32s3eth.defaults")
elseif("${_IDF_TGT}" STREQUAL "esp32p4")
  set(SDKCONFIG_DEFAULTS "sdkconfig.esp32p4.defaults")
else()
  set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")
endif()

# PlatformIO discovers src/ for its environments; native ESP-IDF requires the
# application directory to be registered explicitly as a component.
set(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/src")

get_filename_component(configName "${CMAKE_BINARY_DIR}" NAME)

# Generate deterministic public assets for native ESP-IDF and PlatformIO builds.
if(NOT DEFINED PYTHON OR "${PYTHON}" STREQUAL "")
  message(FATAL_ERROR "ESP-IDF did not provide a Python interpreter for build-asset generation")
endif()

set(ESP32_OT_GENERATED_INCLUDE_DIR "${CMAKE_BINARY_DIR}/generated")

# Resolve a stable board key for the build-asset interface.
if(NOT "${_PIO_ENV}" STREQUAL "")
  set(_BOARD "${_PIO_ENV}")
elseif("${_IDF_TGT}" STREQUAL "esp32")
  set(_BOARD "t-poe-pro")
elseif("${_IDF_TGT}" STREQUAL "esp32s3")
  set(_BOARD "esp32-s3-eth")
elseif("${_IDF_TGT}" STREQUAL "esp32p4")
  set(_BOARD "waveshare-esp32p4-eth")
else()
  set(_BOARD "")
endif()

execute_process(
  COMMAND "${PYTHON}"
          "${CMAKE_SOURCE_DIR}/scripts/build_assets.py"
          --project-dir "${CMAKE_SOURCE_DIR}"
          --build-dir "${CMAKE_BINARY_DIR}"
          --board "${_BOARD}"
  RESULT_VARIABLE _ESP32_OT_PROVISION_RESULT
  OUTPUT_VARIABLE _ESP32_OT_PROVISION_OUTPUT
  ERROR_VARIABLE _ESP32_OT_PROVISION_ERROR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_STRIP_TRAILING_WHITESPACE
)
if(NOT _ESP32_OT_PROVISION_RESULT EQUAL 0)
  message(FATAL_ERROR "Build-asset generation failed: ${_ESP32_OT_PROVISION_ERROR}")
endif()
message(STATUS "${_ESP32_OT_PROVISION_OUTPUT}")

file(STRINGS "${CMAKE_SOURCE_DIR}/VERSION" PROJECT_VER LIMIT_COUNT 1)
if("${PROJECT_VER}" STREQUAL "")
  message(FATAL_ERROR "VERSION must contain a semantic project version")
endif()
project(esp32_ot_security_assessment)

# Define FD_SETSIZE for lwIP socket offset calculation after project().
# Formula: LWIP_SOCKET_OFFSET = FD_SETSIZE - CONFIG_LWIP_MAX_SOCKETS.
# With CONFIG_LWIP_MAX_SOCKETS=48, FD_SETSIZE must be at least 54.
# The toolchain default is 64; the line remains available as an explicit override.
# idf_build_set_property(COMPILE_OPTIONS "-DFD_SETSIZE=64" APPEND)

# Add board-specific compile definitions for direct ESP32-P4 builds.
if(DEFINED IDF_TARGET)
  set(_IDF_TGT "${IDF_TARGET}")
elseif(DEFINED ENV{IDF_TARGET})
  set(_IDF_TGT "$ENV{IDF_TARGET}")
else()
  set(_IDF_TGT "")
endif()

if("${_IDF_TGT}" STREQUAL "esp32p4")
  idf_build_set_property(COMPILE_OPTIONS "-DBOARD_WAVESHARE_ESP32P4_ETH" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_WEB_HTTP_ONLY=0" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DETH_PHY_TYPE=101" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DETH_PHY_ADDR=1" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DETH_PHY_RST_GPIO=51" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DETH_MDC_GPIO=31" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DETH_MDIO_GPIO=52" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DETH_RMII_CLK_MODE=EMAC_CLK_EXT_IN" APPEND)
  idf_build_set_property(COMPILE_OPTIONS "-DETH_RMII_CLK_GPIO=50" APPEND)
endif()

# Create and flash the LittleFS image from ./data. The first argument is the
# partition label from partitions.csv, not its LittleFS subtype.
littlefs_create_partition_image(storage data FLASH_IN_PROJECT)

# SDKCONFIG_DEFAULTS can contain multiple files in precedence order.
# The target-specific value is selected above.
