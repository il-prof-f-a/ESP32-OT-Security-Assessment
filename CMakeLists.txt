cmake_minimum_required(VERSION 3.16.0)

set(ESP32_OT_BOARD "" CACHE STRING
    "ESP32-OT board profile for native ESP-IDF builds")
set_property(CACHE ESP32_OT_BOARD PROPERTY STRINGS
             t-poe-pro esp32-s3-eth waveshare-esp32p4-eth
             guition-jc-esp32p4-m3-dev)

# Keep generated configuration beside other build artifacts. PlatformIO may
# provide its own SDKCONFIG path on the command line, which takes precedence.
if(NOT DEFINED SDKCONFIG)
  set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
include("${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/filter_spaceful_prefix_maps.cmake")

# ESP-IDF 5.5.3 converts the LDFRAGMENTS argument by replacing every space
# with a CMake list separator. That corrupts otherwise valid Windows checkout
# paths. Preserve the list entries verbatim; component manifests already pass
# linker fragments as a proper CMake list.
if(CMAKE_HOST_WIN32)
  function(__ldgen_add_fragment_files fragment_files)
    set(_esp32_ot_fragment_files "")
    foreach(fragment_file IN LISTS fragment_files)
      get_filename_component(abs_path "${fragment_file}" ABSOLUTE)
      list(APPEND _esp32_ot_fragment_files "${abs_path}")
    endforeach()
    idf_build_set_property(__LDGEN_FRAGMENT_FILES
                           "${_esp32_ot_fragment_files}" APPEND)
  endfunction()
endif()

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

# Resolve a stable, explicit board identity. PlatformIO already provides PIOENV;
# native ESP-IDF P4 builds must select a profile because multiple P4 boards exist.
if(NOT "${_PIO_ENV}" STREQUAL "")
  set(_BOARD "${_PIO_ENV}")
elseif("${_IDF_TGT}" STREQUAL "esp32")
  set(_BOARD "t-poe-pro")
elseif("${_IDF_TGT}" STREQUAL "esp32s3")
  set(_BOARD "esp32-s3-eth")
elseif("${_IDF_TGT}" STREQUAL "esp32p4")
  if("${ESP32_OT_BOARD}" STREQUAL "")
    message(FATAL_ERROR
            "ESP32_OT_BOARD must be set for IDF_TARGET=esp32p4; choose waveshare-esp32p4-eth or guition-jc-esp32p4-m3-dev")
  endif()
  set(_BOARD "${ESP32_OT_BOARD}")
else()
  set(_BOARD "${ESP32_OT_BOARD}")
endif()

set(_SUPPORTED_BOARDS
    t-poe-pro
    esp32-s3-eth
    waveshare-esp32p4-eth
    guition-jc-esp32p4-m3-dev)
if(NOT "${_BOARD}" IN_LIST _SUPPORTED_BOARDS)
  message(FATAL_ERROR "Unsupported ESP32_OT board profile: ${_BOARD}")
endif()

if("${_BOARD}" STREQUAL "esp32-s3-eth")
  set(SDKCONFIG_DEFAULTS "sdkconfig.esp32s3eth.defaults")
elseif("${_BOARD}" STREQUAL "guition-jc-esp32p4-m3-dev")
  set(SDKCONFIG_DEFAULTS "sdkconfig.guition-jc-esp32p4-m3-dev.defaults")
elseif("${_BOARD}" STREQUAL "waveshare-esp32p4-eth")
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

if(CMAKE_HOST_WIN32)
  esp32_ot_filter_spaceful_prefix_maps()
endif()

# ESP-Hosted exports a force-include as the two-token CMake option
# "SHELL:-include <header>". The pinned pioarduino builder sorts imported
# application flags and separates that option from its argument. GCC then sees
# the header as a second input file. The joined GCC spelling is equivalent and
# remains one token in both native ESP-IDF and PlatformIO builds.
if(TARGET eh_host_config)
  get_target_property(_ESP_HOST_CONFIG_OPTIONS
                      eh_host_config INTERFACE_COMPILE_OPTIONS)
  if(_ESP_HOST_CONFIG_OPTIONS)
    list(REMOVE_ITEM _ESP_HOST_CONFIG_OPTIONS "SHELL:-include eh_host_port_master_config.h")
    set_property(TARGET eh_host_config PROPERTY INTERFACE_COMPILE_OPTIONS
                 "${_ESP_HOST_CONFIG_OPTIONS}")
  endif()
  target_compile_options(eh_host_config INTERFACE "-includeeh_host_port_master_config.h")
endif()

# ESP-Hosted adds enough linker fragments to exceed cmd.exe's command-line
# limit. Concatenating the declarative .lf inputs is semantics-preserving and
# lets ldgen receive one short path. Track every source so CMake regenerates the
# aggregate whenever an ESP-IDF or managed-component fragment changes.
if(CMAKE_HOST_WIN32 AND "${_IDF_TGT}" STREQUAL "esp32p4")
  idf_build_get_property(_esp32_ot_ldfragments __LDGEN_FRAGMENT_FILES)
  set(_esp32_ot_aggregate_fragment
      "${CMAKE_BINARY_DIR}/esp32_ot_all_fragments.lf")
  file(WRITE "${_esp32_ot_aggregate_fragment}"
       "# Generated from ESP-IDF and managed-component linker fragments.\n")
  foreach(_esp32_ot_fragment IN LISTS _esp32_ot_ldfragments)
    if(NOT EXISTS "${_esp32_ot_fragment}")
      message(FATAL_ERROR "Registered linker fragment does not exist: ${_esp32_ot_fragment}")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                 "${_esp32_ot_fragment}")
    file(READ "${_esp32_ot_fragment}" _esp32_ot_fragment_content)
    file(APPEND "${_esp32_ot_aggregate_fragment}"
         "\n# Source: ${_esp32_ot_fragment}\n${_esp32_ot_fragment_content}\n")
  endforeach()
  idf_build_set_property(__LDGEN_FRAGMENT_FILES
                         "${_esp32_ot_aggregate_fragment}")
endif()

# Define FD_SETSIZE for lwIP socket offset calculation after project().
# Formula: LWIP_SOCKET_OFFSET = FD_SETSIZE - CONFIG_LWIP_MAX_SOCKETS.
# With CONFIG_LWIP_MAX_SOCKETS=48, FD_SETSIZE must be at least 54.
# The toolchain default is 64; the line remains available as an explicit override.
# idf_build_set_property(COMPILE_OPTIONS "-DFD_SETSIZE=64" APPEND)

# PlatformIO supplies build_flags itself. Native ESP-IDF builds receive the
# same board identity and policy here.
if("${_PIO_ENV}" STREQUAL "")
  if("${_BOARD}" STREQUAL "t-poe-pro")
    idf_build_set_property(COMPILE_OPTIONS "-DBOARD_TPOE_PRO" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DLILYGO_T_ETH_POE_PRO" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_MGMT_POLICY=ESP32_OT_MGMT_WIFI_ONLY" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_WEB_HTTP_ONLY=1" APPEND)
  elseif("${_BOARD}" STREQUAL "esp32-s3-eth")
    idf_build_set_property(COMPILE_OPTIONS "-DBOARD_ESP32_S3_ETH" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_MGMT_POLICY=ESP32_OT_MGMT_WIFI_ONLY" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_WEB_HTTP_ONLY=0" APPEND)
  elseif("${_BOARD}" STREQUAL "waveshare-esp32p4-eth")
    idf_build_set_property(COMPILE_OPTIONS "-DBOARD_WAVESHARE_ESP32P4_ETH" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_MGMT_POLICY=ESP32_OT_MGMT_ETHERNET_ONLY" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_WEB_HTTP_ONLY=0" APPEND)
  elseif("${_BOARD}" STREQUAL "guition-jc-esp32p4-m3-dev")
    idf_build_set_property(COMPILE_OPTIONS "-DBOARD_GUITION_JC_ESP32P4_M3_DEV" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_MGMT_POLICY=ESP32_OT_MGMT_WIFI_ONLY" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_WIFI_BACKEND_REMOTE=1" APPEND)
    idf_build_set_property(COMPILE_OPTIONS "-DESP32_OT_WEB_HTTP_ONLY=0" APPEND)
  endif()
endif()

if("${_IDF_TGT}" STREQUAL "esp32p4")
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
