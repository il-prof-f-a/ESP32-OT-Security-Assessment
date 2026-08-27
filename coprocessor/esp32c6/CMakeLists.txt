cmake_minimum_required(VERSION 3.16.0)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
include("${CMAKE_CURRENT_LIST_DIR}/../../scripts/cmake/filter_spaceful_prefix_maps.cmake")

# ESP-IDF 5.5.3 splits spaceful Windows paths while registering linker
# fragments. Preserve the CMake list supplied by ESP-Hosted.
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

project(esp32_ot_esp32c6_coprocessor)

if(CMAKE_HOST_WIN32)
  esp32_ot_filter_spaceful_prefix_maps()
endif()

# Keep the Windows ldgen command below cmd.exe's length limit by combining the
# declarative fragment inputs into one generated file.
if(CMAKE_HOST_WIN32)
  idf_build_get_property(_esp32_ot_ldfragments __LDGEN_FRAGMENT_FILES)
  set(_esp32_ot_aggregate_fragment
      "${CMAKE_BINARY_DIR}/esp32_ot_c6_all_fragments.lf")
  file(WRITE "${_esp32_ot_aggregate_fragment}"
       "# Generated from ESP-IDF and ESP-Hosted linker fragments.\n")
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
