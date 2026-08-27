# Keep ESP-IDF path redaction enabled without triggering a GCC response-file
# bug on Windows. The pinned PlatformIO toolchain uses response files for long
# ESP-IDF commands; GCC truncates prefix-map source prefixes at their first
# space when forwarding those options to cc1/cc1plus. Paths without spaces
# remain mapped, including the user profile, ESP-IDF, toolchain, and build tree.
function(esp32_ot_filter_spaceful_prefix_maps)
  idf_build_get_property(_esp32_ot_compile_options COMPILE_OPTIONS)
  set(_esp32_ot_filtered_options "")
  foreach(_esp32_ot_option IN LISTS _esp32_ot_compile_options)
    if("${_esp32_ot_option}" MATCHES
       "^-f(macro|file|debug)-prefix-map=([^=]+)=")
      set(_source_prefix "${CMAKE_MATCH_2}")
      string(FIND "${_source_prefix}" " " _space_index)
      if(NOT _space_index EQUAL -1)
        message(STATUS
                "Omitting unsupported spaceful prefix-map option for PlatformIO")
        continue()
      endif()
    endif()
    list(APPEND _esp32_ot_filtered_options "${_esp32_ot_option}")
  endforeach()
  idf_build_set_property(COMPILE_OPTIONS "${_esp32_ot_filtered_options}")
endfunction()
