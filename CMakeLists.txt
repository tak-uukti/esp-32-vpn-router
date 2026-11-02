cmake_minimum_required(VERSION 3.16)

# TailTiny lives outside the project as a plain clone (no submodule, no patches).
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/third_party/tailtiny/components")

# Compose the sdkconfig defaults chain explicitly so board profiles and the secret
# credentials file are applied in the right order, lowest priority first.
set(_gadget_defaults "sdkconfig.defaults")

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults.${IDF_TARGET}")
    list(APPEND _gadget_defaults "sdkconfig.defaults.${IDF_TARGET}")
endif()

if(DEFINED ENV{GADGET_PROFILE} AND NOT "$ENV{GADGET_PROFILE}" STREQUAL ""
   AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults.$ENV{GADGET_PROFILE}")
    list(APPEND _gadget_defaults "sdkconfig.defaults.$ENV{GADGET_PROFILE}")
endif()

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.credentials")
    list(APPEND _gadget_defaults "sdkconfig.credentials")
endif()

set(SDKCONFIG_DEFAULTS "${_gadget_defaults}")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tailnet-gadget)
