cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "joinstr_flutter")
project(${PROJECT_NAME} LANGUAGES CXX)

set(PLUGIN_NAME "joinstr_flutter_plugin")

include("../cargokit/cmake/cargokit.cmake")
apply_cargokit(${PLUGIN_NAME} ../rust joinstr_flutter "")

set(joinstr_flutter_bundled_libraries
  "${${PLUGIN_NAME}_cargokit_lib}"
  PARENT_SCOPE
)
