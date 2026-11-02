cmake_minimum_required(VERSION 3.24)
project(palisade-cli VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

include(FetchContent)
set(FETCHCONTENT_QUIET ON)

set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(FTXUI_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)

FetchContent_Declare(ftxui
  URL https://github.com/ArthurSonzogni/FTXUI/archive/refs/tags/v7.0.3.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_Declare(json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
# cpp-httplib is one header; SOURCE_SUBDIR skips its CMake (it probes for zlib/brotli).
FetchContent_Declare(httplib
  URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.61.0.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SOURCE_SUBDIR no-cmake)
FetchContent_MakeAvailable(ftxui json httplib)
find_package(OpenSSL 3 REQUIRED)

add_library(palisade_core STATIC src/config.cpp src/api.cpp)
target_include_directories(palisade_core PUBLIC src SYSTEM PUBLIC ${httplib_SOURCE_DIR})
target_compile_definitions(palisade_core PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT
  PALISADE_CLI_VERSION="${PROJECT_VERSION}")
target_link_libraries(palisade_core PUBLIC nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(palisade_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(palisade-cli src/main.cpp src/tui.cpp)
target_link_libraries(palisade-cli PRIVATE palisade_core ftxui::component ftxui::dom ftxui::screen)
target_compile_options(palisade-cli PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(config_test tests/config_test.cpp)
target_link_libraries(config_test PRIVATE palisade_core)
add_test(NAME config_test COMMAND config_test)
