cmake_minimum_required(VERSION 3.20)

# Detect the macOS SDK before project() so CMake doesn't warn on a stale sysroot
# (mirrors how the gtcaca dependency does it).
if(APPLE)
  execute_process(
    COMMAND xcrun --show-sdk-path
    OUTPUT_VARIABLE _detected_sysroot
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
  if(_detected_sysroot)
    set(CMAKE_OSX_SYSROOT "${_detected_sysroot}" CACHE PATH "macOS SDK path" FORCE)
  endif()
endif()

project(caracal C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

# Where the sibling dependencies live (override with -DGTCACA_ROOT=... etc.)
set(GTCACA_ROOT   "${CMAKE_CURRENT_SOURCE_DIR}/../gtcaca"    CACHE PATH "gtcaca source/build root")
set(LIBPCAPNG_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../libpcapng" CACHE PATH "libpcapng source/build root")

# ── libcaca (required, via pkg-config) ──────────────────────────────────────
include(FindPkgConfig)
pkg_check_modules(CACA REQUIRED caca)

# ── libpcapng ───────────────────────────────────────────────────────────────
pkg_check_modules(PCAPNG QUIET libpcapng)
find_path(PCAPNG_INCLUDE_DIR
  NAMES libpcapng/libpcapng.h
  HINTS ${PCAPNG_INCLUDEDIR} /usr/local/include "${LIBPCAPNG_ROOT}/lib/include")
find_library(PCAPNG_LIBRARY
  NAMES pcapng
  HINTS ${PCAPNG_LIBDIR} /usr/local/lib "${LIBPCAPNG_ROOT}/build/lib")
if(NOT PCAPNG_INCLUDE_DIR OR NOT PCAPNG_LIBRARY)
  message(FATAL_ERROR "libpcapng not found. Build it under ${LIBPCAPNG_ROOT}/build "
                      "or pass -DPCAPNG_INCLUDE_DIR=... -DPCAPNG_LIBRARY=...")
endif()

# ── gtcaca ──────────────────────────────────────────────────────────────────
find_path(GTCACA_INCLUDE_DIR
  NAMES gtcaca/main.h
  HINTS "${GTCACA_ROOT}/src/include" /usr/local/include)
find_path(GTCACA_BUILD_INCLUDE_DIR
  NAMES gtcaca
  HINTS "${GTCACA_ROOT}/build/src/include"
  NO_DEFAULT_PATH)
find_library(GTCACA_LIBRARY
  NAMES gtcaca
  HINTS "${GTCACA_ROOT}/build/src" /usr/local/lib)
if(NOT GTCACA_INCLUDE_DIR OR NOT GTCACA_LIBRARY)
  message(FATAL_ERROR "gtcaca not found. Build it under ${GTCACA_ROOT}/build "
                      "or pass -DGTCACA_INCLUDE_DIR=... -DGTCACA_LIBRARY=...")
endif()

message(STATUS "caca:      ${CACA_LIBRARIES} (${CACA_INCLUDE_DIRS})")
message(STATUS "libpcapng: ${PCAPNG_LIBRARY} (${PCAPNG_INCLUDE_DIR})")
message(STATUS "gtcaca:    ${GTCACA_LIBRARY} (${GTCACA_INCLUDE_DIR})")

# Find libgtcaca.1.dylib / libpcapng at runtime (they live in /usr/local/lib and
# in the dependencies' build trees).
if(APPLE)
  set(CMAKE_MACOSX_RPATH ON)
endif()
get_filename_component(_gtcaca_libdir "${GTCACA_LIBRARY}" DIRECTORY)
get_filename_component(_pcapng_libdir "${PCAPNG_LIBRARY}" DIRECTORY)
list(APPEND CMAKE_BUILD_RPATH   "${_gtcaca_libdir}" "${_pcapng_libdir}" /usr/local/lib)
list(APPEND CMAKE_INSTALL_RPATH "${_gtcaca_libdir}" "${_pcapng_libdir}" /usr/local/lib)

add_executable(caracal
  src/main.c
  src/source.c
  src/dissect.c
  src/posa.c
  src/filter.c
  src/field.c)

target_include_directories(caracal PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CACA_INCLUDE_DIRS}
  ${PCAPNG_INCLUDE_DIR}
  ${GTCACA_INCLUDE_DIR})

if(GTCACA_BUILD_INCLUDE_DIR)
  target_include_directories(caracal PRIVATE ${GTCACA_BUILD_INCLUDE_DIR})
endif()

target_link_directories(caracal PRIVATE ${CACA_LIBRARY_DIRS})

target_link_libraries(caracal PRIVATE
  ${GTCACA_LIBRARY}
  ${PCAPNG_LIBRARY}
  ${CACA_LIBRARIES}
  m)

# Ship the sample protocol definitions next to the binary so caracal can load
# them at startup (CARACAL_PROTOS_DIR) without an install step.
target_compile_definitions(caracal PRIVATE
  CARACAL_PROTOS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/protos")

install(TARGETS caracal RUNTIME DESTINATION bin)
install(DIRECTORY protos/ DESTINATION share/caracal/protos FILES_MATCHING PATTERN "*.posa")
