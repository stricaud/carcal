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

project(carcal C)

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

# ── LuaJIT (required, via pkg-config) ───────────────────────────────────────
pkg_check_modules(LUAJIT REQUIRED luajit)

# ── libpcapng ───────────────────────────────────────────────────────────────
pkg_check_modules(PCAPNG QUIET libpcapng)
# Prefer the source include tree — the installed headers omit protocols/ and
# reassembly.h, which carcal's reassembly + posa decoding need.
find_path(PCAPNG_INCLUDE_DIR
  NAMES libpcapng/reassembly.h libpcapng/libpcapng.h
  HINTS "${LIBPCAPNG_ROOT}/lib/include" ${PCAPNG_INCLUDEDIR} /usr/local/include)
# Prefer the freshly built dylib — the installed one may predate exported
# symbols (reassembly, flow-direction normalizer) that carcal needs.
find_library(PCAPNG_LIBRARY
  NAMES pcapng
  HINTS "${LIBPCAPNG_ROOT}/build/lib" ${PCAPNG_LIBDIR} /usr/local/lib)
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
if(NOT WIN32)
  # Windows has no rpath: the packaged DLLs sit next to carcal.exe instead.
  list(APPEND CMAKE_BUILD_RPATH   "${_gtcaca_libdir}" "${_pcapng_libdir}" /usr/local/lib)
  list(APPEND CMAKE_INSTALL_RPATH "${_gtcaca_libdir}" "${_pcapng_libdir}" /usr/local/lib)
endif()

add_executable(carcal
  src/main.c
  src/source.c
  src/dissect.c
  src/filter.c
  src/field.c
  src/rules.c
  src/lua_run.c)

target_include_directories(carcal PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CACA_INCLUDE_DIRS}
  ${LUAJIT_INCLUDE_DIRS}
  ${PCAPNG_INCLUDE_DIR}
  ${GTCACA_INCLUDE_DIR})

if(GTCACA_BUILD_INCLUDE_DIR)
  target_include_directories(carcal PRIVATE ${GTCACA_BUILD_INCLUDE_DIR})
endif()

target_link_directories(carcal PRIVATE ${CACA_LIBRARY_DIRS} ${LUAJIT_LIBRARY_DIRS})

target_link_libraries(carcal PRIVATE
  ${GTCACA_LIBRARY}
  ${PCAPNG_LIBRARY}
  ${CACA_LIBRARIES}
  ${LUAJIT_LIBRARIES}
  m)

if(WIN32)
  # libpcapng's byte-order/inet_ntop helpers come from ws2_32; needed explicitly
  # when it is linked statically. Live capture is unsupported on Windows (the
  # library compiles its stub backend) — carcal is file-analysis only there.
  target_link_libraries(carcal PRIVATE ws2_32)
endif()

# Older LuaJIT-on-macOS guidance asks for -pagezero_size/-image_base, but those
# are x86_64-only and ignored under arm64 PIE, so we omit them.

# Compiled-in data directories. Default to the in-tree copies so carcal runs
# from the build tree without an install step; a package build (e.g. Homebrew)
# overrides these to the install prefix, e.g.
#   -DCARCAL_DATA_PROTOS=<prefix>/share/carcal/protos
# (the CARCAL_PROTOS_DIR / CARCAL_GRAMMARS_DIR env vars still win at runtime).
set(CARCAL_DATA_PROTOS   "${CMAKE_CURRENT_SOURCE_DIR}/protos"   CACHE PATH "compiled-in protos dir")
set(CARCAL_DATA_GRAMMARS "${CMAKE_CURRENT_SOURCE_DIR}/grammars" CACHE PATH "compiled-in grammars dir")
target_compile_definitions(carcal PRIVATE
  CARCAL_PROTOS_DIR="${CARCAL_DATA_PROTOS}"
  CARCAL_GRAMMARS_DIR="${CARCAL_DATA_GRAMMARS}")

install(TARGETS carcal RUNTIME DESTINATION bin)
install(DIRECTORY protos/ DESTINATION share/carcal/protos FILES_MATCHING PATTERN "*.posa")
install(DIRECTORY grammars/ DESTINATION share/carcal/grammars FILES_MATCHING PATTERN "*.json")
