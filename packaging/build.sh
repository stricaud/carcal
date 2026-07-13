#!/usr/bin/env bash
#
# build.sh — build carcal and its sibling libraries (gtcaca, libpcapng) in
# Release, then produce a self-contained package for the host OS.
#
#   GTCACA_SRC=/path LIBPCAPNG_SRC=/path packaging/build.sh
#
# Defaults assume the libraries are checked out next to this repo (../gtcaca,
# ../libpcapng). Requires: cmake, a C toolchain, pkg-config, and the external
# deps libcaca, luajit, oniguruma (+ python3 + pybind11, which libpcapng's
# CMake configure step needs even though we only build its library).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${GTCACA_SRC:=$ROOT/../gtcaca}"
: "${LIBPCAPNG_SRC:=$ROOT/../libpcapng}"
: "${BUILD_TYPE:=Release}"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

echo "==> libpcapng ($LIBPCAPNG_SRC)"
cmake -S "$LIBPCAPNG_SRC" -B "$LIBPCAPNG_SRC/build" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" >/dev/null
cmake --build "$LIBPCAPNG_SRC/build" --target pcapng -j"$JOBS"

echo "==> gtcaca ($GTCACA_SRC)"
cmake -S "$GTCACA_SRC" -B "$GTCACA_SRC/build" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" >/dev/null
cmake --build "$GTCACA_SRC/build" --target gtcaca -j"$JOBS"

echo "==> carcal ($ROOT)"
cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
      -DGTCACA_ROOT="$GTCACA_SRC" -DLIBPCAPNG_ROOT="$LIBPCAPNG_SRC" >/dev/null
cmake --build "$ROOT/build" --target carcal -j"$JOBS"

export GTCACA_SRC LIBPCAPNG_SRC
case "$(uname -s)" in
  Darwin)
    "$ROOT/packaging/bundle-macos.sh"        # self-contained tarball
    "$ROOT/packaging/macos-pkg.sh"           # + installer .pkg
    ;;
  Linux)
    "$ROOT/packaging/bundle-linux.sh"        # self-contained tarball
    "$ROOT/packaging/appimage.sh"            # + single-file AppImage (best effort)
    ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
echo "==> artifacts in $ROOT/dist/"
