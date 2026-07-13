#!/usr/bin/env bash
#
# windows-installer.sh — wrap the bundle produced by bundle-windows.sh into an
# NSIS installer (the same thing Wireshark ships on Windows).
#
# Run from an MSYS2 MinGW shell after bundle-windows.sh. Needs makensis:
#   pacman -S --needed mingw-w64-ucrt-x86_64-nsis
#
# Best effort: if makensis is missing we warn and leave the zip alone rather
# than failing the whole packaging run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${MSYSTEM_CARCH:-x86_64}"
BUNDLE="$ROOT/dist/carcal-windows-$ARCH"

[ -d "$BUNDLE" ] || { echo "bundle first: $BUNDLE missing" >&2; exit 1; }

if ! command -v makensis >/dev/null 2>&1; then
  echo "!! makensis not found — skipping the installer (the zip is still in dist/)." >&2
  echo "   pacman -S --needed mingw-w64-ucrt-x86_64-nsis" >&2
  exit 0
fi

# Version for the installer metadata. CARCAL_VERSION wins because CI checks out
# shallow, where `git describe` finds no tags. NSIS's VIProductVersion demands a
# strictly numeric x.y.z, so anything else (an untagged build, a -rc suffix)
# falls back to 0.0.0 rather than failing the build.
VERSION="${CARCAL_VERSION:-$(git -C "$ROOT" describe --tags --abbrev=0 2>/dev/null || true)}"
VERSION="${VERSION#v}"
case "$VERSION" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) VERSION="0.0.0" ;;
esac

OUT="$ROOT/dist/carcal-$VERSION-$ARCH-setup.exe"

# makensis is a native Windows binary: hand it Windows paths, not MSYS ones.
makensis -V2 \
  -DVERSION="$VERSION" \
  -DSOURCE_DIR="$(cygpath -w "$BUNDLE")" \
  -DOUTFILE="$(cygpath -w "$OUT")" \
  -DLICENSE_FILE="$(cygpath -w "$ROOT/LICENSE")" \
  "$(cygpath -w "$ROOT/packaging/carcal.nsi")"

echo "==> $OUT"
