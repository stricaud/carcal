#!/usr/bin/env bash
#
# appimage.sh — build a single-file carcal-*.AppImage (Linux). Assembles an
# AppDir, lets linuxdeploy bundle the shared-library dependencies, and points
# carcal at its bundled protos/grammars via an AppRun hook. Best-effort: if
# linuxdeploy can't be obtained it just warns (the tarball from bundle-linux.sh
# remains the fallback).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
BIN="$ROOT/build/carcal"

# CI runners (and many minimal hosts) lack FUSE; make AppImage tools self-extract
# instead of mounting, so linuxdeploy and appimagetool run without FUSE.
export APPIMAGE_EXTRACT_AND_RUN=1
APPDIR="$ROOT/dist/AppDir"
TOOL="$ROOT/dist/linuxdeploy-$ARCH.AppImage"

[ -x "$BIN" ] || { echo "build first: $BIN missing" >&2; exit 1; }

if [ ! -x "$TOOL" ]; then
  url="https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-$ARCH.AppImage"
  echo "==> fetching linuxdeploy"
  if ! curl -fsSL "$url" -o "$TOOL" 2>/dev/null; then
    echo "  ! could not download linuxdeploy ($url); skipping AppImage" >&2
    exit 0
  fi
  chmod +x "$TOOL"
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/carcal" \
         "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps" \
         "$APPDIR/apprun-hooks"
cp "$BIN" "$APPDIR/usr/bin/carcal"
cp -R "$ROOT/protos" "$ROOT/grammars" "$ROOT/scripts" "$APPDIR/usr/share/carcal/" 2>/dev/null || true
cp "$ROOT/packaging/carcal.desktop" "$APPDIR/usr/share/applications/carcal.desktop"
cp "$ROOT/packaging/carcal.png"     "$APPDIR/usr/share/icons/hicolor/256x256/apps/carcal.png"

# point carcal at the in-AppImage data when run
cat > "$APPDIR/apprun-hooks/carcal-data.sh" <<'SH'
export CARCAL_PROTOS_DIR="$APPDIR/usr/share/carcal/protos"
export CARCAL_GRAMMARS_DIR="$APPDIR/usr/share/carcal/grammars"
SH

cd "$ROOT/dist"
OUTPUT="carcal-linux-$ARCH.AppImage" \
  "$TOOL" --appdir "$APPDIR" \
          --desktop-file "$APPDIR/usr/share/applications/carcal.desktop" \
          --icon-file "$APPDIR/usr/share/icons/hicolor/256x256/apps/carcal.png" \
          --output appimage
echo "==> $ROOT/dist/carcal-linux-$ARCH.AppImage"
