#!/usr/bin/env bash
#
# appimage.sh — build a single-file caracal-*.AppImage (Linux). Assembles an
# AppDir, lets linuxdeploy bundle the shared-library dependencies, and points
# caracal at its bundled protos/grammars via an AppRun hook. Best-effort: if
# linuxdeploy can't be obtained it just warns (the tarball from bundle-linux.sh
# remains the fallback).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
BIN="$ROOT/build/caracal"
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
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/caracal" \
         "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps" \
         "$APPDIR/apprun-hooks"
cp "$BIN" "$APPDIR/usr/bin/caracal"
cp -R "$ROOT/protos" "$ROOT/grammars" "$ROOT/scripts" "$APPDIR/usr/share/caracal/" 2>/dev/null || true
cp "$ROOT/packaging/caracal.desktop" "$APPDIR/usr/share/applications/caracal.desktop"
cp "$ROOT/packaging/caracal.png"     "$APPDIR/usr/share/icons/hicolor/256x256/apps/caracal.png"

# point caracal at the in-AppImage data when run
cat > "$APPDIR/apprun-hooks/caracal-data.sh" <<'SH'
export CARACAL_PROTOS_DIR="$APPDIR/usr/share/caracal/protos"
export CARACAL_GRAMMARS_DIR="$APPDIR/usr/share/caracal/grammars"
SH

cd "$ROOT/dist"
OUTPUT="caracal-linux-$ARCH.AppImage" \
  "$TOOL" --appdir "$APPDIR" \
          --desktop-file "$APPDIR/usr/share/applications/caracal.desktop" \
          --icon-file "$APPDIR/usr/share/icons/hicolor/256x256/apps/caracal.png" \
          --output appimage
echo "==> $ROOT/dist/caracal-linux-$ARCH.AppImage"
