#!/usr/bin/env bash
#
# macos-dmg.sh — wrap the macOS bundle into a .dmg, the container macOS users
# expect to download and mount. Run after bundle-macos.sh and macos-pkg.sh.
#
# The DMG holds both ways of using a terminal program:
#
#   carcal.app  — double-clickable, drag it to the /Applications symlink.
#                 carcal is a TUI, so the app's executable is a launcher that
#                 opens Terminal and runs the real binary inside it.
#   carcal.pkg  — for people who want `carcal` on their PATH in a shell they
#                 already have open (installs /usr/local/bin/carcal).
#
# Unsigned and un-notarized, like the .pkg: Gatekeeper will want a right-click ▸
# Open on first launch. Signing/notarizing is a separate exercise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
SRC="$ROOT/dist/carcal-macos-$ARCH"            # bundle tree from bundle-macos.sh
PKG="$ROOT/dist/carcal-macos-$ARCH.pkg"        # installer from macos-pkg.sh
DMG="$ROOT/dist/carcal-macos-$ARCH.dmg"
STAGE="$ROOT/dist/dmgstage"
APP="$STAGE/carcal.app"

[ -d "$SRC" ] || { echo "run bundle-macos.sh first ($SRC missing)" >&2; exit 1; }

rm -rf "$STAGE" "$DMG"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# ── the .app ────────────────────────────────────────────────────────────────
# bundle-macos.sh rewrote the binary's load paths to @executable_path/../lib, so
# the dylibs must sit at Contents/lib for the copied binary to keep resolving
# them — no install_name_tool, and the existing ad-hoc signature stays valid.
cp "$SRC/bin/carcal" "$APP/Contents/MacOS/carcal"
cp -R "$SRC/lib"     "$APP/Contents/lib"
mkdir -p "$APP/Contents/Resources/share"
cp -R "$SRC/share/carcal" "$APP/Contents/Resources/share/carcal"

# CFBundleExecutable. Finder gives a GUI app no terminal, so hand the TUI one:
# `open -a Terminal <script>` runs the script in a new Terminal window.
cat > "$APP/Contents/MacOS/carcal-launcher" <<'SH'
#!/bin/bash
here="$(cd "$(dirname "$0")" && pwd)"
exec /usr/bin/open -a Terminal "$here/carcal-term"
SH

# What Terminal actually runs: point carcal at the data inside the bundle, then
# exec the real binary (which finds its dylibs via @executable_path/../lib).
cat > "$APP/Contents/MacOS/carcal-term" <<'SH'
#!/bin/bash
here="$(cd "$(dirname "$0")" && pwd)"
export CARCAL_PROTOS_DIR="$here/../Resources/share/carcal/protos"
export CARCAL_GRAMMARS_DIR="$here/../Resources/share/carcal/grammars"
exec "$here/carcal"
SH
chmod +x "$APP/Contents/MacOS/carcal-launcher" "$APP/Contents/MacOS/carcal-term"

# Icon (best effort — a missing icon must not fail the build).
if command -v iconutil >/dev/null 2>&1 && [ -f "$ROOT/packaging/carcal.png" ]; then
  ICONSET="$STAGE/carcal.iconset"
  mkdir -p "$ICONSET"
  for sz in 16 32 64 128 256 512; do
    sips -z $sz $sz "$ROOT/packaging/carcal.png" --out "$ICONSET/icon_${sz}x${sz}.png" >/dev/null 2>&1 || true
    sips -z $((sz*2)) $((sz*2)) "$ROOT/packaging/carcal.png" \
         --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null 2>&1 || true
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/carcal.icns" 2>/dev/null || true
  rm -rf "$ICONSET"
fi

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>               <string>carcal</string>
  <key>CFBundleDisplayName</key>        <string>carcal</string>
  <key>CFBundleIdentifier</key>         <string>org.carcal.app</string>
  <key>CFBundleExecutable</key>         <string>carcal-launcher</string>
  <key>CFBundleIconFile</key>           <string>carcal</string>
  <key>CFBundlePackageType</key>        <string>APPL</string>
  <key>CFBundleShortVersionString</key> <string>1.0</string>
  <key>NSHighResolutionCapable</key>    <true/>
</dict>
</plist>
PLIST

# install_name_tool was not run, so the binary's signature is intact; sign the
# bundle itself so Finder will launch it.
codesign -f -s - --deep "$APP" 2>/dev/null || true

# ── the rest of the disk image ──────────────────────────────────────────────
ln -s /Applications "$STAGE/Applications"
[ -f "$PKG" ] && cp "$PKG" "$STAGE/$(basename "$PKG")"

cat > "$STAGE/README.txt" <<'TXT'
carcal — a terminal packet analyzer (a tiny Wireshark for the TUI)

Two ways to install, pick either:

  • Drag carcal.app onto the Applications folder.
    Double-clicking it opens carcal in a new Terminal window.

  • Open the .pkg to install the command-line tool instead.
    That puts `carcal` on your PATH, so you can run:

        carcal /path/to/capture.pcapng

carcal is not signed or notarized yet, so the first launch needs a
right-click ▸ Open (or: System Settings ▸ Privacy & Security ▸ Open Anyway).

Live capture needs privileges — run with sudo, or use a capture file.

https://github.com/stricaud/carcal
TXT

hdiutil create -volname "carcal" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"
echo "==> $DMG"
