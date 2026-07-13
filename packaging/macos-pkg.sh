#!/usr/bin/env bash
#
# macos-pkg.sh — wrap the self-contained macOS bundle (produced by
# bundle-macos.sh) into an installer .pkg. Installs to /usr/local/carcal and
# symlinks /usr/local/bin/carcal. Unsigned (right-click ▸ Open, or
# `installer -pkg`); sign/notarize separately for distribution.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
: "${VERSION:=0.1.0}"
SRC="$ROOT/dist/carcal-macos-$ARCH"          # bundle tree from bundle-macos.sh
PKG="$ROOT/dist/carcal-macos-$ARCH.pkg"

[ -d "$SRC" ] || { echo "run bundle-macos.sh first ($SRC missing)" >&2; exit 1; }

ROOTDIR="$ROOT/dist/pkgroot"
SCRIPTS="$ROOT/dist/pkgscripts"
rm -rf "$ROOTDIR" "$SCRIPTS"
mkdir -p "$ROOTDIR/usr/local/carcal" "$SCRIPTS"
cp -R "$SRC"/* "$ROOTDIR/usr/local/carcal/"

cat > "$SCRIPTS/postinstall" <<'SH'
#!/bin/sh
mkdir -p /usr/local/bin
ln -sf /usr/local/carcal/carcal /usr/local/bin/carcal
exit 0
SH
chmod +x "$SCRIPTS/postinstall"

pkgbuild --root "$ROOTDIR" \
         --scripts "$SCRIPTS" \
         --identifier org.carcal.cli \
         --version "$VERSION" \
         --install-location / \
         "$PKG"
echo "==> $PKG"
