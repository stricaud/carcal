#!/usr/bin/env bash
#
# macos-pkg.sh — wrap the self-contained macOS bundle (produced by
# bundle-macos.sh) into an installer .pkg. Installs to /usr/local/caracal and
# symlinks /usr/local/bin/caracal. Unsigned (right-click ▸ Open, or
# `installer -pkg`); sign/notarize separately for distribution.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
: "${VERSION:=0.1.0}"
SRC="$ROOT/dist/caracal-macos-$ARCH"          # bundle tree from bundle-macos.sh
PKG="$ROOT/dist/caracal-macos-$ARCH.pkg"

[ -d "$SRC" ] || { echo "run bundle-macos.sh first ($SRC missing)" >&2; exit 1; }

ROOTDIR="$ROOT/dist/pkgroot"
SCRIPTS="$ROOT/dist/pkgscripts"
rm -rf "$ROOTDIR" "$SCRIPTS"
mkdir -p "$ROOTDIR/usr/local/caracal" "$SCRIPTS"
cp -R "$SRC"/* "$ROOTDIR/usr/local/caracal/"

cat > "$SCRIPTS/postinstall" <<'SH'
#!/bin/sh
mkdir -p /usr/local/bin
ln -sf /usr/local/caracal/caracal /usr/local/bin/caracal
exit 0
SH
chmod +x "$SCRIPTS/postinstall"

pkgbuild --root "$ROOTDIR" \
         --scripts "$SCRIPTS" \
         --identifier org.caracal.cli \
         --version "$VERSION" \
         --install-location / \
         "$PKG"
echo "==> $PKG"
