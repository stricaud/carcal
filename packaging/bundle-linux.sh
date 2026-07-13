#!/usr/bin/env bash
#
# bundle-linux.sh — produce a self-contained Linux tarball: the carcal binary
# plus every non-system shared library it needs (from ldd), with an rpath of
# $ORIGIN/../lib (via patchelf when available, else a launcher sets
# LD_LIBRARY_PATH). glibc core libs are intentionally not bundled.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
NAME="carcal-linux-$ARCH"
OUT="$ROOT/dist/$NAME"
BIN="$ROOT/build/carcal"

[ -x "$BIN" ] || { echo "build first: $BIN missing" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/bin" "$OUT/lib" "$OUT/share/carcal"
cp "$BIN" "$OUT/bin/carcal"; chmod u+w "$OUT/bin/carcal"

# core libraries that belong to the host, not the package
is_core() {
  case "$1" in
    libc.so*|libm.so*|libdl.so*|libpthread.so*|librt.so*|ld-linux*|\
    libgcc_s.so*|libstdc++.so*|libresolv.so*) return 0 ;;
    *) return 1 ;;
  esac
}

# copy non-core dependencies reported by ldd (ldd is transitive)
ldd "$BIN" | awk '/=>/ {print $3} !/=>/ {print $1}' | while read -r so; do
  [ -f "$so" ] || continue
  base="$(basename "$so")"
  is_core "$base" && continue
  cp -L "$so" "$OUT/lib/$base" 2>/dev/null || true
done

if command -v patchelf >/dev/null 2>&1; then
  patchelf --set-rpath '$ORIGIN/../lib' "$OUT/bin/carcal"
fi

cp -R "$ROOT/protos" "$ROOT/grammars" "$ROOT/scripts" "$OUT/share/carcal/" 2>/dev/null || true
cat > "$OUT/carcal" <<'SH'
#!/usr/bin/env bash
# resolve symlinks (e.g. a /usr/local/bin/carcal -> the bundle) to find our dir
src="$0"
while [ -h "$src" ]; do
  d="$(cd "$(dirname "$src")" && pwd)"; src="$(readlink "$src")"
  case "$src" in /*) ;; *) src="$d/$src" ;; esac
done
here="$(cd "$(dirname "$src")" && pwd)"
export LD_LIBRARY_PATH="$here/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CARCAL_PROTOS_DIR="$here/share/carcal/protos"
export CARCAL_GRAMMARS_DIR="$here/share/carcal/grammars"
exec "$here/bin/carcal" "$@"
SH
chmod +x "$OUT/carcal"

tar -C "$ROOT/dist" -czf "$ROOT/dist/$NAME.tar.gz" "$NAME"
echo "==> $ROOT/dist/$NAME.tar.gz"
