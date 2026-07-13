#!/usr/bin/env bash
#
# bundle-macos.sh — produce a self-contained macOS tarball: the carcal binary
# plus every non-system dylib it needs, with install-names rewritten to
# @executable_path/../lib so it runs anywhere (no Homebrew / DYLD_LIBRARY_PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${GTCACA_SRC:=$ROOT/../gtcaca}"
: "${LIBPCAPNG_SRC:=$ROOT/../libpcapng}"
ARCH="$(uname -m)"
NAME="carcal-macos-$ARCH"
OUT="$ROOT/dist/$NAME"
BIN="$ROOT/build/carcal"

# where @rpath/@loader_path deps may live
SEARCH=("$GTCACA_SRC/build/src" "$LIBPCAPNG_SRC/build/lib" /usr/local/lib /opt/homebrew/lib)

[ -x "$BIN" ] || { echo "build first: $BIN missing" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/bin" "$OUT/lib" "$OUT/share/carcal"
cp "$BIN" "$OUT/bin/carcal"; chmod u+w "$OUT/bin/carcal"

resolve() {                       # echo absolute path of a dependency, or fail
  local dep="$1" base; base="$(basename "$dep")"
  case "$dep" in
    /usr/lib/*|/System/*) return 1 ;;                 # system — never bundle
    /*) [ -f "$dep" ] && { echo "$dep"; return 0; }; return 1 ;;
    *)  for d in "${SEARCH[@]}"; do [ -f "$d/$base" ] && { echo "$d/$base"; return 0; }; done
        return 1 ;;
  esac
}

worklist=("$OUT/bin/carcal")
while [ ${#worklist[@]} -gt 0 ]; do
  f="${worklist[0]}"; worklist=("${worklist[@]:1}")
  while IFS= read -r dep; do
    case "$dep" in /usr/lib/*|/System/*) continue ;; esac
    base="$(basename "$dep")"
    [ "$base" = "$(basename "$f")" ] && continue       # self-reference
    if [ ! -f "$OUT/lib/$base" ]; then
      real="$(resolve "$dep")" || { echo "  ! unresolved: $dep" >&2; continue; }
      cp "$real" "$OUT/lib/$base"; chmod u+w "$OUT/lib/$base"
      install_name_tool -id "@executable_path/../lib/$base" "$OUT/lib/$base"
      worklist+=("$OUT/lib/$base")
    fi
    install_name_tool -change "$dep" "@executable_path/../lib/$base" "$f"
  done < <(otool -L "$f" | tail -n +2 | awk '{print $1}')
done

install_name_tool -add_rpath "@executable_path/../lib" "$OUT/bin/carcal" 2>/dev/null || true

# re-sign (install_name_tool invalidates the signature; required on Apple Silicon)
codesign -f -s - "$OUT/bin/carcal" 2>/dev/null || true
for l in "$OUT"/lib/*.dylib; do codesign -f -s - "$l" 2>/dev/null || true; done

# data + a launcher that points carcal at the bundled protos/grammars
cp -R "$ROOT/protos" "$ROOT/grammars" "$ROOT/scripts" "$OUT/share/carcal/" 2>/dev/null || true
cat > "$OUT/carcal" <<'SH'
#!/usr/bin/env bash
# resolve symlinks (e.g. /usr/local/bin/carcal -> the bundle) to find our dir
src="$0"
while [ -h "$src" ]; do
  d="$(cd "$(dirname "$src")" && pwd)"; src="$(readlink "$src")"
  case "$src" in /*) ;; *) src="$d/$src" ;; esac
done
here="$(cd "$(dirname "$src")" && pwd)"
export CARCAL_PROTOS_DIR="$here/share/carcal/protos"
export CARCAL_GRAMMARS_DIR="$here/share/carcal/grammars"
exec "$here/bin/carcal" "$@"
SH
chmod +x "$OUT/carcal"

tar -C "$ROOT/dist" -czf "$ROOT/dist/$NAME.tar.gz" "$NAME"
echo "==> $ROOT/dist/$NAME.tar.gz"
