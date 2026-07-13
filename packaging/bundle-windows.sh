#!/usr/bin/env bash
#
# bundle-windows.sh — produce a self-contained Windows zip: carcal.exe plus
# every non-system DLL it needs (from ldd, which is transitive under MSYS2),
# with protos/ and grammars/ alongside the exe.
#
# Run from an MSYS2 MinGW shell (UCRT64), after packaging/build.sh has built
# build/carcal.exe.
#
# The layout is deliberately flat — carcal.exe resolves protos/ and grammars/
# relative to its own location (see exe_relative_dir in src/main.c), and Windows
# looks for DLLs in the exe's directory first, so the zip runs from anywhere
# with no launcher, no installer and no PATH changes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${GTCACA_SRC:=$ROOT/../gtcaca}"
: "${LIBPCAPNG_SRC:=$ROOT/../libpcapng}"
ARCH="${MSYSTEM_CARCH:-x86_64}"
NAME="carcal-windows-$ARCH"
OUT="$ROOT/dist/$NAME"
BIN="$ROOT/build/carcal.exe"

[ -f "$BIN" ] || { echo "build first: $BIN missing" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$BIN" "$OUT/carcal.exe"

# ldd resolves DLLs through PATH, and the two sibling libraries live in their
# build trees rather than the MSYS2 prefix — without this they'd come back "not
# found" and we would ship a zip that cannot start.
export PATH="$LIBPCAPNG_SRC/build/lib:$GTCACA_SRC/build/src:$PATH"

# Copy the non-system DLLs ldd reports (ldd is transitive). Anything under
# /c/Windows belongs to the OS (kernel32, msvcrt, ...) and must never be
# shipped; the rest come from the MSYS2 prefix or the build trees, and do.
missing=0
while read -r name arrow dll rest; do
  [ "$arrow" = "=>" ] || continue
  case "$(printf '%s' "$dll" | tr 'A-Z' 'a-z')" in
    /c/windows/*) continue ;;                      # system DLL — never bundle
    ""|"not")                                      # "libfoo.dll => not found"
      echo "  ! unresolved: $name" >&2; missing=1; continue ;;
  esac
  [ -f "$dll" ] || { echo "  ! unresolved: $name" >&2; missing=1; continue; }
  cp -f "$dll" "$OUT/$(basename "$dll")"
done < <(ldd "$BIN")
[ "$missing" -eq 0 ] || { echo "refusing to ship an incomplete bundle" >&2; exit 1; }

cp -R "$ROOT/protos" "$ROOT/grammars" "$ROOT/scripts" "$OUT/" 2>/dev/null || true

cat > "$OUT/README.txt" <<'TXT'
carcal — a terminal packet analyzer (a tiny Wireshark for the TUI)

Run carcal.exe from a terminal, optionally with a capture file:

    carcal.exe path\to\capture.pcapng

Everything needed is in this folder — no installation required. Keep
carcal.exe together with the DLLs and the protos\ and grammars\ folders.

Note: opening capture FILES is fully supported. Live capture from a network
interface is not available on Windows (it needs a raw-socket backend carcal
does not yet have there); use a capture file from Wireshark/dumpcap instead.

For the best display, run carcal in Windows Terminal.

https://github.com/stricaud/carcal
TXT

( cd "$ROOT/dist" && zip -qr "$NAME.zip" "$NAME" )
echo "==> $ROOT/dist/$NAME.zip"
