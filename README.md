# carcal

![carcal in action](carcalui.png)

A terminal packet analyzer — a tiny Wireshark for the TUI. carcal opens
pcap/pcapng captures, lists packets in a **table view**, shows the selected
packet's protocol layers in a **tree view**, and filters with a
**Wireshark/tshark-compatible display-filter** syntax. New protocols can be
defined at runtime with libpcapng-style `.posa` files and bound to ports.

It also has a **command-line scripting mode** (a generalized
[MQS](https://github.com/stricaud/MQS)): instead of decoding only MySQL and
handing a query string to Lua, carcal decodes *any* protocol and hands the
fully decoded fields — and reassembled IP datagrams and TCP streams — to a
**LuaJIT** script.

Built on:

- **[gtcaca](../gtcaca)** — libcaca TUI widget toolkit (table, tree, menu,
  filechooser, dialog, entry, status bar).
- **[libpcapng](../libpcapng)** — pcapng reading; IP-fragment and TCP-stream
  reassembly (`libpcapng_reasm_*`, `pcapng_tcp_reasm_*`); `.posa` protocols.
- **LuaJIT** — embedded scripting engine (found via `pkg-config`).

## Building

Both dependencies must be built first (their `build/` trees are found
automatically as siblings of this repo). libcaca is found via `pkg-config`.

```sh
mkdir build && cd build
cmake ..
make
./carcal /path/to/capture.pcapng
```

Override dependency locations if they live elsewhere:

```sh
cmake .. -DGTCACA_ROOT=/path/to/gtcaca -DLIBPCAPNG_ROOT=/path/to/libpcapng
```

> **Runtime note.** carcal needs the *current* gtcaca and libpcapng shared
> libraries (the scripting mode uses libpcapng's reassembly API). If an older
> copy is already installed in `/usr/local/lib`, it can shadow the freshly built
> one. Either install the up-to-date libraries from their build dirs
> (`sudo make install` in each `build/`), or run with
> `DYLD_LIBRARY_PATH=/path/to/libpcapng/build/lib`.

## Using it

| Key | Action |
|-----|--------|
| `F2` / `^O` | Open a capture file |
| `F10` | Open the menu bar (File / Analyze / Help) |
| `/` | Jump to the display-filter box |
| `Tab` | Cycle focus: filter → packet table → detail tree |
| `↑ ↓ PgUp PgDn Home End` | Navigate the focused pane |
| `← → / Space / Enter` | Collapse/expand a detail-tree node |
| `^F` | Find packet (text, or `hex:DE AD BE EF`) |
| `n` / `N` | Jump to next / previous find match |
| `q` / `^Q` | Quit |

The lower area is split into the **detail tree** (left) and a Wireshark-style
**hex byte pane** (right) for the selected packet. Menus (F10):

- **Edit** — Find Packet / Find Next / Find Previous.
- **Analyze** — Follow TCP Stream, Follow UDP Stream, Decode As…, Decoders…
  (list built-in + loaded `.posa` decoders; `i` import a `.posa`, `n` write a
  new one in the built-in editor with a posa cheat-sheet panel; `^S` saves &
  loads it).
- **Statistics** — IO Graph (packets per interval; green = all, yellow = current
  filter match), drawn with gtcaca's line chart.

### Display filters

Type an expression in the filter box and press `Enter`. Examples:

```
ip.addr == 192.168.1.0/24
tcp.port == 443 && ip.src != 10.0.0.1
udp and dns.qry.name contains "example"
icmp || arp
tcp.flags == 0x12
eth.src == aa:bb:cc:dd:ee:ff
```

Operators: `== eq`, `!= ne`, `> gt`, `< lt`, `>= ge`, `<= le`, `contains`,
`matches` (substring), `&& and`, `|| or`, `! not`, parentheses. Fields use
Wireshark names (`ip.src`, `tcp.dstport`, `dns.qry.name`, …). Aliases match
either direction: `ip.addr`, `ipv6.addr`, `tcp.port`, `udp.port`, `eth.addr`.

A bare field name is an existence test (`tcp`, `dns`).

### Custom protocols (.posa)

carcal loads every `*.posa` in its `protos/` directory at startup, and you can
load more with **File ▸ Load .posa…**. A definition looks like:

```
Object<main> SensorBeacon
    required mac    sensor_mac = 00:00:00:00:00:00
    required ip4    sensor_ip  = 0.0.0.0
    required uint32 uptime_sec = 0
    required uint16 battery_mv = 3300
    required uint8  seq = 0
```

Bind it to a transport port either **in the file itself**, with a `rule` line —

```
rule udp.port == 6666 => SensorBeacon
```

— or at runtime via **Analyze ▸ Decode As…**, entering e.g. `udp 6666
SensorBeacon`. Matching packets are then dissected with that protocol, its fields
appearing in the detail tree and usable in filters (`SensorBeacon.seq == 1`).

Bindings are **entirely data-driven**: a `rule` line is applied by libpcapng while
dissecting, so dropping a `.posa` into `protos/` is all it takes to teach carcal a
new protocol — no C change and no rebuild. (There are deliberately no compiled-in
decoder rules; adding one that a `.posa` already declares would decode the packet
twice and attach the subtree twice.) `rule` binds a port; **Decode As…** and
`protos/decoders.rules` take any display-filter condition, for what a port can't
express.

Field types: `uint8/16/32/64`, `le_uint16/32/64`, `mac`, `ip4`, `cstring`,
`payload`, `bytes<N>`, `bytes[lenfield]`. Indented `NAME = value` lines under an
integer field define enum labels. `Object<parent>` groups sub-protocols
dispatched on the first field's value (see `protos/tftp.posa`). The extended
grammar adds `layer`, `scope`, `when`, `string … until`, `info` and `rule` — see
`protos/rdp.posa`.

### Bundled decoders

| file | protocol | binds to |
| --- | --- | --- |
| `protos/tftp.posa` | TFTP (RFC 1350), dispatched by opcode | `udp.port == 69` |
| `protos/rdp.posa` | RDP over TPKT / X.224 COTP — connection request/confirm, `mstshash` cookie and the negotiation request (requested security protocols) | `tcp.port == 3389` |

## Command-line scripting (LuaJIT)

Drive captures from a Lua script — the generalized MQS use-case. Selecting `-s`
enters scripting mode (no TUI):

```sh
carcal -s script.lua -r capture.pcapng \
        [-f "display filter"] [-X "tcp 3306 MySQL"] [-p extra.posa]
```

| Flag | Meaning |
|------|---------|
| `-s` | Lua script to run |
| `-r` | capture file to read (pcap/pcapng) |
| `-f` | display filter limiting which packets reach `packet()` |
| `-X` | bind a port to a `.posa` protocol (`"<udp\|tcp> <port> <Proto>"`), repeatable |
| `-p` | load an extra `.posa` file, repeatable |

A script defines any of these entry points:

```lua
function init()          end   -- once, before processing
function packet(pkt)     end   -- per (IP-defragmented) packet
function stream(s)       end   -- per reassembled in-order TCP chunk
function finish(stats)   end   -- once, after processing
```

`pkt` carries the decoded packet and its fields in their various forms:

```lua
pkt.number, pkt.time, pkt.len, pkt.protocol, pkt.src, pkt.dst, pkt.info
pkt.srcport, pkt.dstport, pkt.l4, pkt.payload   -- transport payload (full bytes)
pkt.raw                                          -- whole frame bytes
pkt.layers          -- { "eth", "ip", "tcp", … }  ordered
pkt.fields["ip.src"]                             -- natural Lua value
pkt:get("ip.src")   -- { type=, value=, hex=, label= }  (the "various ways")
pkt:getall("ip.addr")                            -- every matching field
pkt:has("tcp")                                   -- existence test
pkt:matches("tcp.flags == 0x02")                 -- the display-filter engine
```

Globals decode arbitrary bytes — including "the various ways a protocol can be
decoded":

```lua
carcal.decode_as(bytes, "TFTP")    -- dispatched posa decode → {field=value,…}
carcal.decode_all(bytes, "TFTP")   -- every candidate sub-protocol's decode
carcal.dissect(bytes [, linktype]) -- full built-in dissection of raw bytes
carcal.protocols()                 -- names of loaded posa protocols
carcal.hex(bytes)
```

### Reassembly

- **IP fragments** are reassembled by libpcapng (`libpcapng_reasm_add`); a
  fragmented datagram reaches `packet()` whole.
- **TCP streams** are reassembled by libpcapng's `pcapng_tcp_reasm_*` API (added
  as a library feature, not specific to carcal). In-order bytes per direction
  arrive at `stream(s)` with `s.data` (new bytes), `s.all` (cumulative),
  `s.src/dst/srcport/dstport/dir`, and `s:decode_as(proto)`.

Bundled examples are in [`scripts/`](scripts/): `summary.lua`, `fields.lua`,
`tftp.lua`, and `mysql-queries.lua` (sniff MariaDB/MySQL `COM_QUERY` statements
from a reassembled stream — the MQS use-case, on any capture file):

```sh
carcal -s scripts/mysql-queries.lua -r dump.pcapng -f "tcp.port == 3306"
```

## Download

Prebuilt binaries for **Windows, macOS and Linux**:
**[stricaud.github.io/carcal](https://stricaud.github.io/carcal/)** (or the
[releases page](https://github.com/stricaud/carcal/releases)).

On macOS, open the `.dmg` and either drag `carcal.app` to Applications or run the
`.pkg` inside it to get `carcal` on your `PATH`.

On Windows, either run the `setup.exe` installer (Start Menu entry, optional
`.pcap`/`.pcapng` association, uninstaller) or unzip the portable `.zip` anywhere
and run `carcal.exe` — no admin rights needed; it finds its `protos\` and
`grammars\` next to the executable. Note that **live capture is not available on
Windows** (see [Live capture](#live-capture)); opening capture files is fully
supported.

## Packaging (Linux, macOS & Windows)

`packaging/build.sh` builds carcal + the sibling libraries (gtcaca, libpcapng)
in Release and produces a **self-contained** bundle under `dist/` — every
non-system library (gtcaca, libpcapng, libcaca, luajit, oniguruma) is bundled
and the binary's load paths are rewritten (`@executable_path/../lib` on macOS,
`$ORIGIN/../lib` on Linux), so it runs with no Homebrew / `LD_LIBRARY_PATH`.
On Windows the DLLs simply sit next to `carcal.exe`, which is where Windows
looks first.

```sh
# libraries checked out next to this repo (../gtcaca, ../libpcapng):
packaging/build.sh
# → dist/carcal-macos-arm64.tar.gz   (or carcal-linux-x86_64.tar.gz, …)
# → dist/carcal-windows-x86_64.zip   (from an MSYS2 UCRT64 shell)
```

The Windows build uses **MSYS2 / MinGW-w64 (UCRT64)**, where libcaca, LuaJIT and
oniguruma are all available prebuilt:

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-{toolchain,cmake,ninja,libcaca,luajit,oniguruma,nsis} zip
packaging/build.sh          # from the UCRT64 shell
```

The tarball contains `carcal` (a launcher that points at its bundled
`protos/` and `grammars/`), `bin/carcal`, and `lib/`. carcal honors
`CARCAL_PROTOS_DIR` / `CARCAL_GRAMMARS_DIR` so the bundle finds its data
wherever it's unpacked.

`build.sh` also emits a native installer alongside the tarball:

- **macOS** — `dist/carcal-macos-<arch>.dmg`, the disk image users actually
  download. It holds both `carcal.app` (drag to the `/Applications` symlink;
  double-clicking opens carcal in a new Terminal window, since it's a TUI) and
  the `.pkg` for anyone who'd rather have `carcal` on their `PATH`. Also emitted
  standalone: `dist/carcal-macos-<arch>.pkg` (installs to `/usr/local/carcal`,
  symlinks `/usr/local/bin/carcal`). Both are unsigned, so first run is
  right-click ▸ Open; sign/notarize separately for wide distribution.
- **Linux** — `dist/carcal-linux-<arch>.AppImage`, a single self-contained
  executable (built with `linuxdeploy`; an `AppRun` hook points carcal at its
  bundled data). Falls back to just the tarball if `linuxdeploy` can't be
  fetched.
- **Windows** — `dist/carcal-<version>-<arch>-setup.exe`, an NSIS installer
  ([packaging/carcal.nsi](packaging/carcal.nsi)) that installs the same tree the
  zip contains, plus a Start Menu entry, an Add/Remove Programs entry and an
  uninstaller. Associating `.pcap`/`.pcapng` with carcal is an **optional,
  off-by-default** component, so it never silently steals the extensions from
  Wireshark. Unsigned, so SmartScreen will warn on first run; sign separately for
  wide distribution. Skipped with a warning if `makensis` isn't installed.

CI ([.github/workflows/release.yml](.github/workflows/release.yml)) builds the
same artifacts on a matrix (Linux x86_64, macOS arm64, Windows x86_64) and
attaches them to a release when a `v*` tag is pushed. gtcaca and libpcapng are
pinned by commit (`GTCACA_REF` / `LIBPCAPNG_REF` at the top of the workflow), so
re-running an old tag rebuilds it identically instead of picking up whatever has
since landed on their default branches — bump those two refs to take new library
versions. Cross-compiling is
intentionally avoided — each platform builds natively (libcaca's terminal
backends make cross-builds of the C dependencies more trouble than a CI matrix).
The Windows job also smoke-tests the *packaged* exe with `--dump`, so a missing
DLL or a broken data-dir lookup fails the build instead of shipping.

The download page at [docs/index.html](docs/index.html) is served by GitHub Pages
and reads the latest release from the GitHub API at load time, so pushing a tag
is all it takes to update it.

## Live capture

**Capture ▸ Start…** lists your interfaces (via libpcapng's live-capture API),
lets you pick one and optionally enter a capture filter (Wireshark display-
filter syntax, applied in-kernel), and streams packets into the table in real
time — the display filter still narrows what's shown, and the view auto-follows
the newest packet. **Capture ▸ Stop** ends it.

Opening an interface needs privileges: **root**, or on Linux
`sudo setcap cap_net_raw+eip $(readlink -f ./carcal)`. Listing interfaces does
not. Captured frames are assumed Ethernet.

**Not available on Windows.** libpcapng's capture backends are Linux
(`PACKET_MMAP`) and BSD/macOS (`bpf`); there is no Npcap backend, so on Windows
the capture API compiles to stubs, the interface list comes back empty and
**Capture ▸ Start…** reports that live capture is unsupported. Capture with
Wireshark/`dumpcap` and open the file in carcal instead.

## Scope / limitations

- pcapng is read via libpcapng; classic `.pcap` via a small built-in reader;
  live capture via libpcapng's capture API (Linux `PACKET_MMAP`, macOS `bpf`;
  unsupported on Windows).
- Built-in dissectors: Ethernet/802.1Q, IPv4, IPv6 (base header), ARP, TCP,
  UDP, ICMP/ICMPv6, DNS. Everything else is reachable through `.posa`.
- Filters use "any" matching semantics for multi-valued fields, like Wireshark.
