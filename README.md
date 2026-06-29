# caracal

A terminal packet analyzer — a tiny Wireshark for the TUI. caracal opens
pcap/pcapng captures, lists packets in a **table view**, shows the selected
packet's protocol layers in a **tree view**, and filters with a
**Wireshark/tshark-compatible display-filter** syntax. New protocols can be
defined at runtime with libpcapng-style `.posa` files and bound to ports.

It also has a **command-line scripting mode** (a generalized
[MQS](https://github.com/stricaud/MQS)): instead of decoding only MySQL and
handing a query string to Lua, caracal decodes *any* protocol and hands the
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
./caracal /path/to/capture.pcapng
```

Override dependency locations if they live elsewhere:

```sh
cmake .. -DGTCACA_ROOT=/path/to/gtcaca -DLIBPCAPNG_ROOT=/path/to/libpcapng
```

> **Runtime note.** caracal needs the *current* gtcaca and libpcapng shared
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
| `q` / `^Q` | Quit |

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

caracal loads every `*.posa` in its `protos/` directory at startup, and you can
load more with **File ▸ Load .posa…**. A definition looks like:

```
Object<main> SensorBeacon
    required mac    sensor_mac = 00:00:00:00:00:00
    required ip4    sensor_ip  = 0.0.0.0
    required uint32 uptime_sec = 0
    required uint16 battery_mv = 3300
    required uint8  seq = 0
```

Then bind it to a transport port via **Analyze ▸ Decode As…**, entering e.g.
`udp 6666 SensorBeacon`. Matching packets are then dissected with that protocol,
its fields appearing in the detail tree and usable in filters
(`SensorBeacon.seq == 1`).

Field types: `uint8/16/32/64`, `le_uint16/32/64`, `mac`, `ip4`, `cstring`,
`payload`, `bytes<N>`, `bytes[lenfield]`. Indented `NAME = value` lines under an
integer field define enum labels. `Object<parent>` groups sub-protocols
dispatched on the first field's value (see `protos/tftp.posa`).

## Command-line scripting (LuaJIT)

Drive captures from a Lua script — the generalized MQS use-case. Selecting `-s`
enters scripting mode (no TUI):

```sh
caracal -s script.lua -r capture.pcapng \
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
caracal.decode_as(bytes, "TFTP")    -- dispatched posa decode → {field=value,…}
caracal.decode_all(bytes, "TFTP")   -- every candidate sub-protocol's decode
caracal.dissect(bytes [, linktype]) -- full built-in dissection of raw bytes
caracal.protocols()                 -- names of loaded posa protocols
caracal.hex(bytes)
```

### Reassembly

- **IP fragments** are reassembled by libpcapng (`libpcapng_reasm_add`); a
  fragmented datagram reaches `packet()` whole.
- **TCP streams** are reassembled by libpcapng's `pcapng_tcp_reasm_*` API (added
  as a library feature, not specific to caracal). In-order bytes per direction
  arrive at `stream(s)` with `s.data` (new bytes), `s.all` (cumulative),
  `s.src/dst/srcport/dstport/dir`, and `s:decode_as(proto)`.

Bundled examples are in [`scripts/`](scripts/): `summary.lua`, `fields.lua`,
`tftp.lua`, and `mysql-queries.lua` (sniff MariaDB/MySQL `COM_QUERY` statements
from a reassembled stream — the MQS use-case, on any capture file):

```sh
caracal -s scripts/mysql-queries.lua -r dump.pcapng -f "tcp.port == 3306"
```

## Scope / limitations

- **Reading only** — live capture is not implemented (libpcapng has no live
  capture path yet). pcapng is read via libpcapng; classic `.pcap` via a small
  built-in reader.
- Built-in dissectors: Ethernet/802.1Q, IPv4, IPv6 (base header), ARP, TCP,
  UDP, ICMP/ICMPv6, DNS. Everything else is reachable through `.posa`.
- Filters use "any" matching semantics for multi-valued fields, like Wireshark.
