# caracal

A terminal packet analyzer — a tiny Wireshark for the TUI. caracal opens
pcap/pcapng captures, lists packets in a **table view**, shows the selected
packet's protocol layers in a **tree view**, and filters with a
**Wireshark/tshark-compatible display-filter** syntax. New protocols can be
defined at runtime with libpcapng-style `.posa` files and bound to ports.

Built on:

- **[gtcaca](../gtcaca)** — libcaca TUI widget toolkit (table, tree, menu,
  filechooser, dialog, entry, status bar).
- **[libpcapng](../libpcapng)** — pcapng reading; `.posa` protocol concept.

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

## Scope / limitations

- **Reading only** — live capture is not implemented (libpcapng has no live
  capture path yet). pcapng is read via libpcapng; classic `.pcap` via a small
  built-in reader.
- Built-in dissectors: Ethernet/802.1Q, IPv4, IPv6 (base header), ARP, TCP,
  UDP, ICMP/ICMPv6, DNS. Everything else is reachable through `.posa`.
- Filters use "any" matching semantics for multi-valued fields, like Wireshark.
