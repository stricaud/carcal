/* dissect.c — turn captured bytes into a cfield tree of protocol layers.
 *
 * Each protocol gets a structural node (abbrev = the protocol name, e.g. "ip")
 * whose children are its fields (abbrev = Wireshark name, e.g. "ip.src"). The
 * same tree feeds the detail tree view, the column summaries, and the display
 * filter, so field names match what tshark users expect.
 */
#include "caracal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include <libpcapng/protocols/ntp.h>   /* struct libpcapng_ntp_hdr (wire layout)   */
#include <libpcapng/protocols/bootp.h> /* struct libpcapng_bootp_hdr (DHCP/BOOTP)  */
#include <libpcapng/protocols/ssl.h>   /* TLS_CONTENT_*, TLS_VERSION_* constants    */

/* ── safe big/little-endian readers ─────────────────────────────────────── */
static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

/* summary sink (NULL when we only need the tree) + packet base for byte ranges */
typedef struct { cpkt_t *sum; const uint8_t *base; } dctx_t;

/* record a node's absolute byte range within the packet (for the hex pane) */
static void set_range(dctx_t *c, cfield_t *n, const uint8_t *p, int len)
{
  if (n && c->base) { n->off = (int)(p - c->base); n->len = len; }
}

static void set_proto(dctx_t *c, const char *name)
{ if (c->sum) snprintf(c->sum->col_proto, sizeof c->sum->col_proto, "%s", name); }
static void set_info(dctx_t *c, const char *fmt, ...)
{
  va_list ap;
  if (!c->sum) return;
  va_start(ap, fmt);
  vsnprintf(c->sum->col_info, sizeof c->sum->col_info, fmt, ap);
  va_end(ap);
}
static void set_src(dctx_t *c, const char *s)
{ if (c->sum) snprintf(c->sum->col_src, sizeof c->sum->col_src, "%s", s); }
static void set_dst(dctx_t *c, const char *s)
{ if (c->sum) snprintf(c->sum->col_dst, sizeof c->sum->col_dst, "%s", s); }

/* forward decls */
static void dissect_l3(dctx_t *c, uint16_t ethertype, const uint8_t *d, int len, cfield_t *root);
static void dissect_ipv4(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_ipv6(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_arp (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_tcp (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_udp (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_icmp(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_dns (dctx_t *c, const uint8_t *d, int len, cfield_t *root, const char *proto);
static void dissect_ntp (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_igmp(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_gre (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_dhcp(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_snmp(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_radius(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_nbns(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_tls (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_ssh (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_http(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_rdp (dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_quic(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_data(dctx_t *c, const uint8_t *d, int len, cfield_t *root);
static void dissect_text(dctx_t *c, const uint8_t *d, int len, cfield_t *root,
                         const char *abbrev, const char *name);

/* ── frame (always present) ─────────────────────────────────────────────── */
static void dissect_frame(dctx_t *c, const cpkt_t *pkt, cfield_t *root)
{
  cfield_t *fr = cfield_add(root, "frame", CV_NONE);
  cfield_t *f;
  cfield_set_label(fr, "Frame: %u bytes on wire, %u captured",
                   pkt->origlen, pkt->caplen);
  set_range(c, fr, pkt->data, (int)pkt->caplen);
  f = cfield_add(fr, "frame.len", CV_UINT);
  cfield_set_uint(f, pkt->origlen);
  cfield_set_label(f, "Frame Length: %u", pkt->origlen);
  f = cfield_add(fr, "frame.cap_len", CV_UINT);
  cfield_set_uint(f, pkt->caplen);
  cfield_set_label(f, "Capture Length: %u", pkt->caplen);
}

/* ── Ethernet ───────────────────────────────────────────────────────────── */
static void dissect_ethernet(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *eth, *f;
  uint16_t type;
  char dsts[24], srcs[24];

  if (len < 14) { set_proto(c, "Ethernet"); return; }
  snprintf(dsts, sizeof dsts, "%02x:%02x:%02x:%02x:%02x:%02x", d[0],d[1],d[2],d[3],d[4],d[5]);
  snprintf(srcs, sizeof srcs, "%02x:%02x:%02x:%02x:%02x:%02x", d[6],d[7],d[8],d[9],d[10],d[11]);
  type = be16(d + 12);

  eth = cfield_add(root, "eth", CV_NONE);
  cfield_set_label(eth, "Ethernet II, Src: %s, Dst: %s", srcs, dsts);
  set_range(c, eth, d, 14);

  f = cfield_add(eth, "eth.dst", CV_MAC); cfield_set_mac(f, d);
  cfield_set_label(f, "Destination: %s", dsts);
  f = cfield_add(eth, "eth.src", CV_MAC); cfield_set_mac(f, d + 6);
  cfield_set_label(f, "Source: %s", srcs);
  f = cfield_add(eth, "eth.type", CV_UINT); cfield_set_uint(f, type);
  cfield_set_label(f, "Type: 0x%04x", type);

  set_proto(c, "Ethernet");
  set_src(c, srcs);
  set_dst(c, dsts);
  set_info(c, "Ethernet II");

  /* 802.1Q VLAN tag — step over one tag for L3 dispatch. */
  if (type == 0x8100 && len >= 18) {
    uint16_t vid = be16(d + 14) & 0x0fff;
    cfield_t *v = cfield_add(root, "vlan", CV_NONE);
    cfield_t *vf = cfield_add(v, "vlan.id", CV_UINT);
    cfield_set_uint(vf, vid);
    cfield_set_label(v, "802.1Q Virtual LAN, ID: %u", vid);
    cfield_set_label(vf, "VLAN ID: %u", vid);
    dissect_l3(c, be16(d + 16), d + 18, len - 18, root);
    return;
  }
  dissect_l3(c, type, d + 14, len - 14, root);
}

static void dissect_l3(dctx_t *c, uint16_t ethertype, const uint8_t *d, int len, cfield_t *root)
{
  if (len <= 0) return;
  switch (ethertype) {
  case 0x0800: dissect_ipv4(c, d, len, root); break;
  case 0x86DD: dissect_ipv6(c, d, len, root); break;
  case 0x0806: dissect_arp (c, d, len, root); break;
  default: break;
  }
}

/* ── IPv4 ───────────────────────────────────────────────────────────────── */
static const char *ipproto_name(uint8_t p)
{
  switch (p) {
  case 1:  return "ICMP";
  case 2:  return "IGMP";
  case 6:  return "TCP";
  case 17: return "UDP";
  case 41: return "IPv6";
  case 47: return "GRE";
  case 50: return "ESP";
  case 89: return "OSPF";
  default: return "IP";
  }
}

static void dissect_ipv4(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *ip, *f;
  int ihl;
  uint8_t proto;
  uint16_t total;
  char ss[16], ds[16];

  if (len < 20) { set_proto(c, "IPv4"); return; }
  ihl   = (d[0] & 0x0f) * 4;
  total = be16(d + 2);
  proto = d[9];
  snprintf(ss, sizeof ss, "%u.%u.%u.%u", d[12], d[13], d[14], d[15]);
  snprintf(ds, sizeof ds, "%u.%u.%u.%u", d[16], d[17], d[18], d[19]);

  ip = cfield_add(root, "ip", CV_NONE);
  cfield_set_label(ip, "Internet Protocol Version 4, Src: %s, Dst: %s", ss, ds);
  set_range(c, ip, d, ihl >= 20 ? ihl : 20);

  f = cfield_add(ip, "ip.version", CV_UINT); cfield_set_uint(f, d[0] >> 4);
  cfield_set_label(f, "Version: %u", d[0] >> 4);
  f = cfield_add(ip, "ip.hdr_len", CV_UINT); cfield_set_uint(f, ihl);
  cfield_set_label(f, "Header Length: %d bytes", ihl);
  f = cfield_add(ip, "ip.dsfield", CV_UINT); cfield_set_uint(f, d[1]);
  cfield_set_label(f, "Differentiated Services Field: 0x%02x", d[1]);
  f = cfield_add(ip, "ip.len", CV_UINT); cfield_set_uint(f, total);
  cfield_set_label(f, "Total Length: %u", total);
  f = cfield_add(ip, "ip.id", CV_UINT); cfield_set_uint(f, be16(d + 4));
  cfield_set_label(f, "Identification: 0x%04x (%u)", be16(d + 4), be16(d + 4));
  f = cfield_add(ip, "ip.flags", CV_UINT); cfield_set_uint(f, d[6] >> 5);
  cfield_set_label(f, "Flags: 0x%02x", d[6] >> 5);
  f = cfield_add(ip, "ip.frag_offset", CV_UINT); cfield_set_uint(f, be16(d + 6) & 0x1fff);
  cfield_set_label(f, "Fragment Offset: %u", be16(d + 6) & 0x1fff);
  f = cfield_add(ip, "ip.ttl", CV_UINT); cfield_set_uint(f, d[8]);
  cfield_set_label(f, "Time to Live: %u", d[8]);
  f = cfield_add(ip, "ip.proto", CV_UINT); cfield_set_uint(f, proto);
  cfield_set_label(f, "Protocol: %s (%u)", ipproto_name(proto), proto);
  f = cfield_add(ip, "ip.checksum", CV_UINT); cfield_set_uint(f, be16(d + 10));
  cfield_set_label(f, "Header Checksum: 0x%04x", be16(d + 10));
  f = cfield_add(ip, "ip.src", CV_IPV4); cfield_set_ipv4(f, d + 12);
  cfield_set_label(f, "Source Address: %s", ss);
  f = cfield_add(ip, "ip.dst", CV_IPV4); cfield_set_ipv4(f, d + 16);
  cfield_set_label(f, "Destination Address: %s", ds);

  set_proto(c, "IPv4");
  set_src(c, ss);
  set_dst(c, ds);
  set_info(c, "%s", ipproto_name(proto));

  if (ihl < 20 || ihl > len) ihl = 20;
  {
    const uint8_t *pl = d + ihl;
    int pll = len - ihl;
    if (pll < 0) pll = 0;
    switch (proto) {
    case 1:  dissect_icmp(c, pl, pll, root); break;
    case 2:  dissect_igmp(c, pl, pll, root); break;
    case 6:  dissect_tcp (c, pl, pll, root); break;
    case 17: dissect_udp (c, pl, pll, root); break;
    case 47: dissect_gre (c, pl, pll, root); break;
    default: break;
    }
  }
}

/* ── IPv6 (base header only; no extension-header walking) ───────────────── */
static void dissect_ipv6(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *ip, *f;
  uint8_t nxt;
  char ss[40], ds[40];

  if (len < 40) { set_proto(c, "IPv6"); return; }
  nxt = d[6];

  f = cfield_add(root, "ipv6", CV_NONE);
  ip = f;
  set_range(c, ip, d, 40);
  { cfield_t *s = cfield_add(ip, "ipv6.src", CV_IPV6); cfield_set_ipv6(s, d + 8);
    snprintf(ss, sizeof ss, "%s", s->str);
    cfield_set_label(s, "Source Address: %s", ss); }
  { cfield_t *dd = cfield_add(ip, "ipv6.dst", CV_IPV6); cfield_set_ipv6(dd, d + 24);
    snprintf(ds, sizeof ds, "%s", dd->str);
    cfield_set_label(dd, "Destination Address: %s", ds); }
  cfield_set_label(ip, "Internet Protocol Version 6, Src: %s, Dst: %s", ss, ds);

  f = cfield_add(ip, "ipv6.plen", CV_UINT); cfield_set_uint(f, be16(d + 4));
  cfield_set_label(f, "Payload Length: %u", be16(d + 4));
  f = cfield_add(ip, "ipv6.nxt", CV_UINT); cfield_set_uint(f, nxt);
  cfield_set_label(f, "Next Header: %s (%u)", ipproto_name(nxt), nxt);
  f = cfield_add(ip, "ipv6.hlim", CV_UINT); cfield_set_uint(f, d[7]);
  cfield_set_label(f, "Hop Limit: %u", d[7]);

  set_proto(c, "IPv6");
  set_src(c, ss);
  set_dst(c, ds);
  set_info(c, "%s", ipproto_name(nxt));

  {
    const uint8_t *pl = d + 40;
    int pll = len - 40;
    switch (nxt) {
    case 6:  dissect_tcp(c, pl, pll, root); break;
    case 17: dissect_udp(c, pl, pll, root); break;
    case 58: { /* ICMPv6 — minimal */
      cfield_t *ic = cfield_add(root, "icmpv6", CV_NONE);
      if (pll >= 2) {
        cfield_t *t = cfield_add(ic, "icmpv6.type", CV_UINT); cfield_set_uint(t, pl[0]);
        cfield_set_label(t, "Type: %u", pl[0]);
      }
      cfield_set_label(ic, "Internet Control Message Protocol v6");
      set_proto(c, "ICMPv6");
      break;
    }
    default: break;
    }
  }
}

/* ── ARP ────────────────────────────────────────────────────────────────── */
static void dissect_arp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *a, *f;
  uint16_t op;
  char sip[16], dip[16], smac[24], dmac[24];

  if (len < 28) { set_proto(c, "ARP"); return; }
  op = be16(d + 6);
  snprintf(smac, sizeof smac, "%02x:%02x:%02x:%02x:%02x:%02x", d[8],d[9],d[10],d[11],d[12],d[13]);
  snprintf(sip,  sizeof sip,  "%u.%u.%u.%u", d[14], d[15], d[16], d[17]);
  snprintf(dmac, sizeof dmac, "%02x:%02x:%02x:%02x:%02x:%02x", d[18],d[19],d[20],d[21],d[22],d[23]);
  snprintf(dip,  sizeof dip,  "%u.%u.%u.%u", d[24], d[25], d[26], d[27]);

  a = cfield_add(root, "arp", CV_NONE);
  cfield_set_label(a, "Address Resolution Protocol (%s)", op == 1 ? "request" : op == 2 ? "reply" : "?");
  set_range(c, a, d, 28);
  f = cfield_add(a, "arp.opcode", CV_UINT); cfield_set_uint(f, op);
  cfield_set_label(f, "Opcode: %u", op);
  f = cfield_add(a, "arp.src.hw_mac", CV_MAC); cfield_set_mac(f, d + 8);
  cfield_set_label(f, "Sender MAC address: %s", smac);
  f = cfield_add(a, "arp.src.proto_ipv4", CV_IPV4); cfield_set_ipv4(f, d + 14);
  cfield_set_label(f, "Sender IP address: %s", sip);
  f = cfield_add(a, "arp.dst.hw_mac", CV_MAC); cfield_set_mac(f, d + 18);
  cfield_set_label(f, "Target MAC address: %s", dmac);
  f = cfield_add(a, "arp.dst.proto_ipv4", CV_IPV4); cfield_set_ipv4(f, d + 24);
  cfield_set_label(f, "Target IP address: %s", dip);

  set_proto(c, "ARP");
  set_src(c, smac);
  set_dst(c, dmac);
  if (op == 1)      set_info(c, "Who has %s? Tell %s", dip, sip);
  else if (op == 2) set_info(c, "%s is at %s", sip, smac);
  else              set_info(c, "ARP opcode %u", op);
}

/* ── TCP ────────────────────────────────────────────────────────────────── */
static void dissect_tcp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *t, *f;
  uint16_t sp, dp;
  uint8_t flags;
  int doff;
  char fs[40];

  if (len < 20) { set_proto(c, "TCP"); return; }
  sp = be16(d + 0);
  dp = be16(d + 2);
  doff = ((d[12] >> 4) & 0x0f) * 4;
  flags = d[13];

  fs[0] = '\0';
  if (flags & 0x02) strcat(fs, "SYN ");
  if (flags & 0x10) strcat(fs, "ACK ");
  if (flags & 0x01) strcat(fs, "FIN ");
  if (flags & 0x04) strcat(fs, "RST ");
  if (flags & 0x08) strcat(fs, "PSH ");
  if (flags & 0x20) strcat(fs, "URG ");
  if (fs[0]) fs[strlen(fs) - 1] = '\0';

  t = cfield_add(root, "tcp", CV_NONE);
  cfield_set_label(t, "Transmission Control Protocol, Src Port: %u, Dst Port: %u", sp, dp);
  set_range(c, t, d, (doff >= 20 && doff <= len) ? doff : 20);
  f = cfield_add(t, "tcp.srcport", CV_UINT); cfield_set_uint(f, sp);
  cfield_set_label(f, "Source Port: %u", sp);
  f = cfield_add(t, "tcp.dstport", CV_UINT); cfield_set_uint(f, dp);
  cfield_set_label(f, "Destination Port: %u", dp);
  f = cfield_add(t, "tcp.seq", CV_UINT); cfield_set_uint(f, be32(d + 4));
  cfield_set_label(f, "Sequence Number: %u", be32(d + 4));
  f = cfield_add(t, "tcp.ack", CV_UINT); cfield_set_uint(f, be32(d + 8));
  cfield_set_label(f, "Acknowledgment Number: %u", be32(d + 8));
  f = cfield_add(t, "tcp.hdr_len", CV_UINT); cfield_set_uint(f, doff);
  cfield_set_label(f, "Header Length: %d bytes", doff);
  f = cfield_add(t, "tcp.flags", CV_UINT); cfield_set_uint(f, flags);
  cfield_set_label(f, "Flags: 0x%03x (%s)", flags, fs);
  f = cfield_add(t, "tcp.window_size", CV_UINT); cfield_set_uint(f, be16(d + 14));
  cfield_set_label(f, "Window: %u", be16(d + 14));
  f = cfield_add(t, "tcp.checksum", CV_UINT); cfield_set_uint(f, be16(d + 16));
  cfield_set_label(f, "Checksum: 0x%04x", be16(d + 16));

  set_proto(c, "TCP");
  set_info(c, "%u \xe2\x86\x92 %u [%s] Seq=%u Win=%u Len=%d",
           sp, dp, fs, be32(d + 4), be16(d + 14),
           len - doff > 0 ? len - doff : 0);

  if (doff < 20 || doff > len) doff = 20;
  {
    const uint8_t *pl = d + doff;
    int pll = len - doff;
    const char *bound;
    if (pll <= 0) return;
    bound = posa_bound_tcp(sp);
    if (!bound) bound = posa_bound_tcp(dp);
    if (bound && posa_dissect(bound, pl, pll, root, (int)(pl - c->base)) > 0) {
      set_proto(c, bound);
      return;
    }
#define TP(x) (sp == (x) || dp == (x))
    if      (TP(80) || TP(8080) || TP(8000) || TP(8888) || TP(3128))
                                     dissect_http(c, pl, pll, root);
    else if (TP(443) || TP(8443))    dissect_tls(c, pl, pll, root);
    else if (TP(22))                 dissect_ssh(c, pl, pll, root);
    else if (TP(21))                 dissect_text(c, pl, pll, root, "ftp", "FTP");
    else if (TP(25) || TP(587))      dissect_text(c, pl, pll, root, "smtp", "SMTP");
    else if (TP(110))                dissect_text(c, pl, pll, root, "pop", "POP");
    else if (TP(143))                dissect_text(c, pl, pll, root, "imap", "IMAP");
    else if (TP(23))                 dissect_text(c, pl, pll, root, "telnet", "Telnet");
    else if (TP(6667))               dissect_text(c, pl, pll, root, "irc", "IRC");
    else if (TP(6379))               dissect_text(c, pl, pll, root, "redis", "Redis");
    else if (TP(3389))               dissect_rdp(c, pl, pll, root);
    else if (TP(53) && pll > 2)      dissect_dns(c, pl + 2, pll - 2, root, "dns"); /* TCP DNS: 2-byte len prefix */
    else if (pll > 0)                dissect_data(c, pl, pll, root);  /* undissected payload */
#undef TP
  }
}

/* ── UDP ────────────────────────────────────────────────────────────────── */
static void dissect_udp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *u, *f;
  uint16_t sp, dp, ln;

  if (len < 8) { set_proto(c, "UDP"); return; }
  sp = be16(d + 0);
  dp = be16(d + 2);
  ln = be16(d + 4);

  u = cfield_add(root, "udp", CV_NONE);
  cfield_set_label(u, "User Datagram Protocol, Src Port: %u, Dst Port: %u", sp, dp);
  set_range(c, u, d, 8);
  f = cfield_add(u, "udp.srcport", CV_UINT); cfield_set_uint(f, sp);
  cfield_set_label(f, "Source Port: %u", sp);
  f = cfield_add(u, "udp.dstport", CV_UINT); cfield_set_uint(f, dp);
  cfield_set_label(f, "Destination Port: %u", dp);
  f = cfield_add(u, "udp.length", CV_UINT); cfield_set_uint(f, ln);
  cfield_set_label(f, "Length: %u", ln);
  f = cfield_add(u, "udp.checksum", CV_UINT); cfield_set_uint(f, be16(d + 6));
  cfield_set_label(f, "Checksum: 0x%04x", be16(d + 6));

  set_proto(c, "UDP");
  set_info(c, "%u \xe2\x86\x92 %u  Len=%d", sp, dp, len - 8);

  {
    const uint8_t *pl = d + 8;
    int pll = len - 8;
    const char *bound;
    if (pll <= 0) return;
    bound = posa_bound_udp(sp);
    if (!bound) bound = posa_bound_udp(dp);
    if (bound && posa_dissect(bound, pl, pll, root, (int)(pl - c->base)) > 0) {
      set_proto(c, bound);
      return;
    }
#define UP(x) (sp == (x) || dp == (x))
    if      (UP(53))                 dissect_dns(c, pl, pll, root, "dns");
    else if (UP(5353))               dissect_dns(c, pl, pll, root, "mdns");
    else if (UP(5355))               dissect_dns(c, pl, pll, root, "llmnr");
    else if (UP(123))                dissect_ntp(c, pl, pll, root);
    else if (UP(67) || UP(68))       dissect_dhcp(c, pl, pll, root);
    else if (UP(137))                dissect_nbns(c, pl, pll, root);
    else if (UP(161) || UP(162))     dissect_snmp(c, pl, pll, root);
    else if (UP(1812)||UP(1813)||UP(1645)||UP(1646)) dissect_radius(c, pl, pll, root);
    else if (UP(514))                dissect_text(c, pl, pll, root, "syslog", "Syslog");
    else if (UP(443) || UP(80))      dissect_quic(c, pl, pll, root);  /* QUIC over UDP */
    else if (pll > 0)                dissect_data(c, pl, pll, root);  /* undissected payload */
#undef UP
  }
}

/* ── NTP (uses libpcapng's struct libpcapng_ntp_hdr for the wire layout) ──── */
static const char *ntp_mode_name(int m)
{
  switch (m) {
  case 1: return "symmetric active";
  case 2: return "symmetric passive";
  case 3: return "client";
  case 4: return "server";
  case 5: return "broadcast";
  case 6: return "control";
  case 7: return "private";
  default: return "reserved";
  }
}

static void dissect_ntp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  const struct libpcapng_ntp_hdr *n = (const struct libpcapng_ntp_hdr *)d;
  cfield_t *ntp, *f;
  int li, vn, mode;

  if (len < (int)sizeof *n) { set_proto(c, "NTP"); return; }
  li   = (n->li_vn_mode >> 6) & 0x3;
  vn   = (n->li_vn_mode >> 3) & 0x7;
  mode =  n->li_vn_mode       & 0x7;

  ntp = cfield_add(root, "ntp", CV_NONE);
  cfield_set_label(ntp, "Network Time Protocol (NTPv%d, %s)", vn, ntp_mode_name(mode));
  set_range(c, ntp, d, len);

  f = cfield_add(ntp, "ntp.flags", CV_UINT); cfield_set_uint(f, n->li_vn_mode);
  cfield_set_label(f, "Flags: 0x%02x (Leap=%d, Version=%d, Mode=%d %s)",
                   n->li_vn_mode, li, vn, mode, ntp_mode_name(mode));
  f = cfield_add(ntp, "ntp.stratum", CV_UINT); cfield_set_uint(f, n->stratum);
  cfield_set_label(f, "Peer Clock Stratum: %u", n->stratum);
  f = cfield_add(ntp, "ntp.ppoll", CV_UINT); cfield_set_uint(f, n->poll);
  cfield_set_label(f, "Peer Polling Interval: %u", n->poll);
  f = cfield_add(ntp, "ntp.precision", CV_UINT); cfield_set_uint(f, (uint8_t)n->precision);
  cfield_set_label(f, "Peer Clock Precision: %d", (int)n->precision);
  f = cfield_add(ntp, "ntp.rootdelay", CV_UINT); cfield_set_uint(f, ntohl(n->root_delay));
  cfield_set_label(f, "Root Delay: %u", ntohl(n->root_delay));
  f = cfield_add(ntp, "ntp.rootdispersion", CV_UINT); cfield_set_uint(f, ntohl(n->root_dispersion));
  cfield_set_label(f, "Root Dispersion: %u", ntohl(n->root_dispersion));
  f = cfield_add(ntp, "ntp.refid", CV_UINT); cfield_set_uint(f, ntohl(n->ref_id));
  cfield_set_label(f, "Reference ID: 0x%08x", ntohl(n->ref_id));
  f = cfield_add(ntp, "ntp.xmt", CV_UINT); cfield_set_uint(f, ntohl(n->tx_timestamp_secs));
  cfield_set_label(f, "Transmit Timestamp (seconds): %u", ntohl(n->tx_timestamp_secs));

  set_proto(c, "NTP");
  set_info(c, "NTPv%d %s", vn, ntp_mode_name(mode));
}

/* ── ICMP ───────────────────────────────────────────────────────────────── */
static void dissect_icmp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *ic, *f;
  if (len < 4) { set_proto(c, "ICMP"); return; }
  ic = cfield_add(root, "icmp", CV_NONE);
  cfield_set_label(ic, "Internet Control Message Protocol");
  set_range(c, ic, d, len < 8 ? len : 8);
  f = cfield_add(ic, "icmp.type", CV_UINT); cfield_set_uint(f, d[0]);
  cfield_set_label(f, "Type: %u", d[0]);
  f = cfield_add(ic, "icmp.code", CV_UINT); cfield_set_uint(f, d[1]);
  cfield_set_label(f, "Code: %u", d[1]);
  f = cfield_add(ic, "icmp.checksum", CV_UINT); cfield_set_uint(f, be16(d + 2));
  cfield_set_label(f, "Checksum: 0x%04x", be16(d + 2));
  set_proto(c, "ICMP");
  if      (d[0] == 8) set_info(c, "Echo (ping) request");
  else if (d[0] == 0) set_info(c, "Echo (ping) reply");
  else                set_info(c, "Type %u Code %u", d[0], d[1]);
}

/* ── DNS (header + first query name) ────────────────────────────────────── */
static int dns_name(const uint8_t *base, int len, int off, char *out, int outsz)
{
  int op = 0, jumped = 0, safety = 0;
  out[0] = '\0';
  while (off < len && base[off] && safety++ < 128) {
    int lab = base[off];
    if ((lab & 0xc0) == 0xc0) {           /* compression pointer */
      if (off + 1 >= len) break;
      if (!jumped) jumped = 1;
      off = ((lab & 0x3f) << 8) | base[off + 1];
      continue;
    }
    off++;
    if (op && op < outsz - 1) out[op++] = '.';
    while (lab-- > 0 && off < len && op < outsz - 1) out[op++] = (char)base[off++];
  }
  out[op] = '\0';
  return op;
}

static void dissect_dns(dctx_t *c, const uint8_t *d, int len, cfield_t *root, const char *proto)
{
  cfield_t *dns, *f;
  uint16_t id, flags, qd, an;
  char qname[256] = "";

  if (len < 12) { set_proto(c, "DNS"); return; }
  id = be16(d + 0); flags = be16(d + 2); qd = be16(d + 4); an = be16(d + 6);

  dns = cfield_add(root, proto, CV_NONE);
  cfield_set_label(dns, "Domain Name System (%s)", (flags & 0x8000) ? "response" : "query");
  set_range(c, dns, d, len);
  f = cfield_add(dns, "dns.id", CV_UINT); cfield_set_uint(f, id);
  cfield_set_label(f, "Transaction ID: 0x%04x", id);
  f = cfield_add(dns, "dns.flags", CV_UINT); cfield_set_uint(f, flags);
  cfield_set_label(f, "Flags: 0x%04x", flags);
  f = cfield_add(dns, "dns.count.queries", CV_UINT); cfield_set_uint(f, qd);
  cfield_set_label(f, "Questions: %u", qd);
  f = cfield_add(dns, "dns.count.answers", CV_UINT); cfield_set_uint(f, an);
  cfield_set_label(f, "Answer RRs: %u", an);

  if (qd > 0) {
    dns_name(d, len, 12, qname, sizeof qname);
    f = cfield_add(dns, "dns.qry.name", CV_STR); cfield_set_str(f, qname);
    cfield_set_label(f, "Query Name: %s", qname);
  }

  set_proto(c, "DNS");
  set_info(c, "%s 0x%04x %s", (flags & 0x8000) ? "response" : "query", id, qname);
}

/* ── small helpers ──────────────────────────────────────────────────────── */
static void printable_line(const uint8_t *d, int len, char *out, int outsz)
{
  int i = 0, o = 0;
  while (i < len && d[i] != '\n' && d[i] != '\r' && o < outsz - 1) {
    out[o++] = (d[i] >= 32 && d[i] < 127) ? (char)d[i] : '.';
    i++;
  }
  out[o] = '\0';
}

/* ── undissected payload (Wireshark's "Data") ───────────────────────────── */
static void dissect_data(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *dn, *f;
  char hex[51];
  int i, n, o = 0;
  if (len <= 0) return;
  dn = cfield_add(root, "data", CV_NONE);
  set_range(c, dn, d, len);
  cfield_set_label(dn, "Data (%d byte%s)", len, len == 1 ? "" : "s");

  f = cfield_add(dn, "data.len", CV_UINT); cfield_set_uint(f, len);
  cfield_set_label(f, "Length: %d", len);

  n = len < 16 ? len : 16;
  for (i = 0; i < n; i++) o += snprintf(hex + o, sizeof hex - o, "%02x", d[i]);
  f = cfield_add(dn, "data.data", CV_BYTES); cfield_set_bytes(f, d, len);
  set_range(c, f, d, len);
  cfield_set_label(f, "Data: %s%s", hex, len > 16 ? "\xe2\x80\xa6" : "");
}

/* ── generic line-oriented text protocol (FTP/SMTP/POP/IMAP/Telnet/IRC/…) ── */
static void dissect_text(dctx_t *c, const uint8_t *d, int len, cfield_t *root,
                         const char *abbrev, const char *name)
{
  cfield_t *n, *f;
  char line[160], ab[CFIELD_ABBREV_MAX];
  if (len <= 0) { set_proto(c, name); return; }
  n = cfield_add(root, abbrev, CV_NONE);
  cfield_set_label(n, "%s", name);
  set_range(c, n, d, len);
  printable_line(d, len, line, sizeof line);
  snprintf(ab, sizeof ab, "%s.line", abbrev);
  f = cfield_add(n, ab, CV_STR);
  cfield_set_str(f, line);
  cfield_set_label(f, "%s", line);
  set_proto(c, name);
  set_info(c, "%s", line[0] ? line : name);
}

/* ── HTTP (request/status line + headers) ───────────────────────────────── */
static void dissect_http(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *h, *f;
  char line[256];
  int i = 0, first = 1;

  h = cfield_add(root, "http", CV_NONE);
  cfield_set_label(h, "Hypertext Transfer Protocol");
  set_range(c, h, d, len);
  set_proto(c, "HTTP");

  while (i < len) {
    int o = 0;
    while (i < len && d[i] != '\n' && o < (int)sizeof line - 1) {
      if (d[i] != '\r') line[o++] = (d[i] >= 32 && d[i] < 127) ? (char)d[i] : '.';
      i++;
    }
    if (i < len && d[i] == '\n') i++;
    line[o] = '\0';
    if (o == 0) break;                       /* blank line ends the headers */
    if (first) {
      int is_resp = (strncmp(line, "HTTP/", 5) == 0);
      first = 0;
      cfield_set_label(h, "Hypertext Transfer Protocol (%s)", is_resp ? "response" : "request");
      f = cfield_add(h, is_resp ? "http.response.line" : "http.request.line", CV_STR);
      cfield_set_str(f, line); cfield_set_label(f, "%s", line);
      set_info(c, "%s", line);
    } else {
      f = cfield_add(h, "http.header", CV_STR);
      cfield_set_str(f, line); cfield_set_label(f, "%s", line);
    }
  }
}

/* ── TLS/SSL (record layer + handshake type + ClientHello SNI) ──────────── */
static const char *tls_ct_name(uint8_t ct)
{
  switch (ct) {
  case 20: return "Change Cipher Spec";
  case 21: return "Alert";
  case TLS_CONTENT_HANDSHAKE: return "Handshake";
  case TLS_CONTENT_APPDATA:   return "Application Data";
  case 24: return "Heartbeat";
  default: return "Unknown";
  }
}
static const char *tls_hs_name(uint8_t h)
{
  switch (h) {
  case 1:  return "Client Hello";
  case 2:  return "Server Hello";
  case 4:  return "New Session Ticket";
  case 11: return "Certificate";
  case 12: return "Server Key Exchange";
  case 13: return "Certificate Request";
  case 14: return "Server Hello Done";
  case 16: return "Client Key Exchange";
  case 20: return "Finished";
  default: return "Handshake Message";
  }
}
static const char *tls_ver_name(uint16_t v)
{
  switch (v) {
  case 0x0300: return "SSL 3.0";
  case 0x0301: return "TLS 1.0";
  case 0x0302: return "TLS 1.1";
  case 0x0303: return "TLS 1.2";
  case 0x0304: return "TLS 1.3";
  default: return "?";
  }
}
static void tls_extract_sni(const uint8_t *d, int len, char *out, int outsz)
{
  int p, extend, extlen;
  out[0] = '\0';
  if (len < 6 || d[5] != 1) return;          /* ClientHello only */
  p = 9 + 2 + 32;                            /* hs hdr + version + random */
  if (p >= len) return;
  p += 1 + d[p];                             /* session id */
  if (p + 2 > len) return;
  p += 2 + be16(d + p);                      /* cipher suites */
  if (p + 1 > len) return;
  p += 1 + d[p];                             /* compression methods */
  if (p + 2 > len) return;
  extlen = be16(d + p); p += 2;
  extend = p + extlen; if (extend > len) extend = len;
  while (p + 4 <= extend) {
    int et = be16(d + p), el = be16(d + p + 2);
    p += 4;
    if (et == 0) {                           /* server_name extension */
      if (p + 5 <= len) {
        int nl = be16(d + p + 3);
        if (p + 5 + nl <= len && nl < outsz) { memcpy(out, d + p + 5, (size_t)nl); out[nl] = '\0'; }
      }
      return;
    }
    p += el;
  }
}
static void dissect_tls(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *t, *f;
  uint8_t ct;
  uint16_t ver, rl;
  if (len < 5) { set_proto(c, "TLS"); return; }
  ct = d[0]; ver = be16(d + 1); rl = be16(d + 3);
  if (ct < 20 || ct > 24) { set_proto(c, "TLS"); return; }  /* mid-stream / not a record */

  t = cfield_add(root, "tls", CV_NONE);
  cfield_set_label(t, "Transport Layer Security (%s, %s)", tls_ver_name(ver), tls_ct_name(ct));
  set_range(c, t, d, len);
  f = cfield_add(t, "tls.record.content_type", CV_UINT); cfield_set_uint(f, ct);
  cfield_set_label(f, "Content Type: %s (%u)", tls_ct_name(ct), ct);
  f = cfield_add(t, "tls.record.version", CV_UINT); cfield_set_uint(f, ver);
  cfield_set_label(f, "Version: %s (0x%04x)", tls_ver_name(ver), ver);
  f = cfield_add(t, "tls.record.length", CV_UINT); cfield_set_uint(f, rl);
  cfield_set_label(f, "Length: %u", rl);
  set_proto(c, "TLS");

  if (ct == TLS_CONTENT_HANDSHAKE && len >= 6) {
    uint8_t hs = d[5];
    f = cfield_add(t, "tls.handshake.type", CV_UINT); cfield_set_uint(f, hs);
    cfield_set_label(f, "Handshake Type: %s (%u)", tls_hs_name(hs), hs);
    if (hs == 1) {
      char sni[128];
      tls_extract_sni(d, len, sni, sizeof sni);
      if (sni[0]) {
        f = cfield_add(t, "tls.handshake.extensions_server_name", CV_STR);
        cfield_set_str(f, sni); cfield_set_label(f, "Server Name: %s", sni);
        set_info(c, "Client Hello (SNI=%s)", sni);
      } else set_info(c, "Client Hello");
    } else set_info(c, "%s", tls_hs_name(hs));
  } else {
    set_info(c, "%s", tls_ct_name(ct));
  }
}

/* ── SSH (banner line or binary packet) ─────────────────────────────────── */
static void dissect_ssh(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *s, *f;
  s = cfield_add(root, "ssh", CV_NONE);
  cfield_set_label(s, "SSH Protocol");
  set_proto(c, "SSH");
  if (len >= 4 && memcmp(d, "SSH-", 4) == 0) {
    char line[128];
    printable_line(d, len, line, sizeof line);
    f = cfield_add(s, "ssh.protocol", CV_STR); cfield_set_str(f, line);
    cfield_set_label(f, "Protocol: %s", line);
    set_info(c, "%s", line);
  } else if (len >= 4) {
    uint32_t plen = be32(d);
    f = cfield_add(s, "ssh.packet_length", CV_UINT); cfield_set_uint(f, plen);
    cfield_set_label(f, "Packet Length: %u", plen);
    set_info(c, "Encrypted packet (len=%u)", plen);
  }
}

/* ── IGMP ───────────────────────────────────────────────────────────────── */
static const char *igmp_type(uint8_t t)
{
  switch (t) {
  case 0x11: return "Membership Query";
  case 0x12: return "v1 Membership Report";
  case 0x16: return "v2 Membership Report";
  case 0x17: return "Leave Group";
  case 0x22: return "v3 Membership Report";
  default:   return "IGMP";
  }
}
static void dissect_igmp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *g, *f;
  if (len < 8) { set_proto(c, "IGMP"); return; }
  g = cfield_add(root, "igmp", CV_NONE);
  cfield_set_label(g, "Internet Group Management Protocol");
  f = cfield_add(g, "igmp.type", CV_UINT); cfield_set_uint(f, d[0]);
  cfield_set_label(f, "Type: %s (0x%02x)", igmp_type(d[0]), d[0]);
  f = cfield_add(g, "igmp.max_resp", CV_UINT); cfield_set_uint(f, d[1]);
  cfield_set_label(f, "Max Resp Time: %u", d[1]);
  f = cfield_add(g, "igmp.maddr", CV_IPV4); cfield_set_ipv4(f, d + 4);
  cfield_set_label(f, "Multicast Address: %s", f->str);
  set_proto(c, "IGMP");
  set_info(c, "%s", igmp_type(d[0]));
}

/* ── GRE ────────────────────────────────────────────────────────────────── */
static void dissect_gre(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *g, *f;
  uint16_t flags, proto;
  if (len < 4) { set_proto(c, "GRE"); return; }
  flags = be16(d); proto = be16(d + 2);
  g = cfield_add(root, "gre", CV_NONE);
  cfield_set_label(g, "Generic Routing Encapsulation");
  f = cfield_add(g, "gre.flags_and_version", CV_UINT); cfield_set_uint(f, flags);
  cfield_set_label(f, "Flags and Version: 0x%04x", flags);
  f = cfield_add(g, "gre.proto", CV_UINT); cfield_set_uint(f, proto);
  cfield_set_label(f, "Protocol Type: 0x%04x", proto);
  set_proto(c, "GRE");
  set_info(c, "Encapsulated 0x%04x", proto);
  if (flags == 0 && len > 4) dissect_l3(c, proto, d + 4, len - 4, root);  /* no optional fields */
}

/* ── DHCP / BOOTP (uses libpcapng's struct libpcapng_bootp_hdr) ─────────── */
static const char *dhcp_msgtype(uint8_t t)
{
  switch (t) {
  case 1: return "Discover"; case 2: return "Offer";  case 3: return "Request";
  case 4: return "Decline";  case 5: return "ACK";    case 6: return "NAK";
  case 7: return "Release";  case 8: return "Inform";
  default: return "?";
  }
}
static void dissect_dhcp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  const struct libpcapng_bootp_hdr *b = (const struct libpcapng_bootp_hdr *)d;
  cfield_t *dh, *f;
  int off;
  uint8_t msgtype = 0;
  if (len < 236) { set_proto(c, "DHCP"); return; }

  dh = cfield_add(root, "dhcp", CV_NONE);
  set_range(c, dh, d, len);
  f = cfield_add(dh, "dhcp.op", CV_UINT); cfield_set_uint(f, b->op);
  cfield_set_label(f, "Message op code: %s (%u)",
                   b->op == 1 ? "Boot Request" : b->op == 2 ? "Boot Reply" : "?", b->op);
  f = cfield_add(dh, "dhcp.id", CV_UINT); cfield_set_uint(f, ntohl(b->xid));
  cfield_set_label(f, "Transaction ID: 0x%08x", ntohl(b->xid));
  f = cfield_add(dh, "dhcp.ip.client", CV_IPV4); cfield_set_ipv4(f, (const uint8_t *)&b->ciaddr);
  cfield_set_label(f, "Client IP address: %s", f->str);
  f = cfield_add(dh, "dhcp.ip.your", CV_IPV4); cfield_set_ipv4(f, (const uint8_t *)&b->yiaddr);
  cfield_set_label(f, "Your (client) IP address: %s", f->str);
  f = cfield_add(dh, "dhcp.ip.server", CV_IPV4); cfield_set_ipv4(f, (const uint8_t *)&b->siaddr);
  cfield_set_label(f, "Next server IP address: %s", f->str);
  f = cfield_add(dh, "dhcp.hw.mac_addr", CV_MAC); cfield_set_mac(f, b->chaddr);
  cfield_set_label(f, "Client MAC address: %s", f->str);

  off = 236;
  if (off + 4 <= len && d[off] == 0x63 && d[off+1] == 0x82 && d[off+2] == 0x53 && d[off+3] == 0x63) {
    off += 4;
    while (off < len) {
      uint8_t code = d[off++], ol;
      if (code == 0xff) break;          /* end */
      if (code == 0x00) continue;       /* pad */
      if (off >= len) break;
      ol = d[off++];
      if (off + ol > len) break;
      if (code == 53 && ol >= 1) {
        msgtype = d[off];
        f = cfield_add(dh, "dhcp.option.dhcp", CV_UINT); cfield_set_uint(f, msgtype);
        cfield_set_label(f, "DHCP Message Type: %s (%u)", dhcp_msgtype(msgtype), msgtype);
      }
      off += ol;
    }
  }
  cfield_set_label(dh, "Dynamic Host Configuration Protocol (%s)",
                   msgtype ? dhcp_msgtype(msgtype) : (b->op == 1 ? "Request" : "Reply"));
  set_proto(c, "DHCP");
  if (msgtype) set_info(c, "DHCP %s", dhcp_msgtype(msgtype));
  else         set_info(c, "BOOTP %s", b->op == 1 ? "Request" : "Reply");
}

/* ── NBNS (NetBIOS Name Service header) ─────────────────────────────────── */
static void dissect_nbns(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *n, *f;
  uint16_t id, flags, qd;
  if (len < 12) { set_proto(c, "NBNS"); return; }
  id = be16(d); flags = be16(d + 2); qd = be16(d + 4);
  n = cfield_add(root, "nbns", CV_NONE);
  cfield_set_label(n, "NetBIOS Name Service");
  f = cfield_add(n, "nbns.id", CV_UINT); cfield_set_uint(f, id);
  cfield_set_label(f, "Transaction ID: 0x%04x", id);
  f = cfield_add(n, "nbns.flags", CV_UINT); cfield_set_uint(f, flags);
  cfield_set_label(f, "Flags: 0x%04x", flags);
  f = cfield_add(n, "nbns.count.queries", CV_UINT); cfield_set_uint(f, qd);
  cfield_set_label(f, "Questions: %u", qd);
  set_proto(c, "NBNS");
  set_info(c, "%s 0x%04x", (flags & 0x8000) ? "response" : "query", id);
}

/* ── SNMP (minimal ASN.1: version + community) ──────────────────────────── */
static long asn1_len(const uint8_t *d, int len, int *off)
{
  int l;
  if (*off >= len) return -1;
  l = d[(*off)++];
  if (l & 0x80) { int n = l & 0x7f; l = 0; while (n-- > 0 && *off < len) l = (l << 8) | d[(*off)++]; }
  return l;
}
static const char *snmp_ver(long v)
{ return v == 0 ? "v1" : v == 1 ? "v2c" : v == 3 ? "v3" : "?"; }
static void dissect_snmp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *s, *f;
  int off = 0, i;
  long version = -1;
  char comm[128] = "";
  if (len < 2 || d[0] != 0x30) { set_proto(c, "SNMP"); return; }
  off = 1; (void)asn1_len(d, len, &off);             /* sequence length */
  if (off < len && d[off] == 0x02) {                 /* version INTEGER */
    long vl, v = 0;
    off++; vl = asn1_len(d, len, &off);
    for (i = 0; i < vl && off < len; i++) v = (v << 8) | d[off++];
    version = v;
  }
  if (off < len && d[off] == 0x04) {                 /* community OCTET STRING */
    long cl; int o = 0;
    off++; cl = asn1_len(d, len, &off);
    for (i = 0; i < cl && off < len && o < (int)sizeof comm - 1; i++, off++)
      comm[o++] = (d[off] >= 32 && d[off] < 127) ? (char)d[off] : '.';
    comm[o] = '\0';
  }
  s = cfield_add(root, "snmp", CV_NONE);
  cfield_set_label(s, "Simple Network Management Protocol");
  if (version >= 0) {
    f = cfield_add(s, "snmp.version", CV_UINT); cfield_set_uint(f, (uint64_t)version);
    cfield_set_label(f, "version: %s (%ld)", snmp_ver(version), version);
  }
  if (comm[0]) {
    f = cfield_add(s, "snmp.community", CV_STR); cfield_set_str(f, comm);
    cfield_set_label(f, "community: %s", comm);
  }
  set_proto(c, "SNMP");
  set_info(c, "%s%s%s", snmp_ver(version), comm[0] ? " community=" : "", comm);
}

/* ── RADIUS ─────────────────────────────────────────────────────────────── */
static const char *radius_code(uint8_t code)
{
  switch (code) {
  case 1:  return "Access-Request";   case 2:  return "Access-Accept";
  case 3:  return "Access-Reject";    case 4:  return "Accounting-Request";
  case 5:  return "Accounting-Response"; case 11: return "Access-Challenge";
  default: return "RADIUS";
  }
}
static void dissect_radius(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *r, *f;
  if (len < 4) { set_proto(c, "RADIUS"); return; }
  r = cfield_add(root, "radius", CV_NONE);
  cfield_set_label(r, "RADIUS Protocol");
  f = cfield_add(r, "radius.code", CV_UINT); cfield_set_uint(f, d[0]);
  cfield_set_label(f, "Code: %s (%u)", radius_code(d[0]), d[0]);
  f = cfield_add(r, "radius.id", CV_UINT); cfield_set_uint(f, d[1]);
  cfield_set_label(f, "Identifier: %u", d[1]);
  f = cfield_add(r, "radius.length", CV_UINT); cfield_set_uint(f, be16(d + 2));
  cfield_set_label(f, "Length: %u", be16(d + 2));
  set_proto(c, "RADIUS");
  set_info(c, "%s id=%u", radius_code(d[0]), d[1]);
}

/* ── RDP (TPKT/X.224 envelope detection) ────────────────────────────────── */
static void dissect_rdp(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *r, *f;
  r = cfield_add(root, "rdp", CV_NONE);
  cfield_set_label(r, "Remote Desktop Protocol");
  set_proto(c, "RDP");
  if (len >= 4 && d[0] == 3 && d[1] == 0) {       /* TPKT header */
    uint16_t tl = be16(d + 2);
    f = cfield_add(r, "tpkt.length", CV_UINT); cfield_set_uint(f, tl);
    cfield_set_label(f, "TPKT Length: %u", tl);
    set_info(c, "TPKT len=%u", tl);
  } else {
    set_info(c, "RDP");
  }
}

/* ── QUIC (IETF; headers only — payload is encrypted) ───────────────────── */
static const char *quic_lpt(uint8_t t)
{
  switch (t) {
  case 0: return "Initial"; case 1: return "0-RTT";
  case 2: return "Handshake"; case 3: return "Retry";
  default: return "?";
  }
}
static void dissect_quic(dctx_t *c, const uint8_t *d, int len, cfield_t *root)
{
  cfield_t *q, *f;
  uint8_t b0;
  if (len < 1) { set_proto(c, "QUIC"); return; }
  b0 = d[0];
  /* Heuristic guard: a long header has the high two bits set (0xC0); a short
     header has 0x40 set and 0x80 clear. Anything else isn't QUIC v1-ish. */
  if (!(b0 & 0x40)) { set_proto(c, "QUIC"); return; }

  q = cfield_add(root, "quic", CV_NONE);
  set_range(c, q, d, len);
  set_proto(c, "QUIC");

  if (b0 & 0x80) {                              /* long header */
    uint32_t ver;
    uint8_t pt = (b0 >> 4) & 0x03;
    int off, dl, sl;
    cfield_set_label(q, "QUIC IETF (long header)");
    f = cfield_add(q, "quic.header_form", CV_UINT); cfield_set_uint(f, 1);
    cfield_set_label(f, "Header Form: Long Header (1)");
    if (len < 6) { set_info(c, "QUIC long header"); return; }
    ver = be32(d + 1);
    f = cfield_add(q, "quic.version", CV_UINT); cfield_set_uint(f, ver);
    cfield_set_label(f, "Version: 0x%08x", ver);
    f = cfield_add(q, "quic.long.packet_type", CV_UINT); cfield_set_uint(f, pt);
    cfield_set_label(f, "Packet Type: %s (%u)", ver == 0 ? "Version Negotiation" : quic_lpt(pt), pt);
    off = 5;
    dl = d[off++];
    if (off + dl <= len) {
      f = cfield_add(q, "quic.dcid", CV_BYTES); cfield_set_bytes(f, d + off, dl);
      cfield_set_label(f, "Destination Connection ID: %d bytes", dl);
      off += dl;
    }
    if (off < len) {
      sl = d[off++];
      if (off + sl <= len) {
        f = cfield_add(q, "quic.scid", CV_BYTES); cfield_set_bytes(f, d + off, sl);
        cfield_set_label(f, "Source Connection ID: %d bytes", sl);
      }
    }
    set_info(c, "QUIC %s", ver == 0 ? "Version Negotiation" : quic_lpt(pt));
  } else {                                      /* short header (1-RTT) */
    cfield_set_label(q, "QUIC IETF (short header, protected)");
    f = cfield_add(q, "quic.header_form", CV_UINT); cfield_set_uint(f, 0);
    cfield_set_label(f, "Header Form: Short Header (0)");
    set_info(c, "QUIC protected payload");
  }
}

/* ── linktype entry ─────────────────────────────────────────────────────── */
static cfield_t *do_dissect(const cpkt_t *pkt, cpkt_t *sum)
{
  dctx_t c;
  cfield_t *root = cfield_new("", CV_NONE);
  c.sum = sum;
  c.base = pkt->data;
  const uint8_t *d = pkt->data;
  int len = (int)pkt->caplen;
  if (!root) return NULL;

  dissect_frame(&c, pkt, root);
  set_proto(&c, "?");
  set_info(&c, "");

  /* pcapng Custom Block: not a captured frame — show the PEN and its bytes. */
  if (pkt->is_custom) {
    cfield_t *cb = cfield_add(root, "pcapng.cb", CV_NONE), *f;
    cfield_set_label(cb, "pcapng Custom Block (PEN 0x%08x, %u bytes)", pkt->pen, pkt->caplen);
    f = cfield_add(cb, "pcapng.cb.pen", CV_UINT); cfield_set_uint(f, pkt->pen);
    cfield_set_label(f, "Private Enterprise Number: 0x%08x", pkt->pen);
    dissect_data(&c, d, len, cb);
    set_proto(&c, "PcapngCB");
    set_src(&c, "—");
    set_dst(&c, "—");
    set_info(&c, "Custom Block, PEN 0x%08x, %u bytes", pkt->pen, pkt->caplen);
    return root;
  }

  switch (pkt->linktype) {
  case LINKTYPE_ETHERNET:
    dissect_ethernet(&c, d, len, root);
    break;
  case LINKTYPE_RAW:
  case LINKTYPE_IPV4:
    if (len > 0 && (d[0] >> 4) == 6) dissect_ipv6(&c, d, len, root);
    else                             dissect_ipv4(&c, d, len, root);
    break;
  case LINKTYPE_IPV6:
    dissect_ipv6(&c, d, len, root);
    break;
  case LINKTYPE_NULL:
    /* 4-byte address-family header, host byte order; 2 = AF_INET */
    if (len >= 4) {
      uint32_t af = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
                    ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
      if (af == 2)               dissect_ipv4(&c, d + 4, len - 4, root);
      else if (af == 24 || af == 30 || af == 28) dissect_ipv6(&c, d + 4, len - 4, root);
    }
    break;
  case LINKTYPE_LINUX_SLL:
    if (len >= 16) dissect_l3(&c, be16(d + 14), d + 16, len - 16, root);
    break;
  default:
    /* Unknown link layer: best-effort treat as raw IP. */
    if (len > 0 && (d[0] >> 4) == 4) dissect_ipv4(&c, d, len, root);
    break;
  }
  return root;
}

cfield_t *dissect_packet(const cpkt_t *pkt)
{
  return do_dissect(pkt, NULL);
}

void dissect_summarize(cpkt_t *pkt)
{
  cfield_t *root;
  if (pkt->summarized) return;
  pkt->col_proto[0] = pkt->col_src[0] = pkt->col_dst[0] = pkt->col_info[0] = '\0';
  root = do_dissect(pkt, pkt);
  cfield_free(root);
  pkt->summarized = 1;
}

/* ── transport locator (for hex/search/follow-stream) ───────────────────── */
static uint32_t fold16(const uint8_t *p)
{ return be32(p) ^ be32(p + 4) ^ be32(p + 8) ^ be32(p + 12); }

int caracal_locate_l4(const cpkt_t *pkt, caracal_l4_t *r)
{
  const uint8_t *d = pkt->data;
  int len = (int)pkt->caplen, off = 0;
  uint16_t et = 0;
  const uint8_t *ip;
  int iplen;
  uint8_t ipproto;

  memset(r, 0, sizeof *r);
  switch (pkt->linktype) {
  case LINKTYPE_ETHERNET:
    if (len < 14) return 0;
    et = (uint16_t)((d[12] << 8) | d[13]); off = 14;
    if (et == 0x8100) { if (len < 18) return 0; et = (uint16_t)((d[16] << 8) | d[17]); off = 18; }
    break;
  case LINKTYPE_RAW: case LINKTYPE_IPV4: case LINKTYPE_IPV6:
    et = (len > 0 && (d[0] >> 4) == 6) ? 0x86DD : 0x0800;
    break;
  case LINKTYPE_NULL: {
    uint32_t af;
    if (len < 4) return 0;
    af = (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
    et = (af == 2) ? 0x0800 : (af == 24 || af == 28 || af == 30) ? 0x86DD : 0;
    off = 4;
    break;
  }
  default:
    if (len > 0 && (d[0] >> 4) == 4) et = 0x0800; else return 0;
  }

  ip = d + off; iplen = len - off;
  if (et == 0x0800) {
    int ihl;
    if (iplen < 20) return 0;
    ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > iplen) return 0;
    ipproto = ip[9];
    r->sip = be32(ip + 12); r->dip = be32(ip + 16);
    off += ihl;
  } else if (et == 0x86DD) {
    if (iplen < 40) return 0;
    ipproto = ip[6];
    r->sip = fold16(ip + 8); r->dip = fold16(ip + 24);
    off += 40;
  } else return 0;

  {
    const uint8_t *l4 = d + off;
    int l4len = len - off;
    if (l4len < 0) return 0;
    r->proto = ipproto;
    if (ipproto == 6) {
      int doff;
      if (l4len < 20) return 0;
      doff = ((l4[12] >> 4) & 0x0f) * 4;
      if (doff < 20 || doff > l4len) return 0;
      r->sport = be16(l4); r->dport = be16(l4 + 2);
      r->seq = be32(l4 + 4); r->flags = l4[13];
      r->payoff = off + doff; r->paylen = l4len - doff;
      return 1;
    } else if (ipproto == 17) {
      if (l4len < 8) return 0;
      r->sport = be16(l4); r->dport = be16(l4 + 2);
      r->payoff = off + 8; r->paylen = l4len - 8;
      return 1;
    }
  }
  return 0;
}
