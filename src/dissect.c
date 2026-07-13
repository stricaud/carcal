/* dissect.c — caracal's thin adapter over libpcapng's generic dissector.
 *
 * The protocol decoding now lives in libpcapng (pcapng_dissect); caracal simply
 * converts that field tree into its own cfield tree, handles pcapng Custom
 * Blocks, and layers user-defined posa protocols on top for bound transport
 * ports. This keeps a single dissection engine (shared with the capture filter)
 * while preserving caracal's posa extension and UI model.
 */
#include "caracal.h"

#include <stdio.h>
#include <string.h>

#include <libpcapng/dissect.h>

/* ── byte readers (for the transport locator) ───────────────────────────── */
static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint32_t fold16(const uint8_t *p)
{ return be32(p) ^ be32(p + 4) ^ be32(p + 8) ^ be32(p + 12); }

/* ── libpcapng field tree → caracal cfield tree ─────────────────────────── */
static cval_type_t map_ft(pcapng_ftype_t t)
{
  switch (t) {
  case PCAPNG_FT_UINT: return CV_UINT;
  case PCAPNG_FT_STR:  return CV_STR;
  case PCAPNG_FT_IPV4: return CV_IPV4;
  case PCAPNG_FT_IPV6: return CV_IPV6;
  case PCAPNG_FT_MAC:  return CV_MAC;
  case PCAPNG_FT_BYTES:return CV_BYTES;
  default:             return CV_NONE;
  }
}
static void copy_children(cfield_t *dst, const pcapng_field_t *src)
{
  const pcapng_field_t *s;
  for (s = src->children; s; s = s->next) {
    cfield_t *f = cfield_add(dst, s->abbrev, map_ft(s->vtype));
    if (!f) continue;
    snprintf(f->label, sizeof f->label, "%s", s->label);
    f->u = s->u;
    snprintf(f->str, sizeof f->str, "%s", s->str);
    if (s->blen > 0) {
      int n = s->blen > CFIELD_BYTES_MAX ? CFIELD_BYTES_MAX : s->blen;
      memcpy(f->bytes, s->bytes, (size_t)n); f->blen = n;
    }
    f->off = s->off; f->len = s->len;
    copy_children(f, s);
  }
}

/* caracal-side posa: run the libpcapng posa engine into a temporary
   pcapng_field_t subtree, then convert it into caracal's cfield tree. */
int posa_dissect(const char *proto, const uint8_t *data, int len, cfield_t *parent, int abs_off)
{
  pcapng_field_t tmp, *c, *n;
  int used;
  memset(&tmp, 0, sizeof tmp);
  used = pcapng_posa_dissect(proto, data, len, &tmp, abs_off, NULL, 0);
  copy_children(parent, &tmp);
  for (c = tmp.children; c; c = n) { n = c->next; c->next = NULL; pcapng_field_free(c); }
  return used;
}

/* Remove top-level generic "data" layers (posa replaces them for bound ports). */
static void remove_data_layers(cfield_t *root)
{
  cfield_t *c = root->children, *prev = NULL, *n;
  root->last_child = NULL;
  for (; c; c = n) {
    n = c->next;
    if (strcmp(c->abbrev, "data") == 0) {
      if (prev) prev->next = n; else root->children = n;
      c->next = NULL; cfield_free(c);
    } else {
      prev = c; root->last_child = c;
    }
  }
}

/* Apply a decoder chosen by the rule engine to the transport payload. Returns
   the decoder name applied, or NULL. */
static const char *apply_rules(const cpkt_t *pkt, cfield_t *root)
{
  caracal_l4_t l4;
  const char *proto = rules_match(root);   /* evaluate rules on the dissection */
  if (!proto) return NULL;
  if (!caracal_locate_l4(pkt, &l4) || l4.paylen <= 0) return NULL;
  remove_data_layers(root);
  posa_dissect(proto, pkt->data + l4.payoff, l4.paylen, root, l4.payoff);
  return proto;
}

/* ── custom block (caracal-specific; not a captured frame) ──────────────── */
static cfield_t *dissect_custom_block(const cpkt_t *pkt)
{
  cfield_t *root = cfield_new("", CV_NONE), *fr, *cb, *f, *dn;
  char hex[51]; int i, hn, o = 0;
  if (!root) return NULL;
  fr = cfield_add(root, "frame", CV_NONE);
  cfield_set_label(fr, "Frame: %u bytes on wire, %u captured", pkt->origlen, pkt->caplen);
  fr->off = 0; fr->len = (int)pkt->caplen;
  cb = cfield_add(root, "pcapng.cb", CV_NONE);
  cfield_set_label(cb, "pcapng Custom Block (PEN 0x%08x, %u bytes)", pkt->pen, pkt->caplen);
  cb->off = 0; cb->len = (int)pkt->caplen;
  f = cfield_add(cb, "pcapng.cb.pen", CV_UINT); cfield_set_uint(f, pkt->pen);
  cfield_set_label(f, "Private Enterprise Number: 0x%08x", pkt->pen);
  dn = cfield_add(cb, "data", CV_NONE);
  cfield_set_label(dn, "Data (%u bytes)", pkt->caplen); dn->off = 0; dn->len = (int)pkt->caplen;
  f = cfield_add(dn, "data.data", CV_BYTES); cfield_set_bytes(f, pkt->data, (int)pkt->caplen);
  f->off = 0; f->len = (int)pkt->caplen;
  hn = pkt->caplen < 16 ? (int)pkt->caplen : 16;
  for (i = 0; i < hn; i++) o += snprintf(hex + o, sizeof hex - o, "%02x", pkt->data[i]);
  cfield_set_label(f, "Data: %s%s", hex, pkt->caplen > 16 ? "\xe2\x80\xa6" : "");
  return root;
}

/* Build the dissection tree, optionally filling summary columns in `sum`. */
static cfield_t *build(const cpkt_t *pkt, cpkt_t *sum)
{
  cfield_t *root;
  pcapng_dissection_t *d;
  const char *decoder;

  if (pkt->is_custom) {
    root = dissect_custom_block(pkt);
    if (sum) {
      snprintf(sum->col_proto, sizeof sum->col_proto, "PcapngCB");
      snprintf(sum->col_src, sizeof sum->col_src, "\xe2\x80\x94");
      snprintf(sum->col_dst, sizeof sum->col_dst, "\xe2\x80\x94");
      snprintf(sum->col_info, sizeof sum->col_info, "Custom Block, PEN 0x%08x, %u bytes", pkt->pen, pkt->caplen);
    }
    return root;
  }

  root = cfield_new("", CV_NONE);
  if (!root) return NULL;
  d = pcapng_dissect(pkt->data, pkt->caplen, pkt->origlen, pkt->linktype);
  if (d) {
    copy_children(root, d->root);
    if (sum) {
      snprintf(sum->col_proto, sizeof sum->col_proto, "%s", d->proto);
      snprintf(sum->col_src,   sizeof sum->col_src,   "%s", d->src);
      snprintf(sum->col_dst,   sizeof sum->col_dst,   "%s", d->dst);
      snprintf(sum->col_info,  sizeof sum->col_info,  "%s", d->info);
    }
    pcapng_dissection_free(d);
  }
  decoder = apply_rules(pkt, root);            /* posa decoder chosen by a rule */
  if (decoder && sum) snprintf(sum->col_proto, sizeof sum->col_proto, "%s", decoder);
  return root;
}

/* ── public: bytes → cfield tree ────────────────────────────────────────── */
cfield_t *dissect_packet(const cpkt_t *pkt) { return build(pkt, NULL); }

void dissect_summarize(cpkt_t *pkt)
{
  cfield_t *root;
  if (pkt->summarized) return;
  pkt->col_proto[0] = pkt->col_src[0] = pkt->col_dst[0] = pkt->col_info[0] = '\0';
  root = build(pkt, pkt);
  cfield_free(root);
  pkt->summarized = 1;
}

/* ── transport locator (for hex/search/follow-stream) ───────────────────── */
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
