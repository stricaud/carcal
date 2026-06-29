/* source.c — load a capture file into a capture_t.
 *
 * pcapng files are read with libpcapng's block reader; classic .pcap files are
 * read directly (a small, self-contained reader). The first 4 bytes select the
 * format. Live capture is intentionally out of scope for now.
 */
#include "caracal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcapng/libpcapng.h>

/* ── packet store growth ────────────────────────────────────────────────── */
static int cap_push(capture_t *cap, const uint8_t *data, uint32_t caplen,
                    uint32_t origlen, uint64_t ts_us, uint16_t linktype)
{
  cpkt_t *p;
  if (cap->count == cap->cap) {
    long nc = cap->cap ? cap->cap * 2 : 1024;
    cpkt_t *np = realloc(cap->pkts, (size_t)nc * sizeof *np);
    if (!np) return -1;
    cap->pkts = np;
    cap->cap = nc;
  }
  p = &cap->pkts[cap->count];
  memset(p, 0, sizeof *p);
  p->data = malloc(caplen ? caplen : 1);
  if (!p->data) return -1;
  memcpy(p->data, data, caplen);
  p->caplen = caplen;
  p->origlen = origlen;
  p->ts_us = ts_us;
  p->linktype = linktype;
  if (cap->count == 0) cap->first_ts_us = ts_us;
  cap->count++;
  return 0;
}

/* ── optional load-progress callback ────────────────────────────────────── */
static void (*g_progress)(void *ud, double frac);
static void  *g_progress_ud;
void capture_set_progress(void (*cb)(void *ud, double frac), void *ud)
{ g_progress = cb; g_progress_ud = ud; }
static void progress(double frac) { if (g_progress) g_progress(g_progress_ud, frac); }

/* ── little helpers honoring a byte-swap flag ───────────────────────────── */
static uint16_t rd16(const uint8_t *p, int swap)
{
  uint16_t v = (uint16_t)(p[0] | (p[1] << 8));
  return swap ? (uint16_t)((v >> 8) | (v << 8)) : v;
}
static uint32_t rd32(const uint8_t *p, int swap)
{
  uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  if (swap)
    v = ((v & 0xff) << 24) | ((v & 0xff00) << 8) |
        ((v & 0xff0000) >> 8) | ((v >> 24) & 0xff);
  return v;
}

/* ── pcapng path (libpcapng callback) ───────────────────────────────────── */
#define MAX_IFACES 64
typedef struct {
  capture_t *cap;
  int        swap;                 /* file endianness != host                 */
  uint16_t   if_linktype[MAX_IFACES];
  uint32_t   if_tsresol_div[MAX_IFACES];  /* ticks per second (default 1e6)    */
  int        n_ifaces;
  double     filesize;             /* for progress reporting (0 = unknown)     */
  double     consumed;
} pcapng_ctx_t;

/* data points just past the 8-byte block header (block_type + total_length). */
static int pcapng_block_cb(uint32_t counter, uint32_t block_type,
                           uint32_t block_total_length, unsigned char *data,
                           void *userdata)
{
  pcapng_ctx_t *ctx = userdata;
  uint32_t body_len = block_total_length >= 8 ? block_total_length - 8 : 0;
  (void)counter;

  switch (block_type) {
  case 0x0A0D0D0A: {  /* Section Header Block — establish endianness */
    if (body_len >= 4) {
      uint32_t magic = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                       ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
      ctx->swap = (magic != 0x1A2B3C4D);  /* stored little-endian if not swapped */
    }
    ctx->n_ifaces = 0;  /* interfaces are per-section */
    break;
  }
  case 0x00000001: {  /* Interface Description Block: linktype(2) reserved(2) snaplen(4) [opts] */
    if (ctx->n_ifaces < MAX_IFACES && body_len >= 8) {
      int i = ctx->n_ifaces++;
      ctx->if_linktype[i] = rd16(data, ctx->swap);
      ctx->if_tsresol_div[i] = 1000000;  /* default 1µs; option parsing omitted */
    }
    break;
  }
  case 0x00000006: {  /* Enhanced Packet Block */
    /* interface_id(4) ts_high(4) ts_low(4) caplen(4) origlen(4) data... */
    if (body_len >= 20) {
      uint32_t ifid    = rd32(data + 0,  ctx->swap);
      uint32_t ts_hi   = rd32(data + 4,  ctx->swap);
      uint32_t ts_lo   = rd32(data + 8,  ctx->swap);
      uint32_t caplen  = rd32(data + 12, ctx->swap);
      uint32_t origlen = rd32(data + 16, ctx->swap);
      uint64_t ticks   = ((uint64_t)ts_hi << 32) | ts_lo;
      uint32_t div     = (ifid < MAX_IFACES && ctx->if_tsresol_div[ifid])
                           ? ctx->if_tsresol_div[ifid] : 1000000;
      uint16_t lt      = ifid < (uint32_t)ctx->n_ifaces ? ctx->if_linktype[ifid]
                                                        : LINKTYPE_ETHERNET;
      uint64_t ts_us   = div ? (ticks * 1000000ULL) / div : ticks;
      if (caplen > body_len - 20) caplen = body_len - 20;
      cap_push(ctx->cap, data + 20, caplen, origlen, ts_us, lt);
    }
    break;
  }
  case 0x00000003: {  /* Simple Packet Block: origlen(4) data... (no timestamp) */
    if (body_len >= 4) {
      uint32_t origlen = rd32(data, ctx->swap);
      uint32_t caplen  = body_len - 4;
      uint16_t lt = ctx->n_ifaces ? ctx->if_linktype[0] : LINKTYPE_ETHERNET;
      if (origlen < caplen) caplen = origlen;
      cap_push(ctx->cap, data + 4, caplen, origlen, 0, lt);
    }
    break;
  }
  case 0x00000BAD:    /* Custom Data Block (copyable) */
  case 0x40000BAD: {  /* Custom Data Block (non-copyable) */
    /* body: PEN(4) + custom data (+ options). Show the PEN and the data. */
    if (body_len >= 4) {
      uint32_t pen     = rd32(data, ctx->swap);
      /* body = PEN(4) + custom data (+ options) + trailing block length(4);
         drop the PEN and the trailing length to show the custom data. */
      uint32_t datalen = body_len >= 8 ? body_len - 8 : 0;
      if (cap_push(ctx->cap, data + 4, datalen, datalen, 0, 0) == 0) {
        cpkt_t *p = &ctx->cap->pkts[ctx->cap->count - 1];
        p->is_custom = 1;
        p->pen = pen;
      }
    }
    break;
  }
  default:
    break;  /* NRB, ISB, DSB, custom, … not relevant to the packet list */
  }
  ctx->consumed += block_total_length;
  if (ctx->filesize > 0) progress(ctx->consumed / ctx->filesize);
  return 0;
}

/* ── classic pcap path ──────────────────────────────────────────────────── */
static int load_classic_pcap(FILE *fp, capture_t *cap, char *errbuf, size_t errlen)
{
  uint8_t gh[24];
  int swap = 0, nano = 0;
  uint32_t magic, linktype;
  uint8_t rh[16];
  double fsz;

  fseek(fp, 0, SEEK_END);
  fsz = (double)ftell(fp);
  rewind(fp);
  if (fread(gh, 1, 24, fp) != 24) {
    snprintf(errbuf, errlen, "short pcap global header");
    return -1;
  }
  magic = (uint32_t)gh[0] | ((uint32_t)gh[1] << 8) |
          ((uint32_t)gh[2] << 16) | ((uint32_t)gh[3] << 24);
  if      (magic == 0xA1B2C3D4) { swap = 0; nano = 0; }
  else if (magic == 0xD4C3B2A1) { swap = 1; nano = 0; }
  else if (magic == 0xA1B23C4D) { swap = 0; nano = 1; }
  else if (magic == 0x4D3CB2A1) { swap = 1; nano = 1; }
  else { snprintf(errbuf, errlen, "not a pcap/pcapng file"); return -1; }

  linktype = rd32(gh + 20, swap);

  for (;;) {
    uint32_t ts_sec, ts_frac, incl, orig;
    uint8_t *buf;
    uint64_t ts_us;
    if (fread(rh, 1, 16, fp) != 16) break;  /* clean EOF */
    ts_sec  = rd32(rh + 0, swap);
    ts_frac = rd32(rh + 4, swap);
    incl    = rd32(rh + 8, swap);
    orig    = rd32(rh + 12, swap);
    if (incl > 4 * 1024 * 1024) { /* sanity guard */
      snprintf(errbuf, errlen, "implausible record length %u", incl);
      return -1;
    }
    buf = malloc(incl ? incl : 1);
    if (!buf) { snprintf(errbuf, errlen, "out of memory"); return -1; }
    if (fread(buf, 1, incl, fp) != incl) { free(buf); break; }
    ts_us = (uint64_t)ts_sec * 1000000ULL + (nano ? ts_frac / 1000 : ts_frac);
    cap_push(cap, buf, incl, orig, ts_us, (uint16_t)linktype);
    free(buf);
    if (fsz > 0) progress((double)ftell(fp) / fsz);
  }
  return 0;
}

/* ── entry point ────────────────────────────────────────────────────────── */
int capture_load(const char *path, capture_t *cap, char *errbuf, size_t errlen)
{
  FILE *fp;
  uint8_t magic[4];

  memset(cap, 0, sizeof *cap);
  snprintf(cap->path, sizeof cap->path, "%s", path);

  fp = fopen(path, "rb");
  if (!fp) { snprintf(errbuf, errlen, "cannot open %s", path); return -1; }
  if (fread(magic, 1, 4, fp) != 4) {
    snprintf(errbuf, errlen, "file too short");
    fclose(fp);
    return -1;
  }

  if (magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A) {
    /* pcapng — hand off to libpcapng */
    pcapng_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.cap = cap;
    fseek(fp, 0, SEEK_END); ctx.filesize = (double)ftell(fp);
    fclose(fp);
    if (libpcapng_file_read((char *)path, pcapng_block_cb, &ctx) < 0) {
      snprintf(errbuf, errlen, "libpcapng failed to read %s", path);
      return -1;
    }
  } else {
    int rc = load_classic_pcap(fp, cap, errbuf, errlen);
    fclose(fp);
    if (rc < 0) return -1;
  }

  return 0;
}

void capture_free(capture_t *cap)
{
  long i;
  if (!cap) return;
  for (i = 0; i < cap->count; i++) free(cap->pkts[i].data);
  free(cap->pkts);
  memset(cap, 0, sizeof *cap);
}
