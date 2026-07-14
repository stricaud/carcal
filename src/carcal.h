/*
 * carcal.h — shared types for carcal, a TUI packet analyzer.
 *
 * Data model, in Wireshark terms:
 *   - A capture is a list of cpkt_t (raw bytes + metadata + cached column text).
 *   - Dissecting a packet yields a tree of cfield_t nodes: protocol layers at
 *     the top, fields below. Each field carries a Wireshark-style abbrev
 *     ("ip.src", "tcp.dstport") used by the display filter, a human label used
 *     by the detail tree view, and a typed value used for comparisons.
 *   - The display filter (filter.c) parses a tshark/Wireshark-compatible
 *     expression and evaluates it against a packet's dissection tree.
 */
#ifndef CARCAL_H
#define CARCAL_H

#include <stdint.h>
#include <stddef.h>

/* ── Field value types ──────────────────────────────────────────────────── */
typedef enum {
  CV_NONE = 0,   /* structural node, no value (e.g. a protocol header)        */
  CV_UINT,       /* unsigned integer                                          */
  CV_STR,        /* text                                                      */
  CV_IPV4,       /* 4 raw bytes in .bytes, dotted-quad in .str                */
  CV_IPV6,       /* 16 raw bytes in .bytes                                    */
  CV_MAC,        /* 6 raw bytes in .bytes                                     */
  CV_BYTES       /* opaque bytes (kept in .bytes up to CFIELD_BYTES_MAX)      */
} cval_type_t;

#define CFIELD_ABBREV_MAX 64
#define CFIELD_LABEL_MAX  192
#define CFIELD_STR_MAX    160
#define CFIELD_BYTES_MAX  16

typedef struct cfield {
  char        abbrev[CFIELD_ABBREV_MAX]; /* "" for label-only structural rows */
  char        label[CFIELD_LABEL_MAX];   /* shown in the detail tree          */
  cval_type_t vtype;
  uint64_t    u;                         /* CV_UINT                           */
  char        str[CFIELD_STR_MAX];       /* CV_STR / formatted ip / mac       */
  uint8_t     bytes[CFIELD_BYTES_MAX];   /* CV_IPV4/6, CV_MAC, CV_BYTES       */
  int         blen;                      /* valid bytes in .bytes             */
  int         off;                       /* byte offset within the packet     */
  int         len;                       /* byte length within the packet     */

  struct cfield *parent;
  struct cfield *children;               /* singly-linked child list          */
  struct cfield *last_child;
  struct cfield *next;                   /* next sibling                      */
} cfield_t;

/* cfield tree construction (field.c) */
cfield_t *cfield_new(const char *abbrev, cval_type_t vtype);
cfield_t *cfield_add(cfield_t *parent, const char *abbrev, cval_type_t vtype);
void      cfield_free(cfield_t *root);
void      cfield_set_label(cfield_t *f, const char *fmt, ...);
void      cfield_set_uint(cfield_t *f, uint64_t v);
void      cfield_set_str(cfield_t *f, const char *s);
void      cfield_set_ipv4(cfield_t *f, const uint8_t ip[4]);
void      cfield_set_ipv6(cfield_t *f, const uint8_t ip[16]);
void      cfield_set_mac(cfield_t *f, const uint8_t mac[6]);
void      cfield_set_bytes(cfield_t *f, const uint8_t *b, int n);
int       cfield_count(cfield_t *parent);                  /* #children       */
cfield_t *cfield_child_at(cfield_t *parent, int index);
/* Collect every node whose abbrev matches `abbrev` (alias-expanded by the
   caller); returns count, fills out[] up to max. */
int       cfield_collect(cfield_t *root, const char *abbrev, cfield_t **out, int max);

/* Render a field as a display-filter expression, e.g. "ip.src == 10.0.0.1".
   The primitive behind Apply as Filter / Apply as Column / coloring rules.
   Returns 0, or -1 if the field cannot be expressed (structural row). */
int       cfield_filter_expr(const cfield_t *f, char *out, size_t n);
/* First field with this abbrev anywhere in the tree, or NULL. */
cfield_t *cfield_find(cfield_t *root, const char *abbrev);
/* Printable value, for a packet-list column cell. */
void      cfield_value_str(const cfield_t *f, char *out, size_t n);

/* ── Captured packet ────────────────────────────────────────────────────── */
typedef struct {
  uint8_t  *data;          /* captured bytes (owned)                          */
  uint32_t  caplen;        /* bytes present in .data                          */
  uint32_t  origlen;       /* original on-wire length                         */
  uint64_t  ts_us;         /* timestamp, microseconds since the Unix epoch    */
  uint16_t  linktype;      /* pcap/pcapng LINKTYPE_*                           */
  uint8_t   is_custom;     /* 1 = pcapng Custom Block (not a captured packet) */
  uint32_t  pen;           /* Custom Block private enterprise number          */

  /* Cached summary columns (filled lazily on first display). */
  int       summarized;
  char      col_proto[16];
  char      col_src[48];
  char      col_dst[48];
  char      col_info[160];
} cpkt_t;

typedef struct {
  cpkt_t  *pkts;
  long     count;
  long     cap;
  uint64_t first_ts_us;    /* for relative time column                        */
  char     path[1024];
} capture_t;

/* ── source.c — load a capture file ─────────────────────────────────────── */
/* Returns 0 on success, fills *cap. Supports pcapng (via libpcapng) and
   classic pcap. On failure returns -1 and writes a message to errbuf. */
int  capture_load(const char *path, capture_t *cap, char *errbuf, size_t errlen);
void capture_free(capture_t *cap);
/* Optional progress callback invoked during capture_load (frac 0..1). Set to
   NULL to disable. Used by the TUI to drive a load-progress gauge. */
void capture_set_progress(void (*cb)(void *ud, double frac), void *ud);

/* Append one packet to a capture (used by live capture). Returns the new
   packet index, or -1 on allocation failure. */
long capture_append(capture_t *cap, const uint8_t *data, uint32_t caplen,
                    uint32_t origlen, uint64_t ts_us, uint16_t linktype);

/* Write `cap` to `path` as pcapng. If `keep` is non-NULL it is an array of
   cap->count flags; only packets with keep[i] != 0 are written (NULL = all).
   pcapng Custom Blocks are skipped (they are not captured frames). Returns the
   number of packets written, or -1 on error (message in errbuf). */
long capture_save(const capture_t *cap, const char *path, const uint8_t *keep,
                  char *errbuf, size_t errlen);

/* ── dissect.c — bytes → cfield tree ────────────────────────────────────── */
/* Build the dissection tree for one packet. Caller frees with cfield_free.
   Registered posa protocols (posa.c) participate in transport dissection. */
cfield_t *dissect_packet(const cpkt_t *pkt);
/* Fill pkt->col_* from a dissection (cheap summary). Safe to call repeatedly. */
void      dissect_summarize(cpkt_t *pkt);

/* Locate the transport (TCP/UDP) header + payload within a packet. Returns 1
   when found. Integers are host order; payoff/paylen index into pkt->data. */
typedef struct {
  int      proto;            /* 6 = TCP, 17 = UDP */
  uint32_t sip, dip;         /* IPv6 folded to 32 bits */
  uint16_t sport, dport;
  uint32_t seq;              /* TCP only */
  uint8_t  flags;            /* TCP only */
  int      payoff, paylen;
} carcal_l4_t;
int       carcal_locate_l4(const cpkt_t *pkt, carcal_l4_t *out);

/* Common LINKTYPE values we understand. */
#define LINKTYPE_NULL      0
#define LINKTYPE_ETHERNET  1
#define LINKTYPE_RAW       101
#define LINKTYPE_LINUX_SLL 113
#define LINKTYPE_IPV4      228
#define LINKTYPE_IPV6      229

/* ── posa — user-defined protocols (engine lives in libpcapng core) ──────── */
#include <libpcapng/posa.h>

/* Compatibility aliases: carcal's older posa_* names map onto the libpcapng
   engine, so existing call sites (dissect.c, lua_run.c, the decoders UI) keep
   working while there is a single engine. */
typedef pcapng_posa_ftype_t posa_ftype_t;
typedef pcapng_posa_enum_t   posa_enum_t;
typedef pcapng_posa_fld_t    posa_fld_t;
typedef pcapng_posa_proto_t  posa_proto_t;

#define POSA_NAME_MAX   PCAPNG_POSA_NAME_MAX
#define POSA_MAX_FLDS   PCAPNG_POSA_MAX_FLDS
#define POSA_MAX_ENUMS  PCAPNG_POSA_MAX_ENUMS

#define PT_U8    PCAPNG_POSA_U8
#define PT_U16   PCAPNG_POSA_U16
#define PT_U32   PCAPNG_POSA_U32
#define PT_U64   PCAPNG_POSA_U64
#define PT_LE16  PCAPNG_POSA_LE16
#define PT_LE32  PCAPNG_POSA_LE32
#define PT_LE64  PCAPNG_POSA_LE64
#define PT_MAC   PCAPNG_POSA_MAC
#define PT_IP4   PCAPNG_POSA_IP4
#define PT_CSTRING PCAPNG_POSA_CSTRING
#define PT_PAYLOAD PCAPNG_POSA_PAYLOAD
#define PT_BYTES_FIXED PCAPNG_POSA_BYTES_FIXED
#define PT_BYTES_REF   PCAPNG_POSA_BYTES_REF

#define posa_load_file  pcapng_posa_load_file
#define posa_load_dir   pcapng_posa_load_dir
#define posa_count      pcapng_posa_count
#define posa_at         pcapng_posa_at
#define posa_find       pcapng_posa_find
#define posa_to_text    pcapng_posa_to_text
#define posa_source     pcapng_posa_source   /* the .posa text as written, if kept */
#define posa_resolve    pcapng_posa_resolve

/* carcal-side wrapper: dissect with the libpcapng posa engine and convert the
   resulting pcapng_field_t subtree into carcal's cfield tree (dissect.c). */
int  posa_dissect(const char *proto_name, const uint8_t *data, int len, cfield_t *parent, int abs_off);

/* ── filter.c — display filter ──────────────────────────────────────────── */
typedef struct cfilter cfilter_t;
/* Compile an expression. On error returns NULL and writes errbuf. Empty/NULL
   expression compiles to a filter that matches everything. */
cfilter_t *filter_compile(const char *expr, char *errbuf, size_t errlen);
/* Evaluate against a dissection tree (non-zero = packet passes). */
int        filter_eval(const cfilter_t *f, cfield_t *root);
void       filter_free(cfilter_t *f);

/* ── colorrules.c — packet-list coloring rules ──────────────────────────── */
/* An ordered list of "<display filter> => fg/bg". The first rule that matches a
   packet paints its row; later rules are not consulted.
 *
 * Rules come from three layers, most specific first:
 *   1. the user's <protos dir>/colorfilters file
 *   2. `color <filter> => <fg> <bg>` lines declared inside the loaded .posa
 *      decoders — a protocol ships its own coloring, no rebuild needed
 *   3. compiled-in defaults
 * colorrules_reload() composes all three; call it after the posa decoders load. */
void colorrules_reload(const char *user_file);
void colorrules_add_defaults(void);
int  colorrules_add_from_posa(void);                  /* returns #imported     */
int  colorrules_load_file(const char *path);          /* -1 if absent          */
int  colorrules_save_file(const char *path);
int  colorrules_add(const char *expr, uint8_t fg, uint8_t bg);
void colorrules_clear(void);
int  colorrules_count(void);
int  colorrules_get(int i, char *expr, size_t elen, uint8_t *fg, uint8_t *bg, int *enabled);
/* 1 + fg/bg if a rule matched, else 0. */
int  colorrules_match(cfield_t *root, uint8_t *fg, uint8_t *bg);
int  colorrules_enabled(void);                        /* View ▸ Colorize       */
void colorrules_set_enabled(int on);
const char *colorrules_color_name(uint8_t v);

/* ── rules.c — decoder rules ────────────────────────────────────────────── */
/* A rule maps a display-filter condition to a posa decoder: when the condition
   matches a packet's dissection, that decoder is applied to the transport
   payload. Lets you pick a decoder by protocol/field/heuristic, not just port. */
int  rules_add(const char *expr, const char *proto, char *errbuf, size_t errlen);
int  rules_load_file(const char *path, char *errbuf, size_t errlen); /* "cond => Decoder" lines */
void rules_load_defaults(void);
const char *rules_match(cfield_t *root);   /* decoder name for a dissection, or NULL */
int  rules_count(void);
int  rules_get(int i, char *expr, size_t elen, char *proto, size_t plen);
int  rules_set(int i, const char *expr, const char *proto, char *errbuf, size_t errlen);
int  rules_remove(int i);
int  rules_save_file(const char *path);   /* persist rules; returns 0 on success */
void rules_clear(void);

/* TCP stream reassembly now lives in libpcapng (pcapng_tcp_reasm_*,
   <libpcapng/reassembly_tcp.h>) — it is a library feature, not carcal's. */

/* ── lua_run.c — scriptable processing (generalized MQS) ────────────────── */
/* Run `script_path` against the capture. For each packet (IP-defragmented via
   libpcapng) the Lua `packet(pkt)` is called (when present and `flt` passes);
   reassembled TCP stream bytes drive `stream(s)`. Returns 0 on success. */
int carcal_lua_run(const char *script_path, capture_t *cap, cfilter_t *flt,
                    char *errbuf, size_t errlen);

#endif /* CARCAL_H */
