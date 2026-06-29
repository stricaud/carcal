/*
 * caracal.h — shared types for caracal, a TUI packet analyzer.
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
#ifndef CARACAL_H
#define CARACAL_H

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

/* ── Captured packet ────────────────────────────────────────────────────── */
typedef struct {
  uint8_t  *data;          /* captured bytes (owned)                          */
  uint32_t  caplen;        /* bytes present in .data                          */
  uint32_t  origlen;       /* original on-wire length                         */
  uint64_t  ts_us;         /* timestamp, microseconds since the Unix epoch    */
  uint16_t  linktype;      /* pcap/pcapng LINKTYPE_*                           */

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

/* ── dissect.c — bytes → cfield tree ────────────────────────────────────── */
/* Build the dissection tree for one packet. Caller frees with cfield_free.
   Registered posa protocols (posa.c) participate in transport dissection. */
cfield_t *dissect_packet(const cpkt_t *pkt);
/* Fill pkt->col_* from a dissection (cheap summary). Safe to call repeatedly. */
void      dissect_summarize(cpkt_t *pkt);

/* Common LINKTYPE values we understand. */
#define LINKTYPE_NULL      0
#define LINKTYPE_ETHERNET  1
#define LINKTYPE_RAW       101
#define LINKTYPE_LINUX_SLL 113
#define LINKTYPE_IPV4      228
#define LINKTYPE_IPV6      229

/* ── posa.c — user-defined protocols ────────────────────────────────────── */
typedef enum {
  PT_U8, PT_U16, PT_U32, PT_U64,
  PT_LE16, PT_LE32, PT_LE64,
  PT_MAC, PT_IP4, PT_CSTRING, PT_PAYLOAD,
  PT_BYTES_FIXED,   /* bytes<N>        */
  PT_BYTES_REF      /* bytes[lenfield] */
} posa_ftype_t;

#define POSA_NAME_MAX   64
#define POSA_MAX_FLDS   64
#define POSA_MAX_ENUMS  32

typedef struct { char name[POSA_NAME_MAX]; uint64_t val; } posa_enum_t;

typedef struct {
  char         name[POSA_NAME_MAX];
  posa_ftype_t type;
  uint64_t     defnum;
  size_t       nbytes;            /* PT_BYTES_FIXED                          */
  char         lenfield[POSA_NAME_MAX]; /* PT_BYTES_REF                      */
  posa_enum_t  enums[POSA_MAX_ENUMS];
  int          nenums;
} posa_fld_t;

typedef struct {
  char        name[POSA_NAME_MAX];
  char        parent[POSA_NAME_MAX];   /* Object<parent>, "" / "main" if top */
  posa_fld_t  flds[POSA_MAX_FLDS];
  int         nflds;
} posa_proto_t;

/* Parse a .posa file / directory; returns #protocols added or -1. */
int  posa_load_file(const char *path, char *errbuf, size_t errlen);
int  posa_load_dir(const char *dir);
int  posa_count(void);
const posa_proto_t *posa_at(int index);
const posa_proto_t *posa_find(const char *name);
/* Bind a transport port to a posa protocol for "Decode As". proto NULL clears. */
void posa_bind_udp(uint16_t port, const char *proto_name);
void posa_bind_tcp(uint16_t port, const char *proto_name);
const char *posa_bound_udp(uint16_t port); /* NULL if none */
const char *posa_bound_tcp(uint16_t port);
/* Dissect `data` as the named posa protocol, attaching a subtree to `parent`.
   Returns bytes consumed, 0 if it could not (unknown proto / no data). */
int  posa_dissect(const char *proto_name, const uint8_t *data, int len, cfield_t *parent);

/* ── filter.c — display filter ──────────────────────────────────────────── */
typedef struct cfilter cfilter_t;
/* Compile an expression. On error returns NULL and writes errbuf. Empty/NULL
   expression compiles to a filter that matches everything. */
cfilter_t *filter_compile(const char *expr, char *errbuf, size_t errlen);
/* Evaluate against a dissection tree (non-zero = packet passes). */
int        filter_eval(const cfilter_t *f, cfield_t *root);
void       filter_free(cfilter_t *f);

#endif /* CARACAL_H */
