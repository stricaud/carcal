/* posa.c — load user-defined protocols (.posa) and dissect with them.
 *
 * The .posa grammar (see libpcapng Tutorial.md Part 9-10):
 *
 *     Object<parent> NAME           # or:  protocol NAME ... end
 *         required uint16 opcode = 1
 *             RRQ = 1               # enum constants, indented under a field
 *         required cstring filename
 *         required payload data
 *
 * Field types: uint8/16/32/64, le_uint16/32/64, mac, ip4, cstring, payload,
 * bytes<N>, bytes[lenfield]. `Object<parent>` groups sub-protocols dispatched
 * on the first field's value.
 */
#include "caracal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

#define MAX_PROTOS 256
static posa_proto_t g_protos[MAX_PROTOS];
static int          g_nprotos = 0;

#define MAX_BINDS 256
typedef struct { uint16_t port; char proto[POSA_NAME_MAX]; int used; } bind_t;
static bind_t g_udp_binds[MAX_BINDS];
static bind_t g_tcp_binds[MAX_BINDS];

int posa_count(void) { return g_nprotos; }
const posa_proto_t *posa_at(int i) { return (i >= 0 && i < g_nprotos) ? &g_protos[i] : NULL; }

const posa_proto_t *posa_find(const char *name)
{
  int i;
  for (i = 0; i < g_nprotos; i++)
    if (strcmp(g_protos[i].name, name) == 0) return &g_protos[i];
  return NULL;
}

/* ── parsing helpers ────────────────────────────────────────────────────── */
static uint64_t parse_num(const char *s)
{
  if (!s) return 0;
  while (*s == ' ' || *s == '\t') s++;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    return (uint64_t)strtoull(s, NULL, 16);
  return (uint64_t)strtoull(s, NULL, 10);
}

static int parse_type(const char *tok, posa_fld_t *f)
{
  if      (!strcmp(tok, "uint8"))      f->type = PT_U8;
  else if (!strcmp(tok, "uint16"))     f->type = PT_U16;
  else if (!strcmp(tok, "uint32"))     f->type = PT_U32;
  else if (!strcmp(tok, "uint64"))     f->type = PT_U64;
  else if (!strcmp(tok, "le_uint16"))  f->type = PT_LE16;
  else if (!strcmp(tok, "le_uint32"))  f->type = PT_LE32;
  else if (!strcmp(tok, "le_uint64"))  f->type = PT_LE64;
  else if (!strcmp(tok, "mac"))        f->type = PT_MAC;
  else if (!strcmp(tok, "ip4"))        f->type = PT_IP4;
  else if (!strcmp(tok, "cstring"))    f->type = PT_CSTRING;
  else if (!strcmp(tok, "payload"))    f->type = PT_PAYLOAD;
  else if (!strncmp(tok, "bytes<", 6)) { f->type = PT_BYTES_FIXED; f->nbytes = (size_t)parse_num(tok + 6); }
  else if (!strncmp(tok, "bytes[", 6)) {
    const char *e;
    f->type = PT_BYTES_REF;
    e = strchr(tok + 6, ']');
    snprintf(f->lenfield, sizeof f->lenfield, "%.*s",
             e ? (int)(e - (tok + 6)) : 0, tok + 6);
  } else return -1;
  return 0;
}

static int is_type_tok(const char *t)
{
  posa_fld_t tmp;
  return parse_type(t, &tmp) == 0;
}

/* split a line into whitespace tokens; returns count */
static int tokenize(char *line, char *toks[], int max)
{
  int n = 0;
  char *p = line;
  while (*p && n < max) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;
    toks[n++] = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    if (*p) *p++ = '\0';
  }
  return n;
}

/* ── source parsing ─────────────────────────────────────────────────────── */
static int parse_src(const char *src, char *errbuf, size_t errlen)
{
  const char *line = src;
  posa_proto_t *cur = NULL;
  int added = 0, lineno = 0;

  while (*line) {
    char buf[1024];
    const char *eol = strchr(line, '\n');
    size_t llen = eol ? (size_t)(eol - line) : strlen(line);
    char *toks[32];
    int nt;
    char *hash;

    lineno++;
    if (llen >= sizeof buf) llen = sizeof buf - 1;
    memcpy(buf, line, llen);
    buf[llen] = '\0';
    line = eol ? eol + 1 : line + strlen(line);

    /* strip comments */
    hash = strchr(buf, '#');
    if (hash) *hash = '\0';

    nt = tokenize(buf, toks, 32);
    if (nt == 0) continue;

    if (!strncmp(toks[0], "Object<", 7) || !strcmp(toks[0], "protocol")) {
      char parent[POSA_NAME_MAX] = "main";
      const char *name = NULL;
      if (!strcmp(toks[0], "protocol")) {
        name = nt > 1 ? toks[1] : NULL;
      } else {
        char *gt = strchr(toks[0], '>');
        const char *p = toks[0] + 7;
        if (gt) { snprintf(parent, sizeof parent, "%.*s", (int)(gt - p), p); }
        name = nt > 1 ? toks[1] : NULL;
      }
      if (!name) { if (errbuf) snprintf(errbuf, errlen, "line %d: missing protocol name", lineno); return -1; }
      if (g_nprotos >= MAX_PROTOS) { if (errbuf) snprintf(errbuf, errlen, "too many protocols"); return -1; }
      cur = &g_protos[g_nprotos++];
      memset(cur, 0, sizeof *cur);
      snprintf(cur->name, sizeof cur->name, "%s", name);
      snprintf(cur->parent, sizeof cur->parent, "%s", parent);
      added++;
      continue;
    }
    if (!strcmp(toks[0], "end")) { cur = NULL; continue; }
    if (!cur) continue;  /* stray line outside a protocol */

    /* field line: [required|optional] <type> <name> [= default] */
    {
      int ti = 0;
      if (!strcmp(toks[0], "required") || !strcmp(toks[0], "optional")) ti = 1;
      if (ti < nt && is_type_tok(toks[ti])) {
        posa_fld_t *f;
        if (cur->nflds >= POSA_MAX_FLDS) continue;
        f = &cur->flds[cur->nflds];
        memset(f, 0, sizeof *f);
        parse_type(toks[ti], f);
        if (ti + 1 < nt) snprintf(f->name, sizeof f->name, "%s", toks[ti + 1]);
        /* default after '=' */
        { int k; for (k = ti + 2; k < nt; k++) if (!strcmp(toks[k], "=") && k + 1 < nt) {
            f->defnum = parse_num(toks[k + 1]); break; } }
        cur->nflds++;
        continue;
      }
    }

    /* enum line: NAME = value (attaches to the most recent field) */
    if (cur->nflds > 0 && nt >= 3 && !strcmp(toks[1], "=")) {
      posa_fld_t *f = &cur->flds[cur->nflds - 1];
      if (f->nenums < POSA_MAX_ENUMS) {
        posa_enum_t *e = &f->enums[f->nenums++];
        snprintf(e->name, sizeof e->name, "%s", toks[0]);
        e->val = parse_num(toks[2]);
      }
      continue;
    }
  }
  return added;
}

int posa_load_file(const char *path, char *errbuf, size_t errlen)
{
  FILE *fp = fopen(path, "rb");
  long sz;
  char *src;
  int rc;
  if (!fp) { if (errbuf) snprintf(errbuf, errlen, "cannot open %s", path); return -1; }
  fseek(fp, 0, SEEK_END);
  sz = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (sz < 0) { fclose(fp); return -1; }
  src = malloc((size_t)sz + 1);
  if (!src) { fclose(fp); return -1; }
  if (fread(src, 1, (size_t)sz, fp) != (size_t)sz) { free(src); fclose(fp); return -1; }
  src[sz] = '\0';
  fclose(fp);
  rc = parse_src(src, errbuf, errlen);
  free(src);
  return rc;
}

int posa_load_dir(const char *dir)
{
  DIR *dp = opendir(dir);
  struct dirent *de;
  int total = 0;
  if (!dp) return -1;
  while ((de = readdir(dp))) {
    size_t n = strlen(de->d_name);
    char path[1200];
    int rc;
    if (n < 6 || strcmp(de->d_name + n - 5, ".posa") != 0) continue;
    snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
    rc = posa_load_file(path, NULL, 0);
    if (rc > 0) total += rc;
  }
  closedir(dp);
  return total;
}

/* ── port bindings ──────────────────────────────────────────────────────── */
static void bind_set(bind_t *tbl, uint16_t port, const char *proto)
{
  int i, free_slot = -1;
  for (i = 0; i < MAX_BINDS; i++) {
    if (tbl[i].used && tbl[i].port == port) {
      if (proto) snprintf(tbl[i].proto, sizeof tbl[i].proto, "%s", proto);
      else       tbl[i].used = 0;
      return;
    }
    if (!tbl[i].used && free_slot < 0) free_slot = i;
  }
  if (proto && free_slot >= 0) {
    tbl[free_slot].used = 1;
    tbl[free_slot].port = port;
    snprintf(tbl[free_slot].proto, sizeof tbl[free_slot].proto, "%s", proto);
  }
}
static const char *bind_get(bind_t *tbl, uint16_t port)
{
  int i;
  for (i = 0; i < MAX_BINDS; i++)
    if (tbl[i].used && tbl[i].port == port) return tbl[i].proto;
  return NULL;
}
void posa_bind_udp(uint16_t port, const char *p) { bind_set(g_udp_binds, port, p); }
void posa_bind_tcp(uint16_t port, const char *p) { bind_set(g_tcp_binds, port, p); }
const char *posa_bound_udp(uint16_t port) { return bind_get(g_udp_binds, port); }
const char *posa_bound_tcp(uint16_t port) { return bind_get(g_tcp_binds, port); }

/* ── dissection ─────────────────────────────────────────────────────────── */
static const char *enum_name(const posa_fld_t *f, uint64_t v)
{
  int i;
  for (i = 0; i < f->nenums; i++)
    if (f->enums[i].val == v) return f->enums[i].name;
  return NULL;
}

static int fld_fixed_size(const posa_fld_t *f)
{
  switch (f->type) {
  case PT_U8:  return 1;
  case PT_U16: case PT_LE16: return 2;
  case PT_U32: case PT_LE32: return 4;
  case PT_U64: case PT_LE64: return 8;
  case PT_MAC: return 6;
  case PT_IP4: return 4;
  case PT_BYTES_FIXED: return (int)f->nbytes;
  default: return -1;  /* variable */
  }
}

static uint64_t rd_be(const uint8_t *d, int n)
{
  uint64_t v = 0; int i;
  for (i = 0; i < n; i++) v = (v << 8) | d[i];
  return v;
}
static uint64_t rd_le(const uint8_t *d, int n)
{
  uint64_t v = 0; int i;
  for (i = n - 1; i >= 0; i--) v = (v << 8) | d[i];
  return v;
}

/* track integer field values by name for bytes[lenfield] */
typedef struct { char name[POSA_NAME_MAX]; uint64_t val; } seen_t;

static int dissect_one(const posa_proto_t *p, const uint8_t *data, int len, cfield_t *node)
{
  int off = 0, i;
  seen_t seen[POSA_MAX_FLDS];
  int nseen = 0;
  char ab[CFIELD_ABBREV_MAX];

  for (i = 0; i < p->nflds; i++) {
    const posa_fld_t *f = &p->flds[i];
    int sz = fld_fixed_size(f);
    cfield_t *cf = NULL;

    snprintf(ab, sizeof ab, "%s.%s", p->name, f->name);

    if (sz >= 0) {  /* fixed-size field */
      if (off + sz > len) break;
      switch (f->type) {
      case PT_U8: case PT_U16: case PT_U32: case PT_U64: {
        uint64_t v = rd_be(data + off, sz);
        const char *en;
        cf = cfield_add(node, ab, CV_UINT); cfield_set_uint(cf, v);
        en = enum_name(f, v);
        if (en) cfield_set_label(cf, "%s: %s (%llu)", f->name, en, (unsigned long long)v);
        else    cfield_set_label(cf, "%s: %llu", f->name, (unsigned long long)v);
        if (nseen < POSA_MAX_FLDS) { snprintf(seen[nseen].name, sizeof seen[nseen].name, "%s", f->name); seen[nseen].val = v; nseen++; }
        break;
      }
      case PT_LE16: case PT_LE32: case PT_LE64: {
        uint64_t v = rd_le(data + off, sz);
        const char *en = enum_name(f, v);
        cf = cfield_add(node, ab, CV_UINT); cfield_set_uint(cf, v);
        if (en) cfield_set_label(cf, "%s: %s (%llu)", f->name, en, (unsigned long long)v);
        else    cfield_set_label(cf, "%s: %llu", f->name, (unsigned long long)v);
        if (nseen < POSA_MAX_FLDS) { snprintf(seen[nseen].name, sizeof seen[nseen].name, "%s", f->name); seen[nseen].val = v; nseen++; }
        break;
      }
      case PT_MAC:
        cf = cfield_add(node, ab, CV_MAC); cfield_set_mac(cf, data + off);
        cfield_set_label(cf, "%s: %s", f->name, cf->str);
        break;
      case PT_IP4:
        cf = cfield_add(node, ab, CV_IPV4); cfield_set_ipv4(cf, data + off);
        cfield_set_label(cf, "%s: %s", f->name, cf->str);
        break;
      case PT_BYTES_FIXED:
        cf = cfield_add(node, ab, CV_BYTES); cfield_set_bytes(cf, data + off, sz);
        cfield_set_label(cf, "%s: %d bytes", f->name, sz);
        break;
      default: break;
      }
      if (cf) { cf->off = off; cf->len = sz; }
      off += sz;
    } else if (f->type == PT_CSTRING) {
      int start = off, n = 0;
      char tmp[256];
      while (off < len && data[off] != '\0' && n < (int)sizeof tmp - 1) tmp[n++] = (char)data[off++];
      tmp[n] = '\0';
      if (off < len && data[off] == '\0') off++;  /* consume NUL */
      cf = cfield_add(node, ab, CV_STR); cfield_set_str(cf, tmp);
      cfield_set_label(cf, "%s: %s", f->name, tmp);
      cf->off = start; cf->len = off - start;
    } else if (f->type == PT_BYTES_REF) {
      int n = 0, j;
      for (j = 0; j < nseen; j++) if (!strcmp(seen[j].name, f->lenfield)) { n = (int)seen[j].val; break; }
      if (off + n > len) n = len - off;
      if (n < 0) n = 0;
      cf = cfield_add(node, ab, CV_BYTES); cfield_set_bytes(cf, data + off, n);
      cfield_set_label(cf, "%s: %d bytes", f->name, n);
      cf->off = off; cf->len = n;
      off += n;
    } else if (f->type == PT_PAYLOAD) {
      int n = len - off;
      if (n < 0) n = 0;
      cf = cfield_add(node, ab, CV_BYTES); cfield_set_bytes(cf, data + off, n);
      cfield_set_label(cf, "%s: %d bytes", f->name, n);
      cf->off = off; cf->len = n;
      off = len;
    }
  }
  return off;
}

/* If `name` is an Object<parent> group, pick the sub-protocol whose first
   field's default matches the first bytes of `data`. */
static const posa_proto_t *resolve_group(const char *name, const uint8_t *data, int len)
{
  int i, best = -1;
  for (i = 0; i < g_nprotos; i++) {
    const posa_proto_t *p = &g_protos[i];
    int sz;
    if (strcmp(p->parent, name) != 0 || p->nflds == 0) continue;
    sz = fld_fixed_size(&p->flds[0]);
    if (sz <= 0 || sz > len) continue;
    {
      uint64_t v = (p->flds[0].type == PT_LE16 || p->flds[0].type == PT_LE32 ||
                    p->flds[0].type == PT_LE64) ? rd_le(data, sz) : rd_be(data, sz);
      if (v == p->flds[0].defnum) { best = i; break; }
    }
  }
  return best >= 0 ? &g_protos[best] : NULL;
}

int posa_dissect(const char *proto_name, const uint8_t *data, int len, cfield_t *parent)
{
  const posa_proto_t *p = posa_find(proto_name);
  cfield_t *node;
  int used;

  if (!proto_name || !data || len <= 0) return 0;

  if (!p) {  /* maybe a group name */
    p = resolve_group(proto_name, data, len);
    if (!p) return 0;
  }

  node = cfield_add(parent, p->name, CV_NONE);
  cfield_set_label(node, "%s", p->name);
  used = dissect_one(p, data, len, node);
  return used > 0 ? used : len;  /* claim the payload even if zero-length fields */
}
