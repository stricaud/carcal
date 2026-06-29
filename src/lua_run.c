/* lua_run.c — scriptable packet/stream processing with LuaJIT.
 *
 * A generalization of MQS: instead of decoding only MySQL and handing a query
 * string to Lua, caracal dissects every packet (built-in protocols + loaded
 * .posa definitions), reassembles IP fragments (libpcapng) and TCP streams, and
 * hands the fully decoded fields — in their various representations — to Lua.
 *
 * Script entry points (all optional except you'll usually want one):
 *     function init()            -- once, before processing
 *     function packet(pkt)       -- per (defragmented) packet
 *     function stream(s)         -- per reassembled in-order TCP chunk
 *     function finish(stats)     -- once, after processing
 *
 * Globals (the `caracal` table):
 *     caracal.decode_as(bytes, proto)   -> {field=value,…}  (posa, full bytes)
 *     caracal.decode_all(bytes, group)  -> { {proto=,fields=}, … }
 *     caracal.dissect(bytes [,linktype])-> pkt-like table
 *     caracal.protocols()               -> { name, … }
 *     caracal.hex(bytes)                -> "aabbcc…"
 */
#include "caracal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <libpcapng/libpcapng.h>
#include <libpcapng/reassembly.h>
#include <libpcapng/reassembly_tcp.h>

/* live dissection root for pkt:matches() during a packet() call */
static cfield_t *g_cur_root = NULL;

/* ── byte readers ───────────────────────────────────────────────────────── */
static uint32_t be32_(const uint8_t *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint16_t be16_(const uint8_t *p) { return (uint16_t)((p[0]<<8)|p[1]); }
static uint64_t rd_be_(const uint8_t *d, int n){ uint64_t v=0;int i;for(i=0;i<n;i++)v=(v<<8)|d[i];return v; }
static uint64_t rd_le_(const uint8_t *d, int n){ uint64_t v=0;int i;for(i=n-1;i>=0;i--)v=(v<<8)|d[i];return v; }
static uint32_t fold16(const uint8_t *p){ return be32_(p)^be32_(p+4)^be32_(p+8)^be32_(p+12); }

/* ── transport extraction ──────────────────────────────────────────────── */
typedef struct {
  int      ok;
  int      proto;            /* 6=TCP 17=UDP */
  uint32_t sip, dip;         /* host order (IPv6 folded to 32 bits)           */
  uint16_t sport, dport;
  uint32_t seq;              /* TCP only                                      */
  uint8_t  flags;            /* TCP only                                      */
  int      poff, plen;       /* payload offset/length within the buffer       */
} l4_t;

static l4_t get_l4(const uint8_t *d, int len, uint16_t lt)
{
  l4_t r; uint16_t et = 0; int off = 0; const uint8_t *ip; int iplen; uint8_t ipproto;
  memset(&r, 0, sizeof r);

  if (lt == LINKTYPE_ETHERNET) {
    if (len < 14) return r;
    et = be16_(d + 12); off = 14;
    if (et == 0x8100) { if (len < 18) return r; et = be16_(d + 16); off = 18; }
  } else if (lt == LINKTYPE_RAW || lt == LINKTYPE_IPV4 || lt == LINKTYPE_IPV6) {
    et = (len > 0 && (d[0] >> 4) == 6) ? 0x86DD : 0x0800;
  } else if (lt == LINKTYPE_NULL) {
    uint32_t af;
    if (len < 4) return r;
    af = (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
    et = (af == 2) ? 0x0800 : (af==24||af==28||af==30) ? 0x86DD : 0;
    off = 4;
  } else {
    if (len > 0 && (d[0] >> 4) == 4) et = 0x0800; else return r;
  }

  ip = d + off; iplen = len - off;
  if (et == 0x0800) {
    int ihl;
    if (iplen < 20) return r;
    ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > iplen) return r;
    ipproto = ip[9];
    r.sip = be32_(ip + 12); r.dip = be32_(ip + 16);
    off += ihl;
  } else if (et == 0x86DD) {
    if (iplen < 40) return r;
    ipproto = ip[6];
    r.sip = fold16(ip + 8); r.dip = fold16(ip + 24);
    off += 40;
  } else return r;

  {
    const uint8_t *l4 = d + off; int l4len = len - off;
    if (l4len < 0) return r;
    r.proto = ipproto;
    if (ipproto == 6) {
      int doff;
      if (l4len < 20) return r;
      doff = ((l4[12] >> 4) & 0x0f) * 4;
      if (doff < 20 || doff > l4len) return r;
      r.sport = be16_(l4); r.dport = be16_(l4 + 2);
      r.seq = be32_(l4 + 4); r.flags = l4[13];
      r.poff = off + doff; r.plen = l4len - doff; r.ok = 1;
    } else if (ipproto == 17) {
      if (l4len < 8) return r;
      r.sport = be16_(l4); r.dport = be16_(l4 + 2);
      r.poff = off + 8; r.plen = l4len - 8; r.ok = 1;
    }
  }
  return r;
}

/* ── cfield → Lua ───────────────────────────────────────────────────────── */
static const char *vtype_name(cval_type_t t)
{
  switch (t) {
  case CV_UINT: return "uint";
  case CV_STR:  return "str";
  case CV_IPV4: return "ipv4";
  case CV_IPV6: return "ipv6";
  case CV_MAC:  return "mac";
  case CV_BYTES:return "bytes";
  default:      return "none";
  }
}

static void push_value(lua_State *L, cfield_t *f)
{
  switch (f->vtype) {
  case CV_UINT: lua_pushnumber(L, (double)f->u); break;
  case CV_STR: case CV_IPV4: case CV_IPV6: case CV_MAC:
    lua_pushstring(L, f->str); break;
  case CV_BYTES: lua_pushlstring(L, (const char *)f->bytes, (size_t)f->blen); break;
  default: lua_pushnil(L);
  }
}

static void push_hex(lua_State *L, cfield_t *f)
{
  static const char hd[] = "0123456789abcdef";
  char buf[64]; int n = 0, i;
  if (f->blen > 0) {
    for (i = 0; i < f->blen && n < (int)sizeof buf - 2; i++) {
      buf[n++] = hd[(f->bytes[i] >> 4) & 0xf];
      buf[n++] = hd[f->bytes[i] & 0xf];
    }
    buf[n] = '\0';
  } else if (f->vtype == CV_UINT) {
    snprintf(buf, sizeof buf, "%llx", (unsigned long long)f->u);
  } else buf[0] = '\0';
  lua_pushstring(L, buf);
}

static void push_node(lua_State *L, cfield_t *f)
{
  const char *nm;
  cfield_t *c; int idx = 1;
  lua_newtable(L);
  lua_pushstring(L, f->abbrev); lua_setfield(L, -2, "abbrev");
  nm = strrchr(f->abbrev, '.'); nm = nm ? nm + 1 : f->abbrev;
  lua_pushstring(L, nm); lua_setfield(L, -2, "name");
  lua_pushstring(L, f->label); lua_setfield(L, -2, "label");
  lua_pushstring(L, vtype_name(f->vtype)); lua_setfield(L, -2, "type");
  push_value(L, f); lua_setfield(L, -2, "value");
  push_hex(L, f);   lua_setfield(L, -2, "hex");
  lua_newtable(L);
  for (c = f->children; c; c = c->next) { push_node(L, c); lua_rawseti(L, -2, idx++); }
  lua_setfield(L, -2, "children");
}

/* flat abbrev→value map (first occurrence wins) at absolute index `tab` */
static void fill_fields(lua_State *L, int tab, cfield_t *f)
{
  cfield_t *c;
  if (f->abbrev[0] && f->vtype != CV_NONE) {
    lua_getfield(L, tab, f->abbrev);
    if (lua_isnil(L, -1)) { lua_pop(L, 1); push_value(L, f); lua_setfield(L, tab, f->abbrev); }
    else lua_pop(L, 1);
  }
  for (c = f->children; c; c = c->next) fill_fields(L, tab, c);
}

/* ordered layer-name list at absolute index `tab` (structural nodes) */
static void fill_layers(lua_State *L, int tab, cfield_t *f, int *idx)
{
  cfield_t *c;
  if (f->abbrev[0] && f->vtype == CV_NONE) {
    lua_pushstring(L, f->abbrev); lua_rawseti(L, tab, (*idx)++);
  }
  for (c = f->children; c; c = c->next) fill_layers(L, tab, c, idx);
}

static void set_metatable(lua_State *L, int objabs, const char *mtfield)
{
  lua_getglobal(L, "caracal");
  lua_getfield(L, -1, mtfield);
  lua_setmetatable(L, objabs);
  lua_pop(L, 1);  /* caracal */
}

/* Build a pkt table on top of the stack. p may be NULL (caracal.dissect). */
static void push_pkt(lua_State *L, const cpkt_t *p, cfield_t *root,
                     long number, int with_time, const capture_t *cap)
{
  cfield_t *c; int idx, tab;
  l4_t l4;

  lua_newtable(L);
  tab = lua_gettop(L);

  if (number > 0) { lua_pushnumber(L, (double)number); lua_setfield(L, tab, "number"); }
  if (p) {
    lua_pushnumber(L, (double)p->origlen); lua_setfield(L, tab, "len");
    lua_pushnumber(L, (double)p->caplen);  lua_setfield(L, tab, "caplen");
    lua_pushnumber(L, (double)p->linktype);lua_setfield(L, tab, "linktype");
    lua_pushnumber(L, (double)p->ts_us);   lua_setfield(L, tab, "timestamp");
    if (with_time && cap) {
      double t = (double)((p->ts_us >= cap->first_ts_us) ? p->ts_us - cap->first_ts_us : 0) / 1e6;
      lua_pushnumber(L, t); lua_setfield(L, tab, "time");
    }
    lua_pushlstring(L, (const char *)p->data, p->caplen); lua_setfield(L, tab, "raw");
  }

  /* summary columns from a structural walk */
  {
    cpkt_t tmp;
    if (p) { tmp = *p; tmp.summarized = 0; dissect_summarize(&tmp);
      lua_pushstring(L, tmp.col_proto); lua_setfield(L, tab, "protocol");
      lua_pushstring(L, tmp.col_src);   lua_setfield(L, tab, "src");
      lua_pushstring(L, tmp.col_dst);   lua_setfield(L, tab, "dst");
      lua_pushstring(L, tmp.col_info);  lua_setfield(L, tab, "info");
    }
  }

  /* layers[] */
  lua_newtable(L); idx = 1;
  for (c = root->children; c; c = c->next) fill_layers(L, lua_gettop(L), c, &idx);
  lua_setfield(L, tab, "layers");

  /* fields{} */
  lua_newtable(L);
  for (c = root->children; c; c = c->next) fill_fields(L, lua_gettop(L), c);
  lua_setfield(L, tab, "fields");

  /* tree[] */
  lua_newtable(L); idx = 1;
  for (c = root->children; c; c = c->next) { push_node(L, c); lua_rawseti(L, -2, idx++); }
  lua_setfield(L, tab, "tree");

  /* transport payload + ports */
  if (p) {
    l4 = get_l4(p->data, (int)p->caplen, p->linktype);
    if (l4.ok) {
      lua_pushnumber(L, l4.sport); lua_setfield(L, tab, "srcport");
      lua_pushnumber(L, l4.dport); lua_setfield(L, tab, "dstport");
      lua_pushstring(L, l4.proto == 6 ? "tcp" : "udp"); lua_setfield(L, tab, "l4");
      if (l4.plen > 0 && l4.poff + l4.plen <= (int)p->caplen) {
        lua_pushlstring(L, (const char *)(p->data + l4.poff), (size_t)l4.plen);
        lua_setfield(L, tab, "payload");
      }
    }
  }

  set_metatable(L, tab, "_pktmt");
}

/* ── posa → Lua decoder (full-fidelity, no 16-byte cfield cap) ──────────── */
typedef struct { char name[POSA_NAME_MAX]; uint64_t val; } seen_t;

static int posa_fixed_size(const posa_fld_t *f)
{
  switch (f->type) {
  case PT_U8: return 1;
  case PT_U16: case PT_LE16: return 2;
  case PT_U32: case PT_LE32: return 4;
  case PT_U64: case PT_LE64: return 8;
  case PT_MAC: return 6;
  case PT_IP4: return 4;
  case PT_BYTES_FIXED: return (int)f->nbytes;
  default: return -1;
  }
}

/* Build a {fieldname=value} table for posa proto p over data[0..len). */
static void push_posa_map(lua_State *L, const posa_proto_t *p, const uint8_t *d, int len)
{
  int off = 0, i, nseen = 0;
  seen_t seen[POSA_MAX_FLDS];
  lua_newtable(L);

  for (i = 0; i < p->nflds; i++) {
    const posa_fld_t *f = &p->flds[i];
    int sz = posa_fixed_size(f);

    if (sz >= 0) {
      if (off + sz > len) break;
      switch (f->type) {
      case PT_U8: case PT_U16: case PT_U32: case PT_U64: {
        uint64_t v = rd_be_(d + off, sz);
        lua_pushnumber(L, (double)v); lua_setfield(L, -2, f->name);
        if (nseen < POSA_MAX_FLDS) { snprintf(seen[nseen].name, sizeof seen[nseen].name, "%s", f->name); seen[nseen].val = v; nseen++; }
        break;
      }
      case PT_LE16: case PT_LE32: case PT_LE64: {
        uint64_t v = rd_le_(d + off, sz);
        lua_pushnumber(L, (double)v); lua_setfield(L, -2, f->name);
        if (nseen < POSA_MAX_FLDS) { snprintf(seen[nseen].name, sizeof seen[nseen].name, "%s", f->name); seen[nseen].val = v; nseen++; }
        break;
      }
      case PT_MAC: {
        char m[24];
        snprintf(m, sizeof m, "%02x:%02x:%02x:%02x:%02x:%02x",
                 d[off],d[off+1],d[off+2],d[off+3],d[off+4],d[off+5]);
        lua_pushstring(L, m); lua_setfield(L, -2, f->name);
        break;
      }
      case PT_IP4: {
        char a[16];
        snprintf(a, sizeof a, "%u.%u.%u.%u", d[off],d[off+1],d[off+2],d[off+3]);
        lua_pushstring(L, a); lua_setfield(L, -2, f->name);
        break;
      }
      case PT_BYTES_FIXED:
        lua_pushlstring(L, (const char *)(d + off), (size_t)sz);
        lua_setfield(L, -2, f->name);
        break;
      default: break;
      }
      off += sz;
    } else if (f->type == PT_CSTRING) {
      int start = off;
      while (off < len && d[off] != '\0') off++;
      lua_pushlstring(L, (const char *)(d + start), (size_t)(off - start));
      lua_setfield(L, -2, f->name);
      if (off < len) off++;  /* NUL */
    } else if (f->type == PT_BYTES_REF) {
      int n = 0, j;
      for (j = 0; j < nseen; j++) if (!strcmp(seen[j].name, f->lenfield)) { n = (int)seen[j].val; break; }
      if (off + n > len) n = len - off;
      if (n < 0) n = 0;
      lua_pushlstring(L, (const char *)(d + off), (size_t)n);
      lua_setfield(L, -2, f->name);
      off += n;
    } else if (f->type == PT_PAYLOAD) {
      int n = len - off; if (n < 0) n = 0;
      lua_pushlstring(L, (const char *)(d + off), (size_t)n);
      lua_setfield(L, -2, f->name);
      off = len;
    }
  }
}

/* ── caracal.* globals ──────────────────────────────────────────────────── */
static int l_decode_as(lua_State *L)
{
  size_t len; const char *d = luaL_checklstring(L, 1, &len);
  const char *proto = luaL_checkstring(L, 2);
  const posa_proto_t *p = posa_resolve(proto, (const uint8_t *)d, (int)len);
  if (!p) { lua_pushnil(L); return 1; }
  push_posa_map(L, p, (const uint8_t *)d, (int)len);
  return 1;
}

static int l_decode_all(lua_State *L)
{
  size_t len; const char *d = luaL_checklstring(L, 1, &len);
  const char *group = luaL_checkstring(L, 2);
  int i, idx = 1;
  lua_newtable(L);
  for (i = 0; i < posa_count(); i++) {
    const posa_proto_t *p = posa_at(i);
    if (strcmp(p->parent, group) != 0) continue;
    lua_newtable(L);
    lua_pushstring(L, p->name); lua_setfield(L, -2, "proto");
    push_posa_map(L, p, (const uint8_t *)d, (int)len);
    lua_setfield(L, -2, "fields");
    lua_rawseti(L, -2, idx++);
  }
  return 1;
}

static int l_dissect(lua_State *L)
{
  size_t len; const char *d = luaL_checklstring(L, 1, &len);
  int lt = (int)luaL_optnumber(L, 2, LINKTYPE_ETHERNET);
  cpkt_t tmp; cfield_t *root;
  memset(&tmp, 0, sizeof tmp);
  tmp.data = (uint8_t *)d; tmp.caplen = (uint32_t)len; tmp.origlen = (uint32_t)len;
  tmp.linktype = (uint16_t)lt;
  root = dissect_packet(&tmp);
  if (!root) { lua_pushnil(L); return 1; }
  push_pkt(L, &tmp, root, 0, 0, NULL);
  cfield_free(root);
  return 1;
}

static int l_protocols(lua_State *L)
{
  int i;
  lua_newtable(L);
  for (i = 0; i < posa_count(); i++) {
    lua_pushstring(L, posa_at(i)->name);
    lua_rawseti(L, -2, i + 1);
  }
  return 1;
}

static int l_hex(lua_State *L)
{
  static const char hd[] = "0123456789abcdef";
  size_t len, i; const char *d = luaL_checklstring(L, 1, &len);
  luaL_Buffer b;
  luaL_buffinit(L, &b);
  for (i = 0; i < len; i++) {
    luaL_addchar(&b, hd[(d[i] >> 4) & 0xf]);
    luaL_addchar(&b, hd[d[i] & 0xf]);
  }
  luaL_pushresult(&b);
  return 1;
}

static int l_matches(lua_State *L)
{
  const char *expr = luaL_checkstring(L, 1);
  char err[160];
  cfilter_t *f;
  int ok = 0;
  if (!g_cur_root) { lua_pushboolean(L, 0); return 1; }
  f = filter_compile(expr, err, sizeof err);
  if (f) { ok = filter_eval(f, g_cur_root); filter_free(f); }
  lua_pushboolean(L, ok);
  return 1;
}

/* Lua-side metatables / convenience methods. */
static const char PRELUDE[] =
  "local C = caracal\n"
  "C._pktmt = { __index = {\n"
  "  has = function(self,name)\n"
  "    if self.fields[name] ~= nil then return true end\n"
  "    for _,l in ipairs(self.layers) do if l==name then return true end end\n"
  "    return false\n"
  "  end,\n"
  "  get = function(self,name)\n"
  "    local function walk(t) for _,n in ipairs(t) do\n"
  "      if n.abbrev==name then return n end\n"
  "      local r=walk(n.children); if r then return r end end end\n"
  "    return walk(self.tree)\n"
  "  end,\n"
  "  getall = function(self,name)\n"
  "    local out={}; local function walk(t) for _,n in ipairs(t) do\n"
  "      if n.abbrev==name then out[#out+1]=n end; walk(n.children) end end\n"
  "    walk(self.tree); return out\n"
  "  end,\n"
  "  matches = function(self,expr) return C._matches(expr) end,\n"
  "} }\n"
  "C._streammt = { __index = {\n"
  "  decode_as = function(self,proto) return C.decode_as(self.data, proto) end,\n"
  "} }\n";

static int register_caracal(lua_State *L, char *err, size_t errlen)
{
  lua_newtable(L);
  lua_pushcfunction(L, l_decode_as);  lua_setfield(L, -2, "decode_as");
  lua_pushcfunction(L, l_decode_all); lua_setfield(L, -2, "decode_all");
  lua_pushcfunction(L, l_dissect);    lua_setfield(L, -2, "dissect");
  lua_pushcfunction(L, l_protocols);  lua_setfield(L, -2, "protocols");
  lua_pushcfunction(L, l_hex);        lua_setfield(L, -2, "hex");
  lua_pushcfunction(L, l_matches);    lua_setfield(L, -2, "_matches");
  lua_setglobal(L, "caracal");
  if (luaL_dostring(L, PRELUDE) != 0) {
    snprintf(err, errlen, "prelude: %s", lua_tostring(L, -1));
    return -1;
  }
  return 0;
}

/* ── stream callback ────────────────────────────────────────────────────── */
typedef struct { lua_State *L; int have_stream; long nstreams; } luactx_t;

static void ip_str(uint32_t ip, char *buf, size_t n)
{ snprintf(buf, n, "%u.%u.%u.%u", (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff); }

static void stream_cb(void *ud, uint32_t sip, uint16_t sport, uint32_t dip,
                      uint16_t dport, int dir, const uint8_t *data, size_t len,
                      const uint8_t *all, size_t alllen)
{
  luactx_t *c = ud;
  lua_State *L = c->L;
  char s[16], d[16];
  int tab;

  if (!c->have_stream) return;
  lua_getglobal(L, "stream");
  lua_newtable(L);
  tab = lua_gettop(L);
  ip_str(sip, s, sizeof s); ip_str(dip, d, sizeof d);
  lua_pushstring(L, s);          lua_setfield(L, tab, "src");
  lua_pushstring(L, d);          lua_setfield(L, tab, "dst");
  lua_pushnumber(L, sport);      lua_setfield(L, tab, "srcport");
  lua_pushnumber(L, dport);      lua_setfield(L, tab, "dstport");
  lua_pushnumber(L, dir);        lua_setfield(L, tab, "dir");
  lua_pushnumber(L, (double)(alllen - len)); lua_setfield(L, tab, "offset");
  lua_pushlstring(L, (const char *)data, len); lua_setfield(L, tab, "data");
  lua_pushlstring(L, (const char *)all, alllen); lua_setfield(L, tab, "all");
  set_metatable(L, tab, "_streammt");
  c->nstreams++;
  if (lua_pcall(L, 1, 0, 0) != 0) {
    fprintf(stderr, "caracal: stream() error: %s\n", lua_tostring(L, -1));
    lua_pop(L, 1);
  }
}

/* ── driver ─────────────────────────────────────────────────────────────── */
static int has_global_fn(lua_State *L, const char *name)
{
  int r;
  lua_getglobal(L, name);
  r = lua_isfunction(L, -1);
  lua_pop(L, 1);
  return r;
}

int caracal_lua_run(const char *script_path, capture_t *cap, cfilter_t *flt,
                    char *errbuf, size_t errlen)
{
  lua_State *L;
  libpcapng_reasm_t *ipctx;
  pcapng_tcp_reasm_t *tctx;
  luactx_t lc;
  long i, matched = 0;
  int have_packet, have_stream;

  L = luaL_newstate();
  if (!L) { snprintf(errbuf, errlen, "cannot create Lua state"); return -1; }
  luaL_openlibs(L);
  if (register_caracal(L, errbuf, errlen) != 0) { lua_close(L); return -1; }

  if (luaL_dofile(L, script_path) != 0) {
    snprintf(errbuf, errlen, "%s", lua_tostring(L, -1));
    lua_close(L);
    return -1;
  }

  have_packet = has_global_fn(L, "packet");
  have_stream = has_global_fn(L, "stream");

  if (has_global_fn(L, "init")) {
    lua_getglobal(L, "init");
    if (lua_pcall(L, 0, 0, 0) != 0) {
      snprintf(errbuf, errlen, "init(): %s", lua_tostring(L, -1));
      lua_close(L);
      return -1;
    }
  }

  ipctx = libpcapng_reasm_new();
  tctx  = pcapng_tcp_reasm_new();
  lc.L = L; lc.have_stream = have_stream; lc.nstreams = 0;

  for (i = 0; i < cap->count; i++) {
    cpkt_t *p = &cap->pkts[i];
    cpkt_t eff = *p;
    uint8_t *defrag = NULL;
    cfield_t *root;
    l4_t l4;

    /* IP-fragment reassembly via libpcapng (Ethernet / IPv4 inputs). */
    if (ipctx && (p->linktype == LINKTYPE_ETHERNET || p->linktype == LINKTYPE_RAW ||
                  p->linktype == LINKTYPE_IPV4)) {
      uint8_t *out = NULL; size_t outlen = 0;
      int rc = libpcapng_reasm_add(ipctx, p->data, p->caplen, &out, &outlen);
      if (rc == 1) { defrag = out; eff.data = out; eff.caplen = (uint32_t)outlen;
                     eff.origlen = (uint32_t)outlen; eff.linktype = LINKTYPE_RAW; }
      else if (rc == 0) { continue; }   /* fragment buffered — wait for the rest */
      /* rc == -1: not a fragment — use the packet as-is */
    }
    eff.summarized = 0;
    root = dissect_packet(&eff);
    if (!root) { free(defrag); continue; }

    if (have_packet && (!flt || filter_eval(flt, root))) {
      g_cur_root = root;
      lua_getglobal(L, "packet");
      push_pkt(L, &eff, root, i + 1, 1, cap);
      if (lua_pcall(L, 1, 0, 0) != 0) {
        fprintf(stderr, "caracal: packet() error: %s\n", lua_tostring(L, -1));
        lua_pop(L, 1);
      }
      g_cur_root = NULL;
      matched++;
    }

    if (have_stream && tctx) {
      l4 = get_l4(eff.data, (int)eff.caplen, eff.linktype);
      if (l4.ok && l4.proto == 6)
        pcapng_tcp_reasm_add(tctx, l4.sip, l4.dip, l4.sport, l4.dport, l4.seq,
                             l4.flags, l4.plen > 0 ? eff.data + l4.poff : NULL,
                             (size_t)(l4.plen > 0 ? l4.plen : 0), stream_cb, &lc);
    }

    cfield_free(root);
    free(defrag);
  }

  if (has_global_fn(L, "finish")) {
    lua_getglobal(L, "finish");
    lua_newtable(L);
    lua_pushnumber(L, (double)cap->count);   lua_setfield(L, -2, "packets");
    lua_pushnumber(L, (double)matched);       lua_setfield(L, -2, "matched");
    lua_pushnumber(L, (double)lc.nstreams);   lua_setfield(L, -2, "streams");
    if (lua_pcall(L, 1, 0, 0) != 0) {
      fprintf(stderr, "caracal: finish() error: %s\n", lua_tostring(L, -1));
      lua_pop(L, 1);
    }
  }

  pcapng_tcp_reasm_free(tctx);
  libpcapng_reasm_free(ipctx);
  lua_close(L);
  return 0;
}
