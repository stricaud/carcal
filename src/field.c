/* field.c — cfield tree construction and traversal helpers. */
#include "carcal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

cfield_t *cfield_new(const char *abbrev, cval_type_t vtype)
{
  cfield_t *f = calloc(1, sizeof *f);
  if (!f) return NULL;
  if (abbrev) snprintf(f->abbrev, sizeof f->abbrev, "%s", abbrev);
  f->vtype = vtype;
  return f;
}

cfield_t *cfield_add(cfield_t *parent, const char *abbrev, cval_type_t vtype)
{
  cfield_t *f = cfield_new(abbrev, vtype);
  if (!f) return NULL;
  f->parent = parent;
  if (parent) {
    if (parent->last_child) parent->last_child->next = f;
    else                    parent->children = f;
    parent->last_child = f;
  }
  return f;
}

void cfield_free(cfield_t *root)
{
  cfield_t *c, *n;
  if (!root) return;
  for (c = root->children; c; c = n) { n = c->next; cfield_free(c); }
  free(root);
}

void cfield_set_label(cfield_t *f, const char *fmt, ...)
{
  va_list ap;
  if (!f) return;
  va_start(ap, fmt);
  vsnprintf(f->label, sizeof f->label, fmt, ap);
  va_end(ap);
}

void cfield_set_uint(cfield_t *f, uint64_t v)
{
  if (!f) return;
  f->vtype = CV_UINT;
  f->u = v;
}

void cfield_set_str(cfield_t *f, const char *s)
{
  if (!f) return;
  f->vtype = CV_STR;
  snprintf(f->str, sizeof f->str, "%s", s ? s : "");
}

void cfield_set_ipv4(cfield_t *f, const uint8_t ip[4])
{
  if (!f) return;
  f->vtype = CV_IPV4;
  memcpy(f->bytes, ip, 4);
  f->blen = 4;
  snprintf(f->str, sizeof f->str, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void cfield_set_ipv6(cfield_t *f, const uint8_t ip[16])
{
  static const char hexd[] = "0123456789abcdef";
  char *p = f->str;
  int i;
  if (!f) return;
  f->vtype = CV_IPV6;
  memcpy(f->bytes, ip, 16);
  f->blen = 16;
  /* Plain (non-compressed) presentation — good enough for display/compare. */
  for (i = 0; i < 16; i += 2) {
    if (i) *p++ = ':';
    *p++ = hexd[(ip[i] >> 4) & 0xf];
    *p++ = hexd[ip[i] & 0xf];
    *p++ = hexd[(ip[i+1] >> 4) & 0xf];
    *p++ = hexd[ip[i+1] & 0xf];
  }
  *p = '\0';
}

void cfield_set_mac(cfield_t *f, const uint8_t mac[6])
{
  if (!f) return;
  f->vtype = CV_MAC;
  memcpy(f->bytes, mac, 6);
  f->blen = 6;
  snprintf(f->str, sizeof f->str, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void cfield_set_bytes(cfield_t *f, const uint8_t *b, int n)
{
  if (!f) return;
  f->vtype = CV_BYTES;
  if (n > CFIELD_BYTES_MAX) n = CFIELD_BYTES_MAX;
  if (n < 0) n = 0;
  memcpy(f->bytes, b, (size_t)n);
  f->blen = n;
}

int cfield_count(cfield_t *parent)
{
  int n = 0;
  cfield_t *c;
  if (!parent) return 0;
  for (c = parent->children; c; c = c->next) n++;
  return n;
}

cfield_t *cfield_child_at(cfield_t *parent, int index)
{
  cfield_t *c;
  if (!parent || index < 0) return NULL;
  for (c = parent->children; c; c = c->next)
    if (index-- == 0) return c;
  return NULL;
}

static void collect_rec(cfield_t *node, const char *abbrev, cfield_t **out, int max, int *n)
{
  cfield_t *c;
  if (!node) return;
  if (node->abbrev[0] && strcmp(node->abbrev, abbrev) == 0 && *n < max)
    out[(*n)++] = node;
  for (c = node->children; c; c = c->next)
    collect_rec(c, abbrev, out, max, n);
}

int cfield_collect(cfield_t *root, const char *abbrev, cfield_t **out, int max)
{
  int n = 0;
  collect_rec(root, abbrev, out, max, &n);
  return n;
}

/* Render a field as a display-filter expression, e.g. "ip.src == 10.0.0.1".
 *
 * This is the primitive behind Apply as Filter, Prepare as Filter, Apply as
 * Column and the coloring rules: everything that needs "the filter for the thing
 * the cursor is on" goes through here. Returns 0 on success, -1 if the field
 * cannot be expressed (a structural row with no abbrev, or an opaque value).
 *
 * The literal forms produced must round-trip through filter_compile(), so they
 * mirror what filter.c's value parser accepts for each cval_type_t. */
int cfield_filter_expr(const cfield_t *f, char *out, size_t n)
{
  if (!f || !out || n == 0) return -1;
  out[0] = '\0';
  if (!f->abbrev[0]) return -1;          /* structural node — not filterable */

  switch (f->vtype) {
  case CV_UINT:
    snprintf(out, n, "%s == %llu", f->abbrev, (unsigned long long)f->u);
    return 0;
  case CV_IPV4:
  case CV_STR:
    if (!f->str[0]) return -1;
    /* Strings are quoted; an embedded quote would break the expression, and we
       have no escape syntax, so refuse rather than emit something unparseable. */
    if (f->vtype == CV_STR) {
      if (strchr(f->str, '"')) return -1;
      snprintf(out, n, "%s == \"%s\"", f->abbrev, f->str);
    } else {
      snprintf(out, n, "%s == %s", f->abbrev, f->str);
    }
    return 0;
  case CV_MAC:
    if (f->blen < 6) return -1;
    snprintf(out, n, "%s == %02x:%02x:%02x:%02x:%02x:%02x", f->abbrev,
             f->bytes[0], f->bytes[1], f->bytes[2],
             f->bytes[3], f->bytes[4], f->bytes[5]);
    return 0;
  case CV_IPV6:
    /* filter.c compares IPv6 as text, and .str already holds the printable
       form the dissector produced. */
    if (!f->str[0]) return -1;
    snprintf(out, n, "%s == %s", f->abbrev, f->str);
    return 0;
  case CV_BYTES:
  case CV_NONE:
  default:
    /* No literal syntax for opaque bytes — offer the presence test instead,
       which is what Wireshark falls back to as well. */
    snprintf(out, n, "%s", f->abbrev);
    return 0;
  }
}

/* Find the first field with this abbrev anywhere in the tree (used by custom
   columns: "show me http.host for every packet"). NULL if absent. */
cfield_t *cfield_find(cfield_t *root, const char *abbrev)
{
  cfield_t *c, *hit;
  if (!root || !abbrev || !*abbrev) return NULL;
  if (root->abbrev[0] && !strcmp(root->abbrev, abbrev)) return root;
  for (c = root->children; c; c = c->next)
    if ((hit = cfield_find(c, abbrev)) != NULL) return hit;
  return NULL;
}

/* Printable value of a field, for a packet-list column cell. */
void cfield_value_str(const cfield_t *f, char *out, size_t n)
{
  if (!f || !out || n == 0) { if (out && n) out[0] = '\0'; return; }
  switch (f->vtype) {
  case CV_UINT: snprintf(out, n, "%llu", (unsigned long long)f->u); break;
  case CV_STR:
  case CV_IPV4:
  case CV_IPV6: snprintf(out, n, "%s", f->str); break;
  case CV_MAC:
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x",
             f->bytes[0], f->bytes[1], f->bytes[2],
             f->bytes[3], f->bytes[4], f->bytes[5]);
    break;
  default: snprintf(out, n, "%s", f->label[0] ? f->label : ""); break;
  }
}
