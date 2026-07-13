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
