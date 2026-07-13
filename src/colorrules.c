/* colorrules.c — Wireshark-style coloring rules for the packet list.
 *
 * An ordered list of "<display filter> => <fg> <bg>". The first rule whose
 * filter matches a packet paints it; later rules are not consulted. That
 * first-match-wins order is the whole point — it's why "bad TCP" sits above
 * "TCP" in Wireshark's default set.
 *
 * Rules live in <protos dir>/colorfilters, one per line:
 *
 *     # comment
 *     tcp.flags.reset == 1    red    black
 *     dns                     white  blue
 *
 * Colors are libcaca ANSI names (see COLORS below). If the file is absent the
 * compiled-in defaults are used, so a fresh install still gets a colored list.
 */
#include "carcal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <caca.h>

#define MAX_COLOR_RULES 64

typedef struct {
  char      expr[192];
  cfilter_t *cond;         /* compiled expr; NULL => rule disabled */
  uint8_t   fg, bg;
  int       enabled;
} crule_t;

static crule_t g_rules[MAX_COLOR_RULES];
static int     g_nrules;
static int     g_enabled = 1;     /* master switch (View ▸ Colorize) */

static const struct { const char *name; uint8_t v; } COLORS[] = {
  { "black",       CACA_BLACK },      { "blue",        CACA_BLUE },
  { "green",       CACA_GREEN },      { "cyan",        CACA_CYAN },
  { "red",         CACA_RED },        { "magenta",     CACA_MAGENTA },
  { "brown",       CACA_BROWN },      { "lightgray",   CACA_LIGHTGRAY },
  { "darkgray",    CACA_DARKGRAY },   { "lightblue",   CACA_LIGHTBLUE },
  { "lightgreen",  CACA_LIGHTGREEN }, { "lightcyan",   CACA_LIGHTCYAN },
  { "lightred",    CACA_LIGHTRED },   { "lightmagenta",CACA_LIGHTMAGENTA },
  { "yellow",      CACA_YELLOW },     { "white",       CACA_WHITE },
  { "default",     CACA_DEFAULT },
};

static int color_by_name(const char *s, uint8_t *out)
{
  size_t i;
  for (i = 0; i < sizeof COLORS / sizeof COLORS[0]; i++)
    if (!strcasecmp(s, COLORS[i].name)) { *out = COLORS[i].v; return 0; }
  return -1;
}

const char *colorrules_color_name(uint8_t v)
{
  size_t i;
  for (i = 0; i < sizeof COLORS / sizeof COLORS[0]; i++)
    if (COLORS[i].v == v) return COLORS[i].name;
  return "default";
}

int  colorrules_count(void)   { return g_nrules; }
int  colorrules_enabled(void) { return g_enabled; }
void colorrules_set_enabled(int on) { g_enabled = on ? 1 : 0; }

int colorrules_get(int i, char *expr, size_t elen, uint8_t *fg, uint8_t *bg, int *enabled)
{
  if (i < 0 || i >= g_nrules) return -1;
  if (expr)    snprintf(expr, elen, "%s", g_rules[i].expr);
  if (fg)      *fg = g_rules[i].fg;
  if (bg)      *bg = g_rules[i].bg;
  if (enabled) *enabled = g_rules[i].enabled;
  return 0;
}

void colorrules_clear(void)
{
  int i;
  for (i = 0; i < g_nrules; i++) {
    if (g_rules[i].cond) filter_free(g_rules[i].cond);
    g_rules[i].cond = NULL;
  }
  g_nrules = 0;
}

/* Append a rule. A rule whose filter doesn't compile is kept but disabled, so a
   typo in the file costs you that one rule instead of silently dropping it. */
int colorrules_add(const char *expr, uint8_t fg, uint8_t bg)
{
  crule_t *r;
  char err[160] = "";
  if (!expr || !*expr || g_nrules >= MAX_COLOR_RULES) return -1;
  r = &g_rules[g_nrules];
  memset(r, 0, sizeof *r);
  snprintf(r->expr, sizeof r->expr, "%s", expr);
  r->fg = fg;
  r->bg = bg;
  r->cond = filter_compile(expr, err, sizeof err);
  r->enabled = r->cond ? 1 : 0;
  g_nrules++;
  return r->cond ? 0 : -1;
}

/* Compiled-in defaults, mirroring the spirit of Wireshark's default set: the
   alarming things first (resets), then chatty protocols, then the generic
   transports. Appended last, so anything more specific already won. */
void colorrules_add_defaults(void)
{
  colorrules_add("tcp.flags.reset == 1", CACA_YELLOW,     CACA_RED);
  colorrules_add("icmp",                 CACA_BLACK,      CACA_LIGHTMAGENTA);
  colorrules_add("arp",                  CACA_BLACK,      CACA_YELLOW);
  colorrules_add("dns",                  CACA_WHITE,      CACA_BLUE);
  colorrules_add("http",                 CACA_BLACK,      CACA_LIGHTGREEN);
  colorrules_add("tcp.flags.syn == 1",   CACA_BLACK,      CACA_LIGHTCYAN);
  colorrules_add("tcp",                  CACA_LIGHTGRAY,  CACA_DEFAULT);
  colorrules_add("udp",                  CACA_LIGHTBLUE,  CACA_DEFAULT);
}

/* Import the `color <filter> => <fg> <bg>` lines declared by the loaded .posa
   files. This is how a protocol ships its own coloring next to its decoder —
   drop in a .posa and its packets are colored, with no rebuild and nothing to
   add here. An unknown color name is skipped rather than failing the load. */
int colorrules_add_from_posa(void)
{
  int i, n = 0, total = pcapng_posa_color_count();
  for (i = 0; i < total; i++) {
    const char *expr = NULL, *fgs = NULL, *bgs = NULL;
    uint8_t fg, bg;
    if (pcapng_posa_color_get(i, &expr, &fgs, &bgs) != 0) continue;
    if (!expr || !fgs || !bgs) continue;
    if (color_by_name(fgs, &fg) != 0 || color_by_name(bgs, &bg) != 0) continue;
    if (colorrules_add(expr, fg, bg) == 0) n++;
  }
  return n;
}

/* Load <path>, appending to whatever is already there. Returns the number of
   rules read, or -1 if the file is absent. */
int colorrules_load_file(const char *path)
{
  FILE *fp = fopen(path, "r");
  char line[320];
  int n = 0;

  if (!fp) return -1;
  while (fgets(line, sizeof line, fp)) {
    char expr[192], fgs[32], bgs[32];
    uint8_t fg, bg;
    char *p = line, *end;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p || *p == '#') continue;

    /* "<expr> <fg> <bg>" — the expression may contain spaces, so take the last
       two whitespace-separated tokens as the colors and everything before as
       the filter. */
    end = p + strlen(p);
    while (end > p && isspace((unsigned char)end[-1])) *--end = '\0';
    {
      char *b = strrchr(p, ' ');
      char *f;
      if (!b) continue;
      *b = '\0';
      snprintf(bgs, sizeof bgs, "%s", b + 1);
      f = strrchr(p, ' ');
      if (!f) continue;
      *f = '\0';
      snprintf(fgs, sizeof fgs, "%s", f + 1);
      /* trim trailing space left on the expression */
      end = p + strlen(p);
      while (end > p && isspace((unsigned char)end[-1])) *--end = '\0';
      snprintf(expr, sizeof expr, "%s", p);
    }
    if (!expr[0]) continue;
    if (color_by_name(fgs, &fg) != 0 || color_by_name(bgs, &bg) != 0) continue;
    colorrules_add(expr, fg, bg);
    n++;
  }
  fclose(fp);
  return n;
}

/* Compose the full rule set, in first-match-wins order:
 *
 *   1. the user's colorfilters file  — so the user can override anything
 *   2. `color` lines from the loaded .posa decoders — a protocol's own color,
 *      which must beat the generic "tcp"/"udp" rules below it
 *   3. the compiled-in defaults      — the generic fallback
 *
 * Call after the posa decoders are loaded (they supply layer 2).
 */
void colorrules_reload(const char *user_file)
{
  colorrules_clear();
  if (user_file && *user_file) colorrules_load_file(user_file);   /* -1 if absent */
  colorrules_add_from_posa();
  colorrules_add_defaults();
}

int colorrules_save_file(const char *path)
{
  FILE *fp = fopen(path, "w");
  int i;
  if (!fp) return -1;
  fprintf(fp, "# carcal coloring rules — first match wins.\n"
              "#   <display filter>  <foreground>  <background>\n"
              "# Colors: black blue green cyan red magenta brown lightgray\n"
              "#         darkgray lightblue lightgreen lightcyan lightred\n"
              "#         lightmagenta yellow white default\n");
  for (i = 0; i < g_nrules; i++)
    fprintf(fp, "%s %s %s\n", g_rules[i].expr,
            colorrules_color_name(g_rules[i].fg),
            colorrules_color_name(g_rules[i].bg));
  fclose(fp);
  return 0;
}

/* First matching rule wins. Returns 1 and fills fg/bg, or 0 for no match. */
int colorrules_match(cfield_t *root, uint8_t *fg, uint8_t *bg)
{
  int i;
  if (!g_enabled || !root) return 0;
  for (i = 0; i < g_nrules; i++) {
    if (!g_rules[i].enabled || !g_rules[i].cond) continue;
    if (filter_eval(g_rules[i].cond, root)) {
      if (fg) *fg = g_rules[i].fg;
      if (bg) *bg = g_rules[i].bg;
      return 1;
    }
  }
  return 0;
}
