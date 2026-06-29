/*
 * caracal — a terminal packet analyzer (a tiny Wireshark for the TUI).
 *
 *   caracal [capture.pcap|.pcapng]
 *
 * Layout:  [menu bar] / [display-filter entry] / [packet table] /
 *          [packet-detail tree] / [status bar]
 *
 * Built on gtcaca's lazy Table and Tree widgets and libpcapng for reading
 * pcapng. Custom protocols are added at runtime by loading .posa definitions
 * (File ▸ Load .posa) and binding them to ports (Analyze ▸ Decode As…).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <caca.h>

#include <gtcaca/main.h>
#include <gtcaca/application.h>
#include <gtcaca/window.h>
#include <gtcaca/menu.h>
#include <gtcaca/table.h>
#include <gtcaca/tree.h>
#include <gtcaca/entry.h>
#include <gtcaca/label.h>
#include <gtcaca/statusbar.h>
#include <gtcaca/dialog.h>
#include <gtcaca/filechooser.h>

#include "caracal.h"

#ifndef CARACAL_PROTOS_DIR
#define CARACAL_PROTOS_DIR "protos"
#endif

#define CTRL(c) ((c) & 0x1f)

enum { FOCUS_FILTER = 0, FOCUS_TABLE, FOCUS_TREE };

typedef struct {
  capture_t cap;

  long     *view;        /* indices into cap.pkts that pass the filter        */
  long      nview;
  long      view_cap;
  cfilter_t *filter;
  char      filter_text[256];

  cfield_t *detail_root; /* dissection of the currently selected packet       */
  long      detail_for;  /* view row the detail belongs to (-1 = none)        */

  int       focus;

  /* widgets */
  gtcaca_menu_widget_t      *menu;
  gtcaca_entry_widget_t     *fentry;
  gtcaca_table_widget_t     *table;
  gtcaca_tree_widget_t      *tree;
  gtcaca_statusbar_widget_t *bar;

  /* layout (for mouse hit-testing) */
  int table_y, table_h, tree_y, tree_h;
} app_t;

static app_t app;

/* ───────────────────────── view (filtered index list) ─────────────────── */
static void view_push(long idx)
{
  if (app.nview == app.view_cap) {
    long nc = app.view_cap ? app.view_cap * 2 : 1024;
    long *nv = realloc(app.view, (size_t)nc * sizeof *nv);
    if (!nv) return;
    app.view = nv;
    app.view_cap = nc;
  }
  app.view[app.nview++] = idx;
}

static long view_pkt_index(long row)   /* table row → cap.pkts index */
{
  if (row < 0 || row >= app.nview) return -1;
  return app.view[row];
}

static void view_rebuild(void)
{
  long i;
  app.nview = 0;
  for (i = 0; i < app.cap.count; i++) {
    cfield_t *root;
    int pass;
    if (app.filter == NULL) { view_push(i); continue; }
    root = dissect_packet(&app.cap.pkts[i]);
    pass = filter_eval(app.filter, root);
    cfield_free(root);
    if (pass) view_push(i);
  }
}

static void invalidate_summaries(void)
{
  long i;
  for (i = 0; i < app.cap.count; i++) app.cap.pkts[i].summarized = 0;
}

/* ───────────────────────── detail tree (re)build ──────────────────────── */
static void detail_clear(void)
{
  if (app.detail_root) { cfield_free(app.detail_root); app.detail_root = NULL; }
  app.detail_for = -1;
}

static gtcaca_tree_model_t tree_model;   /* defined below */

static void detail_rebuild(long row)
{
  long pidx = view_pkt_index(row);
  detail_clear();
  if (pidx >= 0)
    app.detail_root = dissect_packet(&app.cap.pkts[pidx]);
  app.detail_for = row;
  /* Re-set the model so the tree's expand-state is rebuilt against the new
     node pointers (set_model frees the old open-state). */
  if (app.tree) gtcaca_tree_set_model(app.tree, &tree_model);
}

/* ───────────────────────── table model ────────────────────────────────── */
static long tm_rows(gtcaca_table_model_t *m) { (void)m; return app.nview; }
static int  tm_cols(gtcaca_table_model_t *m) { (void)m; return 7; }

static void tm_header(gtcaca_table_model_t *m, int col, char *b, int l)
{
  static const char *h[] = { "No.", "Time", "Source", "Destination",
                             "Protocol", "Length", "Info" };
  (void)m;
  snprintf(b, l, "%s", (col >= 0 && col < 7) ? h[col] : "");
}

static void tm_cell(gtcaca_table_model_t *m, long row, int col, char *b, int l)
{
  long pidx = view_pkt_index(row);
  cpkt_t *p;
  (void)m;
  if (pidx < 0) { b[0] = '\0'; return; }
  p = &app.cap.pkts[pidx];
  dissect_summarize(p);
  switch (col) {
  case 0: snprintf(b, l, "%ld", pidx + 1); break;
  case 1: {
    double t = (double)((p->ts_us >= app.cap.first_ts_us)
                          ? p->ts_us - app.cap.first_ts_us : 0) / 1e6;
    snprintf(b, l, "%.6f", t);
    break;
  }
  case 2: snprintf(b, l, "%s", p->col_src); break;
  case 3: snprintf(b, l, "%s", p->col_dst); break;
  case 4: snprintf(b, l, "%s", p->col_proto); break;
  case 5: snprintf(b, l, "%u", p->origlen); break;
  case 6: snprintf(b, l, "%s", p->col_info); break;
  default: b[0] = '\0';
  }
}

static gtcaca_table_model_t table_model = { tm_rows, tm_cols, tm_header, tm_cell, NULL };

/* ───────────────────────── tree model ─────────────────────────────────── */
/* Nodes are cfield_t*. The super-root (NULL) maps to detail_root's children. */
static cfield_t *tree_parent(void *node) { return node ? (cfield_t *)node : app.detail_root; }

static long tn_child_count(gtcaca_tree_model_t *m, void *node)
{ (void)m; return cfield_count(tree_parent(node)); }

static void *tn_child(gtcaca_tree_model_t *m, void *node, long i)
{ (void)m; return cfield_child_at(tree_parent(node), (int)i); }

static void tn_label(gtcaca_tree_model_t *m, void *node, char *b, int l)
{
  cfield_t *f = (cfield_t *)node;
  (void)m;
  if (!f) { b[0] = '\0'; return; }
  if (f->label[0]) snprintf(b, l, "%s", f->label);
  else             snprintf(b, l, "%s", f->abbrev);
}

static int tn_has_children(gtcaca_tree_model_t *m, void *node)
{ (void)m; return cfield_count((cfield_t *)node) > 0; }

static gtcaca_tree_model_t tree_model = {
  tn_child_count, tn_child, tn_label, tn_has_children, NULL
};

/* ───────────────────────── status line ────────────────────────────────── */
static void refresh_status(void)
{
  char s[320];
  const char *focusname = app.focus == FOCUS_FILTER ? "filter"
                        : app.focus == FOCUS_TABLE  ? "table" : "tree";
  if (app.cap.count == 0) {
    snprintf(s, sizeof s, " No capture  |  F2 Open  F10 Menu  Tab switch  ^Q quit");
  } else {
    long sel = app.table ? gtcaca_table_selected_row(app.table) : 0;
    snprintf(s, sizeof s,
      " %s  |  %ld/%ld pkts shown  |  sel %ld  |  [%s]  |  / filter  F2 open  F10 menu  ^Q quit",
      app.cap.path[0] ? app.cap.path : "(none)",
      app.nview, app.cap.count, app.nview ? sel + 1 : 0, focusname);
  }
  gtcaca_statusbar_set_text(app.bar, s);
}

/* ───────────────────────── filter handling ────────────────────────────── */
static void apply_filter(const char *expr)
{
  char err[160] = "";
  cfilter_t *nf = filter_compile(expr, err, sizeof err);
  if (!nf) {
    gtcaca_dialog_message("Filter error", err[0] ? err : "invalid display filter");
    return;
  }
  if (app.filter) filter_free(app.filter);
  app.filter = nf;
  snprintf(app.filter_text, sizeof app.filter_text, "%s", expr ? expr : "");
  view_rebuild();
  if (app.table) gtcaca_table_set_current(app.table, 0, 0);
  detail_rebuild(0);
}

/* ───────────────────────── capture loading ────────────────────────────── */
static void load_capture(const char *path)
{
  capture_t nc;
  char err[256] = "";
  if (capture_load(path, &nc, err, sizeof err) != 0) {
    gtcaca_dialog_message("Open failed", err[0] ? err : "could not read file");
    return;
  }
  capture_free(&app.cap);
  app.cap = nc;
  view_rebuild();
  if (app.table) {
    gtcaca_table_set_title(app.table, app.cap.path);
    gtcaca_table_set_current(app.table, 0, 0);
  }
  detail_rebuild(0);
}

/* ───────────────────────── one-line modal prompt ──────────────────────── */
static int prompt_line(const char *label, char *out, int outlen)
{
  int W = caca_get_canvas_width(gmo.cv), H = caca_get_canvas_height(gmo.cv);
  int len = 0;
  caca_event_t ev;
  out[0] = '\0';
  for (;;) {
    int x;
    caca_set_color_ansi(gmo.cv, CACA_BLACK, CACA_WHITE);
    for (x = 0; x < W; x++) caca_put_char(gmo.cv, x, H - 1, ' ');
    caca_printf(gmo.cv, 0, H - 1, "%s%s", label, out);
    caca_refresh_display(gmo.dp);
    if (!caca_get_event(gmo.dp, CACA_EVENT_KEY_PRESS, &ev, -1)) continue;
    {
      int k = caca_get_event_key_ch(&ev);
      if (k == CACA_KEY_RETURN || k == 10) return len > 0;
      if (k == CACA_KEY_ESCAPE) return 0;
      if ((k == CACA_KEY_BACKSPACE || k == CACA_KEY_DELETE) && len > 0) out[--len] = '\0';
      else if (k >= 32 && k < 127 && len < outlen - 1) { out[len++] = (char)k; out[len] = '\0'; }
    }
  }
}

/* ───────────────────────── menu actions ───────────────────────────────── */
static void act_open(void *u)
{
  char path[1024];
  (void)u;
  if (gtcaca_filechooser_run(app.cap.path[0] ? "." : ".", path, sizeof path, 0))
    load_capture(path);
}

static void act_reload(void *u)
{
  char path[1024];
  (void)u;
  if (!app.cap.path[0]) return;
  snprintf(path, sizeof path, "%s", app.cap.path);
  load_capture(path);
}

static void act_quit(void *u) { (void)u; gtcaca_main_quit(); }

static void act_load_posa(void *u)
{
  char path[1024], err[160] = "", msg[256];
  int rc;
  (void)u;
  if (!gtcaca_filechooser_run(".", path, sizeof path, 0)) return;
  rc = posa_load_file(path, err, sizeof err);
  if (rc < 0) {
    gtcaca_dialog_message("Load .posa failed", err[0] ? err : "parse error");
    return;
  }
  invalidate_summaries();
  view_rebuild();
  detail_rebuild(app.table ? gtcaca_table_selected_row(app.table) : 0);
  snprintf(msg, sizeof msg, "Loaded %d protocol(s). %d total available.",
           rc, posa_count());
  gtcaca_dialog_message("Protocols loaded", msg);
}

static void act_decode_as(void *u)
{
  char line[128], proto[64];
  char transport[16];
  unsigned port;
  (void)u;
  if (posa_count() == 0) {
    gtcaca_dialog_message("Decode As", "No custom protocols loaded.\nUse File \xe2\x96\xb8 Load .posa first.");
    return;
  }
  if (!prompt_line("Decode As (e.g. 'udp 69 TFTP'):  ", line, sizeof line)) return;
  if (sscanf(line, "%15s %u %63s", transport, &port, proto) != 3) {
    gtcaca_dialog_message("Decode As", "Expected: <udp|tcp> <port> <ProtocolName>");
    return;
  }
  if (!posa_find(proto)) {
    /* allow group names too; only warn if neither a proto nor a group */
    int i, isgroup = 0;
    for (i = 0; i < posa_count(); i++)
      if (strcmp(posa_at(i)->parent, proto) == 0) { isgroup = 1; break; }
    if (!isgroup) {
      gtcaca_dialog_message("Decode As", "Unknown protocol name.");
      return;
    }
  }
  if (!strcmp(transport, "udp"))      posa_bind_udp((uint16_t)port, proto);
  else if (!strcmp(transport, "tcp")) posa_bind_tcp((uint16_t)port, proto);
  else { gtcaca_dialog_message("Decode As", "Transport must be 'udp' or 'tcp'."); return; }

  invalidate_summaries();
  view_rebuild();
  detail_rebuild(app.table ? gtcaca_table_selected_row(app.table) : 0);
}

static void act_about(void *u)
{
  (void)u;
  gtcaca_dialog_message("About caracal",
    "caracal \xe2\x80\x94 a TUI packet analyzer\n"
    "Built on gtcaca + libpcapng.\n\n"
    "Keys: / filter, F2 open, F10 menu, Tab switch pane, ^Q quit.");
}

static void build_menu(void)
{
  int e;
  app.menu = gtcaca_menu_new();

  e = gtcaca_menu_add_entry(app.menu, "File");
  gtcaca_menu_add_item(app.menu, e, "Open\xe2\x80\xa6",     "F2",  act_open,      NULL);
  gtcaca_menu_add_item(app.menu, e, "Reload",               "",    act_reload,    NULL);
  gtcaca_menu_add_separator(app.menu, e);
  gtcaca_menu_add_item(app.menu, e, "Load .posa\xe2\x80\xa6", "",  act_load_posa, NULL);
  gtcaca_menu_add_separator(app.menu, e);
  gtcaca_menu_add_item(app.menu, e, "Quit",                 "^Q",  act_quit,      NULL);

  e = gtcaca_menu_add_entry(app.menu, "Analyze");
  gtcaca_menu_add_item(app.menu, e, "Decode As\xe2\x80\xa6", "",   act_decode_as, NULL);

  e = gtcaca_menu_add_entry(app.menu, "Help");
  gtcaca_menu_add_item(app.menu, e, "About",                "",    act_about,     NULL);
}

/* ───────────────────────── focus + redraw sync ────────────────────────── */
static void sync_focus(void)
{
  if (app.fentry) app.fentry->has_focus = (app.focus == FOCUS_FILTER);
  if (app.table)  app.table->has_focus  = (app.focus == FOCUS_TABLE);
  if (app.tree)   app.tree->has_focus   = (app.focus == FOCUS_TREE);
}

static void redraw(void)
{
  /* Track table selection: rebuild the detail tree when it moves. */
  if (app.table) {
    long sel = gtcaca_table_selected_row(app.table);
    if (sel != app.detail_for) detail_rebuild(sel);
  }
  sync_focus();
  refresh_status();
  gtcaca_redraw();
}

/* feed an editing key to the filter entry */
static void filter_entry_key(int key)
{
  if (app.fentry && app.fentry->private_key_cb)
    app.fentry->private_key_cb(app.fentry, key, NULL);
}

/* ───────────────────────── headless dump (tshark-like) ────────────────── */
static void dump_tree(cfield_t *n, int depth)
{
  cfield_t *c;
  for (c = n->children; c; c = c->next) {
    printf("%*s%s\n", depth * 2, "", c->label[0] ? c->label : c->abbrev);
    dump_tree(c, depth + 1);
  }
}

static int dump_mode(const char *path, const char *expr)
{
  capture_t cap;
  char err[256] = "";
  cfilter_t *flt = NULL;
  long i, shown = 0;
  int printed_detail = 0;

  posa_load_dir(CARACAL_PROTOS_DIR);
  /* Optional port binding for scripted testing, e.g. CARACAL_BIND="udp 69 TFTP" */
  {
    const char *b = getenv("CARACAL_BIND");
    char tr[16], pr[64]; unsigned pt;
    if (b && sscanf(b, "%15s %u %63s", tr, &pt, pr) == 3) {
      if (!strcmp(tr, "udp")) posa_bind_udp((uint16_t)pt, pr);
      else if (!strcmp(tr, "tcp")) posa_bind_tcp((uint16_t)pt, pr);
    }
  }
  if (capture_load(path, &cap, err, sizeof err) != 0) {
    fprintf(stderr, "caracal: %s\n", err);
    return 1;
  }
  if (expr && *expr) {
    flt = filter_compile(expr, err, sizeof err);
    if (!flt) { fprintf(stderr, "caracal: filter: %s\n", err); capture_free(&cap); return 1; }
  }
  printf("# %s — %ld packets, %d custom protocol(s) loaded\n",
         path, cap.count, posa_count());
  if (expr && *expr) printf("# filter: %s\n", expr);

  for (i = 0; i < cap.count; i++) {
    cpkt_t *p = &cap.pkts[i];
    cfield_t *root = dissect_packet(p);
    if (!flt || filter_eval(flt, root)) {
      double t = (double)((p->ts_us >= cap.first_ts_us) ? p->ts_us - cap.first_ts_us : 0) / 1e6;
      dissect_summarize(p);
      printf("%5ld  %.6f  %-15s %-15s %-8s %5u  %s\n",
             i + 1, t, p->col_src, p->col_dst, p->col_proto, p->origlen, p->col_info);
      shown++;
      if (!printed_detail) {
        printf("       └─ detail:\n");
        dump_tree(root, 4);
        printed_detail = 1;
      }
    }
    cfield_free(root);
  }
  printf("# %ld packet(s) matched\n", shown);
  if (flt) filter_free(flt);
  capture_free(&cap);
  return 0;
}

/* ───────────────────────── main ───────────────────────────────────────── */
int main(int argc, char **argv)
{
  gtcaca_application_widget_t *appw;
  gtcaca_window_widget_t *win;
  int W, H;
  int int_w;
  int widths[7];

  app.detail_for = -1;

  /* Headless mode for scripting/testing: caracal --dump <file> [filter] */
  if (argc >= 3 && strcmp(argv[1], "--dump") == 0)
    return dump_mode(argv[2], argc > 3 ? argv[3] : NULL);

  if (gtcaca_init(&argc, &argv) < 0) {
    fprintf(stderr, "caracal: cannot initialize display\n");
    return 1;
  }

  /* Load bundled protocol definitions (best effort). */
  posa_load_dir(CARACAL_PROTOS_DIR);

  W = caca_get_canvas_width(gmo.cv);
  H = caca_get_canvas_height(gmo.cv);

  appw = gtcaca_application_new("caracal");
  win  = gtcaca_window_new(GTCACA_WIDGET(appw), NULL, 0, 0, W, H);

  build_menu();

  gtcaca_label_new(GTCACA_WIDGET(win), "Filter:", 0, 1);
  app.fentry = gtcaca_entry_new(GTCACA_WIDGET(win), 8, 1, W - 9);

  app.table_y = 2;
  app.table_h = (H - 4) * 55 / 100;
  if (app.table_h < 4) app.table_h = 4;
  app.tree_y  = app.table_y + app.table_h;
  app.tree_h  = H - 1 - app.tree_y;
  if (app.tree_h < 3) app.tree_h = 3;

  app.table = gtcaca_table_new(GTCACA_WIDGET(win), 0, app.table_y, W, app.table_h);
  gtcaca_table_set_model(app.table, &table_model);
  gtcaca_table_set_title(app.table, "Packets");

  int_w = W - 2;
  widths[0] = 7;  widths[1] = 12; widths[2] = 18; widths[3] = 18;
  widths[4] = 9;  widths[5] = 7;
  widths[6] = int_w - (widths[0]+widths[1]+widths[2]+widths[3]+widths[4]+widths[5]);
  if (widths[6] < 6) widths[6] = 6;
  gtcaca_table_set_column_widths(app.table, widths, 7);

  app.tree = gtcaca_tree_new(GTCACA_WIDGET(win), 0, app.tree_y, W, app.tree_h);
  gtcaca_tree_set_model(app.tree, &tree_model);
  gtcaca_tree_set_title(app.tree, "Packet details");

  app.bar = gtcaca_statusbar_new("");

  /* Open a file passed on the command line. */
  if (argc > 1) load_capture(argv[1]);
  else { app.filter = filter_compile("", NULL, 0); }

  app.focus = FOCUS_TABLE;

  /* ── event loop ──────────────────────────────────────────────────────── */
  caca_set_mouse(gmo.dp, 1);
  redraw();
  while (1) {
    caca_event_t ev;
    int t, key;

    if (!caca_get_event(gmo.dp, CACA_EVENT_ANY, &ev, -1)) continue;
    t = caca_get_event_type(&ev);

    if (t & CACA_EVENT_RESIZE) { redraw(); continue; }

    if (t & CACA_EVENT_MOUSE_PRESS) {
      int b  = caca_get_event_mouse_button(&ev);
      int my = caca_get_mouse_y(gmo.dp);
      if (b == 4 || b == 5) {                       /* wheel → scroll focused */
        int k = (b == 4) ? CACA_KEY_DOWN : CACA_KEY_UP;
        if (app.focus == FOCUS_TREE) gtcaca_tree_key(app.tree, k, NULL);
        else                         gtcaca_table_key(app.table, k, NULL);
      } else if (b == 1) {                          /* left click → focus pane */
        if (my == 1)                         app.focus = FOCUS_FILTER;
        else if (my >= app.tree_y)           app.focus = FOCUS_TREE;
        else if (my >= app.table_y) {
          long row = app.table->top + (my - (app.table_y + 3));
          app.focus = FOCUS_TABLE;
          if (row >= 0 && row < app.nview) app.table->sel = row;
        }
      }
      redraw();
      continue;
    }

    if (!(t & CACA_EVENT_KEY_PRESS)) continue;
    key = caca_get_event_key_ch(&ev);

    /* menu owns input while open */
    if (app.menu->has_focus) {
      if (key == CACA_KEY_ESCAPE) { app.menu->has_focus = 0; app.menu->is_open = 0; }
      else gtcaca_menu_handle_key(app.menu, key);
      redraw();
      continue;
    }

    /* global keys */
    if (key == CACA_KEY_F10) { app.menu->has_focus = 1; app.menu->active_entry = 0; app.menu->is_open = 0; redraw(); continue; }
    if (key == CACA_KEY_F2)  { act_open(NULL); redraw(); continue; }
    if (key == CTRL('q'))    { break; }
    if (key == CTRL('o'))    { act_open(NULL); redraw(); continue; }
    if (key == '\t') {
      app.focus = (app.focus + 1) % 3;
      redraw();
      continue;
    }

    if (app.focus == FOCUS_FILTER) {
      if (key == CACA_KEY_RETURN || key == 10) {
        apply_filter(gtcaca_entry_get_text(app.fentry));
        app.focus = FOCUS_TABLE;
      } else if (key == CACA_KEY_ESCAPE) {
        app.focus = FOCUS_TABLE;
      } else {
        filter_entry_key(key);
      }
      redraw();
      continue;
    }

    /* '/' focuses the filter from a table/tree pane */
    if (key == '/') { app.focus = FOCUS_FILTER; redraw(); continue; }
    if (key == 'q' || key == 'Q') { break; }

    if (app.focus == FOCUS_TABLE) gtcaca_table_key(app.table, key, NULL);
    else                          gtcaca_tree_key(app.tree, key, NULL);
    redraw();
  }

  caca_set_mouse(gmo.dp, 0);
  detail_clear();
  if (app.filter) filter_free(app.filter);
  capture_free(&app.cap);
  free(app.view);
  caca_free_display(gmo.dp);
  return 0;
}
