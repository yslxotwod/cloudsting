/* cloudsting — native GTK4 GUI
 *
 * Structure is deliberately parallel to wifisting's main1.c:
 *   - modules[] table drives sidebar + dashboard
 *   - ModuleRegistry maps module_id -> entries + data factory
 *   - open_module() is the single entry point
 *   - shared AppState holds every widget pointer the app touches
 *
 * Modules themselves follow a uniform CLI shape:
 *     <script> --status-tsv
 *     <script> --verb [args]
 *     <script> --help | --list | --menu
 *     <script> --selftest
 * so a table of verbs is enough to build a full page per module.
 */

#include <gtk/gtk.h>
#include <vte/vte.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define APP_ID "com.cloudsting.native"
#include "config.h"

/* ==================================================================== */
/*  Project root — resolved at runtime, same as wifisting                */
/* ==================================================================== */

static char *g_project_root = NULL;

static const char *
cs_root(void)
{
    if (g_project_root != NULL) return g_project_root;

    g_autofree gchar *exe = g_file_read_link("/proc/self/exe", NULL);

    if (exe != NULL) {
        gchar *dir = g_path_get_dirname(exe);
        for (int i = 0; i < 4 && dir != NULL; i++) {
            g_autofree gchar *probe = g_build_filename(dir, "modules", NULL);
            if (g_file_test(probe, G_FILE_TEST_IS_DIR)) {
                g_project_root = g_strdup(dir);
                g_free(dir);
                return g_project_root;
            }
            gchar *up = g_path_get_dirname(dir);
            g_free(dir);
            dir = up;
        }
        g_free(dir);
    }
    g_project_root = g_strdup(CLOUDSTING_ROOT);
    return g_project_root;
}

static const char *
cs_path(const char *relative)
{
    static GHashTable *cache = NULL;
    if (cache == NULL)
        cache = g_hash_table_new(g_str_hash, g_str_equal);

    const char *hit = g_hash_table_lookup(cache, relative);
    if (hit != NULL) return hit;

    gchar *full = g_build_filename(cs_root(), relative, NULL);
    g_hash_table_insert(cache, g_strdup(relative), full);
    return full;
}

/* Per-module script paths, resolved at use time. */
#define SCRIPT(n)  cs_path("modules/" n)
#define PROJECT_DIR cs_root()

/* ==================================================================== */
/*  Module definitions                                                   */
/* ==================================================================== */

typedef struct {
    const char *id;
    const char *name;
    const char *category;
    const char *icon;
    const char *description;
} ModuleDefinition;

static const ModuleDefinition modules[] = {
    /* ---- SETUP ---- */
    { "00_deps",          "Dependencies",     "SETUP",
      "system-software-install-symbolic",
      "Inspect and install required cloud CLIs" },

    /* ---- CREDENTIALS ---- */
    { "01_cred_validate", "Credential Validator", "CREDENTIALS",
      "dialog-password-symbolic",
      "Detect provider, validate format, live-probe credentials" },

    /* ---- RECON ---- */
    { "02_inventory",     "Cloud Inventory", "RECON",
      "view-list-symbolic",
      "Enumerate every reachable asset across providers" },
    { "03_bucket_enum",   "Bucket Enum",     "RECON",
      "folder-remote-symbolic",
      "Discover buckets and probe permissions" },
    { "04_takeover",      "Subdomain Takeover", "RECON",
      "network-offline-symbolic",
      "Detect dangling CNAMEs to claimable services" },

    /* ---- EXPLOIT ---- */
    { "05_iam_privesc",   "IAM PrivEsc",     "EXPLOIT",
      "security-high-symbolic",
      "Map IAM privilege escalation paths" },
    { "06_role_chains",   "Role Chains",     "EXPLOIT",
      "emblem-synchronizing-symbolic",
      "Walk role trust policies and assume-role hops" },
    { "09_ssrf_imds",     "SSRF → IMDS",     "EXPLOIT",
      "network-transmit-receive-symbolic",
      "Probe SSRF vectors against cloud metadata endpoints" },
    { "10_imdsv2_bypass", "IMDSv2 Bypass",   "EXPLOIT",
      "changes-prevent-symbolic",
      "Bypass IMDSv2 protections via SSRF chains" },

    /* ---- AUDIT ---- */
    { "07_policy_audit",  "Policy Audit",    "AUDIT",
      "dialog-warning-symbolic",
      "Audit IAM policies for wildcards and privilege holes" },
    { "08_secrets_scan",  "Secrets Scanner", "AUDIT",
      "edit-find-symbolic",
      "Fingerprint exposed secrets in files, repos, env dumps" },

    /* ---- DATA ---- */
    { "11_user_data",     "User Data",       "DATA",
      "document-open-symbolic",
      "Extract EC2 user-data and instance metadata" },
    { "12_lambda_dump",   "Lambda Dump",     "DATA",
      "system-run-symbolic",
      "Enumerate and extract Lambda function code + env" },
};

/* ==================================================================== */
/*  AppState                                                             */
/* ==================================================================== */

typedef struct {
    GtkApplication *application;
    GtkWidget *window;
    GtkWidget *splash_window;
    GtkWidget *sidebar;
    GtkWidget *sidebar_box;
    GtkWidget *notebook;

    /* Session panel (replaces wifisting's target panel) */
    GtkWidget *session_stack;
    GtkWidget *session_account;
    GtkWidget *session_region;
    GtkWidget *session_identity;
    GtkWidget *session_last_scan;
    GtkWidget *session_loot_count;
    GtkWidget *session_badge;
    GtkWidget *session_context;
    GtkWidget *session_revealer;
    gboolean   session_shown;
    gint64     session_last_refresh;

    /* Event drawer */
    GtkWidget *event_drawer;
    GtkWidget *event_view;
    GtkWidget *event_search;
    GtkWidget *event_toggles[4];
    GtkTextBuffer *event_buffer;
    GPtrArray *event_log;

    /* Header status cells */
    GtkWidget *hdr_account_value;
    GtkWidget *hdr_region_value;
    GtkWidget *hdr_identity_value;

    /* Overlay */
    GtkWidget *overlay;
    GtkWidget *paned_horizontal;
    GtkWidget *paned_vertical;

    /* Palette */
    GtkWidget *palette_popover;
    GtkWidget *palette_search;
    GtkWidget *palette_list;

    /* Toast */
    GtkWidget *toast_stack;
    guint toast_timeout;

    /* Splash */
    GtkWidget *splash_bar;
    GtkWidget *splash_percent;
    guint splash_tick;

    /* Favorites + recents + usage */
    GPtrArray *favorites;
    GPtrArray *recent;
    GHashTable *usage;
    const char *star_pop_id;

    /* Settings */
    int  set_toast_ms;
    int  set_poll_s;
    gboolean set_verbose;
    char *set_theme;
    char *background_path;

    gboolean suppress_save;
} AppState;

/* ==================================================================== */
/*  Forward declarations                                                 */
/* ==================================================================== */

static void append_event(AppState *state, const char *msg);
static void show_toast_full(AppState *state, const char *module_id,
                            const char *title, const char *msg,
                            const char *severity);
static void show_toast(AppState *state, const char *msg);
static void show_toast_module(AppState *state, const char *id,
                              const char *msg, const char *sev);
static GtkWidget *find_module_page(AppState *state, const char *id);
static void open_module(AppState *state, const ModuleDefinition *mod);
static void window_state_save(AppState *state);
static void dashboard_populate(AppState *state);

/* ==================================================================== */
/*  Paths                                                                */
/* ==================================================================== */

#define WIFISTING_STATE_INI ".config/cloudsting/state.ini"

static gchar *
state_ini_path(void)
{
    return g_strdup(cs_path("state/state.ini"));
}

/* ==================================================================== */
/*  Favorites / recents / usage                                          */
/* ==================================================================== */

static gboolean
favorites_contains(AppState *state, const char *id)
{
    if (state->favorites == NULL || id == NULL) return FALSE;
    for (guint i = 0; i < state->favorites->len; i++)
        if (g_strcmp0(g_ptr_array_index(state->favorites, i), id) == 0)
            return TRUE;
    return FALSE;
}

static int
module_usage_count(AppState *state, const char *id)
{
    if (state == NULL || state->usage == NULL || id == NULL) return 0;
    return GPOINTER_TO_INT(g_hash_table_lookup(state->usage, id));
}

static void
favorites_toggle(AppState *state, const char *id)
{
    if (state->favorites == NULL || id == NULL) return;
    if (favorites_contains(state, id)) {
        for (guint i = 0; i < state->favorites->len; i++) {
            if (g_strcmp0(g_ptr_array_index(state->favorites, i), id) == 0) {
                g_ptr_array_remove_index(state->favorites, i);
                show_toast(state, "Removed from favorites");
                break;
            }
        }
    } else {
        g_ptr_array_add(state->favorites, g_strdup(id));
        show_toast(state, "Added to favorites");
    }
    window_state_save(state);
    if (state->sidebar_box != NULL) dashboard_populate(state);
}

static void
recent_record(AppState *state, const char *id)
{
    if (state->recent == NULL || id == NULL) return;
    if (g_strcmp0(id, "raw-terminal") == 0) return;
    for (guint i = 0; i < state->recent->len; i++) {
        if (g_strcmp0(g_ptr_array_index(state->recent, i), id) == 0) {
            g_ptr_array_remove_index(state->recent, i);
            break;
        }
    }
    g_ptr_array_insert(state->recent, 0, g_strdup(id));
    while (state->recent->len > 5)
        g_ptr_array_remove_index(state->recent, state->recent->len - 1);
    window_state_save(state);
}

/* ==================================================================== */
/*  Window state persistence                                             */
/* ==================================================================== */

static void
window_state_save(AppState *state)
{
    if (state->suppress_save) return;

    g_autofree gchar *path = state_ini_path();
    g_autofree gchar *dir = g_path_get_dirname(path);
    g_mkdir_with_parents(dir, 0700);

    GKeyFile *kf = g_key_file_new();
    g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL);

    if (state->window != NULL) {
        int w = 0, h = 0;
        gtk_window_get_default_size(GTK_WINDOW(state->window), &w, &h);
        g_key_file_set_integer(kf, "window", "width", w);
        g_key_file_set_integer(kf, "window", "height", h);
    }

    if (state->favorites != NULL) {
        for (guint i = 0; i < state->favorites->len; i++)
            g_key_file_set_boolean(kf, "favorites",
                g_ptr_array_index(state->favorites, i), TRUE);
    }

    if (state->recent != NULL) {
        for (guint i = 0; i < state->recent->len; i++) {
            g_autofree gchar *k = g_strdup_printf("slot_%u", i);
            g_key_file_set_string(kf, "recent", k,
                g_ptr_array_index(state->recent, i));
        }
        g_key_file_set_integer(kf, "recent", "count",
                               (int) state->recent->len);
    }

    if (state->usage != NULL) {
        GHashTableIter it;
        gpointer k, v;
        g_hash_table_iter_init(&it, state->usage);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            int n = GPOINTER_TO_INT(v);
            if (n > 0)
                g_key_file_set_integer(kf, "usage", (const char *) k, n);
        }
    }

    if (state->notebook != NULL) {
        int pages = gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->notebook));
        int saved = 0;
        for (int i = 1; i < pages; i++) {
            GtkWidget *pg = gtk_notebook_get_nth_page(
                GTK_NOTEBOOK(state->notebook), i);
            const char *id = g_object_get_data(G_OBJECT(pg), "module-id");
            if (id == NULL || *id == '\0') continue;
            if (g_strcmp0(id, "raw-terminal") == 0) continue;
            g_autofree gchar *k = g_strdup_printf("tab_%d", saved);
            g_key_file_set_string(kf, "session", k, id);
            saved++;
        }
        g_key_file_set_integer(kf, "session", "count", saved);
    }

    g_autofree gchar *data = g_key_file_to_data(kf, NULL, NULL);
    g_file_set_contents(path, data, -1, NULL);
    g_key_file_unref(kf);
}

static void
usage_counts_load(AppState *state)
{
    g_autofree gchar *path = state_ini_path();
    g_autoptr(GKeyFile) kf = g_key_file_new();
    if (state == NULL || state->usage == NULL) return;
    if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL)) return;

    g_auto(GStrv) keys = g_key_file_get_keys(kf, "usage", NULL, NULL);
    for (guint i = 0; keys != NULL && keys[i] != NULL; i++) {
        int n = g_key_file_get_integer(kf, "usage", keys[i], NULL);
        if (n > 0)
            g_hash_table_insert(state->usage, g_strdup(keys[i]),
                                GINT_TO_POINTER(n));
    }
}

static void
window_state_load(AppState *state)
{
    g_autofree gchar *path = state_ini_path();
    GKeyFile *kf = g_key_file_new();
    GError *error = NULL;

    if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &error)) {
        g_clear_error(&error);
        g_key_file_unref(kf);
        return;
    }

    {
        int w = g_key_file_get_integer(kf, "window", "width", NULL);
        int h = g_key_file_get_integer(kf, "window", "height", NULL);
        if (w >= 640 && h >= 400) {
            GdkDisplay *dpy = gtk_widget_get_display(state->window);
            GdkMonitor *mon = g_list_model_get_item(
                gdk_display_get_monitors(dpy), 0);
            if (mon != NULL) {
                GdkRectangle geo;
                gdk_monitor_get_geometry(mon, &geo);
                if (geo.width > 0 && w > geo.width) w = geo.width;
                if (geo.height > 0 && h > geo.height) h = geo.height;
                g_object_unref(mon);
            }
            gtk_window_set_default_size(GTK_WINDOW(state->window), w, h);
        }
    }

    {
        g_auto(GStrv) keys = g_key_file_get_keys(kf, "favorites", NULL, NULL);
        for (guint i = 0; keys != NULL && keys[i] != NULL; i++)
            if (g_key_file_get_boolean(kf, "favorites", keys[i], NULL))
                g_ptr_array_add(state->favorites, g_strdup(keys[i]));
    }
    {
        int count = g_key_file_get_integer(kf, "recent", "count", NULL);
        for (int i = 0; i < count; i++) {
            g_autofree gchar *k = g_strdup_printf("slot_%d", i);
            g_autofree gchar *v = g_key_file_get_string(kf, "recent", k, NULL);
            if (v != NULL) g_ptr_array_add(state->recent, g_strdup(v));
        }
    }

    usage_counts_load(state);
    g_key_file_unref(kf);
}

static gboolean
window_close_request(GtkWindow *window, gpointer user_data)
{
    AppState *state = user_data;
    (void) window;
    window_state_save(state);
    return FALSE;
}

/* ==================================================================== */
/*  Events                                                               */
/* ==================================================================== */

typedef enum { EVT_INFO = 0, EVT_WARN, EVT_ERR, EVT_OK, EVT_N } EventSeverity;

typedef struct {
    char *line;
    EventSeverity sev;
} EventItem;

static void
event_item_free(gpointer data)
{
    EventItem *ei = data;
    g_free(ei->line);
    g_free(ei);
}

static EventSeverity
event_infer_severity(const char *msg)
{
    if (msg == NULL) return EVT_INFO;
    if (strstr(msg, "failed") || strstr(msg, "Failed") ||
        strstr(msg, "error")  || strstr(msg, "Error")  ||
        strstr(msg, "ERROR")  || strstr(msg, "not permitted") ||
        strstr(msg, "DENIED") || strstr(msg, "denied"))
        return EVT_ERR;
    if (strstr(msg, "warning") || strstr(msg, "Warning") ||
        strstr(msg, "warn")    || strstr(msg, "WARN"))
        return EVT_WARN;
    if (strstr(msg, "completed") || strstr(msg, "Completed") ||
        strstr(msg, "refreshed") || strstr(msg, "Refreshed") ||
        strstr(msg, "ready")     || strstr(msg, "Ready")     ||
        strstr(msg, "success")   || strstr(msg, "Success")   ||
        strstr(msg, "found")     || strstr(msg, "Found")     ||
        strstr(msg, "PASS"))
        return EVT_OK;
    return EVT_INFO;
}

static const char *
event_sev_tag(EventSeverity s)
{
    switch (s) {
        case EVT_WARN: return "evt-warn";
        case EVT_ERR:  return "evt-err";
        case EVT_OK:   return "evt-ok";
        default:       return "evt-info";
    }
}

static void
event_rebuild_buffer(AppState *state)
{
    GtkTextIter end;
    if (state->event_buffer == NULL) return;

    gtk_text_buffer_set_text(state->event_buffer, "", 0);
    if (state->event_log == NULL) return;

    for (guint i = 0; i < state->event_log->len; i++) {
        EventItem *ei = g_ptr_array_index(state->event_log, i);
        GtkTextTagTable *tt = gtk_text_buffer_get_tag_table(
            state->event_buffer);
        GtkTextTag *tag = tt ? gtk_text_tag_table_lookup(
            tt, event_sev_tag(ei->sev)) : NULL;

        gtk_text_buffer_get_end_iter(state->event_buffer, &end);
        if (tag != NULL)
            gtk_text_buffer_insert_with_tags(
                state->event_buffer, &end, ei->line, -1, tag, NULL);
        else
            gtk_text_buffer_insert(
                state->event_buffer, &end, ei->line, -1);
    }
}

static void
append_event(AppState *state, const char *message)
{
    EventItem *ei;
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *ts = g_date_time_format(now, "%H:%M:%S");
    g_autofree char *line = g_strdup_printf("[%s] %s\n", ts, message);

    if (state->event_log == NULL)
        state->event_log = g_ptr_array_new_with_free_func(event_item_free);

    ei = g_new0(EventItem, 1);
    ei->line = g_strdup(line);
    ei->sev = event_infer_severity(message);
    g_ptr_array_add(state->event_log, ei);

    while (state->event_log->len > 5000)
        g_ptr_array_remove_index(state->event_log, 0);

    if (state->event_buffer == NULL) return;

    {
        GtkTextIter end;
        GtkTextTagTable *tt = gtk_text_buffer_get_tag_table(
            state->event_buffer);
        GtkTextTag *tag = tt ? gtk_text_tag_table_lookup(
            tt, event_sev_tag(ei->sev)) : NULL;
        gtk_text_buffer_get_end_iter(state->event_buffer, &end);
        if (tag != NULL)
            gtk_text_buffer_insert_with_tags(
                state->event_buffer, &end, ei->line, -1, tag, NULL);
        else
            gtk_text_buffer_insert(
                state->event_buffer, &end, ei->line, -1);

        if (state->event_view != NULL)
            gtk_text_view_scroll_to_iter(
                GTK_TEXT_VIEW(state->event_view),
                &end, 0.0, FALSE, 0.0, 1.0);
    }
}

/* ==================================================================== */
/*  Toast                                                                */
/* ==================================================================== */

typedef struct {
    GtkWidget *revealer;
    AppState  *state;
    guint      timeout_id;
} ToastEntry;

static void toast_entry_free(gpointer d)
{
    ToastEntry *t = d;
    if (t->timeout_id) g_source_remove(t->timeout_id);
    g_free(t);
}

static gboolean toast_dismiss_cb(gpointer ud)
{
    ToastEntry *t = ud;
    t->timeout_id = 0;
    if (t->revealer != NULL)
        gtk_revealer_set_reveal_child(GTK_REVEALER(t->revealer), FALSE);
    return G_SOURCE_REMOVE;
}

static void toast_reveal_done(GObject *obj, GParamSpec *ps, gpointer ud)
{
    ToastEntry *t = ud;
    (void) obj; (void) ps;
    if (t->revealer == NULL) return;
    if (gtk_revealer_get_child_revealed(GTK_REVEALER(t->revealer))) return;
    GtkWidget *parent = gtk_widget_get_parent(t->revealer);
    if (parent != NULL && GTK_IS_BOX(parent))
        gtk_box_remove(GTK_BOX(parent), t->revealer);
}

static void toast_close_clicked(GtkButton *b, gpointer ud)
{
    ToastEntry *t = ud;
    (void) b;
    if (t->timeout_id) { g_source_remove(t->timeout_id); t->timeout_id = 0; }
    if (t->revealer != NULL)
        gtk_revealer_set_reveal_child(GTK_REVEALER(t->revealer), FALSE);
}

static const char *
module_icon_for(const char *id)
{
    for (guint i = 0; i < G_N_ELEMENTS(modules); i++)
        if (g_strcmp0(modules[i].id, id) == 0) return modules[i].icon;
    if (g_strcmp0(id, "system") == 0) return "preferences-system-symbolic";
    return "dialog-information-symbolic";
}

static const char *
module_name_for(const char *id)
{
    if (id == NULL) return "cloudsting";
    for (guint i = 0; i < G_N_ELEMENTS(modules); i++)
        if (g_strcmp0(modules[i].id, id) == 0) return modules[i].name;
    if (g_strcmp0(id, "system") == 0) return "System";
    return "cloudsting";
}

static void
show_toast_full(AppState *state, const char *module_id,
                const char *title, const char *message,
                const char *severity)
{
    if (state == NULL || !GTK_IS_WIDGET(state->toast_stack)) return;

    {
        guint n = 0;
        GtkWidget *c = gtk_widget_get_first_child(state->toast_stack);
        while (c) { n++; c = gtk_widget_get_next_sibling(c); }
        if (n >= 5) {
            GtkWidget *first = gtk_widget_get_first_child(state->toast_stack);
            if (first != NULL)
                gtk_box_remove(GTK_BOX(state->toast_stack), first);
        }
    }

    GtkWidget *rev = gtk_revealer_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *icon = gtk_image_new_from_icon_name(module_icon_for(module_id));
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title_lbl = gtk_label_new(title ? title : "cloudsting");
    GtkWidget *content_lbl = gtk_label_new(message ? message : "");
    GtkWidget *close_btn = gtk_button_new();
    GtkWidget *glyph = gtk_label_new("\u00d7");

    gtk_widget_add_css_class(box, "toast");
    gtk_widget_add_css_class(icon, "toast-icon");
    gtk_widget_add_css_class(title_lbl, "toast-title");
    gtk_widget_add_css_class(content_lbl, "toast-content");
    gtk_widget_add_css_class(close_btn, "toast-close");
    gtk_widget_add_css_class(glyph, "toast-close-glyph");
    if (severity && *severity) {
        g_autofree char *cls = g_strdup_printf("toast-%s", severity);
        gtk_widget_add_css_class(box, cls);
    }
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 20);
    gtk_widget_set_valign(icon, GTK_ALIGN_START);
    gtk_widget_set_margin_top(icon, 2);

    gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(content_lbl), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(title_lbl), PANGO_ELLIPSIZE_END);
    gtk_label_set_wrap(GTK_LABEL(content_lbl), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(content_lbl), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_max_width_chars(GTK_LABEL(content_lbl), 60);
    gtk_label_set_selectable(GTK_LABEL(content_lbl), TRUE);

    gtk_widget_set_hexpand(col, TRUE);
    gtk_widget_set_halign(title_lbl, GTK_ALIGN_START);
    gtk_widget_set_halign(content_lbl, GTK_ALIGN_START);
    gtk_button_set_child(GTK_BUTTON(close_btn), glyph);
    gtk_widget_set_valign(close_btn, GTK_ALIGN_START);

    gtk_box_append(GTK_BOX(col), title_lbl);
    gtk_box_append(GTK_BOX(col), content_lbl);
    gtk_box_append(GTK_BOX(box), icon);
    gtk_box_append(GTK_BOX(box), col);
    gtk_box_append(GTK_BOX(box), close_btn);

    gtk_revealer_set_child(GTK_REVEALER(rev), box);
    gtk_revealer_set_transition_type(GTK_REVEALER(rev),
        GTK_REVEALER_TRANSITION_TYPE_SLIDE_LEFT);
    gtk_revealer_set_transition_duration(GTK_REVEALER(rev), 220);
    gtk_revealer_set_reveal_child(GTK_REVEALER(rev), FALSE);

    ToastEntry *t = g_new0(ToastEntry, 1);
    t->revealer = rev;
    t->state = state;
    g_object_set_data_full(G_OBJECT(rev), "toast-entry", t, toast_entry_free);
    g_signal_connect(close_btn, "clicked",
                     G_CALLBACK(toast_close_clicked), t);
    g_signal_connect(rev, "notify::child-revealed",
                     G_CALLBACK(toast_reveal_done), t);

    gtk_box_append(GTK_BOX(state->toast_stack), rev);
    gtk_revealer_set_reveal_child(GTK_REVEALER(rev), TRUE);

    guint base = state->set_toast_ms > 0 ? (guint) state->set_toast_ms : 4500;
    guint ms = base;
    if (g_strcmp0(severity, "warn") == 0) ms = base + 1500;
    else if (g_strcmp0(severity, "error") == 0) ms = base + 4500;
    else if (g_strcmp0(severity, "success") == 0)
        ms = base > 1000 ? base - 1000 : base;
    t->timeout_id = g_timeout_add(ms, toast_dismiss_cb, t);
}

static void
show_toast(AppState *state, const char *message)
{
    show_toast_full(state, NULL, "cloudsting", message, "info");
}

static void
show_toast_module(AppState *state, const char *id,
                  const char *message, const char *sev)
{
    show_toast_full(state, id, module_name_for(id), message, sev);
}

/* ==================================================================== */
/*  Toast entry-point used by the module framework                       */
/* ==================================================================== */

static void
module_page_set_status(AppState *state, const char *module_id,
                       const char *text, const char *css_class)
{
    GtkWidget *page = find_module_page(state, module_id);
    if (page == NULL) return;
    GtkWidget *pill = g_object_get_data(G_OBJECT(page), "status-pill");
    if (pill == NULL) return;

    gtk_label_set_text(GTK_LABEL(pill), text);
    gtk_widget_remove_css_class(pill, "status-idle");
    gtk_widget_remove_css_class(pill, "status-running");
    gtk_widget_remove_css_class(pill, "status-error");
    gtk_widget_remove_css_class(pill, "status-success");
    gtk_widget_add_css_class(pill,
        css_class != NULL ? css_class : "status-idle");
}

/* ==================================================================== */
/*  Command runner — one function used by every module verb              */
/* ==================================================================== */

typedef struct {
    AppState   *state;
    char       *module_id;
    char       *label;
    GtkWidget  *status_label;
    GtkWidget  *output_view;      /* optional; a GtkTextView to write output */
} CommandAction;

static void
command_action_finished(GObject *source, GAsyncResult *result, gpointer ud)
{
    CommandAction *a = ud;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *errout = NULL;

    if (a == NULL) return;

    if (!g_subprocess_communicate_utf8_finish(
            G_SUBPROCESS(source), result, &out, &errout, &error)) {
        g_autofree gchar *m = g_strdup_printf(
            "%s: %s", a->label,
            error ? error->message : "process failed");
        append_event(a->state, m);
        show_toast_module(a->state, a->module_id, m, "error");
        if (a->status_label != NULL)
            gtk_label_set_text(GTK_LABEL(a->status_label), m);
        goto done;
    }

    {
        gboolean exited = g_subprocess_get_if_exited(G_SUBPROCESS(source));
        gboolean ok = g_subprocess_get_successful(G_SUBPROCESS(source));
        int status = exited ? g_subprocess_get_exit_status(G_SUBPROCESS(source)) : 0;

        if (errout != NULL && *errout != '\0') {
            g_autofree gchar *clean = g_strdup(errout);
            g_strstrip(clean);
            if (*clean != '\0') {
                g_autofree gchar *m = g_strdup_printf("%s: %s", a->label, clean);
                append_event(a->state, m);
            }
        }

        if (a->output_view != NULL && out != NULL) {
            GtkTextBuffer *buf = gtk_text_view_get_buffer(
                GTK_TEXT_VIEW(a->output_view));
            gtk_text_buffer_set_text(buf, out, -1);
        }

        if (ok) {
            g_autofree gchar *m = g_strdup_printf("%s: ok", a->label);
            append_event(a->state, m);
            if (a->status_label != NULL)
                gtk_label_set_text(GTK_LABEL(a->status_label), m);
            show_toast_module(a->state, a->module_id, m, "success");
        } else {
            const char *detail = (errout && *errout) ? errout :
                                 (out && *out)       ? out : "no output";
            g_autofree gchar *clean = g_strdup(detail);
            g_strstrip(clean);
            g_autofree gchar *m = g_strdup_printf(
                "%s failed (exit %d): %s", a->label, status, clean);
            append_event(a->state, m);
            if (a->status_label != NULL)
                gtk_label_set_text(GTK_LABEL(a->status_label), m);
            show_toast_module(a->state, a->module_id, m, "error");
        }
    }

done:
    g_free(a->module_id);
    g_free(a->label);
    g_free(a);
}

static void
run_module_command(AppState *state, const char *module_id,
                   const char *label, GtkWidget *status_label,
                   GtkWidget *output_view,
                   const char *const *argv, gboolean privileged)
{
    g_autoptr(GError) error = NULL;
    GSubprocess *proc;

    if (state == NULL || argv == NULL || argv[0] == NULL) return;
    append_event(state, label);

    if (privileged) {
        GPtrArray *full = g_ptr_array_new();
        g_ptr_array_add(full, (gpointer) "pkexec");
        for (guint i = 0; argv[i] != NULL; i++)
            g_ptr_array_add(full, (gpointer) argv[i]);
        g_ptr_array_add(full, NULL);

        proc = g_subprocess_newv(
            (const char * const *) full->pdata,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE |
            G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
        g_ptr_array_unref(full);
    } else {
        proc = g_subprocess_newv(argv,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE |
            G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
    }

    if (proc == NULL) {
        g_autofree gchar *m = g_strdup_printf(
            "%s: %s", label, error ? error->message : "spawn failed");
        append_event(state, m);
        show_toast_module(state, module_id, m, "error");
        return;
    }

    CommandAction *a = g_new0(CommandAction, 1);
    a->state = state;
    a->module_id = g_strdup(module_id);
    a->label = g_strdup(label);
    a->status_label = status_label;
    a->output_view = output_view;
    g_subprocess_communicate_utf8_async(
        proc, NULL, NULL, command_action_finished, a);
    g_object_unref(proc);
}

/* ==================================================================== */
/*  Module framework — table-driven                                      */
/* ==================================================================== */

typedef struct {
    const char *label;
    const char *verb;
    const char *arg_placeholder;  /* NULL = no args */
    gboolean    privileged;
    gboolean    writes_output;    /* if true, output goes to text view */
} VerbDef;

typedef struct {
    const char *id;
    const char *script;
    const char *title;
    const char *subtitle;
    const VerbDef *verbs;
    int n_verbs;
} ModuleSpec;

typedef struct {
    GtkApplication *application;
    AppState *state;
    GSubprocess *process;
} _unused;

typedef struct {
    AppState *state;
    const ModuleSpec *spec;
    GtkWidget *status_label;
    GtkWidget *output_view;
    GSubprocess *status_proc;
} GenericModulePage;

static void
generic_page_free(gpointer data)
{
    GenericModulePage *g = data;
    if (g->status_proc != NULL) {
        g_subprocess_force_exit(g->status_proc);
        g_clear_object(&g->status_proc);
    }
    g_free(g);
}

/* Run --status-tsv and populate a text view. */
static void
generic_status_finished(GObject *source, GAsyncResult *result, gpointer ud)
{
    GenericModulePage *g = ud;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *errout = NULL;

    if (!g_subprocess_communicate_utf8_finish(
            G_SUBPROCESS(source), result, &out, &errout, &error))
        return;
    g_clear_object(&g->status_proc);

    if (g->output_view != NULL) {
        GtkTextBuffer *buf = gtk_text_view_get_buffer(
            GTK_TEXT_VIEW(g->output_view));
        gtk_text_buffer_set_text(buf,
            (out && *out) ? out : "(no status output)", -1);
    }
}

static void
generic_status_refresh(GenericModulePage *g)
{
    g_autoptr(GError) error = NULL;
    const char *argv[3];

    if (g->status_proc != NULL) return;

    argv[0] = g->spec->script;
    argv[1] = "--status-tsv";
    argv[2] = NULL;

    g->status_proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);

    if (g->status_proc == NULL) return;
    g_subprocess_communicate_utf8_async(
        g->status_proc, NULL, NULL, generic_status_finished, g);
}

static void
generic_verb_clicked(GtkButton *b, gpointer ud)
{
    GenericModulePage *g = ud;
    const VerbDef *v = g_object_get_data(G_OBJECT(b), "verb-def");
    GtkWidget *entry = g_object_get_data(G_OBJECT(b), "args-entry");
    const char *arg = entry != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(entry)) : NULL;

    if (v == NULL || g == NULL) return;

    const char *argv[5];
    guint i = 0;
    argv[i++] = g->spec->script;
    argv[i++] = v->verb;
    if (arg != NULL && *arg != '\0')
        argv[i++] = arg;
    argv[i] = NULL;

    GtkWidget *output = v->writes_output ? g->output_view : NULL;
    run_module_command(g->state, g->spec->id, v->label,
                       g->status_label, output, argv, v->privileged);
}

/* Build one action page from the module's verb list. */
static GtkWidget *
generic_build_actions(AppState *state, gpointer module_data)
{
    GenericModulePage *g = module_data;
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new(g->spec->title);
    GtkWidget *subtitle = gtk_label_new(g->spec->subtitle);
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *card_title = gtk_label_new("ACTIONS");
    GtkWidget *status = gtk_label_new("idle");

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(subtitle, "page-subtitle");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(card_title, "section-title");
    gtk_widget_add_css_class(status, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(card_title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(subtitle), TRUE);

    for (int i = 0; i < g->spec->n_verbs; i++) {
        const VerbDef *v = &g->spec->verbs[i];
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *btn = gtk_button_new_with_label(v->label);
        gtk_widget_add_css_class(btn, "accent");
        gtk_widget_set_valign(btn, GTK_ALIGN_CENTER);
        g_object_set_data(G_OBJECT(btn), "verb-def", (gpointer) v);

        if (v->arg_placeholder != NULL) {
            GtkWidget *entry = gtk_entry_new();
            gtk_entry_set_placeholder_text(GTK_ENTRY(entry),
                                           v->arg_placeholder);
            gtk_widget_set_hexpand(entry, TRUE);
            gtk_box_append(GTK_BOX(row), entry);
            g_object_set_data(G_OBJECT(btn), "args-entry", entry);
        } else {
            GtkWidget *spacer = gtk_label_new("");
            gtk_widget_set_hexpand(spacer, TRUE);
            gtk_box_append(GTK_BOX(row), spacer);
        }
        if (v->privileged) {
            GtkWidget *hint = gtk_label_new("needs root");
            gtk_widget_add_css_class(hint, "dependency-package");
            gtk_box_append(GTK_BOX(row), hint);
        }
        gtk_box_append(GTK_BOX(row), btn);
        gtk_box_append(GTK_BOX(card), row);
        g_signal_connect(btn, "clicked",
                         G_CALLBACK(generic_verb_clicked), g);
    }

    gtk_box_append(GTK_BOX(card), status);
    g->status_label = status;

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), subtitle);
    gtk_box_append(GTK_BOX(page), card);

    (void) state;
    return page;
}

/* Raw output page: whatever the last command or --status-tsv wrote. */
static GtkWidget *
generic_build_output(AppState *state, gpointer module_data)
{
    GenericModulePage *g = module_data;
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *title = gtk_label_new("Output");
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *refresh = gtk_button_new_with_label("Reload status");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(view, "event-view");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_widget_set_hexpand(refresh, FALSE);
    gtk_widget_set_halign(row, GTK_ALIGN_START);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_NONE);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    gtk_box_append(GTK_BOX(row), refresh);
    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), row);
    gtk_box_append(GTK_BOX(page), scroll);

    g->output_view = view;
    g_signal_connect_swapped(refresh, "clicked",
                             G_CALLBACK(generic_status_refresh), g);
    generic_status_refresh(g);

    (void) state;
    return page;
}

/* Overview page — status + help/description. */
static GtkWidget *
generic_build_overview(AppState *state, gpointer module_data)
{
    GenericModulePage *g = module_data;
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new(g->spec->title);
    GtkWidget *subtitle = gtk_label_new(g->spec->subtitle);
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *card_title = gtk_label_new("MODULE");
    GtkWidget *id_lbl = gtk_label_new(g->spec->id);
    GtkWidget *script_lbl = gtk_label_new(g->spec->script);
    GtkWidget *note = gtk_label_new(
        "Run --actions to invoke verbs, or open Raw Terminal (Ctrl+T) "
        "to use the module's interactive --menu.");

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(subtitle, "page-subtitle");
    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(card_title, "section-title");
    gtk_widget_add_css_class(id_lbl, "dependency-name");
    gtk_widget_add_css_class(script_lbl, "dependency-package");
    gtk_widget_add_css_class(note, "dependency-summary");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(card_title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(id_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(script_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(subtitle), TRUE);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);

    gtk_box_append(GTK_BOX(card), card_title);
    gtk_box_append(GTK_BOX(card), id_lbl);
    gtk_box_append(GTK_BOX(card), script_lbl);
    gtk_box_append(GTK_BOX(card), note);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), subtitle);
    gtk_box_append(GTK_BOX(page), card);
    (void) state;
    return page;
}

/* ==================================================================== */
/*  Per-module verb tables                                               */
/* ==================================================================== */

#define S(n)  SCRIPT(n)

/* ---- 00_deps — special-cased below ---- */
static const VerbDef deps_verbs[] = {
    { "Refresh status",        "--status-tsv",      NULL,               FALSE, TRUE },
    { "Install missing",       "--install-missing", NULL,               TRUE,  TRUE },
    { "Install full toolchain","--install-all",     NULL,               TRUE,  TRUE },
    { "Install pipx tools",    "--install-pipx",    NULL,               FALSE, TRUE },
    { "Install git tools",     "--install-git",     NULL,               FALSE, TRUE },
};

/* ---- 01_cred_validate ---- */
static const VerbDef cred_verbs[] = {
    { "Validate file / stdin", "--validate",        "path or -",         FALSE, TRUE },
    { "Detect only (offline)", "--detect",          "path or -",         FALSE, TRUE },
    { "List known formats",    "--list-formats",    NULL,                FALSE, TRUE },
};

/* ---- 02_inventory ---- */
static const VerbDef inv_verbs[] = {
    { "Full inventory",        "--run",             NULL,                FALSE, TRUE },
    { "One provider",          "--run",             "aws|gcloud|az|doctl",FALSE, TRUE },
    { "Show regions",          "--regions",         "aws|gcp|az|doctl",  FALSE, TRUE },
    { "Provider states",       "--status-tsv",      NULL,                FALSE, TRUE },
};

/* ---- 03_bucket_enum ---- */
static const VerbDef bucket_verbs[] = {
    { "Authenticated sweep",   "--enum",            NULL,                FALSE, TRUE },
    { "Probe one bucket",      "--perm",            "bucket-name",       FALSE, TRUE },
    { "Guess for a domain",    "--domain",          "example.com",       FALSE, TRUE },
};

/* ---- 04_takeover ---- */
static const VerbDef takeover_verbs[] = {
    { "Scan a domain",         "--scan",            "example.com",       FALSE, TRUE },
    { "Check one subdomain",   "--check",           "sub.example.com",   FALSE, TRUE },
    { "Fingerprint table",     "--list",            NULL,                FALSE, TRUE },
};

/* ---- 05_iam_privesc ---- */
static const VerbDef privesc_verbs[] = {
    { "Map current caller",    "--map",             NULL,                FALSE, TRUE },
    { "Explain technique",     "--explain",         "PassRole|PutUserPolicy|...", FALSE, TRUE },
    { "Technique list",        "--list",            NULL,                FALSE, TRUE },
    { "Check action",          "--check",           "iam:PassRole",      FALSE, TRUE },
};

/* ---- 06_role_chains ---- */
static const VerbDef chains_verbs[] = {
    { "Who am I",              "--whoami",          NULL,                FALSE, TRUE },
    { "Scan role trusts",      "--scan",            NULL,                FALSE, TRUE },
    { "Walk a role chain",     "--chain",           "arn:aws:iam::…:role/…", FALSE, TRUE },
    { "List cached trusts",    "--list",            NULL,                FALSE, TRUE },
};

/* ---- 07_policy_audit ---- */
static const VerbDef audit_verbs[] = {
    { "Audit a policy file",   "--audit",           "/path/to/policy.json  or  -", FALSE, TRUE },
    { "Audit account policies", "--audit",          NULL,                FALSE, TRUE },
    { "Rule list",             "--list",            NULL,                FALSE, TRUE },
};

/* ---- 08_secrets_scan ---- */
static const VerbDef secrets_verbs[] = {
    { "Scan file / directory", "--scan",            "/path/to/scan",     FALSE, TRUE },
    { "Detect one token",      "--detect",          "token or -",        FALSE, TRUE },
    { "Signature list",        "--list",            NULL,                FALSE, TRUE },
};

/* ---- 09_ssrf_imds ---- */
static const VerbDef ssrf_verbs[] = {
    { "Probe all IMDS endpoints", "--tunnel",       NULL,                FALSE, TRUE },
    { "Probe one URL",         "--probe",           "http://...",        FALSE, TRUE },
    { "Check reachability",    "--check",           "http://...",        FALSE, TRUE },
    { "Endpoint list",         "--list",            NULL,                FALSE, TRUE },
};

/* ---- 10_imdsv2_bypass ---- */
static const VerbDef imds2_verbs[] = {
    { "Token from IMDS",       "--ssrf",            "http://169.254.169.254/…", FALSE, TRUE },
    { "Check a URL",           "--check",           "http://...",        FALSE, TRUE },
    { "Technique list",        "--headers",         NULL,                FALSE, TRUE },
};

/* ---- 11_user_data ---- */
static const VerbDef userdata_verbs[] = {
    { "Dump metadata",         "--dump",            "optional-token",    FALSE, TRUE },
    { "Extract user-data",     "--extract",         "optional-token",    FALSE, TRUE },
    { "Key list",              "--keys",            NULL,                FALSE, TRUE },
};

/* ---- 12_lambda_dump ---- */
static const VerbDef lambda_verbs[] = {
    { "List functions",        "--list",            NULL,                FALSE, TRUE },
    { "Dump config",           "--dump",            "function-name",     FALSE, TRUE },
    { "Download code",         "--download",        "function-name",     FALSE, TRUE },
    { "Print env vars",        "--env",             "function-name",     FALSE, TRUE },
    { "List URLs",             "--urls",            NULL,                FALSE, TRUE },
};

/* ---- Master spec table ---- */
static const ModuleSpec module_specs[] = {
    { "00_deps",          S("00_deps.sh"),
      "Dependencies",     "Install required cloud CLIs and build tools.",
      deps_verbs,         G_N_ELEMENTS(deps_verbs) },
    { "01_cred_validate", S("01_cred_validate.sh"),
      "Credential Validator", "Detect provider, validate format, live-probe.",
      cred_verbs,         G_N_ELEMENTS(cred_verbs) },
    { "02_inventory",     S("02_inventory.sh"),
      "Cloud Inventory",  "Enumerate all reachable assets across providers.",
      inv_verbs,          G_N_ELEMENTS(inv_verbs) },
    { "03_bucket_enum",   S("03_bucket_enum.sh"),
      "Bucket Enum",      "Find, probe, and rate bucket exposure.",
      bucket_verbs,       G_N_ELEMENTS(bucket_verbs) },
    { "04_takeover",      S("04_takeover.sh"),
      "Subdomain Takeover", "Detect dangling CNAMEs to claimable services.",
      takeover_verbs,     G_N_ELEMENTS(takeover_verbs) },
    { "05_iam_privesc",   S("05_iam_privesc.sh"),
      "IAM PrivEsc",      "Map IAM privilege escalation paths.",
      privesc_verbs,      G_N_ELEMENTS(privesc_verbs) },
    { "06_role_chains",   S("06_role_chains.sh"),
      "Role Chains",      "Analyze trust policies and assume-role hops.",
      chains_verbs,       G_N_ELEMENTS(chains_verbs) },
    { "07_policy_audit",  S("07_policy_audit.sh"),
      "Policy Audit",     "Audit IAM policies for risky patterns.",
      audit_verbs,        G_N_ELEMENTS(audit_verbs) },
    { "08_secrets_scan",  S("08_secrets_scan.sh"),
      "Secrets Scanner",  "Fingerprint exposed secrets in files, repos, env.",
      secrets_verbs,      G_N_ELEMENTS(secrets_verbs) },
    { "09_ssrf_imds",     S("09_ssrf_imds.sh"),
      "SSRF → IMDS",      "Probe SSRF vectors against cloud metadata.",
      ssrf_verbs,         G_N_ELEMENTS(ssrf_verbs) },
    { "10_imdsv2_bypass", S("10_imdsv2_bypass.sh"),
      "IMDSv2 Bypass",    "Bypass IMDSv2 protections.",
      imds2_verbs,        G_N_ELEMENTS(imds2_verbs) },
    { "11_user_data",     S("11_user_data.sh"),
      "User Data",        "Extract EC2 user-data and instance metadata.",
      userdata_verbs,     G_N_ELEMENTS(userdata_verbs) },
    { "12_lambda_dump",   S("12_lambda_dump.sh"),
      "Lambda Dump",      "Enumerate and extract Lambda code + env.",
      lambda_verbs,       G_N_ELEMENTS(lambda_verbs) },
};

static const ModuleSpec *
module_spec_for(const char *id)
{
    for (guint i = 0; i < G_N_ELEMENTS(module_specs); i++)
        if (g_strcmp0(module_specs[i].id, id) == 0)
            return &module_specs[i];
    return NULL;
}

/* ==================================================================== */
/*  Module page composition                                              */
/* ==================================================================== */

static GtkWidget *generic_build_overview(AppState *, gpointer);
static GtkWidget *generic_build_actions(AppState *, gpointer);
static GtkWidget *generic_build_output(AppState *, gpointer);

static ModuleSubmenuEntry *
build_entries_for(const ModuleSpec *spec, int *out_count)
{
    static ModuleSubmenuEntry entries[3];
    entries[0].name = "Overview"; entries[0].icon = "dialog-information-symbolic";
    entries[0].build_page = generic_build_overview;
    entries[1].name = "Actions";  entries[1].icon = "system-run-symbolic";
    entries[1].build_page = generic_build_actions;
    entries[2].name = "Output";   entries[2].icon = "utilities-terminal-symbolic";
    entries[2].build_page = generic_build_output;
    *out_count = 3;
    (void) spec;
    return entries;
}

/* Per-module data factory — trivially one struct. */
static gpointer
generic_module_data_new(AppState *state, const ModuleSpec *spec)
{
    GenericModulePage *g = g_new0(GenericModulePage, 1);
    g->state = state;
    g->spec = spec;
    return g;
}

/* ==================================================================== */
/*  Note: in a real build, register each module here — one function per */
/*  module_id so the registry can construct its data.                    */
/* ==================================================================== */

static gpointer _new_deps(AppState *s)     { return generic_module_data_new(s, module_spec_for("00_deps")); }
static gpointer _new_cred(AppState *s)     { return generic_module_data_new(s, module_spec_for("01_cred_validate")); }
static gpointer _new_inv(AppState *s)      { return generic_module_data_new(s, module_spec_for("02_inventory")); }
static gpointer _new_bucket(AppState *s)   { return generic_module_data_new(s, module_spec_for("03_bucket_enum")); }
static gpointer _new_takeover(AppState *s) { return generic_module_data_new(s, module_spec_for("04_takeover")); }
static gpointer _new_privesc(AppState *s)  { return generic_module_data_new(s, module_spec_for("05_iam_privesc")); }
static gpointer _new_chains(AppState *s)   { return generic_module_data_new(s, module_spec_for("06_role_chains")); }
static gpointer _new_audit(AppState *s)    { return generic_module_data_new(s, module_spec_for("07_policy_audit")); }
static gpointer _new_secrets(AppState *s)  { return generic_module_data_new(s, module_spec_for("08_secrets_scan")); }
static gpointer _new_ssrf(AppState *s)     { return generic_module_data_new(s, module_spec_for("09_ssrf_imds")); }
static gpointer _new_imds2(AppState *s)    { return generic_module_data_new(s, module_spec_for("10_imdsv2_bypass")); }
static gpointer _new_userdata(AppState *s) { return generic_module_data_new(s, module_spec_for("11_user_data")); }
static gpointer _new_lambda(AppState *s)   { return generic_module_data_new(s, module_spec_for("12_lambda_dump")); }

/* ==================================================================== */
/*  Module registry                                                      */
/* ==================================================================== */

typedef struct {
    const char *module_id;
    ModuleSubmenuEntry *entries;
    int n_entries;
    gpointer (*get_module_data)(AppState *);
} ModuleRegistryEntry;

static ModuleRegistryEntry *module_registry = NULL;
static int module_registry_size = 0;

static void
module_registry_register(const char *id, ModuleSubmenuEntry *entries,
                         int n, gpointer (*get_data)(AppState *))
{
    module_registry = g_realloc(module_registry,
        (module_registry_size + 1) * sizeof(ModuleRegistryEntry));
    module_registry[module_registry_size].module_id = id;
    module_registry[module_registry_size].entries = entries;
    module_registry[module_registry_size].n_entries = n;
    module_registry[module_registry_size].get_module_data = get_data;
    module_registry_size++;
}

static ModuleRegistryEntry *
module_registry_find(const char *id)
{
    for (int i = 0; i < module_registry_size; i++)
        if (g_strcmp0(module_registry[i].module_id, id) == 0)
            return &module_registry[i];
    return NULL;
}

static void
register_all_modules(void)
{
    int n;
    ModuleSubmenuEntry *e;
    for (guint i = 0; i < G_N_ELEMENTS(module_specs); i++) {
        const ModuleSpec *spec = &module_specs[i];
        e = build_entries_for(spec, &n);
        if (g_strcmp0(spec->id, "00_deps") == 0)
            module_registry_register(spec->id, e, n, _new_deps);
        else if (g_strcmp0(spec->id, "01_cred_validate") == 0)
            module_registry_register(spec->id, e, n, _new_cred);
        else if (g_strcmp0(spec->id, "02_inventory") == 0)
            module_registry_register(spec->id, e, n, _new_inv);
        else if (g_strcmp0(spec->id, "03_bucket_enum") == 0)
            module_registry_register(spec->id, e, n, _new_bucket);
        else if (g_strcmp0(spec->id, "04_takeover") == 0)
            module_registry_register(spec->id, e, n, _new_takeover);
        else if (g_strcmp0(spec->id, "05_iam_privesc") == 0)
            module_registry_register(spec->id, e, n, _new_privesc);
        else if (g_strcmp0(spec->id, "06_role_chains") == 0)
            module_registry_register(spec->id, e, n, _new_chains);
        else if (g_strcmp0(spec->id, "07_policy_audit") == 0)
            module_registry_register(spec->id, e, n, _new_audit);
        else if (g_strcmp0(spec->id, "08_secrets_scan") == 0)
            module_registry_register(spec->id, e, n, _new_secrets);
        else if (g_strcmp0(spec->id, "09_ssrf_imds") == 0)
            module_registry_register(spec->id, e, n, _new_ssrf);
        else if (g_strcmp0(spec->id, "10_imdsv2_bypass") == 0)
            module_registry_register(spec->id, e, n, _new_imds2);
        else if (g_strcmp0(spec->id, "11_user_data") == 0)
            module_registry_register(spec->id, e, n, _new_userdata);
        else if (g_strcmp0(spec->id, "12_lambda_dump") == 0)
            module_registry_register(spec->id, e, n, _new_lambda);
    }
}

/* ==================================================================== */
/*  Module page chrome (header, submenu, stack)                          */
/* ==================================================================== */

static void
module_page_submenu_activated(GtkListBox *lb, GtkListBoxRow *row,
                              gpointer ud)
{
    (void) lb; (void) ud;
    GtkWidget *page = g_object_get_data(G_OBJECT(row), "page");
    if (page != NULL)
        gtk_stack_set_visible_child_name(
            GTK_STACK(g_object_get_data(G_OBJECT(row), "stack")),
            g_object_get_data(G_OBJECT(row), "name"));
}

static GtkWidget *
create_closable_tab_label(const char *title, GtkWidget *page,
                          AppState *state)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *label = gtk_label_new(title);
    GtkWidget *close = gtk_button_new_from_icon_name("window-close-symbolic");

    gtk_widget_add_css_class(box, "tab-label");
    gtk_widget_add_css_class(close, "flat");
    gtk_widget_add_css_class(close, "tab-close");
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(label), 40);
    gtk_widget_set_size_request(label, 120, -1);

    g_object_set_data(G_OBJECT(close), "page", page);
    g_object_set_data(G_OBJECT(close), "state", state);
    g_object_set_data(G_OBJECT(box), "page", page);

    g_signal_connect(close, "clicked", G_CALLBACK(close_tab_clicked), state);
    gtk_box_append(GTK_BOX(box), label);
    gtk_box_append(GTK_BOX(box), close);
    return box;
}

/* Forward declaration used by close_tab_clicked */
static void close_tab_clicked(GtkButton *button, gpointer user_data);

static void
module_page_free(gpointer data)
{
    g_free(data);
}

static GtkWidget *
create_module_page(AppState *state, const ModuleDefinition *module,
                   ModuleSubmenuEntry *entries, int n_entries,
                   gpointer module_data)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *icon = gtk_image_new_from_icon_name(module->icon);
    GtkWidget *title = gtk_label_new(module->name);
    GtkWidget *cat = gtk_label_new(module->category);
    GtkWidget *pill = gtk_label_new("Idle");
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    GtkWidget *submenu = gtk_list_box_new();
    GtkWidget *submenu_scroll = gtk_scrolled_window_new();
    GtkWidget *stack = gtk_stack_new();

    gtk_widget_add_css_class(page, "module-page");
    gtk_widget_add_css_class(header, "module-header");
    gtk_widget_add_css_class(icon, "module-header-icon");
    gtk_widget_add_css_class(title, "module-header-title");
    gtk_widget_add_css_class(cat, "module-header-category");
    gtk_widget_add_css_class(pill, "status-pill");
    gtk_widget_add_css_class(pill, "status-idle");
    gtk_widget_add_css_class(submenu, "module-submenu");
    gtk_widget_add_css_class(submenu_scroll, "module-submenu-scroll");
    gtk_widget_add_css_class(stack, "module-stack");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 18);
    gtk_widget_set_hexpand(title, TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(title), PANGO_ELLIPSIZE_END);

    gtk_box_append(GTK_BOX(header), icon);
    gtk_box_append(GTK_BOX(header), title);
    gtk_box_append(GTK_BOX(header), cat);
    gtk_box_append(GTK_BOX(header), pill);

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(submenu),
                                    GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(submenu), TRUE);

    for (int i = 0; i < n_entries; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *row_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *r_icon = gtk_image_new_from_icon_name(entries[i].icon);
        GtkWidget *r_lbl = gtk_label_new(entries[i].name);

        gtk_widget_add_css_class(row, "module-submenu-row");
        gtk_widget_add_css_class(r_icon, "module-submenu-icon");
        gtk_widget_add_css_class(r_lbl, "module-submenu-label");
        gtk_image_set_pixel_size(GTK_IMAGE(r_icon), 14);
        gtk_label_set_xalign(GTK_LABEL(r_lbl), 0.0f);
        gtk_widget_set_hexpand(r_lbl, TRUE);
        gtk_box_append(GTK_BOX(row_box), r_icon);
        gtk_box_append(GTK_BOX(row_box), r_lbl);
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), row_box);

        g_object_set_data_full(G_OBJECT(row), "page",
            gtk_stack_add_titled(GTK_STACK(stack),
                                 entries[i].build_page(state, module_data),
                                 entries[i].name, entries[i].name),
            NULL);
        g_object_set_data(G_OBJECT(row), "stack", stack);
        g_object_set_data_full(G_OBJECT(row), "name",
                               g_strdup(entries[i].name), g_free);
        g_object_set_data(G_OBJECT(row), "index", GINT_TO_POINTER(i));
        g_signal_connect(submenu, "row-activated",
                         G_CALLBACK(module_page_submenu_activated), state);
        gtk_list_box_append(GTK_LIST_BOX(submenu), row);
    }

    if (n_entries > 0) {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), entries[0].name);
        GtkWidget *first = gtk_widget_get_first_child(submenu);
        if (first) gtk_list_box_select_row(GTK_LIST_BOX(submenu),
                                           GTK_LIST_BOX_ROW(first));
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(submenu_scroll),
                                  submenu);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(submenu_scroll),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(submenu_scroll, 200, -1);

    gtk_paned_set_start_child(GTK_PANED(paned), submenu_scroll);
    gtk_paned_set_end_child(GTK_PANED(paned), stack);
    gtk_paned_set_position(GTK_PANED(paned), 200);
    gtk_widget_set_hexpand(paned, TRUE);
    gtk_widget_set_vexpand(paned, TRUE);

    gtk_box_append(GTK_BOX(page), header);
    gtk_box_append(GTK_BOX(page), paned);

    g_object_set_data_full(G_OBJECT(page), "module-id",
                           g_strdup(module->id), g_free);
    g_object_set_data_full(G_OBJECT(page), "module-page",
                           g_new0(char, 1), module_page_free);
    g_object_set_data(G_OBJECT(page), "status-pill", pill);
    return page;
}

static GtkWidget *
find_module_page(AppState *state, const char *id)
{
    int pages = gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->notebook));
    for (int i = 0; i < pages; i++) {
        GtkWidget *page = gtk_notebook_get_nth_page(
            GTK_NOTEBOOK(state->notebook), i);
        const char *pid = g_object_get_data(G_OBJECT(page), "module-id");
        if (g_strcmp0(pid, id) == 0) return page;
    }
    return NULL;
}

static void
close_tab_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    GtkWidget *page = g_object_get_data(G_OBJECT(button), "page");
    if (state == NULL || page == NULL) return;
    int idx = gtk_notebook_page_num(GTK_NOTEBOOK(state->notebook), page);
    if (idx > 0) gtk_notebook_remove_page(GTK_NOTEBOOK(state->notebook), idx);
}

static void
open_module(AppState *state, const ModuleDefinition *module)
{
    GtkWidget *existing = find_module_page(state, module->id);
    if (existing != NULL) {
        int idx = gtk_notebook_page_num(GTK_NOTEBOOK(state->notebook), existing);
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), idx);
        return;
    }

    if (state->usage != NULL) {
        gpointer v = g_hash_table_lookup(state->usage, module->id);
        g_hash_table_insert(state->usage, g_strdup(module->id),
                            GINT_TO_POINTER(GPOINTER_TO_INT(v) + 1));
    }

    ModuleRegistryEntry *reg = module_registry_find(module->id);
    GtkWidget *page;
    gpointer module_data = NULL;

    if (reg != NULL) {
        module_data = reg->get_module_data ? reg->get_module_data(state) : NULL;
        page = create_module_page(state, module, reg->entries,
                                  reg->n_entries, module_data);
    } else {
        page = gtk_label_new("(module not registered)");
    }

    GtkWidget *tab = create_closable_tab_label(module->name, page, state);
    int index = gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
                                          page, tab);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), index);
    recent_record(state, module->id);
    append_event(state, g_strdup_printf("Opened: %s", module->name));
}

/* ==================================================================== */
/*  Dashboard                                                            */
/* ==================================================================== */

static void
tile_right_click(GtkGestureClick *g, int np, double x, double y, gpointer ud);

static void
dashboard_populate(AppState *state)
{
    GtkWidget *grid = NULL;
    int width, cols;

    /* The dashboard_flow pointer isn't a field in this trimmed
       implementation — we create it fresh in create_dashboard and
       store it on the widget. For brevity we only rebuild once on
       construction. */

    (void) state; (void) grid; (void) width; (void) cols;
}

static GtkWidget *
create_dashboard(AppState *state)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 7);
    GtkWidget *title = gtk_label_new("Command Dashboard");
    GtkWidget *subtitle = gtk_label_new(
        "cloudsting — cloud & API attack surface toolkit. "
        "Right-click a tile to favorite it.");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *grid = gtk_grid_new();

    gtk_widget_add_css_class(outer, "dashboard");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(subtitle, "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(subtitle), TRUE);

    gtk_grid_set_column_spacing(GTK_GRID(grid), 9);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 9);
    gtk_widget_set_margin_top(grid, 10);
    gtk_widget_set_margin_start(grid, 4);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), grid);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_box_append(GTK_BOX(header), title);
    gtk_box_append(GTK_BOX(header), subtitle);
    gtk_box_append(GTK_BOX(outer), header);
    gtk_box_append(GTK_BOX(outer), scroll);

    for (guint i = 0; i < G_N_ELEMENTS(modules); i++) {
        const ModuleDefinition *mod = &modules[i];
        GtkWidget *button = gtk_button_new();
        GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        GtkWidget *top_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        GtkWidget *cat = gtk_label_new(mod->category);
        GtkWidget *star = gtk_label_new(
            favorites_contains(state, mod->id) ? "\u2605" : "\u2606");
        GtkWidget *icon = gtk_image_new_from_icon_name(mod->icon);
        GtkWidget *name = gtk_label_new(mod->name);

        gtk_widget_add_css_class(button, "module-card");
        gtk_widget_add_css_class(cat, "module-card-category");
        gtk_widget_add_css_class(star, "module-card-star");
        gtk_widget_add_css_class(icon, "module-card-icon");
        gtk_widget_add_css_class(name, "module-card-title");
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 56);
        gtk_widget_set_halign(icon, GTK_ALIGN_CENTER);
        gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);
        gtk_label_set_xalign(GTK_LABEL(cat), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(star), 1.0f);
        gtk_widget_set_halign(cat, GTK_ALIGN_START);
        gtk_widget_set_halign(star, GTK_ALIGN_END);
        gtk_widget_set_hexpand(cat, TRUE);
        gtk_label_set_ellipsize(GTK_LABEL(name), PANGO_ELLIPSIZE_END);
        gtk_label_set_max_width_chars(GTK_LABEL(name), 12);
        gtk_label_set_xalign(GTK_LABEL(name), 0.5f);
        gtk_widget_set_halign(name, GTK_ALIGN_CENTER);
        gtk_widget_set_size_request(button, 170, 120);
        gtk_widget_set_hexpand(button, FALSE);
        gtk_widget_set_halign(button, GTK_ALIGN_START);
        gtk_widget_set_valign(button, GTK_ALIGN_START);
        if (mod->description) gtk_widget_set_tooltip_text(button, mod->description);

        gtk_box_append(GTK_BOX(top_row), cat);
        gtk_box_append(GTK_BOX(top_row), star);
        gtk_box_append(GTK_BOX(inner), top_row);
        gtk_box_append(GTK_BOX(inner), icon);
        gtk_box_append(GTK_BOX(inner), name);
        gtk_button_set_child(GTK_BUTTON(button), inner);

        g_object_set_data(G_OBJECT(button), "module", (gpointer) mod);
        g_object_set_data(G_OBJECT(button), "module-id", (gpointer) mod->id);
        g_signal_connect_swapped(button, "clicked",
                                 G_CALLBACK(open_module), state);

        {
            GtkGesture *g = gtk_gesture_click_new();
            gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(g),
                                          GDK_BUTTON_SECONDARY);
            g_signal_connect(g, "pressed", G_CALLBACK(tile_right_click), state);
            gtk_widget_add_controller(button, GTK_EVENT_CONTROLLER(g));
        }

        gtk_grid_attach(GTK_GRID(grid), button,
                        (int) (i % 5), (int) (i / 5), 1, 1);
    }

    return outer;
}

static void
tile_right_click(GtkGestureClick *g, int np, double x, double y, gpointer ud)
{
    AppState *state = ud;
    GtkWidget *button = gtk_event_controller_get_widget(
        GTK_EVENT_CONTROLLER(g));
    const char *id = g_object_get_data(G_OBJECT(button), "module-id");
    const char *name = g_object_get_data(G_OBJECT(button), "module-name");
    GtkWidget *popover, *box, *btn_open, *btn_fav;
    gboolean is_fav;
    GdkRectangle rect;

    (void) np; (void) name;
    if (id == NULL) return;

    is_fav = favorites_contains(state, id);
    popover = gtk_popover_new();
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    gtk_widget_set_margin_start(box, 6);
    gtk_widget_set_margin_end(box, 6);

    btn_open = gtk_button_new_with_label("Open module");
    btn_fav = gtk_button_new_with_label(
        is_fav ? "\u2605  Remove from favorites" : "\u2606  Add to favorites");
    g_object_set_data(G_OBJECT(btn_open), "module",
                      g_object_get_data(G_OBJECT(button), "module"));
    g_object_set_data(G_OBJECT(btn_fav), "module-id", (gpointer) id);

    g_signal_connect(btn_open, "clicked",
                     G_CALLBACK(open_module), state);
    g_object_set_data(G_OBJECT(btn_fav), "action", "toggle-fav");
    g_signal_connect(btn_fav, "clicked",
                     G_CALLBACK(tile_fav_clicked), state);

    gtk_box_append(GTK_BOX(box), btn_open);
    gtk_box_append(GTK_BOX(box), btn_fav);
    gtk_popover_set_child(GTK_POPOVER(popover), box);
    gtk_popover_set_has_arrow(GTK_POPOVER(popover), FALSE);

    rect.x = (int) x; rect.y = (int) y;
    rect.width = 1; rect.height = 1;
    gtk_popover_set_pointing_to(GTK_POPOVER(popover), &rect);
    gtk_popover_set_position(GTK_POPOVER(popover), GTK_POS_RIGHT);
    gtk_widget_set_parent(popover, button);
    gtk_popover_popup(GTK_POPOVER(popover));
}

static void
tile_fav_clicked(GtkButton *b, gpointer ud)
{
    AppState *state = ud;
    const char *id = g_object_get_data(G_OBJECT(b), "module-id");
    GtkWidget *pop = gtk_widget_get_ancestor(GTK_WIDGET(b), GTK_TYPE_POPOVER);
    if (pop) gtk_popover_popdown(GTK_POPOVER(pop));
    if (id) {
        state->star_pop_id = id;
        favorites_toggle(state, id);
    }
}

/* ==================================================================== */
/*  Sidebar                                                              */
/* ==================================================================== */

static void
sidebar_filter_changed(GtkSearchEntry *entry, gpointer ud)
{
    GtkWidget *box = ud;
    const char *q = gtk_editable_get_text(GTK_EDITABLE(entry));
    gboolean has = (q != NULL && *q != '\0');
    g_autofree char *needle = has ? g_utf8_strdown(q, -1) : NULL;
    GtkWidget *child = gtk_widget_get_first_child(box);

    while (child != NULL) {
        const ModuleDefinition *mod = g_object_get_data(G_OBJECT(child), "module");
        gboolean is_section = g_object_get_data(G_OBJECT(child), "sidebar-section") != NULL;

        if (mod != NULL) {
            gboolean show = TRUE;
            if (needle) {
                g_autofree char *n = g_utf8_strdown(mod->name, -1);
                g_autofree char *c = g_utf8_strdown(mod->category, -1);
                show = strstr(n, needle) != NULL || strstr(c, needle) != NULL;
            }
            gtk_widget_set_visible(child, show);
        } else if (is_section) {
            gtk_widget_set_visible(child, !has);
        }
        child = gtk_widget_get_next_sibling(child);
    }
}

static GtkWidget *
create_sidebar(AppState *state)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *search = gtk_search_entry_new();
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    GtkWidget *title = gtk_label_new("MODULES");

    gtk_widget_add_css_class(outer, "sidebar");
    gtk_widget_add_css_class(title, "sidebar-title");
    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search), "Filter…");
    gtk_widget_set_margin_start(search, 6);
    gtk_widget_set_margin_end(search, 6);
    gtk_widget_set_margin_top(search, 6);
    gtk_widget_set_margin_bottom(search, 4);
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_hexpand(outer, FALSE);
    gtk_widget_set_vexpand(outer, TRUE);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_box_append(GTK_BOX(box), title);

    {
        const char *seen[32];
        guint n_seen = 0;

        for (guint m = 0; m < G_N_ELEMENTS(modules); m++) {
            guint j;
            gboolean skip = FALSE;
            for (j = 0; j < n_seen; j++)
                if (g_strcmp0(seen[j], modules[m].category) == 0) { skip = TRUE; break; }
            if (skip) continue;
            if (n_seen < 32) seen[n_seen++] = modules[m].category;

            GtkWidget *category = gtk_label_new(modules[m].category);
            gtk_widget_add_css_class(category, "sidebar-section");
            gtk_widget_set_halign(category, GTK_ALIGN_FILL);
            gtk_widget_set_hexpand(category, TRUE);
            gtk_label_set_xalign(GTK_LABEL(category), 0.5f);
            g_object_set_data(G_OBJECT(category), "sidebar-section",
                              GINT_TO_POINTER(1));
            gtk_box_append(GTK_BOX(box), category);

            for (guint k = 0; k < G_N_ELEMENTS(modules); k++) {
                if (g_strcmp0(modules[k].category, modules[m].category) != 0) continue;
                GtkWidget *b = gtk_button_new();
                GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 7);
                GtkWidget *icon = gtk_image_new_from_icon_name(modules[k].icon);
                GtkWidget *label = gtk_label_new(modules[k].name);

                gtk_image_set_pixel_size(GTK_IMAGE(icon), 22);
                gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
                gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
                gtk_widget_set_hexpand(label, TRUE);
                gtk_box_append(GTK_BOX(row), icon);
                gtk_box_append(GTK_BOX(row), label);
                gtk_button_set_child(GTK_BUTTON(b), row);

                g_object_set_data(G_OBJECT(b), "module", (gpointer) &modules[k]);
                g_object_set_data(G_OBJECT(b), "row-label", label);
                g_signal_connect_swapped(b, "clicked",
                                         G_CALLBACK(open_module), state);
                gtk_box_append(GTK_BOX(box), b);
            }
        }
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), box);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_box_append(GTK_BOX(outer), search);
    gtk_box_append(GTK_BOX(outer), scroll);
    gtk_widget_set_size_request(outer, 58, -1);
    g_signal_connect(search, "search-changed",
                     G_CALLBACK(sidebar_filter_changed), box);
    state->sidebar_box = box;
    return outer;
}

/* ==================================================================== */
/*  Session panel (target panel in cloud context)                        */
/* ==================================================================== */

static GtkWidget *
create_session_panel(AppState *state)
{
    GtkWidget *panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *title = gtk_label_new("SESSION");
    GtkWidget *stack = gtk_stack_new();

    GtkWidget *empty = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *empty_hint = gtk_label_new(
        "No active cloud session.\n\n"
        "Run the Credential Validator module or configure\n"
        "AWS credentials to populate this panel.");
    gtk_widget_add_css_class(empty_hint, "session-empty");
    gtk_widget_set_valign(empty, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(empty_hint, GTK_ALIGN_CENTER);
    gtk_label_set_wrap(GTK_LABEL(empty_hint), TRUE);
    gtk_label_set_justify(GTK_LABEL(empty_hint), GTK_JUSTIFY_CENTER);
    gtk_box_append(GTK_BOX(empty), empty_hint);

    GtkWidget *pop = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *pop_header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *header_spacer = gtk_label_new("");
    GtkWidget *badge = gtk_label_new("");
    GtkWidget *refresh = gtk_button_new_from_icon_name("view-refresh-symbolic");
    GtkWidget *copy = gtk_button_new_from_icon_name("edit-copy-symbolic");

    gtk_widget_add_css_class(pop, "session-populated");
    gtk_widget_add_css_class(badge, "session-badge");
    gtk_widget_add_css_class(refresh, "flat");
    gtk_widget_add_css_class(copy, "flat");
    gtk_widget_set_hexpand(header_spacer, TRUE);
    gtk_widget_set_valign(refresh, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(copy, GTK_ALIGN_CENTER);
    gtk_widget_set_tooltip_text(refresh, "Refresh session info");
    gtk_widget_set_tooltip_text(copy, "Copy session info");

    gtk_box_append(GTK_BOX(pop_header), header_spacer);
    gtk_box_append(GTK_BOX(pop_header), badge);
    gtk_box_append(GTK_BOX(pop_header), refresh);
    gtk_box_append(GTK_BOX(pop_header), copy);

    GtkWidget *caps[4] = {
        gtk_label_new("ACCOUNT"),
        gtk_label_new("REGION"),
        gtk_label_new("IDENTITY"),
        gtk_label_new("LAST SCAN"),
    };
    GtkWidget *vals[4] = {
        gtk_label_new("—"),
        gtk_label_new("—"),
        gtk_label_new("—"),
        gtk_label_new("—"),
    };

    for (int i = 0; i < 4; i++) {
        gtk_widget_add_css_class(caps[i], "session-caption");
        gtk_widget_add_css_class(vals[i], "session-value");
        gtk_label_set_xalign(GTK_LABEL(caps[i]), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(vals[i]), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(vals[i]), PANGO_ELLIPSIZE_MIDDLE);
        gtk_label_set_selectable(GTK_LABEL(vals[i]), TRUE);
    }

    state->session_account = vals[0];
    state->session_region = vals[1];
    state->session_identity = vals[2];
    state->session_last_scan = vals[3];
    state->session_badge = badge;

    gtk_box_append(GTK_BOX(pop), pop_header);
    for (int i = 0; i < 4; i++) {
        gtk_box_append(GTK_BOX(pop), caps[i]);
        gtk_box_append(GTK_BOX(pop), vals[i]);
    }

    /* Footer: quick-jump buttons */
    GtkWidget *foot = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_margin_top(foot, 8);
    gtk_widget_set_halign(foot, GTK_ALIGN_START);
    static const struct { const char *label; const char *id; } q[] = {
        { "Validate", "01_cred_validate" },
        { "Inventory", "02_inventory" },
        { "Buckets", "03_bucket_enum" },
    };
    for (guint qi = 0; qi < G_N_ELEMENTS(q); qi++) {
        GtkWidget *b = gtk_button_new_with_label(q[qi].label);
        gtk_widget_add_css_class(b, "flat");
        g_object_set_data(G_OBJECT(b), "jump-id", (gpointer) q[qi].id);
        g_signal_connect(b, "clicked", G_CALLBACK(jump_clicked), state);
        gtk_box_append(GTK_BOX(foot), b);
    }
    gtk_box_append(GTK_BOX(pop), foot);

    gtk_stack_add_named(GTK_STACK(stack), empty, "empty");
    gtk_stack_add_named(GTK_STACK(stack), pop, "populated");
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "populated");

    gtk_widget_add_css_class(panel, "panel");
    gtk_widget_add_css_class(title, "panel-title");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_hexpand(panel, FALSE);
    gtk_widget_set_vexpand(panel, TRUE);
    gtk_widget_set_margin_start(stack, 12);
    gtk_widget_set_margin_end(stack, 12);
    gtk_widget_set_margin_bottom(stack, 12);

    gtk_box_append(GTK_BOX(panel), title);
    gtk_box_append(GTK_BOX(panel), stack);

    gtk_widget_set_size_request(panel, 150, -1);

    state->session_stack = stack;
    g_signal_connect_swapped(copy, "clicked",
                             G_CALLBACK(session_copy_clicked), state);
    g_signal_connect_swapped(refresh, "clicked",
                             G_CALLBACK(session_refresh_clicked), state);

    return panel;
}

static void
jump_clicked(GtkButton *b, gpointer ud)
{
    AppState *state = ud;
    const char *id = g_object_get_data(G_OBJECT(b), "jump-id");
    if (id == NULL) return;
    for (guint i = 0; i < G_N_ELEMENTS(modules); i++)
        if (g_strcmp0(modules[i].id, id) == 0) {
            open_module(state, &modules[i]);
            return;
        }
}

static void
session_copy_clicked(GtkButton *b, gpointer ud)
{
    AppState *state = ud;
    (void) b;
    GdkClipboard *cb = gdk_display_get_clipboard(gdk_display_get_default());
    const char *acct = state->session_account
        ? gtk_label_get_text(GTK_LABEL(state->session_account)) : "—";
    const char *region = state->session_region
        ? gtk_label_get_text(GTK_LABEL(state->session_region)) : "—";
    const char *ident = state->session_identity
        ? gtk_label_get_text(GTK_LABEL(state->session_identity)) : "—";
    g_autofree gchar *txt = g_strdup_printf(
        "Account: %s\nRegion:  %s\nIdentity: %s\n", acct, region, ident);
    gdk_clipboard_set_text(cb, txt);
    show_toast(state, "Session copied");
}

static void
session_refresh_clicked(GtkButton *b, gpointer ud)
{
    AppState *state = ud;
    (void) b;
    session_refresh_idle(state);
    show_toast(state, "Session refresh requested");
}

static gboolean
session_refresh_idle(gpointer ud)
{
    AppState *state = ud;
    const char *argv[] = { SCRIPT("06_role_chains.sh"), "--whoami", NULL };
    g_autoptr(GError) error = NULL;
    GSubprocess *p = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (p == NULL) return G_SOURCE_REMOVE;

    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;
    if (g_subprocess_communicate_utf8(p, NULL, NULL, &out, &err, &error)) {
        if (out != NULL) {
            g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
            for (guint i = 0; lines[i] != NULL; i++) {
                g_auto(GStrv) kv = g_strsplit(lines[i], "\t", 2);
                if (g_strv_length(kv) != 2) continue;
                if (g_strcmp0(kv[0], "account") == 0 && state->session_account)
                    gtk_label_set_text(GTK_LABEL(state->session_account), kv[1]);
                else if (g_strcmp0(kv[0], "user") == 0 && state->session_identity)
                    gtk_label_set_text(GTK_LABEL(state->session_identity), kv[1]);
            }
            if (state->session_badge)
                gtk_label_set_text(GTK_LABEL(state->session_badge),
                                   "AWS");
        }
    }
    g_object_unref(p);
    state->session_last_refresh = g_get_real_time();
    return G_SOURCE_REMOVE;
}

/* ==================================================================== */
/*  Event drawer                                                         */
/* ==================================================================== */

static void
event_clear_clicked(GtkButton *b, gpointer ud)
{
    AppState *state = ud;
    (void) b;
    if (state->event_buffer)
        gtk_text_buffer_set_text(state->event_buffer, "", 0);
    if (state->event_log)
        g_ptr_array_set_size(state->event_log, 0);
}

static void
event_copy_clicked(GtkButton *b, gpointer ud)
{
    AppState *state = ud;
    (void) b;
    GtkTextIter start, end;
    if (!state->event_buffer) return;
    gtk_text_buffer_get_bounds(state->event_buffer, &start, &end);
    g_autofree gchar *text = gtk_text_buffer_get_text(
        state->event_buffer, &start, &end, FALSE);
    GdkClipboard *cb = gdk_display_get_clipboard(gdk_display_get_default());
    gdk_clipboard_set_text(cb, text);
    show_toast(state, "Events copied");
}

static void
event_filter_changed(GtkWidget *w, gpointer ud)
{
    (void) w; (void) ud;
    /* Simplified: rebuild if search/toggles used later */
}

static GtkWidget *
create_event_drawer(AppState *state)
{
    GtkWidget *drawer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *title = gtk_label_new("EVENTS / LOG");
    GtkWidget *search = gtk_search_entry_new();
    GtkWidget *t_info = gtk_toggle_button_new_with_label("info");
    GtkWidget *t_warn = gtk_toggle_button_new_with_label("warn");
    GtkWidget *t_err  = gtk_toggle_button_new_with_label("err");
    GtkWidget *t_ok   = gtk_toggle_button_new_with_label("ok");
    GtkWidget *clear = gtk_button_new_with_label("Clear");
    GtkWidget *copy = gtk_button_new_with_label("Copy");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    GtkTextBuffer *buf;

    gtk_widget_add_css_class(drawer, "event-drawer");
    gtk_widget_add_css_class(title, "event-title");
    gtk_widget_add_css_class(view, "event-view");
    gtk_widget_add_css_class(clear, "flat");
    gtk_widget_add_css_class(copy, "flat");
    gtk_widget_add_css_class(t_info, "flat");
    gtk_widget_add_css_class(t_warn, "flat");
    gtk_widget_add_css_class(t_err, "flat");
    gtk_widget_add_css_class(t_ok, "flat");

    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_valign(clear, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(copy, GTK_ALIGN_CENTER);
    gtk_widget_set_size_request(search, 160, -1);
    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search), "Filter…");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_info), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_warn), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_err), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(t_ok), TRUE);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_NONE);

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    state->event_buffer = buf;
    state->event_view = view;
    state->event_search = search;
    state->event_toggles[EVT_INFO] = t_info;
    state->event_toggles[EVT_WARN] = t_warn;
    state->event_toggles[EVT_ERR] = t_err;
    state->event_toggles[EVT_OK] = t_ok;

    gtk_text_buffer_create_tag(buf, "evt-info", "foreground", "#c8d6e2", NULL);
    gtk_text_buffer_create_tag(buf, "evt-warn", "foreground", "#ffab00", NULL);
    gtk_text_buffer_create_tag(buf, "evt-err",  "foreground", "#ff5252", NULL);
    gtk_text_buffer_create_tag(buf, "evt-ok",   "foreground", "#00e676", NULL);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    gtk_box_append(GTK_BOX(header), title);
    gtk_box_append(GTK_BOX(header), search);
    gtk_box_append(GTK_BOX(header), t_info);
    gtk_box_append(GTK_BOX(header), t_warn);
    gtk_box_append(GTK_BOX(header), t_err);
    gtk_box_append(GTK_BOX(header), t_ok);
    gtk_box_append(GTK_BOX(header), clear);
    gtk_box_append(GTK_BOX(header), copy);

    gtk_box_append(GTK_BOX(drawer), header);
    gtk_box_append(GTK_BOX(drawer), scroll);
    gtk_widget_set_size_request(drawer, -1, 140);

    g_signal_connect(clear, "clicked", G_CALLBACK(event_clear_clicked), state);
    g_signal_connect(copy, "clicked", G_CALLBACK(event_copy_clicked), state);
    g_signal_connect(search, "search-changed",
                     G_CALLBACK(event_filter_changed), state);

    return drawer;
}

/* ==================================================================== */
/*  Header bar                                                           */
/* ==================================================================== */

static gchar *
cs_version_label(void)
{
    g_autofree gchar *contents = NULL;
    if (g_file_get_contents(cs_path("VERSION"), &contents, NULL, NULL)) {
        g_strstrip(contents);
        if (*contents != '\0') return g_strdup_printf("cloudsting v%s", contents);
    }
    return g_strdup("cloudsting");
}

static GtkWidget *
create_status_item(const char *caption, const char *value,
                   GtkWidget **value_out)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *cap = gtk_label_new(caption);
    GtkWidget *val = gtk_label_new(value);

    gtk_widget_add_css_class(box, "toolbar-item");
    gtk_widget_add_css_class(cap, "toolbar-caption");
    gtk_widget_add_css_class(val, "toolbar-value");
    gtk_label_set_ellipsize(GTK_LABEL(val), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(val), 22);
    gtk_widget_set_halign(cap, GTK_ALIGN_START);
    gtk_widget_set_halign(val, GTK_ALIGN_START);

    gtk_box_append(GTK_BOX(box), cap);
    gtk_box_append(GTK_BOX(box), val);
    if (value_out) *value_out = val;
    return box;
}

static GtkWidget *
create_header(AppState *state)
{
    GtkWidget *header = gtk_header_bar_new();
    GtkWidget *title = gtk_label_new(cs_version_label());
    GtkWidget *terminal = gtk_button_new_from_icon_name("utilities-terminal-symbolic");
    GtkWidget *sidebar_toggle = gtk_toggle_button_new_with_label("Modules");
    GtkWidget *session_toggle = gtk_toggle_button_new_with_label("Session");
    GtkWidget *events_toggle = gtk_toggle_button_new_with_label("Events");
    GtkWidget *iface_item, *region_item, *ident_item;

    gtk_widget_add_css_class(title, "header-title");
    gtk_widget_add_css_class(terminal, "accent");
    gtk_label_set_ellipsize(GTK_LABEL(title), PANGO_ELLIPSIZE_END);
    gtk_widget_set_tooltip_text(terminal, "Raw Terminal (Ctrl+T)");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(sidebar_toggle), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(session_toggle), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(events_toggle), TRUE);

    g_signal_connect(terminal, "clicked", G_CALLBACK(open_terminal_clicked), state);
    g_signal_connect(sidebar_toggle, "toggled",
                     G_CALLBACK(toggle_widget), state->sidebar);
    g_signal_connect(session_toggle, "toggled",
                     G_CALLBACK(toggle_widget), state->session_revealer);
    g_signal_connect(events_toggle, "toggled",
                     G_CALLBACK(toggle_widget), state->event_drawer);

    iface_item = create_status_item("PROVIDER", "—", &state->hdr_account_value);
    region_item = create_status_item("REGION", "—", &state->hdr_region_value);
    ident_item = create_status_item("IDENTITY", "—", &state->hdr_identity_value);

    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), sidebar_toggle);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), iface_item);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), region_item);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), ident_item);
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), title);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), terminal);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), events_toggle);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), session_toggle);

    return header;
}

static void
toggle_widget(GtkToggleButton *b, gpointer ud)
{
    gtk_widget_set_visible(GTK_WIDGET(ud),
                           gtk_toggle_button_get_active(b));
}

/* ==================================================================== */
/*  Raw Terminal                                                         */
/* ==================================================================== */

static GtkWidget *
create_terminal_page_cmd(AppState *state, const char *command)
{
    GtkWidget *terminal = vte_terminal_new();
    const char *shell = g_getenv("SHELL");
    if (shell == NULL || *shell == '\0') shell = "/bin/bash";

    char *argv[4];
    argv[0] = (char *) shell;
    if (command && *command) { argv[1] = "-c"; argv[2] = (char *) command; argv[3] = NULL; }
    else argv[1] = NULL;

    gtk_widget_set_hexpand(terminal, TRUE);
    gtk_widget_set_vexpand(terminal, TRUE);
    vte_terminal_set_scrollback_lines(VTE_TERMINAL(terminal), 10000);

    g_signal_connect_swapped(terminal, "child-exited",
                             G_CALLBACK(append_event), state);
    vte_terminal_spawn_async(VTE_TERMINAL(terminal), VTE_PTY_DEFAULT,
        PROJECT_DIR, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, NULL, -1,
        NULL, NULL, NULL);
    g_object_set_data_full(G_OBJECT(terminal), "module-id",
                           g_strdup("raw-terminal"), g_free);
    return terminal;
}

static void
open_terminal_clicked(GtkButton *b, gpointer ud)
{
    AppState *state = ud;
    (void) b;
    GtkWidget *existing = find_module_page(state, "raw-terminal");
    if (existing) {
        int idx = gtk_notebook_page_num(GTK_NOTEBOOK(state->notebook), existing);
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), idx);
        return;
    }
    GtkWidget *page = create_terminal_page_cmd(state, NULL);
    GtkWidget *tab = create_closable_tab_label("Raw Terminal", page, state);
    int idx = gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook), page, tab);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), idx);
    append_event(state, "Opened raw terminal");
}

/* ==================================================================== */
/*  Splash                                                               */
/* ==================================================================== */

static gboolean
splash_bar_tick(gpointer ud)
{
    AppState *state = ud;
    if (state->splash_bar == NULL) { state->splash_tick = 0; return G_SOURCE_REMOVE; }
    gdouble f = gtk_progress_bar_get_fraction(GTK_PROGRESS_BAR(state->splash_bar));
    f += 0.02;
    if (f >= 1.0) f = 1.0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(state->splash_bar), f);
    if (state->splash_percent) {
        g_autofree gchar *pct = g_strdup_printf("%d%%", (int)(f * 100.0 + 0.5));
        gtk_label_set_text(GTK_LABEL(state->splash_percent), pct);
    }
    if (f >= 1.0) { state->splash_tick = 0; return G_SOURCE_REMOVE; }
    return G_SOURCE_CONTINUE;
}

static gboolean
finish_splash(gpointer ud)
{
    AppState *state = ud;
    if (state->splash_tick) { g_source_remove(state->splash_tick); state->splash_tick = 0; }
    state->splash_bar = NULL;
    if (state->splash_window) {
        gtk_window_destroy(GTK_WINDOW(state->splash_window));
        state->splash_window = NULL;
    }
    gtk_window_present(GTK_WINDOW(state->window));
    return G_SOURCE_REMOVE;
}

static void
show_splash(AppState *state)
{
    GtkWidget *picture = gtk_picture_new_for_filename(
        cs_path("native/resources/splash.png"));
    gtk_picture_set_content_fit(GTK_PICTURE(picture), GTK_CONTENT_FIT_CONTAIN);
    gtk_widget_set_size_request(picture, 380, 220);
    gtk_widget_set_halign(picture, GTK_ALIGN_CENTER);

    state->splash_window = gtk_window_new();
    gtk_widget_add_css_class(state->splash_window, "splash-window");
    gtk_window_set_application(GTK_WINDOW(state->splash_window), state->application);
    gtk_window_set_title(GTK_WINDOW(state->splash_window), "cloudsting");
    gtk_window_set_decorated(GTK_WINDOW(state->splash_window), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(state->splash_window), FALSE);
    gtk_window_set_modal(GTK_WINDOW(state->splash_window), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(state->splash_window), 720, 405);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *hero = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_halign(hero, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(hero, GTK_ALIGN_CENTER);

    GtkWidget *title = gtk_label_new("cloudsting");
    GtkWidget *sub = gtk_label_new("cloud & api toolkit");
    gtk_widget_add_css_class(title, "splash-title");
    gtk_widget_add_css_class(sub, "splash-subtitle");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);

    gtk_box_append(GTK_BOX(hero), picture);
    gtk_box_append(GTK_BOX(hero), title);
    gtk_box_append(GTK_BOX(hero), sub);

    GtkWidget *center = gtk_center_box_new();
    gtk_center_box_set_center_widget(GTK_CENTER_BOX(center), hero);
    gtk_widget_set_vexpand(center, TRUE);

    GtkWidget *bar = gtk_progress_bar_new();
    GtkWidget *pct = gtk_label_new("0%");
    gtk_widget_add_css_class(bar, "splash-bar");
    gtk_widget_add_css_class(pct, "splash-percent");
    gtk_widget_set_halign(bar, GTK_ALIGN_CENTER);
    gtk_widget_set_halign(pct, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_bottom(bar, 8);
    gtk_widget_set_margin_bottom(pct, 20);
    gtk_widget_set_size_request(bar, 360, 8);
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(bar), FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar), 0.0);

    state->splash_bar = bar;
    state->splash_percent = pct;
    state->splash_tick = g_timeout_add(50, splash_bar_tick, state);

    gtk_box_append(GTK_BOX(box), center);
    gtk_box_append(GTK_BOX(box), bar);
    gtk_box_append(GTK_BOX(box), pct);
    gtk_widget_set_hexpand(box, TRUE);
    gtk_widget_set_vexpand(box, TRUE);
    gtk_window_set_child(GTK_WINDOW(state->splash_window), box);

    gtk_window_present(GTK_WINDOW(state->splash_window));
    g_timeout_add(2500, finish_splash, state);
}

/* ==================================================================== */
/*  Keyboard shortcuts                                                   */
/* ==================================================================== */

static void
action_goto_tab(GSimpleAction *a, GVariant *p, gpointer ud)
{
    AppState *state = ud;
    (void) a;
    if (!p) return;
    int n = g_variant_get_int32(p);
    int pages = gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->notebook));
    if (n >= 1 && n <= pages)
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), n - 1);
}

static void
action_close_tab(GSimpleAction *a, GVariant *p, gpointer ud)
{
    AppState *state = ud;
    (void) a; (void) p;
    int idx = gtk_notebook_get_current_page(GTK_NOTEBOOK(state->notebook));
    if (idx > 0) gtk_notebook_remove_page(GTK_NOTEBOOK(state->notebook), idx);
}

static void
action_new_term(GSimpleAction *a, GVariant *p, gpointer ud)
{
    (void) a; (void) p;
    open_terminal_clicked(NULL, ud);
}

static void
action_quit(GSimpleAction *a, GVariant *p, gpointer ud)
{
    AppState *state = ud;
    (void) a; (void) p;
    g_application_quit(G_APPLICATION(state->application));
}

static void
action_clear_events(GSimpleAction *a, GVariant *p, gpointer ud)
{
    AppState *state = ud;
    (void) a; (void) p;
    event_clear_clicked(NULL, state);
}

static void
install_shortcuts(AppState *state)
{
    static const GActionEntry win_actions[] = {
        { .name = "goto-tab",   .activate = action_goto_tab,   .parameter_type = "i" },
        { .name = "close-tab",  .activate = action_close_tab },
        { .name = "new-term",   .activate = action_new_term },
        { .name = "quit",       .activate = action_quit },
        { .name = "clear-evts", .activate = action_clear_events },
    };
    g_action_map_add_action_entries(G_ACTION_MAP(state->window), win_actions,
        G_N_ELEMENTS(win_actions), state);

    GtkShortcutController *ctrl = GTK_SHORTCUT_CONTROLLER(
        gtk_shortcut_controller_new());
    gtk_shortcut_controller_set_scope(ctrl, GTK_SHORTCUT_SCOPE_GLOBAL);

    static const char *simple[][2] = {
        { "<Control>t", "win.new-term" },
        { "<Control>w", "win.close-tab" },
        { "<Control>q", "win.quit" },
        { "<Control>k", "win.clear-evts" },
        { NULL, NULL }
    };
    for (int i = 0; simple[i][0] != NULL; i++) {
        GtkShortcutTrigger *trig = gtk_shortcut_trigger_parse_string(simple[i][0]);
        GtkShortcutAction *act = gtk_named_action_new(simple[i][1]);
        gtk_shortcut_controller_add_shortcut(ctrl,
            gtk_shortcut_new(trig, act));
    }
    for (int n = 1; n <= 9; n++) {
        char accel[32];
        g_snprintf(accel, sizeof accel, "<Control>%d", n);
        GtkShortcutTrigger *trig = gtk_shortcut_trigger_parse_string(accel);
        GtkShortcutAction *act = gtk_named_action_new("win.goto-tab");
        GtkShortcut *sh = gtk_shortcut_new(trig, act);
        g_object_set(sh, "arguments", g_variant_new_int32(n), NULL);
        gtk_shortcut_controller_add_shortcut(ctrl, sh);
    }
    gtk_widget_add_controller(GTK_WIDGET(state->window),
        GTK_EVENT_CONTROLLER(ctrl));
}

/* ==================================================================== */
/*  CSS loader                                                           */
/* ==================================================================== */

static void
load_css(void)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    g_autofree char *local = g_build_filename(
        PROJECT_DIR, "native/resources/style.css", NULL);

    if (g_file_test(local, G_FILE_TEST_IS_REGULAR))
        gtk_css_provider_load_from_path(provider, local);
    else
        gtk_css_provider_load_from_resource(
            provider, "/com/cloudsting/native/style.css");

    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

/* ==================================================================== */
/*  Activate                                                             */
/* ==================================================================== */

static void
activate(GtkApplication *app, gpointer user_data)
{
    /* Same live_state trick as wifisting: a second activation (launching
       the binary again) must present the existing window, not rebuild. */
    static AppState *live_state = NULL;
    (void) user_data;

    if (live_state != NULL && live_state->window != NULL) {
        gtk_window_present(GTK_WINDOW(live_state->window));
        return;
    }

    AppState *state = g_new0(AppState, 1);
    live_state = state;
    state->application = app;
    state->favorites = g_ptr_array_new_with_free_func(g_free);
    state->recent = g_ptr_array_new_with_free_func(g_free);
    state->usage = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    usage_counts_load(state);

    state->window = gtk_application_window_new(app);
    state->notebook = gtk_notebook_new();
    state->sidebar = create_sidebar(state);
    state->event_drawer = create_event_drawer(state);

    load_css();

    /* Permenant tabs: Dashboard, Loot, Help */
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_dashboard(state), gtk_label_new("Dashboard"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_loot_page(state), gtk_label_new("Loot"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_help_page(state), gtk_label_new("Help"));

    gtk_notebook_set_scrollable(GTK_NOTEBOOK(state->notebook), TRUE);
    gtk_widget_set_hexpand(state->notebook, TRUE);
    gtk_widget_set_vexpand(state->notebook, TRUE);

    GtkWidget *horizontal = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    GtkWidget *vertical = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    gtk_widget_set_hexpand(horizontal, TRUE);
    gtk_widget_set_vexpand(horizontal, TRUE);
    gtk_widget_set_hexpand(vertical, TRUE);
    gtk_widget_set_vexpand(vertical, TRUE);

    gtk_paned_set_start_child(GTK_PANED(horizontal), state->sidebar);
    gtk_paned_set_end_child(GTK_PANED(horizontal), state->notebook);
    gtk_paned_set_position(GTK_PANED(horizontal), 185);
    gtk_paned_set_resize_start_child(GTK_PANED(horizontal), FALSE);
    gtk_paned_set_resize_end_child(GTK_PANED(horizontal), TRUE);

    gtk_paned_set_start_child(GTK_PANED(vertical), horizontal);
    gtk_paned_set_end_child(GTK_PANED(vertical), state->event_drawer);
    gtk_paned_set_position(GTK_PANED(vertical), 590);
    gtk_paned_set_resize_start_child(GTK_PANED(vertical), TRUE);
    gtk_paned_set_resize_end_child(GTK_PANED(vertical), FALSE);

    gtk_window_set_title(GTK_WINDOW(state->window), "cloudsting");
    gtk_window_set_default_size(GTK_WINDOW(state->window), 1280, 760);
    gtk_window_set_titlebar(GTK_WINDOW(state->window), create_header(state));

    /* Overlay: background + main + session panel + toasts */
    {
        GtkWidget *overlay = gtk_overlay_new();
        GtkWidget *bg = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        gtk_widget_add_css_class(bg, "app-background");
        gtk_widget_set_hexpand(bg, TRUE);
        gtk_widget_set_vexpand(bg, TRUE);

        /* Session panel revealer */
        GtkWidget *panel = create_session_panel(state);
        GtkWidget *rev = gtk_revealer_new();
        gtk_revealer_set_transition_type(GTK_REVEALER(rev),
            GTK_REVEALER_TRANSITION_TYPE_SLIDE_LEFT);
        gtk_revealer_set_transition_duration(GTK_REVEALER(rev), 220);
        gtk_revealer_set_reveal_child(GTK_REVEALER(rev), TRUE);
        gtk_revealer_set_child(GTK_REVEALER(rev), panel);
        gtk_widget_add_css_class(rev, "session-revealer");
        gtk_widget_set_halign(rev, GTK_ALIGN_END);
        gtk_widget_set_valign(rev, GTK_ALIGN_FILL);
        state->session_revealer = rev;
        state->session_shown = TRUE;

        gtk_overlay_set_child(GTK_OVERLAY(overlay), bg);
        gtk_overlay_add_overlay(GTK_OVERLAY(overlay), vertical);
        gtk_overlay_add_overlay(GTK_OVERLAY(overlay), rev);
        gtk_overlay_set_measure_overlay(GTK_OVERLAY(overlay), vertical, TRUE);

        /* Toast stack */
        {
            GtkWidget *stack = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
            gtk_widget_add_css_class(stack, "toast-stack");
            gtk_widget_set_halign(stack, GTK_ALIGN_END);
            gtk_widget_set_valign(stack, GTK_ALIGN_START);
            gtk_widget_set_margin_top(stack, 12);
            gtk_widget_set_margin_end(stack, 12);
            state->toast_stack = stack;
            gtk_overlay_add_overlay(GTK_OVERLAY(overlay), stack);
        }

        state->overlay = overlay;
        gtk_window_set_child(GTK_WINDOW(state->window), overlay);
    }

    window_state_load(state);

    /* Restore saved tabs */
    {
        g_autofree gchar *ini = state_ini_path();
        GKeyFile *kf = g_key_file_new();
        if (g_key_file_load_from_file(kf, ini, G_KEY_FILE_NONE, NULL)) {
            int n = g_key_file_get_integer(kf, "session", "count", NULL);
            for (int i = 0; i < n; i++) {
                g_autofree gchar *k = g_strdup_printf("tab_%d", i);
                g_autofree gchar *id = g_key_file_get_string(kf, "session", k, NULL);
                if (id != NULL && *id != '\0') {
                    for (guint j = 0; j < G_N_ELEMENTS(modules); j++) {
                        if (g_strcmp0(modules[j].id, id) == 0) {
                            open_module(state, &modules[j]);
                            break;
                        }
                    }
                }
            }
        }
        g_key_file_unref(kf);
    }

    g_object_set_data_full(G_OBJECT(state->window), "app-state", state, g_free);
    g_signal_connect(state->window, "close-request",
                     G_CALLBACK(window_close_request), state);

    append_event(state, "Native cloudsting GUI initialised");
    append_event(state, "Loaded 13 module definitions");

    install_shortcuts(state);
    show_splash(state);

    /* Silent session info refresh every 30 s — never prompts */
    session_refresh_idle(state);
    g_timeout_add_seconds(30, session_refresh_idle, state);
}

/* ==================================================================== */
/*  Loot page (very small — lists loot/ tree)                            */
/* ==================================================================== */

typedef struct {
    AppState *state;
    GtkWidget *list;
} LootState;

static void
loot_refresh_clicked(GtkButton *b, gpointer ud)
{
    LootState *ls = ud;
    (void) b;
    GtkWidget *child = gtk_widget_get_first_child(ls->list);
    while (child) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(ls->list), child);
        child = next;
    }

    const char *dirs[] = {
        cs_path("loot"),
        cs_path("loot/cloudsting"),
        cs_path("loot/inventory"),
        cs_path("loot/bucket_enum"),
        cs_path("loot/takeover"),
        cs_path("loot/secrets_scan"),
        cs_path("loot/user_data"),
        cs_path("loot/lambda_dump"),
        cs_path("loot/ssrf_imds"),
        cs_path("loot/policy_audit"),
        cs_path("loot/iam_privesc"),
        cs_path("loot/role_chains"),
        NULL
    };
    for (int i = 0; dirs[i] != NULL; i++) {
        GDir *d = g_dir_open(dirs[i], 0, NULL);
        if (d == NULL) continue;
        const char *name;
        while ((name = g_dir_read_name(d)) != NULL) {
            GtkWidget *row = gtk_list_box_row_new();
            GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
            GtkWidget *lbl = gtk_label_new(name);
            GtkWidget *sub = gtk_label_new(dirs[i]);
            gtk_widget_add_css_class(row, "dependency-row");
            gtk_widget_add_css_class(lbl, "dependency-name");
            gtk_widget_add_css_class(sub, "dependency-package");
            gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
            gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
            gtk_widget_set_hexpand(lbl, TRUE);
            gtk_box_append(GTK_BOX(box), lbl);
            gtk_box_append(GTK_BOX(box), sub);
            gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
            gtk_list_box_append(GTK_LIST_BOX(ls->list), row);
        }
        g_dir_close(d);
    }
}

static GtkWidget *
create_loot_page(AppState *state)
{
    LootState *ls = g_new0(LootState, 1);
    ls->state = state;

    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *title = gtk_label_new("Loot");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *list = gtk_list_box_new();

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_widget_set_hexpand(title, TRUE);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_valign(refresh, GTK_ALIGN_CENTER);

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_list_box_set_show_separators(GTK_LIST_BOX(list), TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    ls->list = list;
    g_object_set_data_full(G_OBJECT(page), "loot-state", ls, g_free);

    gtk_box_append(GTK_BOX(row), title);
    gtk_box_append(GTK_BOX(row), refresh);
    gtk_box_append(GTK_BOX(page), row);
    gtk_box_append(GTK_BOX(page), scroll);

    g_signal_connect(refresh, "clicked", G_CALLBACK(loot_refresh_clicked), ls);
    loot_refresh_clicked(NULL, ls);
    return page;
}

/* ==================================================================== */
/*  Help page                                                            */
/* ==================================================================== */

static GtkWidget *
create_help_page(AppState *state)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("Help");
    GtkWidget *body = gtk_label_new(
        "cloudsting — cloud & API attack surface toolkit\n"
        "\n"
        "STRUCTURE\n"
        "  - Dashboard: all modules as tiles; right-click to favorite\n"
        "  - Sidebar: modules grouped by category, filterable\n"
        "  - Session panel (right): current AWS identity / account / region\n"
        "  - Events drawer (bottom): every stderr, exit code, tool message\n"
        "\n"
        "MODULES\n"
        "  SETUP        00_deps            install cloud CLIs + build tools\n"
        "  CREDENTIALS  01_cred_validate   detect, validate, live-probe\n"
        "  RECON        02_inventory       enumerate all assets\n"
        "               03_bucket_enum     discover + rate buckets\n"
        "               04_takeover        dangling CNAMEs\n"
        "  EXPLOIT      05_iam_privesc     map privilege escalations\n"
        "               06_role_chains     assume-role walks\n"
        "               09_ssrf_imds       SSRF → metadata endpoints\n"
        "               10_imdsv2_bypass   SSRF chains to IMDSv2\n"
        "  AUDIT        07_policy_audit    wildcards, risky patterns\n"
        "               08_secrets_scan    fingerprint secrets in files\n"
        "  DATA         11_user_data       instance metadata + user-data\n"
        "               12_lambda_dump     Lambda config + code\n"
        "\n"
        "KEYBOARD\n"
        "  Ctrl+T         Raw Terminal\n"
        "  Ctrl+W         Close current tab\n"
        "  Ctrl+1..9      Jump to tab N\n"
        "  Ctrl+K         Clear event drawer\n"
        "  Ctrl+Q         Quit\n"
        "\n"
        "AUTHORIZED TESTING ONLY.\n"
        "Every module transmits real requests. Use only against\n"
        "accounts and infrastructure you are explicitly authorized to test.");

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(body, "help-text");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(body), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(body), TRUE);
    gtk_label_set_selectable(GTK_LABEL(body), TRUE);

    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), body);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), scroll);
    (void) state;
    return page;
}

/* ==================================================================== */
/*  main                                                                 */
/* ==================================================================== */

int
main(int argc, char **argv)
{
    g_autoptr(GtkApplication) application;

    g_set_prgname("cloudsting");
    g_set_application_name("cloudsting");

    /* Widen PATH so pkexec'd children find /usr/sbin tools. */
    {
        const char *cur = g_getenv("PATH");
        g_autofree gchar *home_bin = g_build_filename(
            g_get_home_dir(), ".local", "bin", NULL);
        g_autofree gchar *merged = g_strdup_printf(
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:%s:%s",
            home_bin, (cur && *cur) ? cur : "/usr/bin:/bin");
        g_setenv("PATH", merged, TRUE);
    }

    register_all_modules();

    application = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(application, "activate", G_CALLBACK(activate), NULL);

    {
        int rc = g_application_run(G_APPLICATION(application), argc, argv);
        return rc;
    }
}