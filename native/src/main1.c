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
#define SCRIPT(n)  "modules/" n
#define PROJECT_DIR cs_root()

/* ==================================================================== */
/*  Module definitions                                                   */
/* ==================================================================== */

typedef struct {
    char *id;
    char *name;
    char *category;
    char *icon;
    char *description;
} ModuleDefinition;

/* One place owns module metadata: data/registry.tsv, read through
 * `cloudsting.sh registry --tsv`. The C table below is only the last-resort
 * fallback for a checkout whose launcher is missing or broken, so the window
 * still opens with something in it instead of an empty grid. */
static GPtrArray *module_table;      /* ModuleDefinition*, owned */

static const ModuleDefinition module_fallback[] = {
    /* Mirrors data/registry.cat: one module per attack. Only reached when the
       launcher is missing or unreadable, so it stays short and honest rather
       than pretending to be the whole tree. */
    { "00_deps",          "Dependencies",     "SETUP",
      "system-software-install-symbolic",
      "Inspect and install required cloud CLIs" },
    { "01_cred_validate", "Credential Validator", "CREDS",
      "dialog-password-symbolic",
      "Credential formats, live probes and telco vendor oracles" },
    { "02_inventory",     "Cloud Inventory", "SURFACE",
      "view-list-symbolic",
      "Enumerate every reachable asset across providers" },
    { "03_bucket_enum",   "Bucket Enum",     "STORAGE",
      "folder-remote-symbolic",
      "Discover buckets and probe permissions" },
    { "04_pivot",         "Cross-Acct Pivot", "IDENTITY",
      "system-users-symbolic",
      "Assume a foreign role and measure what it returns" },
    { "05_iam_privesc",   "IAM PrivEsc",     "IDENTITY",
      "security-high-symbolic",
      "Map IAM privilege escalation paths" },
    { "06_role_chains",   "Role Chains",     "IDENTITY",
      "emblem-synchronizing-symbolic",
      "Walk role trust policies and assume-role hops" },
    { "07_policy_audit",  "Policy Audit",    "IDENTITY",
      "dialog-warning-symbolic",
      "Audit IAM policies for wildcards and privilege holes" },
    { "08_secrets_scan",  "Secrets Scanner", "CREDS",
      "edit-find-symbolic",
      "Fingerprint exposed secrets in files, repos, env dumps" },
    { "09_imds",          "Instance Metadata", "COMPUTE",
      "network-transmit-receive-symbolic",
      "SSRF to IMDSv2 to user-data to credentials" },
    { "10_snapshot",     "Snapshot Theft", "STORAGE",
      "drive-harddisk-symbolic",
      "Shared snapshots and the credentials inside them" },
    { "11_event_trigger", "Event Trigger", "COMPUTE",
      "emblem-synchronizing-symbolic",
      "Inject a forged event and see what the handler does" },
    { "13_cicd",         "CI/CD Supply Chain", "COMPUTE",
      "text-x-script-symbolic",
      "Workflow files, OIDC trust and the branch the deploy watches" },
    { "12_serverless",    "Serverless",      "COMPUTE",
      "system-run-symbolic",
      "Functions across AWS, GCP and Azure: list, env, code" },
    { "14_registry_recon",   "Registry Recon",   "STORAGE",
      "package-x-generic-symbolic",
      "List container registries, images and tags" },
    { "15_container_escape", "Container Escape", "COMPUTE",
      "security-high-symbolic",
      "Detect misconfigurations that allow container escape" },
    { "16_kubernetes",    "Kubernetes",      "COMPUTE",
      "network-workgroup-symbolic",
      "Clusters, RBAC and secrets" },
    { "18_network",       "Cloud Network",   "NETWORK",
      "network-server-symbolic",
      "DNS, subnets, firewall, and subdomain takeover" },
    { "21_db_exposure",   "DB Exposure",     "STORAGE",
      "drive-harddisk-symbolic",
      "Managed databases, public reachability and endpoint probes" },
    { "22_audit_evasion", "Audit Coverage",  "ATTRITION",
      "document-open-recent-symbolic",
      "Which audit controls are missing, and what that hides" },
    { "23_persistence",   "Persistence",     "IDENTITY",
      "document-save-symbolic",
      "Footholds that survive a credential rotation" },
    { "27_rebinding",     "DNS Rebinding",   "DNS",
      "network-workgroup-symbolic",
      "A name that resolves twice" },
    { "58_sse",           "Server-Sent Events", "WEBAPI",
      "document-open-recent-symbolic",
      "A stream nobody authenticated, judged per event" },
    { "60_resp_smuggle",  "Response Smuggling", "WEBAPI",
      "document-open-recent-symbolic",
      "A second response spliced into the first" },
    { "63_pagination",    "Pagination Abuse",   "WEBAPI",
      "view-list-symbolic",
      "A list endpoint that will hand over the table" },
    { "71_logic",         "Business Logic",   "WEBAPI",
      "dialog-information-symbolic",
      "The rule nobody wrote down — a valid request, in the wrong order" },
    { "72_race",          "Race Condition",   "WEBAPI",
      "system-run-symbolic",
      "Two requests that each pass a check neither should" },
    { "74_llm",           "LLM Endpoint",     "WEBAPI",
      "applications-science-symbolic",
      "The model box is an API with a budget" },
    { "75_rotation",      "Key Rotation",     "IDENTITY",
      "dialog-password-symbolic",
      "The credential that outlives its own rotation" },
    { "77_mobile",        "Mobile Backend",   "SURFACE",
      "phone-symbolic",
      "The client version is an authorization input" },
    { "39_tenant_enum",   "Tenant Enum",     "DNS",
      "network-workgroup-symbolic",
      "Tenant id, cert transparency and reverse-DNS per ASN" },
    { "41_api_discovery", "API Discovery",   "SURFACE",
      "view-list-symbolic",
      "Endpoints found by wordlist, baseline and content type" },
    { "42_openapi",       "OpenAPI Analyzer", "WEBAPI",
      "text-x-generic-symbolic",
      "What a spec admits to: security, ids and url-taking params" },
    { "43_graphql",       "GraphQL",         "WEBAPI",
      "network-server-symbolic",
      "Introspection, type surface and query depth" },
    { "44_jwt",           "JWT",             "WEBAPI",
      "dialog-password-symbolic",
      "alg:none, key confusion, kid injection, offline crack" },
    { "45_oauth",         "OAuth",           "WEBAPI",
      "emblem-locked-symbolic",
      "The flow is the attack surface" },
    { "68_graphql_dos",   "GraphQL Cost",    "WEBAPI",
      "network-server-symbolic",
      "Depth, alias and batch cost against a measured control" },
    { "46_key_harvest",   "Key Harvest",     "SURFACE",
      "edit-find-symbolic",
      "Keys and tokens in pages, bundles and headers" },
    { "47_auth_bypass",   "Auth Bypass",     "WEBAPI",
      "security-medium-symbolic",
      "The guard is on the route, not the resource" },
    { "48_bola",          "BOLA",            "WEBAPI",
      "system-users-symbolic",
      "Object-level authorization on subscriber and account ids" },
    { "49_bfla",          "BFLA",            "WEBAPI",
      "system-lock-screen-symbolic",
      "Function-level authorization across verbs and tiers" },
    { "50_mass_assign",   "Mass Assignment", "WEBAPI",
      "document-properties-symbolic",
      "Fields the server trusts because the client sent them" },
    { "51_hpp",           "Parameter Pollution", "WEBAPI",
      "view-refresh-symbolic",
      "One parameter, two meanings" },
    { "52_rate_limit",    "Rate Limit Bypass", "WEBAPI",
      "network-transmit-symbolic",
      "Forwarding-header rotation against a trusting limit" },
    { "53_injection",     "API Injection",   "WEBAPI",
      "utilities-terminal-symbolic",
      "SQL, NoSQL, command, template, LDAP and XPath" },
    { "54_ssrf",          "SSRF",            "WEBAPI",
      "network-transmit-receive-symbolic",
      "Make a server fetch, and prove it by content" },
    { "59_smuggling",     "Request Smuggling", "WEBAPI",
      "view-list-symbolic",
      "The front end and the back end disagree" },
    { "61_cors",          "CORS Abuse",      "WEBAPI",
      "preferences-system-network-symbolic",
      "Origin reflection with the cookie riding along" },
    { "62_version_bypass", "Versioning Bypass", "WEBAPI",
      "document-open-recent-symbolic",
      "The old version answers while the new one is locked" },
    { "64_file_upload",   "File Upload",     "WEBAPI",
      "document-send-symbolic",
      "The extension and content-type matrix" },
    { "56_grpc",          "gRPC / Protobuf", "WEBAPI",
      "network-server-symbolic",
      "Reflection, method auth and protobuf field confusion" },
    { "57_websocket",     "WebSocket",     "WEBAPI",
      "network-wired-symbolic",
      "Handshake auth, message auth and cross-site hijacking" },
    { "67_token_refresh", "Token Refresh", "WEBAPI",
      "emblem-synchronizing-symbolic",
      "The token that outlives the logout" },
    { "78_replay_nonce", "Replay & Nonce", "WEBAPI",
      "view-refresh-symbolic",
      "The request that still works the second time" },
    { "69_bfuzz", "Binary Fuzz", "WEBAPI",
      "applications-engineering-symbolic",
      "The value the schema forbids" },
    { "70_spec_diff", "Spec Diff", "WEBAPI",
      "document-open-recent-symbolic",
      "What changed, and which change added a door" },
    { "66_webhook_sig", "Webhook Signature", "WEBAPI",
      "mail-signed-symbolic",
      "The signature nobody checked" },
    { "65_deserialization", "Deserialization", "WEBAPI",
      "application-x-executable-symbolic",
      "A payload that is a data structure, and a server that rebuilds it" },
    { "76_debug_endpoints", "Debug Endpoints", "SURFACE",
      "utilities-system-monitor-symbolic",
      "Health, actuator, docs and env endpoints" },
};

/* Category → icon. A registry row carries no icon column: the category
 * decides, and a per-id override can be added here without touching the
 * registry. Unknown categories get a neutral folder. */
static const struct { const char *category; const char *icon; } module_icons[] = {
    { "SETUP",      "system-software-install-symbolic" },
    { "CREDS",      "dialog-password-symbolic" },
    { "IDENTITY",   "system-users-symbolic" },
    { "SURFACE",    "view-list-symbolic" },
    { "COMPUTE",    "computer-symbolic" },
    { "STORAGE",    "drive-harddisk-symbolic" },
    { "NETWORK",    "network-wired-symbolic" },
    { "DNS",        "network-workgroup-symbolic" },
    { "ATTRITION",  "dialog-warning-symbolic" },
    { "WEBAPI",     "network-server-symbolic" },
    { "TOOLING",    "applications-utilities-symbolic" },
    /* retired category names, kept so an old registry row still resolves */
    { "RECON",      "view-list-symbolic" },
    { "EXPLOIT",    "security-high-symbolic" },
    { "CREDENTIALS", "dialog-password-symbolic" },
    { "AUDIT",      "dialog-warning-symbolic" },
    { "DATA",       "document-open-symbolic" },
    { "API",        "network-server-symbolic" },
};

static const char *
module_default_icon(const char *category)
{
    if (category != NULL)
        for (guint i = 0; i < G_N_ELEMENTS(module_icons); i++)
            if (g_strcmp0(module_icons[i].category, category) == 0)
                return module_icons[i].icon;
    return "folder-symbolic";
}

static void
module_definition_free(gpointer p)
{
    ModuleDefinition *m = p;
    if (m == NULL) return;
    g_free(m->id);
    g_free(m->name);
    g_free(m->category);
    g_free(m->icon);
    g_free(m->description);
    g_free(m);
}

/* Column order is fixed by `cloudsting.sh registry --tsv`:
 *   id  slug  title  category  mission  verbs  selftest  phase */
static void
module_table_push(GPtrArray *out, const char *id, const char *name,
                  const char *category, const char *description)
{
    ModuleDefinition *m = g_new0(ModuleDefinition, 1);
    m->id          = g_strdup(id != NULL ? id : "");
    m->name        = g_strdup(name != NULL ? name : m->id);
    m->category    = g_strdup(category != NULL && *category ? category : "OTHER");
    m->icon        = g_strdup(module_default_icon(m->category));
    m->description = g_strdup(description != NULL ? description : "");
    g_ptr_array_add(out, m);
}

static void
module_table_load_fallback(GPtrArray *out)
{
    for (guint i = 0; i < G_N_ELEMENTS(module_fallback); i++)
        module_table_push(out, module_fallback[i].id, module_fallback[i].name,
                          module_fallback[i].category,
                          module_fallback[i].description);
}

static GPtrArray *
module_table_load(void)
{
    GPtrArray *out = g_ptr_array_new_with_free_func(module_definition_free);
    g_autofree gchar *root = g_strdup(cs_root());
    g_autofree gchar *launcher = g_build_filename(root, "cloudsting.sh", NULL);

    if (!g_file_test(launcher, G_FILE_TEST_IS_EXECUTABLE)) {
        module_table_load_fallback(out);
        return out;
    }

    const char *argv[] = { launcher, "registry", "--tsv", NULL };
    g_autoptr(GError) error = NULL;
    GSubprocess *p = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (p == NULL) {
        g_warning("registry: %s", error->message);
        module_table_load_fallback(out);
        return out;
    }

    g_autofree gchar *raw = NULL;
    g_autofree gchar *err = NULL;
    if (!g_subprocess_communicate_utf8(p, NULL, NULL, &raw, &err, &error)) {
        g_warning("registry: %s", error->message);
    }
    g_object_unref(p);

    guint seen = 0;
    if (raw != NULL) {
        g_auto(GStrv) lines = g_strsplit(raw, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            if (*lines[i] == '\0') continue;
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", -1);
            if (g_strv_length(f) < 5) continue;
            if (g_strcmp0(f[0], "id") == 0) continue;   /* header row */
            if (f[1] == NULL || *f[1] == '\0') continue;
            module_table_push(out, f[1], f[2], f[3], f[4]);
            seen++;
        }
    }

    if (seen == 0)
        module_table_load_fallback(out);
    return out;
}

static guint
module_count(void)
{
    return module_table != NULL ? module_table->len : 0;
}

static const ModuleDefinition *
module_at(guint index)
{
    if (module_table == NULL || index >= module_table->len) return NULL;
    return g_ptr_array_index(module_table, index);
}

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
/* Forward declarations for callbacks defined after first use in static init or G_CALLBACK */
static void close_tab_clicked(GtkButton *, gpointer);
static void tile_fav_clicked(GtkButton *, gpointer);
static void jump_clicked(GtkButton *, gpointer);
static void session_copy_clicked(GtkButton *, gpointer);
static void session_refresh_clicked(GtkButton *, gpointer);
static gboolean session_refresh_idle(gpointer);
static void open_terminal_clicked(GtkButton *, gpointer);
static void toggle_widget(GtkToggleButton *, gpointer);
static void open_module_clicked(GtkButton *, gpointer);
static GtkWidget *create_loot_page(AppState *);
static GtkWidget *create_help_page(AppState *);

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
    for (guint i = 0; i < module_count(); i++)
        if (g_strcmp0(module_at(i)->id, id) == 0) return module_at(i)->icon;
    if (g_strcmp0(id, "system") == 0) return "preferences-system-symbolic";
    return "dialog-information-symbolic";
}

static const char *
module_name_for(const char *id)
{
    if (id == NULL) return "cloudsting";
    for (guint i = 0; i < module_count(); i++)
        if (g_strcmp0(module_at(i)->id, id) == 0) return module_at(i)->name;
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

        if (out != NULL && *out != '\0') {
            g_autofree gchar *trimmed = g_strdup(out);
            g_strchomp(trimmed);
            if (*trimmed != '\0') {
                g_autofree gchar *m = g_strdup_printf("%s output:\n%s",
                                                      a->label, trimmed);
                append_event(a->state, m);
            }
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
/*  Module framework — per-module pages                                  */
/* ==================================================================== */

/* One page of a module tab.  `spec` lists the buttons the page holds:
 *
 *     "#SECTION"          start a new card with this title
 *     "--verb:Label"      a button that runs `script --verb`
 *     "~--verb:Label"     the verb needs a value; the row gets an entry
 *     "~~--verb:Label"    the value is split on spaces (two positionals)
 *     "--verb:Label!"     the command runs through pkexec
 *
 * Items are separated by '|'.  When `spec` is NULL the page is the module
 * overview (identity card, live status, selftest).
 *
 * This is deliberately hand-written per module — the toolkit has no single
 * generic shape, so every page says what its own verbs actually do. */
typedef struct {
    const char *name;
    const char *icon;
    const char *spec;
    /* Optional script override. A module whose id and file name disagree
       (an entry table reclaimed from a merged module) names its script here
       instead of carrying a second ModuleSpec. */
    const char *script;
} PageSpec;

typedef struct {
    const char *id;
    const char *script;
    const char *title;
    const char *subtitle;
    const PageSpec *pages;
    int n_pages;
} ModuleSpec;

typedef struct {
    AppState *state;
    const ModuleSpec *spec;
    GtkWidget *status_label;
    GSubprocess *status_proc;
} GenericModulePage;

/* One action page's run state: its own output view and status line, so a
   page keeps its own result instead of everybody sharing one drawer.
   `wait` is the subprocess handle — the output itself is already on screen,
   streamed line by line as it arrived, so nothing has to be buffered here. */
typedef struct {
    AppState *state;
    const ModuleSpec *spec;
    const PageSpec *page;
    GtkWidget *view;
    GtkWidget *status;
    GSubprocess *wait;
    GtkWidget *button;
    char *last_err;      /* last stderr line, for the failure summary */
    gint64 started_us;   /* monotonic start, so the footer can print elapsed */
} PageRun;

static void
page_run_busy(PageRun *r, gboolean busy)
{
    if (r == NULL || r->button == NULL) return;
    gtk_widget_set_sensitive(r->button, !busy);
}

static void
page_run_clear(PageRun *r)
{
    page_run_busy(r, FALSE);
}

/* What a verb's value field should prompt for — a bare "value" tells the
   operator nothing. */
static const char *
spec_arg_placeholder(const char *verb)
{
    static const struct { const char *verb; const char *hint; } hints[] = {
        { "--domain",   "example.com" },
        { "--perm",     "bucket-name" },
        { "--scan",     "/path/to/scan" },
        { "--check",    "value to check" },
        { "--probe",    "host or url" },
        { "--explain",  "technique, port or control" },
        { "--chain",    "role name" },
        { "--audit",    "/path/to/policy.json" },
        { "--detect",   "credential value" },
        { "--validate", "/path/to/credential" },
        { "--dhl",      "namespace" },
        { "--images",   "repository" },
        { "--tags",     "repository" },
        { "--pull",     "repository:tag" },
        { "--list",     "repository" },
        { "--dump",     "function name" },
        { "--download", "function name" },
        { "--env",      "function name" },
        { "--invoke",   "function name" },
        { "--decode",   "namespace secret" },
        { "--resolve",  "example.com" },
        { "--records",  "zone id" },
        { "--dangling", "zone id" },
        { "--axfr",     "zone name" },
        { "--ssrf",     "target url" },
        { "--exec",     "target url" },
        { "install",    "package name" },
    };

    for (guint i = 0; verb != NULL && i < G_N_ELEMENTS(hints); i++)
        if (g_strcmp0(verb, hints[i].verb) == 0) return hints[i].hint;
    return "value";
}

/* Parse "~--verb:Label!" into its parts. */
static void
spec_item_parse(const char *item, char **verb_out, char **label_out,
                gboolean *needs_arg, gboolean *split_arg, gboolean *priv)
{
    const char *s = item;
    char *verb, *label = NULL;
    gboolean needs = FALSE, split = FALSE, privileged = FALSE;
    const char *colon;

    while (*s == '~') { needs = TRUE; if (s[1] == '~') split = TRUE; s++; }
    if (*s == '~') s++;

    if (s[0] != '\0' && s[strlen(s) - 1] == '!') {
        privileged = TRUE;
        gchar *tmp = g_strndup(s, strlen(s) - 1);
        verb = tmp;
    } else {
        verb = g_strdup(s);
    }

    colon = strchr(verb, ':');
    if (colon != NULL) {
        label = g_strdup(colon + 1);
        gchar *v = g_strndup(verb, (gsize) (colon - verb));
        g_free(verb);
        verb = v;
    } else {
        /* No explicit label: derive a readable one from the flag. */
        gchar *name = g_strdup(verb);
        char *p;
        if (g_str_has_prefix(name, "--")) memmove(name, name + 2, strlen(name + 2) + 1);
        for (p = name; *p != '\0'; p++)
            if (*p == '-') *p = ' ';
        if (*name != '\0') name[0] = (char) g_ascii_toupper(name[0]);
        label = name;
    }

    *verb_out = verb;
    *label_out = label;
    *needs_arg = needs;
    *split_arg = split;
    *priv = privileged;
}

/* Write a command's output into a page view, colouring each line the way
   the other toolkits do: failures red, warnings amber, results green. */
static void
cs_output_view_install_tags(GtkTextBuffer *buf)
{
    gtk_text_buffer_create_tag(buf, "cs-ok",    "foreground", "#4ade80", NULL);
    gtk_text_buffer_create_tag(buf, "cs-warn",  "foreground", "#ffb454", NULL);
    gtk_text_buffer_create_tag(buf, "cs-error", "foreground", "#ff6b6b", NULL);
    gtk_text_buffer_create_tag(buf, "cs-dim",   "foreground", "#8b93a1", NULL);
    gtk_text_buffer_create_tag(buf, "cs-plain", NULL);
}

static const char *
cs_output_tag_for_line(const char *line)
{
    if (line == NULL || *line == '\0') return "cs-plain";
    if (g_str_has_prefix(line, "#")) return "cs-dim";
    if (g_str_has_prefix(line, "[err]")) return "cs-error";
    if (g_str_has_prefix(line, "[warn]")) return "cs-warn";
    if (g_strstr_len(line, -1, "FAIL") != NULL) return "cs-error";
    if (g_strstr_len(line, -1, "error") != NULL) return "cs-error";
    if (g_strstr_len(line, -1, "missing") != NULL) return "cs-warn";
    if (g_strstr_len(line, -1, "denied") != NULL) return "cs-warn";
    if (g_str_has_prefix(line, "warn") || g_str_has_prefix(line, "WARN"))
        return "cs-warn";
    if (g_str_has_prefix(line, "ok") || g_str_has_prefix(line, "PASS") ||
        g_str_has_prefix(line, "RESULT\tPASS"))
        return "cs-ok";
    if (g_str_has_prefix(line, "note") || g_str_has_prefix(line, "hint") ||
        g_str_has_prefix(line, "state"))
        return "cs-dim";
    return "cs-plain";
}

/* ---------------------------------------------------------------- */
/*  Live output                                                      */
/* ---------------------------------------------------------------- */
/* A module is a process that talks while it works: a scan prints each
 * object as it resolves it, a selftest prints each check as it runs. Waiting
 * for the process to exit and then dumping both pipes turns a two-minute
 * scan into two minutes of nothing followed by a wall of text, so the pages
 * read the pipes line by line and append each line the moment it arrives.
 *
 * Both pipes are read concurrently: a module that fills the stderr pipe
 * while we are still draining stdout would otherwise deadlock on its own
 * diagnostics.
 *
 * Everything below marshals to the main loop — GDK owns the widgets and the
 * reader callbacks run on a worker thread. */

typedef struct {
    GtkWidget *view;        /* borrowed: the page outlives every reader */
    GtkWidget *status;      /* optional label: shows a running line count */
} OutputStream;

typedef struct {
    OutputStream     *stream;
    GDataInputStream *in;
    GString          *partial;   /* a line split across reads */
    gboolean          from_stderr;
    guint             lines;
    char            **tail;      /* last non-empty line, for the summary */
} StreamReader;

typedef struct {
    OutputStream *stream;
    char         *line;
    gboolean      from_stderr;
    guint         lines;
} StreamAppend;

static gboolean
stream_append_idle(gpointer data)
{
    StreamAppend *a = data;

    if (a->stream == NULL || a->stream->view == NULL ||
        !GTK_IS_TEXT_VIEW(a->stream->view))
        goto out;

    {
        GtkTextBuffer *buf = gtk_text_view_get_buffer(
            GTK_TEXT_VIEW(a->stream->view));
        GtkTextIter end;
        g_autofree char *prefixed = NULL;
        const char *shown = a->line != NULL ? a->line : "";

        /* stderr is a diagnostic channel; mark it so the colour rule sees it */
        if (a->from_stderr)
            shown = prefixed = g_strdup_printf("[err] %s", shown);

        gtk_text_buffer_get_end_iter(buf, &end);
        gtk_text_buffer_insert_with_tags_by_name(
            buf, &end, shown, -1, cs_output_tag_for_line(shown), NULL);
        gtk_text_buffer_get_end_iter(buf, &end);
        gtk_text_buffer_insert(buf, &end, "\n", -1);

        /* pin the pane to the newest line unless the operator scrolled away */
        {
            GtkWidget *scroll = gtk_widget_get_parent(a->stream->view);
            if (scroll != NULL && GTK_IS_SCROLLED_WINDOW(scroll)) {
                GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(
                    GTK_SCROLLED_WINDOW(scroll));
                gtk_adjustment_set_value(adj,
                    gtk_adjustment_get_upper(adj) -
                    gtk_adjustment_get_page_size(adj));
            }
        }
    }

    if (a->stream->status != NULL && a->lines > 0) {
        g_autofree char *msg = g_strdup_printf("running… %u lines", a->lines);
        gtk_label_set_text(GTK_LABEL(a->stream->status), msg);
    }

out:
    g_free(a->line);
    g_free(a);
    return G_SOURCE_REMOVE;
}

/* Empty the pane before the first line of a run. */
static void
cs_output_clear(GtkWidget *view)
{
    if (view == NULL || !GTK_IS_TEXT_VIEW(view)) return;
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)),
                             "", -1);
}

static void
stream_reader_free(StreamReader *rd)
{
    if (rd == NULL) return;
    g_object_unref(rd->in);
    if (rd->partial != NULL) g_string_free(rd->partial, TRUE);
    g_free(rd);
}

static void stream_read_next(StreamReader *rd);

static void
stream_read_line(GObject *source, GAsyncResult *result, gpointer ud)
{
    StreamReader *rd = ud;
    g_autoptr(GError) error = NULL;
    gsize len = 0;
    char *line = g_data_input_stream_read_line_finish(
        G_DATA_INPUT_STREAM(source), result, &len, &error);

    if (line == NULL) {
        /* End of stream. A final line with no trailing newline still counts. */
        if (rd->partial != NULL && rd->partial->len > 0) {
            StreamAppend *a = g_new0(StreamAppend, 1);
            a->stream = rd->stream;
            a->line = g_strdup(rd->partial->str);
            a->from_stderr = rd->from_stderr;
            a->lines = rd->lines + 1;
            g_idle_add(stream_append_idle, a);
        }
        stream_reader_free(rd);
        (void) error;
        return;
    }

    /* Keep the last line of look-back for the failure summary. */
    if (rd->tail != NULL && *rd->tail != NULL && *line != '\0') {
        g_free(*rd->tail);
        *rd->tail = g_strdup(line);
    }

    {
        StreamAppend *a = g_new0(StreamAppend, 1);
        a->stream = rd->stream;
        a->line = g_strdup(line);
        a->from_stderr = rd->from_stderr;
        a->lines = ++rd->lines;
        g_idle_add(stream_append_idle, a);
    }

    g_free(line);
    stream_read_next(rd);
}

static void
stream_read_next(StreamReader *rd)
{
    g_data_input_stream_read_line_async(rd->in, G_PRIORITY_DEFAULT, NULL,
                                        stream_read_line, rd);
}

/* One reader per pipe. The reader owns its stream and frees itself at end of
 * file; the caller only waits for the process. */
static void
cs_stream_attach(GSubprocess *proc, OutputStream *stream, char **tail_slot)
{
    GInputStream *out_stream = g_subprocess_get_stdout_pipe(proc);
    GInputStream *err_stream = g_subprocess_get_stderr_pipe(proc);

    if (out_stream != NULL) {
        StreamReader *rd = g_new0(StreamReader, 1);
        rd->stream = stream;
        rd->in = g_data_input_stream_new(out_stream);
        rd->partial = g_string_new("");
        rd->from_stderr = FALSE;
        rd->tail = tail_slot;
        stream_read_next(rd);
    }
    if (err_stream != NULL) {
        StreamReader *rd = g_new0(StreamReader, 1);
        rd->stream = stream;
        rd->in = g_data_input_stream_new(err_stream);
        rd->partial = g_string_new("");
        rd->from_stderr = TRUE;
        rd->tail = tail_slot;
        stream_read_next(rd);
    }
}

static void
cs_output_set(GtkWidget *view, const char *text)
{
    GtkTextBuffer *buf;
    gchar **lines;

    if (view == NULL || !GTK_IS_TEXT_VIEW(view)) return;
    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_set_text(buf, "", -1);
    if (text == NULL || *text == '\0') return;

    lines = g_strsplit(text, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(buf, &end);
        gtk_text_buffer_insert_with_tags_by_name(
            buf, &end, lines[i], -1,
            cs_output_tag_for_line(lines[i]), NULL);
        gtk_text_buffer_get_end_iter(buf, &end);
        gtk_text_buffer_insert(buf, &end, "\n", -1);
    }
    g_strfreev(lines);
}

/* A page-local output pane: title strip plus a scrollable text view. */
static GtkWidget *
page_output_pane(GtkWidget **view_out)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *title = gtk_label_new("OUTPUT");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

    gtk_widget_add_css_class(card, "section-card");
    gtk_widget_add_css_class(title, "section-title");
    gtk_widget_add_css_class(scroll, "module-output-scroll");
    gtk_widget_add_css_class(view, "module-output");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(view), 6);
    gtk_text_view_set_bottom_margin(GTK_TEXT_VIEW(view), 6);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 8);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 8);
    cs_output_view_install_tags(buf);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_size_request(scroll, -1, 260);

    gtk_box_append(GTK_BOX(card), title);
    gtk_box_append(GTK_BOX(card), scroll);
    gtk_widget_set_vexpand(card, TRUE);
    if (view_out != NULL) *view_out = view;
    return card;
}

static void
page_run_free(gpointer data)
{
    PageRun *r = data;
    if (r == NULL) return;
    if (r->wait != NULL) {
        g_subprocess_force_exit(r->wait);
        g_clear_object(&r->wait);
    }
    g_free(r->last_err);
    g_free(r);
}

static void
page_run_finished(GObject *source, GAsyncResult *result, gpointer ud)
{
    PageRun *r = ud;
    g_autoptr(GError) error = NULL;
    gboolean ok = FALSE;
    int status = 0;
    gint64 elapsed_ms = 0;

    if (r == NULL) return;

    /* g_subprocess_wait_finish only reports the exit; the output arrived
     * through the streaming readers and is already in the pane. */
    if (!g_subprocess_wait_finish(G_SUBPROCESS(source), result, &error)) {
        g_autofree gchar *m = g_strdup_printf(
            "error: %s", error ? error->message : "process failed");
        if (r->status != NULL)
            gtk_label_set_text(GTK_LABEL(r->status), "failed");
        append_event(r->state, m);
        goto done;
    }

    ok = g_subprocess_get_successful(G_SUBPROCESS(source));
    if (g_subprocess_get_if_exited(G_SUBPROCESS(source)))
        status = g_subprocess_get_exit_status(G_SUBPROCESS(source));
    if (r->started_us > 0) {
        gint64 now = g_get_monotonic_time();
        if (now > r->started_us) elapsed_ms = (now - r->started_us) / 1000;
    }

    if (r->status != NULL) {
        g_autofree char *label = g_strdup_printf(
            "%s · exit %d · %" G_GINT64_FORMAT " ms",
            ok ? "done" : "finished", status, elapsed_ms);
        gtk_label_set_text(GTK_LABEL(r->status), label);
    }

    {
        const char *what = r->page != NULL ? r->page->name : r->spec->title;
        g_autofree gchar *m = ok
            ? g_strdup_printf("%s: ok", what)
            : g_strdup_printf("%s failed (exit %d): %s", what, status,
                              (r->last_err != NULL && *r->last_err != '\0')
                                  ? r->last_err : "no diagnostics");
        append_event(r->state, m);
    }

done:
    g_clear_object(&r->wait);
    page_run_clear(r);
}

static void
page_verb_clicked(GtkButton *button, gpointer ud)
{
    PageRun *r = ud;
    const char *verb = g_object_get_data(G_OBJECT(button), "cs-verb");
    const char *label = g_object_get_data(G_OBJECT(button), "cs-label");
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "cs-entry");
    gboolean needs_arg = GPOINTER_TO_INT(
        g_object_get_data(G_OBJECT(button), "cs-needs-arg"));
    gboolean split_arg = GPOINTER_TO_INT(
        g_object_get_data(G_OBJECT(button), "cs-split-arg"));
    gboolean privileged = GPOINTER_TO_INT(
        g_object_get_data(G_OBJECT(button), "cs-privileged"));
    const char *arg = entry != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(entry)) : NULL;

    if (r == NULL || verb == NULL) return;
    if (needs_arg && (arg == NULL || *arg == '\0')) {
        show_toast_module(r->state, r->spec->id,
                          "Fill the field this action needs first", "warn");
        return;
    }
    if (r->wait != NULL) {
        show_toast_module(r->state, r->spec->id,
                          "A command from this page is still running", "warn");
        return;
    }

    const char *argv[8];
    guint i = 0;
    g_auto(GStrv) parts = NULL;

    argv[i++] = r->spec->script;
    argv[i++] = verb;
    if (arg != NULL && *arg != '\0') {
        if (split_arg) {
            parts = g_strsplit_set(arg, " \t", -1);
            for (int p = 0; parts[p] != NULL && i < 6; p++)
                if (*parts[p] != '\0') argv[i++] = parts[p];
        } else {
            argv[i++] = arg;
        }
    }
    argv[i] = NULL;

    if (r->status != NULL)
        gtk_label_set_text(GTK_LABEL(r->status), "running…");
    cs_output_clear(r->view);

    /* A module that lost its exec bit still runs: fall back to `bash script`.
     * pkexec needs the same treatment so the fallback survives privilege. */
    gboolean need_shell = !g_file_test(r->spec->script, G_FILE_TEST_IS_EXECUTABLE);

    GSubprocess *proc = NULL;
    if (privileged) {
        GPtrArray *full = g_ptr_array_new();
        g_ptr_array_add(full, (gpointer) "pkexec");
        if (need_shell) g_ptr_array_add(full, (gpointer) "bash");
        for (guint k = 0; argv[k] != NULL; k++) g_ptr_array_add(full, (gpointer) argv[k]);
        g_ptr_array_add(full, NULL);
        proc = g_subprocess_newv((const char * const *) full->pdata,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
            NULL);
        g_ptr_array_unref(full);
    } else {
        const char *spawn_argv[9];
        guint n = 0;
        if (need_shell) spawn_argv[n++] = "bash";
        for (guint k = 0; argv[k] != NULL && n < 9; k++) spawn_argv[n++] = argv[k];
        spawn_argv[n] = NULL;
        proc = g_subprocess_newv(spawn_argv,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
            NULL);
    }

    if (proc == NULL) {
        g_autofree char *msg = g_strdup_printf(
            "error: could not start %s (missing file, or no permission to execute it)",
            r->spec->script);
        cs_output_set(r->view, msg);
        if (r->status != NULL) gtk_label_set_text(GTK_LABEL(r->status), "failed");
        return;
    }

    append_event(r->state, label != NULL ? label : verb);
    page_run_busy(r, TRUE);

    /* Stream both pipes into the pane as lines arrive, then wait for the
     * exit code. The OutputStream outlives the click, so it is anchored to
     * the view widget and freed when the page goes. */
    r->started_us = g_get_monotonic_time();
    r->wait = proc;
    OutputStream *held = g_new0(OutputStream, 1);
    held->view = r->view;
    held->status = r->status;
    g_object_set_data_full(G_OBJECT(r->view), "cs-stream", held, g_free);
    cs_stream_attach(proc, held, &r->last_err);
    g_subprocess_wait_async(proc, NULL, page_run_finished, r);
}

static void
page_run_button_free(gpointer data)
{
    g_signal_handlers_disconnect_by_data(G_OBJECT(data), data);
    (void) data;
}

/* One row of a card: caption, optional entry, button. */
static GtkWidget *
spec_build_row(PageRun *r, const char *item)
{
    gchar *verb = NULL, *label = NULL;
    gboolean needs_arg = FALSE, split_arg = FALSE, privileged = FALSE;
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *caption;
    GtkWidget *entry = NULL;
    GtkWidget *button;

    spec_item_parse(item, &verb, &label, &needs_arg, &split_arg, &privileged);

    caption = gtk_label_new(label);
    gtk_widget_add_css_class(caption, "verb-caption");
    gtk_label_set_xalign(GTK_LABEL(caption), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(caption), TRUE);
    gtk_widget_set_size_request(caption, 168, -1);
    gtk_widget_set_valign(caption, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(row), caption);

    if (needs_arg) {
        entry = gtk_entry_new();
        gtk_entry_set_placeholder_text(GTK_ENTRY(entry),
            spec_arg_placeholder(verb));
        gtk_widget_add_css_class(entry, "verb-arg-entry");
        gtk_widget_set_hexpand(entry, TRUE);
        gtk_box_append(GTK_BOX(row), entry);
    } else {
        GtkWidget *spacer = gtk_label_new("");
        gtk_widget_set_hexpand(spacer, TRUE);
        gtk_box_append(GTK_BOX(row), spacer);
    }

    if (privileged) {
        GtkWidget *hint = gtk_label_new("root");
        gtk_widget_add_css_class(hint, "dependency-package");
        gtk_box_append(GTK_BOX(row), hint);
    }

    button = gtk_button_new_with_label("Run");
    gtk_widget_add_css_class(button, "verb-button");
    gtk_widget_add_css_class(button, "accent");
    gtk_widget_set_valign(button, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(row), button);

    g_object_set_data_full(G_OBJECT(button), "cs-verb", verb, g_free);
    g_object_set_data_full(G_OBJECT(button), "cs-label", label, g_free);
    g_object_set_data(G_OBJECT(button), "cs-entry", entry);
    g_object_set_data(G_OBJECT(button), "cs-needs-arg", GINT_TO_POINTER(needs_arg));
    g_object_set_data(G_OBJECT(button), "cs-split-arg", GINT_TO_POINTER(split_arg));
    g_object_set_data(G_OBJECT(button), "cs-privileged", GINT_TO_POINTER(privileged));

    g_signal_connect(button, "clicked", G_CALLBACK(page_verb_clicked), r);
    if (r != NULL && r->button == NULL) r->button = button;

    return row;
}

/* Build an action page from its spec: cards of labelled rows, then the
   page's own output pane. */
static GtkWidget *
generic_build_spec_page(AppState *state, GenericModulePage *g,
                        const PageSpec *page_spec)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new(page_spec->name);
    GtkWidget *subtitle = gtk_label_new(g->spec->subtitle);
    GtkWidget *scroller = gtk_scrolled_window_new();
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *card = NULL;
    PageRun *r;
    g_auto(GStrv) items = NULL;

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(subtitle, "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(subtitle), TRUE);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroller, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), body);

    r = g_new0(PageRun, 1);
    r->state = state;
    r->spec = g->spec;
    r->page = page_spec;
    {
        /* A page table reclaimed from a merged module names its own script;
           otherwise the run uses the spec the page was opened under. */
        static ModuleSpec script_override;
        if (page_spec->script != NULL) {
            script_override = *g->spec;
            script_override.script = page_spec->script;
            r->spec = &script_override;
        }
    }

    /* Overview carries spec == NULL by contract: it is the status card, not
       an action grid. Splitting it blind hands g_strsplit a NULL. */
    items = page_spec->spec != NULL ? g_strsplit(page_spec->spec, "|", -1)
                                    : g_strsplit("", "|", -1);
    for (int i = 0; items[i] != NULL; i++) {
        const char *item = items[i];
        if (*item == '\0') continue;
        if (*item == '#') {
            GtkWidget *card_title = gtk_label_new(item + 1);
            card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
            gtk_widget_add_css_class(card, "section-card");
            gtk_widget_add_css_class(card_title, "section-title");
            gtk_label_set_xalign(GTK_LABEL(card_title), 0.0f);
            gtk_box_append(GTK_BOX(card), card_title);
            gtk_box_append(GTK_BOX(body), card);
            continue;
        }
        if (card == NULL) {
            card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
            gtk_widget_add_css_class(card, "section-card");
            gtk_box_append(GTK_BOX(body), card);
        }
        gtk_box_append(GTK_BOX(card), spec_build_row(r, item));
    }

    {
        GtkWidget *pane = page_output_pane(&r->view);
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *status = gtk_label_new("idle");

        gtk_widget_add_css_class(status, "dependency-summary");
        gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
        gtk_widget_set_hexpand(status, TRUE);
        gtk_box_append(GTK_BOX(row), status);
        gtk_box_append(GTK_BOX(pane), row);
        r->status = status;
        gtk_box_append(GTK_BOX(body), pane);
    }

    g_object_set_data_full(G_OBJECT(page), "cs-run", r, page_run_free);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), subtitle);
    gtk_box_append(GTK_BOX(page), scroller);
    (void) state;
    return page;
}


static void
overview_status_finished(GObject *source, GAsyncResult *result, gpointer ud)
{
    GenericModulePage *g = ud;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    g_autofree char *errout = NULL;
    GtkWidget *view = g_object_get_data(G_OBJECT(g->status_label), "cs-view");

    if (g_subprocess_communicate_utf8_finish(
            G_SUBPROCESS(source), result, &out, &errout, &error)) {
        g_autofree gchar *text = g_strdup_printf("%s%s%s",
            out != NULL ? out : "",
            (errout != NULL && *errout != '\0') ? "\n" : "",
            (errout != NULL && *errout != '\0') ? errout : "");
        g_strchomp(text);
        cs_output_set(view, *text != '\0' ? text : "no status reported");
        gtk_label_set_text(GTK_LABEL(g->status_label), "status refreshed");
    } else {
        cs_output_set(view, error != NULL ? error->message : "status failed");
        gtk_label_set_text(GTK_LABEL(g->status_label), "status failed");
    }
    g_clear_object(&g->status_proc);
}

static void
overview_refresh_clicked(GtkButton *b, gpointer ud)
{
    GenericModulePage *g = ud;
    const char *argv[3];
    g_autoptr(GError) error = NULL;

    if (g->status_proc != NULL) return;
    argv[0] = g->spec->script;
    argv[1] = "--status-tsv";
    argv[2] = NULL;

    g->status_proc = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    if (g->status_proc == NULL) {
        gtk_label_set_text(GTK_LABEL(g->status_label),
                           error != NULL ? error->message : "spawn failed");
        return;
    }
    gtk_label_set_text(GTK_LABEL(g->status_label), "checking…");
    g_subprocess_communicate_utf8_async(g->status_proc, NULL, NULL,
                                        overview_status_finished, g);
    (void) b;
}

static void
overview_selftest_clicked(GtkButton *b, gpointer ud)
{
    GenericModulePage *g = ud;
    const char *const argv[3] = { g->spec->script, "--selftest", NULL };
    GtkWidget *view = g_object_get_data(G_OBJECT(b), "cs-view");

    run_module_command(g->state, g->spec->id, "Self-test",
                       g->status_label, view, argv, FALSE);
}

/* Overview page: what the module is, its live status, and a self-test. */
static GtkWidget *
generic_build_overview(AppState *state, gpointer module_data)
{
    GenericModulePage *g = module_data;
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new(g->spec->title);
    GtkWidget *subtitle = gtk_label_new(g->spec->subtitle);
    GtkWidget *scroller = gtk_scrolled_window_new();
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *id_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *id_title = gtk_label_new("MODULE");
    GtkWidget *id_lbl = gtk_label_new(g->spec->id);
    GtkWidget *script_lbl = gtk_label_new(g->spec->script);
    GtkWidget *note = gtk_label_new(
        "Every verb of this module has a button on the pages beside this one. "
        "Open Raw Terminal (Ctrl+T) for the module's interactive menu.");
    GtkWidget *status_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *status_title = gtk_label_new("STATUS");
    GtkWidget *status_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *status = gtk_label_new("not checked");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh status");
    GtkWidget *selftest = gtk_button_new_with_label("Self-test");
    GtkWidget *pane;
    GtkWidget *view = NULL;

    gtk_widget_add_css_class(page, "dependency-page");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(subtitle, "page-subtitle");
    gtk_widget_add_css_class(id_card, "section-card");
    gtk_widget_add_css_class(id_title, "section-title");
    gtk_widget_add_css_class(id_lbl, "dependency-name");
    gtk_widget_add_css_class(script_lbl, "dependency-package");
    gtk_widget_add_css_class(note, "dependency-summary");
    gtk_widget_add_css_class(status_card, "section-card");
    gtk_widget_add_css_class(status_title, "section-title");
    gtk_widget_add_css_class(status, "dependency-summary");
    gtk_widget_add_css_class(refresh, "verb-button");
    gtk_widget_add_css_class(selftest, "verb-button");
    gtk_widget_add_css_class(selftest, "accent");

    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(id_title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(id_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(script_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(status_title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(subtitle), TRUE);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_hexpand(status, TRUE);

    gtk_box_append(GTK_BOX(id_card), id_title);
    gtk_box_append(GTK_BOX(id_card), id_lbl);
    gtk_box_append(GTK_BOX(id_card), script_lbl);
    gtk_box_append(GTK_BOX(id_card), note);

    gtk_box_append(GTK_BOX(status_row), status);
    gtk_box_append(GTK_BOX(status_row), selftest);
    gtk_box_append(GTK_BOX(status_row), refresh);
    gtk_box_append(GTK_BOX(status_card), status_title);
    gtk_box_append(GTK_BOX(status_card), status_row);

    pane = page_output_pane(&view);
    g->status_label = status;
    g_object_set_data(G_OBJECT(status), "cs-view", view);
    g_object_set_data(G_OBJECT(selftest), "cs-view", view);

    g_signal_connect(refresh, "clicked",
                     G_CALLBACK(overview_refresh_clicked), g);
    g_signal_connect(selftest, "clicked",
                     G_CALLBACK(overview_selftest_clicked), g);

    gtk_box_append(GTK_BOX(body), id_card);
    gtk_box_append(GTK_BOX(body), status_card);
    gtk_box_append(GTK_BOX(body), pane);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroller, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), body);

    gtk_box_append(GTK_BOX(page), title);
    gtk_box_append(GTK_BOX(page), subtitle);
    gtk_box_append(GTK_BOX(page), scroller);
    (void) state;
    return page;
}

/* A page spec with no button list is the overview. */
static GtkWidget *
build_module_view(AppState *state, gpointer module_data, const PageSpec *ps)
{
    GenericModulePage *g = module_data;
    if (ps == NULL || ps->spec == NULL)
        return generic_build_overview(state, g);
    return generic_build_spec_page(state, g, ps);
}

/* ==================================================================== */
/*  Per-module page tables                                              */
/* ==================================================================== */

#define S(n)  SCRIPT(n)

/* ---- 00_deps ---- */
static const PageSpec deps_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Tools", "applications-system-symbolic",
      "#STATUS|--status-tsv:Tool status|--preflight:Preflight|--distro-info:Distro info"
      "|#INSTALL|~install:Install a package!|--install-missing:Install missing!"
      "|--install-all:Install everything!|--install-pipx:Install pipx!"
      "|--install-git:Install git!" },
};

/* ---- 01_cred_validate ---- */
static const PageSpec cred_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Detect", "system-search-symbolic",
      "#OFFLINE DETECTION|--detect:Detect credentials|--list-formats:Supported formats"
      "|#LIVE VALIDATION|~--validate:Validate a credential" },
};

/* ---- 02_inventory ---- */
static const PageSpec inv_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Sweep", "view-refresh-symbolic",
      "#COLLECT|--run:Run inventory sweep|#REFERENCE|--regions:Configured regions" },
};

/* ---- 03_bucket_enum ---- */
static const PageSpec bucket_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Guess", "system-search-symbolic",
      "#UNAUTHENTICATED|~--domain:Guess buckets for a domain|~--perm:Probe one bucket"
      "|#AUTHENTICATED|--enum:Authenticated sweep" },
};

/* ---- 04_takeover ---- */
static const PageSpec takeover_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Scan", "system-search-symbolic",
      "#TARGETS|~--scan:Scan a domain|~--check:Check one subdomain"
      "|#REFERENCE|--list:Fingerprint table" },
};

/* ---- 04_pivot ---- */
static const PageSpec pivot_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Trust", "security-high-symbolic",
      "#THE DOCUMENT|~--trust:Grade a trust policy or role ARN"
      "|--providers:Providers and mechanisms"
      "|#WHAT A READER CAN CONCLUDE|--techniques:Gaps a delivered credential reveals" },
    { "Assume", "system-users-symbolic",
      "#ASSUME, THEN MEASURE|~--assume:Assume a role and probe what came back|~--enumerate:Enumerate inside the pivoted account"
      "|#ESCALATION|~--escalate:Does the delivered session write" },
    { "Reference", "view-list-symbolic",
      "#VERBS|--list:Verb list" },
};

/* ---- 05_iam_privesc ---- */
static const PageSpec privesc_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Map", "security-high-symbolic",
      "#CALLER|--map:Map current caller"
      "|#KNOWLEDGE|--list:Technique list|~--explain:Explain a technique"
      "|~--check:Check an action" },
};

/* ---- 06_role_chains ---- */
static const PageSpec chains_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Chains", "view-list-symbolic",
      "#DISCOVERY|--scan:Scan trust policies|--whoami:Who am I|--list:List roles"
      "|#TRACE|~--chain:Trace a chain from a role" },
};

/* ---- 07_policy_audit ---- */
static const PageSpec audit_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Audit", "security-high-symbolic",
      "#POLICIES|--audit:Audit live policies|~--audit:Audit a policy file" },
    { "Rules", "view-list-symbolic",
      "#KNOWLEDGE BASE|--list:Rule list|~--explain:Explain a rule"
      "|~--check:Check a keyword" },
};

/* ---- 08_secrets_scan ---- */
static const PageSpec secrets_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Scan", "system-search-symbolic",
      "#SCAN|~--scan:Scan a path|~--detect:Detect a secret"
      "|#REFERENCE|--list:Signature list" },
};

/* ---- 09_ssrf_imds ---- */
static const PageSpec ssrf_imds_legacy_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Probe", "network-transmit-receive-symbolic",
      "#TARGETS|~--probe:Probe a URL|~--check:Check a URL"
      "|#SWEEP|--tunnel:Sweep every endpoint|#REFERENCE|--list:Endpoint list" },
};

/* ---- 10_imdsv2_bypass ---- */
static const PageSpec imds2_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Bypass", "security-high-symbolic",
      "#REQUEST|~--ssrf:Request a v2 token|~--exec:Run a bypass chain"
      "|~--check:Check a target" },
    { "Reference", "view-list-symbolic",
      "#TECHNIQUES|--headers:Header techniques|~--list:Technique list" },
};

/* ---- 11_user_data ---- */
static const PageSpec userdata_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Extract", "document-save-symbolic",
      "#INSTANCE METADATA|--dump:Dump user-data|--extract:Extract and scan"
      "|#REFERENCE|--keys:Key list|--list:Metadata list" },
};

/* ---- 12_lambda_dump ---- */
static const PageSpec lambda_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Enumerate", "view-list-symbolic",
      "#ENUMERATION|--list:List functions|--urls:List function URLs" },
    { "Function", "document-save-symbolic",
      "#BY FUNCTION|~--dump:Dump configuration|~--download:Download code"
      "|~--env:Print environment" },
};

/* ---- 13_serverless_recon (superseded: see serverless_pages below, which
   serves the merged 12_serverless module; this table is kept only while a
   registry row still names 13. ---- */
static const PageSpec serverless_recon_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Enumerate", "view-list-symbolic",
      "#ENUMERATION|--list:List functions|--urls:List function URLs" },
    { "Invoke", "system-run-symbolic",
      "#FUNCTION|~--env:Print environment"
      "|#SWEEP|~--invoke:Invoke a function|--all:Full sweep" },
};

/* ---- 14_registry_recon ---- */
static const PageSpec registry_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Registries", "view-list-symbolic",
      "#SWEEP|--scan:Scan registries"
      "|#REPOSITORY|~--list:List repositories|~--images:List images"
      "|~--tags:List tags|~--pull:Pull an image" },
    { "Marketplace OSINT", "system-search-symbolic",
      "#DOCKER HUB|~--dhl:Search a namespace" },
};

/* ---- 15_container_escape ---- */
static const PageSpec escape_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Scan", "security-high-symbolic",
      "#SCAN|--all:Full escape scan|--check:Check runtime" },
    { "Surface", "view-list-symbolic",
      "#SURFACE|--mounts:Mount points|--proc:Proc and namespaces"
      "|--cgroup:Cgroup escape|--host:Host and docker socket" },
    { "Reference", "view-list-symbolic", "#TECHNIQUES|--list:Technique list" },
};

/* ---- 16_k8s_attack_surface ---- */
static const PageSpec k8ssurf_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Enumerate", "view-list-symbolic",
      "#CLUSTER|--clusters:List clusters"
      "|#WORKLOAD|--nodes:List nodes|--pods:List pods|--secrets:List secrets" },
    { "Audit", "security-high-symbolic",
      "#AUDIT|--rbac:RBAC self-audit|--all:Full sweep|#REFERENCE|--list:Verb list" },
};

/* ---- 17_k8s_secrets ---- */
static const PageSpec k8ssec_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Secrets", "dialog-password-symbolic",
      "#EXTRACT|--extract:Extract secrets|~~--decode:Decode a secret (namespace secret)"
      "|--sa-tokens:Service-account tokens" },
    { "Abuse", "security-high-symbolic",
      "#RBAC|--rbac-abuse:RBAC abuse paths|--all:Full sweep"
      "|#REFERENCE|--list:Verb list" },
};

/* ---- 18_network (was 18_cloud_dns + 19_vpc_map + 20_sg_audit + 04_takeover) ---- */
static const PageSpec dns_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Zones", "network-server-symbolic",
      "#HOSTED ZONES|--zones:List hosted zones|--all:Zones then dangling audit"
      "|#ONE NAME|~--resolve:Resolve a name" },
    { "Records", "view-list-symbolic",
      "#ZONE CONTENT|~--records:Dump zone records"
      "|~--dangling:Audit dead CNAME targets" },
    { "Transfer", "security-high-symbolic",
      "#AXFR|~--axfr:Attempt a zone transfer|#REFERENCE|--list:Technique list" },
};

/* ---- 19_vpc_map ---- */
static const PageSpec vpc_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Topology", "network-transmit-receive-symbolic",
      "#NETWORK|--vpcs:List virtual networks|--subnets:List subnets"
      "|--routes:List route tables|--gateways:List gateways"},
    { "Map", "view-fullscreen-symbolic",
      "#EXPOSURE|--map:Full map and findings|#REFERENCE|--list:Verb reference" },
};

/* ---- 20_sg_audit ---- */
static const PageSpec sg_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Audit", "security-medium-symbolic",
      "#COLLECT|--rules:Collect every rule|--audit:World-open findings"
      "|#ONE PORT|~--explain:Explain a port" },
    { "Reference", "dialog-information-symbolic",
      "#PORT CLASSES|--list:Port class table" },
};

/* ---- 21_db_exposure ---- */
static const PageSpec db_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Inventory", "drive-harddisk-symbolic",
      "#MANAGED DATABASES|--instances:List instances|--public:Publicly reachable only"
      "|#REACH|~~--probe:Probe an endpoint (host [port])" },
    { "Reference", "dialog-information-symbolic",
      "#ENGINES|--engines:Engine and port table" },
};

/* ---- 22_audit_evasion ---- */
static const PageSpec ae_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Posture", "document-open-recent-symbolic",
      "#OBSERVED NOW|--posture:Check audit configuration"
      "|#BLIND SPOTS|--blind:Missing or unobservable controls" },
    { "Reference", "dialog-information-symbolic",
      "#CONTROLS|--list:Control catalogue|~--explain:Explain one control" },
};

/* ---- 23_persistence ---- */
static const PageSpec persist_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Footholds", "document-open-recent-symbolic",
      "#IN THE ACCOUNT|--footholds:Scan for persistence artefacts"
      "|~--explain:Explain one mechanism" },
    { "Reference", "dialog-information-symbolic",
      "#MECHANISMS|--list:Mechanism catalogue" },
};

/* ---- Reclaimed and campaign tables (one per surviving module) ----
   Each page names the script its verbs live in, so a module whose id and
   file name disagree still gets a real page, and a merged module keeps one
   table instead of a second ModuleSpec. */

/* 09_imds — what 09_ssrf_imds, 10_imdsv2_bypass and 11_user_data used to be. */
static const PageSpec imds_pages[] = {
    { "Metadata", "document-open-recent-symbolic",
      "#THIS HOST|--probe:Probe the local metadata service"
      "|#FROM A URL|~--check:Check a url|~--token:Fetch a v2 token"
      "|~--exec:Exec through SSRF|~--userdata:Read user-data"
      "|#ANALYSE|--keys:Instance identity keys|--creds:Dump every credential",
      "09_imds.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--endpoints:Endpoint catalogue|--techniques:Technique catalogue"
      "|--list:All verbs", "09_imds.sh" },
};

/* 12_serverless — what 12_lambda_dump and 13_serverless_recon used to be. */
static const PageSpec serverless_pages[] = {
    { "Overview", "dialog-information-symbolic",
      "#WHAT IS THERE|--list:List functions across providers"
      "|#SOURCE|--urls:Function invoke urls", "12_serverless.sh" },
    { "Functions", "document-open-recent-symbolic",
      "#ONE FUNCTION|~--env:Read its environment|~--dump:Pull its configuration"
      "|~--download:Download its code|#ALL OF THEM|--download-all:Download everything",
      "12_serverless.sh" },
    { "Invoke", "system-run-symbolic",
      "#REACH IT|~~--invoke:Invoke one function|--all:Full sweep",
      "12_serverless.sh" },
};

/* 16_kubernetes — what 16_k8s_attack_surface and 17_k8s_secrets used to be. */
static const PageSpec kubernetes_pages[] = {
    { "Overview", "dialog-information-symbolic", "16_kubernetes.sh" },
    { "Clusters", "document-open-recent-symbolic",
      "#WHERE|--clusters:Reachable clusters|--kubeconfig:Kubeconfig context"
      "|#INSIDE|--nodes:Nodes|--pods:Pods", "16_kubernetes.sh" },
    { "Secrets", "dialog-password-symbolic",
      "#ACCESS|--secrets:Secrets|--sa-tokens:Service account tokens"
      "|~--decode:Decode one secret|--extract:Extract and decode all",
      "16_kubernetes.sh" },
    { "Abuse", "dialog-warning-symbolic",
      "#RBAC|--rbac:Who may do what|--abuse:Escalation checklist",
      "16_kubernetes.sh" },
};

/* 18_network — what 18_cloud_dns, 19_vpc_map, 20_sg_audit and 04_takeover
   used to be. */
static const PageSpec network_pages[] = {
    { "Overview", "dialog-information-symbolic", "18_network.sh" },
    { "Naming", "document-open-recent-symbolic",
      "#ZONES|--zones:Hosted zones|~--records:Records in a zone"
      "|~--resolve:Resolve one name|#BAD RECORDS|~--dangling:Takeover-prone CNAMEs"
      "|~--takeover:Full takeover pass|~--claim:Check one host"
      "|~--axfr:Zone transfer", "18_network.sh" },
    { "Topology", "network-wired-symbolic",
      "#NETWORKS|--vpcs:VPCs and networks|--subnets:Subnets"
      "|--routes:Route tables|--gateways:Gateways|--map:Draw the map",
      "18_network.sh" },
    { "Exposure", "dialog-warning-symbolic",
      "#FIREWALL|--rules:Security group rules|--audit:World-open, graded by port"
      "|#REFERENCE|--fingerprints:Takeover fingerprints",
      "18_network.sh" },
};

/* 39_tenant_enum */
static const PageSpec tenant_pages[] = {
    { "Overview", "dialog-information-symbolic", "39_tenant_enum.sh" },
    { "Tenant", "document-open-recent-symbolic",
      "#THE ORG|~--tenant:Tenant id and federation realm"
      "|#NAMESPACES|~--buckets:Bucket namespaces|~--projects:GCP projects"
      "|~--azure:Azure storage accounts|~--apis:Resolving subdomains",
      "39_tenant_enum.sh" },
    { "Certificates", "security-high-symbolic",
      "#CT LOGS|~--crt:Names from certificate transparency"
      "|#REVERSE DNS|~~--ptr:Sweep a range", "39_tenant_enum.sh" },
};

/* 41_api_discovery */
static const PageSpec apidisc_pages[] = {
    { "Overview", "dialog-information-symbolic", "41_api_discovery.sh" },
    { "Discover", "document-open-recent-symbolic",
      "#ENDPOINTS|~--discover:Brute paths against a measured baseline"
      "|~--spec:Find the spec document|--wordlist:The wordlist it sends",
      "41_api_discovery.sh" },
    { "Methods", "system-run-symbolic",
      "#VERBS|~~--methods:Which verbs one path answers", "41_api_discovery.sh" },
};

/* 42_openapi */
static const PageSpec openapi_pages[] = {
    { "Overview", "dialog-information-symbolic", "42_openapi.sh" },
    { "Spec", "document-open-recent-symbolic",
      "#FIND IT|~--find:Probe well-known spec paths and vendor doc trees"
      "|~--analyze:Read a spec file or url", "42_openapi.sh" },
    { "Report", "view-list-symbolic",
      "#WHAT IT ADMITS|--auth:Operations with no usable security"
      "|--endpoints:Every operation|--params:Url-taking parameters"
      "|~--diff:Two specs, added and removed", "42_openapi.sh" },
};

/* 43_graphql */
static const PageSpec graphql_pages[] = {
    { "Overview", "dialog-information-symbolic", "43_graphql.sh" },
    { "Schema", "document-open-recent-symbolic",
      "#INTROSPECT|~--find:Probe graph paths|~--introspect:Pull the schema"
      "|~--schema:Who may query what", "43_graphql.sh" },
    { "Surface", "view-list-symbolic",
      "#FIELDS|~--queries:Root fields|~--fields:Field graph"
      "|~--depth:Deepest path|~--check:One endpoint", "43_graphql.sh" },
};

/* 68_graphql_dos */
static const PageSpec graphqldos_pages[] = {
    { "Overview", "dialog-information-symbolic", "68_graphql_dos.sh" },
    { "Curve", "view-list-symbolic",
      "#THE COST CURVE|~--probe:Control and every rung"
      "|~--cost:The same curve as a table", "68_graphql_dos.sh" },
    { "Shapes", "document-open-recent-symbolic",
      "#ONE SHAPE AT A TIME"
      "|~--depth:Nested fields|~--aliases:One field, many names"
      "|~--batched:Many operations, one body"
      "|~--fragment:A fragment that spreads into itself"
      "|~--directive:@include on a heavy field"
      "|~--mutate:Alias storm on a mutation — writes", "68_graphql_dos.sh" },
    { "Reference", "help-about-symbolic",
      "--techniques:Every cost shape|--rungs:The probe ladder"
      "|--help:Usage", "68_graphql_dos.sh" },
};

/* 56_grpc */
static const PageSpec grpc_pages[] = {
    { "Overview", "dialog-information-symbolic", "56_grpc.sh" },
    { "Discover", "network-server-symbolic",
      "#IS THIS A gRPC ENDPOINT AT ALL"
      "|~--grpc-status:Health check on the given port"
      "|~--port-scan:Which of the usual ports answer"
      "|~--discover:Ports that speak gRPC, with scheme", "56_grpc.sh" },
    { "Reflection", "view-list-symbolic",
      "#THE SCHEMA IS THE PRIZE"
      "|~--reflect:Does reflection answer without credentials"
      "|~--services:Every service in the descriptor dump"
      "|~--describe:One service, its methods and their verbs"
      "|~--proto:Keep the descriptor bytes for a reader"
      "|--codes:gRPC status codes and what each one proves", "56_grpc.sh" },
    { "Methods", "system-users-symbolic",
      "#DOES THE METHOD ANSWER WITHOUT A TOKEN"
      "|~--auth:Anonymous against authenticated, one method", "56_grpc.sh" },
    { "Fields", "dialog-warning-symbolic",
      "#WHAT THE WIRE FORMAT PERMITS"
      "|~--fuzz:Field confusion against one method"
      "|--payloads:The confusion table"
      "|--list:Every technique, by where the mistake lives", "56_grpc.sh" },
};

/* 57_websocket */
static const PageSpec websocket_pages[] = {
    { "Overview", "dialog-information-symbolic", "57_websocket.sh" },
    { "Discover", "network-wired-symbolic",
      "#WHERE A SOCKET LIVES"
      "|~--discover:Which path answers an upgrade"
      "|--paths:The path table", "57_websocket.sh" },
    { "Handshake", "dialog-password-symbolic",
      "#THE ONLY THING HTTP SEES"
      "|~--handshake:One upgrade, headers and verdict"
      "|~--auth:Does the socket open with no credential", "57_websocket.sh" },
    { "Cross-Site", "dialog-warning-symbolic",
      "#THE BROWSER SENDS THE COOKIE FOR YOU"
      "|~--cswsh:Every origin shape a server may accept"
      "|--origins:The origin table"
      "|--frames:The RFC 6455 opcodes", "57_websocket.sh" },
    { "Messages", "document-open-recent-symbolic",
      "#THE SMALLER HALF OF THE PROBLEM"
      "|~--messages:Open the socket and read what it pushes"
      "|~--fuzz:Message-level payloads"
      "|--payloads:The payload table", "57_websocket.sh" },
};

/* 63_pagination */
static const PageSpec pagination_pages[] = {
    { "Overview", "dialog-information-symbolic", "63_pagination.sh" },
    { "Default", "view-list-symbolic",
      "#WHAT COMES BACK WHEN ASKED FOR NOTHING"
      "|~--probe:The unparameterised response"
      "|~--walk:Does walking pages enumerate the table"
      "|--params:The pagination parameters", "63_pagination.sh" },
    { "Limits", "document-open-recent-symbolic",
      "#ASK FOR ONE, ASK FOR A MILLION"
      "|~--limits:Compare the two"
      "|~--inject:Does the page size reach the query"
      "|--verdicts:What each answer means", "63_pagination.sh" },
    { "Cursors", "emblem-synchronizing-symbolic",
      "#IS THE CURSOR OPAQUE"
      "|~--cursor:A token a client can edit", "63_pagination.sh" },
};

/* 60_resp_smuggle */
static const PageSpec respsmuggle_pages[] = {
    { "Overview", "dialog-information-symbolic", "60_resp_smuggle.sh" },
    { "Posture", "security-medium-symbolic",
      "#WHAT IT SAYS WITHOUT ANY PAYLOAD"
      "|~--probe:Leak, cache and headers in one pass"
      "|~--headers:Which security headers are missing"
      "|~--cache:Would a shared cache keep this", "60_resp_smuggle.sh" },
    { "Splice", "dialog-warning-symbolic",
      "#THE SECOND RESPONSE"
      "|~--reflect:Is anything echoed into the header block"
      "|~--split:Every CR LF vector"
      "|--vectors:The vector table", "60_resp_smuggle.sh" },
    { "Errors", "document-open-symbolic",
      "#WHAT THE ERROR PATH SAYS"
      "|~--leak:Malformed requests and what came back"
      "|--params:Parameters that reach a header", "60_resp_smuggle.sh" },
};

/* 58_sse */
static const PageSpec sse_pages[] = {
    { "Overview", "dialog-information-symbolic", "58_sse.sh" },
    { "Streams", "document-open-recent-symbolic",
      "#IS THERE A STREAM HERE"
      "|~--probe:Which path pushes without a credential"
      "|~--auth:With and without a cookie"
      "|--paths:The path table", "58_sse.sh" },
    { "Browser", "web-browser-symbolic",
      "#CAN A PAGE READ IT"
      "|~--cors:EventSource from a foreign origin"
      "|~--inject:Write into the stream every reader sees", "58_sse.sh" },
    { "Content", "document-open-symbolic",
      "#WHAT CAME DOWN IT"
      "|~--sample:Read the stream and print the events"
      "|--events:The event grammar", "58_sse.sh" },
};

/* 27_rebinding */
static const PageSpec rebind_pages[] = {
    { "Overview", "dialog-information-symbolic", "27_rebinding.sh" },
    { "Resolve", "view-refresh-symbolic",
      "#DOES THE NAME HOLD STILL"
      "|~--check:Resolve twice and compare"
      "|~--ttl:How fast the answer changes"
      "|~--pin:What a resolver pins to", "27_rebinding.sh" },
    { "Rebind", "network-workgroup-symbolic",
      "#THE FLIP|~--rebind:Serve a zone that answers twice"
      "|--responder:Print the authoritative server"
      "|~--hosts:The resolver config, for reproduction", "27_rebinding.sh" },
    { "Reach", "network-server-symbolic",
      "#WHAT IS BEHIND THE ADDRESS"
      "|~--metadata:Make an app fetch the metadata service by name"
      "|~--api:The same, aimed at an internal service"
      "|--targets:The reach table"
      "|--addresses:The addresses a rebind lands on", "27_rebinding.sh" },
};

/* 65_deserialization */
static const PageSpec deser_pages[] = {
    { "Overview", "dialog-information-symbolic", "65_deserialization.sh" },
    { "Formats", "document-open-symbolic",
      "#WHAT THE SERVER WILL REBUILD"
      "|--formats:The magic, the format, where it appears"
      "|--markers:The strings that prove it parsed our stream"
      "|--gadgets:Library names that make it exploitable", "65_deserialization.sh" },
    { "Sweep", "system-search-symbolic",
      "#SEND A STREAM"
      "|~--probe:Does the endpoint take a body at all"
      "|~--detect:Is there a serialized stream here"
      "|~--check:One family, control first"
      "|~--scan:Every family, one control each", "65_deserialization.sh" },
    { "Payloads", "document-send-symbolic",
      "#THE SHAPES"
      "|--payloads:Every payload with what it proves"
      "|~--payloads:One family only", "65_deserialization.sh" },
    { "Reference", "help-about-symbolic",
      "|--list:Formats and their magic"
      "|--status-tsv:Module status"
      "|--help:Usage", "65_deserialization.sh" },
};

/* 66_webhook_sig */
static const PageSpec websig_pages[] = {
    { "Overview", "dialog-information-symbolic", "66_webhook_sig.sh" },
    { "Control", "dialog-password-symbolic",
      "#IS THIS A SIGNED ENDPOINT"
      "|~--probe:One valid signature — if that is refused, stop"
      "|--schemes:Every scheme, its header and its algorithm", "66_webhook_sig.sh" },
    { "Bypass", "dialog-warning-symbolic",
      "#WHAT THE RECEIVER FORGETS"
      "|~--check:The control, then every vector"
      "|~--replay:The same signed request, twice"
      "|~--confusion:Public key as secret, alg=none", "66_webhook_sig.sh" },
    { "Window", "alarm-symbolic",
      "#DOES THE TIMESTAMP MEAN ANYTHING"
      "|~--window:An hour ago, and an hour ahead"
      "|--vectors:What each vector is looking for", "66_webhook_sig.sh" },
    { "Reference", "help-about-symbolic",
      "|--list:Every bypass"
      "|--status-tsv:Module status"
      "|--help:Usage", "66_webhook_sig.sh" },
};

/* 67_token_refresh */
static const PageSpec tokenrefresh_pages[] = {
    { "Overview", "dialog-information-symbolic", "67_token_refresh.sh" },
    { "Control", "dialog-password-symbolic",
      "#DOES THE TOKEN WORK AT ALL"
      "|~--probe:One refresh — if that fails, stop"
      "|--grants:Which grant the stack still implements", "67_token_refresh.sh" },
    { "Lifecycle", "appointment-soon-symbolic",
      "#ROTATION AND REVOCATION"
      "|~--rotate:Walk the chain, then offer the ORIGINAL again"
      "|~--replay:The same refresh token, twice"
      "|~--revoke:Refresh, revoke, refresh again", "67_token_refresh.sh" },
    { "Scope", "preferences-system-symbolic",
      "#WHAT IT GRANTS"
      "|~--scopes:Ask for more than was issued"
      "|~--fixation:A token the server never issued"
      "|~--window:What lifetime the endpoint admits to", "67_token_refresh.sh" },
    { "Reference", "help-about-symbolic",
      "|--vectors:Every failure mode"
      "|--verdicts:What each verdict grades as"
      "|--help:Usage", "67_token_refresh.sh" },
};

/* 78_replay_nonce */
static const PageSpec replay_pages[] = {
    { "Overview", "dialog-information-symbolic", "78_replay_nonce.sh" },
    { "Replay", "view-refresh-symbolic",
      "#SEND IT AGAIN"
      "|~--probe:One request, then the same one"
      "|~--check:Every replay vector that needs no concurrency"
      "|~--replay:The same signed request n times", "78_replay_nonce.sh" },
    { "Nonce", "dialog-password-symbolic",
      "#IS THE NONCE CONSUMED"
      "|~--nonce:Same nonce twice, then fresh ones"
      "|~--timestamp:An hour ago, now, an hour ahead", "78_replay_nonce.sh" },
    { "Idempotency", "object-select-symbolic",
      "#THE Idempotency-Key CONTRACT"
      "|~--idempotency:Same key same body, then same key new body"
      "|--list:Which headers carry a nonce", "78_replay_nonce.sh" },
    { "Reference", "help-about-symbolic",
      "|--vectors:Every failure mode|--help:Usage", "78_replay_nonce.sh" },
};

/* 69_bfuzz */
static const PageSpec bfuzz_pages[] = {
    { "Overview", "dialog-information-symbolic", "69_bfuzz.sh" },
    { "Detect", "system-search-symbolic",
      "#IS IT PARSING BINARY AT ALL"
      "|~--detect:Octet-stream then one empty frame"
      "|~--probe:The control, then one truncated varint", "69_bfuzz.sh" },
    { "Fuzz", "applications-engineering-symbolic",
      "#THE MUTATION SET"
      "|~--fuzz:Every mutation against the same control"
      "|~--truncate:Cut a valid message at every byte", "69_bfuzz.sh" },
    { "Types", "text-x-generic-symbolic",
      "#INTEGERS AND TYPES"
      "|~--varint:Values the type cannot hold"
      "|~--packed:A repeated field in the wrong packing"
      "|~--any:A type_url the server never packs", "69_bfuzz.sh" },
    { "Reference", "help-about-symbolic",
      "|--techniques:Every mutation|--wire:Wire types|--help:Usage", "69_bfuzz.sh" },
};

/* 71_logic */
static const PageSpec logic_pages[] = {
    { "Overview", "dialog-information-symbolic", "71_logic.sh" },
    { "Baseline", "document-save-symbolic",
      "#WHAT DOES ONE UNIT COST"
      "|~--probe:Measure the untouched price every other verb compares to"
      "|~--techniques:Every shape worth trying", "71_logic.sh" },
    { "Quantity", "list-add-symbolic",
      "#THE NUMBER THE CLIENT NAMES"
      "|~--quantity:Negative, zero, overflowing and fractional amounts", "71_logic.sh" },
    { "Price", "document-edit-symbolic",
      "#DOES THE CLIENT OWN THE PRICE"
      "|~--price:A price field the server should be setting, and a currency swap", "71_logic.sh" },
    { "Sequence", "media-playlist-repeat-symbolic",
      "#THE ORDER IS THE ATTACK"
      "|~--sequence:Two legitimate actions whose order breaks the rule"
      "|~--trial:Refund above payment, premium on a trial"
      "|~--discount:The same coupon twice, and two at once", "71_logic.sh" },
    { "Reference", "help-about-symbolic",
      "|--list:Verbs|--help:Usage", "71_logic.sh" },
};

/* 72_race */
static const PageSpec race_pages[] = {
    { "Overview", "dialog-information-symbolic", "72_race.sh" },
    { "Probe", "system-run-symbolic",
      "#ONE ALONE, THEN TWENTY TOGETHER"
      "|~--probe:The contrast is the finding"
      "|~--fire:Raw concurrency with no interpretation", "72_race.sh" },
    { "Money", "emblem-money-symbolic",
      "#THE CASE THAT HAS A BILL"
      "|~--double-spend:Concurrent debits after one balance read"
      "|~--coupon:One code, many redemptions at once"
      "|~--limit:A rolling window fired simultaneously", "72_race.sh" },
    { "Gate", "channel-secure-symbolic",
      "#DOES THE ENDPOINT SERIALISE AT ALL"
      "|~--gate:Distinct responses, which is what a lock looks like", "72_race.sh" },
    { "Reference", "help-about-symbolic",
      "|--techniques:Every check-then-act shape|--list:Verbs|--help:Usage", "72_race.sh" },
};

/* 74_llm */
static const PageSpec llm_pages[] = {
    { "Overview", "dialog-information-symbolic", "74_llm.sh" },
    { "Discover", "system-search-symbolic",
      "#IS THERE A MODEL HERE"
      "|~--probe:One request, and whether it wants a credential"
      "|~--keys:Every known route fired without one"
      "|~--lease-scan:All routes with the config-leak probe", "74_llm.sh" },
    { "Lease", "dialog-password-symbolic",
      "#WHAT THE MODEL WAS TOLD"
      "|~--lease:System prompt, server key and config probes", "74_llm.sh" },
    { "Inject", "text-x-generic-symbolic",
      "#THE INSTRUCTION CHANNEL"
      "|~--inject:Can user text become a system message"
      "|~--tools:What the agent behind the model can reach", "74_llm.sh" },
    { "Cost", "preferences-system-time-symbolic",
      "#ONE REQUEST, HOW MUCH"
      "|~--cost:Is there a ceiling on time or size", "74_llm.sh" },
    { "Reference", "help-about-symbolic",
      "|--techniques:Probes and routes|--list:Verbs|--help:Usage", "74_llm.sh" },
};

/* 75_rotation */
static const PageSpec rotation_pages[] = {
    { "Overview", "dialog-information-symbolic", "75_rotation.sh" },
    { "Revocation", "dialog-password-symbolic",
      "#IS THE OLD KEY DEAD"
      "|~~--old-key:The retired credential against the same route as the new one"
      "|~~--leak-check:A credential from an earlier finding", "75_rotation.sh" },
    { "Window", "preferences-system-time-symbolic",
      "#HOW LONG AFTER THE ROTATION"
      "|~~~--grace:The old key plus the clock, against the advertised window", "75_rotation.sh" },
    { "Policy", "channel-secure-symbolic",
      "#WHERE THE CREDENTIAL IS ACCEPTED"
      "|~--policy:Every transport, so a key in the query string shows up"
      "|~--windows:exp, nbf and the lifetime a rotation cannot beat", "75_rotation.sh" },
    { "Reference", "help-about-symbolic",
      "|--techniques:Transports and checks|--list:Verbs|--help:Usage", "75_rotation.sh" },
};

/* 77_mobile */
static const PageSpec mobile_pages[] = {
    { "Overview", "dialog-information-symbolic", "77_mobile.sh" },
    { "Discover", "system-search-symbolic",
      "#WHAT A MOBILE BACKEND EXPOSES"
      "|~--probe:Config, flags, bootstrap, device routes"
      "|~--static:Debug APKs and build artefacts on the production origin", "77_mobile.sh" },
    { "Config", "document-open-symbolic",
      "#WHAT IS INSIDE THE REMOTE CONFIG"
      "|~~--config:One document, graded by content not by status", "77_mobile.sh" },
    { "Versions", "view-refresh-symbolic",
      "#AN ANCIENT VERSION AND A FUTURE ONE"
      "|~--versions:Both, because one alone proves nothing", "77_mobile.sh" },
    { "Links", "web-browser-symbolic",
      "#WHO MAY OPEN THIS HOST'S LINKS"
      "|~--deep:assetlinks.json and the Apple association file"
      "|~--cert:The TLS the app's traffic actually gets", "77_mobile.sh" },
    { "Reference", "help-about-symbolic",
      "|--techniques:Headers and routes|--list:Verbs|--help:Usage", "77_mobile.sh" },
};

/* 70_spec_diff */
static const PageSpec specdiff_pages[] = {
    { "Overview", "dialog-information-symbolic", "70_spec_diff.sh" },
    { "Compare", "document-open-recent-symbolic",
      "#WHAT MOVED BETWEEN TWO SPECS"
      "|~~--diff:Every change, graded against its siblings"
      "|~~--auth:Only the security column"
      "|~~--new:Only endpoints that did not exist", "70_spec_diff.sh" },
    { "Surface", "view-list-symbolic",
      "#THE REST OF THE DIFF"
      "|~~--params:Only the parameter surface"
      "|~--deprecated:Deprecated endpoints and whether they are guarded", "70_spec_diff.sh" },
    { "Baseline", "document-save-symbolic",
      "#FREEZE A VERSION"
      "|~~--snapshot:Save a spec as tomorrow's baseline", "70_spec_diff.sh" },
    { "Reference", "help-about-symbolic",
      "|--classes:Every class of change|--help:Usage", "70_spec_diff.sh" },
};

/* 44_jwt */
static const PageSpec jwt_pages[] = {
    { "Overview", "dialog-information-symbolic", "44_jwt.sh" },
    { "Inspect", "document-open-recent-symbolic",
      "#A TOKEN|--inspect:Header, claims and grade|--claims:Claims only"
      "|--keys:PEM keys it can use", "44_jwt.sh" },
    { "Attack", "dialog-warning-symbolic",
      "#FORGE|~--forge:Forge with a chosen scheme|~--kid:kid injection"
      "|~--jku:jku injection|#BREAK|~--crack:Offline hmac crack"
      "|~~--alg:Try alg:none and key confusion live", "44_jwt.sh" },
};

/* 45_oauth — the flow is the attack surface, so the pages follow the flow
 * order: what the issuer says about itself, then each gate the flow passes. */
static const PageSpec oauth_pages[] = {
    { "Overview", "dialog-information-symbolic", "45_oauth.sh" },
    { "Issuer", "document-open-recent-symbolic",
      "#WHAT IT SAYS|~--discover:Read the well-known document"
      "|~--check:Discovery plus what it admits"
      "|--paths:Every discovery path tried", "45_oauth.sh" },
    { "Registration", "dialog-warning-symbolic",
      "#REDIRECT_URI|~~~--redirect:Endpoint, client and registered uri"
      "|--redirects:The variant table"
      "|#STATE|~~~--state:Is state a nonce or a decoration"
      "|#CLIENT SECRET|~--pkce:Is PKCE required and is plain allowed", "45_oauth.sh" },
    { "Authorization", "network-server-symbolic",
      "#SCOPE|~~~--scope:Scopes the client never registered"
      "|#AUTH PARAMS|~~~--login-hint:prompt and login_hint behaviour"
      "|#GRANT|~~--implicit:response_type=token still on", "45_oauth.sh" },
    { "Token", "dialog-password-symbolic",
      "#FINISH THE FLOW|~~--cursor:Exchange a code, then replay it", "45_oauth.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--tests:Every check it runs|--redirects:The redirect variants"
      "|--paths:Discovery paths", "45_oauth.sh" },
};

/* 46_key_harvest */
static const PageSpec keyharvest_pages[] = {
    { "Overview", "dialog-information-symbolic", "46_key_harvest.sh" },
    { "Harvest", "document-open-recent-symbolic",
      "#A PAGE|~--harvest:Page and every script it loads"
      "|~--js:One bundle|~--headers:Response headers", "46_key_harvest.sh" },
    { "Detect", "dialog-password-symbolic",
      "#LOCAL|~--detect:Scan a file or stdin|~--defang:Explain one value"
      "|--providers:The provider table", "46_key_harvest.sh" },
};

/* 47_auth_bypass */

/* 48_bola */
static const PageSpec bola_pages[] = {
    { "Overview", "dialog-information-symbolic", "48_bola.sh" },
    { "Objects", "document-open-recent-symbolic",
      "#ONE ID|~~--check:One base, one family, one id"
      "|~--matrix:Every family against one id"
      "|~~--enumerate:Walk the neighbours of a known id",
      "48_bola.sh" },
    { "Sweep", "view-list-symbolic",
      "#WIDE|~~--sweep:Msissn sweep across bases|~~--idlist:Generate ids to try"
      "|#REFERENCE|--patterns:Family table", "48_bola.sh" },
};

/* 49_bfla */
static const PageSpec bfla_pages[] = {
    { "Overview", "dialog-information-symbolic", "49_bfla.sh" },
    { "Functions", "document-open-recent-symbolic",
      "#ONE FUNCTION|~~--check:One base, one function, one verb"
      "|~--methods:Which verbs one path answers"
      "|~--object:Two sessions, one object", "49_bfla.sh" },
    { "Sweep", "view-list-symbolic",
      "#WIDE|~~--sweep:Every function against one base"
      "|~~--compare:Where two sessions diverge"
      "|#REFERENCE|--functions:Function table", "49_bfla.sh" },
};

/* 50_mass_assign */
static const PageSpec massassign_pages[] = {
    { "Overview", "dialog-information-symbolic", "50_mass_assign.sh" },
    { "Fields", "document-open-recent-symbolic",
      "#ONE FIELD|~~~--check:Class, field and readback url"
      "|#THE FORM|~~--sweep:Every field against one base"
      "|~--shadow:Read the portal's own swagger", "50_mass_assign.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--fields:Field table|--verdicts:How a verdict is reached",
      "50_mass_assign.sh" },
};

/* 51_hpp — the parameter has one name and the server reads it twice */
static const PageSpec hpp_pages[] = {
    { "Overview", "dialog-information-symbolic", "51_hpp.sh" },
    { "Duplicate", "document-open-recent-symbolic",
      "#ONE PARAMETER|~~~--check:Url and parameter, every shape"
      "|~--dup:Just the plain duplicate"
      "|#WHICH PARSER|~~--split:Attribute the fold to a class", "51_hpp.sh" },
    { "Encodings", "network-transmit-symbolic",
      "#SYNTAX|~~--array:Array shapes an app may flatten"
      "|~~--encoding:What a proxy splits on"
      "|~~--smuggle:The pair a filter misses", "51_hpp.sh" },
    { "Body", "dialog-password-symbolic",
      "#JSON AND QUERY|~~--json:Same name in both places"
      "|~~--query:One unchallenged read", "51_hpp.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--params:Parameters worth planting|--list:Every vector", "51_hpp.sh" },
};

/* 52_rate_limit */
static const PageSpec ratelimit_pages[] = {
    { "Overview", "dialog-information-symbolic", "52_rate_limit.sh" },
    { "Limit", "document-open-recent-symbolic",
      "#WHERE IT BITES|~~--probe:Count requests to the first limit",
      "52_rate_limit.sh" },
    { "Bypass", "dialog-warning-symbolic",
      "#ROTATE|~~--rotate:Control, refill, then rotate a header"
      "|~~--check:Plain versus one headered request"
      "|#REFERENCE|--headers:Header table|--modes:Header modes",
      "52_rate_limit.sh" },
};

/* 53_injection — the value is interpreted, not stored */
static const PageSpec injection_pages[] = {
    { "Overview", "dialog-information-symbolic", "53_injection.sh" },
    { "Sweep", "document-open-recent-symbolic",
      "#ONE PARAMETER|~~~~--check:Url, parameter, where it lands, family"
      "|#FAMILIES|~~--sqli:Boolean pair and arithmetic"
      "|~~--nosqli:Operator objects in a JSON body"
      "|~~--cmdi:Shell metacharacters", "53_injection.sh" },
    { "Renderers", "network-transmit-symbolic",
      "#TEMPLATES|~~--ssti:Template evaluation, proved by 49"
      "|~~--ldap:Filter injection"
      "|~~--xpath:Predicate injection", "53_injection.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--families:What each family proves|--payloads:Every payload"
      "|--params:Parameters worth testing", "53_injection.sh" },
};

/* 54_ssrf */
static const PageSpec ssrf_pages[] = {
    { "Overview", "dialog-information-symbolic", "54_ssrf.sh" },
    { "Probe", "document-open-recent-symbolic",
      "#ONE PARAMETER|~~~--probe:App url, parameter, method"
      "|~~~--check:App url, parameter, target"
      "|~~--sweep:Every parameter against one base"
      "|~~--callback:Listen for a fetch", "54_ssrf.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--targets:Fetch targets|--params:Url-taking parameters"
      "|--vendors:Vendor oracles|~--parse:Parse a saved body"
      "|~~--save:Keep one body", "54_ssrf.sh" },
};

/* 59_smuggling — where the front end and the back end stop agreeing */
static const PageSpec smuggle_pages[] = {
    { "Overview", "dialog-information-symbolic", "59_smuggling.sh" },
    { "Sweep", "dialog-warning-symbolic",
      "#ONE HOST|~~--probe:Every framing pair against one request"
      "|#SINGLE TECHNIQUE|~~--clte:Content-Length vs Transfer-Encoding"
      "|~~--te:Transfer-Encoding first"
      "|~~--clcl:Two Content-Length values", "59_smuggling.sh" },
    { "HTTP/2", "network-server-symbolic",
      "#DOWNGRADE|~~--h2cl:Is Content-Length legal upstream"
      "|~~--h2te:A smuggled Transfer-Encoding"
      "|~~--downgrade:What the edge advertises", "59_smuggling.sh" },
    { "Timing", "document-open-recent-symbolic",
      "#THE WAIT|~~--desync:Hold a declared body open"
      "|#PRIMER|~~--teobfusc:Every obfuscation, listed", "59_smuggling.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--techniques:What disagrees and what it wins|--framing:The raw header pairs",
      "59_smuggling.sh" },
};

/* 61_cors — the browser sends the cookie; the origin check is the guard */
static const PageSpec cors_pages[] = {
    { "Overview", "dialog-information-symbolic", "61_cors.sh" },
    { "Check", "document-open-recent-symbolic",
      "#ONE ENDPOINT|~~--check:Every origin family against a url"
      "|#FAMILIES|~~--null:The sandboxed-iframe origin"
      "|~~~--suffix:Substring comparisons against the registered host"
      "|~~~--regex:An allowlist that forgot to anchor", "61_cors.sh" },
    { "Credentials", "dialog-password-symbolic",
      "#THE COOKIE|~~--creds:Read and write, with credentials"
      "|~~--methods:Which verbs the preflight advertises"
      "|~~--headers:Which headers the page may read", "61_cors.sh" },
    { "Proof", "dialog-warning-symbolic",
      "#THE HTML|~~--poc:Write the page that would steal the data"
      "|#REFERENCE|~--origins:The origin family table|--list:Header table",
      "61_cors.sh" },
};

/* 62_version_bypass */
static const PageSpec version_pages[] = {
    { "Overview", "dialog-information-symbolic", "62_version_bypass.sh" },
    { "Matrix", "document-open-recent-symbolic",
      "#THE GRID|~~--matrix:Path spellings, query and headers"
      "|~~--sweep:Every path against one base"
      "|~~--probe:One path, every slot", "62_version_bypass.sh" },
    { "Compare", "view-list-symbolic",
      "#TWO SESSIONS|~~--compare:Where an old version answers unlocked"
      "|~--normalise:Show the rewrite slots",
      "62_version_bypass.sh" },
};

/* 64_file_upload */
static const PageSpec upload_pages[] = {
    { "Overview", "dialog-information-symbolic", "64_file_upload.sh" },
    { "Filters", "document-open-recent-symbolic",
      "#EXTENSION|~~--check:Walk the extension matrix"
      "|~~--probe:The content-type axis"
      "|#CONTENT|--polyglot:A valid image carrying markup"
      "|~--magic:Sniff one file", "64_file_upload.sh" },
    { "Names", "view-list-symbolic",
      "#FILENAME TRICKS|~--name:Eleven names a blocklist forgets"
      "|~--sweep:Every endpoint against one base"
      "|#REFERENCE|--extensions|--types|--endpoints",
      "64_file_upload.sh" },
};

/* 76_debug_endpoints */
static const PageSpec debug_pages[] = {
    { "Overview", "dialog-information-symbolic", "76_debug_endpoints.sh" },
    { "Sweep", "document-open-recent-symbolic",
      "#PATH FAMILIES|~--health:Health and probes|~--actuator:Spring actuator"
      "|~--docs:Swagger and GraphiQL|~--env:Dotenv, config, git"
      "|~--telco:Operator portals|#EVERYTHING|~~--scan:One host, all families",
      "76_debug_endpoints.sh" },
    { "Check", "view-list-symbolic",
      "#ONE URL|~--check:Classify one response|~--list:Path catalogue",
      "76_debug_endpoints.sh" },
};

/* 47_auth_bypass — the guard is on the route, not the resource. */
static const PageSpec authbypass_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Gaps", "view-list-symbolic",
      "#NO TOKEN AT ALL|~--gaps:Every protected path, plain GET"
      "|#ONE ROUTE|~~--check:Run the vector table against one path"
      "|~--methods:The verb axis", "47_auth_bypass.sh" },
    { "Vectors", "document-open-recent-symbolic",
      "#SMALLER PASSES|~--headers:Gateway headers that name a path"
      "|~--case:Case fold|~--trailing:Slash, dot, semicolon"
      "|~--encoding:Percent, double and overlong|~--cgi:PHP path suffix"
      "|#THE WHOLE GRID|~--sweep:Every path times every vector"
      "|~--probe:One full url", "47_auth_bypass.sh" },
    { "Reference", "dialog-information-symbolic",
      "#TABLES|--paths:Protected paths|--vectors:Vector catalogue|--list:All verbs",
      "47_auth_bypass.sh" },
};

/* ---- 10_snapshot ---- */
static const PageSpec snapshot_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Sharing", "folder-remote-symbolic",
      "#WHAT A STRANGER CAN RESTORE|--public:Account-wide sweep|--images:Images we own"
      "|#ONE AT A TIME|~--share:One snapshot in full" },
    { "Content", "drive-harddisk-symbolic",
      "#WHAT THE DISK GIVES UP|~--data:Inspect a mounted image"
      "|#REFERENCE|--techniques:Paths and sharing surfaces" },
    { "Reference", "view-list-symbolic",
      "#VERBS|--list:Verb list" },
};

/* ---- 11_event_trigger ---- */
static const PageSpec event_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Wiring", "emblem-synchronizing-symbolic",
      "#WHO CAN TRIGGER IT|--sources:Event source classes|--probe:Provider state"
      "|#WHAT IS WIRED|--rules:Every trigger and its target" },
    { "Inject", "network-transmit-symbolic",
      "#BUILD AN EVENT|~--forge:Print an event body"
      "|#SEND IT|~--inject:Post to a receiver|~--trust:Grade the source policy" },
    { "Reference", "view-list-symbolic",
      "#GAPS|--techniques:Trust gaps worth testing|--list:Verb list" },
};

/* ---- 13_cicd ---- */
static const PageSpec cicd_pages[] = {
    { "Overview", "dialog-information-symbolic", NULL },
    { "Workflows", "text-x-script-symbolic",
      "#STATIC — NO CREDENTIALS NEEDED|~--secrets:Scan a workflow file or directory"
      "|#WHAT IT FOUND|--techniques:The doors and what a yes gives you" },
    { "Trust", "security-high-symbolic",
      "#THE CI TO CLOUD BRIDGE|~--oidc:Grade an OIDC trust policy"
      "|#THE FORGE|~--branch:Is the deploy branch protected|~--pipelines:Repos and workflows" },
    { "Reference", "view-list-symbolic",
      "#PROOF|~--forge:Print a minimal workflow|--probe:Provider state|--list:Verb list" },
};

/* ---- Master spec table ---- */
static const ModuleSpec module_specs[] = {
    { "00_deps", S("00_deps.sh"),
      "Dependencies", "Install required cloud CLIs and build tools.",
      deps_pages, G_N_ELEMENTS(deps_pages) },
    { "01_cred_validate", S("01_cred_validate.sh"),
      "Credential Validator", "Detect provider, validate format, live-probe.",
      cred_pages, G_N_ELEMENTS(cred_pages) },
    { "02_inventory", S("02_inventory.sh"),
      "Cloud Inventory", "Enumerate all reachable assets across providers.",
      inv_pages, G_N_ELEMENTS(inv_pages) },
    { "03_bucket_enum", S("03_bucket_enum.sh"),
      "Bucket Enum", "Find, probe and rate bucket exposure.",
      bucket_pages, G_N_ELEMENTS(bucket_pages) },
    { "04_pivot", S("04_pivot.sh"),
      "Cross-Account Pivot", "Assume the role and report what came back, not what the policy promised.",
      pivot_pages, G_N_ELEMENTS(pivot_pages) },
    { "05_iam_privesc", S("05_iam_privesc.sh"),
      "IAM PrivEsc", "Map IAM privilege escalation paths.",
      privesc_pages, G_N_ELEMENTS(privesc_pages) },
    { "06_role_chains", S("06_role_chains.sh"),
      "Role Chains", "Follow assume-role chains across accounts.",
      chains_pages, G_N_ELEMENTS(chains_pages) },
    { "07_policy_audit", S("07_policy_audit.sh"),
      "Policy Audit", "Audit IAM policies for dangerous statements.",
      audit_pages, G_N_ELEMENTS(audit_pages) },
    { "08_secrets_scan", S("08_secrets_scan.sh"),
      "Secrets Scanner", "Hunt credentials in files, trees and streams.",
      secrets_pages, G_N_ELEMENTS(secrets_pages) },
    { "09_imds", S("09_imds.sh"),
      "Instance Metadata", "SSRF into IMDS, IMDSv2, user-data and the credentials in them.",
      imds_pages, G_N_ELEMENTS(imds_pages) },

    { "10_snapshot", S("10_snapshot.sh"),
      "Snapshot & Image Theft", "The disk that outlived the instance, and who else can restore it.",
      snapshot_pages, G_N_ELEMENTS(snapshot_pages) },
    { "11_event_trigger", S("11_event_trigger.sh"),
      "Event Trigger Abuse", "Make a legitimate event fire a function on your terms.",
      event_pages, G_N_ELEMENTS(event_pages) },
    { "13_cicd", S("13_cicd.sh"),
      "CI/CD Supply Chain", "Walk from a commit to the runner to the credential.",
      cicd_pages, G_N_ELEMENTS(cicd_pages) },
    { "12_serverless", S("12_serverless.sh"),
      "Serverless", "List functions, read their environment, download their code.",
      serverless_pages, G_N_ELEMENTS(serverless_pages) },
    { "14_registry_recon", S("14_registry_recon.sh"),
      "Registry Recon", "Enumerate container registries and marketplaces.",
      registry_pages, G_N_ELEMENTS(registry_pages) },
    { "15_container_escape", S("15_container_escape.sh"),
      "Container Escape", "Detect escape primitives in the current container.",
      escape_pages, G_N_ELEMENTS(escape_pages) },
    { "16_kubernetes", S("16_kubernetes.sh"),
      "Kubernetes", "Clusters, workloads, RBAC reach, and the secrets behind it.",
      kubernetes_pages, G_N_ELEMENTS(kubernetes_pages) },
    { "18_network", S("18_network.sh"),
      "Cloud Network", "DNS, dangling records and claimable subdomains, subnets, routes and firewall exposure.",
      network_pages, G_N_ELEMENTS(network_pages) },
    { "21_db_exposure", S("21_db_exposure.sh"),
      "DB Exposure", "Managed databases, public reachability, endpoint probes.",
      db_pages, G_N_ELEMENTS(db_pages) },
    { "22_audit_evasion", S("22_audit_evasion.sh"),
      "Audit Coverage", "Which audit controls are missing, and what that hides.",
      ae_pages, G_N_ELEMENTS(ae_pages) },
    { "23_persistence", S("23_persistence.sh"),
      "Persistence", "Footholds that already exist, and what removes them.",
      persist_pages, G_N_ELEMENTS(persist_pages) },
    { "39_tenant_enum", S("39_tenant_enum.sh"),
      "Tenant Enumeration", "Tenant id, namespaces, exposed APIs, certificate transparency and PTR.",
      tenant_pages, G_N_ELEMENTS(tenant_pages) },
    { "41_api_discovery", S("41_api_discovery.sh"),
      "API Discovery", "Endpoints on a host or a spec, against a measured baseline.",
      apidisc_pages, G_N_ELEMENTS(apidisc_pages) },
    { "42_openapi", S("42_openapi.sh"),
      "OpenAPI Analyzer", "What a spec admits to: per-operation security, ids, url-taking params.",
      openapi_pages, G_N_ELEMENTS(openapi_pages) },
    { "43_graphql", S("43_graphql.sh"),
      "GraphQL Introspection", "A schema the server never meant to hand out.",
      graphql_pages, G_N_ELEMENTS(graphql_pages) },
    { "63_pagination", S("63_pagination.sh"), "Pagination Abuse",
      "A list endpoint that will hand over the table",
      pagination_pages, G_N_ELEMENTS(pagination_pages) },
    { "60_resp_smuggle", S("60_resp_smuggle.sh"), "Response Smuggling",
      "A second response spliced into the first",
      respsmuggle_pages, G_N_ELEMENTS(respsmuggle_pages) },
    { "58_sse", S("58_sse.sh"), "Server-Sent Events",
      "A stream nobody authenticated, judged per event",
      sse_pages, G_N_ELEMENTS(sse_pages) },
    { "27_rebinding", S("27_rebinding.sh"), "DNS Rebinding",
      "A name that resolves twice — the validator reads the name, the fetcher talks to the address",
      rebind_pages, G_N_ELEMENTS(rebind_pages) },
    { "44_jwt", S("44_jwt.sh"),
      "JWT Attack", "Alg:none, key confusion, kid injection and offline cracking.",
      jwt_pages, G_N_ELEMENTS(jwt_pages) },
    { "45_oauth", S("45_oauth.sh"),
      "OAuth Flow Abuse",
      "redirect_uri, state, PKCE, scope and prompt — every gate the flow passes",
      oauth_pages, G_N_ELEMENTS(oauth_pages) },
    { "46_key_harvest", S("46_key_harvest.sh"),
      "Key Harvest", "Key and token patterns in pages, bundles, headers and specs.",
      keyharvest_pages, G_N_ELEMENTS(keyharvest_pages) },
    { "47_auth_bypass", S("47_auth_bypass.sh"),
      "Auth Bypass", "The guard is on the route, not the resource.",
      authbypass_pages, G_N_ELEMENTS(authbypass_pages) },
    { "48_bola", S("48_bola.sh"),
      "BOLA", "Object-level authorization across subscriber, account and sim ids.",
      bola_pages, G_N_ELEMENTS(bola_pages) },
    { "49_bfla", S("49_bfla.sh"),
      "BFLA", "Function-level authorization across admin, agent and customer verbs.",
      bfla_pages, G_N_ELEMENTS(bfla_pages) },
    { "50_mass_assign", S("50_mass_assign.sh"),
      "Mass Assignment", "Fields the server trusts because the client sent them.",
      massassign_pages, G_N_ELEMENTS(massassign_pages) },
    { "51_hpp", S("51_hpp.sh"),
      "Parameter Pollution",
      "One parameter, two meanings — the duplicate, array and encoding shapes a parser folds.",
      hpp_pages, G_N_ELEMENTS(hpp_pages) },
    { "52_rate_limit", S("52_rate_limit.sh"),
      "Rate Limit Bypass", "Forwarding-header rotation against a limit that trusts the header.",
      ratelimit_pages, G_N_ELEMENTS(ratelimit_pages) },
    { "53_injection", S("53_injection.sh"),
      "API Injection",
      "A value the interpreter reads as code — SQL, NoSQL, command, template, LDAP and XPath.",
      injection_pages, G_N_ELEMENTS(injection_pages) },
    { "54_ssrf", S("54_ssrf.sh"),
      "SSRF Tester", "Make a server fetch metadata, loopback or a local file, and prove it by content.",
      ssrf_pages, G_N_ELEMENTS(ssrf_pages) },
    { "59_smuggling", S("59_smuggling.sh"),
      "Request Smuggling",
      "The front end and the back end disagree about how much of the stream is this request.",
      smuggle_pages, G_N_ELEMENTS(smuggle_pages) },
    { "61_cors", S("61_cors.sh"),
      "CORS Abuse",
      "Origin reflection, null origin and regex bypass — with the cookie riding along.",
      cors_pages, G_N_ELEMENTS(cors_pages) },
    { "62_version_bypass", S("62_version_bypass.sh"),
      "Versioning Bypass", "The old version answers while the new one is locked.",
      version_pages, G_N_ELEMENTS(version_pages) },
    { "56_grpc", S("56_grpc.sh"),
      "gRPC / Protobuf", "Reflection, method auth and field confusion — the framing itself.",
      grpc_pages, G_N_ELEMENTS(grpc_pages) },
    { "57_websocket", S("57_websocket.sh"),
      "WebSocket", "Handshake auth, per-message auth and CSWSH — the origin check is the whole guard.",
      websocket_pages, G_N_ELEMENTS(websocket_pages) },
    { "68_graphql_dos", S("68_graphql_dos.sh"),
      "GraphQL Cost", "Depth, aliases and batching — the gap between a cheap query and a ruinous one.",
      graphqldos_pages, G_N_ELEMENTS(graphqldos_pages) },
    { "64_file_upload", S("64_file_upload.sh"),
      "File Upload", "The extension and content-type matrix an upload filter forgets.",
      upload_pages, G_N_ELEMENTS(upload_pages) },
    { "67_token_refresh", S("67_token_refresh.sh"),
      "Token Refresh", "The token that outlives the logout — rotation, replay and revocation, measured.",
      tokenrefresh_pages, G_N_ELEMENTS(tokenrefresh_pages) },
    { "78_replay_nonce", S("78_replay_nonce.sh"),
      "Replay & Nonce", "The request that still works the second time — check-then-act and the missing nonce store.",
      replay_pages, G_N_ELEMENTS(replay_pages) },
    { "69_bfuzz", S("69_bfuzz.sh"),
      "Binary Fuzz", "The value the schema forbids — what the decoder accepts, the handler believes.",
      bfuzz_pages, G_N_ELEMENTS(bfuzz_pages) },
    { "70_spec_diff", S("70_spec_diff.sh"),
      "Spec Diff", "What changed between two specs, and which change added a door nobody locked.",
      specdiff_pages, G_N_ELEMENTS(specdiff_pages) },
    { "71_logic", S("71_logic.sh"),
      "Business Logic", "The rule nobody wrote down — a valid request, in the wrong order.",
      logic_pages, G_N_ELEMENTS(logic_pages) },
    { "72_race", S("72_race.sh"),
      "Race Condition", "Two requests that each pass a check neither should — the window is the bug.",
      race_pages, G_N_ELEMENTS(race_pages) },
    { "74_llm", S("74_llm.sh"),
      "LLM Endpoint", "The model box is an API with a budget and somebody's key behind it.",
      llm_pages, G_N_ELEMENTS(llm_pages) },
    { "75_rotation", S("75_rotation.sh"),
      "Key Rotation", "The credential that outlives its own rotation — a promise, tested from outside.",
      rotation_pages, G_N_ELEMENTS(rotation_pages) },
    { "77_mobile", S("77_mobile.sh"),
      "Mobile Backend", "The client version is an authorization input, and the app is the only client it expected.",
      mobile_pages, G_N_ELEMENTS(mobile_pages) },
    { "66_webhook_sig", S("66_webhook_sig.sh"),
      "Webhook Signature", "A signature nobody checked — control first, then every receiver mistake.",
      websig_pages, G_N_ELEMENTS(websig_pages) },
    { "65_deserialization", S("65_deserialization.sh"),
      "Deserialization", "The object the server rebuilt — a payload that is a data structure, not a string.",
      deser_pages, G_N_ELEMENTS(deser_pages) },
    { "76_debug_endpoints", S("76_debug_endpoints.sh"),
      "Debug Endpoints", "Health, actuator, docs and env endpoints that answer when they should not.",
      debug_pages, G_N_ELEMENTS(debug_pages) },
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

/* Submenu entry for module navigation panes: one per PageSpec of the module,
   each carrying the spec the page builder renders. */
typedef struct {
    const char *name;
    const char *icon;
    const PageSpec *page;
} ModuleSubmenuEntry;

static ModuleSubmenuEntry *
build_entries_for(const ModuleSpec *spec, int *out_count)
{
    ModuleSubmenuEntry *entries = g_new0(ModuleSubmenuEntry, 8);
    int n = 0;

    for (int i = 0; i < spec->n_pages && n < 8; i++) {
        entries[n].name = spec->pages[i].name;
        entries[n].icon = spec->pages[i].icon;
        entries[n].page = &spec->pages[i];
        n++;
    }
    *out_count = n;
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

/* Adapter so register_all_modules's fallback can reach the generic factory
   without a per-module function. It has to carry the spec: every page builder
   dereferences g->spec->subtitle, so a NULL here opens a page and dies. */
static gpointer
generic_module_data_new_inner(AppState *s)
{
    (void) s;
    return NULL;
}

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
static gpointer _new_serverless(AppState *s) { return generic_module_data_new(s, module_spec_for("13_serverless_recon")); }
static gpointer _new_registry(AppState *s)   { return generic_module_data_new(s, module_spec_for("14_registry_recon")); }
static gpointer _new_escape(AppState *s)     { return generic_module_data_new(s, module_spec_for("15_container_escape")); }
static gpointer _new_k8ssurf(AppState *s)    { return generic_module_data_new(s, module_spec_for("16_k8s_attack_surface")); }
static gpointer _new_k8ssec(AppState *s)     { return generic_module_data_new(s, module_spec_for("17_k8s_secrets")); }
static gpointer _new_dns(AppState *s)        { return generic_module_data_new(s, module_spec_for("18_cloud_dns")); }
static gpointer _new_vpc(AppState *s)        { return generic_module_data_new(s, module_spec_for("19_vpc_map")); }
static gpointer _new_sg(AppState *s)         { return generic_module_data_new(s, module_spec_for("20_sg_audit")); }
static gpointer _new_db(AppState *s)         { return generic_module_data_new(s, module_spec_for("21_db_exposure")); }
static gpointer _new_ae(AppState *s)         { return generic_module_data_new(s, module_spec_for("22_audit_evasion")); }
static gpointer _new_persist(AppState *s)    { return generic_module_data_new(s, module_spec_for("23_persistence")); }

/* ==================================================================== */
/*  Module registry                                                      */
/* ==================================================================== */

typedef struct {
    const char *module_id;
    ModuleSubmenuEntry *entries;
    int n_entries;
    gpointer (*get_module_data)(AppState *);
    /* The spec a factory that takes no spec argument still needs. A hand
       written factory ignores this and looks its own row up; the generic
       fallback has nothing to look up, so the row is carried here. */
    const ModuleSpec *spec;
} ModuleRegistryEntry;

static ModuleRegistryEntry *module_registry = NULL;
static int module_registry_size = 0;

static void
module_registry_register_spec(const char *id, ModuleSubmenuEntry *entries,
                              int n, gpointer (*get_data)(AppState *),
                              const ModuleSpec *spec)
{
    module_registry = g_realloc(module_registry,
        (module_registry_size + 1) * sizeof(ModuleRegistryEntry));
    module_registry[module_registry_size].module_id = id;
    module_registry[module_registry_size].entries = entries;
    module_registry[module_registry_size].n_entries = n;
    module_registry[module_registry_size].get_module_data = get_data;
    module_registry[module_registry_size].spec = spec;
    module_registry_size++;
}

static void
module_registry_register(const char *id, ModuleSubmenuEntry *entries,
                         int n, gpointer (*get_data)(AppState *))
{
    module_registry_register_spec(id, entries, n, get_data, NULL);
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
        else if (g_strcmp0(spec->id, "13_serverless_recon") == 0)
            module_registry_register(spec->id, e, n, _new_serverless);
        else if (g_strcmp0(spec->id, "14_registry_recon") == 0)
            module_registry_register(spec->id, e, n, _new_registry);
        else if (g_strcmp0(spec->id, "15_container_escape") == 0)
            module_registry_register(spec->id, e, n, _new_escape);
        else if (g_strcmp0(spec->id, "16_k8s_attack_surface") == 0)
            module_registry_register(spec->id, e, n, _new_k8ssurf);
        else if (g_strcmp0(spec->id, "17_k8s_secrets") == 0)
            module_registry_register(spec->id, e, n, _new_k8ssec);
        else if (g_strcmp0(spec->id, "18_cloud_dns") == 0)
            module_registry_register(spec->id, e, n, _new_dns);
        else if (g_strcmp0(spec->id, "19_vpc_map") == 0)
            module_registry_register(spec->id, e, n, _new_vpc);
        else if (g_strcmp0(spec->id, "20_sg_audit") == 0)
            module_registry_register(spec->id, e, n, _new_sg);
        else if (g_strcmp0(spec->id, "21_db_exposure") == 0)
            module_registry_register(spec->id, e, n, _new_db);
        else if (g_strcmp0(spec->id, "22_audit_evasion") == 0)
            module_registry_register(spec->id, e, n, _new_ae);
        else if (g_strcmp0(spec->id, "23_persistence") == 0)
            module_registry_register(spec->id, e, n, _new_persist);
        else
            /* A module table added to module_specs[] does not need a hand
               written factory: the generic one carries the same spec. */
            module_registry_register_spec(spec->id, e, n, generic_module_data_new_inner, spec);
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
                                 build_module_view(state, module_data,
                                                   entries[i].page),
                                 entries[i].name, entries[i].name),
            NULL);
        g_object_set_data(G_OBJECT(row), "stack", stack);
        g_object_set_data_full(G_OBJECT(row), "name",
                               g_strdup(entries[i].name), g_free);
        g_object_set_data(G_OBJECT(row), "index", GINT_TO_POINTER(i));
        gtk_list_box_append(GTK_LIST_BOX(submenu), row);
    }
    g_signal_connect(submenu, "row-activated",
                     G_CALLBACK(module_page_submenu_activated), state);

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
        /* a factory handed back nothing cannot build a page: give it the
           carried spec rather than dereferencing NULL one call later */
        if (module_data == NULL && reg->spec != NULL)
            module_data = generic_module_data_new(state, reg->spec);
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

    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), FALSE);
    gtk_widget_set_margin_top(grid, 10);
    gtk_widget_set_margin_start(grid, 4);
    gtk_widget_set_margin_end(grid, 4);
    gtk_widget_set_margin_bottom(grid, 10);
    gtk_widget_set_hexpand(grid, TRUE);
    gtk_widget_set_halign(grid, GTK_ALIGN_FILL);
    gtk_widget_set_valign(grid, GTK_ALIGN_START);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), grid);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_hexpand(scroll, TRUE);

    gtk_box_append(GTK_BOX(header), title);
    gtk_box_append(GTK_BOX(header), subtitle);
    gtk_box_append(GTK_BOX(outer), header);
    gtk_box_append(GTK_BOX(outer), scroll);

    for (guint i = 0; i < module_count(); i++) {
        const ModuleDefinition *mod = module_at(i);
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
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 48);
        gtk_widget_set_halign(icon, GTK_ALIGN_CENTER);
        gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);
        gtk_label_set_xalign(GTK_LABEL(cat), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(star), 1.0f);
        gtk_widget_set_halign(cat, GTK_ALIGN_START);
        gtk_widget_set_halign(star, GTK_ALIGN_END);
        gtk_widget_set_hexpand(cat, TRUE);
        gtk_label_set_wrap(GTK_LABEL(name), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(name), PANGO_WRAP_WORD_CHAR);
        gtk_label_set_lines(GTK_LABEL(name), 2);
        gtk_label_set_justify(GTK_LABEL(name), GTK_JUSTIFY_CENTER);
        gtk_label_set_max_width_chars(GTK_LABEL(name), 14);
        gtk_label_set_xalign(GTK_LABEL(name), 0.5f);
        gtk_widget_set_halign(name, GTK_ALIGN_CENTER);
        gtk_widget_set_valign(name, GTK_ALIGN_START);
        gtk_widget_set_hexpand(button, TRUE);
        gtk_widget_set_vexpand(button, TRUE);
        gtk_widget_set_halign(button, GTK_ALIGN_FILL);
        gtk_widget_set_valign(button, GTK_ALIGN_FILL);
        if (mod->description) gtk_widget_set_tooltip_text(button, mod->description);

        gtk_widget_set_hexpand(inner, TRUE);
        gtk_widget_set_vexpand(inner, TRUE);
        gtk_box_append(GTK_BOX(top_row), cat);
        gtk_box_append(GTK_BOX(top_row), star);
        gtk_box_append(GTK_BOX(inner), top_row);
        gtk_box_append(GTK_BOX(inner), icon);
        gtk_box_append(GTK_BOX(inner), name);
        gtk_button_set_child(GTK_BUTTON(button), inner);

        g_object_set_data(G_OBJECT(button), "module", (gpointer) mod);
        g_object_set_data(G_OBJECT(button), "module-id", (gpointer) mod->id);
        g_signal_connect(button, "clicked",
                           G_CALLBACK(open_module_clicked), state);

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
                     G_CALLBACK(open_module_clicked), state);
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

        for (guint m = 0; m < module_count(); m++) {
            guint j;
            gboolean skip = FALSE;
            for (j = 0; j < n_seen; j++)
                if (g_strcmp0(seen[j], module_at(m)->category) == 0) { skip = TRUE; break; }
            if (skip) continue;
            if (n_seen < 32) seen[n_seen++] = module_at(m)->category;

            GtkWidget *category = gtk_label_new(module_at(m)->category);
            gtk_widget_add_css_class(category, "sidebar-section");
            gtk_widget_set_halign(category, GTK_ALIGN_FILL);
            gtk_widget_set_hexpand(category, TRUE);
            gtk_label_set_xalign(GTK_LABEL(category), 0.5f);
            g_object_set_data(G_OBJECT(category), "sidebar-section",
                              GINT_TO_POINTER(1));
            gtk_box_append(GTK_BOX(box), category);

            for (guint k = 0; k < module_count(); k++) {
                if (g_strcmp0(module_at(k)->category, module_at(m)->category) != 0) continue;
                GtkWidget *b = gtk_button_new();
                GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 7);
                GtkWidget *icon = gtk_image_new_from_icon_name(module_at(k)->icon);
                GtkWidget *label = gtk_label_new(module_at(k)->name);

                gtk_image_set_pixel_size(GTK_IMAGE(icon), 22);
                gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
                gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
                gtk_widget_set_hexpand(label, TRUE);
                gtk_box_append(GTK_BOX(row), icon);
                gtk_box_append(GTK_BOX(row), label);
                gtk_button_set_child(GTK_BUTTON(b), row);

                g_object_set_data(G_OBJECT(b), "module", (gpointer) module_at(k));
                g_object_set_data(G_OBJECT(b), "row-label", label);
                g_signal_connect(b, "clicked",
                                   G_CALLBACK(open_module_clicked), state);
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

    /* Footer: quick-jump buttons (two rows so long labels never clip) */
    GtkWidget *foot = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *foot_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    gtk_widget_set_margin_top(foot, 10);
    gtk_widget_set_halign(foot, GTK_ALIGN_FILL);
    gtk_widget_set_halign(foot_row, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(foot), foot_row);
    static const struct { const char *label; const char *id; } q[] = {
        { "Validate", "01_cred_validate" },
        { "Inventory", "02_inventory" },
        { "Buckets", "03_bucket_enum" },
    };
    for (guint qi = 0; qi < G_N_ELEMENTS(q); qi++) {
        GtkWidget *b = gtk_button_new_with_label(q[qi].label);
        gtk_widget_add_css_class(b, "flat");
        g_object_set_data(G_OBJECT(b), "jump-id", (gpointer) q[qi].id);
        gtk_widget_add_css_class(b, "session-jump");
        g_signal_connect(b, "clicked", G_CALLBACK(jump_clicked), state);
        if (qi == 2) {
            GtkWidget *row2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
            gtk_widget_set_halign(row2, GTK_ALIGN_START);
            gtk_box_append(GTK_BOX(foot), row2);
            foot_row = row2;
        }
        gtk_box_append(GTK_BOX(foot_row), b);
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

    gtk_widget_set_size_request(panel, 236, -1);

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
    for (guint i = 0; i < module_count(); i++)
        if (g_strcmp0(module_at(i)->id, id) == 0) {
            open_module(state, module_at(i));
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

/* Provider state, shortened to something a 22-px badge can hold. */
static const char *
session_state_short(const char *state)
{
    if (state == NULL) return "—";
    if (g_strcmp0(state, "creds-present") == 0) return "ready";
    if (g_strcmp0(state, "creds-missing") == 0) return "no creds";
    if (g_strcmp0(state, "creds-invalid") == 0) return "rejected";
    if (g_strcmp0(state, "tool-missing") == 0) return "no tool";
    return state;
}

/* ARN tail: arn:aws:sts::1234:assumed-role/Admin/ops -> ops */
static const char *
session_identity_tail(const char *arn)
{
    if (arn == NULL || *arn == '\0') return "—";
    const char *slash = strrchr(arn, '/');
    return (slash != NULL && slash[1] != '\0') ? slash + 1 : arn;
}

static void
session_apply_kv(AppState *state, GHashTable *kv)
{
    const char *account  = g_hash_table_lookup(kv, "aws_account");
    const char *region   = g_hash_table_lookup(kv, "aws_region");
    const char *identity = g_hash_table_lookup(kv, "aws_user");
    const char *state_s  = g_hash_table_lookup(kv, "aws_state");
    const char *inv_rows = g_hash_table_lookup(kv, "inventory_rows");
    const char *inv_ts   = g_hash_table_lookup(kv, "inventory_ts");

    if (state->session_account)
        gtk_label_set_text(GTK_LABEL(state->session_account),
                           account && *account ? account : "—");
    if (state->session_region)
        gtk_label_set_text(GTK_LABEL(state->session_region),
                           region && *region ? region : "—");
    if (state->session_identity)
        gtk_label_set_text(GTK_LABEL(state->session_identity),
                           session_identity_tail(identity));

    if (state->session_badge) {
        /* one badge, naming every provider that actually authenticated */
        static const struct { const char *key; const char *label; } provs[] = {
            { "aws_state",    "aws" },
            { "gcloud_state", "gcp" },
            { "azure_state",  "az"  },
            { "doctl_state",  "do"  },
            { "oci_state",    "oci" },
            { "k8s_state",    "k8s" },
        };
        g_autoptr(GString) badge = g_string_new(NULL);
        for (guint i = 0; i < G_N_ELEMENTS(provs); i++) {
            const char *st = g_hash_table_lookup(kv, provs[i].key);
            if (g_strcmp0(st, "creds-present") == 0) {
                if (badge->len > 0) g_string_append_c(badge, '+');
                g_string_append(badge, provs[i].label);
            }
        }
        if (badge->len == 0 && state_s != NULL)
            g_string_append(badge, session_state_short(state_s));
        gtk_label_set_text(GTK_LABEL(state->session_badge),
                           badge->len > 0 ? badge->str : "no access");

        /* The row of per-provider states under the badge: what each one
         * reports, even when it is missing — absence is a fact here. */
        if (state->session_last_scan != NULL) {
            g_autoptr(GString) line = g_string_new(NULL);
            if (inv_rows != NULL && *inv_rows != '\0')
                g_string_append_printf(line, "%s rows", inv_rows);
            if (inv_ts != NULL && *inv_ts != '\0') {
                if (line->len > 0) g_string_append(line, " · ");
                g_string_append(line, inv_ts);
            }
            if (line->len == 0) g_string_append(line, "no scan yet");
            gtk_label_set_text(GTK_LABEL(state->session_last_scan), line->str);
        }
    }
}

static gboolean
session_refresh_idle(gpointer ud)
{
    AppState *state = ud;
    g_autofree gchar *root = g_strdup(cs_root());
    g_autofree gchar *launcher = g_build_filename(root, "cloudsting.sh", NULL);

    gpointer proc = NULL;
    g_autoptr(GError) error = NULL;

    if (g_file_test(launcher, G_FILE_TEST_IS_EXECUTABLE)) {
        const char *argv[] = { launcher, "session", "--tsv", NULL };
        proc = g_subprocess_newv(argv,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
            &error);
    }
    /* Fallback: the module that mints the identity, read directly. */
    if (proc == NULL) {
        g_clear_error(&error);
        const char *argv[] = { SCRIPT("06_role_chains.sh"), "--whoami", NULL };
        proc = g_subprocess_newv(argv,
            G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
            &error);
    }
    if (proc == NULL) {
        g_warning("session: %s", error->message);
        state->session_last_refresh = g_get_real_time();
        return G_SOURCE_REMOVE;
    }

    g_autofree gchar *out = NULL;
    g_autofree gchar *err = NULL;
    if (g_subprocess_communicate_utf8(proc, NULL, NULL, &out, &err, &error)) {
        GHashTable *kv = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, g_free);
        if (out != NULL) {
            g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
            for (guint i = 0; lines[i] != NULL; i++) {
                if (*lines[i] == '\0') continue;
                g_auto(GStrv) pair = g_strsplit(lines[i], "\t", 2);
                if (g_strv_length(pair) != 2) continue;
                g_hash_table_insert(kv, g_strdup(pair[0]), g_strdup(pair[1]));
            }
        }
        /* `06 --whoami` names its keys account/user, the launcher's session
         * verb names them aws_account/aws_user; accept both. */
        if (!g_hash_table_contains(kv, "aws_account")) {
            const char *a = g_hash_table_lookup(kv, "account");
            if (a != NULL) g_hash_table_insert(kv, g_strdup("aws_account"), g_strdup(a));
        }
        if (!g_hash_table_contains(kv, "aws_user")) {
            const char *u = g_hash_table_lookup(kv, "user");
            if (u != NULL) g_hash_table_insert(kv, g_strdup("aws_user"), g_strdup(u));
        }
        if (!g_hash_table_contains(kv, "aws_region")) {
            const char *r = g_hash_table_lookup(kv, "region");
            if (r != NULL) g_hash_table_insert(kv, g_strdup("aws_region"), g_strdup(r));
        }
        if (!g_hash_table_contains(kv, "aws_state")) {
            const char *sst = g_hash_table_lookup(kv, "state");
            if (sst != NULL) g_hash_table_insert(kv, g_strdup("aws_state"), g_strdup(sst));
        }
        session_apply_kv(state, kv);
        g_hash_table_unref(kv);
    }
    g_object_unref(proc);
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

    g_signal_connect(terminal, "clicked", G_CALLBACK(open_terminal_clicked), state);
    g_signal_connect(sidebar_toggle, "toggled",
                     G_CALLBACK(toggle_widget), state->sidebar);
    g_signal_connect(session_toggle, "toggled",
                     G_CALLBACK(toggle_widget), state->session_revealer);
    g_signal_connect(events_toggle, "toggled",
                     G_CALLBACK(toggle_widget), state->event_drawer);

    /* Activate AFTER connecting so the target widgets are forced into the
       exact state the button reports. Setting the state before connecting
       leaves the revealer out of sync until the user clicks once. */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(sidebar_toggle), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(session_toggle), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(events_toggle), TRUE);

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
    GtkWidget *target = ud;
    if (g_getenv("CLOUDSTING_DEBUG_LAYOUT") != NULL)
        g_printerr("DBG toggle %p active=%d target=%p reveal=%d\n", (void*)b,
            gtk_toggle_button_get_active(b), (void*)target,
            GTK_IS_REVEALER(target) ? gtk_revealer_get_reveal_child(GTK_REVEALER(target)) : -1);
    if (target == NULL) return;
    /* Handle GtkRevealer specially for animated hide/show */
    if (GTK_IS_REVEALER(target))
        gtk_revealer_set_reveal_child(GTK_REVEALER(target),
                                      gtk_toggle_button_get_active(b));
    else
        gtk_widget_set_visible(target, gtk_toggle_button_get_active(b));
}

static void
open_module_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const ModuleDefinition *module = g_object_get_data(G_OBJECT(button), "module");
    if (module != NULL) open_module(state, module);
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

    /* Module metadata lives in data/registry.tsv, not in this binary. Load
     * it through the launcher before anything draws a tile or a sidebar
     * row, so adding a module means editing the registry only. */
    module_table = module_table_load();

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
    {
        GtkWidget *right = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_set_hexpand(right, TRUE);
        gtk_widget_set_vexpand(right, TRUE);
        gtk_widget_set_hexpand(state->notebook, TRUE);
        gtk_widget_set_vexpand(state->notebook, TRUE);
        gtk_box_append(GTK_BOX(right), state->notebook);
        gtk_box_append(GTK_BOX(right), state->session_revealer);
        gtk_paned_set_end_child(GTK_PANED(horizontal), right);
    }
    gtk_paned_set_position(GTK_PANED(horizontal), 218);
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

        gtk_overlay_set_child(GTK_OVERLAY(overlay), bg);
        gtk_overlay_add_overlay(GTK_OVERLAY(overlay), vertical);
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
                    for (guint j = 0; j < module_count(); j++) {
                        if (g_strcmp0(module_at(j)->id, id) == 0) {
                            open_module(state, module_at(j));
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
    append_event(state, g_strdup_printf("Loaded %u modules from registry", module_count()));

    install_shortcuts(state);
    show_splash(state);

    /* Silent session info refresh every 30 s — never prompts */
    if (g_getenv("CLOUDSTING_DEBUG_LAYOUT") != NULL)
        g_printerr("DBG reveal_child=%d rev_mapped=%d rev_w=%d\n",
            gtk_revealer_get_reveal_child(GTK_REVEALER(state->session_revealer)),
            gtk_widget_get_mapped(state->session_revealer),
            gtk_widget_get_width(state->session_revealer));
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