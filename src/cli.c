/* Orchestrator mode: parse a unit file, start a transient systemd-run unit
 * with the exact same [Service] properties, re-exec *this same binary*
 * inside it (--ssc-probe-internal), collect + print results. See ssc.h
 * for why self-reexec instead of shelling out to python3.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ssc.h"

/* Directives that must NOT be forwarded to the transient probe unit --
 * either meaningless there (Type=/Restart*=/Standard*=/StateDirectory*=/
 * ExecStart=) or outright rejected by systemd-run for a dynamically-named
 * transient unit with no matching sibling (Sockets=: "Unknown assignment",
 * confirmed by hand -- there's no <name>.socket for a transient unit). */
static const char *SKIP_DIRECTIVES[] = {
    "ExecStart", "Type", "Restart", "RestartSec",
    "StandardOutput", "StandardError", "SyslogIdentifier",
    "StateDirectory", "StateDirectoryMode", "Sockets", NULL,
};

/* For --exec-check: only ExecStart=/Restart*= are dropped (Restart is
 * hardcoded to "no" below so a crashing app gives one clean signal
 * instead of respawn-looping); everything else -- including
 * StateDirectory=/Type=/Standard*= -- is forwarded so the run mirrors
 * production as closely as possible. Sockets= is dropped for the same
 * reason as above. */
static const char *EXEC_SKIP_DIRECTIVES[] = {
    "ExecStart", "Restart", "RestartSec", "Sockets", NULL,
};

static int in_list(const char *key, const char *const *list) {
    for (int i = 0; list[i]; i++) {
        if (strcmp(key, list[i]) == 0) return 1;
    }
    return 0;
}

static int truthy_cfg(const char *v) {
    return v && (strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcmp(v, "1") == 0);
}

/* --- argv builder: a growable array of owned strings --- */
typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} strvec_t;

static void strvec_init(strvec_t *v) { v->items = NULL; v->count = 0; v->capacity = 0; }

static void strvec_push(strvec_t *v, char *s /* takes ownership */) {
    if (v->count == v->capacity) {
        size_t new_cap = v->capacity ? v->capacity * 2 : 16;
        char **grown = realloc(v->items, new_cap * sizeof(char *));
        if (!grown) {
            perror("realloc");
            exit(1);
        }
        v->items = grown;
        v->capacity = new_cap;
    }
    v->items[v->count++] = s;
}

static void strvec_pushf(strvec_t *v, const char *fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    strvec_push(v, strdup(buf));
}

static void strvec_free(strvec_t *v) {
    for (size_t i = 0; i < v->count; i++) free(v->items[i]);
    free(v->items);
    strvec_init(v);
}

/* NULL-terminated argv view into a strvec_t (for execvp/print). Caller
 * frees the returned array (not the strings, which strvec_t still owns). */
static char **strvec_argv(const strvec_t *v) {
    char **argv = malloc((v->count + 1) * sizeof(char *));
    if (!argv) {
        perror("malloc");
        exit(1);
    }
    for (size_t i = 0; i < v->count; i++) argv[i] = v->items[i];
    argv[v->count] = NULL;
    return argv;
}

/* --- distinct-keys helper: iterate each key in pairs exactly once --- */
static int key_seen_before(const kv_list_t *pairs, size_t upto, const char *key) {
    for (size_t i = 0; i < upto; i++) {
        if (strcmp(pairs->items[i].key, key) == 0) return 1;
    }
    return 0;
}

/* --- run a child process, capturing stdout; returns exit code or -1 --- */
static int run_capture(char *const argv[], char **out_stdout) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    ssize_t n;
    char chunk[8192];
    int oom = (buf == NULL);
    while (!oom && (n = read(pipefd[0], chunk, sizeof(chunk))) > 0) {
        if (len + (size_t)n + 1 > cap) {
            cap = (len + (size_t)n + 1) * 2;
            char *grown = realloc(buf, cap);
            if (!grown) {
                oom = 1;
                break;
            }
            buf = grown;
        }
        memcpy(buf + len, chunk, (size_t)n);
        len += (size_t)n;
    }
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (oom) {
        /* Drain a hostile/oversized child output without OOM-crashing the
         * tool itself; report failure rather than dereferencing a NULL or
         * stale buf. */
        free(buf);
        *out_stdout = NULL;
        return -1;
    }
    buf[len] = '\0';
    *out_stdout = buf;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static const char *colorize(const char *status, const char *text, int use_color, char *buf, size_t buflen) {
    if (!use_color) return text;
    const char *code = "0";
    if (strcmp(status, "PASS") == 0) code = "32";
    else if (strcmp(status, "FAIL") == 0) code = "31";
    else if (strcmp(status, "WARN") == 0) code = "33";
    else if (strcmp(status, "INFO") == 0) code = "36";
    snprintf(buf, buflen, "\033[%sm%s\033[0m", code, text);
    return buf;
}

typedef struct { int pass, fail, warn, info; } counts_t;

static void bump(counts_t *c, const char *status) {
    if (strcmp(status, "PASS") == 0) c->pass++;
    else if (strcmp(status, "FAIL") == 0) c->fail++;
    else if (strcmp(status, "WARN") == 0) c->warn++;
    else if (strcmp(status, "INFO") == 0) c->info++;
}

static void print_result_line(const char *status, const char *check, const char *directive,
                                const char *detail, int use_color) {
    char tag[64], colored[96];
    snprintf(tag, sizeof(tag), "[%-4s]", status);
    printf("%s %-32s (%s): %s\n", colorize(status, tag, use_color, colored, sizeof(colored)), check, directive, detail);
}

/* ===================== static lint: "+" prefix check ===================== */

static const char *PLUS_PREFIXABLE[] = {
    "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "ExecPaths", "NoExecPaths", NULL,
};

/* Paths that get a fresh, non-host-backed mount under RootDirectory=
 * (PrivateTmp=/TemporaryFileSystem=/PrivateDevices=) -- see cli.py's
 * _fresh_mount_paths() docstring for the full reasoning. Returns a
 * NULL-terminated array the caller must free (including entries). */
static char **fresh_mount_paths(const kv_list_t *pairs) {
    strvec_t v;
    strvec_init(&v);
    char *private_tmp = kv_merge(pairs, "PrivateTmp");
    if (truthy_cfg(private_tmp)) {
        strvec_push(&v, strdup("/tmp"));
        strvec_push(&v, strdup("/var/tmp"));
    }
    free(private_tmp);
    char *private_devices = kv_merge(pairs, "PrivateDevices");
    if (truthy_cfg(private_devices)) strvec_push(&v, strdup("/dev"));
    free(private_devices);
    char *tmpfs = kv_merge(pairs, "TemporaryFileSystem");
    if (tmpfs) {
        char buf[4096];
        snprintf(buf, sizeof(buf), "%s", tmpfs);
        char *saveptr;
        for (char *tok = strtok_r(buf, " ", &saveptr); tok; tok = strtok_r(NULL, " ", &saveptr)) {
            char *colon = strchr(tok, ':');
            if (colon) *colon = '\0';
            strvec_push(&v, strdup(tok));
        }
    }
    free(tmpfs);
    char **result = strvec_argv(&v);
    free(v.items); /* strvec_argv copied pointers; strings now owned by result */
    return result;
}

static int path_in_list(const char *path, char *const *list) {
    for (int i = 0; list[i]; i++) {
        if (strcmp(path, list[i]) == 0) return 1;
    }
    return 0;
}

static void free_str_array(char **arr) {
    for (int i = 0; arr[i]; i++) free(arr[i]);
    free(arr);
}

static void lint_plus_prefix(const kv_list_t *pairs, counts_t *counts, int use_color) {
    char *root_dir = kv_merge(pairs, "RootDirectory");
    char *root_img = kv_merge(pairs, "RootImage");
    if (!root_dir && !root_img) { free(root_dir); free(root_img); return; }
    free(root_dir);
    free(root_img);

    char **fresh = fresh_mount_paths(pairs);
    int printed_header = 0;

    for (size_t i = 0; i < pairs->count; i++) {
        const char *key = pairs->items[i].key;
        if (!in_list(key, PLUS_PREFIXABLE)) continue;
        char buf[8192];
        snprintf(buf, sizeof(buf), "%s", pairs->items[i].value);
        char *saveptr;
        for (char *path = strtok_r(buf, " ", &saveptr); path; path = strtok_r(NULL, " ", &saveptr)) {
            const char *bare = path;
            while (*bare == '-') bare++;
            if (*bare == '+') continue;

            if (!printed_header) {
                printf("Static lint: RootDirectory=/RootImage= + path prefix check\n");
                printed_header = 1;
            }
            char check[64];
            snprintf(check, sizeof(check), "plus_prefix_%s", key);
            for (char *p = check; *p; p++) *p = (char)tolower((unsigned char)*p);

            if (path_in_list(bare, fresh)) {
                bump(counts, "WARN");
                char detail[1024];
                snprintf(detail, sizeof(detail),
                          "%s=%s has no '+' prefix but RootDirectory=/RootImage= is set -- %s gets its own "
                          "fresh mount inside the chroot (via PrivateTmp=/TemporaryFileSystem=/PrivateDevices=), "
                          "so this resolves against the HOST's %s instead, which is a different, irrelevant "
                          "mount. Use %s=+%s instead.",
                          key, path, bare, bare, key, bare);
                print_result_line("WARN", check, key, detail, use_color);
            } else {
                bump(counts, "INFO");
                char detail[1024];
                snprintf(detail, sizeof(detail),
                          "%s=%s has no '+' prefix under RootDirectory=/RootImage= -- resolved against the "
                          "host's root. Fine if %s is bind-mounted 1:1 from the same host path (e.g. via "
                          "BindPaths=/BindReadOnlyPaths=), otherwise double-check this is the intended target.",
                          key, path, bare);
                print_result_line("INFO", check, key, detail, use_color);
            }
        }
    }
    if (printed_header) printf("\n");
    free_str_array(fresh);
}

/* ===================== static lint: .socket unit ===================== */

static void lint_socket_unit(const char *socket_unit_name, const kv_list_t *pairs, counts_t *counts, int use_color) {
    printf("Static lint: %s [Socket] section\n", socket_unit_name);
    if (pairs->count == 0) {
        printf("(no [Socket] directives found)\n\n");
        return;
    }

    char *accept_v = kv_merge(pairs, "Accept");
    int accept = truthy_cfg(accept_v);
    free(accept_v);

    static const char *max_conn_directives[] = {"MaxConnections", "MaxConnectionsPerSource", NULL};
    for (int i = 0; max_conn_directives[i]; i++) {
        char *v = kv_merge(pairs, max_conn_directives[i]);
        if (v && !accept) {
            bump(counts, "WARN");
            char check[64], detail[1024];
            snprintf(check, sizeof(check), "socket_%s", max_conn_directives[i]);
            for (char *p = check; *p; p++) *p = (char)tolower((unsigned char)*p);
            snprintf(detail, sizeof(detail),
                      "%s=%s is configured but has no effect: per systemd.socket(5), it only applies with "
                      "Accept=yes (one service instance per connection). This unit has Accept=no (or unset, "
                      "same default) -- a single persistent service instance handles the socket instead.",
                      max_conn_directives[i], v);
            print_result_line("WARN", check, max_conn_directives[i], detail, use_color);
        }
        free(v);
    }

    static const char *trigger_directives[] = {"TriggerLimitIntervalSec", "TriggerLimitBurst", NULL};
    for (int i = 0; trigger_directives[i]; i++) {
        char *v = kv_merge(pairs, trigger_directives[i]);
        if (v && strcmp(v, "0") == 0) {
            bump(counts, "WARN");
            char check[64], detail[1024];
            snprintf(check, sizeof(check), "socket_%s", trigger_directives[i]);
            for (char *p = check; *p; p++) *p = (char)tolower((unsigned char)*p);
            snprintf(detail, sizeof(detail),
                      "%s=0 disables activation rate limiting entirely for this socket -- an activation storm "
                      "(e.g. a crash-looping paired .service) would retry unbounded. Intentional?", trigger_directives[i]);
            print_result_line("WARN", check, trigger_directives[i], detail, use_color);
        }
        free(v);
    }

    static const char *info_directives[] = {
        "TriggerLimitIntervalSec", "TriggerLimitBurst", "KeepAlive", "KeepAliveTimeSec",
        "KeepAliveIntervalSec", "KeepAliveProbes", "Backlog", NULL,
    };
    for (int i = 0; info_directives[i]; i++) {
        char *v = kv_merge(pairs, info_directives[i]);
        if (v) {
            bump(counts, "INFO");
            char check[64], detail[256];
            snprintf(check, sizeof(check), "socket_%s", info_directives[i]);
            for (char *p = check; *p; p++) *p = (char)tolower((unsigned char)*p);
            snprintf(detail, sizeof(detail), "%s=%s", info_directives[i], v);
            print_result_line("INFO", check, info_directives[i], detail, use_color);
        }
        free(v);
    }
    printf("\n");
}

/* ===================== transient unit command building ===================== */

static void resolve_self_path(char *out, size_t out_len) {
    ssize_t n = readlink("/proc/self/exe", out, out_len - 1);
    if (n < 0) {
        fprintf(stderr, "error: could not resolve /proc/self/exe: %s\n", strerror(errno));
        exit(1);
    }
    out[n] = '\0';
}

/* Directives probed live by run_probe() -- anything else forwarded but not
 * in this list is reported as "configured but not dynamically probed". */
static const char *PROBED_DIRECTIVES[] = {
    "NoNewPrivileges", "ProtectSystem", "ReadWritePaths", "ProtectHome", "PrivateTmp", "PrivateDevices",
    "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
    "ProtectClock", "ProtectHostname", "ProtectProc", "RestrictNamespaces", "RestrictRealtime",
    "RestrictSUIDSGID", "RestrictAddressFamilies", "LockPersonality", "MemoryDenyWriteExecute",
    "CapabilityBoundingSet", "AmbientCapabilities", "UMask", "PrivateUsers", "ProcSubset",
    "RootDirectory", "RootImage", "NoExecPaths", "ExecPaths", "OOMScoreAdjust", "MemoryMax",
    "MemoryHigh", "TasksMax", "LimitNOFILE", "CPUWeight", "IOWeight", "BindPaths", "BindReadOnlyPaths",
    NULL,
};

static strvec_t build_systemd_run_argv(const char *unit_name, const kv_list_t *pairs, const char *self_path) {
    strvec_t v;
    strvec_init(&v);
    strvec_push(&v, strdup("systemd-run"));
    strvec_push(&v, strdup("--quiet"));
    strvec_push(&v, strdup("--pipe"));
    strvec_push(&v, strdup("--wait"));
    strvec_push(&v, strdup("--collect"));
    strvec_pushf(&v, "--unit=%s", unit_name);
    for (size_t i = 0; i < pairs->count; i++) {
        if (in_list(pairs->items[i].key, SKIP_DIRECTIVES)) continue;
        strvec_pushf(&v, "--property=%s=%s", pairs->items[i].key, pairs->items[i].value);
    }
    /* Auto-inject: let our own (self-reexec'd) binary run regardless of
     * whatever the target unit's own ExecPaths=/NoExecPaths= says --
     * repeated ExecPaths= properties accumulate (same as multiple lines
     * in a real unit file), so this only ever *adds* permission, it can't
     * loosen anything the target itself restricts. Confirmed by hand this
     * alone is NOT enough when the target also sets RootDirectory=: exec
     * permission doesn't help if the file isn't even *visible* inside the
     * chroot in the first place (status=203/EXEC) -- BindReadOnlyPaths=
     * makes sure it's actually there. Harmless when RootDirectory= isn't
     * set: binding a path onto itself in the host's own root is a no-op. */
    strvec_pushf(&v, "--property=ExecPaths=%s", self_path);
    strvec_pushf(&v, "--property=BindReadOnlyPaths=%s", self_path);

    for (size_t i = 0; i < pairs->count; i++) {
        const char *key = pairs->items[i].key;
        if (key_seen_before(pairs, i, key)) continue;
        char *merged = kv_merge(pairs, key);
        strvec_pushf(&v, "--setenv=SSC_CFG_%s=%s", key, merged ? merged : "");
        free(merged);
    }
    struct stat st;
    if (stat("/proc/self/ns/uts", &st) == 0) {
        strvec_pushf(&v, "--setenv=SSC_HOST_NS_UTS_INO=%llu", (unsigned long long)st.st_ino);
    }
    if (stat("/", &st) == 0) {
        strvec_pushf(&v, "--setenv=SSC_HOST_ROOT_DEV_INO=%llu:%llu",
                      (unsigned long long)st.st_dev, (unsigned long long)st.st_ino);
    }
    strvec_push(&v, strdup(self_path));
    strvec_push(&v, strdup("--ssc-probe-internal"));
    return v;
}

/* ===================== --exec-check ===================== */

static void parse_exec_start(const char *value, char *prefixes, size_t prefixes_len, strvec_t *argv_out) {
    size_t i = 0;
    while (value[i] && strchr("-+!:@", value[i]) && i < prefixes_len - 1) {
        prefixes[i] = value[i];
        i++;
    }
    prefixes[i] = '\0';
    const char *rest = value + i;
    /* minimal shell-word split: whitespace-separated, no quoting support
     * (systemd's own ExecStart= word-splitting rarely needs it for a
     * simple "binary --flag value" invocation; good enough for a probe). */
    char buf[8192];
    snprintf(buf, sizeof(buf), "%s", rest);
    char *saveptr;
    for (char *tok = strtok_r(buf, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
        strvec_push(argv_out, strdup(tok));
    }
}

static void run_exec_check(const kv_list_t *pairs, const char *exec_start, double timeout_s,
                            counts_t *counts, int use_color) {
    char prefixes[16];
    strvec_t argv;
    strvec_init(&argv);
    parse_exec_start(exec_start, prefixes, sizeof(prefixes), &argv);
    if (strpbrk(prefixes, "+!")) {
        bump(counts, "WARN");
        print_result_line("WARN", "exec_check", "ExecStart",
                            "ExecStart uses prefix(es) that escape or alter the sandbox ('+'/'!'/'!!', see "
                            "systemd.service(5)) -- skipped, running it would not test the real hardening", use_color);
        strvec_free(&argv);
        return;
    }
    if (argv.count == 0) {
        bump(counts, "WARN");
        print_result_line("WARN", "exec_check", "ExecStart", "ExecStart could not be parsed into a command, skipped", use_color);
        strvec_free(&argv);
        return;
    }

    char unit_name[128];
    snprintf(unit_name, sizeof(unit_name), "sandbox-check-%d-exec", getpid());

    strvec_t cmd;
    strvec_init(&cmd);
    strvec_push(&cmd, strdup("systemd-run"));
    strvec_push(&cmd, strdup("--quiet"));
    strvec_pushf(&cmd, "--unit=%s", unit_name);
    for (size_t i = 0; i < pairs->count; i++) {
        if (in_list(pairs->items[i].key, EXEC_SKIP_DIRECTIVES)) continue;
        strvec_pushf(&cmd, "--property=%s=%s", pairs->items[i].key, pairs->items[i].value);
    }
    strvec_push(&cmd, strdup("--property=Restart=no"));
    for (size_t i = 0; i < argv.count; i++) strvec_push(&cmd, strdup(argv.items[i]));
    strvec_free(&argv);

    fprintf(stderr, "WARNING: --exec-check starts the unit's real ExecStart with production-like paths/network "
                     "bindings; if the real service is already running this may conflict (e.g. port already in use).\n");

    char *out = NULL;
    char **cmd_argv = strvec_argv(&cmd);
    int rc = run_capture(cmd_argv, &out);
    free(cmd_argv);
    strvec_free(&cmd);
    free(out);

    if (rc != 0) {
        bump(counts, "FAIL");
        print_result_line("FAIL", "exec_check", "ExecStart", "systemd-run failed to start the unit", use_color);
        return;
    }

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)timeout_s;
    char active[64] = "?", sub[64] = "?";
    for (;;) {
        char *show_argv_buf[16];
        char unit_prop[160];
        snprintf(unit_prop, sizeof(unit_prop), "%s", unit_name);
        char *show_argv[] = {"systemctl", "show", unit_prop, "--property=ActiveState", "--property=SubState", NULL};
        (void)show_argv_buf;
        char *show_out = NULL;
        run_capture(show_argv, &show_out);
        char *line = show_out ? strtok(show_out, "\n") : NULL;
        while (line) {
            if (strncmp(line, "ActiveState=", 12) == 0) snprintf(active, sizeof(active), "%s", line + 12);
            if (strncmp(line, "SubState=", 9) == 0) snprintf(sub, sizeof(sub), "%s", line + 9);
            line = strtok(NULL, "\n");
        }
        free(show_out);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        int timed_out = now.tv_sec > deadline.tv_sec || (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec);
        if (strcmp(active, "failed") == 0 || timed_out) break;
        struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 300000000L};
        nanosleep(&sleep_time, NULL);
    }

    char detail[256];
    const char *status;
    if (strcmp(active, "failed") == 0) {
        status = "FAIL";
        snprintf(detail, sizeof(detail), "unit failed (ActiveState=%s/%s)", active, sub);
    } else if (strcmp(active, "active") == 0) {
        status = "PASS";
        snprintf(detail, sizeof(detail), "still running after %gs (ActiveState=%s/%s)", timeout_s, active, sub);
    } else if (strcmp(active, "activating") == 0) {
        status = "WARN";
        snprintf(detail, sizeof(detail), "still 'activating' after %gs -- a Type=notify readiness signal may never have been sent", timeout_s);
    } else {
        status = "WARN";
        snprintf(detail, sizeof(detail), "unexpected state ActiveState=%s/%s", active, sub);
    }
    bump(counts, status);
    print_result_line(status, "exec_check", "ExecStart", detail, use_color);

    char *stop_argv[] = {"systemctl", "stop", unit_name, NULL};
    char *reset_argv[] = {"systemctl", "reset-failed", unit_name, NULL};
    char *tmp;
    run_capture(stop_argv, &tmp); free(tmp);
    run_capture(reset_argv, &tmp); free(tmp);
}

/* ===================== main CLI entry point ===================== */

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s --unit PATH [--dry-run] [--exec-check] [--exec-check-timeout SECONDS] "
        "[--socket-unit PATH]\n"
        "       %s --version\n", prog, prog);
}

int run_cli(int argc, char **argv) {
    const char *unit_path = NULL;
    const char *socket_unit_path = NULL;
    int dry_run = 0, exec_check = 0;
    double exec_check_timeout = 5.0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--unit") == 0 && i + 1 < argc) {
            unit_path = argv[++i];
        } else if (strcmp(argv[i], "--socket-unit") == 0 && i + 1 < argc) {
            socket_unit_path = argv[++i];
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(argv[i], "--exec-check") == 0) {
            exec_check = 1;
        } else if (strcmp(argv[i], "--exec-check-timeout") == 0 && i + 1 < argc) {
            exec_check_timeout = atof(argv[++i]);
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    if (!unit_path) {
        usage(argv[0]);
        return 1;
    }
    struct stat st;
    if (stat(unit_path, &st) != 0) {
        fprintf(stderr, "error: unit file not found: %s\n", unit_path);
        return 1;
    }
    if (socket_unit_path && stat(socket_unit_path, &st) != 0) {
        fprintf(stderr, "error: socket unit file not found: %s\n", socket_unit_path);
        return 1;
    }

    kv_list_t pairs;
    if (parse_unit_section(unit_path, "service", &pairs) != 0) {
        fprintf(stderr, "error: could not read %s\n", unit_path);
        return 1;
    }

    char self_path[4096];
    resolve_self_path(self_path, sizeof(self_path));

    if (strncmp(self_path, "/home/", 6) == 0) {
        char *protect_home = kv_merge(&pairs, "ProtectHome");
        int home_hidden = protect_home && (strcasecmp(protect_home, "true") == 0 ||
                                            strcasecmp(protect_home, "read-only") == 0 ||
                                            strcasecmp(protect_home, "tmpfs") == 0);
        free(protect_home);
        if (home_hidden) {
            fprintf(stderr,
                "error: this binary is installed under /home (%s), but %s sets "
                "ProtectHome=; binding it into the transient sandbox would fail "
                "(systemd-run: status=203/EXEC, \"No such file or directory\") since "
                "ProtectHome= hides its own path there. Install it under /usr/local/bin "
                "(or anywhere outside /home) instead. Aborting.\n",
                self_path, unit_path);
            kv_list_free(&pairs);
            return 1;
        }
    }

    char unit_name[128];
    snprintf(unit_name, sizeof(unit_name), "sandbox-check-%d", getpid());
    strvec_t cmd = build_systemd_run_argv(unit_name, &pairs, self_path);

    int use_color = isatty(STDOUT_FILENO);
    counts_t counts = {0, 0, 0, 0};

    lint_plus_prefix(&pairs, &counts, use_color);

    if (socket_unit_path) {
        kv_list_t socket_pairs;
        parse_unit_section(socket_unit_path, "socket", &socket_pairs);
        const char *slash = strrchr(socket_unit_path, '/');
        lint_socket_unit(slash ? slash + 1 : socket_unit_path, &socket_pairs, &counts, use_color);
        kv_list_free(&socket_pairs);
    }

    if (dry_run) {
        for (size_t i = 0; i < cmd.count; i++) {
            /* Quote for shell copy-paste if the arg contains anything a
             * shell would otherwise split on (systemd property values with
             * multiple space-separated entries, e.g. SecureBits=). */
            int needs_quote = strpbrk(cmd.items[i], " \t\"'$`\\") != NULL;
            if (needs_quote) printf("'%s'", cmd.items[i]);
            else printf("%s", cmd.items[i]);
            printf(i + 1 < cmd.count ? " " : "\n");
        }
        strvec_free(&cmd);
        kv_list_free(&pairs);
        return 0;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "error: must run as root (systemd-run needs privileges for a system-scope transient unit)\n");
        strvec_free(&cmd);
        kv_list_free(&pairs);
        return 1;
    }

    char **cmd_argv = strvec_argv(&cmd);
    char *out = NULL;
    int rc = run_capture(cmd_argv, &out);
    free(cmd_argv);
    if (rc != 0 && (!out || out[0] == '\0')) {
        fprintf(stderr, "error: transient unit failed to run (exit %d)\n", rc);
        free(out);
        strvec_free(&cmd);
        kv_list_free(&pairs);
        return 1;
    }

    char *saveptr;
    for (char *line = strtok_r(out, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        char *status = strtok(line, "\t");
        char *check = status ? strtok(NULL, "\t") : NULL;
        char *directive = check ? strtok(NULL, "\t") : NULL;
        char *detail = directive ? strtok(NULL, "") : NULL;
        if (!status || !check || !directive || !detail) continue;
        bump(&counts, status);
        print_result_line(status, check, directive, detail, use_color);
    }
    free(out);

    if (exec_check) {
        char *exec_start = kv_merge(&pairs, "ExecStart");
        if (!exec_start) {
            bump(&counts, "WARN");
            print_result_line("WARN", "exec_check", "ExecStart", "no ExecStart found in unit, skipped", use_color);
        } else {
            run_exec_check(&pairs, exec_start, exec_check_timeout, &counts, use_color);
            free(exec_start);
        }
    }

    printf("\nConfigured but not dynamically probed (static-only, see `systemd-analyze security`):\n");
    int any_unprobed = 0;
    for (size_t i = 0; i < pairs.count; i++) {
        const char *key = pairs.items[i].key;
        if (key_seen_before(&pairs, i, key)) continue;
        if (in_list(key, PROBED_DIRECTIVES) || in_list(key, SKIP_DIRECTIVES)) continue;
        char *merged = kv_merge(&pairs, key);
        printf("  - %s=%s\n", key, merged ? merged : "");
        free(merged);
        any_unprobed = 1;
    }
    if (!any_unprobed) printf("  (none)\n");

    printf("\nSummary: %d PASS, %d FAIL, %d WARN, %d INFO\n", counts.pass, counts.fail, counts.warn, counts.info);

    strvec_free(&cmd);
    kv_list_free(&pairs);
    return counts.fail > 0 ? 1 : 0;
}
