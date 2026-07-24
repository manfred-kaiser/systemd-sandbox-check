/* Probe battery -- runs *inside* the transient sandboxed unit (see
 * ssc.h for why this is the same binary as the orchestrator, re-exec'd).
 * Reads its config from SSC_CFG_<Directive> environment variables set by
 * the orchestrator (cli.c) via --setenv=.
 *
 * Every probe here is chosen to be a no-op (or self-contained to this
 * short-lived process) even if the restriction it tests turns out *not*
 * to be enforced -- no reboot/mount/settimeofday/module-load syscalls.
 * Capability-gated actions are checked by reading the capability bitmask
 * instead of exercising them. Direct C port of probe.py -- see that file
 * (or its git history) for the reasoning behind each individual check.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>

#include "ssc.h"

void ssc_emit(const char *status, const char *check, const char *directive, const char *detail_fmt, ...) {
    char detail[4096];
    va_list ap;
    va_start(ap, detail_fmt);
    vsnprintf(detail, sizeof(detail), detail_fmt, ap);
    va_end(ap);
    /* Tab-delimited (not JSON): avoids needing a JSON library in a binary
     * whose whole point is minimal static-link footprint. Detail must not
     * itself contain literal tabs/newlines -- none of our messages do. */
    printf("%s\t%s\t%s\t%s\n", status, check, directive, detail);
    fflush(stdout);
}

static char *cfg(const char *directive) {
    char name[256];
    snprintf(name, sizeof(name), "SSC_CFG_%s", directive);
    char *v = getenv(name);
    return v; /* NULL if not set; may be "" if set-but-empty */
}

/* --- small helpers, mirroring probe.py's --- */

static int try_create_and_remove(const char *path) {
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return 0;
    close(fd);
    unlink(path);
    return 1;
}

static int try_open_existing(const char *path, int flags) {
    int fd = open(path, flags);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static unsigned long long cap_bitmask(const char *field) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[512];
    unsigned long long value = 0;
    size_t flen = strlen(field);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, field, flen) == 0 && line[flen] == ':') {
            value = strtoull(line + flen + 1, NULL, 16);
            break;
        }
    }
    fclose(f);
    return value;
}

/* CAP_* bit numbers, same as probe.py's CAP_BIT table. */
static int cap_bit(const char *name) {
    static const struct { const char *name; int bit; } table[] = {
        {"CAP_SETGID", 6}, {"CAP_SETUID", 7}, {"CAP_NET_BIND_SERVICE", 10},
        {"CAP_NET_ADMIN", 12}, {"CAP_NET_RAW", 13}, {"CAP_SYS_MODULE", 16},
        {"CAP_SYS_PTRACE", 19}, {"CAP_SYS_ADMIN", 21}, {"CAP_SYS_BOOT", 22},
        {"CAP_SYS_TIME", 25}, {"CAP_WAKE_ALARM", 35},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(table[i].name, name) == 0) return table[i].bit;
    }
    return -1;
}

static int cap_present(const char *name, const char *field) {
    int bit = cap_bit(name);
    if (bit < 0) return 0;
    return (cap_bitmask(field) & (1ULL << bit)) != 0;
}

/* --- /proc/self/mountinfo lookup: fstype + per-mount options for a given
 * mount point, if a dedicated mount exists there. Two properties this file
 * needs that plain permission-based probing can't give us: capability-
 * independence (root's default CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH bypasses
 * DAC permission checks regardless of the actual protection -- confirmed by
 * hand that opendir("/root") succeeds identically whether ProtectHome= is
 * set or not, as long as the unit doesn't ALSO strip those capabilities from
 * CapabilityBoundingSet=) and host-agnosticism (a specific device node like
 * /dev/sda doesn't exist on NVMe-/virtio-only hosts, confirmed by hand on
 * this machine, which has only /dev/nvme0n1). */
static int mountinfo_lookup(const char *path, char *fstype, size_t fstype_len,
                              char *mount_opts, size_t opts_len) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) return 0;
    char line[2048];
    int found = 0;
    while (!found && fgets(line, sizeof(line), f)) {
        char *copy = strdup(line);
        char *fields[16] = {0};
        int nf = 0;
        char *saveptr;
        for (char *tok = strtok_r(copy, " ", &saveptr); tok && nf < 16; tok = strtok_r(NULL, " ", &saveptr)) {
            fields[nf++] = tok;
        }
        /* mountinfo(5): ... (5)mount-point (6)mount-opts ... "-" fstype source super-opts */
        if (nf > 5 && strcmp(fields[4], path) == 0) {
            if (mount_opts) snprintf(mount_opts, opts_len, "%s", fields[5]);
            for (int i = 6; i < nf; i++) {
                if (strcmp(fields[i], "-") == 0 && i + 1 < nf) {
                    if (fstype) snprintf(fstype, fstype_len, "%s", fields[i + 1]);
                    break;
                }
            }
            found = 1;
        }
        free(copy);
    }
    fclose(f);
    return found;
}

/* True if `token` is one of the comma-separated entries in `opts` (not just
 * a substring match -- "noexec" must not match a search for "exec"). */
static int has_mount_opt(const char *opts, const char *token) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", opts);
    char *saveptr;
    for (char *tok = strtok_r(buf, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
        if (strcmp(tok, token) == 0) return 1;
    }
    return 0;
}

/* A "true"-like value for a boolean directive (systemd accepts several
 * spellings; we only need to recognize the common ones here). */
static int truthy(const char *v) {
    if (!v) return 0;
    return strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0 || strcmp(v, "1") == 0;
}

/* blocked_result equivalent: emits PASS/FAIL/INFO depending on whether the
 * directive is set to (one of) truthy_values and whether the restriction
 * was observed to actually be blocked. truthy_values is a single string
 * here since all our callers only ever check one spelling class at a time
 * (either boolean-true or a specific enum value like "pid"/"invisible"). */
static void blocked_result(const char *directive, int (*is_truthy)(const char *),
                            int observed_blocked, const char *check,
                            const char *detail_ok, const char *detail_bad) {
    char *val = cfg(directive);
    if (val == NULL) {
        ssc_emit(SSC_INFO, check, directive, "%s not set in unit; observed: %s",
                 directive, observed_blocked ? "blocked" : "allowed");
        return;
    }
    if (is_truthy(val)) {
        ssc_emit(observed_blocked ? SSC_PASS : SSC_FAIL, check, directive, "%s",
                  observed_blocked ? detail_ok : detail_bad);
    } else {
        ssc_emit(SSC_INFO, check, directive, "%s=%s; observed: %s", directive, val,
                 observed_blocked ? "blocked" : "allowed");
    }
}

static int is_pid_subset(const char *v) { return strcasecmp(v, "pid") == 0; }
static int is_invisible_proc(const char *v) {
    return strcasecmp(v, "invisible") == 0 || strcasecmp(v, "noaccess") == 0 || strcasecmp(v, "restricted") == 0;
}
static int is_home_protected(const char *v) {
    return strcasecmp(v, "true") == 0 || strcasecmp(v, "read-only") == 0 || strcasecmp(v, "tmpfs") == 0;
}
static int is_system_protected(const char *v) {
    return strcasecmp(v, "strict") == 0 || strcasecmp(v, "full") == 0 || strcasecmp(v, "true") == 0;
}

/* --- BindPaths=/BindReadOnlyPaths= destination parsing --- */

/* "SRC", "SRC:DST" or "SRC:DST:OPTIONS" -- a leading -/+ on SRC never
 * applies to DST, so strip it first. Result is a static buffer, good
 * until the next call (all call sites use it immediately). */
static const char *bind_dest(const char *entry) {
    static char buf[4096];
    while (*entry == '-' || *entry == '+') entry++;
    const char *first_colon = strchr(entry, ':');
    if (!first_colon) {
        snprintf(buf, sizeof(buf), "%s", entry);
        return buf;
    }
    const char *dst_start = first_colon + 1;
    const char *second_colon = strchr(dst_start, ':');
    size_t dst_len = second_colon ? (size_t)(second_colon - dst_start) : strlen(dst_start);
    if (dst_len == 0) {
        snprintf(buf, sizeof(buf), "%.*s", (int)(first_colon - entry), entry);
        return buf;
    }
    snprintf(buf, sizeof(buf), "%.*s", (int)dst_len, dst_start);
    return buf;
}

/* --- cgroup / resource-control readback helpers --- */

static char *own_cgroup_path(void) {
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) return NULL;
    char line[1024];
    char *result = NULL;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        /* cgroup v2 unified hierarchy: "0::/path/to/unit.service" */
        if (strncmp(line, "0::", 3) == 0) {
            char full[2048];
            snprintf(full, sizeof(full), "/sys/fs/cgroup%s", line + 3);
            result = strdup(full);
            break;
        }
    }
    fclose(f);
    return result;
}

static char *read_cgroup_file(const char *name) {
    char *cg = own_cgroup_path();
    if (!cg) return NULL;
    char path[3072];
    snprintf(path, sizeof(path), "%s/%s", cg, name);
    free(cg);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char buf[512] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    /* strip trailing whitespace/newline */
    while (n > 0 && isspace((unsigned char)buf[n - 1])) buf[--n] = '\0';
    return strdup(buf);
}

/* Parse a systemd byte-size value ("2G", "1536M", "512", "infinity", "50%")
 * into a byte count. Returns 0 and sets *ok=0 if unparseable/not directly
 * comparable (percentages are relative to total RAM). */
static long long parse_systemd_bytes(const char *value, int *ok) {
    *ok = 0;
    if (!value || *value == '\0' || strcmp(value, "infinity") == 0) return 0;
    size_t len = strlen(value);
    if (value[len - 1] == '%') return 0;
    static const struct { char suffix; long long mult; } units[] = {
        {'K', 1024LL}, {'M', 1024LL * 1024}, {'G', 1024LL * 1024 * 1024}, {'T', 1024LL * 1024 * 1024 * 1024},
    };
    for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
        if (value[len - 1] == units[i].suffix) {
            char numbuf[64];
            snprintf(numbuf, sizeof(numbuf), "%.*s", (int)(len - 1), value);
            char *end;
            double n = strtod(numbuf, &end);
            if (end == numbuf) return 0;
            *ok = 1;
            return (long long)(n * (double)units[i].mult);
        }
    }
    char *end;
    long long n = strtoll(value, &end, 10);
    if (end == value || *end != '\0') return 0;
    *ok = 1;
    return n;
}

/* ============================= run_probe ============================= */

int run_probe(void) {
    /* 1. NoNewPrivileges */
    {
        char nnp = '0';
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "NoNewPrivs:", 11) == 0) {
                    char *p = line + 11;
                    while (*p && isspace((unsigned char)*p)) p++;
                    nnp = *p;
                    break;
                }
            }
            fclose(f);
        }
        blocked_result("NoNewPrivileges", truthy, nnp == '1', "no_new_privileges",
                        "NoNewPrivs flag is set", "NoNewPrivs flag NOT set despite NoNewPrivileges=true");
    }

    /* 2. ProtectSystem: /usr must not be writable */
    {
        char path[128];
        snprintf(path, sizeof(path), "/usr/.sandbox-check-%d", getpid());
        int ok = try_create_and_remove(path);
        blocked_result("ProtectSystem", is_system_protected, !ok, "protect_system",
                        "/usr is not writable", "/usr IS writable");
    }

    /* 3. ReadWritePaths positive control */
    {
        char *rwp = cfg("ReadWritePaths");
        if (rwp && *rwp) {
            char target[2048];
            sscanf(rwp, "%2047s", target);
            struct stat st;
            if (stat(target, &st) == 0 && S_ISDIR(st.st_mode)) {
                char path[3072];
                snprintf(path, sizeof(path), "%s/.sandbox-check-%d", target, getpid());
                int ok = try_create_and_remove(path);
                ssc_emit(ok ? SSC_PASS : SSC_FAIL, "readwritepaths_rw", "ReadWritePaths",
                          ok ? "%s writable as expected" : "%s NOT writable -- over-restrictive?", target);
            } else {
                ssc_emit(SSC_WARN, "readwritepaths_rw", "ReadWritePaths", "%s does not exist, skipped", target);
            }
        }
    }

    /* 3b/3c. BindReadOnlyPaths=/BindPaths= */
    {
        char *bind_ro = cfg("BindReadOnlyPaths");
        if (bind_ro && *bind_ro) {
            char buf[8192];
            snprintf(buf, sizeof(buf), "%s", bind_ro);
            char *saveptr;
            for (char *entry = strtok_r(buf, " ", &saveptr); entry; entry = strtok_r(NULL, " ", &saveptr)) {
                const char *dest = bind_dest(entry);
                struct stat st;
                if (stat(dest, &st) != 0) {
                    ssc_emit(SSC_WARN, "bind_read_only_paths", "BindReadOnlyPaths", "%s does not exist, skipped", dest);
                    continue;
                }
                int writable;
                if (S_ISDIR(st.st_mode)) {
                    char path[3072];
                    snprintf(path, sizeof(path), "%s/.sandbox-check-%d", dest, getpid());
                    writable = try_create_and_remove(path);
                } else {
                    writable = try_open_existing(dest, O_WRONLY);
                }
                ssc_emit(writable ? SSC_FAIL : SSC_PASS, "bind_read_only_paths", "BindReadOnlyPaths",
                          writable ? "%s IS writable -- BindReadOnlyPaths= not enforced?" : "%s is read-only as expected",
                          dest);
            }
        }
        char *bind_rw = cfg("BindPaths");
        if (bind_rw && *bind_rw) {
            char buf[8192];
            snprintf(buf, sizeof(buf), "%s", bind_rw);
            char *saveptr;
            for (char *entry = strtok_r(buf, " ", &saveptr); entry; entry = strtok_r(NULL, " ", &saveptr)) {
                const char *dest = bind_dest(entry);
                struct stat st;
                if (stat(dest, &st) != 0) {
                    ssc_emit(SSC_WARN, "bind_paths", "BindPaths", "%s does not exist, skipped", dest);
                    continue;
                }
                int writable;
                if (S_ISDIR(st.st_mode)) {
                    char path[3072];
                    snprintf(path, sizeof(path), "%s/.sandbox-check-%d", dest, getpid());
                    writable = try_create_and_remove(path);
                } else {
                    writable = try_open_existing(dest, O_WRONLY);
                }
                ssc_emit(writable ? SSC_PASS : SSC_FAIL, "bind_paths", "BindPaths",
                          writable ? "%s writable as expected" : "%s NOT writable -- over-restrictive?", dest);
            }
        }
    }

    /* 4. ProtectHome: a dedicated mount must exist at /root (see
     * mountinfo_lookup's comment for why this replaces a plain
     * opendir()-based accessibility check). */
    {
        int has_own_mount = mountinfo_lookup("/root", NULL, 0, NULL, 0);
        blocked_result("ProtectHome", is_home_protected, has_own_mount, "protect_home",
                        "/root is a dedicated (empty) mount, separate from the host's",
                        "/root is NOT a separate mount -- resolves to the host's real /root");
    }

    /* 5. PrivateTmp: /tmp mount should come from a systemd-private-* source */
    {
        int private_tmp = 0;
        FILE *f = fopen("/proc/self/mountinfo", "r");
        if (f) {
            char line[2048];
            while (fgets(line, sizeof(line), f)) {
                /* field 5 (0-indexed 4) is the mount point */
                char *saveptr;
                char *copy = strdup(line);
                int field = 0;
                char *mp = NULL;
                for (char *tok = strtok_r(copy, " ", &saveptr); tok; tok = strtok_r(NULL, " ", &saveptr), field++) {
                    if (field == 4) { mp = tok; break; }
                }
                int is_tmp = mp && strcmp(mp, "/tmp") == 0;
                int has_private = strstr(line, "systemd-private") != NULL;
                free(copy);
                if (is_tmp && has_private) { private_tmp = 1; break; }
            }
            fclose(f);
        }
        blocked_result("PrivateTmp", truthy, private_tmp, "private_tmp",
                        "/tmp is a private systemd-private mount", "/tmp does NOT look like a private mount (heuristic)");
    }

    /* 6. PrivateDevices: the real host /dev is always kernel-provided
     * "devtmpfs"; PrivateDevices= replaces it with a private, minimal
     * "tmpfs" instance (see mountinfo_lookup's comment for why this
     * replaces a specific-device-node check). */
    {
        char fstype[64] = {0};
        int have_mount = mountinfo_lookup("/dev", fstype, sizeof(fstype), NULL, 0);
        int is_private = have_mount && strcmp(fstype, "tmpfs") == 0;
        blocked_result("PrivateDevices", truthy, is_private, "private_devices",
                        "/dev is a private tmpfs instance, not the host's real devtmpfs",
                        "/dev is still the host's real devtmpfs -- full device list visible");
        int null_ok = try_open_existing("/dev/null", O_RDONLY);
        ssc_emit(null_ok ? SSC_PASS : SSC_WARN, "private_devices_null_control", "PrivateDevices",
                  null_ok ? "/dev/null accessible" : "/dev/null NOT accessible -- likely over-restrictive");
    }

    /* 7. ProtectKernelTunables */
    {
        int ok = try_open_existing("/proc/sys/vm/swappiness", O_RDWR);
        blocked_result("ProtectKernelTunables", truthy, !ok, "protect_kernel_tunables",
                        "/proc/sys/vm/swappiness not writable", "/proc/sys/vm/swappiness IS writable");
    }

    /* 8. ProtectKernelModules */
    {
        int has_cap = cap_present("CAP_SYS_MODULE", "CapBnd");
        blocked_result("ProtectKernelModules", truthy, !has_cap, "protect_kernel_modules",
                        "CAP_SYS_MODULE absent from CapBnd", "CAP_SYS_MODULE still present in CapBnd");
    }

    /* 9. ProtectKernelLogs */
    {
        int ok = try_open_existing("/dev/kmsg", O_RDONLY);
        blocked_result("ProtectKernelLogs", truthy, !ok, "protect_kernel_logs",
                        "/dev/kmsg not accessible", "/dev/kmsg IS accessible");
    }

    /* 10. ProtectControlGroups: cgroupfs never supports creating arbitrary
     * regular files via O_CREAT at all -- confirmed by hand this fails with
     * EPERM identically with or without ProtectControlGroups= (at both the
     * cgroup root and the unit's own delegated subtree), so a
     * try_create_and_remove()-based check had no discriminating power at
     * all. ProtectControlGroups= instead remounts the whole /sys/fs/cgroup
     * tree read-only, which shows up as "ro" vs "rw" in its own mount
     * options. */
    {
        char mount_opts[256] = {0};
        int have_mount = mountinfo_lookup("/sys/fs/cgroup", NULL, 0, mount_opts, sizeof(mount_opts));
        int is_readonly = have_mount && has_mount_opt(mount_opts, "ro");
        blocked_result("ProtectControlGroups", truthy, is_readonly, "protect_control_groups",
                        "/sys/fs/cgroup is mounted read-only", "/sys/fs/cgroup is mounted read-write");
    }

    /* 11. ProtectClock */
    {
        int has_time_cap = cap_present("CAP_SYS_TIME", "CapBnd") || cap_present("CAP_WAKE_ALARM", "CapBnd");
        blocked_result("ProtectClock", truthy, !has_time_cap, "protect_clock",
                        "CAP_SYS_TIME/CAP_WAKE_ALARM absent", "CAP_SYS_TIME or CAP_WAKE_ALARM still present");
    }

    /* 12. ProtectHostname: private UTS namespace */
    {
        char *host_ino = getenv("SSC_HOST_NS_UTS_INO");
        struct stat st;
        int private_uts = 0;
        if (host_ino && stat("/proc/self/ns/uts", &st) == 0) {
            char self_ino[32];
            snprintf(self_ino, sizeof(self_ino), "%llu", (unsigned long long)st.st_ino);
            private_uts = strcmp(self_ino, host_ino) != 0;
        }
        blocked_result("ProtectHostname", truthy, private_uts, "protect_hostname",
                        "private UTS namespace (differs from host)", "UTS namespace matches host -- hostname changes would propagate");
    }

    /* 13. ProtectProc: /proc/1 must not be visible. Confirmed by hand: this
     * is a real gap, not a probe artifact -- ProtectProc= is a no-op for any
     * process that still holds CAP_SYS_PTRACE (the default for a unit that
     * doesn't also restrict CapabilityBoundingSet=), exactly as documented
     * in systemd.exec(5): "ProtectProc= has to be used together with User=/
     * DynamicUser=yes and without CAP_SYS_PTRACE, to be effective." A FAIL
     * here despite ProtectProc= being set usually means CAP_SYS_PTRACE is
     * still in the unit's CapabilityBoundingSet=. */
    {
        DIR *d = opendir("/proc/1");
        int visible = d != NULL;
        if (d) closedir(d);
        blocked_result("ProtectProc", is_invisible_proc, !visible, "protect_proc",
                        "/proc/1 not visible",
                        "/proc/1 IS visible -- if ProtectProc= is set, the unit's "
                        "CapabilityBoundingSet= probably still retains CAP_SYS_PTRACE, "
                        "which is documented to bypass this restriction (systemd.exec(5))");
    }

    /* 14. RestrictNamespaces: unshare(CLONE_NEWNS) must fail. Run in a
     * forked child, not the main probe process -- confirmed by hand
     * (2026-07-24) that calling unshare(CLONE_NEWNS) directly here, when it
     * succeeds (i.e. RestrictNamespaces= is absent/not blocking it), gives
     * this process a freshly unshared mount namespace that changes the
     * outcome of LATER checks in the same run, in particular no_exec_paths
     * (#25): NoExecPaths=/tmp under RootDirectory= without a "+" prefix
     * appeared to depend on RestrictNamespaces= in earlier testing, but
     * that was entirely this contamination, not a real interaction between
     * the two directives -- an isolated, unshare()-free reproduction shows
     * the bug is present either way. Isolating the unshare() call to a
     * child (which exits right after) keeps the main probe process's mount
     * namespace untouched for every check that runs after this one. */
    {
        pid_t pid = fork();
        if (pid == 0) {
            _exit(unshare(CLONE_NEWNS) == 0 ? 0 : 1);
        }
        int status = 0;
        int blocked = 1;
        if (pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status)) {
            blocked = WEXITSTATUS(status) != 0;
        }
        blocked_result("RestrictNamespaces", truthy, blocked, "restrict_namespaces",
                        "unshare(CLONE_NEWNS) blocked", "unshare(CLONE_NEWNS) SUCCEEDED");
    }

    /* 15. RestrictRealtime */
    {
        struct sched_param sp = {.sched_priority = 1};
        int rc = sched_setscheduler(0, SCHED_FIFO, &sp);
        blocked_result("RestrictRealtime", truthy, rc != 0, "restrict_realtime",
                        "SCHED_FIFO refused", "SCHED_FIFO was granted");
    }

    /* 16. RestrictSUIDSGID */
    {
        char tmp_path[] = "/tmp/sandbox-check-suid-XXXXXX";
        int fd = mkstemp(tmp_path);
        int suid_blocked;
        if (fd < 0) {
            suid_blocked = 1; /* couldn't even create it -- treat as N/A-safe, not a false FAIL */
        } else {
            close(fd);
            suid_blocked = chmod(tmp_path, 04755) != 0;
            unlink(tmp_path);
        }
        blocked_result("RestrictSUIDSGID", truthy, suid_blocked, "restrict_suidsgid",
                        "chmod +s refused", "chmod +s SUCCEEDED");
    }

    /* 17. RestrictAddressFamilies */
    {
        int nls = socket(AF_NETLINK, SOCK_RAW, 0);
        int netlink_blocked = nls < 0;
        if (nls >= 0) close(nls);
        char *raf = cfg("RestrictAddressFamilies");
        if (raf) {
            int raf_lists_netlink = strstr(raf, "AF_NETLINK") != NULL;
            const char *status = (netlink_blocked && !raf_lists_netlink) ? SSC_PASS
                                : (raf_lists_netlink && !netlink_blocked) ? SSC_INFO
                                : SSC_FAIL;
            ssc_emit(status, "restrict_af_netlink", "RestrictAddressFamilies",
                      netlink_blocked ? "AF_NETLINK blocked as expected" : "AF_NETLINK socket creation SUCCEEDED");
        } else {
            ssc_emit(SSC_INFO, "restrict_af_netlink", "RestrictAddressFamilies",
                      "RestrictAddressFamilies not set; AF_NETLINK %s", netlink_blocked ? "blocked" : "allowed");
        }

        int s = socket(AF_INET, SOCK_STREAM, 0);
        int inet_ok = 0;
        if (s >= 0) {
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            inet_ok = bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0;
            close(s);
        }
        ssc_emit(inet_ok ? SSC_PASS : SSC_WARN, "restrict_af_inet_control", "RestrictAddressFamilies",
                  inet_ok ? "AF_INET still works" : "AF_INET socket creation FAILED -- over-restrictive");
    }

    /* 18. LockPersonality */
    {
        int rc = personality(ADDR_NO_RANDOMIZE);
        blocked_result("LockPersonality", truthy, rc == -1, "lock_personality",
                        "personality() change refused", "personality() change SUCCEEDED");
    }

    /* 19. MemoryDenyWriteExecute */
    {
        void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int blocked = m == MAP_FAILED;
        if (!blocked) munmap(m, 4096);
        blocked_result("MemoryDenyWriteExecute", truthy, blocked, "memory_deny_write_execute",
                        "RWX mmap refused", "RWX mmap SUCCEEDED");
    }

    /* 20. CapabilityBoundingSet / AmbientCapabilities */
    {
        char *cbs = cfg("CapabilityBoundingSet");
        unsigned long long observed = cap_bitmask("CapBnd");
        if (cbs != NULL) {
            unsigned long long expected = 0;
            char buf[2048];
            snprintf(buf, sizeof(buf), "%s", cbs);
            char *saveptr;
            for (char *tok = strtok_r(buf, " ", &saveptr); tok; tok = strtok_r(NULL, " ", &saveptr)) {
                int bit = cap_bit(tok);
                if (bit >= 0) expected |= (1ULL << bit);
            }
            ssc_emit(observed == expected ? SSC_PASS : SSC_FAIL, "capability_bounding_set", "CapabilityBoundingSet",
                      "CapBnd=0x%llx expected=0x%llx (%s)", observed, expected, cbs);
        } else {
            ssc_emit(SSC_INFO, "capability_bounding_set", "CapabilityBoundingSet",
                      "CapabilityBoundingSet not set; CapBnd=0x%llx", observed);
        }

        char *amb = cfg("AmbientCapabilities");
        if (amb && strstr(amb, "CAP_NET_BIND_SERVICE")) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s >= 0) {
                struct sockaddr_in addr = {0};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(80);
                addr.sin_addr.s_addr = INADDR_ANY;
                if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                    ssc_emit(SSC_PASS, "ambient_cap_net_bind_service", "AmbientCapabilities", "bind(80) succeeded");
                } else if (errno == EACCES || errno == EPERM) {
                    ssc_emit(SSC_FAIL, "ambient_cap_net_bind_service", "AmbientCapabilities",
                              "bind(80) DENIED despite AmbientCapabilities");
                } else {
                    ssc_emit(SSC_PASS, "ambient_cap_net_bind_service", "AmbientCapabilities",
                              "bind(80) got past permission check (%s)", strerror(errno));
                }
                close(s);
            }
        }
    }

    /* 21. UMask */
    {
        char tmp_path[] = "/tmp/sandbox-check-umask-XXXXXX";
        int fd = mkstemp(tmp_path);
        mode_t mode = 0;
        if (fd >= 0) {
            struct stat st;
            fstat(fd, &st);
            mode = st.st_mode & 0777;
            close(fd);
            unlink(tmp_path);
        }
        char *umask_cfg = cfg("UMask");
        if (umask_cfg) {
            mode_t expected_mask = (mode_t)strtol(umask_cfg, NULL, 8);
            mode_t expected_mode = 0666 & ~expected_mask;
            ssc_emit(mode == expected_mode ? SSC_PASS : SSC_WARN, "umask", "UMask",
                      "file created with mode 0%o, expected 0%o for UMask=%s", mode, expected_mode, umask_cfg);
        } else {
            ssc_emit(SSC_INFO, "umask", "UMask", "UMask not set; file created with mode 0%o", mode);
        }
    }

    /* 22. PrivateUsers: /proc/self/uid_map */
    {
        int private_users = 0;
        FILE *f = fopen("/proc/self/uid_map", "r");
        if (f) {
            unsigned long long inside, outside, count;
            if (fscanf(f, "%llu %llu %llu", &inside, &outside, &count) == 3) {
                private_users = count > 0 && count < 0xFFFFFFFFULL;
            }
            fclose(f);
        }
        blocked_result("PrivateUsers", truthy, private_users, "private_users",
                        "uid_map shows a private (non-identity) mapping",
                        "uid_map shows the host's full identity mapping -- not namespaced");
    }

    /* 23. ProcSubset=pid */
    {
        struct stat st;
        int cpuinfo_visible = stat("/proc/cpuinfo", &st) == 0;
        blocked_result("ProcSubset", is_pid_subset, !cpuinfo_visible, "proc_subset",
                        "/proc/cpuinfo hidden (ProcSubset=pid)", "/proc/cpuinfo still visible despite ProcSubset=pid");
    }

    /* 24. RootDirectory=/RootImage= */
    {
        char *host_root = getenv("SSC_HOST_ROOT_DEV_INO");
        struct stat st;
        int chrooted = 0;
        if (host_root && stat("/", &st) == 0) {
            char self_root[64];
            snprintf(self_root, sizeof(self_root), "%llu:%llu",
                      (unsigned long long)st.st_dev, (unsigned long long)st.st_ino);
            chrooted = strcmp(self_root, host_root) != 0;
        }
        char *rootdir_cfg = cfg("RootDirectory");
        if (!rootdir_cfg) rootdir_cfg = cfg("RootImage");
        if (rootdir_cfg) {
            ssc_emit(chrooted ? SSC_PASS : SSC_FAIL, "root_directory", "RootDirectory",
                      chrooted ? "root filesystem differs from host (chrooted)"
                               : "root filesystem MATCHES host -- RootDirectory/RootImage not effective?");
        } else {
            ssc_emit(SSC_INFO, "root_directory", "RootDirectory",
                      "RootDirectory/RootImage not set; root %s host", chrooted ? "differs from" : "matches");
        }
    }

    /* 25. NoExecPaths=/ExecPaths=: copy ourselves somewhere not allowlisted
     * and confirm we can't execute the copy there. */
    {
        char *noexec_cfg = cfg("NoExecPaths");
        if (noexec_cfg) {
            char self_path[4096] = {0};
            ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
            char tmp_copy[] = "/tmp/sandbox-check-noexec-XXXXXX";
            int src_fd = -1, dst_fd = -1;
            if (n > 0) src_fd = open(self_path, O_RDONLY);
            if (src_fd >= 0) dst_fd = mkstemp(tmp_copy);
            if (src_fd >= 0 && dst_fd >= 0) {
                char buf[65536];
                ssize_t r;
                while ((r = read(src_fd, buf, sizeof(buf))) > 0) {
                    if (write(dst_fd, buf, (size_t)r) != r) break;
                }
                close(src_fd);
                close(dst_fd);
                chmod(tmp_copy, 0700);

                pid_t pid = fork();
                if (pid < 0) {
                    /* fork() itself failing (e.g. TasksMax= already at the
                     * limit) is NOT the same thing as "exec was blocked" --
                     * waitpid(-1, ...) below would otherwise reap some
                     * unrelated child (or, with none, decode a leftover
                     * status of 0 as a spurious "PASS"/exit-code-0 exec
                     * success), misreporting a resource-limit hiccup as
                     * either a false PASS or a false FAIL for NoExecPaths=. */
                    unlink(tmp_copy);
                    ssc_emit(SSC_WARN, "no_exec_paths", "NoExecPaths",
                              "fork() failed (%s); exec-restriction not tested", strerror(errno));
                } else if (pid == 0) {
                    /* child: redirect stdout/stderr away first -- if exec
                     * actually succeeds (the allowlist isn't enforced),
                     * we must not let the re-exec'd copy write anything
                     * into the parent probe's own report stream. Then
                     * exec into --ssc-noop (NOT --ssc-probe-internal:
                     * that would recurse into a full nested probe run,
                     * which would itself try this same exec test again). */
                    int devnull = open("/dev/null", O_WRONLY);
                    if (devnull >= 0) {
                        dup2(devnull, STDOUT_FILENO);
                        dup2(devnull, STDERR_FILENO);
                    }
                    execl(tmp_copy, tmp_copy, "--ssc-noop", (char *)NULL);
                    _exit(126); /* execl failed -- treat exactly like a blocked exec below */
                } else {
                    int status = 0;
                    waitpid(pid, &status, 0);
                    /* execl failing in the child due to EACCES/EPERM shows up
                     * as our _exit(126); a real exec success runs the child
                     * probe battery instead and exits 0. */
                    int exec_blocked = WIFEXITED(status) && WEXITSTATUS(status) == 126;
                    unlink(tmp_copy);
                    ssc_emit(exec_blocked ? SSC_PASS : SSC_FAIL, "no_exec_paths", "NoExecPaths",
                              exec_blocked ? "copy of interpreter outside ExecPaths= refused to execute"
                                           : "copy of interpreter outside ExecPaths= EXECUTED -- allowlist not enforced");
                }
            } else {
                if (src_fd >= 0) close(src_fd);
                ssc_emit(SSC_WARN, "no_exec_paths", "NoExecPaths", "could not set up the exec probe");
            }
        }
    }

    /* 26. OOMScoreAdjust */
    {
        char *oom_cfg = cfg("OOMScoreAdjust");
        if (oom_cfg) {
            FILE *f = fopen("/proc/self/oom_score_adj", "r");
            if (f) {
                long observed = 0;
                fscanf(f, "%ld", &observed);
                fclose(f);
                long expected = strtol(oom_cfg, NULL, 10);
                ssc_emit(observed == expected ? SSC_PASS : SSC_FAIL, "oom_score_adjust", "OOMScoreAdjust",
                          "oom_score_adj=%ld, expected %ld", observed, expected);
            } else {
                ssc_emit(SSC_WARN, "oom_score_adjust", "OOMScoreAdjust", "could not read /proc/self/oom_score_adj");
            }
        }
    }

    /* 27. MemoryMax=/MemoryHigh= */
    {
        static const struct { const char *directive; const char *cgfile; } mem_checks[] = {
            {"MemoryMax", "memory.max"}, {"MemoryHigh", "memory.high"},
        };
        for (size_t i = 0; i < sizeof(mem_checks) / sizeof(mem_checks[0]); i++) {
            char *cfg_val = cfg(mem_checks[i].directive);
            if (!cfg_val) continue;
            char *observed_raw = read_cgroup_file(mem_checks[i].cgfile);
            char check[64];
            snprintf(check, sizeof(check), "%s", mem_checks[i].directive);
            for (char *p = check; *p; p++) *p = (char)tolower((unsigned char)*p);
            if (!observed_raw) {
                ssc_emit(SSC_WARN, check, mem_checks[i].directive, "could not read cgroup %s", mem_checks[i].cgfile);
                continue;
            }
            int ok;
            long long expected_bytes = parse_systemd_bytes(cfg_val, &ok);
            if (strcmp(observed_raw, "max") == 0) {
                ssc_emit(ok ? SSC_FAIL : SSC_INFO, check, mem_checks[i].directive,
                          "%s=max (unlimited), expected %s", mem_checks[i].cgfile, cfg_val);
            } else if (!ok) {
                ssc_emit(SSC_INFO, check, mem_checks[i].directive,
                          "%s=%s; configured value '%s' not parsed for comparison", mem_checks[i].cgfile, observed_raw, cfg_val);
            } else {
                long long observed_bytes = strtoll(observed_raw, NULL, 10);
                ssc_emit(observed_bytes == expected_bytes ? SSC_PASS : SSC_FAIL, check, mem_checks[i].directive,
                          "%s=%lld bytes, expected %lld bytes (%s)", mem_checks[i].cgfile, observed_bytes, expected_bytes, cfg_val);
            }
            free(observed_raw);
        }
    }

    /* 28. TasksMax= */
    {
        char *tasks_cfg = cfg("TasksMax");
        if (tasks_cfg) {
            char *observed_raw = read_cgroup_file("pids.max");
            if (!observed_raw) {
                ssc_emit(SSC_WARN, "tasks_max", "TasksMax", "could not read cgroup pids.max");
            } else {
                int ok;
                long long expected = parse_systemd_bytes(tasks_cfg, &ok);
                if (strcmp(observed_raw, "max") == 0) {
                    ssc_emit(ok ? SSC_FAIL : SSC_INFO, "tasks_max", "TasksMax", "pids.max=max (unlimited), expected %s", tasks_cfg);
                } else if (!ok) {
                    ssc_emit(SSC_INFO, "tasks_max", "TasksMax",
                              "pids.max=%s; configured value '%s' not parsed for comparison", observed_raw, tasks_cfg);
                } else {
                    long long observed = strtoll(observed_raw, NULL, 10);
                    ssc_emit(observed == expected ? SSC_PASS : SSC_FAIL, "tasks_max", "TasksMax",
                              "pids.max=%lld, expected %lld (TasksMax=%s)", observed, expected, tasks_cfg);
                }
                free(observed_raw);
            }
        }
    }

    /* 29. LimitNOFILE= via getrlimit() -- simpler and more robust in C
     * than parsing /proc/self/limits text. */
    {
        char *nofile_cfg = cfg("LimitNOFILE");
        if (nofile_cfg) {
            struct rlimit rl;
            if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
                char expected_soft_buf[64];
                snprintf(expected_soft_buf, sizeof(expected_soft_buf), "%s", nofile_cfg);
                char *colon = strchr(expected_soft_buf, ':');
                if (colon) *colon = '\0';
                int match;
                if (strcmp(expected_soft_buf, "infinity") == 0) {
                    match = rl.rlim_cur == RLIM_INFINITY;
                } else {
                    match = (rlim_t)strtoull(expected_soft_buf, NULL, 10) == rl.rlim_cur;
                }
                if (rl.rlim_cur == RLIM_INFINITY) {
                    ssc_emit(match ? SSC_PASS : SSC_FAIL, "limit_nofile", "LimitNOFILE",
                              "soft RLIMIT_NOFILE=unlimited, expected %s (LimitNOFILE=%s)", expected_soft_buf, nofile_cfg);
                } else {
                    ssc_emit(match ? SSC_PASS : SSC_FAIL, "limit_nofile", "LimitNOFILE",
                              "soft RLIMIT_NOFILE=%llu, expected %s (LimitNOFILE=%s)",
                              (unsigned long long)rl.rlim_cur, expected_soft_buf, nofile_cfg);
                }
            } else {
                ssc_emit(SSC_WARN, "limit_nofile", "LimitNOFILE", "getrlimit(RLIMIT_NOFILE) failed");
            }
        }
    }

    /* 30. CPUWeight=/IOWeight= */
    {
        char *cpu_cfg = cfg("CPUWeight");
        if (cpu_cfg) {
            char *observed_raw = read_cgroup_file("cpu.weight");
            if (!observed_raw) {
                ssc_emit(SSC_WARN, "cpu_weight", "CPUWeight", "could not read cgroup cpu.weight (cpu controller not enabled?)");
            } else {
                long observed = strtol(observed_raw, NULL, 10);
                long expected = strtol(cpu_cfg, NULL, 10);
                ssc_emit(observed == expected ? SSC_PASS : SSC_FAIL, "cpu_weight", "CPUWeight",
                          "cpu.weight=%ld, expected %ld", observed, expected);
                free(observed_raw);
            }
        }
        char *io_cfg = cfg("IOWeight");
        if (io_cfg) {
            char *observed_raw = read_cgroup_file("io.weight");
            if (!observed_raw) {
                ssc_emit(SSC_WARN, "io_weight", "IOWeight", "could not read cgroup io.weight (io controller not enabled?)");
            } else {
                char default_word[64] = {0};
                long observed = -1;
                if (sscanf(observed_raw, "%63s %ld", default_word, &observed) == 2) {
                    long expected = strtol(io_cfg, NULL, 10);
                    ssc_emit(observed == expected ? SSC_PASS : SSC_FAIL, "io_weight", "IOWeight",
                              "io.weight default=%ld, expected %ld", observed, expected);
                } else {
                    ssc_emit(SSC_WARN, "io_weight", "IOWeight", "could not parse io.weight: '%s'", observed_raw);
                }
                free(observed_raw);
            }
        }
    }

    /* 31. Seccomp -- intentionally not exercised live */
    if (cfg("SystemCallFilter")) {
        ssc_emit(SSC_INFO, "syscall_filter", "SystemCallFilter", "not dynamically probed for safety; see systemd-analyze security");
    }
    if (cfg("SystemCallArchitectures")) {
        ssc_emit(SSC_INFO, "syscall_architectures", "SystemCallArchitectures", "not dynamically probed; see systemd-analyze security");
    }

    return 0;
}
