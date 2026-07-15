/* systemd-sandbox-check (C port) -- shared declarations.
 *
 * Single static binary, two modes dispatched in main():
 *   - orchestrator mode (default): parse a unit file, start a transient
 *     systemd-run unit with the exact same [Service] properties, re-exec
 *     *this same binary* inside it (see cli.c), collect + print results.
 *   - probe mode (--ssc-probe-internal, never invoked by a user directly):
 *     runs the actual check battery, reading its config from SSC_CFG_*
 *     environment variables set by the orchestrator (see probe.c).
 *
 * Why self-reexec instead of shelling out to python3: the probe runs
 * *inside* the transient unit, which inherits the target unit's own
 * NoExecPaths=/ExecPaths= allowlist. A system python3 (or any interpreter
 * not already on that allowlist) may simply not be executable there (this
 * is exactly what happened testing this against minicms.service, which
 * only allows its own bundled interpreter to run). A single self-contained
 * static binary sidesteps the whole problem: the orchestrator adds its own
 * path to ExecPaths= for the transient run (see build_systemd_run_argv),
 * so it never depends on anything the target unit happens to allow.
 */
#ifndef SSC_H
#define SSC_H

#define SSC_VERSION "0.1.0"

#include <stddef.h>

/* --- Ordered (key, value) pair list, preserving repeated directives ---
 * as separate entries (systemd.service(5): repeated ExecPaths=/
 * BindReadOnlyPaths=/etc. accumulate; repeated SystemCallFilter= each keep
 * their own leading '~' polarity -- collapsing to one merged string breaks
 * that, confirmed by hand against the Python version). */
typedef struct {
    char *key;
    char *value;
} kv_pair_t;

typedef struct {
    kv_pair_t *items;
    size_t count;
    size_t capacity;
} kv_list_t;

void kv_list_init(kv_list_t *list);
void kv_list_free(kv_list_t *list);
void kv_list_append(kv_list_t *list, const char *key, const char *value);

/* Parse one INI-style section (case-insensitive name) of a systemd unit
 * file into an ordered kv_list_t. section is e.g. "service" or "socket". */
int parse_unit_section(const char *path, const char *section, kv_list_t *out);

/* Merge all values for `key` (repeated occurrences space-joined, matching
 * systemd's own accumulation for multi-value settings), or NULL if the
 * key never appears. Caller must free() the result. */
char *kv_merge(const kv_list_t *list, const char *key);

/* True if `key` appears at least once. */
int kv_has(const kv_list_t *list, const char *key);

/* Entry points for the two modes (see cli.c / probe.c). */
int run_cli(int argc, char **argv);
int run_probe(void);

/* Shared status tags for probe output lines: "STATUS\tcheck\tdirective\tdetail\n" */
#define SSC_PASS "PASS"
#define SSC_FAIL "FAIL"
#define SSC_WARN "WARN"
#define SSC_INFO "INFO"

void ssc_emit(const char *status, const char *check, const char *directive, const char *detail_fmt, ...);

#endif
