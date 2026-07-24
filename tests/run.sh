#!/bin/sh
# Black-box test suite: runs the built binary against fixture unit files and
# checks its --dry-run/--version output (never runs a real transient unit --
# that needs root + systemd, out of scope for CI). Extends the two smoke
# checks that used to live inline in the GitHub workflows.
set -eu

cd "$(dirname "$0")/.."
BIN=src/systemd-sandbox-check
UNITS=tests/units
SOCKETS=tests/sockets

fail_count=0

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s -- %s\n' "$1" "$2"; fail_count=$((fail_count + 1)); }

# assert_contains NAME NEEDLE -- COMMAND...
# Runs COMMAND, asserts exit code 0 and that its combined output contains NEEDLE.
assert_contains() {
    name=$1; needle=$2; shift 2
    if [ "$1" = "--" ]; then shift; fi
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$name" "expected exit 0, got $rc (output: $out)"
    elif ! printf '%s' "$out" | grep -qF -- "$needle"; then
        fail "$name" "output did not contain '$needle' (output: $out)"
    else
        pass "$name"
    fi
}

# assert_not_contains NAME NEEDLE -- COMMAND...
assert_not_contains() {
    name=$1; needle=$2; shift 2
    if [ "$1" = "--" ]; then shift; fi
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$name" "expected exit 0, got $rc (output: $out)"
    elif printf '%s' "$out" | grep -qF -- "$needle"; then
        fail "$name" "output unexpectedly contained '$needle' (output: $out)"
    else
        pass "$name"
    fi
}

# assert_fails NAME -- COMMAND...
# Asserts COMMAND exits non-zero.
assert_fails() {
    name=$1; shift
    if [ "$1" = "--" ]; then shift; fi
    if "$@" >/tmp/ssc-test-out.$$ 2>&1; then
        fail "$name" "expected non-zero exit, got 0 (output: $(cat /tmp/ssc-test-out.$$))"
    else
        pass "$name"
    fi
    rm -f /tmp/ssc-test-out.$$
}

make -C src >/dev/null

# --- CLI basics ---

assert_contains "version_flag" "systemd-sandbox-check" -- \
    "$BIN" --version

assert_fails "missing_unit_arg" -- \
    "$BIN"

assert_fails "unit_file_not_found" -- \
    "$BIN" --unit /nonexistent.service --dry-run

# --- unit-file parsing / systemd-run argv building ---

assert_contains "basic_dry_run_invokes_systemd_run" "systemd-run" -- \
    "$BIN" --unit "$UNITS/basic.service" --dry-run

assert_contains "basic_dry_run_forwards_property" "--property=NoNewPrivileges=true" -- \
    "$BIN" --unit "$UNITS/basic.service" --dry-run

assert_not_contains "basic_dry_run_excludes_execstart" "--property=ExecStart=" -- \
    "$BIN" --unit "$UNITS/basic.service" --dry-run

assert_contains "repeated_directives_forwarded_as_separate_properties" "--property=ExecPaths=/a" -- \
    "$BIN" --unit "$UNITS/repeated-execpaths.service" --dry-run

assert_contains "repeated_directives_forwarded_as_separate_properties_2" "--property=ExecPaths=/b" -- \
    "$BIN" --unit "$UNITS/repeated-execpaths.service" --dry-run

assert_contains "repeated_directives_merged_for_probe_env" "SSC_CFG_ExecPaths=/a /b" -- \
    "$BIN" --unit "$UNITS/repeated-execpaths.service" --dry-run

# --- "+"-prefix lint (RootDirectory=/RootImage=) ---

assert_contains "plus_prefix_bug_reproduction_warns" "has no '+' prefix" -- \
    "$BIN" --unit examples/privatetmp-noexecpaths-bug.service --dry-run

assert_contains "plus_prefix_info_for_non_fresh_mount_path" "Fine if /etc/example is bind-mounted" -- \
    "$BIN" --unit "$UNITS/plus-prefix-info.service" --dry-run

assert_not_contains "plus_prefix_pass_silent_when_already_prefixed" "Static lint: RootDirectory=/RootImage=" -- \
    "$BIN" --unit "$UNITS/plus-prefix-pass.service" --dry-run

# --- [Socket] static lint ---

assert_contains "socket_lint_maxconnections_without_accept" "only applies with Accept=yes" -- \
    "$BIN" --unit "$UNITS/basic.service" --dry-run --socket-unit "$SOCKETS/lint-maxconn.socket"

assert_contains "socket_lint_triggerlimit_zero_warns" "disables activation rate limiting" -- \
    "$BIN" --unit "$UNITS/basic.service" --dry-run --socket-unit "$SOCKETS/lint-triggerlimit-zero.socket"

echo
if [ "$fail_count" -eq 0 ]; then
    echo "All tests passed."
    exit 0
else
    echo "$fail_count test(s) failed."
    exit 1
fi
