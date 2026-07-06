"""Command line interface: dynamic sandbox-hardening check for a systemd unit.

Starts a transient systemd unit with the *exact* [Service] hardening
properties found in the target unit file and runs a battery of safe,
self-contained probes inside it to verify which restrictions actually take
effect (and that legitimately allowed paths, like ReadWritePaths, still
work). Complements the static `systemd-analyze security <unit>` score with a
live, on-host check.

Requires root (systemd-run needs privileges to create system-scope transient
units). Probes are chosen to never affect host state even if a restriction
turns out *not* to be enforced (no reboot/mount/settimeofday/module-load
syscalls -- those are only checked indirectly via capability bitmasks).
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from importlib import resources
from pathlib import Path

# Directives that must NOT be forwarded to the transient probe unit.
SKIP_DIRECTIVES = {
    "ExecStart", "Type", "Restart", "RestartSec",
    "StandardOutput", "StandardError", "SyslogIdentifier",
    "StateDirectory", "StateDirectoryMode",
}

# Directives that must NOT be forwarded when running the real ExecStart
# (--exec-check): everything else, including StateDirectory/Type/Standard*,
# is forwarded so the run mirrors production as closely as possible.
# Restart* is dropped and hardcoded to Restart=no below so a crashing app
# gives one clean signal instead of respawn-looping.
EXEC_SKIP_DIRECTIVES = {"ExecStart", "Restart", "RestartSec"}

# ExecStart prefix characters (systemd.service(5)) that change privileges or
# error handling. '+'/'!'/'!!' escape or alter the sandbox itself, so running
# under them would not actually exercise the hardening we just configured.
UNSAFE_EXEC_PREFIXES = set("+!")

# Directives actively exercised by a dedicated probe in probe.py. Anything
# else that got forwarded to the sandbox is only reported as "not
# dynamically checked" so coverage gaps stay visible instead of silently
# assumed fine.
PROBED_DIRECTIVES = {
    "NoNewPrivileges", "ProtectSystem", "ReadWritePaths", "ProtectHome",
    "PrivateTmp", "PrivateDevices", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
    "ProtectClock", "ProtectHostname", "ProtectProc", "RestrictNamespaces",
    "RestrictRealtime", "RestrictSUIDSGID", "RestrictAddressFamilies",
    "LockPersonality", "MemoryDenyWriteExecute", "CapabilityBoundingSet",
    "AmbientCapabilities", "UMask",
}


def parse_unit(path: Path) -> dict[str, str]:
    directives: dict[str, str] = {}
    in_service = False
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_service = line[1:-1].strip().lower() == "service"
            continue
        if not in_service or "=" not in line:
            continue
        key, _, value = line.partition("=")
        directives[key.strip()] = value.strip()
    return directives


def build_systemd_run_cmd(unit_name: str, directives: dict[str, str], host_env: dict[str, str]) -> list[str]:
    cmd = [
        "systemd-run", "--quiet", "--pipe", "--wait", "--collect",
        f"--unit={unit_name}",
    ]
    for key, value in directives.items():
        if key in SKIP_DIRECTIVES:
            continue
        cmd.append(f"--property={key}={value}")
    for env_key, env_val in host_env.items():
        cmd.append(f"--setenv={env_key}={env_val}")
    cmd += ["/usr/bin/python3", "-"]
    return cmd


def parse_exec_start(value: str) -> tuple[str, list[str]]:
    """Split an ExecStart= value into its prefix characters and argv."""
    i = 0
    while i < len(value) and value[i] in "-+!:@":
        i += 1
    return value[:i], shlex.split(value[i:])


def build_exec_check_cmd(unit_name: str, directives: dict[str, str], argv: list[str]) -> list[str]:
    cmd = ["systemd-run", "--quiet", f"--unit={unit_name}"]
    for key, value in directives.items():
        if key in EXEC_SKIP_DIRECTIVES:
            continue
        cmd.append(f"--property={key}={value}")
    cmd.append("--property=Restart=no")
    cmd += argv
    return cmd


def poll_unit_state(unit_name: str, timeout: float) -> dict[str, str]:
    fields = ["ActiveState", "SubState", "Result"]
    deadline = time.monotonic() + timeout
    state: dict[str, str] = {}
    while True:
        proc = subprocess.run(
            ["systemctl", "show", unit_name, *(f"--property={f}" for f in fields)],
            capture_output=True, text=True, timeout=5,
        )
        state = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
        if state.get("ActiveState") == "failed" or time.monotonic() >= deadline:
            return state
        time.sleep(0.3)


def run_exec_check(unit_name: str, directives: dict[str, str], timeout: float) -> tuple[str, str]:
    """Start the unit's real ExecStart inside the identical sandbox and report
    whether it comes up and stays up, instead of only checking that
    individual restrictions are enforced in isolation."""
    exec_start = directives.get("ExecStart")
    if not exec_start:
        return "WARN", "no ExecStart found in unit, skipped"

    prefixes, argv = parse_exec_start(exec_start)
    if UNSAFE_EXEC_PREFIXES & set(prefixes):
        return "WARN", (
            f"ExecStart uses prefix(es) {prefixes!r} (e.g. '+' escapes the sandbox) "
            "-- skipped, running it would not test the real hardening"
        )
    if not argv:
        return "WARN", "ExecStart could not be parsed into a command, skipped"

    start = subprocess.run(
        build_exec_check_cmd(unit_name, directives, argv),
        capture_output=True, text=True, timeout=15,
    )
    if start.returncode != 0:
        return "FAIL", f"systemd-run failed to start the unit: {start.stderr.strip()}"

    try:
        state = poll_unit_state(unit_name, timeout)
        active, sub, result = state.get("ActiveState", "?"), state.get("SubState", "?"), state.get("Result", "?")
        logs = subprocess.run(
            ["journalctl", "-u", unit_name, "--no-pager", "-n", "15"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if active == "failed":
            return "FAIL", f"unit failed (Result={result}); last journal lines:\n{logs}"
        if active == "active":
            return "PASS", f"still running after {timeout:g}s (ActiveState={active}/{sub})"
        if active == "activating":
            return "WARN", f"still 'activating' after {timeout:g}s -- a Type=notify readiness signal may never have been sent"
        return "WARN", f"unexpected state ActiveState={active}/{sub} Result={result}; last journal lines:\n{logs}"
    finally:
        subprocess.run(["systemctl", "stop", unit_name], capture_output=True, text=True, timeout=10)
        subprocess.run(["systemctl", "reset-failed", unit_name], capture_output=True, text=True, timeout=10)


def colorize(status: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    codes = {"PASS": "32", "FAIL": "31", "WARN": "33", "INFO": "36"}
    return f"\033[{codes.get(status, '0')}m{text}\033[0m"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--unit", type=Path, required=True,
                         help="Path to the systemd unit file to test")
    parser.add_argument("--dry-run", action="store_true",
                         help="Print the systemd-run command(s) that would be executed and exit")
    parser.add_argument("--exec-check", action="store_true",
                         help="Additionally start the unit's real ExecStart inside the identical sandbox and "
                              "check whether it comes up and stays up. Has real side effects (binds real "
                              "ports/paths, may conflict with an already-running instance of the same service) "
                              "-- unlike the other probes, this is not a no-op.")
    parser.add_argument("--exec-check-timeout", type=float, default=5.0,
                         help="Seconds to observe the real ExecStart process before concluding pass/fail (default: 5)")
    args = parser.parse_args()

    if not args.unit.is_file():
        sys.exit(f"error: unit file not found: {args.unit}")

    probe_src = resources.files("systemd_sandbox_check").joinpath("probe.py").read_text()

    directives = parse_unit(args.unit)
    host_env = {"HARDEN_CONFIG": json.dumps(directives)}
    try:
        host_env["HOST_NS_UTS_INO"] = str(os.stat("/proc/self/ns/uts").st_ino)
    except OSError:
        pass

    unit_name = f"sandbox-check-{os.getpid()}"
    cmd = build_systemd_run_cmd(unit_name, directives, host_env)

    if args.dry_run:
        print(shlex.join(cmd))
        if args.exec_check:
            _, argv = parse_exec_start(directives.get("ExecStart", ""))
            if argv:
                print(shlex.join(build_exec_check_cmd(f"{unit_name}-exec", directives, argv)))
        return

    if os.geteuid() != 0:
        sys.exit("error: must run as root (systemd-run needs privileges for a system-scope transient unit)")

    required_tools = ["systemd-run", "python3"]
    if args.exec_check:
        required_tools += ["systemctl", "journalctl"]
    for tool in required_tools:
        if shutil.which(tool) is None:
            sys.exit(f"error: required tool not found in PATH: {tool}")

    proc = subprocess.run(cmd, input=probe_src, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0 and not proc.stdout:
        sys.exit(f"error: transient unit failed to run:\n{proc.stderr}")

    use_color = sys.stdout.isatty()
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}

    for line in proc.stdout.splitlines():
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue
        status = result["status"]
        counts[status] = counts.get(status, 0) + 1
        tag = colorize(status, f"[{status:4}]", use_color)
        print(f"{tag} {result['check']:32} ({result['directive']}): {result['detail']}")

    if args.exec_check:
        print(
            "WARNING: --exec-check starts the unit's real ExecStart with production-like paths/network "
            "bindings; if the real service is already running this may conflict (e.g. port already in use).",
            file=sys.stderr,
        )
        status, detail = run_exec_check(f"{unit_name}-exec", directives, args.exec_check_timeout)
        counts[status] = counts.get(status, 0) + 1
        tag = colorize(status, f"[{status:4}]", use_color)
        print(f"{tag} {'exec_check':32} (ExecStart): {detail}")

    not_dynamically_checked = set(directives) - PROBED_DIRECTIVES - SKIP_DIRECTIVES
    if not_dynamically_checked:
        print()
        print("Configured but not dynamically probed (static-only, see `systemd-analyze security`):")
        for name in sorted(not_dynamically_checked):
            print(f"  - {name}={directives[name]}")

    print()
    print(f"Summary: {counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['WARN']} WARN, {counts['INFO']} INFO")
    if proc.stderr.strip():
        print(f"(systemd-run stderr: {proc.stderr.strip()})", file=sys.stderr)

    sys.exit(1 if counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
