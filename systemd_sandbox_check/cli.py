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
from importlib import resources
from pathlib import Path

# Directives that must NOT be forwarded to the transient probe unit.
SKIP_DIRECTIVES = {
    "ExecStart", "Type", "Restart", "RestartSec",
    "StandardOutput", "StandardError", "SyslogIdentifier",
    "StateDirectory", "StateDirectoryMode",
}

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
                         help="Print the systemd-run command that would be executed and exit")
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
        return

    if os.geteuid() != 0:
        sys.exit("error: must run as root (systemd-run needs privileges for a system-scope transient unit)")

    for tool in ("systemd-run", "python3"):
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
