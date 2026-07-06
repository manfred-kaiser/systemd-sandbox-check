# systemd-sandbox-check

<p align="center">
  <a href="https://pypi.org/project/systemd-sandbox-check"><img src="https://img.shields.io/pypi/v/systemd-sandbox-check" alt="PyPI"></a>
  <a href="https://pypi.org/project/systemd-sandbox-check"><img src="https://img.shields.io/pypi/pyversions/systemd-sandbox-check" alt="Python versions"></a>
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/blob/main/LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/systemd-sandbox-check" alt="License"></a>
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/python-package.yml"><img src="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/python-package.yml/badge.svg" alt="Build status"></a>
</p>

Verifies that systemd sandboxing/hardening directives on a unit *actually*
take effect at runtime, instead of only looking good on paper.

`systemd-analyze security <unit>` gives you a static score based on which
directives are present in the unit file. It does not tell you whether, say,
`ProtectSystem=strict` really makes `/usr` read-only in your kernel/systemd
version, whether `RestrictAddressFamilies` really blocks the socket families
you excluded, or whether a `ReadWritePaths` entry is still writable once
every other restriction is layered on top.

This tool takes a unit file, starts a **transient unit with the exact same
`[Service]` hardening properties**, and runs a battery of small, safe probes
inside it — then reports, directive by directive, whether the restriction is
actually enforced and whether the things that should still work still do.

## Usage

```
sudo systemd-sandbox-check --unit /path/to/some.service
```

Add `--dry-run` to print the `systemd-run` command that would be executed,
without running anything.

Requires root, because creating a system-scope transient unit via
`systemd-run` requires privileges.

## What it checks

For each hardening directive found in the unit's `[Service]` section (e.g.
`ProtectSystem`, `ProtectHome`, `PrivateDevices`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`,
`ProtectClock`, `ProtectHostname`, `ProtectProc`, `RestrictNamespaces`,
`RestrictRealtime`, `RestrictSUIDSGID`, `RestrictAddressFamilies`,
`LockPersonality`, `MemoryDenyWriteExecute`, `CapabilityBoundingSet`,
`AmbientCapabilities`, `UMask`, `NoNewPrivileges`) it runs a targeted probe
and reports `PASS` / `FAIL` / `WARN` / `INFO`.

Positive controls are included where relevant (e.g. `ReadWritePaths` targets
must stay writable, `AF_INET` sockets must keep working) so the tool also
flags over-restrictive configurations, not just missing ones.

`SystemCallFilter` / `SystemCallArchitectures` (seccomp) are intentionally
**not** exercised live — doing so safely would require invoking syscalls
(reboot, mount, module load, ...) that risk real side effects if a filter
turns out not to be enforced. These are reported as configured-but-not-probed;
cross-check them with `systemd-analyze security <unit>` instead.

## Safety

Every probe is chosen to be a no-op (or self-contained to the ephemeral
sandboxed process) even if the restriction it's testing turns out *not* to
be enforced — no probe can reboot, remount, change the system clock, or load
a kernel module for real. Capability-gated actions like that are checked
indirectly by reading the process's capability bitmask instead of exercising
them.

## Installation

```
pip install systemd-sandbox-check
```

Or from a checkout:

```
pip install .
```

(Regular install, not editable — this is a small CLI tool, not a library
under active local development.)
