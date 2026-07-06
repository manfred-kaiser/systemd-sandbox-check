# systemd-sandbox-check

<p align="center">
  <a href="https://pypi.org/project/systemd-sandbox-check"><img src="https://img.shields.io/pypi/v/systemd-sandbox-check" alt="PyPI"></a>
  <a href="https://pypi.org/project/systemd-sandbox-check"><img src="https://img.shields.io/pypi/pyversions/systemd-sandbox-check" alt="Python versions"></a>
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/blob/main/LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/systemd-sandbox-check" alt="License"></a>
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/python-package.yml"><img src="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/python-package.yml/badge.svg" alt="Build status"></a>
</p>

<p align="center">
  <strong>Verify that systemd sandboxing/hardening directives on a unit
  actually take effect at runtime — not just on paper.</strong>
</p>

---

## Why

Individual hardening directives are enforced by systemd/the kernel — that
part can be trusted. The actual open question when you lock a unit down this
hard is: **does the application still work, or did you just make the
sandbox too restrictive for it?** A typo, a wrong path in `ReadWritePaths`,
or a directive that quietly needs something the app does at startup can
break the service in ways `systemd-analyze security` — which only checks
which directives are *present* — has no way to catch.

`systemd-sandbox-check` takes a unit file and starts a **transient unit with
the exact same `[Service]` hardening properties** to answer that question
two ways:

- A battery of small, safe probes reports, directive by directive, whether
  the restriction is actually wired up and whether things the app needs
  (a writable state directory, outbound sockets, ...) still work.
- `--exec-check` goes further and starts the unit's *real* `ExecStart`
  inside that identical sandbox, to directly confirm the application itself
  comes up and stays up under it — not just that the individual restrictions
  behave as expected in isolation.

## Installation

```
pip install systemd-sandbox-check
```

Or from a checkout (regular install, not editable):

```
pip install .
```

## Usage

```
sudo systemd-sandbox-check --unit /path/to/some.service
```

Requires root, because creating a system-scope transient unit via
`systemd-run` requires privileges. Add `--dry-run` to print the
`systemd-run` command that would be executed, without running anything.

Example output:

```
[PASS] protect_system_usr_rw            (ProtectSystem): /usr is not writable
[PASS] readwritepaths_rw                (ReadWritePaths): /var/lib/example writable as expected
[FAIL] protect_home                     (ProtectHome): /root IS accessible
[PASS] restrict_af_netlink              (RestrictAddressFamilies): AF_NETLINK blocked as expected
[PASS] restrict_af_inet_control         (RestrictAddressFamilies): AF_INET still works
[INFO] syscall_filter                   (SystemCallFilter): not dynamically probed for safety; see systemd-analyze security

Configured but not dynamically probed (static-only, see `systemd-analyze security`):
  - SystemCallArchitectures=native

Summary: 19 PASS, 1 FAIL, 0 WARN, 3 INFO
```

Exit code is non-zero if any check comes back `FAIL`, so it can be wired
into CI.

### `--exec-check`: does the application itself still come up?

```
sudo systemd-sandbox-check --unit /path/to/some.service --exec-check
```

This additionally starts the unit's real `ExecStart` command inside the
identical sandbox and watches it for `--exec-check-timeout` seconds
(default: 5) via `systemctl show`/`journalctl`, reporting whether it reached
a running state or failed — the direct answer to "does my application still
work under this hardening, or is it too restrictive."

**This is not a no-op** like the other probes — it runs the real
application binary with production-like paths and network bindings. If an
instance of the same service is already running, expect conflicts (e.g. the
port is already bound); stop the real service first if you want a clean
result. `ExecStart=` lines prefixed with `+`/`!`/`!!` (which escape or alter
the sandbox — see `systemd.service(5)`) are skipped with a warning instead
of silently running unsandboxed.

## What it checks

For each of these directives found in the unit's `[Service]` section, a
targeted probe runs inside the transient unit and reports `PASS` / `FAIL` /
`WARN` / `INFO`:

| Directive | Probe |
|---|---|
| `NoNewPrivileges` | reads the `NoNewPrivs` flag from `/proc/self/status` |
| `ProtectSystem` | tries to create a file under `/usr` |
| `ReadWritePaths` | positive control: confirms the path is still writable |
| `ProtectHome` | tries to list `/root` |
| `PrivateTmp` | checks `/tmp`'s mount source for a `systemd-private-*` path |
| `PrivateDevices` | checks `/dev/sda` is gone, `/dev/null` still works |
| `ProtectKernelTunables` | tries to open `/proc/sys/vm/swappiness` for writing |
| `ProtectKernelModules` | checks `CAP_SYS_MODULE` is absent from the capability bounding set |
| `ProtectKernelLogs` | tries to open `/dev/kmsg` |
| `ProtectControlGroups` | tries to create a file under `/sys/fs/cgroup` |
| `ProtectClock` | checks `CAP_SYS_TIME`/`CAP_WAKE_ALARM` are absent |
| `ProtectHostname` | compares the UTS namespace inode against the host's |
| `ProtectProc` | tries to list `/proc/1` |
| `RestrictNamespaces` | tries `unshare(CLONE_NEWNS)` |
| `RestrictRealtime` | tries to switch to `SCHED_FIFO` |
| `RestrictSUIDSGID` | tries to `chmod +s` a temp file |
| `RestrictAddressFamilies` | tries an `AF_NETLINK` socket; confirms `AF_INET` still works |
| `LockPersonality` | tries to change the process personality |
| `MemoryDenyWriteExecute` | tries an anonymous RWX `mmap` |
| `CapabilityBoundingSet` / `AmbientCapabilities` | decodes the capability bitmask; confirms a granted capability (e.g. binding a privileged port) still works |
| `UMask` | checks the mode of a freshly created file |

Positive controls are included where relevant (`ReadWritePaths`, `AF_INET`)
so the tool also flags over-restrictive configurations, not just missing
ones.

## Limitations

`SystemCallFilter` / `SystemCallArchitectures` (seccomp) are intentionally
**not** exercised live — doing so safely would require invoking syscalls
(reboot, mount, module load, ...) that risk real side effects if a filter
turns out not to be enforced. These are reported as configured-but-not-probed;
cross-check them with `systemd-analyze security <unit>` instead.

## Safety

Every probe in the default run is chosen to be a no-op (or self-contained to
the ephemeral sandboxed process) even if the restriction it's testing turns
out *not* to be enforced — no probe can reboot, remount, change the system
clock, or load a kernel module for real. Capability-gated actions like that
are checked indirectly by reading the process's capability bitmask instead
of exercising them.

`--exec-check` is the one deliberate exception: it's opt-in precisely
because it runs the real application, with real side effects. See the
`--exec-check` section above.

## License

MIT, see [LICENSE](LICENSE).
