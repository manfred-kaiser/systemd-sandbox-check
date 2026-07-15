<h1 align="center">systemd-sandbox-check</h1>

<p align="center">
  <strong>Runtime verification for systemd sandboxing/hardening directives on
  a unit file.</strong>
</p>

<p align="center">
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/blob/main/LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/systemd-sandbox-check" alt="License"></a>
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/c-build.yml"><img src="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/c-build.yml/badge.svg" alt="Build status"></a>
</p>

---

`systemd-analyze security <unit>` checks which hardening directives are
*present* in a unit file. `systemd-sandbox-check` checks whether they are
actually *enforced*: it starts a transient unit with the same `[Service]`
properties, runs a battery of probes inside it, and reports directive by
directive whether each restriction holds and whether the application still
works under it.

## Quick Start

### 1. Build

Single statically linked binary, no runtime dependencies.

```sh
cd src
make
sudo cp systemd-sandbox-check /usr/local/bin/
```

Requires `gcc` and glibc's static-linking support (`glibc-devel-static` on
openSUSE/RHEL, `libc6-dev` on Debian/Ubuntu).

> **Install outside `/home`.**
> The orchestrator bind-mounts its own binary into the transient sandbox to
> re-exec itself there. If the binary lives under a directory a target
> unit's `ProtectHome=` hides, that bind mount fails
> (`status=203/EXEC`). `/usr/local/bin` is unaffected. The tool also checks
> this itself at startup and aborts with an explanation rather than letting
> `systemd-run` fail with an opaque error.

### 2. Run

```sh
sudo systemd-sandbox-check --unit /path/to/some.service
```

Requires root: creating a system-scope transient unit via `systemd-run`
requires privileges. Add `--dry-run` to print the `systemd-run` command
without running anything.

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

Exit code is non-zero if any check reports `FAIL`, so it can be used as a
CI gate.

### 3. Optional: `--exec-check` and `--socket-unit`

```sh
sudo systemd-sandbox-check --unit /path/to/some.service --exec-check
```

Starts the unit's real `ExecStart` command inside the transient sandbox and
polls `systemctl show` for `--exec-check-timeout` seconds (default: 5),
reporting whether it reached `active` or `failed`. Unlike the other
probes, this runs the actual application with its configured paths and
network bindings — if the same service is already running, expect
conflicts (e.g. a port already bound); stop it first for a clean result.
`ExecStart=` lines prefixed with `+`/`!`/`!!` (which alter or escape the
sandbox — see `systemd.service(5)`) are skipped with a warning rather than
run outside the sandbox.

```sh
sudo systemd-sandbox-check --unit /path/to/some.service --socket-unit /path/to/some.socket
```

Runs static checks against the matching `[Socket]` section
(`TriggerLimitIntervalSec=`/`TriggerLimitBurst=` presence, `Accept=`/
`MaxConnections=` combinations, `KeepAlive*=` consistency) alongside the
`[Service]` probe battery.

## What it checks

| Directive | Probe |
|---|---|
| `NoNewPrivileges` | reads the `NoNewPrivs` flag from `/proc/self/status` |
| `ProtectSystem` | tries to create a file under `/usr` |
| `ReadWritePaths` | positive control: confirms the path is still writable |
| `BindReadOnlyPaths` | confirms the bind-mounted path is readable but not writable |
| `BindPaths` | positive control: confirms the bind-mounted path is still writable |
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
| `PrivateUsers` | checks `/proc/self/uid_map` for a non-identity mapping |
| `ProcSubset` | tries to list `/proc/1` vs. only `/proc/self` |
| `RootDirectory` / `RootImage` | confirms the process's `/` differs from the host's |
| `NoExecPaths` / `ExecPaths` | copies the probe binary to a non-allowlisted path and confirms it refuses to execute |
| `OOMScoreAdjust` | reads `/proc/self/oom_score_adj` |
| `MemoryMax` / `MemoryHigh` | reads back the effective cgroup v2 `memory.max`/`memory.high` |
| `TasksMax` | reads back the effective cgroup v2 `pids.max` |
| `LimitNOFILE` | reads back the process's `RLIMIT_NOFILE` via `getrlimit()` |
| `CPUWeight` / `IOWeight` | reads back the effective cgroup v2 `cpu.weight`/`io.weight` |

Positive controls (`ReadWritePaths`, `BindPaths`, `AF_INET`) run alongside
the negative ones, so an over-restrictive configuration is reported the
same way a missing restriction is.

Two checks run statically, without starting a transient unit:

- The `"+"` path-prefix convention for `ReadWritePaths=`/`ReadOnlyPaths=`/
  `InaccessiblePaths=`/`ExecPaths=`/`NoExecPaths=` under `RootDirectory=`/
  `RootImage=` (see [systemd/systemd#39935](https://github.com/systemd/systemd/issues/39935)):
  a bare (non-`+`-prefixed) path under those directives resolves relative
  to the host root instead of the chroot when `RootDirectory=`/
  `RootImage=` is also set; this is flagged.
- `[Socket]` section checks, with `--socket-unit` (see above).

`SystemCallFilter`/`SystemCallArchitectures` (seccomp) are reported as
configured-but-not-probed, not exercised live — doing so would require
syscalls (reboot, mount, module load, ...) with real side effects if a
filter turns out not to be enforced. Cross-check them with
`systemd-analyze security <unit>`.

## Example: a restriction that looks enforced but isn't

`NoExecPaths=/tmp` looks like it makes `PrivateTmp=true`'s private `/tmp`
non-executable. Under one specific combination of directives, it silently
does not — and `systemd-analyze security` has no way to catch it, since it
only checks that `NoExecPaths=` is present, not what it actually covers.

[`examples/privatetmp-noexecpaths-bug.service`](examples/privatetmp-noexecpaths-bug.service)
reproduces it:

```sh
sudo systemd-sandbox-check --unit examples/privatetmp-noexecpaths-bug.service
# [FAIL] no_exec_paths (NoExecPaths): copy of interpreter outside ExecPaths= EXECUTED -- allowlist not enforced
```

Confirmed by testing, isolating each directive one at a time: the unit
needs `RestrictNamespaces=` set alongside `RootDirectory=` for this to
happen — `RootDirectory=` with a bare `NoExecPaths=/tmp` and no
`RestrictNamespaces=` correctly blocks execution. With both present, a bare
path in `NoExecPaths=`/`ExecPaths=`/etc. resolves against the host's root
instead of `RootDirectory=`, missing the chroot's own private `/tmp` mount
entirely. The fix is the same either way — prefix the path with `+`:
`NoExecPaths=+/tmp` (see `systemd.exec(5)`).

## Safety

Every probe in the default run is either a no-op or self-contained to the
transient sandboxed process, regardless of whether the restriction it
tests turns out to be enforced: no probe reboots, remounts, changes the
system clock, or loads a kernel module. Capability-gated actions of that
kind are checked by reading the process's capability bitmask instead of
performing them.

`--exec-check` is the exception: it runs the unit's actual `ExecStart`, so
it can have the same side effects the unit itself would have.

## How it works

One static binary has two modes, dispatched via an internal-only CLI flag:

- **Orchestrator** (default): parses the target unit file, starts a
  transient unit via `systemd-run` with the same `[Service]` properties,
  re-execs itself inside that transient unit to run the probe battery, and
  collects and prints the results.
- **Probe** (`--ssc-probe-internal`, not user-facing): runs the checks,
  reading its configuration from environment variables set by the
  orchestrator.

The probe process runs inside the transient unit, and therefore inherits
the target unit's own `NoExecPaths=`/`ExecPaths=` allowlist. A general
interpreter (e.g. `python3`) is not guaranteed to be executable there — for
example, a unit that only allows its own bundled interpreter to run would
block a system Python. Self-reexec avoids this dependency: the
orchestrator adds its own binary's path to the transient unit's
`ExecPaths=`/`BindReadOnlyPaths=`, so the probe process only depends on a
path the orchestrator controls.

## License

MIT, see [LICENSE](LICENSE).
