# systemd-sandbox-check

<p align="center">
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/blob/main/LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/systemd-sandbox-check" alt="License"></a>
  <a href="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/c-build.yml"><img src="https://github.com/manfred-kaiser/systemd-sandbox-check/actions/workflows/c-build.yml/badge.svg" alt="Build status"></a>
</p>

<p align="center">
  <strong>Runtime verification for systemd sandboxing/hardening directives on
  a unit file.</strong>
</p>

---

## Example

A unit with `PrivateTmp=true`, `RootDirectory=/some/chroot`, and
`NoExecPaths=/tmp` looks like it makes `/tmp` non-executable inside the
chroot. It does not: `NoExecPaths=` (like `ReadWritePaths=`,
`ReadOnlyPaths=`, `InaccessiblePaths=`, `ExecPaths=`) resolves a bare path
against the host's root, not against `RootDirectory=`, when both are set
([systemd/systemd#39935](https://github.com/systemd/systemd/issues/39935)).
The chroot's own `/tmp` — where `PrivateTmp=` actually mounts the private
tmpfs — is left executable. The fix is to prefix the path with `+`:
`NoExecPaths=+/tmp`.

`systemd-analyze security <unit>` reports `NoExecPaths=` as present and
scores the unit accordingly; it has no way to detect that the restriction
does not apply to the path it is meant to cover. This gap is what
`systemd-sandbox-check` was written for: it starts a transient unit with
the same properties and tests directly whether `/tmp` is actually
non-executable, instead of only checking that the directive is set.

## What it does

`systemd-analyze security <unit>` checks which hardening directives are
*present* in a unit file. It does not check whether they are actually
enforced at runtime, or whether the application still works under them.

`systemd-sandbox-check` takes a unit file, starts a transient unit with the
same `[Service]` properties via `systemd-run`, and runs a battery of probes
inside it. Each probe targets one directive and reports whether the
restriction is observed to be in effect, and — where applicable — whether
a corresponding positive control (a path the unit is supposed to still be
able to write to, a capability it is supposed to retain) still works.

`--exec-check` extends this by running the unit's actual `ExecStart`
command inside the same transient sandbox and reporting via
`systemctl`/`journalctl` whether it reaches a running state.

## Installation

Single statically linked binary, no runtime dependencies.

```
cd src
make
sudo cp systemd-sandbox-check /usr/local/bin/
```

Requires `gcc` and glibc's static-linking support (`glibc-devel-static` on
openSUSE/RHEL, `libc6-dev` on Debian/Ubuntu).

Install it outside any directory covered by a target unit's `ProtectHome=`
(e.g. not under `/home`). The orchestrator bind-mounts its own binary path
into the transient sandbox to re-exec itself there; if `ProtectHome=` also
hides that path, the bind mount fails and `systemd-run` exits with
`status=203/EXEC`. `/usr/local/bin` is unaffected by `ProtectHome=`.

The tool checks this condition itself at startup: if it is running from
under `/home` and the target unit sets `ProtectHome=true`/`read-only`/
`tmpfs`, it exits with an error before invoking `systemd-run`.

## Usage

```
sudo systemd-sandbox-check --unit /path/to/some.service
```

Requires root: creating a system-scope transient unit via `systemd-run`
requires privileges. `--dry-run` prints the `systemd-run` command that
would be executed, without running anything.

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

Exit code is non-zero if any check reports `FAIL`, so it can be used as a
CI gate.

### `--exec-check`

```
sudo systemd-sandbox-check --unit /path/to/some.service --exec-check
```

Starts the unit's `ExecStart` command inside the transient sandbox and
polls `systemctl show` for `--exec-check-timeout` seconds (default: 5),
reporting whether the unit reached `active` or `failed`.

Unlike the other probes, this runs the actual application binary with its
configured paths and network bindings, not a self-contained no-op. If an
instance of the same service is already running, this can conflict with it
(e.g. a port already bound); stop the real service first for a clean
result. `ExecStart=` lines prefixed with `+`/`!`/`!!` (which alter or
escape the sandbox — see `systemd.service(5)`) are skipped with a warning
rather than run outside the sandbox.

### `--socket-unit`

```
sudo systemd-sandbox-check --unit /path/to/some.service --socket-unit /path/to/some.socket
```

Runs static checks against the `[Socket]` section
(`TriggerLimitIntervalSec=`/`TriggerLimitBurst=` presence, `Accept=`/
`MaxConnections=` combinations, `KeepAlive*=` consistency) in addition to
the `[Service]` probe battery.

## What it checks

For each of these directives found in the unit's `[Service]` section, a
probe runs inside the transient unit and reports `PASS` / `FAIL` / `WARN` /
`INFO`:

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

Positive controls (`ReadWritePaths`, `BindPaths`, `AF_INET`) are included
alongside the negative ones, so an over-restrictive configuration is
reported the same way a missing restriction is.

Two static checks run without starting a transient unit:

- The `"+"` path-prefix convention for `ReadWritePaths=`/`ReadOnlyPaths=`/
  `InaccessiblePaths=`/`ExecPaths=`/`NoExecPaths=` under `RootDirectory=`/
  `RootImage=` (see [systemd/systemd#39935](https://github.com/systemd/systemd/issues/39935)):
  a bare (non-`+`-prefixed) path under those directives resolves relative
  to the host root instead of the chroot when `RootDirectory=`/
  `RootImage=` is also set; this is flagged.
- `[Socket]` section checks (with `--socket-unit`), listed under
  `--socket-unit` above.

## Limitations

`SystemCallFilter` / `SystemCallArchitectures` (seccomp) are not exercised
live. Doing so would require invoking syscalls (reboot, mount, module load,
...) that have real side effects if the filter turns out not to be
enforced. These are reported as configured-but-not-probed; cross-check
them with `systemd-analyze security <unit>`.

## Safety

Every probe in the default run is either a no-op or self-contained to the
transient sandboxed process, regardless of whether the restriction it
tests turns out to be enforced: no probe reboots, remounts, changes the
system clock, or loads a kernel module. Capability-gated actions of that
kind are checked by reading the process's capability bitmask instead of
performing them.

`--exec-check` is the exception: it runs the unit's actual `ExecStart`, so
it can have the same side effects the unit itself would have (see
`--exec-check` above).

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
