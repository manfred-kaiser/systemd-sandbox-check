# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tests/run.sh`: a black-box test suite covering CLI basics, unit-file
  parsing/`systemd-run` argv construction, the "+"-prefix lint, the
  `[Socket]` static lint and the new `ProtectProc=`/`CAP_SYS_PTRACE` lint
  (17 checks). Wired into both `c-build.yml` and `release.yml`, replacing
  the smoke checks that used to live inline in the workflow YAML.
- A new static lint: `ProtectProc=invisible`/`noaccess`/`ptraceable` is a
  no-op for any process that still holds `CAP_SYS_PTRACE` in its effective
  `CapabilityBoundingSet=` -- documented in systemd.exec(5), confirmed by
  hand (see the `protect_proc` fix above). Unlike the dynamic `protect_proc`
  probe, this fires purely from parsing the unit file (even under
  `--dry-run`, no root/systemd-run needed), so it catches the gap before a
  single live run is ever done.

### Fixed

- `protect_home`: replaced an `opendir("/root")`-based accessibility check
  with a check for a dedicated mount at `/root` in `/proc/self/mountinfo`.
  The old check had no discriminating power for any root-run unit that
  doesn't also strip `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH` from
  `CapabilityBoundingSet=`: root's default capabilities bypass the
  substitute directory's `0000` permissions regardless of whether
  `ProtectHome=` is set at all, so `opendir()` succeeded identically either
  way (confirmed by hand).
- `private_devices`: replaced a hardcoded `/dev/sda` existence check with a
  comparison of `/dev`'s filesystem type (`tmpfs` when private, `devtmpfs`
  on the host) via mountinfo. The old check silently reported `PrivateDevices=`
  as enforced on any host without a SATA/SCSI disk at that exact path --
  including this project's own NVMe-only dev machine -- regardless of
  whether the directive was even set.
- `protect_control_groups`: replaced an `open(O_CREAT)`-under-`/sys/fs/cgroup`
  check with a read-only mount-option check via mountinfo. cgroupfs doesn't
  support creating arbitrary regular files at all, with or without
  `ProtectControlGroups=`, at either the cgroup root or the unit's own
  delegated subtree (confirmed by hand) -- the old check had no
  discriminating power.
- `protect_proc`: detail message now notes that a FAIL despite
  `ProtectProc=` being set usually means `CapabilityBoundingSet=` still
  retains `CAP_SYS_PTRACE`, which systemd.exec(5) documents as bypassing
  this restriction entirely. Not a probe bug -- confirmed by hand this is
  real, documented systemd behavior -- but worth surfacing so it isn't
  mistaken for one.

## [0.2.0] - 2026-07-15

### Changed

- **Rewritten from Python to C, and the Python implementation removed.**
  The tool now ships as a single statically linked binary that re-execs
  itself inside the transient sandbox to run its probes, instead of
  shelling out to `python3` -- which may not be executable at all under a
  unit's own `NoExecPaths=`/`ExecPaths=` allowlist. See the README's "How
  it works" section. Functional parity with the last Python version was
  verified check-by-check (39 checks, identical PASS/FAIL/WARN/INFO output)
  before the Python source was deleted.
- `pip install systemd-sandbox-check` / `pyproject.toml` / the PyPI publish
  workflow no longer apply; build from source with `make -C src` instead.

### Added

- `--exec-check` (with `--exec-check-timeout`, default 5s): starts the
  unit's real `ExecStart` inside the identical sandbox and reports via
  `systemctl`/`journalctl` whether the application itself comes up and
  stays up, instead of only checking individual restrictions in isolation.
  Not a no-op like the other probes -- has real side effects (production
  paths/network bindings) and is therefore opt-in.
- `--socket-unit` for static `[Socket]` section lint checks alongside the
  `[Service]` probe battery.
- Probes for `PrivateUsers`, `ProcSubset`, `RootDirectory`/`RootImage`,
  `NoExecPaths`/`ExecPaths`, `BindPaths`/`BindReadOnlyPaths`,
  `OOMScoreAdjust`, `MemoryMax`/`MemoryHigh`, `TasksMax`, `LimitNOFILE`,
  `CPUWeight`/`IOWeight`.
- A static lint for the `"+"` path-prefix convention required by
  `ReadWritePaths=`/`ReadOnlyPaths=`/`InaccessiblePaths=`/`ExecPaths=`/
  `NoExecPaths=` under `RootDirectory=`/`RootImage=`
  ([systemd/systemd#39935](https://github.com/systemd/systemd/issues/39935)).
- A startup guard: if the binary is running from under `/home` and the
  target unit sets `ProtectHome=true`/`read-only`/`tmpfs`, abort immediately
  with an explanatory error instead of letting `systemd-run` fail later with
  an opaque `status=203/EXEC`.

## [0.1.0] - 2026-07-06

### Added

- Initial release: `systemd-sandbox-check --unit <file>` starts a transient
  systemd unit with the exact `[Service]` hardening properties of the target
  unit file and runs a safe probe battery inside it (NoNewPrivileges,
  ProtectSystem, ProtectHome, PrivateTmp, PrivateDevices,
  ProtectKernelTunables, ProtectKernelModules, ProtectKernelLogs,
  ProtectControlGroups, ProtectClock, ProtectHostname, ProtectProc,
  RestrictNamespaces, RestrictRealtime, RestrictSUIDSGID,
  RestrictAddressFamilies, LockPersonality, MemoryDenyWriteExecute,
  CapabilityBoundingSet, AmbientCapabilities, UMask)
- `--dry-run` to print the `systemd-run` invocation without executing it

[Unreleased]: https://github.com/manfred-kaiser/systemd-sandbox-check/compare/0.2.0...main
[0.2.0]: https://github.com/manfred-kaiser/systemd-sandbox-check/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/manfred-kaiser/systemd-sandbox-check/releases/tag/0.1.0
