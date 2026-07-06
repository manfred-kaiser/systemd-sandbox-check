# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--exec-check` (with `--exec-check-timeout`, default 5s): starts the
  unit's real `ExecStart` inside the identical sandbox and reports via
  `systemctl`/`journalctl` whether the application itself comes up and
  stays up, instead of only checking individual restrictions in isolation.
  Not a no-op like the other probes -- has real side effects (production
  paths/network bindings) and is therefore opt-in.

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

[Unreleased]: https://github.com/manfred-kaiser/systemd-sandbox-check/compare/0.1.0...main
[0.1.0]: https://github.com/manfred-kaiser/systemd-sandbox-check/releases/tag/0.1.0
