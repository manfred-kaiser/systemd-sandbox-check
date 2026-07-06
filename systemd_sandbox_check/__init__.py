"""systemd_sandbox_check module.

Dynamically verifies that systemd sandboxing/hardening directives on a unit
file actually take effect at runtime, complementing the static
`systemd-analyze security` score.
"""

__version__ = "0.1.0"
