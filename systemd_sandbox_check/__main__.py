"""systemd_sandbox_check module.

Example usage:
    python -m systemd_sandbox_check --unit /path/to/some.service
"""

from systemd_sandbox_check.cli import main

if __name__ == "__main__":
    main()
