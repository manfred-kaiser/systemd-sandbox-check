from pathlib import Path

from systemd_sandbox_check.cli import (
    build_exec_check_cmd,
    build_systemd_run_cmd,
    parse_exec_start,
    parse_unit,
)

UNIT_CONTENT = """\
[Unit]
Description=example

[Service]
Type=simple
ExecStart=/usr/bin/example
User=example
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# a comment
ReadWritePaths=/var/lib/example

[Install]
WantedBy=multi-user.target
"""


def test_parse_unit_extracts_service_section_only(tmp_path: Path) -> None:
    unit_file = tmp_path / "example.service"
    unit_file.write_text(UNIT_CONTENT)

    directives = parse_unit(unit_file)

    assert directives["Type"] == "simple"
    assert directives["NoNewPrivileges"] == "true"
    assert directives["RestrictAddressFamilies"] == "AF_INET AF_INET6 AF_UNIX"
    assert "Description" not in directives
    assert "WantedBy" not in directives


def test_build_systemd_run_cmd_skips_execstart_and_forwards_properties() -> None:
    directives = {
        "ExecStart": "/usr/bin/example",
        "Type": "simple",
        "NoNewPrivileges": "true",
    }

    cmd = build_systemd_run_cmd("test-unit", directives, {"HARDEN_CONFIG": "{}"})

    assert "--property=ExecStart=/usr/bin/example" not in cmd
    assert "--property=Type=simple" not in cmd
    assert "--property=NoNewPrivileges=true" in cmd
    assert "--setenv=HARDEN_CONFIG={}" in cmd
    assert cmd[-2:] == ["/usr/bin/python3", "-"]
    assert "--unit=test-unit" in cmd


def test_parse_exec_start_splits_prefix_and_argv() -> None:
    prefixes, argv = parse_exec_start("-/usr/bin/example --config /etc/example.toml")

    assert prefixes == "-"
    assert argv == ["/usr/bin/example", "--config", "/etc/example.toml"]


def test_parse_exec_start_no_prefix() -> None:
    prefixes, argv = parse_exec_start("/usr/bin/example")

    assert prefixes == ""
    assert argv == ["/usr/bin/example"]


def test_build_exec_check_cmd_forwards_state_directory_and_forces_no_restart() -> None:
    directives = {
        "ExecStart": "/usr/bin/example",
        "Restart": "on-failure",
        "RestartSec": "2s",
        "StateDirectory": "example",
        "NoNewPrivileges": "true",
    }

    cmd = build_exec_check_cmd("test-unit-exec", directives, ["/usr/bin/example", "--config", "x.toml"])

    assert "--property=ExecStart=/usr/bin/example" not in cmd
    assert "--property=Restart=on-failure" not in cmd
    assert "--property=StateDirectory=example" in cmd
    assert "--property=NoNewPrivileges=true" in cmd
    assert "--property=Restart=no" in cmd
    assert cmd[-3:] == ["/usr/bin/example", "--config", "x.toml"]
