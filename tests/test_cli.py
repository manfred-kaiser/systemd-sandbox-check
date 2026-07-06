from pathlib import Path

from systemd_sandbox_check.cli import build_systemd_run_cmd, parse_unit

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
