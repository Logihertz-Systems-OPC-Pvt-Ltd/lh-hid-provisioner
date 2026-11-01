"""Unit tests for the lh-provision command line interface."""

from pathlib import Path

from typer.testing import CliRunner

from lh_hid_provisioner.cli import app

runner = CliRunner()

SAMPLE_PROFILE_YAML = """
version: "1"
hostname: "cli-test.example.com"
locale: "en_US.UTF-8"
timezone: "UTC"
networking:
  interface: "eth0"
  mode: "dhcp"
ssh:
  authorized_keys:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIValidKeyPlaceholder admin@cli.test"
  disable_root_password_login: true
  sshd_port: 22
packages:
  - "curl"
sysctl:
  net.ipv4.ip_forward: 0
"""


def test_cli_version() -> None:
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "lh-provision v" in res.output
    assert "Logihertz Systems" in res.output


def test_cli_help() -> None:
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "compile" in res.output
    assert "lint" in res.output
    assert "init-template" in res.output


def test_cli_compile_stdout(tmp_path: Path) -> None:
    prof_file = tmp_path / "test.yaml"
    prof_file.write_text(SAMPLE_PROFILE_YAML, encoding="utf-8")

    res = runner.invoke(app, ["compile", str(prof_file), "--target-os", "debian"])
    assert res.exit_code == 0
    assert "REM Target OS: debian" in res.output
    assert 'hostnamectl set-hostname "cli-test.example.com"' in res.output


def test_cli_compile_file_output(tmp_path: Path) -> None:
    prof_file = tmp_path / "test.yaml"
    prof_file.write_text(SAMPLE_PROFILE_YAML, encoding="utf-8")
    out_file = tmp_path / "compiled.txt"

    res = runner.invoke(
        app,
        ["compile", str(prof_file), "--target-os", "ubuntu", "--output", str(out_file)],
    )
    assert res.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "REM Target OS: ubuntu" in content


def test_cli_compile_invalid_profile(tmp_path: Path) -> None:
    prof_file = tmp_path / "bad.yaml"
    prof_file.write_text("invalid: yaml [", encoding="utf-8")

    res = runner.invoke(app, ["compile", str(prof_file), "--target-os", "alpine"])
    assert res.exit_code == 1
    assert "Profile Error" in res.output


def test_cli_lint_clean(tmp_path: Path) -> None:
    script_file = tmp_path / "clean.txt"
    script_file.write_text(
        "DEFAULT_DELAY 100\nDELAY 1000\nSTRING echo 'Hello'\nENTER\nDELAY 500\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["lint", str(script_file)])
    assert res.exit_code == 0
    assert "No issues found" in res.output


def test_cli_lint_strict_mode(tmp_path: Path) -> None:
    # SYN-004 is a warning (MEDIUM)
    script_file = tmp_path / "warn.txt"
    script_file.write_text(
        "DEFAULT_DELAY 100\nSTRING echo $UNQUOTED\nENTER\n",
        encoding="utf-8",
    )

    # Normal mode: passes because it's only a warning
    res_normal = runner.invoke(app, ["lint", str(script_file)])
    assert res_normal.exit_code == 0

    # Strict mode: fails on warnings
    res_strict = runner.invoke(app, ["lint", str(script_file), "--strict"])
    assert res_strict.exit_code == 1


def test_cli_lint_critical_fails(tmp_path: Path) -> None:
    script_file = tmp_path / "bad.txt"
    script_file.write_text(
        "DEFAULT_DELAY 100\nSTRING rm -rf /\nENTER\n",
        encoding="utf-8",
    )

    res = runner.invoke(app, ["lint", str(script_file)])
    assert res.exit_code == 1
    assert "SEC-001" in res.output


def test_cli_lint_formats_and_output_file(tmp_path: Path) -> None:
    script_file = tmp_path / "bad.txt"
    script_file.write_text(
        "DEFAULT_DELAY 100\nSTRING rm -rf /\nENTER\n",
        encoding="utf-8",
    )

    # JSON format
    json_out = tmp_path / "report.json"
    res_json = runner.invoke(
        app,
        ["lint", str(script_file), "--format", "json", "--output", str(json_out)],
    )
    assert res_json.exit_code == 1
    assert json_out.exists()
    assert '"rule_id": "SEC-001"' in json_out.read_text(encoding="utf-8")

    # SARIF format
    sarif_out = tmp_path / "report.sarif"
    res_sarif = runner.invoke(
        app,
        ["lint", str(script_file), "--format", "sarif", "--output", str(sarif_out)],
    )
    assert res_sarif.exit_code == 1
    assert sarif_out.exists()
    assert '"version": "2.1.0"' in sarif_out.read_text(encoding="utf-8")


def test_cli_init_template(tmp_path: Path) -> None:
    # Stdout
    res = runner.invoke(app, ["init-template", "--target-os", "debian"])
    assert res.exit_code == 0
    assert "hostname: " in res.output

    # File output
    tpl_file = tmp_path / "debian.yaml"
    res_file = runner.invoke(
        app,
        ["init-template", "--target-os", "alpine", "--output", str(tpl_file)],
    )
    assert res_file.exit_code == 0
    assert tpl_file.exists()
    content = tpl_file.read_text(encoding="utf-8")
    assert "alpine-node01" in content


def test_cli_compile_output_write_error(tmp_path: Path) -> None:
    prof_file = tmp_path / "test.yaml"
    prof_file.write_text(SAMPLE_PROFILE_YAML, encoding="utf-8")
    bad_output = tmp_path

    res = runner.invoke(
        app,
        ["compile", str(prof_file), "--target-os", "debian", "--output", str(bad_output)],
    )
    assert res.exit_code == 1
    assert "Output Error" in res.output


def test_cli_lint_read_error(tmp_path: Path) -> None:
    res = runner.invoke(app, ["lint", str(tmp_path)])
    assert res.exit_code != 0


def test_cli_lint_write_error(tmp_path: Path) -> None:
    script_file = tmp_path / "clean.txt"
    script_file.write_text("DEFAULT_DELAY 100\n", encoding="utf-8")
    bad_output = tmp_path

    res = runner.invoke(app, ["lint", str(script_file), "--output", str(bad_output)])
    assert res.exit_code == 1
    assert "Output Error" in res.output


def test_cli_init_template_write_error(tmp_path: Path) -> None:
    bad_output = tmp_path
    res = runner.invoke(app, ["init-template", "--output", str(bad_output)])
    assert res.exit_code == 1
    assert "Output Error" in res.output
