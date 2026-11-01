"""Unit tests for YAML server provisioning profile parser and validator."""

from pathlib import Path

import pytest

from lh_hid_provisioner.models import NetworkMode
from lh_hid_provisioner.parser import (
    ProfileValidationError,
    parse_profile,
    validate_hostname,
    validate_locale,
    validate_network_config,
    validate_packages,
    validate_ssh_config,
    validate_sysctl,
)

VALID_SSH_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleValidKeyString123 admin@test.local"


def test_validate_hostname_valid() -> None:
    assert validate_hostname("node1") == "node1"
    assert validate_hostname("server-01.internal.net") == "server-01.internal.net"
    assert validate_hostname("a.b.c") == "a.b.c"


@pytest.mark.parametrize(
    "invalid_host",
    [
        "",
        "   ",
        "-starts-with-hyphen",
        "ends-with-hyphen-",
        "has..empty.segment",
        "has_underscore",
        "has space",
        "a" * 254,
    ],
)
def test_validate_hostname_invalid(invalid_host: str) -> None:
    with pytest.raises(ProfileValidationError):
        validate_hostname(invalid_host)


def test_validate_locale_valid() -> None:
    assert validate_locale("en_US.UTF-8") == "en_US.UTF-8"
    assert validate_locale("C.UTF-8") == "C.UTF-8"
    assert validate_locale("POSIX") == "POSIX"


@pytest.mark.parametrize("invalid_locale", ["", "   ", "invalid locale!@#"])
def test_validate_locale_invalid(invalid_locale: str) -> None:
    with pytest.raises(ProfileValidationError):
        validate_locale(invalid_locale)


def test_validate_network_dhcp() -> None:
    net = validate_network_config({"interface": "eth0", "mode": "dhcp"})
    assert net.interface == "eth0"
    assert net.mode == NetworkMode.DHCP
    assert net.address is None
    assert net.gateway is None


def test_validate_network_static_valid() -> None:
    net = validate_network_config(
        {
            "interface": "ens3",
            "mode": "static",
            "address": "192.168.1.100/24",
            "gateway": "192.168.1.1",
            "nameservers": ["1.1.1.1", "8.8.8.8"],
        }
    )
    assert net.interface == "ens3"
    assert net.mode == NetworkMode.STATIC
    assert net.address == "192.168.1.100/24"
    assert net.gateway == "192.168.1.1"
    assert net.nameservers == ["1.1.1.1", "8.8.8.8"]


@pytest.mark.parametrize(
    "invalid_data",
    [
        "not a dict",
        {"mode": "dhcp"},  # missing interface
        {"interface": "invalid interface name with spaces!"},
        {"interface": "eth0", "mode": "unknown_mode"},
        {"interface": "eth0", "mode": "static"},  # missing static fields
        {"interface": "eth0", "mode": "static", "address": "not_an_ip"},
        {"interface": "eth0", "mode": "static", "address": "192.168.1.10/24", "gateway": "not_ip"},
        {
            "interface": "eth0",
            "mode": "static",
            "address": "192.168.1.10/24",
            "gateway": "192.168.1.1",
            "nameservers": ["bad_dns"],
        },
    ],
)
def test_validate_network_invalid(invalid_data: object) -> None:
    with pytest.raises(ProfileValidationError):
        validate_network_config(invalid_data)  # type: ignore[arg-type]


def test_validate_ssh_valid() -> None:
    ssh = validate_ssh_config(
        {
            "authorized_keys": [VALID_SSH_KEY],
            "disable_root_password_login": True,
            "sshd_port": 2222,
        }
    )
    assert len(ssh.authorized_keys) == 1
    assert ssh.disable_root_password_login is True
    assert ssh.sshd_port == 2222


@pytest.mark.parametrize(
    "invalid_ssh",
    [
        "not a dict",
        {"authorized_keys": "not a list"},
        {"authorized_keys": [""]},
        {"authorized_keys": ["single_word_no_key_data"]},
        {"authorized_keys": ["unsupported-key-type AAAABBBB"]},
        {"authorized_keys": [VALID_SSH_KEY], "disable_root_password_login": "not-bool"},
        {"authorized_keys": [VALID_SSH_KEY], "sshd_port": 70000},
        {"authorized_keys": [VALID_SSH_KEY], "sshd_port": 0},
    ],
)
def test_validate_ssh_invalid(invalid_ssh: object) -> None:
    with pytest.raises(ProfileValidationError):
        validate_ssh_config(invalid_ssh)  # type: ignore[arg-type]


def test_validate_packages_valid() -> None:
    assert validate_packages(None) == []
    assert validate_packages(["curl", "htop", "vim+extra", "my_pkg-1"]) == [
        "curl",
        "htop",
        "vim+extra",
        "my_pkg-1",
    ]


@pytest.mark.parametrize("invalid_pkg", ["not a list", [""], ["pkg with spaces"]])
def test_validate_packages_invalid(invalid_pkg: object) -> None:
    with pytest.raises(ProfileValidationError):
        validate_packages(invalid_pkg)


def test_validate_sysctl_valid() -> None:
    assert validate_sysctl(None) == {}
    res = validate_sysctl({"net.ipv4.ip_forward": 1, "net.ipv4.tcp_syncookies": True})
    assert res["net.ipv4.ip_forward"] == 1
    assert res["net.ipv4.tcp_syncookies"] == 1


@pytest.mark.parametrize(
    "invalid_sysctl",
    ["not a dict", {"invalid key with spaces": 1}, {"net.ipv4.ip_forward": [1, 2]}],
)
def test_validate_sysctl_invalid(invalid_sysctl: object) -> None:
    with pytest.raises(ProfileValidationError):
        validate_sysctl(invalid_sysctl)


def test_parse_profile_full_yaml(tmp_path: Path) -> None:
    yaml_content = f"""
version: "1"
hostname: "test-node01.internal"
locale: "en_US.UTF-8"
timezone: "UTC"
networking:
  interface: "eth0"
  mode: "dhcp"
ssh:
  authorized_keys:
    - "{VALID_SSH_KEY}"
  disable_root_password_login: true
  sshd_port: 22
packages:
  - "curl"
  - "vim"
sysctl:
  net.ipv4.ip_forward: 0
"""
    profile = parse_profile(yaml_content)
    assert profile.hostname == "test-node01.internal"
    assert profile.networking.interface == "eth0"
    assert len(profile.ssh.authorized_keys) == 1
    assert profile.packages == ["curl", "vim"]
    assert profile.sysctl["net.ipv4.ip_forward"] == 0

    # Also test from file path
    f = tmp_path / "profile.yaml"
    f.write_text(yaml_content, encoding="utf-8")
    profile2 = parse_profile(f)
    assert profile2.hostname == profile.hostname


def test_parse_profile_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(FileNotFoundError):
        parse_profile(missing)


def test_parse_profile_invalid_yaml_syntax() -> None:
    with pytest.raises(ProfileValidationError, match="Invalid YAML syntax"):
        parse_profile("key: [unclosed list")


def test_parse_profile_missing_sections() -> None:
    with pytest.raises(ProfileValidationError, match="networking"):
        parse_profile("version: '1'\nhostname: 'node1'\nlocale: 'en_US.UTF-8'")

    with pytest.raises(ProfileValidationError, match="ssh"):
        parse_profile(
            "version: '1'\nhostname: 'node1'\nlocale: 'en_US.UTF-8'\n"
            "networking:\n  interface: 'eth0'\n  mode: 'dhcp'"
        )


def test_parse_profile_root_not_mapping() -> None:
    with pytest.raises(ProfileValidationError, match="root must be a mapping"):
        parse_profile("- item 1\n- item 2\n")


def test_validate_network_dhcp_optional_nameservers() -> None:
    # Valid nameserver in DHCP
    net = validate_network_config(
        {"interface": "eth0", "mode": "dhcp", "nameservers": ["1.1.1.1", "invalid-ignored"]}
    )
    assert net.nameservers == ["1.1.1.1"]


def test_parse_profile_unreadable_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "locked.yaml"
    f.write_text("dummy: content", encoding="utf-8")

    def mock_read_text(*args: object, **kwargs: object) -> str:
        raise OSError("Permission denied")

    monkeypatch.setattr(Path, "read_text", mock_read_text)
    with pytest.raises(ProfileValidationError, match="Failed to read profile file"):
        parse_profile(f)

