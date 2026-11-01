# ==============================================================================
# Product:       lh-hid-provisioner (lh-provision)
# Module:        tests.test_compiler
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for OS-specific HID keystroke automation script compiler."""

from lh_hid_provisioner.compiler import compile_profile
from lh_hid_provisioner.linter import lint_script
from lh_hid_provisioner.models import (
    NetworkConfig,
    NetworkMode,
    ServerProfile,
    SSHConfig,
    TargetOS,
)

VALID_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyPlaceholder admin@example.com"


def make_test_profile(mode: NetworkMode = NetworkMode.DHCP) -> ServerProfile:
    net = NetworkConfig(
        interface="eth0",
        mode=mode,
        address="192.168.1.100/24" if mode == NetworkMode.STATIC else None,
        gateway="192.168.1.1" if mode == NetworkMode.STATIC else None,
        nameservers=["1.1.1.1", "8.8.8.8"] if mode == NetworkMode.STATIC else [],
    )
    ssh = SSHConfig(
        authorized_keys=[VALID_KEY],
        disable_root_password_login=True,
        sshd_port=2222,
    )
    return ServerProfile(
        version="1",
        hostname="srv01.example.com",
        locale="en_US.UTF-8",
        timezone="UTC",
        networking=net,
        ssh=ssh,
        packages=["curl", "htop"],
        sysctl={"net.ipv4.ip_forward": 0, "net.ipv4.tcp_syncookies": 1},
    )


def test_compile_debian_dhcp() -> None:
    profile = make_test_profile(NetworkMode.DHCP)
    script = compile_profile(profile, TargetOS.DEBIAN)

    assert "REM Target OS: debian" in script
    assert "DEFAULT_DELAY 100" in script
    assert "DELAY 1000" in script
    assert 'hostnamectl set-hostname "srv01.example.com"' in script
    assert "iface eth0 inet dhcp" in script
    assert "apt-get install -y curl htop" in script
    assert "Port 2222" in script
    assert "sysctl --system" in script

    # Ensure compiler output is 100% clean according to linter
    report = lint_script(script)
    assert report.total_issues == 0


def test_compile_debian_static() -> None:
    profile = make_test_profile(NetworkMode.STATIC)
    script = compile_profile(profile, TargetOS.DEBIAN)

    assert "iface eth0 inet static" in script
    assert "address 192.168.1.100/24" in script
    assert "gateway 192.168.1.1" in script
    assert 'echo "nameserver 1.1.1.1" >> /etc/resolv.conf' in script

    report = lint_script(script)
    assert report.total_issues == 0


def test_compile_ubuntu_dhcp() -> None:
    profile = make_test_profile(NetworkMode.DHCP)
    script = compile_profile(profile, TargetOS.UBUNTU)

    assert "REM Target OS: ubuntu" in script
    assert "/etc/netplan/01-netcfg.yaml" in script
    assert "dhcp4: true" in script
    assert "netplan apply" in script

    report = lint_script(script)
    assert report.total_issues == 0


def test_compile_ubuntu_static() -> None:
    profile = make_test_profile(NetworkMode.STATIC)
    script = compile_profile(profile, TargetOS.UBUNTU)

    assert "addresses: [192.168.1.100/24]" in script
    assert "via: 192.168.1.1" in script
    assert 'addresses: ["1.1.1.1", "8.8.8.8"]' in script
    assert "netplan apply" in script

    report = lint_script(script)
    assert report.total_issues == 0


def test_compile_alpine_dhcp() -> None:
    profile = make_test_profile(NetworkMode.DHCP)
    script = compile_profile(profile, TargetOS.ALPINE)

    assert "REM Target OS: alpine" in script
    # Alpine specific commands
    assert 'echo "srv01.example.com" > /etc/hostname && hostname -F /etc/hostname' in script
    assert "/etc/profile.d/locale.sh" in script
    assert "apk update && apk add curl htop" in script
    assert "rc-update add sshd default && rc-service sshd restart" in script
    assert "sysctl -p /etc/sysctl.d/99-hardening.conf" in script

    report = lint_script(script)
    assert report.total_issues == 0


def test_compile_alpine_static() -> None:
    profile = make_test_profile(NetworkMode.STATIC)
    script = compile_profile(profile, TargetOS.ALPINE)

    assert "iface eth0 inet static" in script
    assert "address 192.168.1.100/24" in script
    assert "/etc/init.d/networking restart" in script

    report = lint_script(script)
    assert report.total_issues == 0


def test_compile_empty_packages_and_sysctl() -> None:
    profile = make_test_profile(NetworkMode.DHCP)
    profile.packages = []
    profile.sysctl = {}
    script = compile_profile(profile, TargetOS.DEBIAN)

    assert "apt-get install" not in script
    assert "99-hardening.conf" not in script
    report = lint_script(script)
    assert report.total_issues == 0
