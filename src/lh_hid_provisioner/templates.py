# ==============================================================================
# Product:       lh-hid-provisioner (lh-provision)
# Module:        src.lh_hid_provisioner.templates
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Profile template generators for Debian, Ubuntu, and Alpine Linux."""

from lh_hid_provisioner.models import TargetOS

DEBIAN_TEMPLATE = """# Logihertz HID Server Provisioning Profile: Debian Linux
version: "1"
hostname: "debian-node01.internal"
locale: "en_US.UTF-8"
timezone: "UTC"

networking:
  interface: "eth0"
  mode: "dhcp"
  # Uncomment below for static network configuration:
  # mode: "static"
  # address: "192.168.10.50/24"
  # gateway: "192.168.10.1"
  # nameservers:
  #   - "1.1.1.1"
  #   - "8.8.8.8"

ssh:
  authorized_keys:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKey admin@logihertz.internal"
  disable_root_password_login: true
  sshd_port: 22

packages:
  - "curl"
  - "htop"
  - "vim"
  - "ufw"
  - "ca-certificates"

sysctl:
  net.ipv4.ip_forward: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.tcp_syncookies: 1
"""

UBUNTU_TEMPLATE = """# Logihertz HID Server Provisioning Profile: Ubuntu Linux
version: "1"
hostname: "ubuntu-server01.internal"
locale: "en_US.UTF-8"
timezone: "Etc/UTC"

networking:
  interface: "ens3"
  mode: "dhcp"
  # Uncomment below for static network configuration via Netplan:
  # mode: "static"
  # address: "10.0.1.20/24"
  # gateway: "10.0.1.1"
  # nameservers:
  #   - "1.1.1.1"
  #   - "8.8.8.8"

ssh:
  authorized_keys:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKey admin@logihertz.internal"
  disable_root_password_login: true
  sshd_port: 22

packages:
  - "curl"
  - "htop"
  - "tmux"
  - "apparmor"
  - "needrestart"

sysctl:
  net.ipv4.ip_forward: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.tcp_syncookies: 1
  fs.protected_hardlinks: 1
  fs.protected_symlinks: 1
"""

ALPINE_TEMPLATE = """# Logihertz HID Server Provisioning Profile: Alpine Linux
version: "1"
hostname: "alpine-node01.internal"
locale: "C.UTF-8"
timezone: "UTC"

networking:
  interface: "eth0"
  mode: "dhcp"
  # Uncomment below for static network configuration:
  # mode: "static"
  # address: "172.16.0.10/24"
  # gateway: "172.16.0.1"
  # nameservers:
  #   - "1.1.1.1"

ssh:
  authorized_keys:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKey admin@logihertz.internal"
  disable_root_password_login: true
  sshd_port: 22

packages:
  - "curl"
  - "htop"
  - "openssh"
  - "tzdata"

sysctl:
  net.ipv4.ip_forward: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.tcp_syncookies: 1
"""


def generate_template(target_os: TargetOS) -> str:
    """Generate a valid, fully documented YAML provisioning profile template.

    Args:
        target_os: Operating system target (Debian, Ubuntu, or Alpine).

    Returns:
        String containing YAML profile template.
    """
    match target_os:
        case TargetOS.DEBIAN:
            return DEBIAN_TEMPLATE
        case TargetOS.UBUNTU:
            return UBUNTU_TEMPLATE
        case TargetOS.ALPINE:
            return ALPINE_TEMPLATE
