# lh-hid-provisioner

[![CI](https://github.com/logihertz/lh-hid-provisioner/actions/workflows/ci.yml/badge.svg)](https://github.com/logihertz/lh-hid-provisioner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A clean-room CLI utility by **Logihertz Systems OPC Pvt Ltd** for system administrators and DevSecOps engineers to compile declarative YAML server profiles into deterministic USB HID keystroke automation scripts and lint existing HID scripts for safety, syntax compliance, and malicious payloads.

---

## Key Features

- **Declarative YAML Profiles**: Specify hostname, locale, timezone, networking (DHCP or static IP, gateway, nameservers), SSH public keys, packages, and sysctl hardening parameters in clean, validated YAML.
- **Multi-OS Compilation**:
  - **Debian Linux**: Generates native `/etc/network/interfaces`, `systemd`, `hostnamectl`, and `apt-get` automation.
  - **Ubuntu Linux**: Configures Netplan (`/etc/netplan/01-netcfg.yaml`), `systemd`, and `apt-get`.
  - **Alpine Linux**: Tailored for OpenRC services, musl libc locale configuration, `/etc/network/interfaces`, and `apk` package manager.
- **Defensive Security Guardrails**:
  - `SEC-001`: Blocks destructive filesystem commands (`rm -rf /`, `mkfs`, raw `dd` disk wipes, fork bombs).
  - `SEC-002`: Blocks interactive reverse shell patterns (`/dev/tcp/`, netcat `-e`, socat, Python/Perl/Ruby socket shells).
  - `SEC-003`: Blocks credential and private key exfiltration (`/etc/shadow`, `id_rsa`, `id_ed25519` via curl/wget/nc).
  - `SEC-004`: Detects unchecked remote script execution (`curl | bash`, `wget | sh`).
- **Syntax and Reliability Checks**:
  - `SYN-001`: Identifies unrecognized HID commands and stray shell input.
  - `SYN-002`: Enforces inter-command delay thresholds to prevent buffer overrun on target systems.
  - `SYN-003`: Validates delay duration format and boundaries.
  - `SYN-004`: Flags unsafe unquoted shell variables (`$VAR` vs `"$VAR"`).
- **Multiple Reporting Formats**:
  - Rich terminal tables with color-coded severity levels.
  - Machine-readable JSON for CI/CD integrations.
  - OASIS **SARIF v2.1.0** for native GitHub Code Scanning integration.

---

## Installation

Using `uv`:
```bash
uv pip install .
```

Or using standard `pip`:
```bash
pip install .
```

---

## Quickstart & CLI Reference

The CLI entry point is `lh-provision`.

### 1. Generate Starter Profile Template

Create a pre-configured, validated YAML profile for your target operating system:

```bash
lh-provision init-template --target-os debian --output debian-profile.yaml
lh-provision init-template --target-os ubuntu --output ubuntu-profile.yaml
lh-provision init-template --target-os alpine --output alpine-profile.yaml
```

### 2. Compile Profile to HID Script

Compile your declarative profile into a DuckyScript-compatible USB HID keystroke script:

```bash
lh-provision compile debian-profile.yaml --target-os debian --output deploy-debian.txt
```

### 3. Lint and Validate HID Scripts

Analyze HID automation scripts for syntax errors and security threats:

```bash
# Pretty terminal table report
lh-provision lint deploy-debian.txt

# Enforce strict mode (fail on any warning)
lh-provision lint deploy-debian.txt --strict

# Export to JSON
lh-provision lint deploy-debian.txt --format json --output report.json

# Export to SARIF v2.1.0 for GitHub Security tab
lh-provision lint deploy-debian.txt --format sarif --output results.sarif
```

---

## Profile Specification

```yaml
version: "1"
hostname: "web01.internal.logihertz.com"
locale: "en_US.UTF-8"
timezone: "UTC"

networking:
  interface: "eth0"
  mode: "static"
  address: "192.168.1.50/24"
  gateway: "192.168.1.1"
  nameservers:
    - "1.1.1.1"
    - "8.8.8.8"

ssh:
  authorized_keys:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... sysadmin@logihertz.com"
  disable_root_password_login: true
  sshd_port: 22

packages:
  - "curl"
  - "htop"
  - "vim"
  - "ufw"

sysctl:
  net.ipv4.ip_forward: 0
  net.ipv4.conf.all.send_redirects: 0
  net.ipv4.conf.all.accept_redirects: 0
  net.ipv4.conf.all.accept_source_route: 0
  net.ipv4.conf.all.rp_filter: 1
  net.ipv4.tcp_syncookies: 1
```

---

## Development & Testing

Run linter, security analyzer, and unit tests:

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Code formatting and linting
ruff check .

# Static application security testing (SAST)
bandit -r src/

# Run unit and integration tests with coverage
pytest --cov=lh_hid_provisioner
```

---

## License

MIT License. Copyright (c) 2026 Logihertz Systems OPC Pvt Ltd.

