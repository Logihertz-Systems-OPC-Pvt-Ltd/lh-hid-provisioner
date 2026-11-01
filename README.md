# lh-hid-provisioner

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-hid-provisioner/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-hid-provisioner/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise cryptographic token & hid provisioning developed by **Logihertz Systems (OPC) Private Limited**.

Audits and provisions FIDO2/WebAuthn security keys, YubiKey PIV/OATH profiles, and hardware token attestation manifests to enforce PIN complexity, touch-presence policies, and trusted CA attestation chains.

---

## Key Features

- **Declarative YAML-to-HID Compilation**: Compiles network, user, SSH, and sysctl configurations into deterministic HID automation scripts for Debian, Ubuntu, and Alpine.
- **Defensive Safety Linter**: Scans scripts for destructive filesystem operations (`rm -rf /`, `mkfs`), reverse shells, and exfiltration commands.
- **Syntax & Delay Verification**: Checks for missing command execution delays (`DELAY`) that cause character dropping on slow consoles.
- **Shell Variable Sanitization**: Enforces strict quoting and escaping of shell variables to prevent command injection.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `SEC-001` | `CRITICAL` | Destructive filesystem command detected in HID automation payload (rm -rf, mkfs, dd) |
| `SEC-002` | `CRITICAL` | Reverse shell or outbound network socket execution detected (nc, bash -i, /dev/tcp) |
| `SEC-003` | `CRITICAL` | Unauthorized credential exfiltration or token exposure command detected |
| `SEC-004` | `HIGH` | Unauthorized privilege escalation command (modifying /etc/sudoers or visudo) |
| `SYN-001` | `HIGH` | Syntax error or unsupported command in target OS HID script |
| `SYN-002` | `MEDIUM` | Missing inter-command execution delay (burst command overrun risk) |
| `SYN-003` | `HIGH` | Dangerous unquoted shell variable or unsanitized shell expansion |
| `SYN-004` | `MEDIUM` | Deprecated keyboard layout character code or untranslatable keycode |
| `PROF-001` | `HIGH` | Missing required host configuration parameters in YAML profile |
| `PROF-002` | `LOW` | Insecure default network or SSH configuration in generated profile |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-hid-provisioner.git
cd lh-hid-provisioner

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-provision` (also accessible via `lh-provision`).

```bash
# Compile a YAML server profile to a Debian HID script
lh-provision compile profile.yaml --target-os debian --output script.txt

# Lint and validate an existing HID script for safety guardrails
lh-provision lint script.txt --strict

# Export lint findings to OASIS SARIF v2.1.0
lh-provision lint script.txt --format sarif --output lint-results.sarif

# Generate starter YAML provisioning profile template
lh-provision init --output starter-profile.yaml
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
