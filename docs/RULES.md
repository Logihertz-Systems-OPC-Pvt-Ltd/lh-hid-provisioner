# Security Rules Reference: lh-hid-provisioner

An enterprise usb hid server provisioning & script linter developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-hid-provisioner`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `SEC-001` | `CRITICAL` | Destructive Execution | Destructive Filesystem Command Detected in HID Script |
| `SEC-002` | `CRITICAL` | Command Injection | Reverse Shell or Outbound Socket Execution Detected |
| `SEC-003` | `CRITICAL` | Data Exfiltration | Unauthorized Credential Exfiltration Command |
| `SEC-004` | `HIGH` | Privilege Escalation | Unauthorized Privilege Escalation Command |
| `SYN-001` | `HIGH` | Syntax Compliance | Syntax Error or Unsupported Command in Target Script |
| `SYN-002` | `MEDIUM` | Timing Reliability | Missing Inter-Command Execution Delay |
| `SYN-003` | `HIGH` | Input Validation | Dangerous Unquoted Shell Variable in Payload |
| `SYN-004` | `MEDIUM` | Compatibility | Deprecated Keyboard Layout Character Code |
| `PROF-001` | `HIGH` | Profile Validation | Missing Required Host Configuration Parameters |
| `PROF-002` | `LOW` | Configuration | Insecure Default Network or SSH Configuration in Profile |

---

## Granular Rule Specifications

### `SEC-001`: Destructive Filesystem Command Detected in HID Script

- **Severity**: `CRITICAL`
- **Category**: `Destructive Execution`
- **Description**: Commands like rm -rf /, mkfs, or dd targeting root partitions detected in HID automation payload.
- **Remediation**: Remove destructive commands from automation scripts and verify target disk partitions explicitly.

---

### `SEC-002`: Reverse Shell or Outbound Socket Execution Detected

- **Severity**: `CRITICAL`
- **Category**: `Command Injection`
- **Description**: Network socket commands (nc -e, bash -i >& /dev/tcp, python -c socket) detected in script.
- **Remediation**: Prohibit arbitrary reverse shell commands; use authenticated SSH bastion hosts for remote access.

---

### `SEC-003`: Unauthorized Credential Exfiltration Command

- **Severity**: `CRITICAL`
- **Category**: `Data Exfiltration`
- **Description**: Commands attempting to curl/wget /etc/shadow or private SSH keys to remote endpoints.
- **Remediation**: Eliminate exfiltration commands and enforce strict console provisioning isolation.

---

### `SEC-004`: Unauthorized Privilege Escalation Command

- **Severity**: `HIGH`
- **Category**: `Privilege Escalation`
- **Description**: Script attempts to overwrite /etc/sudoers or inject unrestricted NOPASSWD directives.
- **Remediation**: Configure scoped sudo rules with explicit command lists rather than blanket NOPASSWD access.

---

### `SYN-001`: Syntax Error or Unsupported Command in Target Script

- **Severity**: `HIGH`
- **Category**: `Syntax Compliance`
- **Description**: Unknown or malformed HID command keyword that fails console execution.
- **Remediation**: Use standard HID command keywords (STRING, ENTER, DELAY) recognized by target parser.

---

### `SYN-002`: Missing Inter-Command Execution Delay

- **Severity**: `MEDIUM`
- **Category**: `Timing Reliability`
- **Description**: Successive commands lack DELAY instructions, risking character drop on slow consoles.
- **Remediation**: Insert DELAY 200 between command execution lines to ensure console buffer flush.

---

### `SYN-003`: Dangerous Unquoted Shell Variable in Payload

- **Severity**: `HIGH`
- **Category**: `Input Validation`
- **Description**: Shell expansion variables used without quotes, susceptible to argument injection.
- **Remediation**: Wrap all shell variable expansions in double quotes (e.g. "$VAR") in compiled commands.

---

### `SYN-004`: Deprecated Keyboard Layout Character Code

- **Severity**: `MEDIUM`
- **Category**: `Compatibility`
- **Description**: Untranslatable special character or non-ASCII glyph in ASCII HID script.
- **Remediation**: Sanitize input strings to printable ASCII characters compatible with US keyboard layout.

---

### `PROF-001`: Missing Required Host Configuration Parameters

- **Severity**: `HIGH`
- **Category**: `Profile Validation`
- **Description**: Server profile YAML missing mandatory hostname, network, or root user specification.
- **Remediation**: Provide complete configuration parameters in profile YAML according to schema specification.

---

### `PROF-002`: Insecure Default Network or SSH Configuration in Profile

- **Severity**: `LOW`
- **Category**: `Configuration`
- **Description**: Profile generates SSH server configuration allowing root password login.
- **Remediation**: Configure PermitRootLogin prohibit-password and enforce SSH public key authentication.

---
