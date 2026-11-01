# Security Policy

## Clean-Room Security Commitment

`lh-hid-provisioner` is authored as an independent, clean-room implementation by **Logihertz Systems OPC Pvt Ltd** to ensure zero code provenance risks, no copied third-party vulnerabilities, and strict adherence to defensive design patterns.

## Defensive Guardrails in HID Provisioning

USB HID automation devices inherently operate with console keyboard privileges. Consequently, `lh-hid-provisioner` provides built-in linter guardrails that inspect and block:

1. **Destructive Filesystem Commands (`SEC-001`)**: Commands that attempt to delete filesystem roots, format block storage devices, zero disks, or trigger fork bombs.
2. **Reverse Shells (`SEC-002`)**: Sockets, named pipes, or interpreter one-liners intended to open covert outbound channels.
3. **Credential Exfiltration (`SEC-003`)**: Pipeline transfers or network uploads reading `/etc/shadow`, `/etc/gshadow`, or SSH private keys.
4. **Unchecked Remote Script Execution (`SEC-004`)**: Directly executing piped network payloads (`curl | bash`).

## Reporting a Vulnerability

If you discover a potential security vulnerability within `lh-hid-provisioner` or identify an evasion pattern in the defensive linter:

1. **Do not disclose the vulnerability publicly.**
2. Send an email to the Logihertz Security Team at: **security@logihertz.com**.
3. Include:
   - Detailed description of the issue or bypass vector.
   - Proof-of-concept (PoC) profile or HID script triggering the issue.
   - Recommended remediation if available.

We commit to acknowledging your report within 48 hours and providing regular updates throughout the triage and patch process.

