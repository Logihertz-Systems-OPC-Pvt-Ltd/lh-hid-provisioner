# ==============================================================================
# Product:       lh-hid-provisioner (lh-provision)
# Module:        src.lh_hid_provisioner.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Core data models and enums for lh-hid-provisioner."""

from dataclasses import dataclass, field
from enum import StrEnum


class TargetOS(StrEnum):
    """Supported target operating systems for HID provisioning."""

    DEBIAN = "debian"
    UBUNTU = "ubuntu"
    ALPINE = "alpine"


class NetworkMode(StrEnum):
    """Network configuration modes."""

    DHCP = "dhcp"
    STATIC = "static"


class OutputFormat(StrEnum):
    """Supported report output formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class Severity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Linter finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def is_error_level(self) -> bool:
        """Return True if severity represents an error/blocking level."""
        return self in (Severity.HIGH, Severity.CRITICAL)

    @property
    def sarif_level(self) -> str:
        """Map severity to SARIF v2.1.0 result level."""
        match self:
            case Severity.CRITICAL | Severity.HIGH:
                return "error"
            case Severity.MEDIUM:
                return "warning"
            case Severity.LOW | Severity.INFO:
                return "note"


@dataclass
class NetworkConfig:
    """Network interface configuration."""

    interface: str
    mode: NetworkMode = NetworkMode.DHCP
    address: str | None = None
    gateway: str | None = None
    nameservers: list[str] = field(default_factory=list)


@dataclass
class SSHConfig:
    """SSH service and authentication configuration."""

    authorized_keys: list[str] = field(default_factory=list)
    disable_root_password_login: bool = True
    sshd_port: int = 22


@dataclass
class ServerProfile:
    """Declarative YAML server provisioning profile."""

    version: str
    hostname: str
    locale: str
    networking: NetworkConfig
    ssh: SSHConfig
    timezone: str = "UTC"
    packages: list[str] = field(default_factory=list)
    sysctl: dict[str, int | str] = field(default_factory=dict)


@dataclass
class LintFinding:
    """A single diagnostic finding from the HID script linter."""

    rule_id: str
    rule_name: str
    severity: Severity
    line_number: int
    message: str
    code_snippet: str
    suggestion: str | None = None


@dataclass
class LintReport:
    """Diagnostic report aggregating all lint findings for an HID script."""

    file_path: str
    findings: list[LintFinding] = field(default_factory=list)

    @property
    def total_issues(self) -> int:
        """Return total count of diagnostic findings."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Count of INFO severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def has_failures(self, strict: bool = False) -> bool:
        """Determine if report contains failures that should fail the build/check.

        In strict mode, any finding (including warning/info) is considered a failure.
        In normal mode, only HIGH and CRITICAL findings trigger failure.
        """
        if strict:
            return len(self.findings) > 0
        return any(f.severity.is_error_level for f in self.findings)
