"""YAML server provisioning profile parser and strict schema validator."""

import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

from lh_hid_provisioner.models import NetworkConfig, NetworkMode, ServerProfile, SSHConfig

VALID_SSH_KEY_TYPES = {
    "ssh-rsa",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-dss",
}

HOSTNAME_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
INTERFACE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{1,16}$")
LOCALE_REGEX = re.compile(r"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)?(@[a-zA-Z0-9_-]+)?$")
SYSCTL_KEY_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+$")
PACKAGE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]+$")


class ProfileValidationError(ValueError):
    """Raised when profile validation fails against schema or safety requirements."""


def validate_hostname(hostname: str) -> str:
    """Validate RFC 1123 hostname syntax.

    Args:
        hostname: Hostname string to validate.

    Returns:
        The validated hostname.

    Raises:
        ProfileValidationError: If hostname format is invalid.
    """
    if not isinstance(hostname, str) or not hostname.strip():
        raise ProfileValidationError("Hostname must be a non-empty string.")

    cleaned = hostname.strip()
    if len(cleaned) > 253:
        raise ProfileValidationError(
            f"Hostname exceeds maximum length of 253 characters (got {len(cleaned)})."
        )

    # Check labels
    labels = cleaned.split(".")
    for label in labels:
        if not label:
            raise ProfileValidationError(f"Hostname contains empty segment: '{cleaned}'.")
        if not HOSTNAME_LABEL_REGEX.match(label):
            raise ProfileValidationError(
                f"Invalid hostname label '{label}'. Must be alphanumeric and 1-63 characters."
            )
    return cleaned


def validate_locale(locale: str) -> str:
    """Validate system locale identifier format.

    Args:
        locale: Locale identifier (e.g., 'en_US.UTF-8').

    Returns:
        The validated locale.

    Raises:
        ProfileValidationError: If locale identifier is malformed.
    """
    if not isinstance(locale, str) or not locale.strip():
        raise ProfileValidationError("Locale must be a non-empty string.")

    cleaned = locale.strip()
    if not LOCALE_REGEX.match(cleaned):
        raise ProfileValidationError(
            f"Invalid locale format: '{cleaned}'. Expected format like 'en_US.UTF-8' or 'C.UTF-8'."
        )
    return cleaned


def validate_network_config(data: dict[str, Any]) -> NetworkConfig:
    """Validate and construct NetworkConfig from dictionary.

    Args:
        data: Networking configuration dictionary.

    Returns:
        Validated NetworkConfig instance.

    Raises:
        ProfileValidationError: If network configuration parameters are invalid.
    """
    if not isinstance(data, dict):
        raise ProfileValidationError("Networking configuration must be a mapping/dictionary.")

    interface = data.get("interface")
    if not isinstance(interface, str) or not INTERFACE_NAME_REGEX.match(interface.strip()):
        raise ProfileValidationError(
            f"Invalid or missing network interface: '{interface}'. "
            "Must be 1-16 characters (e.g., 'eth0', 'ens3')."
        )
    interface = interface.strip()

    raw_mode = data.get("mode", "dhcp")
    if not isinstance(raw_mode, str):
        raise ProfileValidationError("Networking mode must be a string ('dhcp' or 'static').")

    mode_str = raw_mode.strip().lower()
    try:
        mode = NetworkMode(mode_str)
    except ValueError as err:
        raise ProfileValidationError(
            f"Invalid network mode: '{raw_mode}'. Supported modes are 'dhcp' or 'static'."
        ) from err

    address = None
    gateway = None
    nameservers: list[str] = []

    if mode == NetworkMode.STATIC:
        raw_address = data.get("address")
        if not raw_address or not isinstance(raw_address, str):
            raise ProfileValidationError(
                "Static networking mode requires a CIDR IP address (e.g., '192.168.1.50/24')."
            )
        try:
            # Validate CIDR format
            ipaddress.ip_interface(raw_address.strip())
            address = raw_address.strip()
        except ValueError as err:
            raise ProfileValidationError(
                f"Invalid static IP/CIDR address '{raw_address}': {err}"
            ) from err

        raw_gateway = data.get("gateway")
        if not raw_gateway or not isinstance(raw_gateway, str):
            raise ProfileValidationError(
                "Static networking mode requires a valid default gateway IP."
            )
        try:
            ipaddress.ip_address(raw_gateway.strip())
            gateway = raw_gateway.strip()
        except ValueError as err:
            raise ProfileValidationError(
                f"Invalid gateway IP address '{raw_gateway}': {err}"
            ) from err

        raw_nameservers = data.get("nameservers", [])
        if not isinstance(raw_nameservers, list):
            raise ProfileValidationError("Nameservers must be a list of IP address strings.")
        for ns in raw_nameservers:
            if not isinstance(ns, str):
                raise ProfileValidationError(f"Nameserver entry must be a string, got: {type(ns)}")
            try:
                ipaddress.ip_address(ns.strip())
                nameservers.append(ns.strip())
            except ValueError as err:
                raise ProfileValidationError(f"Invalid nameserver IP '{ns}': {err}") from err
    else:
        # DHCP mode can optionally specify nameservers
        raw_nameservers = data.get("nameservers", [])
        if isinstance(raw_nameservers, list):
            for ns in raw_nameservers:
                if isinstance(ns, str):
                    try:
                        ipaddress.ip_address(ns.strip())
                        nameservers.append(ns.strip())
                    except ValueError:
                        pass

    return NetworkConfig(
        interface=interface,
        mode=mode,
        address=address,
        gateway=gateway,
        nameservers=nameservers,
    )


def validate_ssh_config(data: dict[str, Any]) -> SSHConfig:
    """Validate and construct SSHConfig from dictionary.

    Args:
        data: SSH configuration dictionary.

    Returns:
        Validated SSHConfig instance.

    Raises:
        ProfileValidationError: If SSH parameters or public keys are invalid.
    """
    if not isinstance(data, dict):
        raise ProfileValidationError("SSH configuration must be a mapping/dictionary.")

    raw_keys = data.get("authorized_keys", [])
    if not isinstance(raw_keys, list):
        raise ProfileValidationError("authorized_keys must be a list of SSH public key strings.")

    validated_keys: list[str] = []
    for key_entry in raw_keys:
        if not isinstance(key_entry, str) or not key_entry.strip():
            raise ProfileValidationError("SSH public key entries must be non-empty strings.")
        key_str = key_entry.strip()
        parts = key_str.split()
        if len(parts) < 2:
            raise ProfileValidationError(
                f"Malformed SSH public key '{key_str[:30]}...'. Must contain key type and token."
            )
        key_type = parts[0]
        if key_type not in VALID_SSH_KEY_TYPES:
            valid_types = ", ".join(sorted(VALID_SSH_KEY_TYPES))
            raise ProfileValidationError(
                f"Unsupported SSH key type '{key_type}'. Supported types: {valid_types}"
            )
        validated_keys.append(key_str)

    disable_root_pw = data.get("disable_root_password_login", True)
    if not isinstance(disable_root_pw, bool):
        raise ProfileValidationError("disable_root_password_login must be a boolean.")

    sshd_port = data.get("sshd_port", 22)
    if not isinstance(sshd_port, int) or not (1 <= sshd_port <= 65535):
        raise ProfileValidationError(
            f"Invalid sshd_port: '{sshd_port}'. Must be integer between 1 and 65535."
        )

    return SSHConfig(
        authorized_keys=validated_keys,
        disable_root_password_login=disable_root_pw,
        sshd_port=sshd_port,
    )


def validate_packages(packages: Any) -> list[str]:
    """Validate list of packages to install.

    Args:
        packages: List of package name strings.

    Returns:
        Validated list of unique package names.

    Raises:
        ProfileValidationError: If package list or package names are invalid.
    """
    if packages is None:
        return []
    if not isinstance(packages, list):
        raise ProfileValidationError("packages must be a list of strings.")

    validated: list[str] = []
    for pkg in packages:
        if not isinstance(pkg, str) or not pkg.strip():
            raise ProfileValidationError("Package name must be a non-empty string.")
        pkg_name = pkg.strip()
        if not PACKAGE_NAME_REGEX.match(pkg_name):
            raise ProfileValidationError(
                f"Invalid package name '{pkg_name}'. Package names must be alphanumeric with +-_."
            )
        if pkg_name not in validated:
            validated.append(pkg_name)
    return validated


def validate_sysctl(sysctl_data: Any) -> dict[str, int | str]:
    """Validate kernel sysctl parameter key-value pairs.

    Args:
        sysctl_data: Mapping of sysctl keys to values.

    Returns:
        Validated sysctl dictionary.

    Raises:
        ProfileValidationError: If sysctl entries are malformed.
    """
    if sysctl_data is None:
        return {}
    if not isinstance(sysctl_data, dict):
        raise ProfileValidationError("sysctl must be a dictionary of key-value pairs.")

    validated: dict[str, int | str] = {}
    for key, val in sysctl_data.items():
        if not isinstance(key, str) or not SYSCTL_KEY_REGEX.match(key.strip()):
            raise ProfileValidationError(
                f"Invalid sysctl key '{key}'. Must be a valid dotted identifier."
            )
        if isinstance(val, bool):
            validated[key.strip()] = 1 if val else 0
        elif isinstance(val, (int, str)):
            validated[key.strip()] = val
        else:
            raise ProfileValidationError(
                f"Invalid sysctl value for key '{key}': {val}. Must be integer or string."
            )
    return validated


def parse_profile(content_or_path: str | Path) -> ServerProfile:
    """Parse and validate a declarative YAML server provisioning profile.

    Args:
        content_or_path: YAML string content or Path to YAML profile file.

    Returns:
        Validated ServerProfile instance.

    Raises:
        ProfileValidationError: If parsing or validation fails.
        FileNotFoundError: If path does not exist.
    """
    raw_content: str
    if isinstance(content_or_path, Path) or (
        isinstance(content_or_path, str) and not ("\n" in content_or_path or ":" in content_or_path)
    ):
        path = Path(content_or_path)
        if not path.is_file():
            raise FileNotFoundError(f"Profile file not found: {path}")
        try:
            raw_content = path.read_text(encoding="utf-8")
        except OSError as err:
            raise ProfileValidationError(f"Failed to read profile file '{path}': {err}") from err
    else:
        raw_content = str(content_or_path)

    try:
        data = yaml.safe_load(raw_content)
    except yaml.YAMLError as err:
        raise ProfileValidationError(f"Invalid YAML syntax: {err}") from err

    if not isinstance(data, dict):
        raise ProfileValidationError("Profile YAML root must be a mapping/dictionary.")

    version = str(data.get("version", "1"))
    hostname = validate_hostname(data.get("hostname", ""))
    locale = validate_locale(data.get("locale", "en_US.UTF-8"))
    timezone = str(data.get("timezone", "UTC")).strip()

    raw_net = data.get("networking")
    if raw_net is None:
        raise ProfileValidationError("Profile missing required 'networking' configuration section.")
    networking = validate_network_config(raw_net)

    raw_ssh = data.get("ssh")
    if raw_ssh is None:
        raise ProfileValidationError("Profile missing required 'ssh' configuration section.")
    ssh = validate_ssh_config(raw_ssh)

    packages = validate_packages(data.get("packages"))
    sysctl = validate_sysctl(data.get("sysctl"))

    return ServerProfile(
        version=version,
        hostname=hostname,
        locale=locale,
        timezone=timezone,
        networking=networking,
        ssh=ssh,
        packages=packages,
        sysctl=sysctl,
    )
