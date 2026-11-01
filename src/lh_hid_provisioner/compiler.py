"""Deterministic OS-specific HID keystroke automation script compiler."""

from lh_hid_provisioner.models import (
    NetworkConfig,
    NetworkMode,
    ServerProfile,
    SSHConfig,
    TargetOS,
)


class HIDScriptBuilder:
    """Helper to assemble DuckyScript / HID commands with deterministic delays."""

    def __init__(self, default_delay_ms: int = 100) -> None:
        self.lines: list[str] = []
        self.default_delay_ms = default_delay_ms
        self.add_command(f"DEFAULT_DELAY {default_delay_ms}")

    def add_comment(self, comment: str) -> None:
        """Add a comment line."""
        self.lines.append(f"REM {comment}")

    def add_blank(self) -> None:
        """Add an empty separator line."""
        self.lines.append("")

    def add_command(self, cmd: str) -> None:
        """Add a raw HID script command."""
        self.lines.append(cmd)

    def add_delay(self, ms: int) -> None:
        """Add a millisecond delay."""
        self.lines.append(f"DELAY {ms}")

    def add_type_line(self, shell_command: str, delay_after_ms: int = 500) -> None:
        """Type a shell command line and press ENTER followed by a delay."""
        self.lines.append(f"STRING {shell_command}")
        self.lines.append("ENTER")
        if delay_after_ms > 0:
            self.lines.append(f"DELAY {delay_after_ms}")

    def build(self) -> str:
        """Return the compiled HID script as a single string."""
        return "\n".join(self.lines) + "\n"


def _compile_debian_networking(builder: HIDScriptBuilder, net: NetworkConfig) -> None:
    builder.add_comment("Configure networking (/etc/network/interfaces)")
    builder.add_type_line("cat << 'EOF' > /etc/network/interfaces")
    builder.add_type_line("auto lo")
    builder.add_type_line("iface lo inet loopback")
    builder.add_type_line("")
    builder.add_type_line(f"auto {net.interface}")

    if net.mode == NetworkMode.STATIC:
        builder.add_type_line(f"iface {net.interface} inet static")
        if net.address:
            builder.add_type_line(f"    address {net.address}")
        if net.gateway:
            builder.add_type_line(f"    gateway {net.gateway}")
    else:
        builder.add_type_line(f"iface {net.interface} inet dhcp")

    builder.add_type_line("EOF")

    if net.nameservers:
        builder.add_comment("Configure DNS nameservers (/etc/resolv.conf)")
        builder.add_type_line("rm -f /etc/resolv.conf")
        for ns in net.nameservers:
            builder.add_type_line(f'echo "nameserver {ns}" >> /etc/resolv.conf')

    builder.add_comment("Restart networking subsystem")
    builder.add_type_line("systemctl restart networking || ifreload -a", delay_after_ms=1500)


def _compile_ubuntu_networking(builder: HIDScriptBuilder, net: NetworkConfig) -> None:
    builder.add_comment("Configure networking via Netplan (/etc/netplan/01-netcfg.yaml)")
    builder.add_type_line("mkdir -p /etc/netplan")
    builder.add_type_line("cat << 'EOF' > /etc/netplan/01-netcfg.yaml")
    builder.add_type_line("network:")
    builder.add_type_line("  version: 2")
    builder.add_type_line("  renderer: networkd")
    builder.add_type_line("  ethernets:")
    builder.add_type_line(f"    {net.interface}:")

    if net.mode == NetworkMode.STATIC:
        if net.address:
            builder.add_type_line(f"      addresses: [{net.address}]")
        if net.gateway:
            builder.add_type_line("      routes:")
            builder.add_type_line("        - to: default")
            builder.add_type_line(f"          via: {net.gateway}")
        if net.nameservers:
            ns_list = ", ".join(f'"{ns}"' for ns in net.nameservers)
            builder.add_type_line("      nameservers:")
            builder.add_type_line(f"        addresses: [{ns_list}]")
    else:
        builder.add_type_line("      dhcp4: true")

    builder.add_type_line("EOF")
    builder.add_comment("Apply Netplan configuration")
    builder.add_type_line("netplan apply", delay_after_ms=2000)


def _compile_alpine_networking(builder: HIDScriptBuilder, net: NetworkConfig) -> None:
    builder.add_comment("Configure networking (/etc/network/interfaces)")
    builder.add_type_line("cat << 'EOF' > /etc/network/interfaces")
    builder.add_type_line("auto lo")
    builder.add_type_line("iface lo inet loopback")
    builder.add_type_line("")
    builder.add_type_line(f"auto {net.interface}")

    if net.mode == NetworkMode.STATIC:
        builder.add_type_line(f"iface {net.interface} inet static")
        if net.address:
            builder.add_type_line(f"    address {net.address}")
        if net.gateway:
            builder.add_type_line(f"    gateway {net.gateway}")
    else:
        builder.add_type_line(f"iface {net.interface} inet dhcp")

    builder.add_type_line("EOF")

    if net.nameservers:
        builder.add_comment("Configure DNS nameservers (/etc/resolv.conf)")
        builder.add_type_line("rm -f /etc/resolv.conf")
        for ns in net.nameservers:
            builder.add_type_line(f'echo "nameserver {ns}" >> /etc/resolv.conf')

    builder.add_comment("Restart Alpine networking service")
    builder.add_type_line("/etc/init.d/networking restart", delay_after_ms=1500)


def _compile_ssh(builder: HIDScriptBuilder, ssh: SSHConfig, target_os: TargetOS) -> None:
    builder.add_comment("Setup SSH directories and authorized public keys")
    builder.add_type_line("mkdir -p -m 700 /root/.ssh")
    builder.add_type_line("rm -f /root/.ssh/authorized_keys")

    for key in ssh.authorized_keys:
        builder.add_type_line(f'echo "{key}" >> /root/.ssh/authorized_keys')

    builder.add_type_line("chmod 600 /root/.ssh/authorized_keys")

    if ssh.disable_root_password_login:
        builder.add_comment("Harden SSH configuration: prohibit root password login")
        builder.add_type_line(
            "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' "
            "/etc/ssh/sshd_config"
        )

    if ssh.sshd_port != 22:
        builder.add_comment(f"Configure SSH listening port ({ssh.sshd_port})")
        builder.add_type_line(
            f"sed -i 's/^#\\?Port .*/Port {ssh.sshd_port}/' /etc/ssh/sshd_config"
        )

    builder.add_comment("Enable and restart SSH service")
    if target_os == TargetOS.ALPINE:
        builder.add_type_line(
            "rc-update add sshd default && rc-service sshd restart", delay_after_ms=1000
        )
    else:
        builder.add_type_line("systemctl enable --now ssh", delay_after_ms=1000)


def _compile_packages(builder: HIDScriptBuilder, packages: list[str], target_os: TargetOS) -> None:
    if not packages:
        return

    pkg_str = " ".join(packages)
    builder.add_comment(f"Install provisioning packages: {pkg_str}")

    if target_os == TargetOS.ALPINE:
        builder.add_type_line(f"apk update && apk add {pkg_str}", delay_after_ms=3000)
    else:
        builder.add_type_line(
            "export DEBIAN_FRONTEND=noninteractive && "
            f"apt-get update -y && apt-get install -y {pkg_str}",
            delay_after_ms=3000,
        )


def _compile_sysctl(
    builder: HIDScriptBuilder, sysctl: dict[str, int | str], target_os: TargetOS
) -> None:
    if not sysctl:
        return

    builder.add_comment("Apply kernel sysctl hardening configuration")
    builder.add_type_line("mkdir -p /etc/sysctl.d")
    builder.add_type_line("cat << 'EOF' > /etc/sysctl.d/99-hardening.conf")
    for key, val in sorted(sysctl.items()):
        builder.add_type_line(f"{key} = {val}")
    builder.add_type_line("EOF")

    if target_os == TargetOS.ALPINE:
        builder.add_type_line("sysctl -p /etc/sysctl.d/99-hardening.conf", delay_after_ms=1000)
    else:
        builder.add_type_line("sysctl --system", delay_after_ms=1000)


def compile_profile(profile: ServerProfile, target_os: TargetOS) -> str:
    """Compile declarative ServerProfile into deterministic HID keystroke automation script.

    Args:
        profile: Validated ServerProfile instance.
        target_os: Target OS (Debian, Ubuntu, or Alpine).

    Returns:
        String containing complete DuckyScript HID automation script.
    """
    builder = HIDScriptBuilder(default_delay_ms=100)

    # Header block
    builder.add_comment("========================================================")
    builder.add_comment("Logihertz Systems OPC Pvt Ltd - HID Server Provisioning")
    builder.add_comment(f"Target OS: {target_os.value}")
    builder.add_comment(f"Hostname:  {profile.hostname}")
    builder.add_comment(f"Timezone:  {profile.timezone}")
    builder.add_comment("========================================================")
    builder.add_blank()

    # Initial registration delay
    builder.add_comment("Initial delay for OS USB HID enumeration")
    builder.add_delay(1000)
    builder.add_blank()

    # Hostname & Timezone
    builder.add_comment("Configure Hostname and Timezone")
    if target_os == TargetOS.ALPINE:
        builder.add_type_line(
            f'echo "{profile.hostname}" > /etc/hostname && hostname -F /etc/hostname'
        )
        builder.add_type_line(
            f'ln -sf "/usr/share/zoneinfo/{profile.timezone}" /etc/localtime && '
            f'echo "{profile.timezone}" > /etc/timezone'
        )
        builder.add_type_line(f'echo "export LANG={profile.locale}" > /etc/profile.d/locale.sh')
    else:
        builder.add_type_line(
            f'hostnamectl set-hostname "{profile.hostname}" || '
            f'echo "{profile.hostname}" > /etc/hostname'
        )
        builder.add_type_line(
            f'timedatectl set-timezone "{profile.timezone}" || '
            f'ln -sf "/usr/share/zoneinfo/{profile.timezone}" /etc/localtime'
        )
        builder.add_type_line(
            f'localectl set-locale LANG="{profile.locale}" || '
            f'echo "LANG={profile.locale}" > /etc/default/locale'
        )
    builder.add_blank()

    # Networking
    if target_os == TargetOS.DEBIAN:
        _compile_debian_networking(builder, profile.networking)
    elif target_os == TargetOS.UBUNTU:
        _compile_ubuntu_networking(builder, profile.networking)
    elif target_os == TargetOS.ALPINE:
        _compile_alpine_networking(builder, profile.networking)
    builder.add_blank()

    # SSH
    _compile_ssh(builder, profile.ssh, target_os)
    builder.add_blank()

    # Packages
    _compile_packages(builder, profile.packages, target_os)
    builder.add_blank()

    # Sysctl
    _compile_sysctl(builder, profile.sysctl, target_os)
    builder.add_blank()

    # Synchronization and completion marker
    builder.add_comment("Sync filesystem changes and verify completion")
    builder.add_type_line('sync && echo "=== LOGIHERTZ_PROVISIONING_COMPLETE ==="')
    builder.add_delay(500)

    return builder.build()
