"""HID script syntax and defensive security guardrail linter."""

import re
from pathlib import Path

from lh_hid_provisioner.models import LintFinding, LintReport, Severity

# Valid HID Script keywords & keys (Standard DuckyScript / USB HID primitives)
VALID_COMMAND_KEYWORDS = {
    "REM",
    "//",
    "DELAY",
    "DEFAULT_DELAY",
    "DEFAULTDELAY",
    "STRING",
    "STRINGLN",
    "ENTER",
    "REPEAT",
    # Modifiers
    "GUI",
    "WINDOWS",
    "COMMAND",
    "MENU",
    "APP",
    "SHIFT",
    "ALT",
    "CONTROL",
    "CTRL",
    # Navigation & control keys
    "ARROWUP",
    "UP",
    "ARROWDOWN",
    "DOWN",
    "ARROWLEFT",
    "LEFT",
    "ARROWRIGHT",
    "RIGHT",
    "PAGEUP",
    "PAGEDOWN",
    "HOME",
    "END",
    "INSERT",
    "DELETE",
    "BACKSPACE",
    "TAB",
    "ESCAPE",
    "ESC",
    "SPACE",
    "CAPSLOCK",
    "PRINTSCREEN",
    "SCROLLLOCK",
    "PAUSE",
    "BREAK",
}

# Add function keys F1-F24
for i in range(1, 25):
    VALID_COMMAND_KEYWORDS.add(f"F{i}")

# Valid key combination prefixes
VALID_MODIFIERS = {"CTRL", "CONTROL", "ALT", "SHIFT", "GUI", "WINDOWS", "COMMAND"}

# Dangerous filesystem command patterns (SEC-001)
DESTRUCTIVE_PATTERNS = [
    (
        re.compile(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*|--recursive)\s+.*(/\s*$|/\*|--no-preserve-root|\~|\$HOME)",
            re.IGNORECASE,
        ),
        "Destructive recursive deletion of system root or home directory.",
    ),
    (
        re.compile(
            r"\b(mkfs(\.[a-z0-9]+)?)\s+/dev/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])",
            re.IGNORECASE,
        ),
        "Direct disk format command targeting system storage device.",
    ),
    (
        re.compile(
            r"\bdd\s+if=/dev/(zero|urandom)\s+of=/dev/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])",
            re.IGNORECASE,
        ),
        "Destructive raw disk block overwrite via dd.",
    ),
    (
        re.compile(r">\s*/dev/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])", re.IGNORECASE),
        "Raw shell redirection wiping storage block device.",
    ),
    (
        re.compile(
            r"\bshred\s+(-[a-zA-Z0-9]+\s+)?/dev/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])",
            re.IGNORECASE,
        ),
        "Storage device wipe via shred.",
    ),
    (
        re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
        "Denial-of-service fork bomb detected.",
    ),
]

# Reverse shell command patterns (SEC-002)
REVERSE_SHELL_PATTERNS = [
    (
        re.compile(r"/dev/(tcp|udp)/[a-zA-Z0-9_.-]+/\d+", re.IGNORECASE),
        "Bash/sh network redirection reverse shell.",
    ),
    (
        re.compile(
            r"\bn?(cat|c)\s+.*-[ec]\s+(/bin/)?(bash|sh|zsh|dash)",
            re.IGNORECASE,
        ),
        "Netcat reverse shell with command execution flag (-e / -c).",
    ),
    (
        re.compile(r"\bsocat\s+.*(exec:|tcp-connect:)", re.IGNORECASE),
        "Socat reverse shell or TCP redirector execution.",
    ),
    (
        re.compile(r"\b(mkfifo\s+.*\|\s*(/bin/)?(bash|sh)|mknod\s+.*p\b)", re.IGNORECASE),
        "Named pipe / FIFO reverse shell pipeline.",
    ),
    (
        re.compile(r"python[23]?\s+-c\s+.*socket.*connect", re.IGNORECASE),
        "Python socket reverse shell one-liner.",
    ),
    (
        re.compile(r"perl\s+-e\s+.*Socket.*connect", re.IGNORECASE),
        "Perl Socket reverse shell one-liner.",
    ),
    (
        re.compile(r"ruby\s+-e\s+.*TCPSocket", re.IGNORECASE),
        "Ruby TCPSocket reverse shell one-liner.",
    ),
    (
        re.compile(r"php\s+-r\s+.*fsockopen", re.IGNORECASE),
        "PHP fsockopen reverse shell one-liner.",
    ),
]

# Credential exfiltration patterns (SEC-003)
EXFIL_PATTERNS = [
    (
        re.compile(
            r"\bcurl\s+.*(-d|--data|--data-binary|--data-raw|--upload-file|-T)\s+.*(/etc/shadow|/etc/gshadow|id_rsa|id_ed25519|\.aws/credentials)",
            re.IGNORECASE,
        ),
        "Sensitive credential exfiltration via curl POST/upload.",
    ),
    (
        re.compile(r"\bcurl\s+.*@/etc/(shadow|gshadow)", re.IGNORECASE),
        "Exfiltration of system password hash database via curl @/etc/shadow.",
    ),
    (
        re.compile(
            r"\bwget\s+.*--post-(file|data)=.*(/etc/shadow|/etc/gshadow|id_rsa|id_ed25519)",
            re.IGNORECASE,
        ),
        "Sensitive credential exfiltration via wget POST.",
    ),
    (
        re.compile(
            r"\bcat\s+.*(/etc/shadow|/etc/gshadow|id_rsa|id_ed25519)\s*\|\s*(curl|wget|nc|ncat|socat)",
            re.IGNORECASE,
        ),
        "Exfiltration pipeline streaming credentials into network client.",
    ),
    (
        re.compile(
            r"\bn?(c|cat)\s+.*<\s*(/etc/shadow|/etc/gshadow|id_rsa|id_ed25519)",
            re.IGNORECASE,
        ),
        "Exfiltration of credentials via netcat stdin redirection.",
    ),
]

# Unchecked remote script execution (SEC-004)
REMOTE_PIPE_PATTERNS = [
    (
        re.compile(r"\bcurl\s+[^|\n]+?\|\s*(sudo\s+)?(bash|sh|zsh)\b", re.IGNORECASE),
        "Unchecked remote script piped directly from curl into shell interpreter.",
    ),
    (
        re.compile(r"\bwget\s+[^|\n]+?\|\s*(sudo\s+)?(bash|sh|zsh)\b", re.IGNORECASE),
        "Unchecked remote script piped directly from wget into shell interpreter.",
    ),
]


def find_unquoted_shell_variables(cmd: str) -> list[str]:
    """Identify unquoted shell variable expansions like $VAR or ${VAR}.

    Safe patterns such as "$VAR", '${VAR}', arithmetic $((...)), escaped \\$VAR,
    and numeric/special parameters ($?, $$, $!, $#, $0) are ignored.

    Args:
        cmd: Shell command string.

    Returns:
        List of unquoted variable references found.
    """
    unquoted: list[str] = []
    i = 0
    n = len(cmd)
    in_single_quote = False
    in_double_quote = False

    var_pattern = re.compile(r"^\$([a-zA-Z_][a-zA-Z0-9_]*|\{[a-zA-Z_][a-zA-Z0-9_]*\})")

    while i < n:
        char = cmd[i]

        # Handle escape character
        if char == "\\":
            i += 2
            continue

        # Toggle single quotes
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            i += 1
            continue

        # Toggle double quotes
        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            i += 1
            continue

        # Check for variable outside quotes
        if char == "$" and not in_single_quote and not in_double_quote:
            # Check if arithmetic expansion $((...))
            if i + 1 < n and cmd[i + 1] == "(":
                # skip $(...) or $((...))
                i += 2
                continue

            match = var_pattern.match(cmd[i:])
            if match:
                var_name = match.group(0)
                unquoted.append(var_name)
                i += len(var_name)
                continue

        i += 1

    return unquoted


def lint_script(content_or_path: str | Path) -> LintReport:
    """Lint an HID keystroke automation script for syntax compliance and security guardrails.

    Args:
        content_or_path: Script content string or path to .txt script.

    Returns:
        LintReport with all identified findings.
    """
    file_path = "<string>"
    raw_content: str

    if isinstance(content_or_path, Path) or (
        isinstance(content_or_path, str)
        and not ("\n" in content_or_path or "\r" in content_or_path)
    ):
        path = Path(content_or_path)
        if path.is_file():
            file_path = str(path)
            raw_content = path.read_text(encoding="utf-8")
        else:
            raw_content = str(content_or_path)
    else:
        raw_content = str(content_or_path)

    lines = raw_content.splitlines()
    findings: list[LintFinding] = []

    has_default_delay = False
    last_action_line: int | None = None
    last_action_type: str | None = None

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip empty lines
        if not stripped:
            continue

        # Comments
        if stripped.startswith("REM") or stripped.startswith("//"):
            continue

        parts = stripped.split(maxsplit=1)
        command_prefix = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""

        # Check SYN-001 (Invalid Command)
        is_valid_command = False
        if command_prefix in VALID_COMMAND_KEYWORDS:
            is_valid_command = True
        elif command_prefix in VALID_MODIFIERS:
            # Combo like "CTRL ALT t" or "GUI r"
            is_valid_command = True

        if not is_valid_command:
            findings.append(
                LintFinding(
                    rule_id="SYN-001",
                    rule_name="Invalid HID Command",
                    severity=Severity.HIGH,
                    line_number=idx,
                    message=f"Unrecognized HID script command '{command_prefix}'.",
                    code_snippet=stripped,
                    suggestion=(
                        "Ensure line begins with a valid HID command (e.g., STRING, DELAY, ENTER) "
                        "or valid key modifier combination."
                    ),
                )
            )
            continue

        # Check SYN-003 (Malformed Delay)
        if command_prefix in ("DELAY", "DEFAULT_DELAY", "DEFAULTDELAY"):
            if command_prefix in ("DEFAULT_DELAY", "DEFAULTDELAY"):
                has_default_delay = True

            if not rest:
                findings.append(
                    LintFinding(
                        rule_id="SYN-003",
                        rule_name="Malformed Delay",
                        severity=Severity.HIGH,
                        line_number=idx,
                        message=f"{command_prefix} requires an integer millisecond parameter.",
                        code_snippet=stripped,
                        suggestion=f"Specify positive milliseconds, e.g., '{command_prefix} 500'.",
                    )
                )
            else:
                try:
                    delay_val = int(rest)
                    if delay_val <= 0:
                        findings.append(
                            LintFinding(
                                rule_id="SYN-003",
                                rule_name="Malformed Delay",
                                severity=Severity.HIGH,
                                line_number=idx,
                                message=(
                                    f"{command_prefix} value must be positive integer (> 0), "
                                    f"got: {delay_val}."
                                ),
                                code_snippet=stripped,
                                suggestion="Provide a positive integer delay value (e.g. 500).",
                            )
                        )
                except ValueError:
                    findings.append(
                        LintFinding(
                            rule_id="SYN-003",
                            rule_name="Malformed Delay",
                            severity=Severity.HIGH,
                            line_number=idx,
                            message=f"{command_prefix} parameter '{rest}' is not a valid integer.",
                            code_snippet=stripped,
                            suggestion="Ensure delay parameter contains only digits (e.g., 500).",
                        )
                    )

            # Delay encountered - reset last action tracker
            last_action_line = None
            last_action_type = None
            continue

        # Check SYN-002 (Missing Inter-Command Delay)
        if command_prefix in ("STRING", "STRINGLN", "ENTER"):
            if not has_default_delay and last_action_line is not None:
                # Two consecutive execution lines without delay
                is_enter_then_string = (
                    last_action_type == "ENTER" and command_prefix in ("STRING", "STRINGLN")
                )
                is_consecutive_string = (
                    last_action_type in ("STRING", "STRINGLN")
                    and command_prefix in ("STRING", "STRINGLN")
                )
                if is_enter_then_string or is_consecutive_string:
                    findings.append(
                        LintFinding(
                            rule_id="SYN-002",
                            rule_name="Missing Inter-Command Delay",
                            severity=Severity.MEDIUM,
                            line_number=idx,
                            message=(
                                f"Command on line {idx} immediately follows action on line "
                                f"{last_action_line} without an intervening DELAY or DEFAULT_DELAY."
                            ),
                            code_snippet=stripped,
                            suggestion=(
                                "Insert 'DELAY <ms>' between command executions or "
                                "declare 'DEFAULT_DELAY 100' at start of script."
                            ),
                        )
                    )
            last_action_line = idx
            last_action_type = command_prefix
        else:
            last_action_line = None
            last_action_type = None

        # Deep inspection of STRING / STRINGLN payloads
        if command_prefix in ("STRING", "STRINGLN"):
            payload = rest

            # Check SYN-004 (Unsafe Unquoted Shell Variables)
            unquoted_vars = find_unquoted_shell_variables(payload)
            if unquoted_vars:
                var_list_str = ", ".join(unquoted_vars)
                findings.append(
                    LintFinding(
                        rule_id="SYN-004",
                        rule_name="Unsafe Unquoted Shell Variable",
                        severity=Severity.MEDIUM,
                        line_number=idx,
                        message=f"Unquoted shell variable(s) detected: {var_list_str}.",
                        code_snippet=stripped,
                        suggestion=f'Wrap variables in double quotes, e.g. "{unquoted_vars[0]}".',
                    )
                )

            # Check SEC-001 (Destructive Filesystem Commands)
            for pattern, desc in DESTRUCTIVE_PATTERNS:
                if pattern.search(payload):
                    findings.append(
                        LintFinding(
                            rule_id="SEC-001",
                            rule_name="Destructive Filesystem Command",
                            severity=Severity.CRITICAL,
                            line_number=idx,
                            message=f"{desc} Payload: '{payload}'",
                            code_snippet=stripped,
                            suggestion="Remove destructive disk or filesystem commands.",
                        )
                    )

            # Check SEC-002 (Reverse Shell Patterns)
            for pattern, desc in REVERSE_SHELL_PATTERNS:
                if pattern.search(payload):
                    findings.append(
                        LintFinding(
                            rule_id="SEC-002",
                            rule_name="Reverse Shell Pattern",
                            severity=Severity.CRITICAL,
                            line_number=idx,
                            message=f"{desc} Payload: '{payload}'",
                            code_snippet=stripped,
                            suggestion="Remove reverse shell listener/redirector from script.",
                        )
                    )

            # Check SEC-003 (Credential Exfiltration Patterns)
            for pattern, desc in EXFIL_PATTERNS:
                if pattern.search(payload):
                    findings.append(
                        LintFinding(
                            rule_id="SEC-003",
                            rule_name="Credential Exfiltration Pattern",
                            severity=Severity.CRITICAL,
                            line_number=idx,
                            message=f"{desc} Payload: '{payload}'",
                            code_snippet=stripped,
                            suggestion="Prevent transmission of sensitive credential stores.",
                        )
                    )

            # Check SEC-004 (Unchecked Remote Script Execution)
            for pattern, desc in REMOTE_PIPE_PATTERNS:
                if pattern.search(payload):
                    findings.append(
                        LintFinding(
                            rule_id="SEC-004",
                            rule_name="Unchecked Remote Script Execution",
                            severity=Severity.HIGH,
                            line_number=idx,
                            message=f"{desc} Payload: '{payload}'",
                            code_snippet=stripped,
                            suggestion=(
                                "Download scripts to a local file, verify checksum, and "
                                "execute explicitly."
                            ),
                        )
                    )

    return LintReport(file_path=file_path, findings=findings)
