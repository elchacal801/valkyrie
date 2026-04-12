"""
VALKYRIE MCP Server — Command Denylist

Architectural enforcement layer that blocks destructive commands before execution.
This is NOT a prompt-based guardrail — the MCP server physically cannot execute
these commands regardless of what the LLM requests.
"""

# Binaries that must never be executed by the MCP server.
# These cover: data destruction, network exfiltration, remote access, and
# filesystem modification tools.
BLOCKED_BINARIES: set[str] = {
    # Data destruction
    "rm",
    "rmdir",
    "del",
    "shred",
    "wipe",
    "srm",
    # Disk modification
    "dd",
    "mkfs",
    "fdisk",
    "parted",
    "gdisk",
    "format",
    "diskpart",
    # Network / exfiltration
    "wget",
    "curl",
    "ssh",
    "scp",
    "rsync",
    "nc",
    "ncat",
    "netcat",
    "ftp",
    "sftp",
    "telnet",
    # System modification
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init",
    "systemctl",
    "kill",
    "killall",
    "pkill",
    # Package management (prevent installing anything)
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pip",
    "pip3",
    # Shell escalation
    "bash",
    "sh",
    "zsh",
    "fish",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
}

# Path prefixes that tools must never write to.
# Populated at runtime with the evidence directory path.
BLOCKED_WRITE_PATHS: set[str] = set()

# Arguments/flags that are blocked regardless of which binary is called.
BLOCKED_ARGUMENTS: set[str] = {
    "-exec",      # find -exec can run arbitrary commands
    "--exec",
    "-delete",    # find -delete removes files
    "-i",         # sed -i modifies files in place (when used with sed)
}


def check_binary(binary: str) -> str | None:
    """Check if a binary is on the denylist.

    Returns None if allowed, or a reason string if blocked.
    """
    # Normalize: strip path, lowercase
    name = binary.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()

    if name in BLOCKED_BINARIES:
        return f"Blocked binary: '{name}' is on the VALKYRIE denylist"
    return None


def check_arguments(binary: str, args: list[str]) -> str | None:
    """Check if any arguments are dangerous for the given binary.

    Returns None if allowed, or a reason string if blocked.
    """
    name = binary.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()

    # sed -i is dangerous (in-place file modification)
    if name == "sed" and "-i" in args:
        return "Blocked: 'sed -i' modifies files in place"

    # find -exec and -delete are dangerous
    if name == "find":
        for arg in args:
            if arg in ("-exec", "-execdir", "-delete", "-ok"):
                return f"Blocked: 'find {arg}' can modify or delete files"

    # tar extraction could overwrite files
    if name == "tar":
        for arg in args:
            if arg in ("-x", "--extract", "-C"):
                return "Blocked: 'tar' extraction can overwrite files"

    # awk system() can execute arbitrary commands
    if name in ("awk", "gawk", "mawk"):
        for arg in args:
            if "system(" in arg:
                return "Blocked: 'awk system()' can execute arbitrary commands"

    return None


def check_write_path(path: str) -> str | None:
    """Check if a path is in a protected (evidence) directory.

    Returns None if allowed, or a reason string if blocked.
    """
    import os
    normalized = os.path.normpath(os.path.abspath(path))

    for blocked in BLOCKED_WRITE_PATHS:
        blocked_norm = os.path.normpath(os.path.abspath(blocked))
        if normalized.startswith(blocked_norm):
            return f"Blocked: write to evidence directory '{blocked}'"
    return None


def register_evidence_path(path: str) -> None:
    """Register an evidence directory as write-protected.

    Called at server startup or when a new case is initialized.
    """
    BLOCKED_WRITE_PATHS.add(path)
