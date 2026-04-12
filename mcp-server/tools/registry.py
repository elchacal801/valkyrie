"""
VALKYRIE MCP Server — Registry Analysis Tools

Wraps registry parsing utilities:
- RegRipper (rip.pl): plugin-based registry analysis
- RECmd: registry key/value extraction

Provides two functions:
- get_registry_key: Read a specific key and its values
- check_persistence: Scan known persistence locations

All execution goes through safe_subprocess (shell=False, denylist check, SHA256 audit).
"""

import os
import re
from typing import Any

from parsers.common import (
    build_tool_response,
    safe_subprocess,
    truncate_rows,
)

# Known Windows persistence registry locations, organized by hive type.
# Used by check_persistence() to systematically scan for persistence mechanisms.
PERSISTENCE_KEYS: dict[str, list[dict[str, str]]] = {
    "ntuser": [
        {
            "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "description": "Programs that run at user logon",
            "mitre": "T1547.001",
        },
        {
            "key": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "description": "Programs that run once at next user logon",
            "mitre": "T1547.001",
        },
        {
            "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
            "description": "User shell folder paths (startup folder hijacking)",
            "mitre": "T1547.001",
        },
        {
            "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
            "description": "User shell folder paths (startup folder hijacking)",
            "mitre": "T1547.001",
        },
        {
            "key": "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "description": "Winlogon helper DLLs and scripts",
            "mitre": "T1547.004",
        },
        {
            "key": "Environment",
            "description": "User environment variables (PATH hijacking)",
            "mitre": "T1574.007",
        },
    ],
    "software": [
        {
            "key": "Microsoft\\Windows\\CurrentVersion\\Run",
            "description": "System-wide programs that run at logon",
            "mitre": "T1547.001",
        },
        {
            "key": "Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "description": "System-wide programs that run once at next boot",
            "mitre": "T1547.001",
        },
        {
            "key": "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "description": "Policy-based run keys",
            "mitre": "T1547.001",
        },
        {
            "key": "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "description": "Winlogon Shell and Userinit values",
            "mitre": "T1547.004",
        },
        {
            "key": "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            "description": "Image File Execution Options (debugger hijacking)",
            "mitre": "T1546.012",
        },
        {
            "key": "Classes\\*\\shellex\\ContextMenuHandlers",
            "description": "Shell extension context menu handlers",
            "mitre": "T1546",
        },
        {
            "key": "Microsoft\\Windows\\CurrentVersion\\App Paths",
            "description": "Application path overrides",
            "mitre": "T1574",
        },
    ],
    "system": [
        {
            "key": "ControlSet001\\Services",
            "description": "Windows services (service persistence)",
            "mitre": "T1543.003",
        },
        {
            "key": "ControlSet001\\Control\\Session Manager\\BootExecute",
            "description": "Boot execution programs",
            "mitre": "T1547.001",
        },
        {
            "key": "ControlSet001\\Control\\Session Manager\\KnownDLLs",
            "description": "Known DLLs list (DLL hijacking defense check)",
            "mitre": "T1574.001",
        },
        {
            "key": "ControlSet001\\Control\\SecurityProviders\\SecurityProviders",
            "description": "Security Support Providers (SSP persistence)",
            "mitre": "T1547.005",
        },
        {
            "key": "ControlSet001\\Control\\Lsa",
            "description": "LSA configuration (authentication package persistence)",
            "mitre": "T1547.002",
        },
        {
            "key": "ControlSet001\\Control\\Print\\Monitors",
            "description": "Print monitors (port monitor persistence)",
            "mitre": "T1547.010",
        },
        {
            "key": "ControlSet001\\Control\\TimeZoneInformation",
            "description": "System timezone (for timestamp analysis)",
            "mitre": "",
        },
    ],
    "sam": [
        {
            "key": "SAM\\Domains\\Account\\Users",
            "description": "Local user accounts",
            "mitre": "T1136.001",
        },
    ],
}


def get_registry_key(
    hive_path: str,
    key_path: str,
    recursive: bool = False,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Read a specific registry key and its values.

    Tries RegRipper first, falls back to RECmd.
    """
    if not os.path.isfile(hive_path):
        return build_tool_response(
            tool_name="get_registry_key",
            data=None,
            evidence_file=hive_path,
            error=f"Hive file not found: {hive_path}",
        )

    # Try RegRipper first
    result = _try_regripper(hive_path, key_path, case_dir=case_dir)
    if result is not None:
        return result

    # Fallback to RECmd
    result = _try_recmd(hive_path, key_path, recursive=recursive, case_dir=case_dir)
    if result is not None:
        return result

    return build_tool_response(
        tool_name="get_registry_key",
        data=None,
        evidence_file=hive_path,
        error="Neither RegRipper nor RECmd available on this system",
    )


def _try_regripper(
    hive_path: str,
    key_path: str,
    *,
    case_dir: str | None = None,
) -> dict[str, Any] | None:
    """Try to read a registry key using RegRipper."""
    try:
        result = safe_subprocess(
            "rip.pl",
            ["-r", hive_path, "-p", "all"],  # Run all relevant plugins
            timeout=120,
            tool_name="get_registry_key:regripper",
            case_dir=case_dir,
        )
    except Exception:
        return None

    if result["exit_code"] != 0:
        return None

    # Parse RegRipper output — look for the requested key
    entries = _parse_regripper_output(result["stdout"], key_path)

    return build_tool_response(
        tool_name="get_registry_key",
        data={
            "hive_path": hive_path,
            "key_path": key_path,
            "entries": entries,
            "entry_count": len(entries),
            "parser": "regripper",
        },
        evidence_file=hive_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _try_recmd(
    hive_path: str,
    key_path: str,
    recursive: bool = False,
    *,
    case_dir: str | None = None,
) -> dict[str, Any] | None:
    """Try to read a registry key using RECmd."""
    args = [
        "-f", hive_path,
        "--kn", key_path,
    ]
    if recursive:
        args.append("--recursive")

    try:
        result = safe_subprocess(
            "RECmd",
            args,
            timeout=120,
            tool_name="get_registry_key:recmd",
            case_dir=case_dir,
        )
    except Exception:
        return None

    if result["exit_code"] != 0:
        return None

    entries = _parse_recmd_output(result["stdout"])

    return build_tool_response(
        tool_name="get_registry_key",
        data={
            "hive_path": hive_path,
            "key_path": key_path,
            "entries": entries,
            "entry_count": len(entries),
            "parser": "recmd",
        },
        evidence_file=hive_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _parse_regripper_output(
    raw: str,
    target_key: str,
) -> list[dict[str, Any]]:
    """Parse RegRipper output, extracting entries relevant to the target key."""
    entries = []
    in_target_section = False
    current_entry: dict[str, Any] | None = None

    target_lower = target_key.lower().replace("/", "\\")

    for line in raw.splitlines():
        stripped = line.strip()

        # Check if we've entered a section matching our target key
        if target_lower in stripped.lower():
            in_target_section = True
            if current_entry:
                entries.append(current_entry)
            current_entry = {"key": stripped, "values": [], "last_written": ""}
            continue

        # Detect section boundaries
        if stripped.startswith("---") or (stripped and not stripped[0].isspace() and in_target_section):
            if current_entry and current_entry != entries[-1] if entries else True:
                if current_entry:
                    entries.append(current_entry)
            in_target_section = False
            current_entry = None
            continue

        if in_target_section and current_entry:
            # Parse "LastWrite Time" lines
            if "lastwrite" in stripped.lower() or "last written" in stripped.lower():
                time_match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", stripped)
                if time_match:
                    current_entry["last_written"] = time_match.group(1)
            elif stripped:
                # Parse value lines: "ValueName    REG_SZ    ValueData"
                current_entry["values"].append(stripped)

    if current_entry and (not entries or current_entry != entries[-1]):
        entries.append(current_entry)

    return entries


def _parse_recmd_output(raw: str) -> list[dict[str, Any]]:
    """Parse RECmd output into structured key/value records."""
    entries = []
    current_key = None

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Key path lines
        if stripped.startswith("Key:") or stripped.startswith("Path:"):
            if current_key:
                entries.append(current_key)
            current_key = {
                "key": stripped.split(":", 1)[1].strip(),
                "values": [],
                "last_written": "",
            }
        elif current_key:
            if "Last Write" in stripped:
                time_match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", stripped)
                if time_match:
                    current_key["last_written"] = time_match.group(1)
            elif stripped.startswith("Value:") or "REG_" in stripped:
                current_key["values"].append(stripped)

    if current_key:
        entries.append(current_key)

    return entries


def check_persistence(
    hive_path: str,
    hive_type: str,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Scan known persistence locations in a registry hive.

    Checks all known persistence keys for the specified hive type
    and returns entries found at each location.
    """
    if not os.path.isfile(hive_path):
        return build_tool_response(
            tool_name="check_persistence",
            data=None,
            evidence_file=hive_path,
            error=f"Hive file not found: {hive_path}",
        )

    hive_type = hive_type.lower()
    if hive_type not in PERSISTENCE_KEYS:
        return build_tool_response(
            tool_name="check_persistence",
            data=None,
            evidence_file=hive_path,
            error=f"Unknown hive type: '{hive_type}'. Valid types: {', '.join(PERSISTENCE_KEYS.keys())}",
        )

    keys_to_check = PERSISTENCE_KEYS[hive_type]
    results = []
    total_entries_found = 0

    for key_info in keys_to_check:
        key_result = get_registry_key(
            hive_path=hive_path,
            key_path=key_info["key"],
            case_dir=case_dir,
        )

        data = key_result.get("data") or {}
        entries = data.get("entries", [])
        has_entries = len(entries) > 0

        results.append({
            "key_path": key_info["key"],
            "description": key_info["description"],
            "mitre_attack": key_info["mitre"],
            "found": has_entries,
            "entry_count": len(entries),
            "entries": entries,
        })

        if has_entries:
            total_entries_found += len(entries)

    return build_tool_response(
        tool_name="check_persistence",
        data={
            "hive_path": hive_path,
            "hive_type": hive_type,
            "keys_checked": len(keys_to_check),
            "keys_with_entries": sum(1 for r in results if r["found"]),
            "total_entries_found": total_entries_found,
            "persistence_locations": results,
        },
        evidence_file=hive_path,
    )
