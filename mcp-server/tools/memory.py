"""
VALKYRIE MCP Server — Memory Analysis Tools

Wraps Volatility 3 for memory dump analysis with a strict plugin allowlist.
Only approved plugins can be executed — the LLM cannot run arbitrary
Volatility commands.

Plugin-specific output parsers convert raw Volatility text into structured JSON.

All execution goes through safe_subprocess (shell=False, denylist check, SHA256 audit).
"""

import os
import re
from typing import Any

from parsers.common import (
    build_tool_response,
    safe_subprocess,
    truncate_rows,
    MAX_OUTPUT_ROWS,
)

# Strict allowlist of Volatility 3 plugins the MCP server can execute.
# This is an ARCHITECTURAL constraint — adding plugins requires a code change.
ALLOWED_PLUGINS: dict[str, str] = {
    "pslist": "windows.pslist.PsList",
    "pstree": "windows.pstree.PsTree",
    "netscan": "windows.netscan.NetScan",
    "malfind": "windows.malfind.Malfind",
    "handles": "windows.handles.Handles",
    "dlllist": "windows.dlllist.DllList",
    "cmdline": "windows.cmdline.CmdLine",
    "filescan": "windows.filescan.FileScan",
    "hivelist": "windows.registry.hivelist.HiveList",
    "timeliner": "timeliner.Timeliner",
}

# Arguments that are blocked even for allowed plugins
BLOCKED_PLUGIN_ARGS = {
    "--dump",  # Dumping memory regions to disk can be very large
    "--write",
    "-D",  # Dump directory for some plugins
}


def analyze_memory(
    dump_path: str,
    plugin: str,
    pid: int | None = None,
    extra_args: list[str] | None = None,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Analyze a memory dump using Volatility 3.

    Args:
        dump_path: Path to the memory dump file.
        plugin: Plugin name (must be in ALLOWED_PLUGINS).
        pid: Optional PID filter.
        extra_args: Additional safe arguments.
        case_dir: Case directory for audit logging.
    """
    # Validate plugin against allowlist
    if plugin not in ALLOWED_PLUGINS:
        return build_tool_response(
            tool_name="analyze_memory",
            data=None,
            evidence_file=dump_path,
            error=(
                f"Plugin '{plugin}' is not in the allowlist. "
                f"Allowed plugins: {', '.join(sorted(ALLOWED_PLUGINS.keys()))}"
            ),
        )

    if not os.path.isfile(dump_path):
        return build_tool_response(
            tool_name="analyze_memory",
            data=None,
            evidence_file=dump_path,
            error=f"Memory dump not found: {dump_path}",
        )

    # Validate extra_args against blocked arguments
    if extra_args:
        for arg in extra_args:
            if arg in BLOCKED_PLUGIN_ARGS:
                return build_tool_response(
                    tool_name="analyze_memory",
                    data=None,
                    evidence_file=dump_path,
                    error=f"Blocked argument: '{arg}' is not allowed",
                )

    # Build the Volatility 3 command
    vol_plugin = ALLOWED_PLUGINS[plugin]
    args = [
        "-f", dump_path,
        vol_plugin,
    ]

    # Add PID filter if specified
    if pid is not None:
        args.extend(["--pid", str(pid)])

    # Add validated extra args
    if extra_args:
        args.extend(extra_args)

    result = safe_subprocess(
        "vol",  # Volatility 3 binary name on SIFT
        args,
        timeout=300,
        tool_name=f"analyze_memory:{plugin}",
        case_dir=case_dir,
    )

    # Volatility may also be installed as "vol.py" or "volatility3"
    if result["exit_code"] != 0 and "not found" in result.get("stderr", "").lower():
        for alt_binary in ["vol.py", "volatility3", "python3 -m volatility3"]:
            try:
                result = safe_subprocess(
                    alt_binary,
                    args,
                    timeout=300,
                    tool_name=f"analyze_memory:{plugin}",
                    case_dir=case_dir,
                )
                if result["exit_code"] == 0:
                    break
            except Exception:
                continue

    if result["exit_code"] != 0:
        return build_tool_response(
            tool_name="analyze_memory",
            data=None,
            evidence_file=dump_path,
            output_sha256=result["sha256"],
            duration_seconds=result["duration_seconds"],
            error=f"Volatility {plugin} failed (exit {result['exit_code']}): {result['stderr'][:500]}",
        )

    # Parse plugin-specific output
    parser = PLUGIN_PARSERS.get(plugin, _parse_generic_table)
    parsed_data = parser(result["stdout"])

    row_data = truncate_rows(parsed_data) if isinstance(parsed_data, list) else parsed_data

    return build_tool_response(
        tool_name="analyze_memory",
        data={
            "plugin": plugin,
            "vol_plugin": vol_plugin,
            "results": row_data["rows"] if isinstance(row_data, dict) else row_data,
            "total_results": row_data.get("total_rows", len(parsed_data)) if isinstance(row_data, dict) else len(parsed_data),
            "truncated": row_data.get("truncated", False) if isinstance(row_data, dict) else False,
            "pid_filter": pid,
        },
        evidence_file=dump_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


# --- Plugin-Specific Parsers ---

def _parse_generic_table(raw: str) -> list[dict[str, Any]]:
    """Parse Volatility's generic table output format.

    Volatility 3 outputs a header line followed by data rows separated
    by tabs or 2+ whitespace. This parser handles both formats.
    """
    lines = [l for l in raw.splitlines() if l.strip()]
    if len(lines) < 2:
        return []

    # Find the header line (first line that looks like column headers)
    header_idx = 0
    for i, line in enumerate(lines):
        if not line.startswith("Volatility") and not line.startswith("*"):
            header_idx = i
            break

    header_line = lines[header_idx].strip()

    # Detect delimiter: if tabs present, use tab; otherwise use 2+ whitespace
    use_tabs = "\t" in header_line
    if use_tabs:
        headers = [h.strip() for h in header_line.split("\t") if h.strip()]
    else:
        headers = re.split(r"\s{2,}", header_line)

    if not headers:
        return []

    rows = []
    for line in lines[header_idx + 1:]:
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("-"):
            continue

        if use_tabs:
            values = [v.strip() for v in line.split("\t")]
        else:
            values = re.split(r"\s{2,}", line, maxsplit=len(headers) - 1)

        if len(values) >= len(headers):
            rows.append(dict(zip(headers, values[:len(headers)])))
        elif values:
            padded = values + [""] * (len(headers) - len(values))
            rows.append(dict(zip(headers, padded)))

    return rows


def _parse_pslist(raw: str) -> list[dict[str, Any]]:
    """Parse pslist output into structured process records."""
    rows = _parse_generic_table(raw)

    # Normalize field names
    for row in rows:
        # Common pslist columns: PID, PPID, ImageFileName, Offset, Threads, Handles, ...
        if "PID" in row:
            try:
                row["PID"] = int(row["PID"])
            except (ValueError, TypeError):
                pass
        if "PPID" in row:
            try:
                row["PPID"] = int(row["PPID"])
            except (ValueError, TypeError):
                pass
        if "Threads" in row:
            try:
                row["Threads"] = int(row["Threads"])
            except (ValueError, TypeError):
                pass
        if "Handles" in row:
            try:
                row["Handles"] = int(row["Handles"])
            except (ValueError, TypeError):
                pass

    return rows


def _parse_netscan(raw: str) -> list[dict[str, Any]]:
    """Parse netscan output into structured network connection records."""
    rows = _parse_generic_table(raw)

    for row in rows:
        # Parse out local/foreign address:port pairs
        for addr_field in ("LocalAddr", "ForeignAddr", "Local Address", "Foreign Address"):
            val = row.get(addr_field, "")
            if ":" in val:
                parts = val.rsplit(":", 1)
                row[f"{addr_field}_ip"] = parts[0]
                try:
                    row[f"{addr_field}_port"] = int(parts[1])
                except (ValueError, IndexError):
                    row[f"{addr_field}_port"] = parts[1] if len(parts) > 1 else ""

        if "PID" in row:
            try:
                row["PID"] = int(row["PID"])
            except (ValueError, TypeError):
                pass

    return rows


def _parse_malfind(raw: str) -> list[dict[str, Any]]:
    """Parse malfind output into structured injection detection records."""
    entries = []
    current = None

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # New process entry
        if line.startswith("Process:"):
            if current:
                entries.append(current)
            current = {"raw_header": line, "hex_dump": [], "disassembly": []}
            # Parse: Process: explorer.exe Pid: 1234 Address: 0x12340000 Vad Tag: VadS ...
            pid_match = re.search(r"Pid:\s*(\d+)", line)
            proc_match = re.search(r"Process:\s*(\S+)", line)
            addr_match = re.search(r"Address:\s*(0x[0-9a-fA-F]+)", line)
            prot_match = re.search(r"Protection:\s*(\S+)", line)

            if proc_match:
                current["process"] = proc_match.group(1)
            if pid_match:
                current["pid"] = int(pid_match.group(1))
            if addr_match:
                current["address"] = addr_match.group(1)
            if prot_match:
                current["protection"] = prot_match.group(1)
        elif current and re.match(r"^0x[0-9a-fA-F]+", line):
            current["hex_dump"].append(line)
        elif current:
            current["disassembly"].append(line)

    if current:
        entries.append(current)

    # Check for MZ header (PE injection indicator)
    for entry in entries:
        hex_text = " ".join(entry.get("hex_dump", []))
        entry["has_mz_header"] = "4d 5a" in hex_text.lower() or "MZ" in hex_text
        entry["has_rwx"] = "PAGE_EXECUTE_READWRITE" in entry.get("protection", "")

    return entries


def _parse_cmdline(raw: str) -> list[dict[str, Any]]:
    """Parse cmdline output into process command line records."""
    entries = []
    current = None

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # Volatility 3 cmdline format:
        # PID    Process    Args
        # 4      System     Required memory at ... is not valid
        # 1234   explorer   C:\Windows\explorer.exe
        if re.match(r"^\d+\s+", line):
            parts = re.split(r"\s+", line, maxsplit=2)
            if len(parts) >= 2:
                entry = {
                    "pid": int(parts[0]),
                    "process": parts[1],
                    "cmdline": parts[2] if len(parts) > 2 else "",
                }
                entries.append(entry)

    return entries


# Map plugin names to their specific parsers
PLUGIN_PARSERS = {
    "pslist": _parse_pslist,
    "pstree": _parse_pslist,  # Same format as pslist
    "netscan": _parse_netscan,
    "malfind": _parse_malfind,
    "cmdline": _parse_cmdline,
    "handles": _parse_generic_table,
    "dlllist": _parse_generic_table,
    "filescan": _parse_generic_table,
    "hivelist": _parse_generic_table,
    "timeliner": _parse_generic_table,
}
