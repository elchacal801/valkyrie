"""
VALKYRIE MCP Server — Common Parsing Utilities

Shared infrastructure for all tool modules:
- safe_subprocess: Execute forensic tools with shell=False, denylist checks, and audit logging
- parse_csv_output: Parse CSV/TSV tool output into structured dicts
- truncate_output: Cap large result sets with summary statistics
- compute_sha256: Hash tool output for audit trail integrity
"""

import hashlib
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import denylist

logger = logging.getLogger("valkyrie.common")

# Maximum rows to return from tools that produce tabular output.
# Full output is written to the case working directory; only truncated
# results go back to the LLM to prevent context window overflow.
MAX_OUTPUT_ROWS = 500

# Maximum raw output size (bytes) to capture from a subprocess.
# Prevents memory exhaustion on tools that produce multi-GB output.
MAX_RAW_OUTPUT_BYTES = 50 * 1024 * 1024  # 50 MB

# Default subprocess timeout in seconds.
DEFAULT_TIMEOUT = 300  # 5 minutes


class ToolExecutionError(Exception):
    """Raised when a forensic tool fails to execute."""

    def __init__(self, tool: str, reason: str, exit_code: int | None = None):
        self.tool = tool
        self.reason = reason
        self.exit_code = exit_code
        super().__init__(f"{tool}: {reason}")


def compute_sha256(data: str | bytes) -> str:
    """Compute SHA256 hex digest of data."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def safe_subprocess(
    binary: str,
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    case_dir: str | None = None,
    tool_name: str = "",
) -> dict[str, Any]:
    """Execute a forensic tool safely with denylist enforcement and audit logging.

    All subprocess calls in the MCP server MUST go through this function.

    Args:
        binary: The executable to run (e.g., "mmls", "vol.py").
        args: List of arguments (NOT a shell string).
        timeout: Maximum execution time in seconds.
        case_dir: Path to the active case directory for audit logging.
        tool_name: Logical tool name for audit trail (e.g., "get_partition_layout").

    Returns:
        Dict with keys: stdout, stderr, exit_code, sha256, duration_seconds, truncated.

    Raises:
        ToolExecutionError: If the binary is blocked or execution fails.
    """
    # --- Denylist enforcement ---
    block_reason = denylist.check_binary(binary)
    if block_reason:
        raise ToolExecutionError(binary, block_reason)

    block_reason = denylist.check_arguments(binary, args)
    if block_reason:
        raise ToolExecutionError(binary, block_reason)

    # --- Build the command ---
    cmd = [binary] + args

    # --- Execute with shell=False ---
    start_time = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            shell=False,  # CRITICAL: Never use shell=True
            timeout=timeout,
            text=False,  # Capture as bytes to handle binary output
        )
    except FileNotFoundError:
        raise ToolExecutionError(
            binary, f"Binary not found: '{binary}'. Is it installed on this SIFT Workstation?"
        )
    except subprocess.TimeoutExpired:
        raise ToolExecutionError(
            binary, f"Execution timed out after {timeout} seconds"
        )

    duration = time.monotonic() - start_time

    # --- Decode output ---
    stdout_bytes = result.stdout[:MAX_RAW_OUTPUT_BYTES]
    truncated = len(result.stdout) > MAX_RAW_OUTPUT_BYTES

    try:
        stdout = stdout_bytes.decode("utf-8", errors="replace")
    except Exception:
        stdout = stdout_bytes.decode("latin-1", errors="replace")

    try:
        stderr = result.stderr.decode("utf-8", errors="replace")
    except Exception:
        stderr = result.stderr.decode("latin-1", errors="replace")

    # --- Compute integrity hash ---
    output_hash = compute_sha256(stdout)

    # --- Audit logging ---
    if case_dir:
        _write_audit_entry(
            case_dir=case_dir,
            tool_name=tool_name or binary,
            command=cmd,
            exit_code=result.returncode,
            output_sha256=output_hash,
            output_length=len(stdout),
            duration_seconds=round(duration, 3),
            truncated=truncated,
        )

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": result.returncode,
        "sha256": output_hash,
        "duration_seconds": round(duration, 3),
        "truncated": truncated,
    }


def _write_audit_entry(
    *,
    case_dir: str,
    tool_name: str,
    command: list[str],
    exit_code: int,
    output_sha256: str,
    output_length: int,
    duration_seconds: float,
    truncated: bool,
) -> None:
    """Append an audit entry to the case's tool-execution.jsonl."""
    log_dir = Path(case_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "tool-execution.jsonl"

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": tool_name,
        "command": command,
        "exit_code": exit_code,
        "output_sha256": output_sha256,
        "output_length": output_length,
        "duration_seconds": duration_seconds,
        "truncated": truncated,
    }

    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.warning("Failed to write audit entry: %s", e)


def parse_csv_output(
    raw_output: str,
    *,
    delimiter: str = ",",
    has_header: bool = True,
    max_rows: int = MAX_OUTPUT_ROWS,
) -> dict[str, Any]:
    """Parse CSV/TSV tool output into a list of dicts.

    Returns:
        Dict with keys: rows (list of dicts), total_rows, truncated, columns.
    """
    import csv
    import io

    reader = csv.reader(io.StringIO(raw_output), delimiter=delimiter)
    rows_raw = list(reader)

    if not rows_raw:
        return {"rows": [], "total_rows": 0, "truncated": False, "columns": []}

    if has_header:
        columns = [c.strip() for c in rows_raw[0]]
        data_rows = rows_raw[1:]
    else:
        columns = [f"col_{i}" for i in range(len(rows_raw[0]))]
        data_rows = rows_raw

    total_rows = len(data_rows)
    truncated = total_rows > max_rows
    data_rows = data_rows[:max_rows]

    rows = []
    for row in data_rows:
        if len(row) >= len(columns):
            rows.append(dict(zip(columns, row[:len(columns)])))
        elif row:  # Skip truly empty rows
            padded = row + [""] * (len(columns) - len(row))
            rows.append(dict(zip(columns, padded)))

    return {
        "rows": rows,
        "total_rows": total_rows,
        "truncated": truncated,
        "columns": columns,
    }


def parse_line_output(
    raw_output: str,
    *,
    max_rows: int = MAX_OUTPUT_ROWS,
) -> dict[str, Any]:
    """Parse newline-separated tool output into a list of strings.

    Returns:
        Dict with keys: lines, total_lines, truncated.
    """
    lines = [line for line in raw_output.splitlines() if line.strip()]
    total = len(lines)
    truncated = total > max_rows

    return {
        "lines": lines[:max_rows],
        "total_lines": total,
        "truncated": truncated,
    }


def truncate_rows(
    rows: list[dict[str, Any]],
    max_rows: int = MAX_OUTPUT_ROWS,
) -> dict[str, Any]:
    """Truncate a list of parsed rows with summary statistics.

    Returns:
        Dict with keys: rows, total_rows, truncated, summary.
    """
    total = len(rows)
    truncated = total > max_rows

    result = {
        "rows": rows[:max_rows],
        "total_rows": total,
        "truncated": truncated,
    }

    if truncated:
        result["summary"] = (
            f"Showing {max_rows} of {total} rows. "
            f"Use date/path filters to narrow results."
        )

    return result


def build_tool_response(
    *,
    tool_name: str,
    data: Any,
    evidence_file: str = "",
    output_sha256: str = "",
    duration_seconds: float = 0.0,
    error: str | None = None,
) -> dict[str, Any]:
    """Build a standardized MCP tool response envelope.

    Every tool response includes metadata for audit trail traceability.
    """
    response = {
        "tool": tool_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_file": evidence_file,
        "output_sha256": output_sha256,
        "duration_seconds": duration_seconds,
    }

    if error:
        response["status"] = "error"
        response["error"] = error
        response["data"] = None
    else:
        response["status"] = "success"
        response["data"] = data

    return response
