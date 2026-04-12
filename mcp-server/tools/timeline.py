"""
VALKYRIE MCP Server — Timeline Tools

Wraps timeline generation utilities:
- log2timeline.py + psort.py (Plaso): super timeline from disk images
- MFTECmd: MFT (Master File Table) parsing with MACB timestamps

All execution goes through safe_subprocess (shell=False, denylist check, SHA256 audit).
"""

import csv
import io
import os
from typing import Any

from parsers.common import (
    build_tool_response,
    parse_csv_output,
    safe_subprocess,
    truncate_rows,
    MAX_OUTPUT_ROWS,
)


def generate_timeline(
    image_path: str,
    output_dir: str,
    start_date: str | None = None,
    end_date: str | None = None,
    filter_path: str | None = None,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Generate a super timeline using log2timeline/plaso.

    Two-step process:
    1. log2timeline.py: Parse the disk image into a plaso storage file
    2. psort.py: Sort and filter the storage into CSV output
    """
    if not os.path.isfile(image_path):
        return build_tool_response(
            tool_name="generate_timeline",
            data=None,
            evidence_file=image_path,
            error=f"Image file not found: {image_path}",
        )

    os.makedirs(output_dir, exist_ok=True)
    plaso_file = os.path.join(output_dir, "timeline.plaso")
    csv_file = os.path.join(output_dir, "timeline.csv")

    # Step 1: Parse the image with log2timeline
    l2t_args = [
        "--storage-file", plaso_file,
        image_path,
    ]

    result_l2t = safe_subprocess(
        "log2timeline.py",
        l2t_args,
        timeout=600,  # 10 min — plaso can be slow on large images
        tool_name="generate_timeline:log2timeline",
        case_dir=case_dir,
    )

    if result_l2t["exit_code"] != 0:
        return build_tool_response(
            tool_name="generate_timeline",
            data=None,
            evidence_file=image_path,
            output_sha256=result_l2t["sha256"],
            duration_seconds=result_l2t["duration_seconds"],
            error=f"log2timeline failed (exit {result_l2t['exit_code']}): {result_l2t['stderr'][:500]}",
        )

    # Step 2: Sort and export with psort
    psort_args = [
        "-o", "l2tcsv",  # Output format: log2timeline CSV
        "-w", csv_file,
        plaso_file,
    ]

    # Date filters
    if start_date:
        psort_args.extend(["--slice", start_date])

    result_psort = safe_subprocess(
        "psort.py",
        psort_args,
        timeout=300,
        tool_name="generate_timeline:psort",
        case_dir=case_dir,
    )

    if result_psort["exit_code"] != 0:
        return build_tool_response(
            tool_name="generate_timeline",
            data=None,
            evidence_file=image_path,
            output_sha256=result_psort["sha256"],
            duration_seconds=result_l2t["duration_seconds"] + result_psort["duration_seconds"],
            error=f"psort failed (exit {result_psort['exit_code']}): {result_psort['stderr'][:500]}",
        )

    # Parse the CSV output
    try:
        with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
            raw_csv = f.read()
    except OSError as e:
        return build_tool_response(
            tool_name="generate_timeline",
            data=None,
            evidence_file=image_path,
            error=f"Failed to read timeline CSV: {e}",
        )

    parsed = parse_csv_output(raw_csv, delimiter=",", max_rows=MAX_OUTPUT_ROWS)

    # Apply path filter if specified
    if filter_path and parsed["rows"]:
        # Filter rows where any field contains the path substring
        filtered = [
            row for row in parsed["rows"]
            if any(filter_path.lower() in str(v).lower() for v in row.values())
        ]
        parsed["rows"] = filtered[:MAX_OUTPUT_ROWS]
        parsed["filtered_by"] = filter_path
        parsed["total_after_filter"] = len(filtered)

    total_duration = result_l2t["duration_seconds"] + result_psort["duration_seconds"]

    return build_tool_response(
        tool_name="generate_timeline",
        data={
            "entries": parsed["rows"],
            "total_entries": parsed["total_rows"],
            "truncated": parsed["truncated"],
            "columns": parsed["columns"],
            "csv_file": csv_file,
            "plaso_file": plaso_file,
            "date_filter": {"start": start_date, "end": end_date},
            "path_filter": filter_path,
        },
        evidence_file=image_path,
        output_sha256=result_psort["sha256"],
        duration_seconds=total_duration,
    )


def extract_mft(
    image_path: str,
    output_dir: str,
    start_date: str | None = None,
    end_date: str | None = None,
    filter_path: str | None = None,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Parse the MFT from a disk image using MFTECmd.

    Returns file entries with full MACB timestamps.
    """
    if not os.path.isfile(image_path):
        return build_tool_response(
            tool_name="extract_mft",
            data=None,
            evidence_file=image_path,
            error=f"Image/MFT file not found: {image_path}",
        )

    os.makedirs(output_dir, exist_ok=True)
    csv_output = os.path.join(output_dir, "mft_output.csv")

    # MFTECmd arguments
    args = [
        "-f", image_path,
        "--csv", output_dir,
        "--csvf", "mft_output.csv",
    ]

    result = safe_subprocess(
        "MFTECmd",
        args,
        timeout=300,
        tool_name="extract_mft",
        case_dir=case_dir,
    )

    if result["exit_code"] != 0:
        # Fallback: try analyzeMFT (available on some SIFT installs)
        result = safe_subprocess(
            "analyzeMFT.py",
            ["-f", image_path, "-o", csv_output],
            timeout=300,
            tool_name="extract_mft:analyzeMFT",
            case_dir=case_dir,
        )

        if result["exit_code"] != 0:
            return build_tool_response(
                tool_name="extract_mft",
                data=None,
                evidence_file=image_path,
                output_sha256=result["sha256"],
                duration_seconds=result["duration_seconds"],
                error=f"MFT parsing failed (exit {result['exit_code']}): {result['stderr'][:500]}",
            )

    # Parse the CSV output
    try:
        with open(csv_output, "r", encoding="utf-8", errors="replace") as f:
            raw_csv = f.read()
    except OSError as e:
        return build_tool_response(
            tool_name="extract_mft",
            data=None,
            evidence_file=image_path,
            error=f"Failed to read MFT CSV: {e}",
        )

    parsed = parse_csv_output(raw_csv, delimiter=",", max_rows=MAX_OUTPUT_ROWS)

    # Apply filters
    rows = parsed["rows"]

    if filter_path:
        rows = [
            row for row in rows
            if any(filter_path.lower() in str(v).lower() for v in row.values())
        ]

    if start_date:
        rows = _filter_by_date(rows, start_date, after=True)

    if end_date:
        rows = _filter_by_date(rows, end_date, after=False)

    row_data = truncate_rows(rows)

    return build_tool_response(
        tool_name="extract_mft",
        data={
            "entries": row_data["rows"],
            "total_entries": parsed["total_rows"],
            "displayed_entries": len(row_data["rows"]),
            "truncated": row_data["truncated"],
            "columns": parsed["columns"],
            "csv_file": csv_output,
            "filters": {
                "start_date": start_date,
                "end_date": end_date,
                "path": filter_path,
            },
        },
        evidence_file=image_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _filter_by_date(
    rows: list[dict[str, Any]],
    date_str: str,
    after: bool = True,
) -> list[dict[str, Any]]:
    """Filter rows by date, checking common timestamp column names."""
    date_columns = [
        "Created0x10", "LastModified0x10", "LastAccess0x10",
        "Created0x30", "LastModified0x30",
        "created", "modified", "accessed", "changed",
        "Date", "date", "Timestamp", "timestamp",
    ]

    filtered = []
    for row in rows:
        for col in date_columns:
            val = row.get(col, "")
            if val and date_str <= val if after else val <= date_str:
                filtered.append(row)
                break

    return filtered if filtered else rows  # Return all rows if no date columns found
