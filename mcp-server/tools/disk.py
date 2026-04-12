"""
VALKYRIE MCP Server — Disk Analysis Tools

Wraps The Sleuth Kit (TSK) utilities for disk image analysis:
- mmls: partition table parsing
- fls: file listing within a filesystem
- icat: file extraction by inode

All execution goes through safe_subprocess (shell=False, denylist check, SHA256 audit).
"""

import os
import re
from typing import Any

from parsers.common import (
    ToolExecutionError,
    build_tool_response,
    compute_sha256,
    parse_line_output,
    safe_subprocess,
    truncate_rows,
)


def get_partition_layout(
    image_path: str,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Display the partition table of a disk image using mmls.

    Returns structured partition information including type, offset, size.
    """
    if not os.path.isfile(image_path):
        return build_tool_response(
            tool_name="get_partition_layout",
            data=None,
            evidence_file=image_path,
            error=f"Image file not found: {image_path}",
        )

    result = safe_subprocess(
        "mmls",
        [image_path],
        tool_name="get_partition_layout",
        case_dir=case_dir,
    )

    if result["exit_code"] != 0:
        return build_tool_response(
            tool_name="get_partition_layout",
            data=None,
            evidence_file=image_path,
            output_sha256=result["sha256"],
            duration_seconds=result["duration_seconds"],
            error=f"mmls failed (exit {result['exit_code']}): {result['stderr'][:500]}",
        )

    partitions = _parse_mmls_output(result["stdout"])

    return build_tool_response(
        tool_name="get_partition_layout",
        data={
            "partitions": partitions,
            "partition_count": len(partitions),
            "image_path": image_path,
        },
        evidence_file=image_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _parse_mmls_output(raw: str) -> list[dict[str, Any]]:
    """Parse mmls text output into structured partition records."""
    partitions = []
    # mmls output format:
    #      Slot      Start        End          Length       Description
    # 000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
    # 001:  -------   0000000000   0000002047   0000002048   Unallocated
    # 002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("Slot") or line.startswith("---"):
            continue

        match = re.match(
            r"(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)",
            line,
        )
        if match:
            partitions.append({
                "slot": match.group(1),
                "type": match.group(2),
                "start_sector": int(match.group(3)),
                "end_sector": int(match.group(4)),
                "length_sectors": int(match.group(5)),
                "description": match.group(6).strip(),
            })

    return partitions


def list_files(
    image_path: str,
    path: str = "/",
    partition_offset: int | None = None,
    recursive: bool = False,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """List files and directories in a disk image using fls.

    Args:
        image_path: Path to the disk image.
        path: Directory path within the image.
        partition_offset: Partition start sector (from get_partition_layout).
        recursive: List files recursively.
        case_dir: Case directory for audit logging.
    """
    if not os.path.isfile(image_path):
        return build_tool_response(
            tool_name="list_files",
            data=None,
            evidence_file=image_path,
            error=f"Image file not found: {image_path}",
        )

    args = []

    if partition_offset is not None:
        args.extend(["-o", str(partition_offset)])

    if recursive:
        args.append("-r")

    # Use -p for full path display, -l for long format (timestamps + size)
    args.extend(["-p", "-l", image_path])

    result = safe_subprocess(
        "fls",
        args,
        tool_name="list_files",
        case_dir=case_dir,
    )

    if result["exit_code"] != 0:
        return build_tool_response(
            tool_name="list_files",
            data=None,
            evidence_file=image_path,
            output_sha256=result["sha256"],
            duration_seconds=result["duration_seconds"],
            error=f"fls failed (exit {result['exit_code']}): {result['stderr'][:500]}",
        )

    files = _parse_fls_output(result["stdout"])
    file_data = truncate_rows(files)

    return build_tool_response(
        tool_name="list_files",
        data={
            "path": path,
            "files": file_data["rows"],
            "total_files": file_data["total_rows"],
            "truncated": file_data["truncated"],
            "image_path": image_path,
        },
        evidence_file=image_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _parse_fls_output(raw: str) -> list[dict[str, Any]]:
    """Parse fls -p -l output into structured file records.

    fls -l output format:
    r/r 66-128-3:    Users/user/Desktop/file.txt    2024-01-15 10:30:00 (UTC)    ...
    d/d 33-144-1:    Users/user/Documents    2024-01-10 08:00:00 (UTC)    ...
    """
    files = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # Parse the type indicator and inode
        # fls formats: "r/r 66-128-3:" or "r/r * 102-128-1:" (deleted)
        match = re.match(r"([rd/\-]+)\s*(\*)?\s*(\d+)(?:-\d+-\d+)?:\s+(.*)", line)
        if match:
            type_indicator = match.group(1)
            deleted_marker = match.group(2)  # "*" if deleted, None otherwise
            inode = int(match.group(3))
            remainder = match.group(4).strip()

            # Determine file type
            if deleted_marker == "*":
                file_type = "deleted"
            elif type_indicator.startswith("d"):
                file_type = "directory"
            elif type_indicator.startswith("r"):
                file_type = "file"
            else:
                file_type = "other"

            # The remainder contains the path and potentially timestamps
            # Split on tab characters if present
            parts = remainder.split("\t")
            name = parts[0].strip() if parts else remainder

            entry = {
                "name": name,
                "type": file_type,
                "inode": inode,
                "raw_type": type_indicator,
            }

            # Extract timestamps if available in long format
            if len(parts) > 1:
                for i, part in enumerate(parts[1:], 1):
                    part = part.strip()
                    if re.match(r"\d{4}-\d{2}-\d{2}", part):
                        if i == 1:
                            entry["modified"] = part
                        elif i == 2:
                            entry["accessed"] = part
                        elif i == 3:
                            entry["changed"] = part
                        elif i == 4:
                            entry["created"] = part

            files.append(entry)

    return files


def extract_file(
    image_path: str,
    inode: int,
    output_dir: str,
    output_name: str,
    partition_offset: int | None = None,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Extract a file from a disk image by inode using icat.

    The extracted file is written to the case working directory,
    NEVER to the evidence directory.
    """
    if not os.path.isfile(image_path):
        return build_tool_response(
            tool_name="extract_file",
            data=None,
            evidence_file=image_path,
            error=f"Image file not found: {image_path}",
        )

    # Validate output directory is not in the evidence path
    from denylist import check_write_path
    block = check_write_path(output_dir)
    if block:
        return build_tool_response(
            tool_name="extract_file",
            data=None,
            evidence_file=image_path,
            error=block,
        )

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, output_name)

    args = []
    if partition_offset is not None:
        args.extend(["-o", str(partition_offset)])
    args.extend([image_path, str(inode)])

    result = safe_subprocess(
        "icat",
        args,
        tool_name="extract_file",
        case_dir=case_dir,
    )

    if result["exit_code"] != 0:
        return build_tool_response(
            tool_name="extract_file",
            data=None,
            evidence_file=image_path,
            output_sha256=result["sha256"],
            duration_seconds=result["duration_seconds"],
            error=f"icat failed (exit {result['exit_code']}): {result['stderr'][:500]}",
        )

    # icat outputs the file content to stdout — write it to the output file
    try:
        with open(output_path, "wb") as f:
            f.write(result["stdout"].encode("latin-1"))  # Preserve binary content
    except OSError as e:
        return build_tool_response(
            tool_name="extract_file",
            data=None,
            evidence_file=image_path,
            error=f"Failed to write extracted file: {e}",
        )

    # Compute hash of the extracted file
    file_hash = compute_sha256(open(output_path, "rb").read())

    return build_tool_response(
        tool_name="extract_file",
        data={
            "output_path": output_path,
            "sha256": file_hash,
            "size_bytes": os.path.getsize(output_path),
            "source_inode": inode,
            "image_path": image_path,
        },
        evidence_file=image_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )
