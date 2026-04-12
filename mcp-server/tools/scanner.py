"""
VALKYRIE MCP Server — Scanner Tools

Wraps pattern matching and string extraction utilities:
- YARA: signature-based scanning for malware and IOC detection
- strings / FLOSS: extract printable strings from binary files

All execution goes through safe_subprocess (shell=False, denylist check, SHA256 audit).
"""

import os
import re
from typing import Any

from parsers.common import (
    build_tool_response,
    safe_subprocess,
    truncate_rows,
    parse_line_output,
    MAX_OUTPUT_ROWS,
)


def scan_yara(
    target_path: str,
    rules_path: str,
    recursive: bool = False,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Scan a file or directory with YARA rules.

    Returns matching rule names, matched strings, and file offsets.
    """
    if not os.path.exists(target_path):
        return build_tool_response(
            tool_name="scan_yara",
            data=None,
            error=f"Target not found: {target_path}",
        )

    if not os.path.isfile(rules_path):
        return build_tool_response(
            tool_name="scan_yara",
            data=None,
            error=f"YARA rules file not found: {rules_path}",
        )

    args = []

    if recursive:
        args.append("-r")

    # Show matching strings with their offsets
    args.append("-s")

    args.extend([rules_path, target_path])

    result = safe_subprocess(
        "yara",
        args,
        timeout=300,
        tool_name="scan_yara",
        case_dir=case_dir,
    )

    if result["exit_code"] != 0:
        # YARA returns exit code 0 for no matches and non-zero for errors
        # But some versions return 1 for "no matches" — check stderr
        if not result["stderr"].strip() or "could not open file" not in result["stderr"].lower():
            # Likely just no matches
            return build_tool_response(
                tool_name="scan_yara",
                data={
                    "matches": [],
                    "match_count": 0,
                    "target_path": target_path,
                    "rules_path": rules_path,
                },
                evidence_file=target_path,
                output_sha256=result["sha256"],
                duration_seconds=result["duration_seconds"],
            )

        return build_tool_response(
            tool_name="scan_yara",
            data=None,
            evidence_file=target_path,
            output_sha256=result["sha256"],
            duration_seconds=result["duration_seconds"],
            error=f"YARA scan failed: {result['stderr'][:500]}",
        )

    matches = _parse_yara_output(result["stdout"])

    return build_tool_response(
        tool_name="scan_yara",
        data={
            "matches": matches,
            "match_count": len(matches),
            "target_path": target_path,
            "rules_path": rules_path,
            "recursive": recursive,
        },
        evidence_file=target_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _parse_yara_output(raw: str) -> list[dict[str, Any]]:
    """Parse YARA output with -s flag into structured match records.

    YARA -s output format:
    RuleName TargetFile
    0x1234:$string_identifier: matched_text
    0x5678:$another_string: other_matched_text
    AnotherRule TargetFile
    ...
    """
    matches = []
    current_match: dict[str, Any] | None = None

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # Check if this is a rule match line (no 0x prefix = rule name + file)
        if not line.startswith("0x"):
            parts = line.split(None, 1)
            if len(parts) >= 1:
                if current_match:
                    matches.append(current_match)
                current_match = {
                    "rule": parts[0],
                    "file": parts[1] if len(parts) > 1 else "",
                    "strings": [],
                }
        elif current_match:
            # Parse string match: 0xOFFSET:$IDENTIFIER: MATCHED_TEXT
            str_match = re.match(
                r"(0x[0-9a-fA-F]+):(\$\w+):\s*(.*)", line
            )
            if str_match:
                current_match["strings"].append({
                    "offset": str_match.group(1),
                    "identifier": str_match.group(2),
                    "matched_text": str_match.group(3)[:200],  # Truncate long matches
                })

    if current_match:
        matches.append(current_match)

    return matches


def extract_strings(
    file_path: str,
    min_length: int = 6,
    encoding: str = "both",
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Extract printable strings from a file.

    Tries FLOSS first (for advanced obfuscated string extraction),
    falls back to the standard 'strings' utility.
    """
    if not os.path.isfile(file_path):
        return build_tool_response(
            tool_name="extract_strings",
            data=None,
            error=f"File not found: {file_path}",
        )

    # Try FLOSS first (better for malware analysis)
    result = _try_floss(file_path, min_length, case_dir=case_dir)
    if result is not None:
        return result

    # Fallback to standard strings
    return _run_strings(file_path, min_length, encoding, case_dir=case_dir)


def _try_floss(
    file_path: str,
    min_length: int,
    *,
    case_dir: str | None = None,
) -> dict[str, Any] | None:
    """Try to extract strings using FLOSS (FLARE Obfuscated String Solver)."""
    try:
        result = safe_subprocess(
            "floss",
            ["--minimum-length", str(min_length), file_path],
            timeout=120,
            tool_name="extract_strings:floss",
            case_dir=case_dir,
        )
    except Exception:
        return None

    if result["exit_code"] != 0:
        return None

    parsed = parse_line_output(result["stdout"], max_rows=MAX_OUTPUT_ROWS)

    # Categorize strings
    categories = _categorize_strings(parsed["lines"])

    return build_tool_response(
        tool_name="extract_strings",
        data={
            "strings": parsed["lines"],
            "total_strings": parsed["total_lines"],
            "truncated": parsed["truncated"],
            "categories": categories,
            "parser": "floss",
            "min_length": min_length,
        },
        evidence_file=file_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _run_strings(
    file_path: str,
    min_length: int,
    encoding: str,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Extract strings using the standard 'strings' utility."""
    args = ["-n", str(min_length)]

    if encoding == "unicode":
        args.extend(["-e", "l"])  # Little-endian 16-bit
    elif encoding == "both":
        # Run twice: ASCII and Unicode
        pass  # Default 'strings' does ASCII; we'll add unicode in a second pass

    args.append(file_path)

    result = safe_subprocess(
        "strings",
        args,
        timeout=120,
        tool_name="extract_strings:strings",
        case_dir=case_dir,
    )

    if result["exit_code"] != 0:
        return build_tool_response(
            tool_name="extract_strings",
            data=None,
            evidence_file=file_path,
            output_sha256=result["sha256"],
            duration_seconds=result["duration_seconds"],
            error=f"strings failed: {result['stderr'][:500]}",
        )

    ascii_strings = result["stdout"].splitlines()

    # If "both" encoding, also extract Unicode strings
    unicode_strings = []
    if encoding == "both":
        try:
            unicode_result = safe_subprocess(
                "strings",
                ["-n", str(min_length), "-e", "l", file_path],
                timeout=120,
                tool_name="extract_strings:strings_unicode",
                case_dir=case_dir,
            )
            if unicode_result["exit_code"] == 0:
                unicode_strings = unicode_result["stdout"].splitlines()
        except Exception:
            pass  # Unicode extraction is best-effort

    # Combine and deduplicate
    all_strings = list(dict.fromkeys(ascii_strings + unicode_strings))  # Preserve order, dedup
    truncated = len(all_strings) > MAX_OUTPUT_ROWS
    all_strings = all_strings[:MAX_OUTPUT_ROWS]

    categories = _categorize_strings(all_strings)

    return build_tool_response(
        tool_name="extract_strings",
        data={
            "strings": all_strings,
            "total_strings": len(ascii_strings) + len(unicode_strings),
            "truncated": truncated,
            "categories": categories,
            "parser": "strings",
            "min_length": min_length,
            "encoding": encoding,
        },
        evidence_file=file_path,
        output_sha256=result["sha256"],
        duration_seconds=result["duration_seconds"],
    )


def _categorize_strings(strings: list[str]) -> dict[str, list[str]]:
    """Categorize extracted strings into forensically relevant groups.

    Identifies: URLs, IPs, file paths, email addresses, commands, and other IOCs.
    Returns at most 50 items per category to prevent context overflow.
    """
    MAX_PER_CATEGORY = 50

    categories: dict[str, list[str]] = {
        "urls": [],
        "ip_addresses": [],
        "file_paths": [],
        "email_addresses": [],
        "commands": [],
        "registry_keys": [],
        "base64_candidates": [],
    }

    ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    path_pattern = re.compile(r"[A-Z]:\\[\w\\. -]+", re.IGNORECASE)
    reg_pattern = re.compile(r"(HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\\]+", re.IGNORECASE)
    cmd_indicators = {"cmd", "powershell", "wscript", "cscript", "mshta", "rundll32",
                      "regsvr32", "certutil", "bitsadmin", "schtasks", "net ", "whoami",
                      "ipconfig", "systeminfo", "tasklist", "wmic", "invoke-"}
    # Base64: 20+ chars of [A-Za-z0-9+/] possibly ending with =
    b64_pattern = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

    for s in strings:
        s_stripped = s.strip()
        if not s_stripped:
            continue

        if url_pattern.search(s_stripped) and len(categories["urls"]) < MAX_PER_CATEGORY:
            categories["urls"].append(url_pattern.search(s_stripped).group())

        if ip_pattern.search(s_stripped) and len(categories["ip_addresses"]) < MAX_PER_CATEGORY:
            ip = ip_pattern.search(s_stripped).group()
            # Filter out common non-routable IPs
            if not ip.startswith(("0.", "255.", "127.")):
                categories["ip_addresses"].append(ip)

        if path_pattern.search(s_stripped) and len(categories["file_paths"]) < MAX_PER_CATEGORY:
            categories["file_paths"].append(path_pattern.search(s_stripped).group())

        if email_pattern.search(s_stripped) and len(categories["email_addresses"]) < MAX_PER_CATEGORY:
            categories["email_addresses"].append(email_pattern.search(s_stripped).group())

        if reg_pattern.search(s_stripped) and len(categories["registry_keys"]) < MAX_PER_CATEGORY:
            categories["registry_keys"].append(reg_pattern.search(s_stripped).group())

        if any(cmd in s_stripped.lower() for cmd in cmd_indicators) and len(categories["commands"]) < MAX_PER_CATEGORY:
            categories["commands"].append(s_stripped[:200])

        if b64_pattern.match(s_stripped) and len(categories["base64_candidates"]) < MAX_PER_CATEGORY:
            categories["base64_candidates"].append(s_stripped[:200])

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}
