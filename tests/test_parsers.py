"""
VALKYRIE — Parser Test Suite

Tests all MCP server parsers against realistic sample tool outputs.
These tests run WITHOUT forensic tools installed — they feed pre-captured
output through the parsers to verify correct structured extraction.

Run: python -m pytest tests/test_parsers.py -v
"""

import json
import os
import sys
from pathlib import Path

# Add mcp-server to path for imports
MCP_DIR = str(Path(__file__).parent.parent / "mcp-server")
sys.path.insert(0, MCP_DIR)

import pytest

SAMPLE_DIR = Path(__file__).parent / "sample_outputs"


def _read_sample(name: str) -> str:
    return (SAMPLE_DIR / name).read_text(encoding="utf-8")


# ============================================================================
# parsers/common.py tests
# ============================================================================

class TestCommonParsers:

    def test_compute_sha256_string(self):
        from parsers.common import compute_sha256
        result = compute_sha256("test")
        assert len(result) == 64
        assert result == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def test_compute_sha256_bytes(self):
        from parsers.common import compute_sha256
        result = compute_sha256(b"test")
        assert len(result) == 64

    def test_parse_csv_output_basic(self):
        from parsers.common import parse_csv_output
        csv_data = "Name,Size,Type\nfile1.exe,1024,executable\nfile2.dll,2048,library\n"
        result = parse_csv_output(csv_data)
        assert result["total_rows"] == 2
        assert result["columns"] == ["Name", "Size", "Type"]
        assert len(result["rows"]) == 2
        assert result["rows"][0]["Name"] == "file1.exe"
        assert result["rows"][1]["Size"] == "2048"
        assert result["truncated"] is False

    def test_parse_csv_output_truncation(self):
        from parsers.common import parse_csv_output
        rows = "Col1,Col2\n" + "\n".join(f"val{i},data{i}" for i in range(1000))
        result = parse_csv_output(rows, max_rows=100)
        assert result["total_rows"] == 1000
        assert len(result["rows"]) == 100
        assert result["truncated"] is True

    def test_parse_csv_output_empty(self):
        from parsers.common import parse_csv_output
        result = parse_csv_output("")
        assert result["total_rows"] == 0
        assert result["rows"] == []

    def test_parse_csv_output_tsv(self):
        from parsers.common import parse_csv_output
        tsv = "PID\tName\n1234\texplorer.exe\n"
        result = parse_csv_output(tsv, delimiter="\t")
        assert result["rows"][0]["PID"] == "1234"
        assert result["rows"][0]["Name"] == "explorer.exe"

    def test_parse_line_output(self):
        from parsers.common import parse_line_output
        lines = "line1\nline2\nline3\n\nline4\n"
        result = parse_line_output(lines)
        assert result["total_lines"] == 4  # empty line excluded
        assert len(result["lines"]) == 4

    def test_parse_line_output_truncation(self):
        from parsers.common import parse_line_output
        lines = "\n".join(f"line{i}" for i in range(1000))
        result = parse_line_output(lines, max_rows=50)
        assert result["total_lines"] == 1000
        assert len(result["lines"]) == 50
        assert result["truncated"] is True

    def test_truncate_rows(self):
        from parsers.common import truncate_rows
        rows = [{"id": i} for i in range(1000)]
        result = truncate_rows(rows, max_rows=100)
        assert result["total_rows"] == 1000
        assert len(result["rows"]) == 100
        assert result["truncated"] is True
        assert "summary" in result

    def test_build_tool_response_success(self):
        from parsers.common import build_tool_response
        resp = build_tool_response(
            tool_name="test_tool",
            data={"key": "value"},
            evidence_file="disk.E01",
            output_sha256="abc123",
        )
        assert resp["status"] == "success"
        assert resp["tool"] == "test_tool"
        assert resp["data"]["key"] == "value"
        assert resp["evidence_file"] == "disk.E01"
        assert "timestamp" in resp

    def test_build_tool_response_error(self):
        from parsers.common import build_tool_response
        resp = build_tool_response(
            tool_name="test_tool",
            data=None,
            error="Something went wrong",
        )
        assert resp["status"] == "error"
        assert resp["error"] == "Something went wrong"
        assert resp["data"] is None


# ============================================================================
# denylist.py tests
# ============================================================================

class TestDenylist:

    def test_blocked_binaries(self):
        import denylist
        for cmd in ["rm", "dd", "shred", "wget", "curl", "ssh", "bash", "python"]:
            result = denylist.check_binary(cmd)
            assert result is not None, f"{cmd} should be blocked"

    def test_allowed_binaries(self):
        import denylist
        for cmd in ["mmls", "fls", "icat", "vol", "yara", "strings", "grep", "cat"]:
            result = denylist.check_binary(cmd)
            assert result is None, f"{cmd} should be allowed"

    def test_path_stripping(self):
        import denylist
        assert denylist.check_binary("/usr/bin/rm") is not None
        assert denylist.check_binary("/usr/local/bin/mmls") is None
        assert denylist.check_binary("C:\\Windows\\system32\\cmd.exe") is not None

    def test_case_insensitive(self):
        import denylist
        assert denylist.check_binary("RM") is not None
        assert denylist.check_binary("Wget") is not None

    def test_sed_inplace_blocked(self):
        import denylist
        assert denylist.check_arguments("sed", ["-i", "s/a/b/"]) is not None
        assert denylist.check_arguments("sed", ["-e", "s/a/b/"]) is None

    def test_find_exec_blocked(self):
        import denylist
        assert denylist.check_arguments("find", ["/tmp", "-name", "*.txt", "-exec", "rm"]) is not None
        assert denylist.check_arguments("find", ["/tmp", "-name", "*.txt", "-delete"]) is not None
        assert denylist.check_arguments("find", ["/tmp", "-name", "*.txt"]) is None

    def test_tar_extract_blocked(self):
        import denylist
        assert denylist.check_arguments("tar", ["-x", "-f", "archive.tar"]) is not None
        assert denylist.check_arguments("tar", ["-tf", "archive.tar"]) is None  # listing is fine

    def test_awk_system_blocked(self):
        import denylist
        assert denylist.check_arguments("awk", ["{ system(\"rm -rf /\") }"]) is not None
        assert denylist.check_arguments("awk", ["{ print $1 }"]) is None

    def test_write_path_protection(self):
        import denylist
        denylist.register_evidence_path("/cases/CASE-001/evidence")
        assert denylist.check_write_path("/cases/CASE-001/evidence/disk.E01") is not None
        assert denylist.check_write_path("/cases/CASE-001/analysis/output.json") is None
        # Cleanup
        denylist.BLOCKED_WRITE_PATHS.discard("/cases/CASE-001/evidence")


# ============================================================================
# Disk parser tests (mmls, fls)
# ============================================================================

class TestDiskParsers:

    def test_parse_mmls_output(self):
        from tools.disk import _parse_mmls_output
        raw = _read_sample("mmls_output.txt")
        partitions = _parse_mmls_output(raw)

        assert len(partitions) >= 4
        # Check the NTFS partition
        ntfs_parts = [p for p in partitions if "NTFS" in p.get("description", "")]
        assert len(ntfs_parts) == 2
        assert ntfs_parts[0]["start_sector"] == 2048
        assert ntfs_parts[0]["length_sectors"] == 1024000

        # Check unallocated space
        unalloc = [p for p in partitions if "Unallocated" in p.get("description", "")]
        assert len(unalloc) >= 1

    def test_parse_fls_output(self):
        from tools.disk import _parse_fls_output
        raw = _read_sample("fls_output.txt")
        files = _parse_fls_output(raw)

        assert len(files) >= 6

        # Check file types parsed correctly
        file_types = {f["name"]: f["type"] for f in files}
        # Regular files
        assert any("svchost.exe" in f["name"] for f in files)
        # Directories
        dirs = [f for f in files if f["type"] == "directory"]
        assert len(dirs) >= 1
        # Deleted files (marked with *)
        deleted = [f for f in files if f["type"] == "deleted"]
        assert len(deleted) >= 1

        # Check inodes parsed
        for f in files:
            assert "inode" in f
            assert isinstance(f["inode"], int)


# ============================================================================
# Memory parser tests (Volatility 3)
# ============================================================================

class TestMemoryParsers:

    def test_parse_pslist(self):
        from tools.memory import _parse_pslist
        raw = _read_sample("vol_pslist_output.txt")
        processes = _parse_pslist(raw)

        assert len(processes) >= 10

        # Check PID parsing
        pids = {p.get("PID"): p for p in processes if isinstance(p.get("PID"), int)}
        assert 4 in pids  # System
        assert 4832 in pids  # Suspicious svchost
        assert 5248 in pids  # PowerShell

        # Check parent-child relationship
        suspicious_svchost = pids[4832]
        assert suspicious_svchost.get("PPID") == 2148  # Spawned by explorer, not services.exe

        # Check process names
        assert pids[564].get("ImageFileName") == "lsass.exe"

    def test_parse_netscan(self):
        from tools.memory import _parse_netscan
        raw = _read_sample("vol_netscan_output.txt")
        connections = _parse_netscan(raw)

        assert len(connections) >= 5

        # Check external connections parsed
        established = [c for c in connections if c.get("State") == "ESTABLISHED"]
        assert len(established) >= 4

        # Check PID parsed as int
        for conn in connections:
            if "PID" in conn and conn["PID"] != "":
                assert isinstance(conn["PID"], int)

    def test_parse_malfind(self):
        from tools.memory import _parse_malfind
        raw = _read_sample("vol_malfind_output.txt")
        entries = _parse_malfind(raw)

        assert len(entries) == 3

        # Check MZ header detection
        svchost_entry = [e for e in entries if e.get("pid") == 4832]
        assert len(svchost_entry) == 1
        assert svchost_entry[0]["has_mz_header"] is True
        assert svchost_entry[0]["has_rwx"] is True
        assert svchost_entry[0]["process"] == "svchost.exe"

        # Chrome entry should also have RWX (JIT — known false positive)
        chrome_entry = [e for e in entries if e.get("pid") == 3456]
        assert len(chrome_entry) == 1
        assert chrome_entry[0]["has_mz_header"] is False  # No MZ in JIT region

    def test_parse_cmdline(self):
        from tools.memory import _parse_cmdline
        raw = _read_sample("vol_cmdline_output.txt")
        entries = _parse_cmdline(raw)

        assert len(entries) >= 8

        # Check suspicious command line detected
        suspicious = [e for e in entries if e["pid"] == 4832]
        assert len(suspicious) == 1
        assert "-connect 203.0.113.42:8443" in suspicious[0]["cmdline"]

        # Check encoded PowerShell command
        ps_entries = [e for e in entries if e["pid"] == 5120]
        assert len(ps_entries) == 1
        assert "-EncodedCommand" in ps_entries[0]["cmdline"]

    def test_plugin_allowlist(self):
        from tools.memory import ALLOWED_PLUGINS
        # All expected plugins present (expanded from original 10 to 17)
        expected = {
            "pslist", "psscan", "pstree", "cmdline", "envars",
            "malfind", "ldrmodules", "ssdt", "vadinfo",
            "handles", "dlllist", "netscan", "svcscan",
            "filescan", "hivelist", "timeliner", "banners",
        }
        assert set(ALLOWED_PLUGINS.keys()) == expected

        # Dangerous plugins NOT present
        for dangerous in ["shellcode", "procdump", "memdump", "linux.bash"]:
            assert dangerous not in ALLOWED_PLUGINS


# ============================================================================
# Scanner parser tests (YARA, strings)
# ============================================================================

class TestScannerParsers:

    def test_parse_yara_output(self):
        from tools.scanner import _parse_yara_output
        raw = _read_sample("yara_output.txt")
        matches = _parse_yara_output(raw)

        assert len(matches) == 2

        # Check CobaltStrike match
        cs_match = [m for m in matches if m["rule"] == "CobaltStrike_Beacon_Encoded"]
        assert len(cs_match) == 1
        assert len(cs_match[0]["strings"]) == 4
        assert cs_match[0]["strings"][0]["identifier"] == "$s1"
        assert "svchost.exe" in cs_match[0]["file"]

        # Check PowerShell match
        ps_match = [m for m in matches if m["rule"] == "Suspicious_PowerShell_Download"]
        assert len(ps_match) == 1
        assert len(ps_match[0]["strings"]) == 3

    def test_categorize_strings(self):
        from tools.scanner import _categorize_strings
        raw = _read_sample("strings_output.txt")
        strings = [s.strip() for s in raw.splitlines() if s.strip()]
        categories = _categorize_strings(strings)

        # URLs detected
        assert "urls" in categories
        assert any("203.0.113.42" in u for u in categories["urls"])

        # IPs detected
        assert "ip_addresses" in categories
        assert "203.0.113.42" in categories["ip_addresses"]
        assert "198.51.100.10" in categories["ip_addresses"]
        # 127.x should be filtered
        assert "127.0.0.1" not in categories.get("ip_addresses", [])

        # File paths detected
        assert "file_paths" in categories
        assert any("svchost.exe" in p for p in categories["file_paths"])

        # Commands detected
        assert "commands" in categories
        assert any("whoami" in c for c in categories["commands"])
        assert any("powershell" in c.lower() for c in categories["commands"])

        # Registry keys detected
        assert "registry_keys" in categories
        assert any("CurrentVersion\\Run" in k for k in categories["registry_keys"])

        # Base64 candidates detected
        assert "base64_candidates" in categories
        assert len(categories["base64_candidates"]) >= 1

        # Email detected
        assert "email_addresses" in categories
        assert "admin@contoso.com" in categories["email_addresses"]


# ============================================================================
# Registry parser tests
# ============================================================================

class TestRegistryParsers:

    def test_persistence_keys_defined(self):
        from tools.registry import PERSISTENCE_KEYS
        # All hive types have entries
        assert "ntuser" in PERSISTENCE_KEYS
        assert "software" in PERSISTENCE_KEYS
        assert "system" in PERSISTENCE_KEYS
        assert "sam" in PERSISTENCE_KEYS

        # Each entry has required fields
        for hive_type, keys in PERSISTENCE_KEYS.items():
            for key_info in keys:
                assert "key" in key_info, f"Missing 'key' in {hive_type}"
                assert "description" in key_info, f"Missing 'description' in {hive_type}"
                assert "mitre" in key_info, f"Missing 'mitre' in {hive_type}"

    def test_persistence_key_count(self):
        from tools.registry import PERSISTENCE_KEYS
        total = sum(len(keys) for keys in PERSISTENCE_KEYS.values())
        assert total >= 20, f"Expected 20+ persistence locations, got {total}"

    def test_mitre_mappings_valid(self):
        from tools.registry import PERSISTENCE_KEYS
        for hive_type, keys in PERSISTENCE_KEYS.items():
            for key_info in keys:
                mitre = key_info["mitre"]
                if mitre:  # Some entries like TimeZoneInformation have empty mitre
                    assert mitre.startswith("T"), f"Invalid MITRE ID: {mitre}"


# ============================================================================
# Integration: response envelope format
# ============================================================================

class TestResponseEnvelope:

    def test_envelope_has_required_fields(self):
        from parsers.common import build_tool_response
        resp = build_tool_response(
            tool_name="analyze_memory",
            data={"plugin": "pslist", "results": []},
            evidence_file="/cases/CASE-001/evidence/memory.raw",
            output_sha256="abc123def456",
            duration_seconds=2.5,
        )
        # Required fields for audit trail
        assert "tool" in resp
        assert "timestamp" in resp
        assert "evidence_file" in resp
        assert "output_sha256" in resp
        assert "duration_seconds" in resp
        assert "status" in resp
        assert "data" in resp

    def test_envelope_json_serializable(self):
        from parsers.common import build_tool_response
        resp = build_tool_response(
            tool_name="test",
            data={"nested": {"key": [1, 2, 3]}},
        )
        # Must be JSON-serializable (MCP sends JSON over stdio)
        serialized = json.dumps(resp, default=str)
        deserialized = json.loads(serialized)
        assert deserialized["data"]["nested"]["key"] == [1, 2, 3]


# ============================================================================
# Memory failure scenario tests (ISF symbol mismatch, empty results)
# ============================================================================

class TestMemoryFailureScenarios:
    """Tests for graceful degradation when Volatility plugins return empty results."""

    def test_pslist_empty_headers_only(self):
        """Simulate ISF symbol failure: headers present but no data rows."""
        from tools.memory import _parse_pslist
        raw = (
            "Volatility 3 Framework 2.27.0\n\n"
            "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\tFile output\n"
        )
        result = _parse_pslist(raw)
        assert result == []

    def test_psscan_in_plugin_parsers(self):
        """Verify psscan is registered and uses pslist parser."""
        from tools.memory import PLUGIN_PARSERS, _parse_pslist
        assert "psscan" in PLUGIN_PARSERS
        assert PLUGIN_PARSERS["psscan"] is _parse_pslist

    def test_new_plugins_in_allowlist(self):
        """Verify all new pool-scanning and enumeration plugins are allowlisted."""
        from tools.memory import ALLOWED_PLUGINS
        for plugin in ["psscan", "envars", "svcscan", "ldrmodules", "ssdt", "vadinfo", "banners"]:
            assert plugin in ALLOWED_PLUGINS, f"{plugin} missing from ALLOWED_PLUGINS"

    def test_generic_parser_empty_output(self):
        """Generic table parser handles empty and header-only input."""
        from tools.memory import _parse_generic_table
        assert _parse_generic_table("") == []
        assert _parse_generic_table("Volatility 3 Framework 2.27.0\n") == []
        assert _parse_generic_table("Header1\tHeader2\n") == []

    def test_malfind_empty_output(self):
        from tools.memory import _parse_malfind
        assert _parse_malfind("") == []
        assert _parse_malfind("Volatility 3 Framework 2.27.0\n\n") == []

    def test_cmdline_empty_output(self):
        from tools.memory import _parse_cmdline
        assert _parse_cmdline("") == []
        assert _parse_cmdline("PID\tProcess\tArgs\n") == []

    def test_netscan_empty_output(self):
        from tools.memory import _parse_netscan
        assert _parse_netscan("") == []

    def test_dump_args_blocked_in_analyze_memory(self):
        """--dump is still blocked in the generic analyze_memory tool."""
        from tools.memory import BLOCKED_PLUGIN_ARGS
        assert "--dump" in BLOCKED_PLUGIN_ARGS

    def test_symbol_env_cache(self):
        """Symbol env resolution returns consistent env dict."""
        from tools.memory import _get_symbol_env, SYMBOL_SERVER_URL
        env = _get_symbol_env("/fake/dump.raw")
        assert "VOLATILITY3_SYMBOLS_URL" in env
        assert env["VOLATILITY3_SYMBOLS_URL"] == SYMBOL_SERVER_URL
        # Second call should return cached result
        env2 = _get_symbol_env("/fake/dump.raw")
        assert env is env2


class TestDumpProcessMemory:
    """Tests for the dump_process_memory safety checks."""

    def test_dump_rejects_evidence_directory(self):
        """dump_process_memory refuses to write to evidence-protected path."""
        from tools.memory import dump_process_memory
        import denylist
        denylist.register_evidence_path("/cases/TEST-SAFETY/evidence")
        try:
            result = dump_process_memory(
                dump_path="/cases/TEST-SAFETY/evidence/mem.raw",
                pid=4832,
                output_dir="/cases/TEST-SAFETY/evidence",
            )
            assert result["status"] == "error"
            assert "protected" in result["error"].lower() or "blocked" in result["error"].lower()
        finally:
            denylist.BLOCKED_WRITE_PATHS.discard("/cases/TEST-SAFETY/evidence")

    def test_dump_rejects_missing_dump(self):
        """dump_process_memory returns error for missing dump file."""
        from tools.memory import dump_process_memory
        result = dump_process_memory(
            dump_path="/nonexistent/memory.raw",
            pid=4832,
            output_dir="/tmp/test-dump",
        )
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()


class TestSafeSubprocessEnv:
    """Test that safe_subprocess passes environment variables correctly."""

    def test_env_parameter_accepted(self):
        """safe_subprocess accepts the env parameter without error."""
        import inspect
        from parsers.common import safe_subprocess
        sig = inspect.signature(safe_subprocess)
        assert "env" in sig.parameters
