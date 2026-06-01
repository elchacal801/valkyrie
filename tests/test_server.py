"""
Integration tests for the MCP server dispatch layer and evidence guardrails.

These exercise the real `handle_tool_call` routing and the architectural
write-protection — without requiring any forensic binaries to be installed.
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

MCP_DIR = str(Path(__file__).parent.parent / "mcp-server")
sys.path.insert(0, MCP_DIR)

pytest.importorskip("mcp", reason="mcp package not installed")

import server  # noqa: E402
import denylist  # noqa: E402

SAMPLE = Path(__file__).parent.parent / "eval" / "datasets" / "entra-azure-sample.json"

EXPECTED_TOOLS = {
    "get_partition_layout", "list_files", "extract_file", "generate_timeline",
    "extract_mft", "analyze_memory", "dump_process_memory", "get_registry_key",
    "check_persistence", "scan_yara", "extract_strings", "analyze_cloud_logs",
}


def _call(name, args):
    return json.loads(asyncio.run(server.handle_tool_call(name, args)))


class TestToolRegistry:

    def test_all_tools_registered(self):
        names = {t.name for t in server.TOOLS}
        assert EXPECTED_TOOLS <= names, f"missing: {EXPECTED_TOOLS - names}"

    def test_every_tool_has_schema(self):
        for t in server.TOOLS:
            assert t.inputSchema.get("type") == "object"
            assert "properties" in t.inputSchema


class TestDispatch:

    def test_unknown_tool_errors(self):
        result = _call("does_not_exist", {})
        assert result["status"] == "error"
        assert "unknown tool" in result["error"].lower()

    def test_missing_evidence_file_errors(self):
        result = _call("get_partition_layout", {"image_path": "/nope/disk.E01"})
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()

    def test_cloud_dispatch_end_to_end(self):
        """analyze_cloud_logs runs fully through dispatch — no binaries needed."""
        result = _call("analyze_cloud_logs", {"log_path": str(SAMPLE)})
        assert result["status"] == "success"
        assert result["execution_id"].startswith("EXEC-")
        assert result["data"]["total_findings"] >= 8


class TestEvidenceGuardrail:

    def test_extract_file_blocked_to_evidence_dir(self, tmp_path):
        """Architectural write-protection: extraction into a registered evidence
        directory is refused before any tool runs."""
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00")
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        denylist.register_evidence_path(str(evidence))
        try:
            result = _call("extract_file", {
                "image_path": str(img), "inode": 5,
                "output_dir": str(evidence), "output_name": "x.bin",
            })
            assert result["status"] == "error"
            assert "protect" in result["error"].lower() or "evidence" in result["error"].lower()
            assert not (evidence / "x.bin").exists()
        finally:
            denylist.BLOCKED_WRITE_PATHS.discard(str(evidence))
