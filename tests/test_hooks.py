"""
End-to-end tests for the PreToolUse evidence-protection hook.

Runs the actual `.claude/hooks/pre-tool-use.sh` with crafted hook input and
asserts the allow/block decision — verifying the *architectural* guardrail
(not a prompt) behaves correctly even on Bash commands the model might emit.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).parent.parent / ".claude" / "hooks" / "pre-tool-use.sh"


def _run_hook(tool_name, tool_input):
    if shutil.which("bash") is None:
        pytest.skip("bash not available")
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    proc = subprocess.run(
        ["bash", str(HOOK)], input=payload, capture_output=True, text=True, timeout=30
    )
    return json.loads(proc.stdout.strip())


class TestPreToolUseHook:

    def test_non_bash_tool_allowed(self):
        assert _run_hook("Read", {"file_path": "/cases/x/evidence/disk.E01"})["decision"] == "allow"

    def test_redirect_into_evidence_blocked(self):
        d = _run_hook("Bash", {"command": "cat foo > /cases/CASE-1/evidence/out.bin"})
        assert d["decision"] == "block"
        assert "evidence" in d["reason"].lower()

    def test_copy_into_evidence_blocked(self):
        d = _run_hook("Bash", {"command": "cp /tmp/x /cases/CASE-1/evidence/x"})
        assert d["decision"] == "block"

    def test_destructive_command_blocked(self):
        assert _run_hook("Bash", {"command": "rm -rf /tmp/stuff"})["decision"] == "block"
        assert _run_hook("Bash", {"command": "dd if=/dev/zero of=/cases/x/evidence/disk.E01"})["decision"] == "block"

    def test_benign_read_allowed(self):
        d = _run_hook("Bash", {"command": "grep -i malware /cases/CASE-1/analysis/memory.json"})
        assert d["decision"] == "allow"

    def test_write_outside_evidence_allowed(self):
        d = _run_hook("Bash", {"command": "echo done > /cases/CASE-1/analysis/note.txt"})
        assert d["decision"] == "allow"
