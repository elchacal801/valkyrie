#!/usr/bin/env bash
# VALKYRIE PreToolUse Hook — Evidence Write Protection
#
# This hook runs BEFORE every tool call. It inspects the tool input
# and blocks any attempt to write to evidence directories.
#
# Input: JSON on stdin with tool_name and tool_input fields
# Output: JSON on stdout — {"decision": "allow"} or {"decision": "block", "reason": "..."}
#
# This is an ARCHITECTURAL guardrail, not a prompt-based one.
# Even if the model ignores instructions, this hook prevents evidence spoliation.

set -euo pipefail

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_name',''))" 2>/dev/null || echo "")
TOOL_INPUT=$(echo "$INPUT" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('tool_input',{})))" 2>/dev/null || echo "{}")

# Only inspect Bash tool calls — MCP tools are already typed and safe
if [ "$TOOL_NAME" != "Bash" ]; then
    echo '{"decision": "allow"}'
    exit 0
fi

# Extract the command from the Bash tool input
COMMAND=$(echo "$TOOL_INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command',''))" 2>/dev/null || echo "")

# Check for evidence directory references in write operations
# Evidence directories are typically under /cases/*/evidence/ or /mnt/evidence/
EVIDENCE_PATTERNS=(
    "/cases/.*/evidence/"
    "/mnt/evidence"
    "/evidence/"
)

WRITE_INDICATORS=(
    ">"          # Redirect output
    ">>"         # Append output
    "tee "       # Write to file
    "cp .* /cases/.*/evidence"
    "mv .* /cases/.*/evidence"
    "touch .*/evidence"
    "chmod .*/evidence"
    "chown .*/evidence"
)

for pattern in "${WRITE_INDICATORS[@]}"; do
    if echo "$COMMAND" | grep -qE "$pattern"; then
        for ev_pattern in "${EVIDENCE_PATTERNS[@]}"; do
            if echo "$COMMAND" | grep -qE "$ev_pattern"; then
                echo "{\"decision\": \"block\", \"reason\": \"EVIDENCE PROTECTION: Blocked write operation targeting evidence directory. Evidence must remain read-only to prevent spoliation.\"}"
                exit 0
            fi
        done
    fi
done

# Check for destructive commands that somehow bypassed the deny list
BLOCKED_CMDS="^(rm|dd|shred|mkfs|fdisk|format|del)\b"
if echo "$COMMAND" | grep -qE "$BLOCKED_CMDS"; then
    echo "{\"decision\": \"block\", \"reason\": \"EVIDENCE PROTECTION: Destructive command blocked by pre-tool-use hook.\"}"
    exit 0
fi

echo '{"decision": "allow"}'
