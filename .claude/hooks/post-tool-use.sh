#!/usr/bin/env bash
# VALKYRIE PostToolUse Hook — Forensic Audit Logging
#
# This hook runs AFTER every tool call. It logs the tool execution
# to the case directory's audit trail (logs/tool-execution.jsonl).
#
# Input: JSON on stdin with tool_name, tool_input, and tool_output fields
# Output: Empty (audit hooks don't produce output)
#
# The audit log enables judges to trace any finding back to the specific
# tool execution that produced it (Judging Criterion #5).

set -euo pipefail

INPUT=$(cat)

# Extract fields from the hook input
TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_name',''))" 2>/dev/null || echo "unknown")
TOOL_INPUT=$(echo "$INPUT" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('tool_input',{})))" 2>/dev/null || echo "{}")
TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_output',''))" 2>/dev/null || echo "")

# Compute SHA256 of the tool output for integrity verification
OUTPUT_HASH=$(echo -n "$TOOL_OUTPUT" | sha256sum | cut -d' ' -f1 2>/dev/null || echo "hash_failed")

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

# Find the active case directory
# Look for CASE.md in common locations, or use VALKYRIE_CASE_DIR env var
CASE_DIR="${VALKYRIE_CASE_DIR:-}"

if [ -z "$CASE_DIR" ]; then
    # Try to find an active case directory
    for candidate in /cases/*/CASE.md ./cases/*/CASE.md; do
        if [ -f "$candidate" ]; then
            CASE_DIR=$(dirname "$candidate")
            break
        fi
    done
fi

# If no case directory found, log to a fallback location
if [ -z "$CASE_DIR" ]; then
    CASE_DIR="${HOME}/.valkyrie/audit"
    mkdir -p "$CASE_DIR/logs"
fi

LOG_FILE="$CASE_DIR/logs/tool-execution.jsonl"
mkdir -p "$(dirname "$LOG_FILE")"

# Build the audit entry as a single JSON line
python3 -c "
import json, sys

entry = {
    'timestamp': '$TIMESTAMP',
    'tool_name': '$TOOL_NAME',
    'tool_input': json.loads('$TOOL_INPUT') if '$TOOL_INPUT' != '{}' else {},
    'output_sha256': '$OUTPUT_HASH',
    'output_length': len('$TOOL_OUTPUT'),
}

with open('$LOG_FILE', 'a') as f:
    f.write(json.dumps(entry) + '\n')
" 2>/dev/null || true

# Never fail — audit logging should not block tool execution
exit 0
