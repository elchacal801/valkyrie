# VALKYRIE — Claude Code Project Guide

## What This Is

VALKYRIE is an autonomous forensic IR agent for SIFT Workstation. It uses Claude Code + a custom MCP server + SIFT forensic tools to investigate digital evidence.

## MCP-First Rule

Always use `mcp__valkyrie__*` tools for forensic operations. The MCP server provides structured JSON output, automatic audit logging with SHA256 hashes, denylist enforcement, and output truncation. Only use Bash for supplementary operations not covered by MCP (grep pipelines, jq filtering, hex inspection).

**MCP tools available:**
- `analyze_memory` — Volatility 3 plugins (pslist, psscan, netscan, malfind, cmdline, dlllist, handles, envars, svcscan, ldrmodules, vadinfo, filescan, hivelist, timeliner, banners)
- `dump_process_memory` — Extract process memory to case directory for FLOSS/YARA analysis
- `get_partition_layout` — Disk partition table (mmls)
- `list_files` — File listing from disk image (fls)
- `extract_file` — Extract file by inode (icat)
- `generate_timeline` — Super timeline (log2timeline/plaso)
- `extract_mft` — MFT parsing (MFTECmd)
- `get_registry_key` — Registry key reading (RegRipper/RECmd)
- `check_persistence` — Persistence mechanism scan
- `scan_yara` — YARA signature scanning
- `extract_strings` — String extraction (tries FLOSS first, falls back to strings)

## Memory Analysis Workflow

1. **Check symbols**: Run `analyze_memory(plugin="banners")` to identify the OS build
2. **Process listing**: Try `pslist` first. If it returns 0 rows (ISF symbol mismatch), fall back to `psscan` (pool scanning — works without symbols)
3. **Command lines**: Try `cmdline`. If empty, fall back to `extract_strings` on the dump with grep for `.exe` paths
4. **Injection detection**: Run `malfind`. If empty, try `vadinfo` on suspect PIDs for PAGE_EXECUTE_READWRITE regions
5. **Network**: Run `netscan` (pool scanning — always works)
6. **Services**: Run `svcscan` for service enumeration
7. **Malware triage**: Use `dump_process_memory` to extract suspicious process memory, then `extract_strings` (FLOSS) and `scan_yara`

## Case Directory Conventions

```
/cases/<CASE-ID>/
├── evidence/          # READ-ONLY — never write here
├── inventory.json     # Phase 1
├── triage.json        # Phase 2
├── analysis/          # Phase 3 technique outputs
├── synthesis.json     # Phase 4
├── corrections/       # Phase 5 self-correction
├── report/            # Phase 6 final deliverables
└── logs/              # Audit trail (tool-execution.jsonl)
```

## Evidence Protection

The evidence directory is write-protected by both the MCP denylist and the pre-tool-use hook. Never attempt to write to evidence paths. Use `extract_file` to copy artifacts to the case working directory for analysis.

## Investigation Skill

Use `/investigate` to start an investigation. See `skills/ir-analysis/SKILL.md` for modes:
- `/investigate` — Adaptive (auto-assess evidence)
- `/investigate memory` — Direct memory analysis
- `/investigate --guided` — Full 6-phase pipeline
- `/investigate --lean` — Fast triage

## Running Tests

```bash
cd /opt/valkyrie/mcp-server
source ../.venv/bin/activate
python3 -m pytest ../tests/test_parsers.py -v
```
