# VALKYRIE Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                              │
│                     (Reasoning Engine)                          │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                VALKYRIE Skill Framework                    │  │
│  │                                                           │  │
│  │  SKILL.md ──► Orchestrator ──► 7 Technique Protocols      │  │
│  │  /investigate    │                                        │  │
│  │                  ├─► Evidence Collector                    │  │
│  │                  ├─► Self-Correction (3 layers)            │  │
│  │                  └─► Report Generator                     │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              Technique Protocols                     │  │  │
│  │  │  timeline-reconstruction  │  artifact-correlation    │  │  │
│  │  │  hypothesis-testing       │  memory-analysis         │  │  │
│  │  │  persistence-enumeration  │  log-analysis            │  │  │
│  │  │  malware-triage                                      │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────┴───────────────────────────────┐  │
│  │              Claude Code Hooks                             │  │
│  │  PreToolUse: pre-tool-use.sh (evidence write protection)  │  │
│  │  PostToolUse: post-tool-use.sh (SHA256 audit logging)     │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
├──────────────────────────────┼───────────────────────────────────┤
│         TRUST BOUNDARY 1: Claude Code Sandbox                    │
├──────────────────────────────┼───────────────────────────────────┤
│                              │                                   │
│  ┌───────────────────────────┴───────────────────────────────┐  │
│  │           VALKYRIE MCP Server (stdio transport)            │  │
│  │                                                            │  │
│  │  server.py ──► Tool Dispatch ──► Response Envelope         │  │
│  │       │                                                    │  │
│  │  ┌────┴─────────────────────────────────────────────────┐  │  │
│  │  │  denylist.py              parsers/common.py          │  │  │
│  │  │  48 blocked binaries      safe_subprocess()          │  │  │
│  │  │  argument validation      shell=False ALWAYS         │  │  │
│  │  │  path write protection    SHA256 audit logging       │  │  │
│  │  │                           output truncation          │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  │       │                                                    │  │
│  │  ┌────┴─────────────────────────────────────────────────┐  │  │
│  │  │  Tool Modules (typed functions only)                  │  │  │
│  │  │                                                      │  │  │
│  │  │  disk.py      ── mmls, fls, icat                     │  │  │
│  │  │  timeline.py  ── log2timeline, MFTECmd               │  │  │
│  │  │  memory.py    ── volatility3 (10-plugin allowlist)   │  │  │
│  │  │  registry.py  ── regripper, RECmd                    │  │  │
│  │  │  scanner.py   ── yara, strings/FLOSS                 │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                   │
├──────────────────────────────┼───────────────────────────────────┤
│         TRUST BOUNDARY 2: subprocess(shell=False)                │
├──────────────────────────────┼───────────────────────────────────┤
│                              │                                   │
│  ┌───────────────────────────┴───────────────────────────────┐  │
│  │           SIFT Workstation Tools                           │  │
│  │                                                            │  │
│  │  sleuthkit (mmls, fls, icat)  │  volatility3              │  │
│  │  plaso (log2timeline, psort)  │  yara                     │  │
│  │  MFTECmd / analyzeMFT         │  strings / FLOSS          │  │
│  │  RegRipper / RECmd            │  ewfverify                │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                   │
├──────────────────────────────┼───────────────────────────────────┤
│         TRUST BOUNDARY 3: OS filesystem (read-only mount)        │
├──────────────────────────────┼───────────────────────────────────┤
│                              │                                   │
│  ┌───────────────────────────┴───────────────────────────────┐  │
│  │           Evidence (READ-ONLY)                             │  │
│  │                                                            │  │
│  │  /cases/CASE-XXX/evidence/                                 │  │
│  │  ├── disk.E01          (mounted read-only)                 │  │
│  │  ├── memory.raw        (read-only access)                  │  │
│  │  └── logs/             (read-only access)                  │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │           Case Working Directory (WRITE)                    │  │
│  │                                                            │  │
│  │  /cases/CASE-XXX/                                          │  │
│  │  ├── inventory.json     (Phase 1 output)                   │  │
│  │  ├── triage.json        (Phase 2 output)                   │  │
│  │  ├── analysis/          (Phase 3 output)                   │  │
│  │  ├── synthesis.json     (Phase 4 output)                   │  │
│  │  ├── corrections/       (Phase 5 output)                   │  │
│  │  ├── report/            (Phase 6 output)                   │  │
│  │  └── logs/              (audit trail)                      │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Trust Boundaries

VALKYRIE enforces evidence integrity through **5 architectural layers**. These are enforced in code, not via prompts — they cannot be bypassed by model jailbreaking or prompt injection.

### Layer 1: Typed MCP Functions (Architectural)

The MCP server exposes **10 typed functions**, not a generic shell. The agent can call `get_partition_layout(image_path)` or `analyze_memory(dump_path, plugin)`, but it **cannot** construct arbitrary shell commands. This is the most fundamental constraint — the attack surface is limited to 10 well-defined operations.

**What it prevents**: Arbitrary command execution, filesystem modification, network access
**How it's enforced**: Python MCP server only registers specific `Tool` objects; JSON-RPC dispatch only routes to known handlers
**What happens if bypassed**: Would require modifying the MCP server source code itself

### Layer 2: Denylist + Argument Validation (Architectural)

Even within the 10 typed functions, the `denylist.py` module checks every subprocess call before execution:
- **48 blocked binaries**: rm, dd, shred, wget, curl, ssh, bash, python, etc.
- **Dangerous argument blocking**: `sed -i`, `find -exec`, `find -delete`, `tar -x`, `awk system()`
- **Write path protection**: Any write operation targeting a registered evidence directory is blocked

**What it prevents**: Destructive commands smuggled via tool arguments
**How it's enforced**: `check_binary()` and `check_arguments()` called in `safe_subprocess()` before every `subprocess.run()`
**What happens if bypassed**: Would require modifying `denylist.py` or `common.py` source code

### Layer 3: shell=False (Architectural)

All subprocess calls use `shell=False`. This is hardcoded in `safe_subprocess()` in `parsers/common.py`. With `shell=False`:
- No shell metacharacters are interpreted (`;`, `|`, `&&`, `>`, `` ` ``)
- No command chaining is possible
- No environment variable expansion occurs
- Arguments are passed as a list, not a string

**What it prevents**: Shell injection via crafted arguments
**How it's enforced**: `subprocess.run(cmd, shell=False)` is the only subprocess call in the codebase
**What happens if bypassed**: Would require modifying `common.py` to change `shell=False` to `shell=True`

### Layer 4: Claude Code Hooks (Architectural)

Two shell scripts run as Claude Code hooks, inspecting tool calls at the framework level:

- **PreToolUse** (`pre-tool-use.sh`): Inspects every Bash command before execution. Blocks writes targeting evidence directories (`/cases/*/evidence/`, `/mnt/evidence/`). Returns `{"decision": "block"}` to prevent execution.
- **PostToolUse** (`post-tool-use.sh`): After every tool call, logs the tool name, arguments, output SHA256 hash, and timestamp to `logs/tool-execution.jsonl`. This creates the audit trail judges can use to trace findings.

**What it prevents**: Evidence modification via Bash commands that bypass the MCP server
**How it's enforced**: Claude Code framework executes hooks automatically; the model cannot disable them
**What happens if bypassed**: Would require modifying Claude Code's hook execution system

### Layer 5: Read-Only Evidence Mount (OS-Level)

Evidence directories are mounted read-only at the OS level:
```bash
mount -o ro /dev/sdb1 /cases/CASE-001/evidence/
```

This is the final backstop. Even if all software layers are compromised, the operating system prevents writes to the evidence partition.

**What it prevents**: Any modification to original evidence files
**How it's enforced**: Linux kernel filesystem permissions
**What happens if bypassed**: Would require root access to remount with write permissions

### Prompt-Based Guardrails (Documented as Non-Architectural)

In addition to the 5 architectural layers, VALKYRIE uses prompt-based guardrails in the skill protocols:

| Guardrail | Location | What It Does | Limitation |
|-----------|----------|-------------|------------|
| Pipeline sequencing | `orchestrator.md` | Instructs agent to follow 6-phase pipeline in order | Agent could skip phases if it decides to |
| Finding verification | `self-correction.md` | Instructs agent to re-verify findings with MCP tools | Agent could claim verification without actually running tools |
| Citation enforcement | `SKILL.md` | Requires every finding to cite specific tool output | Agent could generate plausible-looking citations without backing |
| Evidence tier assignment | `SKILL.md` | Requires distinguishing confirmed findings from inferences | Agent could assign wrong tier |

**These guardrails are valuable for quality but not trustworthy for safety.** Evidence protection relies on the 5 architectural layers, not on prompt compliance.

---

## Data Flow

```
Evidence (read-only)
    │
    ▼
MCP Server ──► safe_subprocess(shell=False) ──► SIFT Tool
    │                                              │
    │                                              ▼
    │                                         Raw output
    │                                              │
    │                                              ▼
    │◄─────────── parse_to_json() ◄───────── Structured JSON
    │
    ▼
Response Envelope (data + SHA256 + timestamp)
    │
    ▼
Claude Code (agent reasons about structured data)
    │
    ▼
Case Directory (writes findings, corrections, report)
    │
    ▼
Audit Trail (tool-execution.jsonl — every call logged)
```

---

## Architectural Pattern

VALKYRIE uses **Pattern 6: Purpose-Built MCP Server** from the hackathon guidance — described by organizers as "the most sound architecture in the evaluation."

Combined with **Claude Code as Direct Agent Extension** (Pattern 2), this creates a hybrid architecture:

- **Claude Code**: Reasoning engine, context management, skill framework, subagent dispatch
- **Custom MCP Server**: Safety enforcement, tool wrapping, data translation, audit logging
- **Skill Framework**: Analytical methodology, self-correction, evidence tiering, reporting

The analytical complexity lives in the skill framework (markdown protocols), not in the MCP server (Python code). The MCP server is deliberately lean — 5 tool modules, ~1500 lines of Python. The skill framework is where the intellectual work happens — 7 technique protocols, orchestrator, self-correction, evidence collector, 5 templates.

---

## Component Inventory

| Component | Files | Lines (approx) | Purpose |
|-----------|-------|----------------|---------|
| MCP Server | 8 .py files | ~1,500 | Safety, tool wrapping, audit logging |
| Skill Framework | 11 .md files | ~3,000 | Analytical reasoning, methodology, self-correction |
| Templates | 5 files | ~400 | Structured output formats |
| Hooks | 2 .sh files | ~100 | Evidence protection, audit logging |
| Configuration | 1 .json file | ~60 | MCP registration, permissions |
| **Total** | **27 core files** | **~5,000** | |
