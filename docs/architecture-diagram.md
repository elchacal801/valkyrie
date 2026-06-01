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
│  │  SKILL.md ──► Orchestrator ──► 9 Technique Protocols      │  │
│  │  /investigate    │            (hypothesis-driven swarm)    │  │
│  │                  ├─► Evidence Collector                    │  │
│  │                  ├─► Self-Correction (3 layers)            │  │
│  │                  ├─► Verification (CONFIRMED/INFERRED/      │  │
│  │                  │     UNVERIFIED, grounded in re-runs)     │  │
│  │                  ├─► Persistent Loop (measurable delta)     │  │
│  │                  └─► Report Generator (+ Verif. Ledger)    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              Technique Protocols                     │  │  │
│  │  │  timeline-reconstruction  │  artifact-correlation    │  │  │
│  │  │  hypothesis-testing       │  memory-analysis         │  │  │
│  │  │  persistence-enumeration  │  log-analysis            │  │  │
│  │  │  malware-triage           │  ai-adversary-analysis   │  │  │
│  │  │  cloud-log-analysis (Entra ID / Azure / M365)        │  │  │
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
│  │  │  73 blocked binaries      safe_subprocess()          │  │  │
│  │  │  argument validation      shell=False ALWAYS         │  │  │
│  │  │  path write protection    execution_id + SHA256 audit│  │  │
│  │  │                           output truncation          │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  │       │                                                    │  │
│  │  ┌────┴─────────────────────────────────────────────────┐  │  │
│  │  │  Tool Modules (typed functions only)                  │  │  │
│  │  │                                                      │  │  │
│  │  │  disk.py      ── mmls, fls, icat                     │  │  │
│  │  │  timeline.py  ── log2timeline, MFTECmd               │  │  │
│  │  │  memory.py    ── volatility3 (17-plugin allowlist)   │  │  │
│  │  │  registry.py  ── regripper, RECmd                    │  │  │
│  │  │  scanner.py   ── yara, strings/FLOSS                 │  │  │
│  │  │  cloud.py     ── Entra ID / Azure / M365 (read-only) │  │  │
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

The MCP server exposes **12 typed functions**, not a generic shell. The agent can call `get_partition_layout(image_path)` or `analyze_memory(dump_path, plugin)`, but it **cannot** construct arbitrary shell commands. This is the most fundamental constraint — the attack surface is limited to 12 well-defined operations.

**What it prevents**: Arbitrary command execution, filesystem modification, network access
**How it's enforced**: Python MCP server only registers specific `Tool` objects; JSON-RPC dispatch only routes to known handlers
**What happens if bypassed**: Would require modifying the MCP server source code itself

### Layer 2: Denylist + Argument Validation (Architectural)

Even within the 12 typed functions, the `denylist.py` module checks every subprocess call before execution:
- **73 blocked binaries**: rm, dd, shred, wget, curl, ssh, bash, python, etc.
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

| Guardrail | Location | What It Does | Limitation (and what mitigates it) |
|-----------|----------|-------------|------------|
| Pipeline sequencing | `orchestrator.md` | Instructs agent to follow the 6-phase pipeline in order | Agent could skip phases; the standardized report makes a skipped phase visible |
| Finding verification | `verification.md` / `self-correction.md` | Re-derives each finding from a fresh tool call (CONFIRMED/INFERRED/UNVERIFIED) | A claimed CONFIRMED **requires** a `verifier_exec_id` that must exist in `tool-execution.jsonl` — a fabricated verification is detectable in the audit log |
| Citation enforcement | `SKILL.md` | Requires every finding to cite a specific tool output | Citations carry an `execution_id`; a citation with no matching audit line is detectable |
| Evidence tier assignment | `SKILL.md` | Distinguishes confirmed findings from inferences | The `eval/` harness scores asserted vs inferred separately, surfacing miscalibration |

**These guardrails are valuable for quality but not trustworthy for safety.** Evidence protection relies on the 5 architectural layers, not on prompt compliance. The execution-id'd audit log makes *quality* guardrail compliance independently checkable, which is the next best thing.

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

Combined with **Claude Code as Direct Agent Extension** (Pattern 2), this creates a hybrid architecture that exercises all three execution patterns the hackathon recognizes:

- **Single-agent** — the default `/investigate` direct/guided flow (reference-grade, low risk)
- **Multi-agent** — Phase 3 dispatches parallel Tier-1 subagents, with an early contradiction pass before Tier-2 (a hypothesis-driven swarm)
- **Persistent loop** — `--loop` iterates to verifiable success with a measured first→final accuracy delta

Layering:

- **Claude Code**: Reasoning engine (Claude Opus 4.8), context management, skill framework, subagent dispatch
- **Custom MCP Server**: Safety enforcement, tool wrapping, data translation, execution-id'd audit logging
- **Skill Framework**: Analytical methodology, self-correction + verification, persistent loop, evidence tiering, reporting

The analytical complexity lives in the skill framework (markdown protocols), not in the MCP server (Python code). The MCP server is deliberately lean — 6 tool modules of typed wrappers. The skill framework is where the intellectual work happens — 9 technique protocols (including AI-adversary and cloud-log analysis), orchestrator, self-correction, verification, persistent loop, evidence collector, and templates.

---

## Component Inventory

| Component | Files | Lines (approx) | Purpose |
|-----------|-------|----------------|---------|
| MCP Server | 9 .py modules | ~1,900 | Safety, tool wrapping (incl. cloud), execution-id'd audit logging |
| Skill Framework | 14 .md files | ~3,600 | Analytical reasoning, self-correction, verification, persistent loop |
| Templates | 5 files | ~450 | Structured output formats (+ verification block / ledger) |
| Accuracy Harness | `eval/` (script + ground truth + examples) | ~400 | precision/recall/F1 vs documented ground truth |
| Tests | 5 test files | ~900 | 81 tests: parsers, denylist, server dispatch, hooks, eval, cloud |
| Hooks | 2 .sh files | ~135 | Evidence protection, audit logging |
| CI | `.github/workflows` + Makefile | ~60 | Automated tests on 3.10–3.12 |
| **Total** | **40+ core files** | **~7,500** | |
