<p align="center">
  <img src="docs/images/valkyrie-banner.jpeg" alt="VALKYRIE" width="100%"/>
</p>

<h1 align="center">VALKYRIE</h1>

<p align="center">
  <strong>Teach an AI agent to think like a senior forensic analyst.</strong>
</p>

<p align="center">
  Autonomous incident response with structured analytical reasoning,<br/>
  multi-layer self-correction, and architectural evidence protection.
</p>

<p align="center">
  <a href="https://findevil.devpost.com/"><img src="https://img.shields.io/badge/SANS-Find%20Evil!-2ecc71?style=flat-square" alt="Find Evil!"/></a>
  <img src="https://img.shields.io/badge/framework-Claude%20Code-cc785c?style=flat-square" alt="Claude Code"/>
  <img src="https://img.shields.io/badge/architecture-Custom%20MCP-5c8fcc?style=flat-square" alt="MCP Server"/>
  <img src="https://img.shields.io/badge/tests-46%20passing-brightgreen?style=flat-square" alt="Tests"/>
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="MIT License"/>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#results">Results</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#self-correction-in-action">Self-Correction</a> ·
  <a href="docs/accuracy-report.md">Accuracy Report</a>
</p>

---

**Validated Autonomous Logic for Kill-chain Yielding Rapid Incident Examination**

An autonomous AI incident response agent for the [SANS "Find Evil!" Hackathon](https://findevil.devpost.com/). VALKYRIE runs on the SIFT Workstation, uses Claude Code as the agentic framework, and leverages a custom MCP server with structured analytical reasoning to investigate digital forensic evidence.

## What Makes VALKYRIE Different

Most forensic AI agents are **tool runners** — they wrap forensic tools behind an LLM and execute them in sequence. VALKYRIE is an **analytical reasoner** — it applies structured analytic techniques adapted from US Intelligence Community doctrine to investigate incidents with hypothesis testing, evidence tiering, and multi-layer self-correction.

| Capability | Tool Runner | VALKYRIE |
|-----------|------------|----------|
| Tool execution | Sequential phases | Adaptive technique selection based on evidence |
| Findings | Binary (found/not found) | 3-tier evidence with confidence scores |
| Self-correction | Retry on failure | 3-layer forensic validation (artifact, temporal, analytical) |
| Reasoning | Hidden | Transparent hypothesis testing (ACH for IR) |
| Audit trail | Tool execution log | Case directory IS the audit trail — every finding cites its source |

## Results

Tested against the SRL-2018 Compromised Enterprise Network — memory dumps from a domain controller and two workstations.

### What VALKYRIE Found Autonomously

- **Cobalt Strike SMB Beacon** on workstations via WMI lateral movement, C2 over named pipe `\\.\pipe\diagsvc-22`
- **Meterpreter reverse_https** on the DC connecting to external C2 at `52.41.122.38:443`
- **Mimikatz credential dumping** (`sekurlsa::logonpasswords`) on the DC — all domain credentials compromised
- **PowerSploit framework** including Kerberoasting, keylogging, and AMSI bypass
- **Complete kill chain** mapped across 15+ MITRE ATT&CK techniques
- **Cross-host correlation**: identical Cobalt Strike payloads on both workstations, WMI sourced from DC

**19 findings** across 3 investigations | **16 Tier 1, 3 Tier 3** | **0 hallucinated artifacts** | **2 false positives caught**

### Self-Correction in Action

During the first investigation, VALKYRIE initially flagged `subject_srv.exe` as a suspicious backdoor (listening on port 3262, registered as a service, started 14 minutes before memory capture). It then discovered a Windows Event ID 7045 in memory strings:

```
ServiceName: F-Response Subject
ImagePath: C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262
```

**F-Response is a legitimate forensic acquisition tool deployed by the IR team.** VALKYRIE reclassified the finding from HIGH-severity backdoor to BENIGN before it reached the final report. In the same investigation, it reclassified `172.16.4.10:8080` from "C2 server" to "corporate web proxy" after finding the PAC file in memory.

This is the difference between a tool runner and an analytical reasoner: **the ability to challenge your own initial assessment when contradicting evidence appears.**

## Architecture

```
Claude Code (reasoning engine)
    │
VALKYRIE Skill Framework (/investigate command)
    ├── Orchestrator (6-phase IR pipeline)
    ├── Self-Correction (3 forensic validation layers)
    ├── 7+ Technique Protocols (IR-adapted SATs)
    └── Templates & Reporting
    │
Claude Code Hooks (evidence protection + audit logging)
    │
Custom MCP Server (Python, stdio transport)
    ├── 5 tool modules (11 tools): disk, timeline, memory, registry, scanner
    ├── 17 Volatility plugins with ISF symbol auto-resolution
    ├── FLOSS-first string extraction, controlled process memory dump
    └── Denylist (73 binaries) + shell=False + SHA256 audit logging
    │
SIFT Workstation Tools (sleuthkit, volatility3, plaso, yara, floss, regripper)
    │
Evidence (read-only, write-protected at 5 architectural layers)
```

### Trust Boundaries

**Architectural enforcement (not prompt-based):**
1. **Typed MCP server** — 11 read-only functions, no shell access to the agent
2. **Denylist** — 73 blocked binaries (rm, dd, wget, curl, ssh) at subprocess level
3. **shell=False** — hardcoded on every subprocess call, no injection possible
4. **PreToolUse hook** — blocks any write attempt to evidence directories
5. **PostToolUse hook** — logs every tool call with SHA256 hash of output

## Quick Start

```bash
# On SIFT Workstation (WSL2 or native)
git clone https://github.com/elchacal801/valkyrie.git
cd valkyrie
chmod +x install.sh && ./install.sh

# Run an investigation
cd /opt/valkyrie
claude
/investigate --guided --evidence-path /cases/CASE-001/evidence/
```

## Usage

```
/investigate                                    # Auto-assess evidence, select techniques
/investigate memory                             # Memory analysis specifically
/investigate timeline                           # Timeline reconstruction
/investigate --guided                           # Walk through all 6 IR phases
/investigate --lean                             # Fast triage (3 techniques)
/investigate --resume <case-id>                 # Continue a previous investigation
/investigate --iterate <case-id>                # Re-run with corrected approach
/investigate --evidence-path /path/to/evidence  # Specify evidence location
```

## Investigation Pipeline

| Phase | Name | What Happens | Output |
|-------|------|-------------|--------|
| 1 | Evidence Inventory | Catalog files, compute SHA256, classify types | `inventory.json` |
| 2 | Triage Assessment | YARA scan, process listing, network connections, anomaly detection | `triage.json` |
| 3 | Deep Analysis | Execute technique protocols against evidence | `analysis/*.json` |
| 4 | Correlation & Synthesis | Cross-reference findings, build attack narrative, ACH | `synthesis.json` |
| 5 | Self-Correction | 3-layer forensic validation with auto-remediation | `corrections/` |
| 6 | Reporting | Structured narrative with citations to specific artifacts | `report/` |

## Evidence Tiers

| Tier | Source | Confidence |
|------|--------|------------|
| Tier 1 | Direct tool output (single MCP call) | Highest — single-source confirmed |
| Tier 2 | Cross-referenced (2+ tools corroborate) | High — multi-source confirmed |
| Tier 3 | Analytical inference (agent reasoning) | Variable — requires explicit confidence score |

## Resilience

VALKYRIE handles real-world tool failures gracefully:

- **ISF symbol mismatch**: When Volatility3 `pslist`/`cmdline`/`malfind` return empty (missing symbols), automatically falls back to pool-scanning plugins (`psscan`/`netscan`) which work without symbols. Documents the limitation in findings.
- **Partial evidence**: Memory-only evidence? Pipeline adapts technique selection — skips disk-only techniques, adjusts to memory + malware triage + memory-based persistence.
- **Tool failure**: If a tool crashes or times out, the MCP server returns a structured error. The protocol guides the agent to alternative approaches, not dead ends.

## Judging Criteria Alignment

| Criterion | Where to Look |
|-----------|--------------|
| **#1 Autonomous Execution** (tiebreaker) | Run `/investigate --guided` — 6 phases execute without human input. See `skills/ir-analysis/SKILL.md` |
| **#2 IR Accuracy** | [`docs/accuracy-report.md`](docs/accuracy-report.md) — 19 findings, 0 hallucinations, 2 self-corrections |
| **#3 Breadth & Depth** | 7 technique protocols, 11 MCP tools, 17 Volatility plugins. See `skills/ir-analysis/protocols/` |
| **#4 Constraint Implementation** | [`docs/architecture-diagram.md`](docs/architecture-diagram.md) — 5 architectural layers, 46 unit tests |
| **#5 Audit Trail** | `logs/tool-execution.jsonl` in every case directory. Every finding cites `[TOOL: name, evidence, detail]` |
| **#6 Usability** | One-command install, `CLAUDE.md` project guide, fallback strategies documented |

## Novel Contribution

VALKYRIE's analytical reasoning framework is inspired by [Blevene/structured-analysis-skill](https://github.com/Blevene/structured-analysis-skill) (Apache 2.0), which implements CIA/IC Structured Analytic Techniques. The novel contributions are:

- **IR-specific technique library** — 7+ forensic techniques (timeline reconstruction, artifact correlation, ACH-adapted hypothesis testing, memory analysis, persistence enumeration, log analysis, malware triage)
- **Forensic self-correction** — Three-layer validation (artifact existence, temporal consistency, analytical coherence) catching IR-specific hallucination patterns
- **Custom MCP server** — 11 typed functions with denylist enforcement, SHA256 audit logging, ISF symbol auto-resolution, controlled process memory dump, FLOSS-first string extraction
- **Evidence tiering** — Distinguishing confirmed findings from analytical inferences with explicit confidence scoring
- **Resilient memory analysis** — Pool-scanning fallback when ISF symbols are missing, with graceful degradation documented in findings

## License

MIT — see [LICENSE](LICENSE).

## Author

Diego Parra / [CrimsonVector Security](https://crimsonvector.com/)
