<p align="center">
  <img src="docs/images/valkyrie-banner-v2.jpeg" alt="VALKYRIE" width="100%"/>
</p>

<h1 align="center">VALKYRIE</h1>

<p align="center">
  <strong>Teach an AI agent to think like a senior forensic analyst.</strong>
</p>

<p align="center">
  Autonomous incident response with structured analytical reasoning,<br/>
  per-finding verification, a measurable learning loop, and architectural evidence protection.
</p>

<p align="center">
  <a href="https://findevil.devpost.com/"><img src="https://img.shields.io/badge/SANS-Find%20Evil!-2ecc71?style=flat-square" alt="Find Evil!"/></a>
  <img src="https://img.shields.io/badge/framework-Claude%20Code-cc785c?style=flat-square" alt="Claude Code"/>
  <img src="https://img.shields.io/badge/architecture-Custom%20MCP-5c8fcc?style=flat-square" alt="MCP Server"/>
  <img src="https://img.shields.io/badge/tests-81%20passing-brightgreen?style=flat-square" alt="Tests"/>
  <img src="https://img.shields.io/badge/model-Claude%20Opus%204.8-cc785c?style=flat-square" alt="Claude Opus 4.8"/>
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="MIT License"/>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#results">Results</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#self-correction-in-action">Self-Correction</a> ·
  <a href="docs/sample-output/TEST-001/report/investigation-report.md">Sample Report</a> ·
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
| Hallucination handling | Hope for the best | Per-finding verdicts — CONFIRMED / INFERRED / **UNVERIFIED** (flagged, not hidden) |
| Improvement | One pass | Persistent learning loop with a measurable first→final accuracy gain |
| Scope | Host disk only | Host **and** cloud (Entra ID / Azure / M365 identity-plane attacks) |
| Reasoning | Hidden | Transparent hypothesis testing (ACH for IR) |
| Audit trail | Tool execution log | Case directory IS the audit trail — every finding cites an `execution_id` |

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
    ├── Orchestrator (6-phase IR pipeline + hypothesis-driven subagent swarm)
    ├── Self-Correction (3 forensic validation layers)
    ├── Verification (per-finding CONFIRMED / INFERRED / UNVERIFIED grounding)
    ├── Persistent Learning Loop (iterate to verifiable success; measured delta)
    ├── 9 Technique Protocols (IR-adapted SATs + AI-adversary + cloud)
    └── Templates & Reporting (+ Verification Ledger)
    │
Claude Code Hooks (evidence protection + audit logging)
    │
Custom MCP Server (Python, stdio transport)
    ├── 6 tool modules (12 tools): disk, timeline, memory, registry, scanner, cloud
    ├── 17 Volatility plugins with ISF symbol auto-resolution
    ├── Entra ID / Azure / M365 cloud-log analysis (ATT&CK for Cloud)
    └── Denylist (73 binaries) + shell=False + execution_id'd SHA256 audit logging
    │
SIFT Workstation Tools (sleuthkit, volatility3, plaso, yara, floss, regripper)
    │
Evidence (read-only, write-protected at 5 architectural layers)
    │
Accuracy Harness (eval/) — precision/recall/F1 vs documented ground truth
```

### Trust Boundaries

**Architectural enforcement (not prompt-based)** — these hold even if the model is fully jailbroken:
1. **Typed MCP server** — 12 read-only functions, no shell access to the agent
2. **Denylist** — 73 blocked binaries (rm, dd, wget, curl, ssh) at subprocess level
3. **shell=False** — hardcoded on every subprocess call, no injection possible
4. **PreToolUse hook** — blocks any write attempt to evidence directories
5. **PostToolUse hook** — logs every tool call with SHA256 hash of output

**Prompt-based guidance (CLAUDE.md / protocols)** — workflow and analytical rigor (MCP-first rule, citation requirement, technique selection). These shape *how* the agent reasons; the five layers above enforce *what it can do* regardless.

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
/investigate cloud                              # Entra ID / Azure / M365 identity-plane analysis
/investigate --guided                           # Walk through all 6 IR phases
/investigate --lean                             # Fast triage (3 techniques)
/investigate --loop <case-id>                   # Persistent learning loop until verifiable success
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
| 5 | Self-Correction & Verification | 3-layer validation + per-finding grounding (CONFIRMED/INFERRED/UNVERIFIED) | `corrections/` |
| 6 | Reporting | Structured narrative + Verification Ledger, citations to specific artifacts | `report/` |

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

## Quantified Accuracy

VALKYRIE ships an **accuracy harness** (`eval/`) that scores findings against documented
ground truth and emits the report's required false-positive / missed-artifact tables:

```bash
make eval        # self-test on the bundled fixture
python eval/run_eval.py --findings <case>/report/findings.json \
                        --truth eval/ground_truth/nist-hacking-case.json --out <case>/report
```

Precision is measured only over **asserted** claims, so Tier-3 inferences are never
mistaken for hallucinations — and the persistent loop records F1 per iteration to prove
a first→final improvement. Ground-truth sets: NIST CFReDS Hacking Case (disk), a public
memory-image template, and a synthetic Entra/Azure/M365 sample (scores P/R/F1 = 1.0). See
[`eval/README.md`](eval/README.md). To reproduce on real evidence end-to-end, follow the
[live-run runbook](docs/live-run-runbook.md).

## Judging Criteria Alignment

The SANS FIND EVIL! Stage-2 rubric weights three axes equally; the called-out qualities
(hallucination management, persistent loop, guardrails, audit trail) map as follows:

| Criterion | Where to Look |
|-----------|--------------|
| **Autonomous Execution Quality** | `/investigate --guided` runs 6 phases unattended; `--loop` self-corrects to verifiable success. See `skills/ir-analysis/protocols/orchestrator.md` |
| **IR Accuracy / hallucination mgmt** | Per-finding verdicts (`protocols/verification.md`) + quantified `eval/` harness. Confirmed vs inferred is a first-class output; UNVERIFIED claims are flagged, not hidden |
| **Breadth & Depth** | 9 technique protocols (incl. AI-adversary + **cloud**), 12 MCP tools, 17 Volatility plugins, host **and** identity-plane coverage |
| **Persistent Learning Loop** | `protocols/persistent-loop.md` — `logs/progress.jsonl` with first→final accuracy delta and full iteration traces |
| **Architectural guardrails** | [`docs/architecture-diagram.md`](docs/architecture-diagram.md) — 5 architectural layers, explicitly separated from prompt-based guidance |
| **Audit Trail** | `logs/tool-execution.jsonl` — every line has an `execution_id`; every finding cites `exec:<id>` so any claim traces to one tool execution + its SHA256 |
| **Documentation / Usability** | One-command install, CI (81 tests), `CLAUDE.md`, dataset docs, fallback strategies |

## Novel Contribution

VALKYRIE's analytical reasoning framework is inspired by [Blevene/structured-analysis-skill](https://github.com/Blevene/structured-analysis-skill) (Apache 2.0), which implements CIA/IC Structured Analytic Techniques. The novel contributions are:

- **IR-specific technique library** — 9 forensic techniques (timeline reconstruction, artifact correlation, ACH-adapted hypothesis testing, memory analysis, persistence enumeration, log analysis, malware triage, AI-adversary analysis, and cloud-log analysis)
- **AI-adversary detection** — First IR agent to reason about AI-driven attacks as a distinct threat category, grounded in GTIG, MITRE ATLAS v5.4.0, Arctic Wolf, and Unit42 threat intelligence. Six analytical lenses: behavioral entropy, credential automation, LOLBin chaining, API-based attacks, absence-of-evidence, and decoy artifact detection
- **Per-finding verification** — Chain-of-verification grounded in *fresh tool calls* (never re-reasoning, which only inflates confidence): every finding is CONFIRMED / INFERRED / UNVERIFIED, so hallucinations are caught and flagged rather than presented as fact
- **Forensic self-correction** — Three-layer validation (artifact existence, temporal consistency, analytical coherence) catching IR-specific hallucination patterns
- **Measurable persistent learning loop** — Iterates to verifiable success criteria with a demonstrable first→final accuracy delta and preserved iteration traces
- **Cloud-forensics breadth** — Entra ID / Azure / M365 identity-plane analysis (impossible travel, MFA fatigue, OAuth consent abuse, BEC inbox rules…) mapped to ATT&CK for Cloud — for attacks that never touch a host disk
- **Quantified accuracy harness** — precision/recall/F1 vs documented ground truth, distinguishing asserted claims from inferences
- **Custom MCP server** — 12 typed functions with denylist enforcement, `execution_id`-stamped SHA256 audit logging, ISF symbol auto-resolution, controlled process memory dump, FLOSS-first string extraction
- **Resilient memory analysis** — Pool-scanning fallback when ISF symbols are missing, with graceful degradation documented in findings

### Built on frontier Claude

VALKYRIE targets **Claude Opus 4.8** — the same Claude Code + MCP reference architecture
SANS demoed — and uses its extended-reasoning for hypothesis generation and verifier
adjudication. Forensic findings are *verifiable rewards* (an artifact either re-derives at
its cited offset or it does not), which is exactly what frontier reasoning + grounded
verification exploit. Running on a frontier model rather than a small local default is a
deliberate accuracy choice for high-stakes IR.

## License

MIT — see [LICENSE](LICENSE).

## Author

Diego Parra / [CrimsonVector Security](https://crimsonvector.com/)
