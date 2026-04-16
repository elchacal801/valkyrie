---
name: investigate
description: Conduct autonomous incident response investigation on forensic evidence using structured analytical techniques — inventory evidence, triage anomalies, reconstruct timelines, correlate artifacts, test competing hypotheses, validate findings, and produce a defensible investigative report with full citations to specific tool outputs and artifact locations.
argument-hint: "[technique or flags, e.g. timeline, memory, --guided, --lean, --evidence-path /cases/001/evidence]"
allowed-tools: Agent, Task, Read, Write, Glob, Grep, Bash, mcp__valkyrie__get_partition_layout, mcp__valkyrie__list_files, mcp__valkyrie__extract_file, mcp__valkyrie__generate_timeline, mcp__valkyrie__extract_mft, mcp__valkyrie__analyze_memory, mcp__valkyrie__get_registry_key, mcp__valkyrie__check_persistence, mcp__valkyrie__scan_yara, mcp__valkyrie__extract_strings, mcp__valkyrie__dump_process_memory
---

# VALKYRIE IR Analysis Skill

Conduct structured forensic investigations using techniques adapted from intelligence community analytical doctrine. Every finding must cite a specific tool output. Every judgment must trace to evidence. Confirmed findings are distinguished from analytical inferences.

## Invocation

```
/investigate                                    → Adaptive mode (auto-assess evidence, select techniques)
/investigate <technique>                        → Direct mode (run one technique)
/investigate --guided                           → Guided mode (walk through all 6 IR phases)
/investigate --resume <case-id>                 → Resume or update existing investigation
/investigate --iterate <case-id>                → Re-run with corrected approach or new evidence
/investigate --iterate <case-id> <technique>    → Re-run specific technique(s) only
/investigate --lean                             → Lean mode (triage + timeline + persistence only)
/investigate --evidence-path <path>             → Specify evidence directory (default: auto-detect)
/investigate --case-id <id>                     → Specify case identifier (default: auto-generate)
/investigate --no-enrich                        → Disable IOC enrichment / threat intel lookup
```

Techniques: `timeline`, `correlation`, `hypothesis`, `memory`, `persistence`, `logs`, `malware`, `ai-adversary`, `ioc-enrich`, `lateral`, `root-cause`

Flags combine: `/investigate --guided --lean --evidence-path /cases/001/evidence` is valid.

## Execution

**You MUST read the orchestrator protocol before proceeding.** It contains phase routing, technique selection logic, and the technique routing table.

### Step -1 — Investigation Banner

When the investigation starts, display this banner to clearly mark the beginning of a VALKYRIE investigation:

```
========================================================================
  VALKYRIE — Autonomous IR Investigation
  SANS Find Evil! Hackathon 2026
------------------------------------------------------------------------
  Case ID:    [case-id]
  Evidence:   [evidence-path]
  Mode:       [adaptive | guided | lean | direct:<technique>]
  Started:    [timestamp]
========================================================================
```

### Phase Progress

At the start of each phase, display a progress marker:

```
--- Phase [N]/6: [Phase Name] -------------------------------------------
```

At the end of each phase, display a completion summary:

```
[Phase N complete] [key metric, e.g., "5 findings" or "0 corrections"]
```

### Step 0 — Context Inference

Before parsing explicit arguments, scan the conversation history and working directory for implicit inputs:

- **Evidence location**: Has the user mentioned a path to evidence files? Are there disk images (.E01, .raw, .dd), memory dumps (.raw, .vmem, .lime), logs (.evtx), or registry hives in the current directory or a nearby `/cases/` directory?
- **Case context**: Has the user described the incident? (ransomware, lateral movement, data exfiltration, malware infection, insider threat) Map these to relevant techniques.
- **Prior investigation**: Are there existing case directories in `/cases/` for the same evidence? (→ suggest `--resume` or `--iterate`)
- **Implicit mode hints**: Did the user say "quick look" (→ `--lean`), "full investigation" (→ `--guided`), or reference a specific analysis type (→ direct technique)?
- **Known IOCs**: Has the user provided IP addresses, file hashes, domain names, or process names to look for?

### Step 0.1 — Validate Assumptions

If context inference produced any results, present them to the user for confirmation:

```
Based on our conversation and the evidence I can see:

**Evidence path**: [detected or specified path]
**Evidence types**: [disk image, memory dump, logs, etc.]
**Mode**: [inferred mode + rationale]
**Techniques**: [inferred techniques based on evidence types]
**Known IOCs**: [any IOCs mentioned, or "none provided"]

Does this look right? Adjust anything before I proceed.
```

If the user provided explicit arguments, those always take precedence over inferences.

If no evidence path can be determined, ask the user: "Where is the evidence? Provide the path with `--evidence-path <path>` or tell me where to look."

### Steps 1–6 — Main Execution

1. Read `protocols/orchestrator.md` (relative to this skill's directory)
2. Parse explicit arguments → determine mode and flags (merge with Step 0 inferences, explicit args win)
3. Follow the orchestrator's instructions for the detected mode
4. For technique execution, follow the orchestrator's Technique Execution Contract:
   - **1 technique** (Direct mode): Execute in-context — read protocol, read template, execute SETUP → PRIME → EXECUTE → ARTIFACT → FINDINGS → HANDOFF, write artifact to case directory
   - **2+ techniques**: Dispatch to subagents in dependency-aware tiers — each subagent reads protocol/template, executes the technique, writes the artifact, and returns a compact findings summary
5. For evidence inventory: read and execute `protocols/evidence-collector.md`
6. For report synthesis: follow the orchestrator's Phase 6 reporting instructions

## Investigation Pipeline

The orchestrator controls a 6-phase pipeline. Each phase reads the previous phase's output from the case directory and writes its own structured output. This is the pipeline architecture — context does not accumulate across phases.

| Phase | Name | Input | Output | Key Actions |
|-------|------|-------|--------|-------------|
| 1 | Evidence Inventory | Evidence path | `inventory.json` | Catalog files, compute SHA256 hashes, classify evidence types |
| 2 | Triage Assessment | `inventory.json` | `triage.json` | YARA scan, partition layout, initial timeline bounds, obvious anomalies |
| 3 | Deep Analysis | `triage.json` + evidence | `analysis/*.json` | Execute selected technique protocols against evidence |
| 4 | Correlation & Synthesis | `analysis/*.json` | `synthesis.json` | Cross-reference findings, build attack narrative, assign evidence tiers |
| 5 | Self-Correction | All prior outputs | `corrections/` | Three-layer forensic validation with auto-remediation |
| 6 | Reporting | All outputs + corrections | `report/` | Structured investigative narrative with citations |

## Self-Correction (3 Forensic Validation Layers)

Self-correction is the core differentiator. It catches IR-specific hallucination patterns that generic AI agents miss.

- **Layer 1 — Artifact Existence** (after each technique, silent): Does every referenced file path, offset, registry key, PID, and log entry actually exist in the evidence? Re-invoke the relevant MCP tool to verify.
- **Layer 2 — Temporal Consistency** (before synthesis, silent): Are all timestamps chronologically possible? Do MAC times align with the claimed narrative? Are timezone conversions correct? Are there unexplained gaps?
- **Layer 3 — Analytical Coherence** (before reporting, silent): Does the attack narrative follow a plausible kill chain? Are there alternative explanations not considered? Do MITRE ATT&CK mappings match the observed artifacts? Would a senior analyst challenge any conclusion?
- **Auto-Remediation**: When any layer detects a HIGH-severity issue: log the issue, re-invoke the relevant MCP tool for ground truth, document what changed, flag the correction in the final report. Capped at 3 corrections per layer per run.

All corrections are logged to `corrections/correction-NNN.json` with full traceability: what was wrong, how it was detected, what the corrected value is, and the SHA256 hash of the verification tool output.

## Evidence Tiers

Every finding includes its evidence tier and citation:

- **Tier 1 (Highest confidence)**: Direct tool output. One artifact, one tool, one finding.
  Citation: `[TOOL: volatility3.pslist, evidence: memory.raw, PID: 4832, offset: 0x...]`

- **Tier 2 (High confidence)**: Cross-referenced — 2+ independent tools corroborate the same finding.
  Citation: `[CORROBORATED: volatility3.netscan + timeline.MFT @ 2026-03-15T14:23:00Z + registry.Run key]`

- **Tier 3 (Variable confidence)**: Analytical inference — the agent's reasoning connecting artifacts. Must be explicitly labeled as inference with a confidence score (HIGH/MEDIUM/LOW).
  Citation: `[INFERENCE: lateral movement via RDP based on event correlation, confidence: MEDIUM]`

The tier is determined by which pipeline phase produced the finding: Phase 3 → Tier 1, Phase 4 → Tier 2 or 3.

## Report Standardization Rule

**Every investigation report MUST include ALL sections defined in `templates/investigation-report.md`, regardless of mode, evidence type, or phases executed.** The report structure is identical every time — no sections are ever omitted.

When a section's corresponding phase or technique was not executed, the section MUST:
1. Still appear with its heading
2. State **"Not performed."** followed by a specific reason (e.g., which phase was skipped and why)
3. Include a remediation path (e.g., `/investigate --iterate <CASE-ID> hypothesis`)

This ensures operational consistency for IR/IM workflows — the report consumer always knows what to expect and can immediately see what analysis remains to be done.

## Citation Requirement

Every claim in every artifact must be cited. No exceptions. Citation formats:

| Source | Format |
|--------|--------|
| MCP tool output | `[TOOL: <tool_name>, evidence: <file>, <key_detail>]` |
| Cross-reference | `[CORROBORATED: <tool1> + <tool2> @ <timestamp_or_detail>]` |
| Inference | `[INFERENCE: <reasoning summary>, confidence: HIGH\|MEDIUM\|LOW]` |
| Prior phase | `[PHASE: <phase_name>, finding: <finding_id>]` |
| User-provided | `[USER: session context]` |
| Self-correction | `[CORRECTED: was <original>, now <corrected>, verified by <tool>]` |

Tool output is presented as fact when the tool executed successfully. Inferences are never presented as confirmed findings — always qualified with confidence level.

## Case Directory Structure

The investigation writes all output to a structured case directory. This directory IS the audit trail — judges can navigate it to trace any finding back to the tool execution that produced it.

```
/cases/<CASE-ID>/
├── evidence/                    # Read-only mounted evidence (NEVER written to)
├── inventory.json               # Phase 1: evidence catalog with SHA256 hashes
├── triage.json                  # Phase 2: initial findings, anomalies, timeline bounds
├── analysis/                    # Phase 3: per-technique deep analysis
│   ├── timeline-reconstruction.json
│   ├── memory-analysis.json
│   ├── artifact-correlation.json
│   └── hypothesis-testing.json
├── synthesis.json               # Phase 4: cross-referenced attack narrative
├── corrections/                 # Phase 5: self-correction log
│   ├── correction-001.json
│   ├── correction-002.json
│   └── validation-summary.json
├── report/                      # Phase 6: final deliverables
│   ├── investigation-report.md
│   ├── findings.json
│   └── accuracy-report.md
├── logs/                        # Agent execution audit trail
│   ├── tool-execution.jsonl
│   └── reasoning-trace.jsonl
└── CASE.md                      # Case metadata
```

## Context Window Management

Forensic investigations can generate massive tool output. Follow these rules to prevent context overflow:

1. **MCP tool outputs are pre-parsed and truncated** by the server before reaching you. Work with the structured JSON summaries, not raw tool output.
2. **Read phase outputs from disk** — each phase writes to the case directory. Read prior phase files rather than relying on conversation context.
3. **When executing 2+ techniques**, dispatch as subagents (each gets a fresh context window).
4. **Run `/compact` between Phase 4 and Phase 5** — this is the peak context accumulation point.
5. **Never load all technique protocols at once** — the orchestrator tells you which protocols to load for the current phase.

## Technique Routing Table

| Invocation | Protocol File | Artifact Output | Phase |
|-----------|---------------|-----------------|-------|
| `timeline` | `protocols/techniques/timeline-reconstruction.md` | `analysis/timeline-reconstruction.json` | Deep Analysis |
| `correlation` | `protocols/techniques/artifact-correlation.md` | `analysis/artifact-correlation.json` | Correlation |
| `hypothesis` | `protocols/techniques/hypothesis-testing.md` | `analysis/hypothesis-testing.json` | Correlation |
| `memory` | `protocols/techniques/memory-analysis.md` | `analysis/memory-analysis.json` | Deep Analysis |
| `persistence` | `protocols/techniques/persistence-enumeration.md` | `analysis/persistence-enumeration.json` | Deep Analysis |
| `logs` | `protocols/techniques/log-analysis.md` | `analysis/log-analysis.json` | Deep Analysis |
| `malware` | `protocols/techniques/malware-triage.md` | `analysis/malware-triage.json` | Deep Analysis |
| `ai-adversary` | `protocols/techniques/ai-adversary-analysis.md` | `analysis/ai-adversary-analysis.json` | Correlation |

All paths are relative to the skill directory (`skills/ir-analysis/`).
