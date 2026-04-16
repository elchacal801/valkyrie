# Orchestrator Protocol

Route modes, select techniques, and manage the 6-phase IR investigation pipeline.

---

## Mode Detection

Parse the skill invocation arguments:

| Input | Mode |
|-------|------|
| No args | **Adaptive** — auto-assess evidence, select techniques |
| Technique name (e.g., `timeline`, `memory`) | **Direct** — run single technique |
| `--guided` | **Guided** — walk through all 6 IR phases |
| `--resume <case-id>` | **Resume** — continue existing investigation |
| `--iterate <case-id>` | **Iterate** — re-run with corrected approach |
| `--iterate <case-id> <technique>` | **Iterate (scoped)** — re-run specific technique(s) |
| `--lean` | **Lean** — triage + timeline + persistence only |
| `--no-enrich` | Flag — disable IOC enrichment |
| `--evidence-path <path>` | Flag — specify evidence directory |
| `--case-id <id>` | Flag — specify case identifier |

Flags combine with modes: `--guided --lean --evidence-path /cases/001/evidence` is valid.

### Mode Conflict Resolution

| Combination | Resolution |
|---|---|
| `--lean` + `--guided` | Lean overrides technique selection; guided phases still execute |
| `--lean` + technique name | ERROR: lean mode selects its own techniques — cannot combine with direct mode |
| `--resume` + `--iterate` | ERROR: choose one |

---

## Technique Routing Table

| Invocation | Protocol File | Artifact Output | Phase | Evidence Requires |
|-----------|---------------|-----------------|-------|-------------------|
| `timeline` | `protocols/techniques/timeline-reconstruction.md` | `analysis/timeline-reconstruction.json` | Deep Analysis | Disk image OR logs |
| `correlation` | `protocols/techniques/artifact-correlation.md` | `analysis/artifact-correlation.json` | Correlation | 2+ Phase 3 outputs |
| `hypothesis` | `protocols/techniques/hypothesis-testing.md` | `analysis/hypothesis-testing.json` | Correlation | 2+ evidence types |
| `memory` | `protocols/techniques/memory-analysis.md` | `analysis/memory-analysis.json` | Deep Analysis | Memory dump |
| `persistence` | `protocols/techniques/persistence-enumeration.md` | `analysis/persistence-enumeration.json` | Deep Analysis | Disk image |
| `logs` | `protocols/techniques/log-analysis.md` | `analysis/log-analysis.json` | Deep Analysis | Log files (.evtx) |
| `malware` | `protocols/techniques/malware-triage.md` | `analysis/malware-triage.json` | Deep Analysis | Suspicious files |

All paths are relative to the skill directory (`skills/ir-analysis/`).

---

## Case Directory Setup

At the start of ANY investigation:

1. Determine case ID:
   - If `--case-id` provided: use that
   - Otherwise: generate as `CASE-YYYY-MM-DD-<incident-type-slug>` (e.g., `CASE-2026-04-15-ransomware`)
2. Create the case directory structure:
   ```
   /cases/<CASE-ID>/
   ├── analysis/
   ├── corrections/
   ├── report/
   └── logs/
   ```
3. Copy `case-templates/CASE.md` to `/cases/<CASE-ID>/CASE.md`
4. Fill in known metadata fields in CASE.md
5. Set environment variable: `export VALKYRIE_CASE_DIR=/cases/<CASE-ID>`
6. Record the case directory path — all outputs go here

---

## Evidence Type Assessment

After Phase 1 (Evidence Inventory) completes and writes `inventory.json`, assess the available evidence to drive technique selection.

### Evidence Classification

| File Extension / Signature | Evidence Type | Enables Techniques |
|---------------------------|---------------|-------------------|
| `.E01`, `.raw`, `.dd`, `.img`, `.vmdk` | Disk Image | timeline, persistence, malware, logs (if evtx extractable) |
| `.raw`, `.vmem`, `.lime`, `.dmp` (memory signature) | Memory Dump | memory, correlation |
| `.evtx` | Windows Event Logs | logs, timeline |
| `.reg`, `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM` | Registry Hives | persistence |
| `.pcap`, `.pcapng` | Network Capture | (future: network-analysis) |

### Technique Selection Matrix

| Evidence Available | Techniques Auto-Selected |
|-------------------|--------------------------|
| Disk image only | timeline, persistence, malware |
| Memory dump only | memory, malware (via `dump_process_memory` + triage on suspect PIDs), persistence (via svcscan/ldrmodules for memory-based service and module enumeration) |
| Disk + Memory | timeline, persistence, memory, correlation, hypothesis |
| Disk + Logs | timeline, persistence, logs, correlation |
| Disk + Memory + Logs | timeline, persistence, memory, logs, correlation, hypothesis |
| Unknown / mixed | Use `--guided` mode, inventory first |

**Rule**: When 2+ evidence types are present, ALWAYS include `correlation` and `hypothesis` — these produce Tier 2 and Tier 3 findings and demonstrate analytical reasoning (Criterion #1).

---

## Adaptive Mode

1. Run Phase 1 (Evidence Inventory) — read and execute `protocols/evidence-collector.md`
2. Assess evidence types from `inventory.json`
3. Select techniques using the Technique Selection Matrix
4. Present selection to user:
   ```
   Evidence assessment complete:
   - Disk image: [found/not found] — [path]
   - Memory dump: [found/not found] — [path]
   - Log files: [found/not found] — [count] files
   - Registry hives: [found/not found] — [count] files

   Selected techniques: [list with rationale]
   Estimated phases: [which of 1-6 will execute]

   Proceed? Or adjust with specific technique names.
   ```
5. On confirmation, execute Phases 2-6

---

## Guided Mode

Execute all 6 phases in order. Each phase reads prior phase output from the case directory.

### Phase 1 — Evidence Inventory

1. Read and execute `protocols/evidence-collector.md`
2. Output: `inventory.json` in case directory
3. Report to user: evidence types found, file count, total size, SHA256 hashes
4. Run Integrity Gate (defined in evidence-collector.md)

### Phase 2 — Triage Assessment

1. Read `inventory.json` from case directory
2. For each evidence type, run quick-look tools:
   - Disk image: `get_partition_layout()` → partition table overview
   - Disk image: `scan_yara(rules="default")` → known-bad indicator scan
   - Memory dump: `analyze_memory(plugin="pslist")` → process listing
   - Memory dump: `analyze_memory(plugin="netscan")` → network connections
   - Logs: count events by Event ID, identify gaps
3. Identify:
   - **Obvious IOCs**: known-bad hashes, suspicious process names, external IP connections
   - **Timeline bounds**: earliest and latest suspicious activity timestamps
   - **Anomalies**: unexpected processes, unusual network connections, tampered logs
4. Write `triage.json` to case directory:
   ```json
   {
     "case_id": "<CASE-ID>",
     "timestamp": "<ISO-8601>",
     "evidence_summary": {...},
     "iocs_found": [...],
     "timeline_bounds": {"earliest": "<timestamp>", "latest": "<timestamp>"},
     "anomalies": [...],
     "recommended_techniques": [...]
   }
   ```
5. Report findings to user. Ask for confirmation to proceed to Deep Analysis.

### Phase 3 — Deep Analysis

1. Read `triage.json` for context and timeline bounds
2. Select techniques based on evidence types (use Technique Selection Matrix, or user's explicit selection)
3. Execute techniques via the **Technique Execution Contract** (see below)
4. Each technique writes its output to `analysis/<technique-name>.json`

### Phase 4 — Correlation & Synthesis

1. Read ALL `analysis/*.json` files from the case directory
2. Execute the `correlation` technique protocol — cross-reference findings across evidence sources
3. Execute the `hypothesis` technique protocol — test competing explanations
4. Build the attack narrative:
   - Chronological sequence of events
   - Kill chain mapping (Initial Access → Execution → Persistence → Privilege Escalation → Lateral Movement → Collection → Exfiltration)
   - Evidence tier assignment for each finding
   - MITRE ATT&CK technique mapping
5. Write `synthesis.json` to case directory:
   ```json
   {
     "case_id": "<CASE-ID>",
     "attack_narrative": "...",
     "kill_chain": [...],
     "findings": [
       {
         "finding_id": "F-001",
         "description": "...",
         "confidence": "HIGH|MEDIUM|LOW",
         "evidence_tier": 1|2|3,
         "supporting_tools": [...],
         "citations": [...],
         "mitre_attack": {"tactic": "...", "technique": "..."},
         "timeline_position": "<ISO-8601>"
       }
     ],
     "competing_hypotheses": {...},
     "unresolved_questions": [...]
   }
   ```

### Phase 5 — Self-Correction & Validation

1. Read and execute `protocols/self-correction.md`
2. The self-correction protocol reads ALL prior phase outputs and validates across them
3. Corrections are written to `corrections/` directory
4. A `corrections/validation-summary.json` summarizes what was checked and what was corrected
5. **Run `/compact` after this phase** — context is at peak accumulation

### Phase 6 — Reporting

#### Report Standardization Rule

**Every report MUST include ALL sections defined in `templates/investigation-report.md`, regardless of investigation mode or evidence available.** This is a non-negotiable requirement for operational IR/IM use — the report consumer must be able to trust that the output structure is identical every time.

When a section's corresponding phase or technique was not executed:
- The section heading MUST still appear in the report
- The section body MUST state: **"Not performed."** followed by a one-line reason (e.g., "Only one evidence type was available — hypothesis testing requires 2+ independent evidence sources for cross-referencing." or "Lean mode was selected for rapid triage — Phase 4 (Correlation) is skipped in lean mode.")
- The section MUST include a remediation path: how to run the skipped analysis (e.g., `/investigate --iterate <CASE-ID> hypothesis`)

This applies to all sections including but not limited to: Competing Hypotheses Assessment, Sensitivity Analysis, Self-Correction Summary, Limitations and Caveats, Audit Trail, and Citations.

#### Report Generation Steps

1. Read `synthesis.json` and `corrections/validation-summary.json`
2. Generate the investigation report using `templates/investigation-report.md` — populate ALL sections, using "Not performed" explanations for any section whose phase did not execute
3. Generate machine-readable findings using `templates/finding-template.json`
4. Generate accuracy self-assessment using `templates/accuracy-report.md`
5. Write all outputs to `report/` directory
6. Present the investigation summary to the user in this format:

```
========================================================================
  INVESTIGATION COMPLETE — [CASE-ID]
========================================================================

  Findings:       [N] total ([CRITICAL] critical, [HIGH] high, [MEDIUM] medium)
  Evidence Tier:  [N] Tier 1 | [N] Tier 2 | [N] Tier 3
  Self-Correction: [N] corrections applied, [N] in-flight reclassifications
  Techniques:     [list of techniques run]
  MITRE ATT&CK:  [N] techniques mapped

  TOP FINDINGS:
  [F-001] [CRITICAL] [one-line description]
  [F-002] [HIGH]     [one-line description]
  [F-003] [HIGH]     [one-line description]

  IOCs:
  - [type]: [value]
  - [type]: [value]

  Report: [case-dir]/report/investigation-report.md
  Audit:  [case-dir]/logs/tool-execution.jsonl
========================================================================
```

---

## Direct Mode

1. Look up technique in the routing table. If not found, respond with: "Unknown technique '{{INPUT}}'. Valid techniques: `timeline`, `correlation`, `hypothesis`, `memory`, `persistence`, `logs`, `malware`." — then stop.
2. Create case directory (if not already created)
3. Run Phase 1 (Evidence Inventory) if `inventory.json` doesn't exist
4. Check that the required evidence type is available for the requested technique
5. Execute the single technique via in-context execution (Technique Execution Contract)
6. Present findings
7. Offer: "Would you like me to continue with a full investigation, or is this technique sufficient?"

---

## Lean Mode

Execute a minimal investigation with only the highest-value techniques:

1. Phase 1 (Evidence Inventory) — always
2. Phase 2 (Triage) — always
3. Phase 3 (Deep Analysis) — **only**: `timeline` + `persistence`
4. Phase 5 (Self-Correction) — Layer 1 only (artifact existence validation)
5. Phase 6 (Reporting) — **full standardized report** (see Report Standardization Rule)

Skip Phase 4 (Correlation) entirely. This mode is for fast triage when time is constrained.

> **Note**: Although phases may be skipped in lean mode, the final report always includes all sections. Skipped sections state why they were not performed and how to run them (see Report Standardization Rule).

---

## Resume Mode

1. Read `/cases/<case-id>/CASE.md` and determine investigation state
2. Check which phase outputs exist:
   - `inventory.json` → Phase 1 complete
   - `triage.json` → Phase 2 complete
   - `analysis/*.json` → Phase 3 complete (check which techniques ran)
   - `synthesis.json` → Phase 4 complete
   - `corrections/` → Phase 5 complete
   - `report/` → Phase 6 complete
3. Resume from the first incomplete phase
4. If all phases complete: offer to re-run with `--iterate` for updated analysis

---

## Iterate Mode

1. Read the existing case directory at `/cases/<case-id>/`
2. Archive prior outputs: rename `synthesis.json` → `synthesis.v1.json`, etc.
3. Re-run from Phase 3 (Deep Analysis) using the same evidence but potentially different technique selection or corrected approach
4. Compare new findings to prior findings — document what changed
5. Write iteration metadata to `CASE.md`

### Scoped Iteration (`--iterate <case-id> <technique>`)

1. Archive only the specified technique's artifact
2. Re-run only that technique
3. If the technique's findings changed, offer to re-run Phase 4 (Correlation) and Phase 5 (Self-Correction)

---

## Technique Execution Contract

### In-Context Execution (1 technique — Direct mode)

1. **Read** the protocol file from the routing table
2. **Read** the template file (if applicable)
3. **Execute** the protocol: SETUP → PRIME → EXECUTE → ARTIFACT → FINDINGS → HANDOFF
4. **Write** the artifact to `analysis/<technique-name>.json` in the case directory
5. **Layer 1 Check** (silent): Did all protocol steps complete? Are all required fields populated? Any missing citations?
6. If Layer 1 fails: re-execute missed steps before proceeding
7. **Update** `CASE.md` with technique completion status

### Subagent Dispatch (2+ techniques)

#### Dependency Tier Assignment

| Tier | Techniques | Dependencies | Dispatch |
|------|-----------|-------------|----------|
| 1 (Independent) | timeline, memory, persistence, logs, malware | `inventory.json` + `triage.json` | Parallel subagents |
| 2 (Dependent) | correlation, hypothesis | ALL Tier 1 outputs in `analysis/` | Parallel subagents (after Tier 1 completes) |

Within each tier, techniques run in parallel. The orchestrator waits for all Tier 1 subagents to complete before dispatching Tier 2.

#### Subagent Prompt Template

Each technique subagent receives:

```
You are a VALKYRIE forensic technique executor. Execute a single IR analysis technique and write the artifact to disk.

## Technique
- **Name**: {{TECHNIQUE_NAME}}
- **Protocol file**: {{PROTOCOL_PATH}} (relative to skill directory)
- **Artifact output**: {{CASE_DIR}}/analysis/{{ARTIFACT_NAME}}.json

## Case Context
- **Case ID**: {{CASE_ID}}
- **Evidence path**: {{EVIDENCE_PATH}}
- **Triage summary**: {{TRIAGE_SUMMARY}} (key findings from triage.json)
- **Timeline bounds**: {{EARLIEST}} to {{LATEST}}

## Available Files
{{FILE_MANIFEST — list of files in case directory}}

## Instructions

1. Read the protocol file
2. Read case files as needed per the protocol's SETUP step
3. Execute ALL protocol steps: SETUP → PRIME → EXECUTE → ARTIFACT → FINDINGS → HANDOFF
4. Write the completed artifact as JSON to the output path
5. Perform Layer 1 compliance check:
   - All protocol steps completed?
   - All findings have citations to specific tool outputs?
   - All evidence tier assignments justified?
   - If Layer 1 fails: fix and re-write the artifact
6. Return ONLY this summary:

Technique: {{TECHNIQUE_NAME}}
Artifact: {{CASE_DIR}}/analysis/{{ARTIFACT_NAME}}.json
Status: COMPLETED | FAILED | PARTIAL
Layer1: PASS | FAIL (details)
Findings:
- [finding] [Tier: 1|2|3] [Confidence: HIGH|MEDIUM|LOW]
- [finding] [Tier: 1|2|3] [Confidence: HIGH|MEDIUM|LOW]
Handoff: [key outputs for downstream techniques]
Errors: [any errors or "none"]

IMPORTANT:
- Do NOT return full artifact content — only the summary above
- Every finding must cite the specific MCP tool call that produced the evidence
- Use the MCP tools (mcp__valkyrie__*) to query forensic evidence — do not fabricate output
```

#### Return Processing

After all subagents complete, the orchestrator:
1. Collects compact summaries (technique name + status + findings + handoff)
2. Logs any FAILED or PARTIAL techniques
3. Verifies artifact files exist on disk
4. Proceeds to the next tier or phase
