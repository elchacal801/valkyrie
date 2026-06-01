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
| `--loop <case-id>` | **Loop** — iterate until verifiable success/stagnation (see `protocols/persistent-loop.md`) |
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
| `ai-adversary` | `protocols/techniques/ai-adversary-analysis.md` | `analysis/ai-adversary-analysis.json` | Correlation | 2+ Phase 3 outputs |

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

## Execution Logging (cross-cutting)

Two append-only logs in `logs/` make every investigation reproducible and traceable —
both are required evidence for the judging criteria (audit-trail quality + token usage).

### 1. Tool-execution audit log — `logs/tool-execution.jsonl`

Written automatically by the MCP server for every forensic tool call. Each line carries a
unique **`execution_id`** (e.g. `EXEC-3f9a1c-0007`), timestamp, command, exit code,
`output_sha256`, output length, and duration. **Every finding must cite the `execution_id`
of the tool call that produced its evidence** so a judge can trace any claim to one line.

### 2. Cost & token ledger — `logs/cost-ledger.jsonl`

At the **end of each phase** (and each loop iteration), append one record capturing the
resource cost of the work just completed. Token counts come from the Claude Code session
usage; if a precise count is unavailable, record `tokens: null` and keep wall-clock +
tool-call counts (never fabricate a number).

```json
{
  "timestamp": "<ISO-8601>",
  "phase": "3-deep-analysis",
  "iteration": 1,
  "wall_clock_seconds": 142.7,
  "tool_calls": 18,
  "tokens": {"input": 84210, "output": 9120, "total": 93330},
  "cumulative_tokens": 187540,
  "notes": "timeline + memory + persistence subagents"
}
```

The final report's Audit Trail section summarizes this ledger (total tokens, total tool
calls, wall-clock per phase) — the single-agent "logs with timestamps and token usage" deliverable.

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

### AI-Adversary Auto-Selection Triggers

The `ai-adversary` technique is automatically added to the selected techniques when ANY of the following conditions are detected during Phase 2 (Triage) or Phase 3 (Deep Analysis):

| Trigger | Detection Method | Confidence |
|---|---|---|
| Sub-minute activity cluster (5+ suspicious events in 60s) | Phase 2 triage timeline scan | HIGH |
| Same credential on 3+ systems within 5 minutes | Phase 2 log scan (Event ID 4624) | HIGH |
| LOLBin chain detected (3+ legitimate tools in sequence) | Phase 2 process/cmdline scan | MEDIUM |
| Zero YARA matches on clearly suspicious files | Phase 3 malware-triage output | MEDIUM |
| WMI/COM/BITS activity during incident window | Phase 2 triage | LOW |
| LLM API artifacts in strings output | Phase 3 technique outputs | HIGH |
| Any Phase 3 technique flags `ai_tempo` anomalies | Phase 3 timeline/memory outputs | HIGH |

When no triggers fire, `ai-adversary` is NOT auto-selected (to avoid unnecessary analysis on clearly human-operated incidents). It can always be explicitly requested via `/investigate ai-adversary` or `/investigate --iterate <case-id> ai-adversary`.

When AI-adversary triggers are detected during Phase 2, `ai-adversary` is added to all evidence combinations that include 2+ Tier 1 technique outputs.

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
5. **Then read and execute `protocols/verification.md`** — assign every finding an
   independent verdict (CONFIRMED / INFERRED / UNVERIFIED) by re-deriving its claim
   from a fresh tool call. Writes `corrections/verification-ledger.json`. Any
   `UNVERIFIED` asserted claim is downgraded and flagged (never silently dropped).
6. **Run `/compact` after this phase** — context is at peak accumulation

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

1. Look up technique in the routing table. If not found, respond with: "Unknown technique '{{INPUT}}'. Valid techniques: `timeline`, `correlation`, `hypothesis`, `memory`, `persistence`, `logs`, `malware`, `ai-adversary`." — then stop.
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
4. Phase 5 (Self-Correction) — Layer 1 only (artifact existence validation), then
   `verification.md` on CRITICAL/HIGH findings only (verdict CONFIRMED/UNVERIFIED)
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

## Loop Mode

Read and execute `protocols/persistent-loop.md`. The loop repeatedly iterates the
investigation on the same evidence — each pass runs self-correction + verification,
appends a record to `logs/progress.jsonl`, and **course-corrects toward the open
items** (UNVERIFIED claims, open HIGH issues, missing kill-chain phases) — until
verifiable success criteria are met, progress stagnates, or `--max-iterations` is
reached. With `--truth`, each iteration is scored by `eval/run_eval.py` so the report
can show the iteration-1 → final F1 delta. The loop always terminates and never ships
a result worse than a prior iteration (regression guard).

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
| 2 (Dependent) | correlation, hypothesis, ai-adversary | ALL Tier 1 outputs in `analysis/` | Parallel subagents (after Tier 1 completes) |

> **Note on ai-adversary placement**: The ai-adversary technique consumes all Tier 1 outputs and benefits from reading `artifact-correlation.json` (decoy candidates, absence indicators). For v1, it runs in parallel with correlation and hypothesis (Option A — simpler orchestration). A future optimization (Option B) would sequence it after correlation for richer input.

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
4. **Early Contradiction Pass (after Tier 1, before dispatching Tier 2).**
   Compare findings across the completed Tier-1 techniques for the same artifact
   (timeline↔memory, memory↔logs, logs↔persistence) using the contradiction
   patterns in `techniques/artifact-correlation.md` (timestamp mismatch, existence
   mismatch, process/PID mismatch, hash mismatch). For each contradiction:
   - attempt to resolve it now by re-invoking the specific MCP tool on the disputed
     artifact (a contradiction caught here is cheaper than one discovered in Phase 4);
   - if unresolved, mark both findings LOW confidence and pass the contradiction
     forward in the Tier-2 subagent context so correlation/hypothesis treat it as a
     signal rather than silently averaging over it.
   Record the pass result in `analysis/contradiction-pass.json` (pairs checked,
   contradictions found, resolved/unresolved).
5. Proceeds to the next tier or phase
