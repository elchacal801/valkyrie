# Protocol: Timeline Reconstruction

> **Phase**: Deep Analysis | **Evidence**: Disk image, logs | **Produces**: Tier 1 findings
> **Output Artifact**: `analysis/timeline-reconstruction.json`
> **MCP Tools**: `generate_timeline()`, `extract_mft()`, `get_event_logs()` (if available)

---

## Purpose

Construct a comprehensive timeline of system activity from all available temporal artifacts. Identify the sequence of events, temporal anomalies (timestomping, clock skew), and establish the investigation time bounds (T0 = first suspicious activity, TN = last).

---

## Execution

### 1. SETUP

- Read `inventory.json` for evidence file paths and types
- Read `triage.json` for initial timeline bounds and known IOCs (if Phase 2 has run)
- Determine available temporal sources:
  - MFT (Master File Table) — file creation, modification, access times
  - Event logs (.evtx) — Windows security, system, application events
  - Prefetch — application execution times
  - Registry timestamps — key last-modified times
- Note the evidence system's timezone (from registry `TimeZoneInformation` key or triage output)

### 2. PRIME

"I will now reconstruct a comprehensive timeline from all available temporal evidence sources. Focus is on identifying the sequence of attack events, temporal anomalies that may indicate anti-forensics, and establishing when the incident began (T0) and ended (TN)."

### 3. EXECUTE

#### 3.1 Extract MFT Timeline

If a disk image is available:

1. Invoke `extract_mft(image_path)` via MCP
2. Parse the MFT entries, focusing on:
   - Files in suspicious directories: `\Windows\Temp\`, `\Users\*\AppData\`, `\ProgramData\`, `\Users\Public\`, `\$Recycle.Bin\`
   - Files with executable extensions: `.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, `.js`, `.hta`
   - Files created or modified within the triage timeline bounds
3. Record each entry with all four MACB timestamps:
   - **M** (Modified) — file content last changed
   - **A** (Accessed) — file last accessed
   - **C** (Changed) — MFT entry metadata changed
   - **B** (Born/Created) — file created

#### 3.2 Extract Super Timeline (if log2timeline/plaso available)

1. Invoke `generate_timeline(evidence_path, start_date, end_date)` via MCP
2. The super timeline aggregates: MFT, event logs, prefetch, registry, browser history, and other temporal artifacts into a single chronological view
3. Filter to the investigation time window (from triage bounds, or ±7 days around known incident date)

#### 3.3 Analyze Event Logs

If event logs are available (standalone .evtx files or extracted from disk image):

1. Focus on high-value Event IDs:
   - **4624/4625** — Logon success/failure (look for unusual accounts, times, logon types)
   - **4688** — Process creation (look for suspicious process chains)
   - **4697/7045** — Service installation (persistence indicator)
   - **1102** — Audit log cleared (anti-forensics indicator)
   - **4720/4732** — Account creation/group modification (privilege escalation)
   - **5140/5145** — Network share access (lateral movement)
   - **1116/1117** — Windows Defender detection/action
2. Correlate event log timestamps with MFT timestamps

#### 3.4 Identify Temporal Anomalies

Scan the consolidated timeline for:

1. **Timestomping indicators**:
   - Created time (B) AFTER Modified time (M) — files backdated
   - All MACB times identical to the second — bulk timestamp manipulation
   - Timestamps suspiciously round (all at :00 seconds)
   - File creation time doesn't match the MFT entry sequence number (file created much later than its neighbors)

2. **Clock skew / manipulation**:
   - System time change events (Event ID 4616)
   - Timeline entries that jump backward in time
   - Entries from the future relative to the evidence collection date

3. **Gap detection**:
   - Periods >1 hour with zero timeline entries during what should be active hours
   - Log gaps that could indicate log clearing
   - Missing log files that should exist (e.g., Security.evtx missing)

#### 3.5 AI-Adversary Temporal Indicators

Scan the consolidated timeline for patterns associated with automated or AI-driven operations. These checks are informed by real-world AI attack observations (GTIG AI Threat Tracker, Barracuda Agentic AI Report 2026).

1. **Sub-minute event clustering**: Identify clusters where 5+ distinct suspicious events occur within a 60-second window. Human operators rarely execute 5 distinct actions in under a minute — they need to read output, evaluate results, and decide next steps. Record each cluster with its event count, time span, and event types.

2. **"Too-regular" interval detection**: For each cluster of 3+ sequential suspicious events, compute the inter-event intervals and their coefficient of variation (CV = standard deviation / mean). Flag clusters where CV < 0.15 — this indicates metronomic timing inconsistent with human operation. Humans show CV > 0.30 due to variable reaction times and decision pauses.

3. **Behavioral entropy check**: Assess suspicious activity clusters spanning > 5 minutes. Flag if the cluster contains no pauses > 30 seconds — sustained, evenly-paced activity without reading/decision pauses suggests automated or AI-driven execution. Human attacks show bursty patterns (intense activity → pause for recon → activity).

4. **Parallelized event detection**: Identify cases where two or more causally independent suspicious events occur within a 5-second window on the same system (e.g., file creation in directory A and registry modification in hive B simultaneously). Humans operate serially; parallel operations suggest programmatic execution.

Add these to the `anomalies` array in the artifact output with the following type values: `ai_tempo`, `sub_minute_cluster`, `regular_interval`, `parallel_ops`.

#### 3.6 Establish Investigation Bounds

Determine:
- **T0 (First suspicious activity)**: The earliest timestamp associated with a suspicious artifact. Must be supported by at least one Tier 1 citation.
- **TN (Last suspicious activity)**: The latest timestamp associated with suspicious activity.
- **Evidence window**: The full range of timestamps available in the evidence (may extend before T0 and after TN).

### 4. ARTIFACT

Write `analysis/timeline-reconstruction.json` to the case directory:

```json
{
  "technique": "timeline-reconstruction",
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "sources_used": ["mft", "evtx_security", "evtx_system", "prefetch"],
  "timezone": "UTC",
  "evidence_timezone": "America/New_York (UTC-5)",
  "investigation_bounds": {
    "t0": {"timestamp": "<ISO-8601>", "description": "...", "source": "..."},
    "tn": {"timestamp": "<ISO-8601>", "description": "...", "source": "..."},
    "evidence_window": {"earliest": "<ISO-8601>", "latest": "<ISO-8601>"}
  },
  "timeline_entries": [
    {
      "timestamp": "<ISO-8601>",
      "source": "mft|evtx|prefetch|registry",
      "event_type": "file_created|file_modified|process_start|logon|service_install|log_cleared|...",
      "description": "...",
      "artifact_path": "...",
      "macb": "M..B",
      "suspicious": true,
      "citation": "[TOOL: extract_mft, evidence: disk.E01, entry: ...]"
    }
  ],
  "anomalies": [
    {
      "type": "timestomping|clock_skew|gap|log_cleared",
      "description": "...",
      "affected_entries": ["..."],
      "severity": "HIGH|MEDIUM|LOW",
      "citation": "[TOOL: ...]"
    }
  ],
  "findings": [
    {
      "finding_id": "TL-001",
      "description": "...",
      "confidence": "HIGH|MEDIUM|LOW",
      "evidence_tier": 1,
      "citation": "[TOOL: ...]"
    }
  ]
}
```

### 5. FINDINGS

Summarize:
- Investigation time bounds (T0 to TN) with supporting evidence
- Number of timeline entries analyzed
- Key temporal clusters (multiple events within 60-second windows)
- Anomalies detected (timestomping, gaps, cleared logs)
- Suspicious file activity patterns

**Layer 1 Self-Check:**
- [ ] T0 identified with Tier 1 citation?
- [ ] Every timeline entry has a source and citation?
- [ ] Timezone consistently applied across all entries?
- [ ] Anomalies have supporting evidence (not just inference)?
- [ ] At least one temporal source analyzed?

### 6. HANDOFF

Pass to downstream techniques:
- **Investigation bounds** (T0, TN) — used by all other techniques to focus their analysis window
- **Temporal anomalies** — used by hypothesis-testing to evaluate anti-forensics hypothesis
- **Suspicious file paths** — used by memory-analysis and persistence-enumeration to focus their searches
- **Key timestamps** — used by artifact-correlation for cross-source timeline alignment
- **AI-adversary temporal indicators** — used by ai-adversary-analysis technique for behavioral entropy scoring

---

## Watch-Outs

- **Super timeline size**: Plaso output can be millions of entries. The MCP server truncates to a manageable size. Work with the truncated/filtered output and request specific time ranges if needed.
- **Timezone traps**: Windows stores some timestamps in UTC (NTFS MFT) and others in local time (some event logs). Always normalize to UTC in your findings, noting the evidence system timezone.
- **MFT tunnel entries**: When a file is deleted and a new file is created in the same directory shortly after, the new file may inherit the old file's creation timestamp (NTFS tunneling). This is NOT timestomping — it's a filesystem behavior.
- **Prefetch timestamps**: Prefetch files record the LAST execution time and up to 8 previous execution times. The file creation time is the FIRST execution time. Don't confuse these.
