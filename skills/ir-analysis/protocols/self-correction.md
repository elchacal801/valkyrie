# Self-Correction Protocol

Three-layer forensic validation that catches IR-specific hallucination patterns. This is the core differentiator — generic AI agents hallucinate artifacts, invent timestamps, and construct plausible-but-wrong narratives. This protocol systematically detects and corrects those failures.

---

## When This Protocol Runs

The orchestrator invokes this protocol during Phase 5 (Self-Correction & Validation). It reads ALL prior phase outputs from the case directory and validates across them.

**Input**: Case directory containing `inventory.json`, `triage.json`, `analysis/*.json`, `synthesis.json`
**Output**: `corrections/` directory with individual correction records and a validation summary

---

## Layer 1 — Artifact Existence Validation

**Purpose**: Verify that every forensic artifact referenced in findings actually exists in the evidence. This catches the most common IR hallucination: the agent claims to have found something that isn't there.

**Runs**: After each technique (silent) AND during Phase 5 (comprehensive)

### Checks

For each finding in `synthesis.json` and all `analysis/*.json` files:

#### 1.1 File Path Verification
- For every file path referenced in a finding: invoke `list_files()` MCP tool to verify the file exists in the evidence
- For every extracted file referenced: verify it exists in the case working directory
- **Failure pattern**: "Agent claims `C:\Windows\Temp\malware.exe` was found, but `list_files()` shows no such file"

#### 1.2 Offset and Sector Validation
- For every disk offset referenced: verify it falls within the valid range of the evidence file (check against `inventory.json` file size)
- For every memory offset referenced: verify it falls within the valid range of the memory dump
- **Failure pattern**: "Agent claims process at offset `0xFFFFFFFF` but memory dump is only 4GB"

#### 1.3 Process ID Verification
- For every PID referenced from memory analysis: re-invoke `analyze_memory(plugin="pslist")` and verify the PID exists in the output
- Check that the process name matches what was claimed
- **Failure pattern**: "Agent claims PID 4832 is `svchost.exe` but pslist shows PID 4832 is `chrome.exe`"

#### 1.4 Registry Key Verification
- For every registry key path referenced: invoke `get_registry_key()` to verify it exists
- Verify the claimed value matches the actual value
- Check that the registry key path is valid for the detected Windows version (e.g., don't reference Windows 11 keys on a Windows 7 image)
- **Failure pattern**: "Agent claims `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\malware` exists but `get_registry_key()` returns not found"

#### 1.5 Log Entry Verification
- For every event log entry cited: verify the Event ID exists in the referenced log file
- Verify the timestamp matches (within 1-second tolerance for timezone conversion)
- Verify the claimed message content is present in the actual log entry
- **Failure pattern**: "Agent claims Event ID 4688 at 14:23:00 shows `powershell.exe` launch but the actual event at that time shows `cmd.exe`"

#### 1.6 Hash Verification
- For every file hash (MD5, SHA1, SHA256) cited: if the file was extracted, compute the actual hash and compare
- **Failure pattern**: "Agent claims file hash is `abc123...` but actual SHA256 is `def456...`"

### Layer 1 Severity Classification

| Issue | Severity | Action |
|-------|----------|--------|
| Referenced file does not exist | HIGH | Re-invoke tool, correct or remove finding |
| PID mismatch (wrong process name) | HIGH | Re-invoke pslist, correct finding |
| Registry key not found | HIGH | Re-invoke registry tool, correct finding |
| Offset out of range | HIGH | Remove offset reference, flag as uncorroborated |
| Log entry content mismatch | MEDIUM | Re-invoke log tool, correct details |
| Hash mismatch | MEDIUM | Recompute hash, correct finding |
| Timestamp within tolerance (< 1s) | LOW | Log but do not correct |

---

## Layer 2 — Temporal Consistency Validation

**Purpose**: Verify that the timeline of events is chronologically possible and internally consistent. This catches the second most common IR hallucination: the agent constructs a plausible narrative with impossible timing.

**Runs**: Before synthesis (Phase 4) AND during Phase 5

### Checks

#### 2.1 Chronological Ordering
- Extract ALL timestamps from all `analysis/*.json` files and `synthesis.json`
- Sort chronologically
- Check every cause-effect pair: does the cause precede the effect?
- **Failure pattern**: "Agent claims persistence mechanism was installed before initial access"

#### 2.2 Timezone Consistency
- Identify the timezone of the evidence system (from registry or OS artifacts)
- Verify all timestamps in findings use consistent timezone handling
- Check for UTC vs. local time confusion (common when mixing Volatility output with timeline output)
- Flag any finding where the timestamp appears to be in a different timezone than the evidence system
- **Failure pattern**: "Timeline shows file created at 14:00 UTC but memory analysis references the same event at 14:00 EST (5-hour discrepancy)"

#### 2.3 MAC Time Consistency
- For file-based findings: check Modified, Accessed, Created timestamps
- Flag timestomping indicators: Created time AFTER Modified time, or all MAC times identical to the second
- Flag impossible sequences: file modified before it was created
- **Failure pattern**: "Agent reports file created 2026-03-15 but modified 2026-03-10 — either timestomping or hallucination"

#### 2.4 Temporal Gap Analysis
- Identify gaps >24 hours in the attack timeline
- For each gap: is there a reasonable explanation? (weekends, off-hours, slow lateral movement)
- Flag unexplained gaps as potential missing evidence or analytical incompleteness
- **Failure pattern**: "Agent claims attack started Monday and completed Wednesday but has no events for Tuesday"

#### 2.5 Evidence Timeframe Bounds
- All findings timestamps must fall within the evidence timeframe (from `inventory.json` metadata)
- Timestamps before the earliest evidence file timestamp or after the latest are suspicious
- **Failure pattern**: "Agent claims activity in January 2026 but the disk image was created in March 2026 and the earliest MFT entry is February 2026"

### Layer 2 Severity Classification

| Issue | Severity | Action |
|-------|----------|--------|
| Effect precedes cause | HIGH | Re-examine timeline, correct sequence |
| Timezone confusion (>1 hour discrepancy) | HIGH | Normalize all timestamps, re-correlate |
| Timestomping indicators detected | MEDIUM | Flag as anti-forensics finding (this is a FINDING, not an error) |
| Timestamp outside evidence bounds | MEDIUM | Verify against inventory, correct or flag |
| Unexplained gap >24 hours | LOW | Document as limitation |
| MAC time inconsistency | LOW | Log for analyst review |

---

## Layer 3 — Analytical Coherence Validation

**Purpose**: Verify that the analytical narrative makes sense as a whole. This catches the third hallucination pattern: individually correct findings that don't form a coherent attack story.

**Runs**: Before reporting (Phase 6)

### Checks

#### 3.1 Kill Chain Plausibility
- Map all findings to the MITRE ATT&CK kill chain phases
- Check for gaps: is there initial access without execution? Persistence without initial access? Exfiltration without collection?
- Every kill chain phase referenced must have at least one supporting finding
- **Failure pattern**: "Agent claims data exfiltration but has no findings for how data was collected or staged"

#### 3.2 Cross-Technique Contradiction Detection
- Compare findings from different techniques that reference the same artifact
- Flag contradictions: timeline says file was created at T1, but memory analysis says the process that created it wasn't running until T2
- **Failure pattern**: "Timeline reconstruction says malware executed at 14:00 but memory analysis shows no process matching that executable at 14:00"

#### 3.3 MITRE ATT&CK Consistency
- For each ATT&CK technique assignment: verify that the claimed technique matches the observed behavior
- Check that sub-technique assignments are valid for the parent technique
- Verify that the TTPs are consistent with a plausible threat actor profile (don't mix nation-state TTPs with commodity malware indicators without explanation)
- **Failure pattern**: "Agent assigns T1053 (Scheduled Task) but the evidence shows a Run key, which is T1547.001"

#### 3.4 Confidence Calibration
- Review all confidence assignments:
  - HIGH confidence: must be Tier 1 or Tier 2 evidence (direct tool output or cross-referenced)
  - MEDIUM confidence: can be Tier 2 or Tier 3
  - LOW confidence: appropriate for Tier 3 (inference) or single-source findings with caveats
- Flag miscalibration: HIGH confidence on a Tier 3 inference, or LOW confidence on a Tier 1 direct observation
- **Failure pattern**: "Agent assigns HIGH confidence to an inference based on circumstantial evidence"

#### 3.5 Alternative Hypothesis Check
- Review the hypothesis-testing output (if available)
- Verify that the null hypothesis (legitimate activity) was genuinely considered
- Check that at least one alternative explanation was evaluated and rejected with evidence
- Flag if the analysis only considered one hypothesis
- **Failure pattern**: "Agent concluded APT intrusion without considering that the 'suspicious' PowerShell script was a legitimate admin tool"

#### 3.6 Senior Analyst Challenge Test
- For each HIGH-confidence finding, ask: "What would a senior analyst challenge about this conclusion?"
- Common challenges:
  - "Are you sure that's malware and not a legitimate admin tool?"
  - "Could this network connection be normal business activity?"
  - "Is this persistence mechanism from a legitimate software installer?"
  - "Have you ruled out the red team / penetration test scenario?"
- If a plausible challenge cannot be answered with evidence: downgrade confidence

### Layer 3 Severity Classification

| Issue | Severity | Action |
|-------|----------|--------|
| Kill chain gap (missing phase) | MEDIUM | Document as limitation, adjust narrative |
| Cross-technique contradiction | HIGH | Re-examine both techniques, resolve |
| Wrong MITRE ATT&CK mapping | MEDIUM | Correct the mapping |
| Confidence miscalibration | MEDIUM | Adjust confidence level |
| No alternative hypotheses considered | HIGH | Run hypothesis-testing technique |
| Cannot answer senior analyst challenge | MEDIUM | Downgrade confidence, add caveat |

---

## Auto-Remediation Procedure

When any layer detects a HIGH-severity issue:

### Step 1 — Log the Detection

Write a correction record to `corrections/correction-NNN.json`:

```json
{
  "correction_id": "C-001",
  "detection_layer": 1,
  "issue_type": "hallucinated_artifact",
  "severity": "HIGH",
  "description": "Referenced file C:\\Windows\\Temp\\malware.exe does not exist in evidence",
  "affected_finding": "F-003",
  "original_value": "Malware executable found at C:\\Windows\\Temp\\malware.exe",
  "corrected_value": "",
  "verification_method": "",
  "verification_output_hash": "",
  "timestamp": "2026-04-15T14:23:00Z"
}
```

### Step 2 — Verify with Ground Truth

Re-invoke the relevant MCP tool to get ground truth:
- File existence → `list_files(path)`
- Process → `analyze_memory(plugin="pslist")`
- Registry → `get_registry_key(key_path)`
- Timeline → `generate_timeline(start, end)` or `extract_mft()`
- Log entry → parse the specific .evtx file

Record the SHA256 hash of the verification output.

### Step 3 — Correct or Remove

Based on verification:
- **If the artifact exists but was described incorrectly**: update the finding with correct details
- **If the artifact does not exist**: remove the finding or downgrade to Tier 3 inference with LOW confidence
- **If the timeline is wrong**: correct the timestamp and re-check temporal consistency

Update the correction record with `corrected_value`, `verification_method`, and `verification_output_hash`.

### Step 4 — Document for Report

Update `corrections/correction-NNN.json` with the complete correction record. This will be included in the final report's Self-Correction Summary section.

### Caps and Guards

- **Maximum 3 corrections per layer per run**. If more than 3 HIGH-severity issues are found in a single layer, log all of them but only auto-remediate the first 3. The rest are flagged for manual review.
- **No recursive correction**: Correcting a finding does not trigger re-validation of the corrected finding. The corrected value is accepted as-is.
- **Correction priority**: Layer 1 (artifact existence) > Layer 2 (temporal) > Layer 3 (analytical). If the correction budget is exhausted, Layer 1 issues take priority because they represent fabricated evidence.

---

## Validation Summary

After all three layers complete, write `corrections/validation-summary.json`:

```json
{
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "layers_executed": [1, 2, 3],
  "layer_1": {
    "checks_run": 6,
    "issues_found": 2,
    "high_severity": 1,
    "corrections_applied": 1,
    "details": ["C-001: hallucinated file path corrected"]
  },
  "layer_2": {
    "checks_run": 5,
    "issues_found": 1,
    "high_severity": 0,
    "corrections_applied": 0,
    "details": ["Unexplained gap 2026-03-15 to 2026-03-16 logged as limitation"]
  },
  "layer_3": {
    "checks_run": 6,
    "issues_found": 0,
    "high_severity": 0,
    "corrections_applied": 0,
    "details": []
  },
  "total_corrections": 1,
  "findings_removed": 0,
  "confidence_downgrades": 0,
  "overall_assessment": "Investigation validated with 1 correction applied. Layer 1 caught a hallucinated file path that was corrected via MFT re-query."
}
```

This summary is included in the final report and allows judges to see exactly what the agent caught and fixed.
