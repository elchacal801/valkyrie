# Protocol: Artifact Correlation

> **Phase**: Correlation | **Evidence**: 2+ Phase 3 technique outputs | **Produces**: Tier 2 findings
> **Output Artifact**: `analysis/artifact-correlation.json`
> **Depends on**: All Phase 3 (Deep Analysis) technique outputs

---

## Purpose

Cross-reference findings from independent analysis techniques to identify corroborated evidence (Tier 2) and detect contradictions between sources. This technique produces the highest-confidence findings in the investigation by requiring multiple independent tools to agree.

---

## Execution

### 1. SETUP

- Read ALL `analysis/*.json` files from the case directory (Phase 3 outputs)
- Read `triage.json` for context
- Build a master list of all findings from all techniques, each tagged with its source technique
- Note which evidence types were analyzed (disk, memory, logs, registry)

### 2. PRIME

"I will now cross-reference findings from all analysis techniques to identify where independent evidence sources corroborate each other. Corroborated findings become Tier 2 (highest confidence). Contradictions between sources will be flagged for investigation."

### 3. EXECUTE

#### 3.1 Build the Correlation Matrix

Create a matrix with:
- **Rows**: Unique findings/artifacts (deduplicated by subject — e.g., "suspicious process X", "file Y created at time T")
- **Columns**: Evidence sources (each technique that ran)
- **Cells**: Whether this technique found supporting evidence for this artifact (SUPPORTS / CONTRADICTS / NO DATA)

#### 3.2 Identify Corroborations (Tier 2 Promotion)

For each finding, check if 2+ independent techniques provide supporting evidence:

| Correlation Pattern | Example | Tier |
|-------------------|---------|------|
| Timeline + Memory | MFT shows file created at T; memory shows process that created it was running at T | Tier 2 |
| Memory + Registry | Process found in memory; matching Run key found in registry | Tier 2 |
| Timeline + Logs | MFT entry at T; matching Event ID 4688 (process creation) at T | Tier 2 |
| Memory + Network | Process in memory; netscan shows that PID connected to external IP | Tier 2 |
| Timeline + Persistence + Memory | File created at T; Run key pointing to file; process loaded in memory | Tier 2 (strong) |
| YARA + Memory | YARA rule matches file on disk; same file loaded as process in memory | Tier 2 |

**Promotion rule**: A finding becomes Tier 2 when 2+ independent tools/sources provide supporting evidence AND the evidence is consistent (timestamps align, paths match, PIDs correspond).

#### 3.3 Detect Contradictions

Flag cases where techniques disagree:

| Contradiction Pattern | Example | Action |
|----------------------|---------|--------|
| Timestamp mismatch | Timeline says file created at T1; memory says process started at T2 (difference > 5 minutes) | Flag for Layer 2 temporal validation |
| Existence mismatch | Registry shows persistence key; but file it points to not found on disk or in MFT | Flag: possible file deletion after persistence setup |
| Process mismatch | Memory shows process X; but no execution evidence in prefetch, MFT, or event logs | Flag: possible fileless execution or anti-forensics |
| Hash mismatch | File hash from disk doesn't match hash from memory dump extraction | Flag: possible in-memory modification or file replacement |

**Contradictions are NOT errors** — they are investigative signals. A process in memory with no disk artifacts suggests fileless malware. A persistence key pointing to a missing file suggests the attacker cleaned up. Document the contradiction as a finding.

#### 3.4 Identify Orphan Findings

Findings from Phase 3 that have NO corroboration from any other technique:
- These remain at Tier 1 (single-source)
- If the finding is critical to the narrative: flag it for additional investigation or confidence downgrade
- Orphan findings from a single tool are inherently less reliable

#### 3.5 Build Cross-Source Attack Narrative

Using corroborated findings, construct the timeline of the attack:

1. **Initial Access**: How did the attacker get in? (Corroborated by timeline + logs)
2. **Execution**: What did they run? (Corroborated by memory + timeline + prefetch)
3. **Persistence**: How did they maintain access? (Corroborated by registry + timeline)
4. **Privilege Escalation**: Did they elevate? (Corroborated by logs + memory)
5. **Lateral Movement**: Did they move to other systems? (Corroborated by logs + network + memory)
6. **Collection/Exfiltration**: What did they take? (Corroborated by timeline + network)

Not all kill chain phases will have corroborated findings. Document gaps.

### 4. ARTIFACT

Write `analysis/artifact-correlation.json` to the case directory:

```json
{
  "technique": "artifact-correlation",
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "techniques_correlated": ["timeline-reconstruction", "memory-analysis", "persistence-enumeration"],
  "correlation_matrix": {
    "findings": [
      {
        "subject": "suspicious executable X",
        "sources": {
          "timeline-reconstruction": "SUPPORTS — file created at T",
          "memory-analysis": "SUPPORTS — process running at T",
          "persistence-enumeration": "NO DATA"
        },
        "correlation_strength": "STRONG",
        "tier": 2
      }
    ]
  },
  "tier_2_findings": [
    {
      "finding_id": "CR-001",
      "description": "...",
      "confidence": "HIGH",
      "evidence_tier": 2,
      "corroborating_sources": ["timeline-reconstruction:TL-003", "memory-analysis:MA-001"],
      "citation": "[CORROBORATED: extract_mft entry @ T + volatility3.pslist PID 4832]"
    }
  ],
  "contradictions": [
    {
      "id": "CONTRA-001",
      "description": "...",
      "sources_in_conflict": ["timeline-reconstruction:TL-005", "memory-analysis:MA-003"],
      "investigative_significance": "...",
      "recommended_action": "..."
    }
  ],
  "orphan_findings": [
    {
      "original_id": "TL-007",
      "source_technique": "timeline-reconstruction",
      "reason_orphaned": "No corroboration from memory or persistence analysis",
      "recommendation": "Remains Tier 1; lower confidence for narrative"
    }
  ],
  "attack_narrative": {
    "initial_access": {"description": "...", "evidence": [...], "confidence": "..."},
    "execution": {"description": "...", "evidence": [...], "confidence": "..."},
    "persistence": {"description": "...", "evidence": [...], "confidence": "..."},
    "privilege_escalation": {"description": "...", "evidence": [...], "confidence": "..."},
    "lateral_movement": {"description": "...", "evidence": [...], "confidence": "..."},
    "collection_exfiltration": {"description": "...", "evidence": [...], "confidence": "..."},
    "gaps": ["No evidence for privilege escalation phase"]
  }
}
```

### 5. FINDINGS

Summarize:
- Number of findings promoted to Tier 2 (with specific corroboration details)
- Contradictions detected (with investigative significance)
- Orphan findings flagged
- Attack narrative coverage (which kill chain phases have corroborated evidence)
- Confidence assessment of overall narrative

**Layer 1 Self-Check:**
- [ ] Every Tier 2 finding cites at least 2 independent tool outputs?
- [ ] Contradictions documented with both conflicting sources cited?
- [ ] Orphan findings identified and properly classified?
- [ ] Attack narrative gaps explicitly documented?
- [ ] Timestamp alignment verified across corroborated findings (within tolerance)?

### 6. HANDOFF

Pass to:
- **hypothesis-testing**: Corroborated findings and contradictions as evidence for competing hypotheses
- **self-correction (Layer 3)**: Attack narrative for analytical coherence validation
- **reporting**: Tier 2 findings for the investigation report

---

## Watch-Outs

- **False corroboration**: Two tools finding the same artifact doesn't mean they independently confirm it. If both tools read the same data source (e.g., both read the MFT), that's one source, not two. True corroboration requires independent evidence sources.
- **Correlation ≠ causation**: Just because two events happened at the same time doesn't mean they're related. Look for logical connections, not just temporal ones.
- **Survivor bias in orphan findings**: A finding with no corroboration might be the most important one — it could represent evidence that was partially cleaned by the attacker. Don't dismiss orphans automatically.
- **Kill chain completeness**: Not every incident follows the full kill chain. A ransomware attack may skip lateral movement. An insider threat may start at privilege escalation. Don't force findings into a template that doesn't fit.
