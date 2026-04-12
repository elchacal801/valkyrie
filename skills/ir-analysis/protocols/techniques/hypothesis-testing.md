# Protocol: Hypothesis Testing (ACH for Incident Response)

> **Phase**: Correlation | **Evidence**: All prior technique outputs | **Produces**: Tier 3 findings
> **Output Artifact**: `analysis/hypothesis-testing.json`
> **Adapted from**: Analysis of Competing Hypotheses (ACH) — CIA/IC Structured Analytic Technique
> **Bias Mitigated**: Confirmation bias, premature closure, anchoring to first hypothesis

---

## Purpose

Evaluate competing explanations for the observed forensic evidence by focusing on disconfirmation rather than confirmation. The hypothesis with the least inconsistent evidence is most plausible. This technique prevents the agent from anchoring on the first plausible narrative and forces systematic consideration of alternatives.

This is the core analytical reasoning technique that demonstrates VALKYRIE thinks like a senior analyst, not just a tool runner.

---

## Execution

### 1. SETUP

- Read `synthesis.json` or all `analysis/*.json` files for findings and evidence
- Read `triage.json` for initial incident type hypothesis
- Read `analysis/artifact-correlation.json` for corroborations and contradictions
- Compile a master evidence list: every finding from all techniques, with tier and confidence

### 2. PRIME

"I will now evaluate ALL competing hypotheses for what caused the observed forensic evidence. The focus is on disproving hypotheses, not confirming a preferred one. Each hypothesis must be tested against every piece of evidence. The goal is to identify the explanation with the fewest inconsistencies."

### 3. EXECUTE

#### 3.1 Generate Competing Hypotheses

Generate at least 4 hypotheses, always including these standard alternatives:

| # | Hypothesis | Description |
|---|-----------|-------------|
| H1 | **Targeted intrusion (APT)** | A sophisticated threat actor deliberately compromised this system as part of a targeted campaign. Indicators: specific TTPs, lateral movement, data staging, custom tools. |
| H2 | **Opportunistic malware** | The system was infected by commodity malware (ransomware, cryptominer, botnet agent) via phishing, exploit kit, or drive-by download. Indicators: known malware families, automated behavior. |
| H3 | **Insider threat** | An authorized user misused their access for unauthorized purposes. Indicators: legitimate credentials, normal working hours, access to specific data. |
| H4 | **Legitimate activity (null hypothesis)** | The observed artifacts are the result of normal system administration, software updates, or authorized security testing. This MUST be genuinely considered. |
| H5 | **Red team / penetration test** | The observed activity is from an authorized security assessment. Indicators: testing tools (Cobalt Strike, Metasploit), limited scope, specific timeframe. |

Add case-specific hypotheses based on the evidence (e.g., "supply chain compromise via trojanized update" if software update artifacts are suspicious).

#### 3.2 Compile Evidence Items

List ALL evidence items from the investigation. For each item, record:
- Evidence ID (from the source technique)
- Description
- Source technique
- Evidence tier (1, 2, or 3)
- Confidence level

Include:
- **Positive evidence**: What was observed
- **Negative evidence**: What was expected but absent (e.g., "no lateral movement indicators found despite network access")
- **Contradictions**: Conflicts between techniques (from artifact-correlation)

#### 3.3 Build the Diagnosticity Matrix

Create a matrix: hypotheses across columns, evidence items down rows.

Rate each cell:
- **C** (Consistent) — This evidence is what you'd expect if this hypothesis were true
- **I** (Inconsistent) — This evidence contradicts this hypothesis
- **N** (Neutral) — This evidence neither supports nor contradicts this hypothesis

**Critical rule — Law of Diagnostic Dominance**: Evidence rated C or N across ALL hypotheses has ZERO diagnostic value. Flag it explicitly. Only evidence that is I for at least one hypothesis helps discriminate.

Example matrix:

| Evidence | H1: APT | H2: Malware | H3: Insider | H4: Legitimate | H5: Red Team |
|----------|---------|-------------|-------------|---------------|--------------|
| Encrypted C2 channel to external IP | C | C | N | I | C |
| Custom tool not in any malware DB | C | I | N | I | C |
| Activity only during business hours | N | N | C | C | N |
| Credential theft from LSASS | C | N | I | I | C |
| No data exfiltration detected | I | N | C | C | N |

#### 3.4 Tally Inconsistencies

Count the number of I (Inconsistent) ratings for each hypothesis. The hypothesis with the **fewest** inconsistencies is most plausible.

**Important**: This is not a vote. A single highly reliable inconsistency can eliminate a hypothesis even if it has fewer total I ratings. Weight the quality of the inconsistent evidence, not just the count.

#### 3.5 Sensitivity Analysis

Identify evidence items that, if reinterpreted or removed, would change the conclusion:
- Which single piece of evidence is most critical to the leading hypothesis?
- If that evidence were wrong (Layer 1 catches a hallucinated artifact), would the conclusion change?
- Are there any "linchpin" assumptions that the entire analysis rests on?

#### 3.6 Define Future Indicators

For the leading hypothesis, define observable events that would:
- **Confirm**: What additional evidence would strengthen this conclusion? (e.g., "If we found the C2 infrastructure IP in threat intel feeds as APT-X")
- **Refute**: What evidence would disprove this conclusion? (e.g., "If the 'custom tool' turns out to be a legitimate admin utility")

### 4. ARTIFACT

Write `analysis/hypothesis-testing.json` to the case directory:

```json
{
  "technique": "hypothesis-testing",
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "hypotheses": [
    {
      "id": "H1",
      "name": "Targeted intrusion (APT)",
      "description": "...",
      "inconsistencies": 1,
      "key_consistent_evidence": ["E-001", "E-003"],
      "key_inconsistent_evidence": ["E-005"],
      "assessment": "Most plausible — fewest inconsistencies, strongest corroboration"
    }
  ],
  "evidence_items": [
    {
      "id": "E-001",
      "description": "...",
      "source_technique": "timeline-reconstruction",
      "evidence_tier": 1,
      "ratings": {"H1": "C", "H2": "I", "H3": "N", "H4": "I", "H5": "C"},
      "diagnostic_value": "HIGH — discriminates between H1/H5 and H2/H4"
    }
  ],
  "diagnosticity_matrix": "...",
  "zero_diagnostic_items": ["E-003 — consistent with all hypotheses"],
  "leading_hypothesis": {
    "id": "H1",
    "name": "Targeted intrusion (APT)",
    "confidence": "MEDIUM",
    "inconsistency_count": 1,
    "rationale": "..."
  },
  "eliminated_hypotheses": [
    {
      "id": "H4",
      "name": "Legitimate activity",
      "reason": "Inconsistent with 3 evidence items: encrypted C2, credential theft, custom tool"
    }
  ],
  "sensitivity_analysis": {
    "critical_evidence": "E-002 (custom tool not in malware DB)",
    "impact_if_wrong": "If the tool is actually a legitimate admin utility, H1 and H2 become equally plausible",
    "linchpin_assumptions": ["The C2 channel is not a legitimate VPN connection"]
  },
  "future_indicators": {
    "confirm": ["C2 IP found in APT-X threat intel", "Second stage payload discovered"],
    "refute": ["'Custom tool' identified as legitimate software", "Red team engagement confirmed for this timeframe"]
  },
  "findings": [
    {
      "finding_id": "HT-001",
      "description": "Targeted intrusion is the most plausible explanation...",
      "confidence": "MEDIUM",
      "evidence_tier": 3,
      "citation": "[INFERENCE: ACH analysis — H1 has fewest inconsistencies (1) vs H2 (2), H3 (3), H4 (3), H5 (1). H1 preferred over H5 due to absence of red team indicators. Confidence: MEDIUM]"
    }
  ]
}
```

### 5. FINDINGS

Summarize:
- Most plausible hypothesis with confidence level and key supporting evidence
- Eliminated hypotheses with specific disconfirming evidence
- Critical sensitivities — what would change the conclusion
- Zero-diagnostic-value evidence identified and flagged
- Future indicators for ongoing monitoring

**Layer 1 Self-Check:**
- [ ] At least 4 hypotheses evaluated (including null)?
- [ ] Null hypothesis (legitimate activity) genuinely considered?
- [ ] Diagnosticity matrix complete (every cell rated)?
- [ ] Zero-diagnostic-value items identified?
- [ ] Leading hypothesis has a confidence level with explicit rationale?
- [ ] At least one hypothesis eliminated with specific evidence?
- [ ] Sensitivity analysis identifies the most critical evidence item?
- [ ] Findings are labeled as Tier 3 (inference)?

### 6. HANDOFF

Pass to:
- **self-correction (Layer 3)**: The leading hypothesis and elimination rationale for analytical coherence validation
- **reporting**: The ACH matrix and findings for the investigation report — this is key material for demonstrating analytical reasoning to judges
- **future indicators**: For the monitoring/next-steps section of the report

---

## Watch-Outs

- **Anchoring to the first hypothesis**: The most common failure. If the triage suggested "ransomware," the agent will unconsciously favor H2 (opportunistic malware). Combat this by rating H1 (APT) first and looking for evidence that SUPPORTS it before evaluating H2.
- **Confirmation through consistency**: Do not mistake "most consistent evidence" for "most plausible hypothesis." Focus on inconsistencies. A hypothesis with 10 consistent items and 3 inconsistent items is LESS plausible than one with 5 consistent items and 0 inconsistent items.
- **Missing hypothesis trap**: If the true explanation isn't among the listed hypotheses, the matrix produces a false winner. If results feel forced (no hypothesis has fewer than 3 inconsistencies), add hypotheses.
- **Noise in large matrices**: With 5+ hypotheses and 10+ evidence items, individual C/I/N ratings accumulate noise. Focus on HIGH-diagnostic-value evidence and strong inconsistencies, not the total count.
- **Tier 3 labeling**: All findings from hypothesis testing are Tier 3 (inference) by definition. Never assign Tier 1 or Tier 2 to a hypothesis testing conclusion — those tiers are reserved for direct tool output and cross-referenced findings.
