# Investigation Report: {{CASE_ID}}

**Date**: {{REPORT_DATE}}

**Examiner**: {{EXAMINER_NAME}}

**Classification**: {{CLASSIFICATION}}

**Status**: {{STATUS}}

---

## Investigation Summary

{{INVESTIGATION_SUMMARY}}

**Incident Type**: {{INCIDENT_TYPE}}
**Investigation Period**: {{T0}} to {{TN}}
**Evidence Analyzed**: {{EVIDENCE_SUMMARY}}
**Techniques Applied**: {{TECHNIQUES_USED}}

---

## Key Findings

| # | Finding | Confidence | Evidence Tier | Supporting Tools | MITRE ATT&CK |
|---|---------|------------|---------------|------------------|---------------|
{{#FINDINGS}}
| {{FINDING_ID}} | {{DESCRIPTION}} | {{CONFIDENCE}} | Tier {{TIER}} | {{TOOLS}} | {{MITRE}} |
{{/FINDINGS}}

**Tier Legend**: Tier 1 = Direct tool output | Tier 2 = Cross-referenced (2+ tools) | Tier 3 = Analytical inference

---

## Attack Narrative

### Timeline of Events

{{ATTACK_NARRATIVE}}

### Kill Chain Mapping

| Phase | Activity | Evidence | Confidence |
|-------|----------|----------|------------|
| Initial Access | {{INITIAL_ACCESS}} | {{EVIDENCE}} | {{CONFIDENCE}} |
| Execution | {{EXECUTION}} | {{EVIDENCE}} | {{CONFIDENCE}} |
| Persistence | {{PERSISTENCE}} | {{EVIDENCE}} | {{CONFIDENCE}} |
| Privilege Escalation | {{PRIV_ESC}} | {{EVIDENCE}} | {{CONFIDENCE}} |
| Lateral Movement | {{LATERAL}} | {{EVIDENCE}} | {{CONFIDENCE}} |
| Collection | {{COLLECTION}} | {{EVIDENCE}} | {{CONFIDENCE}} |
| Exfiltration | {{EXFIL}} | {{EVIDENCE}} | {{CONFIDENCE}} |

**Kill Chain Gaps**: {{GAPS}}

---

## Competing Hypotheses Assessment

{{#IF HYPOTHESIS_TESTING_RAN}}

| Hypothesis | Inconsistencies | Assessment |
|-----------|----------------|------------|
{{#HYPOTHESES}}
| {{NAME}} | {{INCONSISTENCY_COUNT}} | {{ASSESSMENT}} |
{{/HYPOTHESES}}

**Leading Hypothesis**: {{LEADING_HYPOTHESIS}}
**Confidence**: {{HYPOTHESIS_CONFIDENCE}}
**Key Discriminating Evidence**: {{DISCRIMINATING_EVIDENCE}}

**Eliminated Hypotheses**: {{ELIMINATED}}

{{#ELSE}}

**Not performed.** {{HYPOTHESIS_SKIP_REASON}}

To run hypothesis testing on this case, use: `/investigate --iterate {{CASE_ID}} hypothesis`

{{/IF}}

---

## Sensitivity Analysis

{{#IF HYPOTHESIS_TESTING_RAN}}

What would change the conclusion:

| Question | Answer |
|----------|--------|
| **Most critical evidence** | {{CRITICAL_EVIDENCE}} |
| **If that evidence is wrong** | {{IMPACT_IF_WRONG}} |
| **What would refute the conclusion** | {{REFUTATION_EVIDENCE}} |
| **Linchpin assumptions** | {{LINCHPIN_ASSUMPTIONS}} |

{{#ELSE}}

**Not performed.** Sensitivity analysis requires hypothesis testing (Phase 4). {{HYPOTHESIS_SKIP_REASON}}

{{/IF}}

---

## AI-Adversary Assessment

{{#IF AI_ADVERSARY_RAN}}

**Composite AI-Adversary Likelihood**: {{AI_LIKELIHOOD_SCORE}} ({{AI_CLASSIFICATION}})
**Confidence**: {{AI_CONFIDENCE}}

| Analytical Lens | Score | Key Indicators |
|----------------|-------|----------------|
| Behavioral Entropy (Temporal) | {{TEMPORAL_SCORE}} | {{TEMPORAL_INDICATORS}} |
| Credential Automation | {{CREDENTIAL_SCORE}} | {{CREDENTIAL_INDICATORS}} |
| LOLBin Chain Analysis | {{LOLBIN_SCORE}} | {{LOLBIN_INDICATORS}} |
| API-Based Attack Indicators | {{API_SCORE}} | {{API_INDICATORS}} |
| Absence-of-Evidence | {{ABSENCE_SCORE}} | {{ABSENCE_INDICATORS}} |
| Decoy Artifact Detection | {{DECOY_SCORE}} | {{DECOY_INDICATORS}} |

{{AI_ASSESSMENT_NARRATIVE}}

**Threat Intelligence References**: {{THREAT_INTEL_REFS}}

**Caveat**: {{AI_CAVEAT}}

{{#ELSE}}

**Not performed.** {{AI_ADVERSARY_SKIP_REASON}}

To run AI-adversary analysis on this case, use: `/investigate --iterate {{CASE_ID}} ai-adversary`

{{/IF}}

---

## Audit Trail — How to Verify Each Finding

Each finding traces back to a specific tool execution. To independently verify any finding:

{{#FINDINGS_AUDIT}}
### {{FINDING_ID}}: {{FINDING_TITLE}}

**Evidence lineage:**
1. **Tool**: {{TOOL_NAME}} on {{EVIDENCE_FILE}}
   - Output: `{{OUTPUT_PATH}}` ({{OUTPUT_DETAIL}})
   - SHA256 of output: `{{OUTPUT_SHA256}}`
2. **Verification**: {{VERIFICATION_METHOD}}
   - How to reproduce: `{{REPRODUCE_COMMAND}}`

{{/FINDINGS_AUDIT}}

---

## Investigative Methodology

### Techniques Applied

| Technique | Purpose | Key Output |
|----------|---------|------------|
{{#TECHNIQUES}}
| {{NAME}} | {{PURPOSE}} | {{KEY_OUTPUT}} |
{{/TECHNIQUES}}

### Tool Execution Summary

| Tool | Invocations | Evidence Analyzed | Key Findings Produced |
|------|------------|-------------------|----------------------|
{{#TOOLS}}
| {{TOOL_NAME}} | {{COUNT}} | {{EVIDENCE}} | {{FINDINGS_COUNT}} |
{{/TOOLS}}

### Evidence Sources

| # | File | Type | SHA256 | Findings Sourced |
|---|------|------|--------|-----------------|
{{#EVIDENCE_FILES}}
| {{NUM}} | {{NAME}} | {{TYPE}} | {{SHA256_SHORT}} | {{FINDINGS_COUNT}} |
{{/EVIDENCE_FILES}}

---

## Self-Correction Summary

{{#IF SELF_CORRECTION_RAN}}

{{SELF_CORRECTION_NARRATIVE}}

### Corrections Applied

| # | Layer | Issue Type | Severity | Description | Resolution |
|---|-------|-----------|----------|-------------|------------|
{{#CORRECTIONS}}
| {{CORRECTION_ID}} | Layer {{LAYER}} | {{ISSUE_TYPE}} | {{SEVERITY}} | {{DESCRIPTION}} | {{RESOLUTION}} |
{{/CORRECTIONS}}

### Validation Summary

- **Layer 1 (Artifact Existence)**: {{LAYER1_CHECKS}} checks, {{LAYER1_ISSUES}} issues found, {{LAYER1_CORRECTIONS}} corrected
- **Layer 2 (Temporal Consistency)**: {{LAYER2_CHECKS}} checks, {{LAYER2_ISSUES}} issues found, {{LAYER2_CORRECTIONS}} corrected
- **Layer 3 (Analytical Coherence)**: {{LAYER3_CHECKS}} checks, {{LAYER3_ISSUES}} issues found, {{LAYER3_CORRECTIONS}} corrected

**Total corrections**: {{TOTAL_CORRECTIONS}}
**Findings removed**: {{FINDINGS_REMOVED}}
**Confidence downgrades**: {{CONFIDENCE_DOWNGRADES}}

{{#ELSE}}

**Not performed.** {{SELF_CORRECTION_SKIP_REASON}}

To run self-correction on this case, use: `/investigate --iterate {{CASE_ID}}`

{{/IF}}

---

## Limitations and Caveats

{{LIMITATIONS}}

### Evidence Not Analyzed

{{EVIDENCE_NOT_ANALYZED}}

### Techniques Not Applied

{{TECHNIQUES_NOT_APPLIED}}

### Known Gaps

{{KNOWN_GAPS}}

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Evidence | Confidence |
|--------|----------|---------------|----------|------------|
{{#MITRE_MAPPINGS}}
| {{TACTIC}} | {{TECHNIQUE}} ({{TECHNIQUE_ID}}) | {{SUB_TECHNIQUE}} | {{EVIDENCE_REF}} | {{CONFIDENCE}} |
{{/MITRE_MAPPINGS}}

---

## Indicators of Compromise

| Type | Value | Context | Source Finding |
|------|-------|---------|---------------|
{{#IOCS}}
| {{TYPE}} | `{{VALUE}}` | {{CONTEXT}} | {{FINDING_ID}} |
{{/IOCS}}

---

## Recommendations

{{RECOMMENDATIONS}}

---

## Citations

Every finding in this report traces to a specific tool execution. Full tool execution logs are available at `{{CASE_DIR}}/logs/tool-execution.jsonl`.

| Citation ID | Format | Reference |
|------------|--------|-----------|
{{#CITATIONS}}
| {{CIT_ID}} | {{FORMAT}} | {{REFERENCE}} |
{{/CITATIONS}}

---

*Report generated by VALKYRIE (Validated Autonomous Logic for Kill-chain Yielding Rapid Incident Examination)*
*Case directory: {{CASE_DIR}}*
*Report timestamp: {{REPORT_TIMESTAMP}}*
