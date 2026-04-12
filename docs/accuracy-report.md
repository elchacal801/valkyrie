# Accuracy Report

## Overview

This accuracy report documents VALKYRIE's performance against test evidence datasets. It is an honest self-assessment — transparency about limitations is more valuable than claiming perfection.

---

## Summary Metrics

| Metric | Value |
|--------|-------|
| Test cases run | <!-- count --> |
| Total findings produced | <!-- count --> |
| Self-corrections applied | <!-- count --> |
| Hallucinations detected (Layer 1) | <!-- count --> |
| Temporal inconsistencies detected (Layer 2) | <!-- count --> |
| Analytical coherence issues detected (Layer 3) | <!-- count --> |
| Evidence integrity maintained | <!-- YES/NO --> |

---

## Findings Accuracy

<!-- Populated after testing against cases with known ground truth -->

### By Confidence Level

| Confidence | Count | Verified Correct | Verified Incorrect | Unverified |
|-----------|-------|-----------------|-------------------|------------|
| HIGH | | | | |
| MEDIUM | | | | |
| LOW | | | | |

### By Evidence Tier

| Tier | Count | Accuracy Rate | Notes |
|------|-------|--------------|-------|
| Tier 1 (direct tool output) | | | |
| Tier 2 (cross-referenced) | | | |
| Tier 3 (analytical inference) | | | |

---

## Self-Correction Performance

### Layer 1: Artifact Existence Validation

| Check | Count | Issues Found | Corrected |
|-------|-------|-------------|-----------|
| File path verification | | | |
| PID verification | | | |
| Registry key verification | | | |
| Log entry verification | | | |
| Offset validation | | | |
| Hash verification | | | |

### Layer 2: Temporal Consistency

| Check | Count | Issues Found | Corrected |
|-------|-------|-------------|-----------|
| Chronological ordering | | | |
| Timezone consistency | | | |
| MAC time consistency | | | |
| Temporal gap analysis | | | |
| Evidence timeframe bounds | | | |

### Layer 3: Analytical Coherence

| Check | Count | Issues Found | Corrected |
|-------|-------|-------------|-----------|
| Kill chain plausibility | | | |
| Cross-technique contradiction | | | |
| MITRE ATT&CK consistency | | | |
| Confidence calibration | | | |
| Alternative hypothesis check | | | |

---

## Evidence Integrity

### Protection Layers Tested

| Layer | Test | Result |
|-------|------|--------|
| Typed MCP functions | Attempted arbitrary shell command via MCP | <!-- BLOCKED/ALLOWED --> |
| Denylist | Attempted `rm` via tool argument | <!-- BLOCKED/ALLOWED --> |
| shell=False | Attempted shell injection via crafted argument | <!-- BLOCKED/ALLOWED --> |
| PreToolUse hook | Attempted write to evidence directory via Bash | <!-- BLOCKED/ALLOWED --> |
| Read-only mount | Attempted write to mounted evidence partition | <!-- BLOCKED/ALLOWED --> |

### Evidence Hash Verification

| Evidence File | Pre-Investigation SHA256 | Post-Investigation SHA256 | Match |
|--------------|--------------------------|--------------------------|-------|
| | | | |

---

## Known Limitations

1. **Static malware analysis only**: VALKYRIE performs YARA scanning and string extraction but cannot execute suspicious files in a sandbox
2. **No network forensics**: PCAP analysis is not currently implemented
3. **Context window constraints**: Very large evidence sets may require multiple `/investigate --iterate` cycles
4. **Tool availability**: Some SIFT tools (MFTECmd, FLOSS, RECmd) are optional; the agent falls back to alternatives when unavailable
5. **Single-system analysis**: VALKYRIE analyzes one system at a time; multi-host correlation is not automated

---

*This report will be populated with specific metrics after testing against the SANS starter case data.*
