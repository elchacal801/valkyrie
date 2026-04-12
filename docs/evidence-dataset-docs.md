# Evidence Dataset Documentation

## Overview

This document describes the evidence datasets VALKYRIE was tested against, what the agent found, and how findings were validated.

---

## Test Datasets

### Dataset 1: SANS Starter Case Data

| Field | Value |
|-------|-------|
| **Source** | [SANS Find Evil! Hackathon Starter Data](https://sansorg.egnyte.com/fl/HhH7crTYT4JK) |
| **Type** | <!-- disk image / memory dump / logs --> |
| **Size** | <!-- total size --> |
| **SHA256** | <!-- hash of evidence files --> |
| **OS** | <!-- Windows version --> |
| **Description** | <!-- brief description of the scenario --> |

#### Evidence Files

| # | File | Type | Size | SHA256 |
|---|------|------|------|--------|
| 1 | | | | |

#### What VALKYRIE Found

<!-- Populated after testing -->

| # | Finding | Confidence | Evidence Tier | Correct? |
|---|---------|------------|---------------|----------|
| 1 | | | | |

#### Self-Corrections Applied

| # | Layer | Issue | Resolution |
|---|-------|-------|------------|
| 1 | | | |

---

## Testing Methodology

1. **Evidence preparation**: Downloaded starter case data, verified SHA256 hashes, mounted read-only
2. **Full guided investigation**: `/investigate --guided --evidence-path <path>`
3. **Lean triage**: `/investigate --lean --evidence-path <path>`
4. **Individual technique testing**: Each technique run independently to verify output quality
5. **Self-correction testing**: Verified all three validation layers executed and detected real issues
6. **Evidence integrity verification**: Confirmed evidence file hashes unchanged after investigation

## Reproducibility

To reproduce these results:

```bash
# 1. Install VALKYRIE on SIFT Workstation
./install.sh

# 2. Download the starter case data
# (from the hackathon Egnyte link above)

# 3. Mount evidence read-only
sudo mkdir -p /cases/TEST-001/evidence
sudo mount -o ro <evidence_path> /cases/TEST-001/evidence/

# 4. Run the investigation
cd /opt/valkyrie
claude
/investigate --guided --evidence-path /cases/TEST-001/evidence/

# 5. Review results
ls /cases/TEST-001/
cat /cases/TEST-001/report/investigation-report.md
cat /cases/TEST-001/corrections/validation-summary.json
```

---

*This document will be updated with specific findings after testing against the starter case data.*
