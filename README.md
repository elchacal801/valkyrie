<p align="center">
  <img src="docs/images/valkyrie-banner.png" alt="VALKYRIE" width="100%"/>
</p>

<p align="center">
  <img src="docs/images/valkyrie-logo.svg" alt="" width="60"/>
</p>

<h1 align="center">VALKYRIE</h1>

<p align="center">
  <strong>Teach an AI agent to think like a senior forensic analyst.</strong>
</p>

<p align="center">
  Autonomous incident response with structured analytical reasoning,<br/>
  multi-layer self-correction, and architectural evidence protection.
</p>

<p align="center">
  <a href="https://findevil.devpost.com/"><img src="https://img.shields.io/badge/SANS-Find%20Evil!-2ecc71?style=flat-square" alt="Find Evil!"/></a>
  <img src="https://img.shields.io/badge/framework-Claude%20Code-cc785c?style=flat-square" alt="Claude Code"/>
  <img src="https://img.shields.io/badge/architecture-Custom%20MCP-5c8fcc?style=flat-square" alt="MCP Server"/>
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="MIT License"/>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#investigation-pipeline">Pipeline</a> ·
  <a href="docs/accuracy-report.md">Accuracy Report</a>
</p>

---

**Validated Autonomous Logic for Kill-chain Yielding Rapid Incident Examination**

An autonomous AI incident response agent for the [SANS "Find Evil!" Hackathon](https://findevil.devpost.com/). VALKYRIE runs on the SIFT Workstation, uses Claude Code as the agentic framework, and leverages a custom MCP server with structured analytical reasoning to investigate digital forensic evidence.

## What Makes VALKYRIE Different

Most forensic AI agents are **tool runners** -- they wrap forensic tools behind an LLM and execute them in sequence. VALKYRIE is an **analytical reasoner** -- it applies structured analytic techniques adapted from US Intelligence Community doctrine to investigate incidents with hypothesis testing, evidence tiering, and multi-layer self-correction.

| Capability | Tool Runner | VALKYRIE |
|-----------|------------|----------|
| Tool execution | Sequential phases | Adaptive technique selection based on evidence |
| Findings | Binary (found/not found) | 3-tier evidence with confidence scores |
| Self-correction | Retry on failure | 3-layer forensic validation (artifact existence, temporal consistency, analytical coherence) |
| Reasoning | Hidden | Transparent hypothesis testing (ACH for IR) |
| Audit trail | Tool execution log | Case directory IS the audit trail |

## Architecture

```
Claude Code (reasoning engine)
    |
VALKYRIE Skill Framework (/investigate command)
    |-- Orchestrator (6-phase IR pipeline)
    |-- Self-Correction (3 forensic validation layers)
    |-- 7+ Technique Protocols (IR-adapted SATs)
    |-- Templates & Reporting
    |
Claude Code Hooks (evidence protection + audit logging)
    |
Custom MCP Server (Python, stdio transport)
    |-- 5 tool modules: disk, timeline, memory, registry, scanner
    |-- Denylist + shell=False + SHA256 logging
    |
SIFT Workstation Tools (sleuthkit, volatility3, plaso, yara, regripper)
    |
Evidence (read-only mount)
```

### Trust Boundaries

**Architectural enforcement (not prompt-based):**
1. MCP server exposes only typed read functions -- no shell access to the agent
2. Denylist blocks destructive binaries (rm, dd, shred, wget, curl, ssh) at subprocess level
3. All subprocess calls use `shell=False` -- no shell injection possible
4. Evidence mounted read-only at OS level
5. PreToolUse hook blocks any write attempt to evidence directory
6. PostToolUse hook logs every tool call with SHA256 hash of output

**Prompt-based guardrails (documented as such):**
- Skill protocols instruct the agent to follow the pipeline sequence
- Self-correction protocols instruct the agent to verify findings before reporting

### Judging Criteria Alignment

| Criterion | VALKYRIE Component |
|-----------|-------------------|
| #1 Autonomous Execution (tiebreaker) | Adaptive technique selection, ACH hypothesis testing, 3-layer self-correction with tool re-invocation |
| #2 IR Accuracy | 3-tier evidence with confidence scores, explicit hallucination detection via Layer 1 validation |
| #3 Breadth & Depth | 5 tool modules with deep analysis via 7+ technique protocols (depth over breadth) |
| #4 Constraint Implementation | 5-layer architectural enforcement (typed MCP + denylist + hooks + shell=False + read-only mount) |
| #5 Audit Trail | Case directory structure = audit trail. Per-phase JSON output + correction records + reasoning trace |
| #6 Usability | One-liner install, clear documentation, reproducible on SIFT Workstation |

## Quick Start

```bash
# On SIFT Workstation
curl -fsSL https://raw.githubusercontent.com/elchacal801/valkyrie/main/install.sh | bash

# Run an investigation
/investigate --guided --evidence-path /cases/CASE-001/evidence/
```

## Usage

```
/investigate                                    # Auto-assess evidence, select techniques
/investigate timeline                           # Run timeline reconstruction specifically
/investigate memory                             # Focus on memory analysis
/investigate --guided                           # Walk through all 6 IR phases
/investigate --lean                             # Fast triage mode (3 techniques)
/investigate --resume <case-id>                 # Continue a previous investigation
/investigate --iterate <case-id>                # Re-run with new evidence
/investigate --evidence-path /path/to/evidence  # Specify evidence location
```

## Investigation Pipeline

1. **Evidence Inventory** -- Catalog evidence files, compute hashes, classify types
2. **Triage Assessment** -- Quick-look YARA scan, partition layout, initial timeline bounds
3. **Deep Analysis** -- Technique execution (timeline reconstruction, memory analysis, persistence enumeration, etc.)
4. **Correlation & Synthesis** -- Cross-reference findings across evidence sources, build attack narrative
5. **Self-Correction & Validation** -- Three-layer forensic validation with auto-remediation
6. **Reporting** -- Structured investigative narrative with citations to specific artifacts

## Evidence Tiers

| Tier | Source | Confidence |
|------|--------|------------|
| Tier 1 | Direct tool output (single MCP call) | Highest -- single-source confirmed |
| Tier 2 | Cross-referenced (2+ tools corroborate) | High -- multi-source confirmed |
| Tier 3 | Analytical inference (agent reasoning) | Variable -- requires confidence score |

## Novel Contribution

VALKYRIE's analytical reasoning framework is inspired by the pattern of [Blevene/structured-analysis-skill](https://github.com/Blevene/structured-analysis-skill) (Apache 2.0), which implements CIA/IC Structured Analytic Techniques. The novel contribution is:

- **IR-specific technique library** -- 7+ forensic investigation techniques (timeline reconstruction, artifact correlation, ACH-adapted hypothesis testing, memory analysis, persistence enumeration, log analysis, malware triage)
- **Forensic self-correction layers** -- Three-layer validation (artifact existence, temporal consistency, analytical coherence) specifically designed to catch IR-specific hallucination patterns
- **Custom MCP server** -- Purpose-built for SIFT Workstation tool safety with typed functions, denylist enforcement, and SHA256 audit logging
- **Evidence tiering system** -- Distinguishing confirmed findings from analytical inferences with explicit confidence scoring

## License

MIT -- see [LICENSE](LICENSE).

## Author

Diego Parra / [CrimsonVector Security](https://github.com/elchacal801)
