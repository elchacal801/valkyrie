# VALKYRIE — Devpost Submission

> Draft text for the Devpost submission form at https://findevil.devpost.com/

---

## Project Name

VALKYRIE — Autonomous IR Agent for SIFT Workstation

## Short Description (one-liner)

An autonomous forensic investigation agent that thinks like a senior analyst — not just a tool runner — with structured hypothesis testing, multi-layer self-correction, and architectural evidence protection.

---

## Inspiration

Forensic investigators spend hours manually running tools, correlating artifacts, and building narratives. Most AI agents for IR simply wrap forensic tools behind an LLM and run them in sequence. The result is a tool runner, not an analyst.

We asked: what if an AI agent could reason about evidence the way a senior investigator does? Not just "run pslist and report the output," but "these three PowerShell processes were spawned by WMI from a remote host, which means lateral movement — let me check the named pipe C2 channel and test whether this is an APT or a red team exercise."

VALKYRIE was built to bridge that gap. It applies structured analytic techniques adapted from US Intelligence Community doctrine (specifically Analysis of Competing Hypotheses) to digital forensic evidence, producing investigations with tiered evidence, transparent reasoning, and honest self-assessment.

## What It Does

VALKYRIE conducts autonomous incident response investigations on SIFT Workstation using a 6-phase pipeline:

1. **Evidence Inventory** — Catalogs evidence files, computes SHA256 hashes, classifies types (disk images, memory dumps, logs, registry hives)
2. **Triage Assessment** — Quick-look YARA scan, process listing, network connections, initial anomaly detection
3. **Deep Analysis** — Executes technique protocols: memory analysis, timeline reconstruction, persistence enumeration, log analysis, malware triage
4. **Correlation & Synthesis** — Cross-references findings, builds attack narrative with MITRE ATT&CK mapping, runs Analysis of Competing Hypotheses (ACH) to systematically evaluate explanations
5. **Self-Correction & Verification** — Three-layer forensic validation catches hallucinated artifacts, temporal impossibilities, and analytical incoherence and auto-remediates; then a per-finding grounding pass labels each finding CONFIRMED / INFERRED / UNVERIFIED
6. **Reporting** — Produces a structured investigative report (with a Verification Ledger) where every claim cites the specific tool execution that produced the evidence

It also analyzes **cloud** identity logs (`/investigate cloud`) and can run a **persistent learning loop** (`/investigate --loop`) that iterates to verifiable success with a measured accuracy gain.

### Key Differentiators

**3-Tier Evidence System**: Every finding is classified by how it was produced:
- Tier 1: Direct tool output (highest confidence)
- Tier 2: Cross-referenced by 2+ independent tools
- Tier 3: Analytical inference (explicitly labeled with confidence score)

**3-Layer Self-Correction**: Not just "retry on error" — VALKYRIE systematically validates its own work:
- Layer 1: Re-invokes forensic tools to verify that every cited PID, file path, and registry key actually exists
- Layer 2: Checks that the timeline is chronologically possible and timezone-consistent
- Layer 3: Validates that the attack narrative follows a plausible kill chain and that alternative hypotheses were considered

**Hypothesis Testing (ACH for IR)**: Before concluding "APT intrusion," VALKYRIE systematically evaluates competing hypotheses — commodity malware, insider threat, legitimate activity, red team, **AI-assisted attack** — and eliminates them with specific evidence. The hypothesis with the fewest inconsistencies wins.

**Per-Finding Verification (hallucination guard)**: After self-correction, every finding gets an independent verdict — **CONFIRMED** (re-derived from a fresh tool call), **INFERRED** (analytical conclusion, never penalized), or **UNVERIFIED** (asserted but couldn't be grounded — flagged and downgraded, *never silently dropped*). Verification is grounded in tool re-execution, not re-reasoning, because re-reasoning only inflates confidence. This is the direct answer to "are hallucinations caught and flagged? are confirmed findings distinguished from inferences?"

**Measurable Persistent Learning Loop**: `/investigate --loop` iterates on the same evidence until verifiable success criteria are met (zero ungrounded asserted findings, zero open HIGH issues, kill-chain evidenced-or-marked) or progress stagnates. `logs/progress.jsonl` records each iteration's signals and a demonstrable first→final accuracy delta, with full execution traces preserved.

**Cloud breadth (Entra ID / Azure / M365)**: Modern intrusions often never touch a host disk. VALKYRIE analyzes identity-plane logs for impossible travel, MFA fatigue, illicit OAuth consent, BEC inbox rules, privileged role grants, and mass downloads — each mapped to MITRE ATT&CK for Cloud.

**Quantified accuracy**: A bundled harness (`eval/`) scores findings against documented ground truth (NIST CFReDS Hacking Case, a public memory image, and a synthetic Entra/Azure sample), producing precision/recall/F1 and explicit false-positive / missed-artifact tables — measuring precision only over *asserted* claims so inferences aren't mistaken for hallucinations.

**Architectural Evidence Protection**: Not prompt-based guardrails. Five enforcement layers that physically prevent evidence modification:
1. Typed MCP server (12 read-only functions — no shell access)
2. Denylist (73 blocked binaries including rm, dd, wget, curl, ssh)
3. `shell=False` on every subprocess call
4. PreToolUse hook blocks writes to evidence directories
5. PostToolUse hook logs every tool execution with SHA256 hashes

## How We Built It

**Framework**: Claude Code (CLI) as the agentic reasoning engine

**Custom MCP Server** (Python, stdio transport): 12 forensic tools wrapping SleuthKit (mmls, fls, icat), Volatility 3 (17 plugins), Plaso (log2timeline), YARA, FLOSS, RegRipper, and RECmd. Every tool call goes through `safe_subprocess()` with denylist checks and SHA256 audit logging. The server also includes a controlled process memory dump tool for extracting suspicious process images for FLOSS analysis.

**Skill Framework**: 9 technique protocols (markdown documents) that guide the agent through structured analysis — each protocol defines SETUP, PRIME, EXECUTE, ARTIFACT, FINDINGS, and HANDOFF steps. An orchestrator manages phase routing, technique selection, and a hypothesis-driven subagent swarm (parallel Tier-1 with an early contradiction pass before Tier-2). Dedicated `verification.md` (per-finding grounding) and `persistent-loop.md` (measurable iteration) protocols sit in Phase 5+. Includes a novel AI-adversary detection protocol grounded in GTIG, MITRE ATLAS v5.4.0, Arctic Wolf, and Unit42, plus a cloud-log analysis protocol mapped to ATT&CK for Cloud.

**Hooks**: PreToolUse hook enforces evidence write protection. PostToolUse hook maintains a JSONL audit trail; every tool execution carries a unique `execution_id` + SHA256, so any finding traces to one exact tool call.

**Test Suite & CI**: 81 tests (parsers, denylist, server dispatch, evidence-protection hooks, cloud detectors, eval harness) running on GitHub Actions across Python 3.10–3.12.

**Model**: Targets Claude Opus 4.8 — the same Claude Code + MCP reference architecture SANS demoed — and leans on frontier reasoning for hypothesis generation and verifier adjudication.

## Results

We tested VALKYRIE against the SRL-2018 Compromised Enterprise Network dataset — memory dumps from a domain controller and two workstations.

**What VALKYRIE found autonomously:**

- **Cobalt Strike SMB Beacon** deployed via WMI lateral movement on workstations, communicating over named pipe `\\.\pipe\diagsvc-22`
- **Meterpreter reverse_https** on the domain controller connecting to external C2 at `52.41.122.38:443` (AWS)
- **Mimikatz credential dumping** (`sekurlsa::logonpasswords`) on the DC — all domain credentials compromised
- **PowerSploit framework** including Invoke-Kerberoast, Get-Keystrokes, and AMSI bypass
- **Complete kill chain** mapped across 15+ MITRE ATT&CK techniques from Initial Access through C2
- **Cross-host correlation**: Identical Cobalt Strike payloads on both workstations, WMI lateral movement sourced from the DC

**Self-correction in action:**

During the first investigation, VALKYRIE initially flagged `subject_srv.exe` as a suspicious backdoor and `172.16.4.10:8080` as a C2 server. It then found contradicting evidence — a Windows Event ID 7045 identifying the binary as F-Response (a forensic tool), and a PAC file showing the IP was the corporate web proxy. It reclassified both before the formal validation phase, preventing two false positives from reaching the final report.

**Metrics:**
- 19 findings across 3 investigations (16 Tier 1, 3 Tier 3)
- 0 hallucinated artifacts detected in formal validation (14 PIDs verified)
- 2 in-flight reclassifications (false positive prevention)
- 100% evidence integrity (SHA256 hashes unchanged post-investigation)

## Challenges We Ran Into

1. **Volatility 3 ISF symbol mismatch**: 7 of 17 Volatility plugins returned empty results on all three memory dumps due to missing Intermediate Symbol Format files. We implemented a fallback strategy — pool-scanning plugins (psscan, netscan) work without ISF symbols, and raw strings extraction compensated for lost cmdline/malfind data.

2. **Subagent permissions**: When dispatching parallel investigation subagents, they couldn't access Bash or Write tools due to Claude Code's permission inheritance model. We resolved this by installing comprehensive permissions globally so subagents inherit them.

3. **Context window management**: A 5 GB memory dump generates massive tool output. The MCP server pre-parses and truncates results (500 rows max), and the pipeline architecture writes each phase to disk so the agent reads from files rather than accumulating context.

## What We Learned

- **Fallback strategies are essential**: Real forensic evidence is messy. Tools fail, symbols are missing, processes exit before capture. The protocols need explicit "if this fails, try that" guidance.
- **Self-correction is more than retry**: The most valuable corrections weren't tool failures — they were analytical errors. Reclassifying F-Response from "backdoor" to "forensic tool" required the agent to challenge its own initial assessment.
- **Architecture beats prompts**: Every safety guardrail that matters is enforced in code (denylist, shell=False, typed MCP functions), not in prompt instructions. The LLM literally cannot bypass them.

## What's Next

- Publish headline precision/recall/F1 on the full NIST CFReDS Hacking Case and a public memory image via the bundled `eval/` harness
- More cloud providers (AWS CloudTrail, GCP audit, Okta) behind the same `analyze_cloud_logs` model
- Network forensics (PCAP analysis) and automated multi-host / host↔cloud correlation
- IOC enrichment + structured `iocs.json` export for SIEM/EDR and YARA rule generation from discovered IOCs

## Built With

- Claude Code (Anthropic) — agentic framework
- Model Context Protocol (MCP) — tool integration
- SIFT Workstation (SANS) — forensic tool suite
- Volatility 3 — memory forensics
- SleuthKit — disk forensics
- Plaso / log2timeline — super timeline generation
- YARA — signature scanning
- FLOSS (Mandiant) — obfuscated string extraction
- RegRipper / RECmd — Windows registry analysis
- Microsoft Entra ID / Azure / M365 logs — cloud identity-plane analysis (ATT&CK for Cloud)
- Python — MCP server + accuracy harness implementation

---

## Links

- **Repository**: https://github.com/elchacal801/valkyrie
- **Demo Video**: [TODO]
- **Accuracy Report**: See `docs/accuracy-report.md` in the repository
- **Architecture Diagram**: See `docs/architecture-diagram.md` in the repository
