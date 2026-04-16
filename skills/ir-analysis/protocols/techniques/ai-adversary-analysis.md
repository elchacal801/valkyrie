# Protocol: AI-Adversary Analysis

> **Phase**: Correlation | **Evidence**: All prior technique outputs | **Produces**: Tier 2 and Tier 3 findings
> **Output Artifact**: `analysis/ai-adversary-analysis.json`
> **Depends on**: 2+ Phase 3 (Deep Analysis) outputs
> **Analytical Framework**: Behavioral pattern analysis calibrated for non-human operational tempo, tool orchestration, and anti-forensic sophistication
> **Threat Intelligence Basis**: GTIG AI Threat Tracker (PROMPTFLUX, PROMPTSTEAL, PROMPTLOCK), MITRE ATLAS v5.4.0 (AML.T0096–T0101), Arctic Wolf AI Malware Report, Unit42 AI in Malware analysis

---

## Purpose

Traditional forensic analysis assumes human-speed operations, sequential decision-making, and known TTP patterns. AI-driven attacks violate all three assumptions: frontier models (Anthropic Mythos, OpenAI Spud, open-source variants) can chain exploits in seconds, generate polymorphic payloads on demand, and operate through legitimate APIs without spawning detectable processes.

This technique applies six analytical lenses to existing forensic evidence to detect behavioral signatures of AI-assisted or fully-autonomous adversaries. It consumes outputs from all Tier 1 techniques and produces Tier 2 (cross-referenced) and Tier 3 (inference) findings.

**Important**: This protocol detects **non-human operational patterns**, not AI specifically. Sophisticated scripted attacks, automated red team tools, and worm propagation may produce similar signatures. Findings should be framed as "automated/AI-driven indicators" with appropriate caveats.

---

## Execution

### 1. SETUP

- Read ALL `analysis/*.json` files from the case directory (Phase 3 outputs)
- Read `triage.json` for initial anomalies and timeline bounds
- Read `analysis/artifact-correlation.json` (if available) for corroboration counts and contradictions
- Build a master evidence list:
  - All timestamps from all techniques
  - All credential/authentication events
  - All process execution chains and command lines
  - All persistence mechanisms discovered
  - All malware triage classifications
  - All corroboration counts per finding (from artifact-correlation)

### 2. PRIME

"I will now analyze all prior technique outputs through six lenses designed to detect AI-driven or automated adversary behavior. This analysis is grounded in real-world threat intelligence: Google GTIG's documented AI-enabled malware families (PROMPTFLUX, PROMPTSTEAL), MITRE ATLAS agent attack techniques, and published indicators from Arctic Wolf and Unit42. Each lens produces a 0.0–1.0 score; the composite assessment indicates the likelihood of AI-adversary involvement."

### 3. EXECUTE

#### 3.1 Behavioral Entropy Analysis (Temporal Pacing)

Pull all timestamps from `timeline-reconstruction.json` (if available) and `log-analysis.json`. Analyze the temporal distribution of suspicious events:

1. **Sub-minute kill chain detection**: Measure the time between adjacent kill chain phases (initial access → execution → persistence → lateral movement). If any two adjacent phases complete within 60 seconds, flag as AI-tempo indicator. Human operators need time to read output, make decisions, and type commands — sub-minute phase transitions are anomalous.

2. **Metronomic timing detection**: For clusters of 3+ sequential suspicious events, compute the inter-event intervals and their coefficient of variation (CV = standard deviation / mean). CV < 0.15 across 5+ events indicates mechanical pacing — human operators show CV > 0.30 due to variable reaction times, typing speeds, and decision pauses.

3. **Sustained activity without pauses**: Assess suspicious activity clusters spanning > 5 minutes. If the cluster contains no pauses > 30 seconds, the operator likely did not pause to read output or make decisions. Human operators exhibit bursty patterns (intense activity → pause → activity). Sustained, evenly-paced activity is a scripted/AI indicator.

4. **Parallelized operations**: Identify cases where two or more causally independent suspicious events occur within a 5-second window on the same system (e.g., file creation in one directory AND registry modification simultaneously). Humans operate serially. Parallel operations suggest programmatic execution or multi-threaded tooling.

**Scoring**: Each indicator contributes to a `temporal_anomaly_score` (0.0–1.0):
- 0 indicators → 0.0
- Sub-minute kill chain alone → 0.4
- Sub-minute + metronomic timing → 0.7
- Sub-minute + metronomic + sustained + parallel → 1.0

#### 3.2 Credential Automation Pattern Detection

Pull all authentication events from `log-analysis.json` (Event IDs 4624, 4625, 4648, 4776). Analyze credential usage patterns:

1. **Credential velocity**: For each account appearing in successful logon events, compute:
   - Number of distinct target systems (by hostname/IP)
   - Time span from first to last logon
   - Velocity = distinct systems / time span (minutes)
   - **Flag if velocity > 3 systems/minute** — humans cannot authenticate to 3+ systems per minute manually

2. **Parallel credential detection**: Identify cases where the same account has overlapping authentication sessions — logon events within 5 seconds of each other on different target systems. Humans authenticate sequentially; parallel authentication indicates programmatic credential use.

3. **Logon type consistency**: For each account moving laterally, compute the distribution of logon types. If 100% of logons are type 3 (network) with zero interactive (type 2) or RDP (type 10) logons, the access is programmatic — no human sat at a console or RDP session.

4. **Authentication regularity**: Compute inter-authentication intervals for accounts showing lateral movement. If intervals show CV < 0.15 (mechanical regularity), the credential use is automated.

**Scoring**: `credential_automation_score` (0.0–1.0):
- No lateral movement → 0.0
- Velocity > 3/min alone → 0.4
- Velocity + parallel auth → 0.6
- All four indicators → 1.0

#### 3.3 Legitimate Tool Sequence Analysis (LOLBin Chaining)

Pull process creation events from `log-analysis.json` (Event ID 4688, Sysmon ID 1), `memory-analysis.json` (cmdline output), and `timeline-reconstruction.json`. Analyze for living-off-the-land binary chains:

1. **Known suspicious chains**: Identify sequences of legitimate tool executions that, individually, are benign but in sequence indicate adversary activity:
   - `certutil -decode` → `regsvr32 /s` → `rundll32` (download + register + execute)
   - `mshta` → `powershell -ep bypass` (HTA to PowerShell execution)
   - `bitsadmin /transfer` → execution of downloaded file (download + execute)
   - `wmic process call create` chained across commands (remote process creation)
   - `rundll32 javascript:` → subsequent execution (script proxy)

2. **Chain velocity**: If a multi-tool chain completes in under 10 seconds, the operator did not manually type each command. Human typing speed for complex commands is ~30 WPM; a 3-command chain takes at minimum 15–20 seconds with human operation.

3. **No interactive shell parent**: LOLBin chains without `explorer.exe` → `cmd.exe` lineage (no user desktop session) suggest programmatic invocation via API, scheduled task, or WMI.

4. **Parent process analysis**: Chains spawned by `wmiprvse.exe`, `wsmprovhost.exe`, or `svchost.exe` suggest remote/API-based execution rather than interactive use.

**Scoring**: `lolbin_chain_score` (0.0–1.0):
- No LOLBin chains → 0.0
- Known chain detected → 0.3
- Chain + sub-10s velocity → 0.6
- Chain + velocity + no interactive parent → 0.9

#### 3.4 API-Based Attack Indicator Analysis

Pull from `memory-analysis.json`, `log-analysis.json`, and `persistence-enumeration.json`. Check for attack patterns that bypass traditional process-creation monitoring:

1. **Execution without process creation**: Evidence of code execution (WMI method invocations via Event ID 5857–5861, DCOM object instantiation, PowerShell remoting via Event 4103/4104 without corresponding 4688) indicates API-driven attacks.

2. **BITS job abuse**: Check for Background Intelligent Transfer Service (BITS) artifacts — BITS transfer jobs can download executables without triggering standard download detection. Look for BITS-Client event log entries (Event ID 60) or `bitsadmin` command lines.

3. **COM object instantiation patterns**: Unusual CLSID references in registry or process handles that map to known execution proxies: `MMC20.Application`, `ShellWindows`, `ShellBrowserWindow`, `Excel.Application`.

4. **Service Control Manager remote abuse**: Remote service creation (Event ID 7045) without corresponding local process creation — indicates SCM API-based remote code execution.

5. **LLM API artifacts** (per GTIG threat intelligence): Search for indicators of AI-tool-assisted attacks in extracted strings, process memory, and network artifacts:
   - API endpoint strings: `api.openai.com`, `generativelanguage.googleapis.com`, `api-inference.huggingface.co`, `api.anthropic.com`
   - API key patterns: `sk-`, `AIza`, `hf_` prefixed tokens in process memory or strings output
   - Known AI malware artifacts: `thinking_robot_log.txt` (PROMPTFLUX), `c:\Programdata\info\` directory structure (PROMPTSTEAL/LAMEHUG)
   - Code generation residue: `[citation:N]` markers, `Return only commands, without markdown` prompt strings
   - HTTP headers: `X-LLM-Enhanced: true`, model identifiers in request bodies

**Scoring**: `api_attack_score` (0.0–1.0):
- No API-based indicators → 0.0
- Execution without process creation → 0.3
- BITS/COM/SCM abuse → 0.5
- LLM API artifacts found → 0.8
- Multiple API indicators + LLM artifacts → 1.0

#### 3.5 Absence-of-Evidence Analysis

For each kill chain phase observed in the attack narrative, check whether the **expected supporting artifacts** are present. AI-driven attacks produce "cleaner" forensic footprints — the AI may know which artifacts each action creates and selectively avoid or clean them.

**Expected Artifact Matrix:**

| Kill Chain Phase Observed | Expected Supporting Artifacts | Absence Signal |
|---|---|---|
| Execution (process creation evidence) | Prefetch file, Amcache entry, shimcache entry | 0/3 present → fileless execution indicator |
| Persistence (registry key found) | Referenced file on disk, MFT entry for file, shimcache for file | Registry → nonexistent file → cleaned or memory-only |
| Lateral movement (logon event) | Source process on origin system, netscan connection in memory | No origin evidence → programmatic credential reuse |
| C2 (network connection found) | DNS resolution event, process with established connection, firewall log | Connection without DNS → hardcoded IP (more sophisticated) |
| Data staging/exfil suspected | File access timestamps, staging directory, clipboard/archive artifacts | No staging → direct memory-to-network exfil |

**Absence ratio**: (expected artifacts − found artifacts) / expected artifacts

- 0.0–0.3: Normal (most artifacts present — typical human-operated attack)
- 0.3–0.6: Elevated absence (some cleanup or fileless techniques)
- 0.6–1.0: Significant absence (sophisticated anti-forensics or AI-level artifact minimization)

**Scoring**: `absence_score` = average absence ratio across all observed kill chain phases

#### 3.6 Decoy Artifact Detection

Pull from `artifact-correlation.json` (if available). Check for evidence that may have been deliberately planted to create a false trail:

1. **Suspiciously high corroboration**: If a single finding has 5+ independent sources all supporting it, it may be a planted decoy. Real attacks rarely leave evidence in 5+ independent locations. An AI adversary can deliberately plant artifacts across multiple evidence sources to create a convincing but false trail. Record these in `decoy_candidates`.

2. **Too-perfect evidence chains**: A complete kill chain with Tier 2 corroboration at every phase AND zero contradictions AND zero gaps is statistically unusual. Real incidents are messy — contradictions, gaps, and orphan findings are expected. If the attack narrative has zero unexplained artifacts: flag as anomalous.

3. **Null hypothesis contradiction pattern**: If every piece of evidence is inconsistent with H4 (legitimate activity) with no ambiguous items, the evidence may be constructed to look obviously malicious. Real attacks almost always have some evidence that could go either way.

4. **Loud + quiet co-occurrence**: Check if there is a "loud" attack path (many artifacts, obvious IOCs, clear trail) alongside a "quiet" signal (few artifacts, subtle indicators). The loud path may be a decoy while the real attack proceeds through the quiet channel.

**Scoring**: `decoy_score` (0.0–1.0):
- No decoy indicators → 0.0
- High corroboration on 1+ findings → 0.2
- Too-perfect + high corroboration → 0.5
- Too-perfect + high corroboration + null-hypothesis pattern → 0.8

#### 3.7 Composite AI-Adversary Assessment

Combine the six scores with weights reflecting their diagnostic reliability:

| Lens | Weight | Rationale |
|------|--------|-----------|
| Temporal anomaly | 0.25 | Most directly measurable; hardest for AI to disguise |
| Credential automation | 0.20 | Strong discriminator between human and automated lateral movement |
| LOLBin chaining | 0.15 | Suggestive but also used by sophisticated human operators |
| API-based attack | 0.15 | High specificity when LLM artifacts found; lower without |
| Absence-of-evidence | 0.15 | Novel analytical lens; less validated but high theoretical value |
| Decoy indicators | 0.10 | Hardest to assess; highest false positive risk |

**Composite score** = weighted sum → `ai_adversary_likelihood` (0.0–1.0)

**Classification mapping:**
- 0.0–0.2: **None** — No AI-adversary indicators detected
- 0.2–0.4: **Minimal** — Some automation indicators; likely human with scripting
- 0.4–0.6: **Moderate** — Possible AI-assisted attack; warrants further investigation
- 0.6–0.8: **Strong** — Probable AI-driven attack; multiple independent indicators
- 0.8–1.0: **Very Strong** — High-confidence AI adversary; behavior inconsistent with human operation

**Mandatory caveat** (include in ALL non-zero assessments): "This assessment is an analytical framework grounded in published threat intelligence (GTIG, MITRE ATLAS, Arctic Wolf, Unit42), not a deterministic detection. The scoring reflects behavioral patterns statistically associated with AI-driven operations but does not constitute proof. Human operators using sophisticated automation may produce similar patterns. Attribution of AI involvement requires additional evidence beyond forensic artifact analysis."

### 4. ARTIFACT

Write `analysis/ai-adversary-analysis.json` to the case directory:

```json
{
  "technique": "ai-adversary-analysis",
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "input_techniques": ["timeline-reconstruction", "log-analysis", "memory-analysis", "..."],
  "temporal_analysis": {
    "score": 0.0,
    "sub_minute_chains": [],
    "metronomic_clusters": [],
    "sustained_activity": [],
    "parallel_operations": [],
    "details": "..."
  },
  "credential_analysis": {
    "score": 0.0,
    "credential_velocity": [],
    "parallel_auth_events": [],
    "logon_type_consistency": [],
    "auth_regularity": [],
    "details": "..."
  },
  "lolbin_analysis": {
    "score": 0.0,
    "chains_detected": [],
    "chain_velocities": [],
    "parent_analysis": [],
    "details": "..."
  },
  "api_attack_analysis": {
    "score": 0.0,
    "execution_without_process": [],
    "bits_com_scm_abuse": [],
    "llm_api_artifacts": [],
    "details": "..."
  },
  "absence_analysis": {
    "score": 0.0,
    "per_phase_matrix": [
      {
        "kill_chain_phase": "execution",
        "expected_artifacts": ["prefetch", "amcache", "shimcache"],
        "found_artifacts": ["prefetch"],
        "absence_ratio": 0.67,
        "significance": "..."
      }
    ],
    "overall_absence_ratio": 0.0,
    "details": "..."
  },
  "decoy_analysis": {
    "score": 0.0,
    "high_corroboration_findings": [],
    "too_perfect_indicators": [],
    "null_hypothesis_pattern": false,
    "loud_quiet_cooccurrence": false,
    "details": "..."
  },
  "composite_assessment": {
    "ai_adversary_likelihood": 0.0,
    "classification": "none|minimal|moderate|strong|very_strong",
    "confidence": "HIGH|MEDIUM|LOW",
    "caveat": "This assessment is an analytical framework...",
    "component_scores": {
      "temporal": 0.0,
      "credential": 0.0,
      "lolbin": 0.0,
      "api_attack": 0.0,
      "absence": 0.0,
      "decoy": 0.0
    },
    "primary_contributors": [],
    "rationale": "..."
  },
  "threat_intelligence_references": {
    "mitre_atlas": ["AML.T0096", "AML.T0098", "AML.T0099", "AML.T0100", "AML.T0101"],
    "gtig_families": ["PROMPTFLUX", "PROMPTSTEAL", "PROMPTLOCK", "QUIETVAULT", "FRUITSHELL"],
    "data_sources": ["GTIG AI Threat Tracker (Nov 2025)", "MITRE ATLAS v5.4.0 (Feb 2026)", "Arctic Wolf AI Malware Report", "Unit42 AI in Malware"]
  },
  "findings": [
    {
      "finding_id": "AI-001",
      "description": "...",
      "confidence": "HIGH|MEDIUM|LOW",
      "evidence_tier": 2,
      "citation": "..."
    }
  ]
}
```

### 5. FINDINGS

Summarize:
- Composite AI-adversary likelihood score and classification
- Which of the six analytical lenses contributed most (primary contributors)
- Specific high-scoring indicators with evidence citations
- When assessment is "none" (score < 0.2): produce an explicit "No AI-adversary indicators detected" finding — this is a valid and expected result, especially for pre-2025 evidence
- Reference applicable MITRE ATLAS techniques and GTIG malware families

**Layer 1 Self-Check:**
- [ ] Every score backed by specific evidence items from input techniques?
- [ ] Composite score mathematically correct from component scores and weights?
- [ ] Caveat present in all non-zero assessments?
- [ ] "No indicators" finding explicitly produced when composite score < 0.2?
- [ ] All input technique files actually read and referenced?
- [ ] Absence-of-evidence matrix populated with actual artifact checks (not assumed)?
- [ ] LLM API artifact checks actually performed (string searches, not assumed)?
- [ ] Threat intelligence references included?

### 6. HANDOFF

Pass to:
- **self-correction (Layer 3)**: Composite assessment for analytical coherence validation; "too-perfect evidence" check integration
- **hypothesis-testing**: AI-adversary indicators as evidence supporting or refuting H6 (AI-Assisted Attack). **Note**: In v1, ai-adversary and hypothesis-testing both run in Tier 2 (parallel). H6 evaluation uses Phase 2 triage triggers and Tier 1 technique outputs directly. When running `--iterate` with ai-adversary after an initial investigation, hypothesis-testing can read `analysis/ai-adversary-analysis.json` for enriched H6 evaluation.
- **reporting**: AI-Adversary Assessment section in the investigation report

---

## Watch-Outs

- **Automation ≠ AI**: Scripted attacks (bash scripts, Metasploit autopwn, worm propagation) produce similar temporal patterns to AI-driven attacks. The protocol detects non-human operational tempo, not specifically AI. Frame findings as "automated/AI-driven" not "definitely AI."
- **Test evidence will return "no indicators"**: The SRL-2015 and SRL-2018 test datasets are human-generated incidents from before the agentic AI era. "No AI-adversary indicators detected" is the correct finding — this is not a failure of the protocol.
- **Scoring is a framework, not a validated model**: The 0.0–1.0 scores and component weights are analytical heuristics derived from published threat intelligence. They provide structured reasoning, not statistical certainty. The weights should be tuned as more real-world AI-attack forensic data becomes available.
- **Decoy detection is recursive**: If you suspect decoys, the real attack may be elsewhere in the evidence. Flag the suspicion but do not claim to have found the "real" attack without evidence.
- **Absence is a signal, not proof**: Missing artifacts can result from legitimate causes (audit policy gaps, log rollover, evidence collection scope). Always consider alternative explanations for artifact absence before attributing it to AI sophistication.
- **LLM API detection is early-stage**: The GTIG-documented patterns (PROMPTFLUX/PROMPTSTEAL) represent first-generation AI malware that made operational security mistakes (hardcoded API keys, logging prompts). Future AI-enabled malware will be more sophisticated. The indicators in section 3.4 will evolve as the threat landscape matures.
