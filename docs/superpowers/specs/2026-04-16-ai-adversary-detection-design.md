# Design Spec: AI-Adversary Detection for VALKYRIE

**Date**: 2026-04-16
**Status**: Implemented (v1)
**Author**: VALKYRIE Development Team

---

## Problem Statement

Frontier AI models (Anthropic Mythos, OpenAI Spud, Grok Build, open-source variants) are being weaponized for offensive cyber operations. Google GTIG has documented active AI-enabled malware families in the wild. MITRE ATLAS v5.4.0 added agent-specific attack techniques. VALKYRIE's existing 7 technique protocols assume human-speed operations and known TTP patterns, creating blind spots for AI-driven attacks.

## Threat Landscape Basis

This design is grounded in published threat intelligence, not theoretical patterns:

### Real-World AI Malware Families (GTIG AI Threat Tracker, Nov 2025)

| Family | Type | AI Integration | Key Artifacts |
|--------|------|---------------|---------------|
| **PROMPTFLUX** | VBScript dropper | Queries Gemini API hourly for obfuscation code ("Thinking Robot" module) | `%TEMP%\thinking_robot_log.txt`, hardcoded Gemini API key, Startup folder persistence |
| **PROMPTSTEAL/LAMEHUG** | Python data miner (APT28) | Uses Hugging Face API (Qwen2.5-Coder LLM) for dynamic command generation | `c:\Programdata\info\` directory, Hugging Face API tokens, system enumeration output |
| **PROMPTLOCK** | Go ransomware | Runtime Lua script generation via LLM | Cross-platform, dynamic script generation |
| **QUIETVAULT** | JS credential stealer | Leverages on-host AI CLI tools for secret discovery | GitHub repo creation for exfil, env var access |
| **FRUITSHELL** | PowerShell reverse shell | Hard-coded prompts to confuse LLM-based security analysis | Anti-LLM-detection prompt strings |

### MITRE ATLAS v5.4.0 Agent-Specific Techniques (Feb 2026)

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| AML.T0096 | AI Service API | Living-off-the-land via AI APIs for C2 |
| AML.T0098 | AI Agent Tool Credential Harvesting | Autonomous credential extraction |
| AML.T0099 | AI Agent Tool Data Poisoning | Prompt injection via data sources |
| AML.T0100 | AI Agent Clickbait | Luring agents into unintended actions |
| AML.T0101 | Data Destruction via AI Agent Tool | Leveraging agent capabilities for destruction |

### Detection Indicators (Arctic Wolf, Unit42)

- **YARA categories**: `AI_Gen_EmojiInCode_Batch` (30%), `AI_Gen_PyInstallerLLMPayload_Python` (18%), `AI_Gen_LLMApiAbuse_MultiPlatform` (8%), `AI_Gen_HardcodedLLM_APIKeys` (7%)
- **Code artifacts**: `[citation:N]` markers, emoji in code, verbose tutorial comments, Markdown headers in binaries
- **API patterns**: Runtime LLM API integration (~8% of samples), hardcoded LLM API keys (~7%)

### Mythos/Spud Capabilities (April 2026)

- Autonomous zero-day discovery across major OS and browser codebases
- Exploit chaining without human direction at each step
- Sub-minute vulnerability identification and exploitation
- Unexpected autonomous behaviors during safety testing

## Design Decisions

1. **Tier 2 placement**: The ai-adversary technique is a Correlation-phase technique (like artifact-correlation and hypothesis-testing) because it requires cross-technique pattern analysis
2. **Six analytical lenses**: Behavioral entropy, credential automation, LOLBin chaining, API-based attacks, absence-of-evidence, and decoy detection
3. **Composite scoring framework**: Weighted 0.0-1.0 scores with explicit caveats about analytical vs. statistical certainty
4. **Graceful degradation**: Protocol produces valid "no indicators" output for pre-AI-era evidence
5. **H6 hypothesis**: Added to ACH matrix with 10 diagnostic criteria (5 consistent, 5 inconsistent with AI-assisted attack)
6. **Real-world grounding**: Every analytical lens references published threat intelligence

## Architecture

### Files Modified

| File | Change |
|------|--------|
| `protocols/techniques/ai-adversary-analysis.md` | **NEW** — 8th technique protocol |
| `protocols/techniques/timeline-reconstruction.md` | Added section 3.5: AI-Adversary Temporal Indicators |
| `protocols/techniques/memory-analysis.md` | Added section 3.5: Legitimate Service Abuse & AI-Tool Detection |
| `protocols/techniques/artifact-correlation.md` | Added sections 3.6-3.7: Decoy Detection, Absence-of-Evidence |
| `protocols/techniques/hypothesis-testing.md` | Added H6 hypothesis + section 3.6: AI-Adversary Evaluation |
| `protocols/techniques/persistence-enumeration.md` | Added section 3.4: Advanced Persistence Mechanisms |
| `protocols/techniques/log-analysis.md` | Added section 3.5: Credential Frequency & Automation Analysis |
| `protocols/techniques/malware-triage.md` | Added section 3.6: AI-Generated Payload Indicators |
| `protocols/self-correction.md` | Added Layer 3.7: Too-Perfect Evidence Detection |
| `protocols/orchestrator.md` | Added ai-adversary routing, tier assignment, auto-selection triggers |
| `templates/investigation-report.md` | Added AI-Adversary Assessment section |
| `SKILL.md` | Added `ai-adversary` to technique list |

### Data Flow

```
Tier 1 Techniques (parallel)
  timeline → temporal indicators (ai_tempo anomalies)
  memory → LLM API artifacts, service abuse indicators
  persistence → advanced persistence (COM, DLL, WMI, env var)
  logs → credential automation patterns
  malware → AI-generated payload indicators
       ↓
Tier 2 Techniques (parallel, after Tier 1)
  correlation → decoy candidates + absence indicators
  hypothesis → H6 diagnostic evaluation
  ai-adversary → 6-lens composite assessment (0.0-1.0)
       ↓
Self-Correction (Layer 3.7)
  → too-perfect evidence check
       ↓
Report
  → AI-Adversary Assessment section
```

## References

- [GTIG AI Threat Tracker](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools)
- [Arctic Wolf AI Malware Report](https://arcticwolf.com/resources/blog/the-ai-malware-surge-behavior-attribution-and-defensive-readiness/)
- [Unit42 AI in Malware](https://unit42.paloaltonetworks.com/ai-use-in-malware/)
- [MITRE ATLAS v5.4.0](https://atlas.mitre.org/)
- [Zenity MITRE ATLAS Agent Techniques](https://zenity.io/blog/current-events/mitre-atlas-ai-security)
- [Barracuda Agentic AI Threats](https://blog.barracuda.com/2026/02/27/agentic-ai--the-2026-threat-multiplier-reshaping-cyberattacks)
- [CFR Mythos Analysis](https://www.cfr.org/articles/six-reasons-claude-mythos-is-an-inflection-point-for-ai-and-global-security)
- [Fortune: AI-Driven Cybersecurity Risks](https://fortune.com/2026/04/10/anthropic-mythos-ai-driven-cybersecurity-risks-already-here/)
