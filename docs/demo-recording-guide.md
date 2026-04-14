# VALKYRIE Demo Video Recording Guide

**Target**: Under 5 minutes. Live terminal screencast with narration showing autonomous execution and self-correction.

---

## Setup (before recording)

### Terminal
- Use a clean terminal with dark background, large font (14-16pt)
- Recommended recorder: **asciinema** (`apt install asciinema`) or **OBS Studio** for full screen capture
- Resolution: 1920x1080 or higher

### Evidence
- Extract a memory dump to a fresh case directory:
  ```bash
  mkdir -p /cases/DEMO-001/evidence
  7z x /path/to/base-wkstn-05-memory.7z -o/cases/DEMO-001/evidence/
  ```

### VALKYRIE
- Ensure install.sh has been run: `cd ~/valkyrie && ./install.sh`
- Verify: `which vol mmls fls yara floss strings`
- Clear any previous case output: `rm -rf /cases/DEMO-001/{analysis,corrections,report,logs,*.json}`

---

## Recording Script (4-5 minutes)

### Segment 1: Introduction (30 seconds)

**Narration**: "VALKYRIE is an autonomous IR agent for SIFT Workstation. It doesn't just run tools — it reasons about evidence using structured analytic techniques from intelligence community doctrine. Let me show you a full investigation."

**On screen**: Show the README briefly, then:
```bash
cd /opt/valkyrie
claude
```

### Segment 2: Launch Investigation (30 seconds)

**Narration**: "I'll run a guided investigation on a Windows 7 memory dump from the SRL-2018 compromised enterprise scenario."

**Type**:
```
/investigate --guided --evidence-path /cases/DEMO-001/evidence/
```

**The agent will display**:
- Investigation banner with case ID
- Step 0: Context inference and assumption validation
- Confirmation prompt → confirm

### Segment 3: Phase 1-2 — Inventory + Triage (60 seconds)

**Narration**: "Phase 1 catalogs evidence and computes SHA256 hashes. Phase 2 runs an initial triage — process listing with psscan and network connections with netscan."

**Let the agent run**. It will:
- Compute SHA256 hash
- Run `analyze_memory(plugin="psscan")` 
- Run `analyze_memory(plugin="netscan")`
- Present triage findings (WMI→PowerShell chains, named pipe connections)

**Key moment to highlight**: "Notice it's using psscan instead of pslist — the agent detected that ISF symbols are missing and automatically fell back to pool scanning."

### Segment 4: Phase 3 — Deep Analysis (60 seconds)

**Narration**: "Phase 3 executes the memory analysis protocol. The agent searches for injected code, encoded PowerShell, and C2 indicators."

**Let the agent run**. It will:
- Extract strings searching for attack patterns
- Find the encoded PowerShell stager
- Find the named pipe `diagsvc-22`
- Find the VirtualAlloc shellcode

**Key moment**: "It just found a Cobalt Strike SMB Beacon communicating over a named pipe. Let's see if it catches the false positives."

### Segment 5: Self-Correction (60 seconds) ← THE MONEY SHOT

**Narration**: "Watch this — the agent initially flagged subject_srv.exe as a suspicious backdoor. But now it's finding contradicting evidence..."

**Let the agent run**. It will:
- Discover Event ID 7045 identifying subject_srv.exe as F-Response
- Reclassify from HIGH-severity backdoor to BENIGN
- Discover PAC file reclassifying 172.16.4.10 from C2 to corporate proxy

**Narration**: "Two false positives caught before they reached the final report. This is what self-correction looks like — not retrying a failed tool, but challenging your own initial assessment when new evidence contradicts it."

### Segment 6: Phase 4-5 — Synthesis + Validation (45 seconds)

**Narration**: "Phase 4 builds the attack narrative and runs Analysis of Competing Hypotheses — evaluating APT, commodity malware, insider threat, legitimate activity, and red team as competing explanations."

**Let the agent run**. It will:
- Build kill chain mapping
- Run ACH (5 hypotheses, diagnosticity matrix)
- Run 3-layer validation (PIDs, timeline, analytical coherence)

### Segment 7: Phase 6 — Report + Wrap-up (30 seconds)

**Narration**: "Phase 6 produces the final report with every finding citing its source tool. Let me show the investigation summary."

**Show the final summary output** with findings table and IOCs.

**Narration**: "19 seconds — VALKYRIE conducted a complete 6-phase forensic investigation with hypothesis testing, self-correction, and a full audit trail. Every finding traces to a specific tool execution. That's VALKYRIE."

**Show the case directory**:
```bash
ls -la /cases/DEMO-001/
cat /cases/DEMO-001/report/investigation-report.md | head -30
```

---

## Post-Recording

1. Trim to under 5 minutes
2. Add title card at start: "VALKYRIE — Autonomous IR Agent | SANS Find Evil! Hackathon 2026"
3. Upload to YouTube (unlisted) or Loom
4. Add link to Devpost submission

## Tips

- **Don't speed up the recording** — judges want to see real execution time
- **Pause briefly** at key moments (self-correction, hypothesis testing) so judges can read
- **If the agent asks for confirmation**, respond quickly — this shows the guided mode interaction
- **If something fails** (vol timeout, etc.), that's fine — show the fallback strategy working
- The self-correction segment is the most important — make sure the before/after reclassification is clearly visible

## Fallback Plan

If the full investigation takes too long for a single recording:
1. Record Phase 1-3 in one take
2. Record Phase 4-6 in a second take
3. Edit together with a brief transition: "Phases 4-6 continue the analysis..."
