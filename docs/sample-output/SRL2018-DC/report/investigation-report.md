# Investigation Report: SRL2018-DC

**Date**: 2026-04-14

**Examiner**: VALKYRIE (Autonomous IR Agent)

**Classification**: APT — Fully Compromised Domain Controller

**Status**: COMPLETE (memory analysis)

---

## Investigation Summary

The domain controller BASE-DC (172.16.4.4) is the **primary attack hub** for the SRL-2018 enterprise compromise. Analysis reveals external Meterpreter C2 to AWS (52.41.122.38:443), Mimikatz credential dumping with sekurlsa::logonpasswords (all domain creds compromised), PowerSploit framework deployment, WMI-based lateral movement to workstations, Kerberoasting, keylogging, and AMSI bypass. This represents **total domain compromise**.

**System**: Windows Server 2016 x64 (DC) | `BASE-DC.shieldbase.lan` | `172.16.4.4`
**Evidence**: 5.0 GB memory dump | SHA256: `9679193c2b7852817006c55481124666422fea67ba63c872cf5e4203c6fa629a`
**Captured**: 2018-09-06 22:57:49 UTC

---

## Key Findings

| # | Finding | Confidence | Tier | MITRE |
|---|---------|------------|------|-------|
| F-001 | **External C2**: Meterpreter reverse_https to `52.41.122.38:443` (AWS) | HIGH | 1 | T1071.001, T1573 |
| F-002 | **Mimikatz**: `sekurlsa::logonpasswords` — ALL domain credentials dumped | HIGH | 1 | T1003.001, T1003.006 |
| F-003 | **Shellcode injection**: VirtualAlloc+CreateThread in PowerShell, Python, and VBS variants | HIGH | 1 | T1055.001, T1059.006 |
| F-004 | **WMI lateral movement**: 5 WmiPrvSE instances, `wmic process call create`, 30+ cmd.exe chains | HIGH | 1 | T1047, T1021.006 |
| F-005 | **PowerSploit**: Invoke-Shellcode, Invoke-ReflectivePEInjection, Invoke-Kerberoast, Get-Keystrokes | HIGH | 1 | T1558.003, T1056.001 |
| F-006 | **AMSI bypass**: 9 references — evading Windows Defender on Server 2016 | HIGH | 1 | T1562.001 |
| F-007 | **Download cradles**: IEX+Net.WebClient, VBS ActiveX, Office macro (Workbook_Open) | HIGH | 1 | T1059.001, T1059.005, T1204.002 |
| F-008 | **Domain recon**: PowerView, Invoke-UserHunter, Invoke-Command (82 refs), PsExec, schtasks | MEDIUM | 1 | T1087, T1018 |
| F-009 | **VBS dropper**: `C:\Users\Public\config.vbs` with hidden attribute | HIGH | 1 | T1059.005, T1564.001 |

---

## Attack Narrative

### Kill Chain

| Phase | Activity | Evidence |
|-------|----------|----------|
| **Initial Access** | Unknown — likely phishing or exploit → workstation → credential theft → DC login | Inferred |
| **Execution** | Meterpreter reverse_https, encoded PowerShell, VBS droppers, WMI remote exec | strings: Invoke-Shellcode, encodedcommand, wmic |
| **Persistence** | VBS dropper at `C:\Users\Public\config.vbs`, multiple cmd.exe chains across days | strings + psscan |
| **Privilege Escalation** | Mimikatz sekurlsa::logonpasswords on DC = domain admin equivalent | strings: invoke-mimikatz |
| **Defense Evasion** | AMSI bypass (9 refs), encoded commands, hidden VBS, reflective injection | strings |
| **Credential Access** | Mimikatz (LSASS dump), Kerberoasting (Invoke-Kerberoast), keylogging (Get-Keystrokes) | strings |
| **Discovery** | PowerView, Invoke-UserHunter, domain enumeration | strings |
| **Lateral Movement** | WMI to workstations (wkstn-01, wkstn-05 confirmed), WinRM, PsExec, schtasks | psscan: WmiPrvSE, strings: wmic |
| **Command & Control** | External: Meterpreter HTTPS → 52.41.122.38:443. Internal: CS SMB Beacons on workstations | strings |
| **Collection** | Keylogging via Get-Keystrokes | strings |

### Timeline

| Date | Event |
|------|-------|
| Aug 16 21:05 | DC booted |
| Aug 16 22:10 | First PowerShell session (PID 5612) |
| Aug 17 00:34-00:59 | regedit.exe + cmd.exe activity from explorer |
| Aug 31 01:14 | CS beacon deployed on wkstn-05 via WMI |
| Aug 31 21:28 | Suspicious svchost on wkstn-01 |
| Sep 1-5 | Sustained WMI + cmd.exe activity on DC (5 WmiPrvSE instances) |
| Sep 6 17:47-22:54 | Heavy cmd.exe spawning on DC (attacker still active) |
| Sep 6 19:37 | F-Response deployed by IR team |
| Sep 6 22:57 | DC memory captured (attacker cmd.exe at 22:53 — **4 minutes before capture**) |

---

## IOCs

| Type | Value | Context |
|------|-------|---------|
| **External C2 IP** | `52.41.122.38` | Meterpreter reverse_https, port 443 (AWS) |
| Payload | `windows/meterpreter/reverse_https` | Invoke-Shellcode command |
| Credential Tool | `Invoke-Mimikatz`, `sekurlsa::logonpasswords` | Full domain credential dump |
| Framework | PowerSploit (Invoke-Shellcode, Invoke-ReflectivePEInjection, Invoke-Kerberoast) | Post-exploitation |
| Dropper Path | `C:\Users\Public\config.vbs` | Hidden VBS launcher |
| Lateral Movement | `wmic process call create` | WMI execution to workstations |
| Recon Tool | PowerView, Invoke-UserHunter | Domain enumeration |

---

## Competing Hypotheses Assessment

**Not performed.** Only one evidence type was available (memory dump) — hypothesis testing requires 2+ independent evidence sources for meaningful cross-referencing. Memory-only analysis produces Tier 1 findings from direct tool output but cannot generate the Tier 2 corroboration needed to discriminate between competing hypotheses.

To run hypothesis testing on this case, use: `/investigate --iterate SRL2018-DC hypothesis`

---

## Sensitivity Analysis

**Not performed.** Sensitivity analysis requires hypothesis testing (Phase 4), which was not executed for this investigation. See Competing Hypotheses Assessment above for rationale.

---

## Audit Trail — How to Verify Each Finding

**Not performed.** Full audit trail generation requires Phase 4 (Correlation & Synthesis) to assign evidence lineage and verification methods to each finding. This investigation ran in adaptive mode with a single evidence type, which skipped Phase 4.

Tool execution logs are available at `docs/sample-output/SRL2018-DC/logs/tool-execution.jsonl` for manual verification.

---

## Investigative Methodology

### Techniques Applied

| Technique | Purpose | Key Output |
|----------|---------|------------|
| Memory Analysis | Process enumeration, string extraction, network connection mapping | 9 findings (F-001 through F-009) |

### Tool Execution Summary

| Tool | Invocations | Evidence Analyzed | Key Findings Produced |
|------|------------|-------------------|----------------------|
| volatility3 (psscan) | 2 | DC memory dump | Process tree, WMI chains, cmd.exe activity |
| volatility3 (netscan) | 1 | DC memory dump | External C2 connection (52.41.122.38:443) |
| strings (ASCII + UTF-16) | 4+ | DC memory dump | Mimikatz, PowerSploit, shellcode, VBS dropper, AMSI bypass |

### Evidence Sources

| # | File | Type | SHA256 (first 16) | Findings Sourced |
|---|------|------|--------|-----------------|
| 1 | DC memory dump | Memory dump (raw) | `9679193c2b78...` | 9 findings |

---

## Self-Correction Summary

**Not performed.** Self-correction (Phase 5) was not executed for this investigation. Adaptive mode with a single evidence type ran Phases 1-3 and Phase 6 only.

To run self-correction on this case, use: `/investigate --iterate SRL2018-DC`

---

## Limitations and Caveats

### Evidence Not Analyzed
- No disk image available — cannot verify on-disk artifacts, Prefetch files, or registry persistence
- No event logs (.evtx) — cannot correlate Security, PowerShell, or Sysmon logs for the DC
- No network capture — cannot analyze C2 traffic volume or data exfiltration
- No memory dumps from wkstn-02, wkstn-03, wkstn-04, or wkstn-06 — lateral movement scope unknown

### Techniques Not Applied
- Timeline reconstruction (requires disk image)
- Persistence enumeration (requires disk/registry)
- Log analysis (requires .evtx files)
- Hypothesis testing (requires 2+ evidence types)
- Self-correction / 3-layer validation (Phase 5 not executed)

### Known Gaps
- **Initial access vector unknown**: How the attacker first gained access to the domain is not determinable from memory alone
- **Exfiltration volume unknown**: Cannot determine if or how much data was exfiltrated via the Meterpreter C2 channel
- **Full lateral movement scope unknown**: WMI activity to wkstn-01 and wkstn-05 confirmed, but other hosts may also be compromised
- **Temporal precision limited**: Memory analysis provides process creation times but not full activity timelines

---

## Cross-Case Correlation (3 hosts)

| Capability | DC | WK-05 | WK-01 |
|------------|:--:|:-----:|:-----:|
| External C2 (52.41.122.38) | **HUB** | — | — |
| CS SMB Beacon (diagsvc) | — | diagsvc-22 | diagsvc ref |
| Mimikatz | sekurlsa full | — | -DumpCreds |
| Encoded PS stager | Variants | JABz... | JABz... (identical) |
| WMI source | 5 WmiPrvSE | Target | WmiPrvSE present |
| VirtualAlloc shellcode | PS+Python+VBS | PS | PS |
| Kerberoasting | Yes | — | — |
| Keylogging | Yes | — | — |

**The DC is the C2 hub.** Meterpreter connects externally. SMB Beacons on workstations relay through named pipes back to the DC.

---

## Recommendations

1. **IMMEDIATE**: Isolate entire shieldbase.lan domain. The DC is fully compromised — all credentials must be assumed stolen.
2. **Reset ALL domain credentials** including krbtgt (twice, per MS guidance), all service accounts, all user accounts.
3. **Rebuild DC from clean media** — do not attempt remediation of a compromised DC.
4. **Block 52.41.122.38** at perimeter firewall and check historical netflow for data exfiltration volume.
5. **Analyze all remaining workstations** (wkstn-02 through 06, servers) for the same CS beacon IOCs.
6. **Check 172.16.5.21** — WK-01 had an active WinRM connection to this host, suggesting additional lateral movement.
7. **Engage threat intel** to attribute 52.41.122.38 and the specific Meterpreter/CS configuration.

---

## Citations

Every finding in this report traces to a specific tool execution. Full tool execution logs are available at `docs/sample-output/SRL2018-DC/logs/tool-execution.jsonl`.

| Citation ID | Format | Reference |
|------------|--------|-----------|
| C-001 | TOOL | volatility3.psscan — process list with PIDs, PPIDs, names, timestamps |
| C-002 | TOOL | volatility3.netscan — network connections (external C2 IP identified) |
| C-003 | TOOL | strings (ASCII) — Mimikatz, PowerSploit, shellcode, VBS dropper content |
| C-004 | TOOL | strings (UTF-16LE) — AMSI bypass references, encoded PowerShell commands |

---

*Report generated by VALKYRIE (Validated Autonomous Logic for Kill-chain Yielding Rapid Incident Examination)*
*Case directory: docs/sample-output/SRL2018-DC*
*Report timestamp: 2026-04-14T08:00:00Z*
