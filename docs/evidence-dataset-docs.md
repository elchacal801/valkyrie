# Evidence Dataset Documentation

## Overview

VALKYRIE was tested against the SRL-2018 Compromised Enterprise Network dataset — memory dumps from three hosts in a domain compromised by an APT actor using Cobalt Strike, Mimikatz, and PowerSploit.

---

## Dataset: SRL-2018 Compromised Enterprise Network

| Field | Value |
|-------|-------|
| **Source** | [SANS Find Evil! Hackathon Starter Data](https://sansorg.egnyte.com/fl/HhH7crTYT4JK) |
| **Scenario** | APT attack on `shieldbase.lan` enterprise domain |
| **Evidence Type** | Memory dumps (raw, captured with dc3dd) |
| **Hosts Analyzed** | 3 of 20 available (DC, workstation-01, workstation-05) |
| **Total Evidence Size** | 11.0 GB (3.0 GB + 3.0 GB + 5.0 GB) |

### Evidence Files

| # | File | Host | OS | Size | SHA256 |
|---|------|------|----|------|--------|
| 1 | base-wkstn-05-memory.img | BASE-WKSTN-05 (172.16.7.15) | Windows 7 SP1 x64 | 3.0 GB | `74ff679b25727d5f...` |
| 2 | base-wkstn-01-memory.img | BASE-WKSTN-01 (172.16.7.11) | Windows 10 x64 | 3.0 GB | `e52f84eca8703c30...` |
| 3 | base-dc-memory.img | BASE-DC (172.16.4.4) | Windows Server 2016 x64 | 5.0 GB | `9679193c2b785281...` |

---

## Investigation Results

### Case TEST-001: Workstation 05 (Full 6-Phase Pipeline)

| # | Finding | Confidence | Tier | Correct? |
|---|---------|------------|------|----------|
| F-001 | Cobalt Strike SMB Beacon via WMI, named pipe `diagsvc-22` | HIGH | 1 | YES |
| F-002 | Post-exploitation via 5 rundll32.exe injections | HIGH | 1 | YES |
| F-003 | Orphaned rundll32 PID 7100 (6+ day persistence) | MEDIUM | 1 | YES |
| F-004 | AV evasion (McAfee + Sysmon active, attack succeeded) | MEDIUM | 3 | YES |
| HT-001 | ACH: Targeted APT most plausible (0 inconsistencies) | HIGH | 3 | YES |

**Self-Corrections**:

| # | Layer | Issue | Resolution |
|---|-------|-------|------------|
| 1 | In-flight | subject_srv.exe flagged as backdoor | Reclassified as F-Response forensic agent (Event ID 7045) |
| 2 | In-flight | 172.16.4.10:8080 flagged as C2 | Reclassified as corporate web proxy (PAC file found) |

### Case SRL2018-DC: Domain Controller

| # | Finding | Confidence | Tier | Correct? |
|---|---------|------------|------|----------|
| F-001 | External C2: Meterpreter reverse_https to 52.41.122.38:443 | HIGH | 1 | YES |
| F-002 | Mimikatz sekurlsa::logonpasswords (full domain cred dump) | HIGH | 1 | YES |
| F-003 | VirtualAlloc shellcode (PowerShell + Python + VBS variants) | HIGH | 1 | YES |
| F-004 | WMI lateral movement (5 WmiPrvSE, 30+ cmd.exe) | HIGH | 1 | YES |
| F-005 | PowerSploit (Kerberoast, Keystrokes, ReflectivePEInjection) | HIGH | 1 | YES |
| F-006 | AMSI bypass (9 references) | HIGH | 1 | YES |
| F-007 | IEX download cradles + VBS/macro droppers | HIGH | 1 | YES |
| F-008 | Domain recon (PowerView, Invoke-UserHunter, PsExec) | MEDIUM | 1 | YES |
| F-009 | VBS dropper at C:\Users\Public\config.vbs (hidden) | HIGH | 1 | YES |

### Case SRL2018-WK01: Workstation 01

| # | Finding | Confidence | Tier | Correct? |
|---|---------|------------|------|----------|
| F-001 | Identical Cobalt Strike stager as wkstn-05 | HIGH | 1 | YES |
| F-002 | Invoke-Mimikatz -DumpCreds | HIGH | 1 | YES |
| F-003 | Outbound WinRM pivot to 172.16.5.21:5985 | HIGH | 1 | YES |
| F-004 | Suspicious late svchost PID 10552 (Aug 31, same date as attack) | MEDIUM | 1 | YES |
| F-005 | Attack processes exited before capture (strings remain) | MEDIUM | 3 | YES |

### Cross-Host IOC Correlation

| IOC | wkstn-05 | wkstn-01 | DC |
|-----|:--------:|:--------:|:--:|
| CS stager (`JABz...`) | Yes | Identical | Variants |
| Named pipe `diagsvc-22` | Yes | Ref | No |
| Mimikatz | No | -DumpCreds | sekurlsa full |
| VirtualAlloc shellcode | Yes | Yes | Yes (3 variants) |
| External C2 52.41.122.38 | No | No | Yes |
| WMI lateral movement | Target | Present | Source |

---

## Reproducibility

```bash
# 1. Install VALKYRIE on SIFT Workstation
./install.sh

# 2. Extract evidence from SRL-2018 dataset
mkdir -p /cases/TEST-001/evidence
7z x base-wkstn-05-memory.7z -o/cases/TEST-001/evidence/

# 3. Run the investigation
cd /opt/valkyrie
claude
/investigate --guided --evidence-path /cases/TEST-001/evidence/

# 4. Review results
cat /cases/TEST-001/report/investigation-report.md
cat /cases/TEST-001/corrections/validation-summary.json
cat /cases/TEST-001/logs/tool-execution.jsonl | python3 -m json.tool
```

Evidence integrity: All SHA256 hashes verified unchanged after investigation.
