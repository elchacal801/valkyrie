# Protocol: Log Analysis

> **Phase**: Deep Analysis | **Evidence**: Windows Event Logs (.evtx) | **Produces**: Tier 1 findings
> **Output Artifact**: `analysis/log-analysis.json`
> **MCP Tools**: `list_files()`, `extract_file()`, `generate_timeline()` (evtx parsing)

---

## Purpose

Analyze Windows Event Logs to identify authentication events, process creation, service installations, and other security-relevant activity. Event logs provide timestamped, structured evidence of system activity that complements disk and memory analysis.

---

## Execution

### 1. SETUP

- Read `inventory.json` for event log file paths (.evtx files)
- Read `triage.json` for timeline bounds and known IOCs
- Read `analysis/timeline-reconstruction.json` (if available) for timestamps to focus on
- Identify available log files: Security, System, Application, PowerShell/Operational, Sysmon, TaskScheduler

### 2. PRIME

"I will now analyze Windows Event Logs to identify authentication events, process execution, service changes, and security-relevant activity. Focus is on high-value Event IDs that indicate compromise, lateral movement, or persistence."

### 3. EXECUTE

#### 3.1 Security Log Analysis

Focus on these high-value Event IDs:

**Authentication Events:**
| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 4624 | Successful logon | Check logon type (3=network, 10=RDP), unusual accounts, unusual times |
| 4625 | Failed logon | Brute force indicators, password spraying patterns |
| 4648 | Explicit credentials logon | Credential use with alternate credentials (lateral movement) |
| 4672 | Special privileges assigned | Admin logon indicator |
| 4776 | NTLM credential validation | Pass-the-hash indicators |

**Process & Service Events:**
| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 4688 | Process creation | Suspicious process chains, LOLBins, encoded commands |
| 4697 | Service installed | Persistence via service creation |
| 7045 | Service installed (System log) | Same as 4697, often more reliable |

**Account & Group Changes:**
| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 4720 | User account created | Unauthorized account creation |
| 4732 | Member added to security group | Privilege escalation via group membership |
| 4728 | Member added to global group | Same as above for domain groups |

**Anti-Forensics Indicators:**
| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 1102 | Audit log cleared | Critical anti-forensics indicator |
| 104 | Log cleared (System log) | Same for System/Application logs |

**Network Events:**
| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 5140 | Network share accessed | Lateral movement via SMB |
| 5145 | Detailed share access | File-level access to network shares |
| 5156 | Windows Filtering Platform connection | Network connection details |

#### 3.2 PowerShell Logs (if available)

Check `Microsoft-Windows-PowerShell/Operational.evtx`:
| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 4103 | Module logging | PowerShell commands executed with full text |
| 4104 | Script block logging | Full PowerShell script content (most valuable) |

Flag: base64-encoded commands, `Invoke-Expression`, `DownloadString`, `Invoke-Mimikatz`, `Invoke-WebRequest`

#### 3.3 Sysmon Logs (if available)

Check `Microsoft-Windows-Sysmon/Operational.evtx`:
| Event ID | Meaning | Significance |
|----------|---------|-------------|
| 1 | Process creation | Full command line with hashes |
| 3 | Network connection | Process-level network connections |
| 7 | Image loaded | DLL loading events |
| 8 | CreateRemoteThread | Process injection indicator |
| 11 | File created | File creation with hash |
| 13 | Registry value set | Registry modification |
| 22 | DNS query | DNS lookups by process |

#### 3.4 Pattern Detection

Across all analyzed logs, look for:

1. **Lateral movement patterns**: Logon type 3 (network) from internal IPs, followed by process creation
2. **Brute force patterns**: Multiple 4625 events from the same source in a short time window
3. **Privilege escalation**: 4672 events for non-admin accounts, 4732 events adding users to Administrators
4. **Log gaps**: Missing time ranges that could indicate log clearing between 1102 events
5. **Off-hours activity**: Authentication events outside normal business hours for the organization's timezone

### 4. ARTIFACT

Write `analysis/log-analysis.json`:

```json
{
  "technique": "log-analysis",
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "logs_analyzed": [
    {"name": "Security.evtx", "total_events": 15432, "relevant_events": 87}
  ],
  "authentication_summary": {
    "successful_logons": 234,
    "failed_logons": 12,
    "logon_types": {"3": 150, "10": 20, "2": 64},
    "unusual_logons": [...]
  },
  "process_events": [...],
  "service_installations": [...],
  "account_changes": [...],
  "anti_forensics": [...],
  "patterns_detected": [...],
  "findings": [...]
}
```

### 5. FINDINGS

Summarize: authentication anomalies, suspicious process creation events, service installations, account changes, anti-forensics indicators, and lateral movement patterns.

**Layer 1 Self-Check:**
- [ ] Every Event ID cited actually exists in the referenced log?
- [ ] Timestamps extracted correctly with proper timezone handling?
- [ ] Logon types correctly mapped (2=interactive, 3=network, 10=RDP)?
- [ ] Account names and SIDs consistent across correlated events?
- [ ] Log gaps accurately identified (not just sparse activity periods)?

### 6. HANDOFF

Pass to:
- **artifact-correlation**: Authentication events with timestamps for cross-reference against timeline and memory
- **hypothesis-testing**: Lateral movement and privilege escalation evidence for competing hypotheses
- **timeline-reconstruction**: Event timestamps for consolidated timeline

---

## Watch-Outs

- **Event log rollover**: Older events may have been overwritten by newer events if the log file hit its maximum size. Absence of events in a time range may mean rollover, not clearing.
- **Timezone in event logs**: Windows Event Logs store timestamps in UTC. Ensure consistent timezone handling when correlating with other evidence sources.
- **Logon type confusion**: Type 3 (network) logons are normal for file share access and do not inherently indicate compromise. Focus on type 3 logons from unexpected sources or at unexpected times.
- **4688 without command line**: Process creation auditing must be enabled to capture command lines in Event ID 4688. If command lines are empty, the audit policy was not configured for command-line logging.
- **Log clearing vs. no logging**: Event ID 1102 proves the Security log was cleared. But if audit policies were never enabled, there are simply no events to find — this is not anti-forensics, it's misconfiguration.
