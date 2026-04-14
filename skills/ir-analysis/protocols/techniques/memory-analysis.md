# Protocol: Memory Analysis

> **Phase**: Deep Analysis | **Evidence**: Memory dump | **Produces**: Tier 1 findings
> **Output Artifact**: `analysis/memory-analysis.json`
> **MCP Tools**: `analyze_memory()` with plugins: pslist, psscan, pstree, netscan, malfind, cmdline, dlllist, handles, envars, svcscan, ldrmodules, vadinfo, banners; `dump_process_memory()`; `extract_strings()`

---

## Purpose

Analyze a volatile memory capture to identify running processes, network connections, injected code, and other runtime artifacts that may not be visible on disk. Memory analysis often reveals fileless malware, process injection, and active C2 channels that disk-only analysis misses.

---

## Execution

### 1. SETUP

- Read `inventory.json` for memory dump file path and size
- Read `triage.json` for any known suspicious PIDs or IOCs from initial triage
- Read `analysis/timeline-reconstruction.json` (if available) for suspicious file paths and timestamps to correlate against

### 2. PRIME

"I will now analyze the memory dump to identify suspicious processes, injected code, active network connections, and other volatile artifacts. Each finding will cite the specific Volatility plugin and memory offset."

### 3. EXECUTE

#### 3.0 Symbol Check (run first)

Invoke `analyze_memory(plugin="banners")` to identify the OS build. The banners plugin works without ISF symbols and reveals the kernel version string. If subsequent plugins return empty results (headers only, 0 data rows), this confirms an ISF symbol mismatch — fall back to pool-scanning plugins as described below.

#### 3.1 Process Enumeration

1. Invoke `analyze_memory(plugin="pslist")` — list all processes with PID, PPID, name, threads, handles, creation time
   - **Fallback**: If pslist returns 0 data rows (empty table with headers only), invoke `analyze_memory(plugin="psscan")` instead. psscan uses pool scanning which works without ISF symbols. Note in findings that psscan was used — it may include terminated processes and lacks some metadata that pslist provides.
2. Invoke `analyze_memory(plugin="pstree")` — hierarchical process tree showing parent-child relationships. Skip if pslist failed (psscan results can be sorted by PPID to approximate the tree).
3. Flag suspicious patterns:
   - **Orphan processes**: Process with a PPID that doesn't exist in pslist (parent terminated or hidden)
   - **Name masquerading**: `svchost.exe` with wrong parent (should be `services.exe`), `lsass.exe` with wrong parent (should be `wininit.exe`), process names with typos (`scvhost.exe`, `svch0st.exe`)
   - **Unusual process chains**: `cmd.exe` or `powershell.exe` spawned by `outlook.exe`, `excel.exe`, `winword.exe`, or `iexplore.exe`
   - **Multiple single-instance processes**: More than one `lsass.exe`, `csrss.exe`, or `smss.exe`
   - **Processes from unusual paths**: Executables running from `\Temp`, `\AppData`, `\Users\Public`, `\ProgramData`

#### 3.2 Command Line Analysis

1. Invoke `analyze_memory(plugin="cmdline")` — extract command lines for all processes
   - **Fallback**: If cmdline returns 0 rows, fall back to `extract_strings(file_path=<dump_path>, min_length=8)` and search for command-line patterns: paths ending in `.exe`, `-EncodedCommand`, `-nop -w hidden`, `IEX`, `Net.WebClient`, etc. Note reduced fidelity: string extraction cannot attribute commands to specific PIDs.
2. Flag suspicious command lines:
   - **Encoded PowerShell**: `-EncodedCommand`, `-e`, base64 strings
   - **Download cradles**: `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`, `Net.WebClient`
   - **Hidden execution**: `-WindowStyle Hidden`, `-NonInteractive`, `-NoProfile`
   - **LOLBins usage**: `certutil -decode`, `bitsadmin /transfer`, `mshta`, `regsvr32 /s /n /u /i:`
   - **Reconnaissance**: `whoami`, `ipconfig`, `systeminfo`, `net user`, `net group`, `nltest`

#### 3.3 Injected Code Detection

1. Invoke `analyze_memory(plugin="malfind")` — detect potentially injected code regions
   - **Fallback**: If malfind returns 0 rows, invoke `analyze_memory(plugin="vadinfo", pid=<PID>)` on suspect PIDs to manually inspect VAD entries for `PAGE_EXECUTE_READWRITE` regions. Also use `dump_process_memory()` to extract suspect process memory for FLOSS/strings analysis.
2. For each result, assess:
   - **MZ header present**: PE file injected into another process (process hollowing or injection)
   - **RWX memory pages** (`PAGE_EXECUTE_READWRITE`): Writable and executable memory — common for shellcode
   - **False positive indicators**: .NET JIT compilation, legitimate DLLs, Chrome V8 JIT. Flag but note that these are common benign causes.
3. For high-confidence injections, invoke `analyze_memory(plugin="dlllist", pid=<PID>)` to check loaded DLLs

#### 3.4 Network Connections

1. Invoke `analyze_memory(plugin="netscan")` — extract network connections and listening sockets
2. For each connection:
   - Classify: internal (RFC 1918) vs. external IP
   - Match PID to process name from pslist
   - Flag: processes that shouldn't have network access (e.g., `notepad.exe` connecting externally)
   - Flag: connections to unusual ports (>49151 to external IPs)
   - Flag: established connections to external IPs from system processes
3. Record all external IPs as potential IOCs

#### 3.5 Cross-Reference with Disk Artifacts

For each suspicious process found in memory:
1. Does a matching executable exist on disk? (Check against timeline/MFT if available)
2. Does a Prefetch file exist for this executable? (No Prefetch + running process = possible fileless execution)
3. Does the process have a matching Amcache entry?
4. Does a registry persistence key point to this executable?

Document mismatches — a process running in memory with no disk artifact is a significant finding.

### 4. ARTIFACT

Write `analysis/memory-analysis.json`:

```json
{
  "technique": "memory-analysis",
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "dump_path": "<memory dump path>",
  "process_summary": {
    "total_processes": 85,
    "suspicious_processes": 3,
    "orphan_processes": 1
  },
  "suspicious_processes": [
    {
      "pid": 4832,
      "ppid": 1234,
      "name": "svchost.exe",
      "path": "C:\\Windows\\Temp\\svchost.exe",
      "flags": ["wrong_path", "name_masquerading"],
      "cmdline": "...",
      "creation_time": "<ISO-8601>",
      "citation": "[TOOL: analyze_memory:pslist, evidence: memory.raw, PID: 4832]"
    }
  ],
  "injections_detected": [...],
  "network_connections": {
    "total": 42,
    "external": 5,
    "suspicious": 2,
    "connections": [...]
  },
  "disk_correlation": {
    "processes_with_disk_artifact": 82,
    "processes_without_disk_artifact": 3,
    "fileless_candidates": [...]
  },
  "findings": [...]
}
```

### 5. FINDINGS

Summarize: suspicious process count, injection detections, external connections, fileless execution candidates, and processes that warrant further investigation.

**Layer 1 Self-Check:**
- [ ] Every PID cited actually exists in pslist output?
- [ ] Process names and paths match between pslist and cmdline?
- [ ] Network connection PIDs match processes in pslist?
- [ ] Malfind results filtered for known false positives (.NET JIT)?
- [ ] All findings cite specific plugin, PID, and offset?

### 6. HANDOFF

Pass to:
- **artifact-correlation**: Suspicious PIDs and file paths for disk cross-reference
- **hypothesis-testing**: Process anomalies and network connections as evidence
- **timeline-reconstruction**: Process creation timestamps for timeline alignment

---

## Watch-Outs

- **Process hollowing**: A legitimate process name at a legitimate path, but with injected code replacing the original executable in memory. Malfind detects the injected code, but pslist shows a normal-looking process.
- **.NET false positives in malfind**: .NET processes legitimately have RWX regions from JIT compilation. Check if the process is a known .NET application before flagging.
- **SMSS/CSRSS session isolation**: There should be one SMSS and one CSRSS per Windows session (session 0 + session 1 at minimum). Multiple instances are normal in multi-session environments.
- **Memory dump timing**: The memory dump captures a single point in time. A process that was running during the incident may have terminated before the dump was captured.
