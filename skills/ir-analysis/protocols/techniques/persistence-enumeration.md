# Protocol: Persistence Enumeration

> **Phase**: Deep Analysis | **Evidence**: Disk image (registry hives) | **Produces**: Tier 1 findings
> **Output Artifact**: `analysis/persistence-enumeration.json`
> **MCP Tools**: `check_persistence()`, `get_registry_key()`, `list_files()`, `extract_mft()`

---

## Purpose

Systematically enumerate all persistence mechanisms on the system to identify how an attacker maintains access across reboots. This technique checks registry Run keys, services, scheduled tasks, startup folders, and other known persistence locations against known-good baselines.

---

## Execution

### 1. SETUP

- Read `inventory.json` for disk image path and extracted registry hive locations
- Read `triage.json` for known suspicious file paths and IOCs
- Read `analysis/timeline-reconstruction.json` (if available) for timestamps to correlate persistence creation against
- Identify available registry hives: NTUSER.DAT, SOFTWARE, SYSTEM, SAM

### 2. PRIME

"I will now enumerate all persistence mechanisms found in the evidence by systematically checking registry keys, services, scheduled tasks, and startup folders. Each finding will identify the persistence method, its MITRE ATT&CK mapping, and the referenced executable."

### 3. EXECUTE

#### 3.1 Registry-Based Persistence

For each available registry hive, invoke `check_persistence()`:

1. **NTUSER.DAT**: User-level persistence
   - `check_persistence(hive_path, hive_type="ntuser")`
   - Checks: Run, RunOnce, Shell Folders, Winlogon helpers, environment variables

2. **SOFTWARE**: System-wide persistence
   - `check_persistence(hive_path, hive_type="software")`
   - Checks: Run, RunOnce, Policy Run keys, Winlogon, IFEO, App Paths

3. **SYSTEM**: Service and boot persistence
   - `check_persistence(hive_path, hive_type="system")`
   - Checks: Services, BootExecute, KnownDLLs, SecurityProviders, LSA, Print Monitors

4. **SAM**: Account persistence
   - `check_persistence(hive_path, hive_type="sam")`
   - Checks: Local user accounts (new accounts = T1136.001)

#### 3.2 Analyze Found Entries

For each persistence entry found:

1. **Identify the executable**: What file does this persistence mechanism point to?
2. **Verify the executable exists**: Use `list_files()` to check if the referenced file exists in the disk image
3. **Check the executable path**: Is it in a standard location (`C:\Windows\System32\`) or suspicious (`C:\Users\Public\`, `C:\Windows\Temp\`)?
4. **Check creation time**: Use MFT data (if available) to determine when the persistence entry was created. Does the creation time correlate with the incident timeline?
5. **Baseline comparison**: Is this a known Windows default entry, or is it anomalous?

#### 3.3 Filesystem-Based Persistence

Check startup folders via `list_files()`:
- `Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
- `ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`

Check for scheduled tasks:
- `Windows\System32\Tasks\` — enumerate all task XML files
- Look for tasks with suspicious actions (PowerShell, cmd, executables from temp directories)

Check for WMI event subscriptions:
- `Windows\System32\wbem\Repository\` — WMI database files (complex to parse; flag if recently modified)

#### 3.4 Service Analysis

For entries from the SYSTEM hive Services key:
1. Focus on services with `Start` type 2 (Auto) or 3 (Manual) that have unusual binary paths
2. Flag services with:
   - Binary path pointing to `\Temp\`, `\AppData\`, `\Users\Public\`
   - Service DLLs (`ServiceDll` value) in non-standard locations
   - Services created near incident timestamps
   - Services with names mimicking legitimate services

### 4. ARTIFACT

Write `analysis/persistence-enumeration.json`:

```json
{
  "technique": "persistence-enumeration",
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "hives_checked": ["ntuser", "software", "system", "sam"],
  "summary": {
    "total_persistence_locations_checked": 22,
    "locations_with_entries": 8,
    "suspicious_entries": 3,
    "known_good_entries": 15
  },
  "persistence_entries": [
    {
      "entry_id": "PE-001",
      "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "name": "WindowsUpdate",
      "value": "C:\\Users\\Public\\update.exe -silent",
      "hive": "ntuser",
      "mitre_attack": "T1547.001",
      "suspicious": true,
      "suspicious_reasons": ["executable_in_public_folder", "name_mimics_legitimate"],
      "executable_exists": true,
      "executable_created": "<ISO-8601>",
      "citation": "[TOOL: check_persistence, evidence: NTUSER.DAT, key: Run, value: WindowsUpdate]"
    }
  ],
  "findings": [...]
}
```

### 5. FINDINGS

Summarize: total persistence locations checked, suspicious entries found (with MITRE ATT&CK mapping), services of interest, and filesystem-based persistence.

**Layer 1 Self-Check:**
- [ ] Every registry key path cited is valid for the detected Windows version?
- [ ] Every referenced executable was verified to exist (or not) via list_files?
- [ ] MITRE ATT&CK mappings match the actual persistence mechanism?
- [ ] Known-good entries (legitimate Windows defaults) not flagged as suspicious?
- [ ] Service binary paths verified against disk image?

### 6. HANDOFF

Pass to:
- **artifact-correlation**: Suspicious executables and their paths for cross-reference with timeline and memory
- **hypothesis-testing**: Persistence mechanisms as evidence for/against attack hypotheses
- **timeline-reconstruction**: Persistence creation timestamps

---

## Watch-Outs

- **Legitimate persistence is everywhere**: Most Run key entries are legitimate software. Focus on entries with executables in unusual paths, recently created, or with obfuscated names.
- **ControlSet numbering**: The SYSTEM hive has multiple ControlSets (ControlSet001, ControlSet002). Check the `Select\Current` value to identify which ControlSet was active at the time of the incident.
- **Deleted persistence**: An attacker may have created and later removed a persistence mechanism. Check for deleted registry keys (registry transaction logs) or deleted files in startup folders (MFT deleted entries).
- **WMI persistence is hard to parse**: WMI event subscriptions are stored in a binary database format. Flag recently modified WMI repository files rather than attempting to parse the binary format.
