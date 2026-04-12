# Evidence Collector Protocol

Inventory, validate, and catalog all forensic evidence before analysis begins. This protocol runs during Phase 1 of the investigation pipeline.

---

## Purpose

Create a complete, hash-verified inventory of all available evidence. This inventory drives technique selection and provides the ground truth that Layer 1 self-correction validates against.

---

## Execution

### Step 1 — Locate Evidence

1. Determine the evidence path:
   - If `--evidence-path` was provided: use that path
   - If `VALKYRIE_EVIDENCE_PATH` environment variable is set: use that
   - Otherwise: scan common locations:
     - `/cases/<CASE-ID>/evidence/`
     - `/mnt/evidence/`
     - Current directory
   - If no evidence found: halt and ask the user for the path

2. Verify the path exists and is accessible
3. Check mount status: is the evidence mounted read-only? Log the mount flags.

### Step 2 — Scan and Classify Evidence Files

For each file in the evidence directory (recursive scan):

1. Record: file path, file name, file size, file type (via `file` command or extension mapping)
2. Classify by evidence type:

| Pattern | Evidence Type | Classification |
|---------|--------------|----------------|
| `.E01`, `.Ex01` | EnCase image | `disk_image` |
| `.raw`, `.dd`, `.img` (large, >100MB) | Raw disk image | `disk_image` |
| `.vmdk` | VMware disk | `disk_image` |
| `.raw`, `.vmem`, `.lime`, `.dmp` (memory signature) | Memory dump | `memory_dump` |
| `.evtx` | Windows Event Log | `event_log` |
| `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` | Registry hive | `registry_hive` |
| `.pcap`, `.pcapng` | Network capture | `network_capture` |
| `.prefetch`, `.pf` | Prefetch files | `prefetch` |
| Other | Unknown | `other` |

**Memory vs. Disk Disambiguation**: `.raw` files can be either disk images or memory dumps. Distinguish by:
- File size: memory dumps are typically 1-64 GB, disk images can be any size
- File signature: memory dumps may start with specific patterns (e.g., `LIME` header for LiME format)
- If ambiguous, classify as `unknown` and ask the user

### Step 3 — Compute Integrity Hashes

For each evidence file:

1. Compute SHA256 hash: `sha256sum <file>`
2. Record the hash in the inventory
3. For EnCase images (.E01): also run `ewfverify` if available to validate the image integrity

**Important**: Hash computation runs BEFORE any analysis tool touches the evidence. This establishes the integrity baseline.

### Step 4 — Build Inventory

Write `inventory.json` to the case directory:

```json
{
  "case_id": "<CASE-ID>",
  "evidence_path": "/cases/CASE-001/evidence/",
  "scan_timestamp": "2026-04-15T10:00:00Z",
  "mount_read_only": true,
  "files": [
    {
      "path": "/cases/CASE-001/evidence/disk.E01",
      "name": "disk.E01",
      "size_bytes": 10737418240,
      "size_human": "10.0 GB",
      "type": "disk_image",
      "format": "EnCase",
      "sha256": "abc123...",
      "ewf_verified": true
    },
    {
      "path": "/cases/CASE-001/evidence/memory.raw",
      "name": "memory.raw",
      "size_bytes": 4294967296,
      "size_human": "4.0 GB",
      "type": "memory_dump",
      "format": "raw",
      "sha256": "def456..."
    }
  ],
  "summary": {
    "total_files": 5,
    "total_size_bytes": 16106127360,
    "total_size_human": "15.0 GB",
    "evidence_types": ["disk_image", "memory_dump", "event_log"],
    "disk_images": 1,
    "memory_dumps": 1,
    "event_logs": 3,
    "registry_hives": 0,
    "network_captures": 0,
    "other": 0
  }
}
```

### Step 5 — Report to Orchestrator

Present the inventory to the user:

```
## Evidence Inventory Complete

**Evidence path**: /cases/CASE-001/evidence/ (mounted read-only: YES)
**Total files**: 5 (15.0 GB)

| # | File | Type | Size | SHA256 (first 16) |
|---|------|------|------|--------------------|
| 1 | disk.E01 | Disk image (EnCase) | 10.0 GB | abc123def456... |
| 2 | memory.raw | Memory dump | 4.0 GB | 789abc012def... |
| 3 | Security.evtx | Event log | 128 MB | ... |
| 4 | System.evtx | Event log | 64 MB | ... |
| 5 | Application.evtx | Event log | 32 MB | ... |

**Evidence types detected**: disk image, memory dump, event logs
**Integrity**: All hashes computed. EnCase image verified.
```

---

## Integrity Gate

After inventory, run these checks before proceeding to Triage:

### Hard Checks (HALT if failed)

| Check | Threshold | Action on Failure |
|-------|-----------|-------------------|
| **Evidence exists** | At least 1 file classified as disk_image, memory_dump, or event_log | Halt: "No analyzable evidence found at {{PATH}}. Provide the correct evidence path." |
| **Hash computed** | SHA256 computed for all files | Halt: "Could not compute hash for {{FILE}}. Evidence may be corrupted or inaccessible." |
| **Evidence accessible** | All files readable | Halt: "Cannot read {{FILE}}. Check permissions and mount status." |

### Soft Checks (WARN and proceed)

| Check | Threshold | Warning |
|-------|-----------|---------|
| **Multiple evidence types** | 2+ distinct types | "Only one evidence type available ({{TYPE}}). Cross-correlation will be limited." |
| **Reasonable file size** | Disk image > 100 MB, memory dump > 256 MB | "{{FILE}} is unusually small ({{SIZE}}). It may be truncated or incomplete." |
| **Read-only mount** | Evidence on read-only mount | "Evidence is NOT mounted read-only. Recommend: `mount -o remount,ro {{PATH}}`" |

### Gate Result

```
## Integrity Gate
- Evidence exists: PASS (3 analyzable files)
- Hashes computed: PASS (5/5)
- Evidence accessible: PASS
- Multiple types: PASS (disk + memory + logs)
- File sizes: PASS
- Read-only mount: PASS

Gate result: PROCEED
```

If any hard check fails, halt and surface to the user. If only soft checks fail, log warnings and proceed.
