# Technique: Cloud Log Analysis (Entra ID / Azure / M365)

**Phase**: Deep Analysis | **Evidence**: cloud log exports | **Produces**: Tier 1 findings
**Output**: `analysis/cloud-log-analysis.json` | **MCP tool**: `analyze_cloud_logs`

Modern intrusions increasingly never touch a host disk — the attacker lives in the
identity plane (token theft, OAuth abuse, BEC). This technique analyzes Entra ID
sign-in/audit logs, Azure activity logs, and the Microsoft 365 Unified Audit Log for
those behaviours and maps them to **MITRE ATT&CK for Cloud**.

---

## SETUP

1. Read `inventory.json`; collect files classified as `cloud_log`
   (`.json`/`.ndjson`/`.csv` Entra/Azure/M365 exports).
2. Read `triage.json` for the incident window and any known accounts/IPs.

## PRIME

> "I will analyze cloud identity and control-plane logs for account compromise and
> abuse that leave no host artifact: impossible travel, MFA fatigue, risky/legacy
> sign-ins, password spray, illicit OAuth consent, service-principal secret additions,
> privileged role grants, malicious inbox rules, and mass download. Each finding cites
> the `analyze_cloud_logs` execution that produced it and maps to ATT&CK for Cloud."

## EXECUTE

For each cloud log file, call `analyze_cloud_logs(log_path=<file>)` (the tool
auto-detects type and runs all detectors). Then reason over the structured findings:

- **Initial access / valid accounts (T1078.004)**: impossible travel, risky sign-ins,
  legacy-auth (MFA-bypassing protocols), password spray (T1110.003) / brute force.
- **MFA attacks (T1621)**: repeated MFA challenges/denials (push-bombing) — correlate
  a fatigue burst immediately followed by a success (likely compromise).
- **Persistence / privilege (T1098, T1098.001, T1098.003, T1528, T1550.001)**: illicit
  OAuth consent grants, service-principal credential additions, privileged role
  assignments — these grant standing access that survives a password reset.
- **Collection / exfil (T1114.003, T1564.008, T1530)**: inbox/transport rules
  (auto-forward, hide-replies = BEC) and mass file downloads.

**Cross-reference** (raise to Tier 2 where possible):
- Tie a cloud account compromise to host evidence (same user/host in memory, timeline,
  or sign-in IP appearing in `netscan`).
- Sequence cloud events into the kill chain (spray → success → consent grant → inbox
  rule → download) and check tempo for AI-speed automation (sub-minute transitions).

## ARTIFACT

Write `analysis/cloud-log-analysis.json`:

```json
{
  "technique": "cloud-log-analysis",
  "case_id": "<CASE-ID>",
  "logs_analyzed": [{"path": "...", "type": "entra_signin", "records": 1234}],
  "findings": [
    {
      "finding_id": "CL-001",
      "title": "Impossible travel sign-in",
      "description": "...",
      "confidence": "HIGH",
      "evidence_tier": 1,
      "mitre_attack": ["T1078.004"],
      "iocs": ["<ip>", "<upn>"],
      "citation": "[TOOL: analyze_cloud_logs, exec: <execution_id>, evidence: signins.json, type: entra_signin]"
    }
  ]
}
```

## FINDINGS

Summarize the compromised accounts, the attacker IPs/apps, and the standing-access
mechanisms granted (consent/roles/SP secrets) — these are the remediation priorities
(revoke tokens, remove consent, reset, disable legacy auth).

## HANDOFF

Pass compromised accounts + IPs to `artifact-correlation` (host↔cloud) and
`hypothesis-testing` (H6 AI-adversary: sub-minute cloud kill chains, programmatic
token use). Cloud findings are first-class inputs to the attack narrative.

## Watch-Outs

- **Time zones**: cloud timestamps are UTC; normalize when correlating with host logs.
- **Impossible travel** here is a heuristic (different country within ~1h); a corporate
  VPN/egress can cause false positives — note when the second location is a known egress.
- **Consent grants** can be legitimate admin activity — flag, then check whether the app
  and the grantor are expected (publisher, prior approvals).
- **Service principals legitimately authenticate constantly** — focus on *new* secrets
  and *new* SPs near the incident window.
- The tool is **read-only**; it never modifies the log file or evidence.
