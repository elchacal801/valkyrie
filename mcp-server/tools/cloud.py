"""
VALKYRIE MCP Server — Cloud Log Analysis (Entra ID / Azure / M365)

Parses identity- and cloud-control-plane logs and surfaces the behaviours that
matter for modern, fast-moving (often AI-driven) intrusions where the "C drive"
is never touched:

    * Entra ID sign-in logs        (impossible travel, MFA fatigue, risky/legacy auth, spray)
    * Entra ID audit logs          (illicit OAuth consent, privileged role grants, SP secrets)
    * Azure activity logs          (control-plane role assignments)
    * Microsoft 365 Unified Audit  (inbox-rule creation, mass download)

This tool is **read-only and in-process** — it never shells out and never writes
to the log file. Like every VALKYRIE tool it returns the standard response
envelope with an ``execution_id`` and ``output_sha256`` for audit traceability,
and maps each detection to MITRE ATT&CK for Cloud.

Accepted formats: JSON array, Graph ``{"value": [...]}``, NDJSON, or CSV
(Microsoft 365 UAL ``AuditData`` JSON columns are merged automatically).
"""

from __future__ import annotations

import csv
import io
import json
import os
import time as _time
from collections import defaultdict
from datetime import datetime
from typing import Any

from parsers.common import (
    MAX_OUTPUT_ROWS,
    build_tool_response,
    record_in_process_execution,
)

# Sign-in client apps that indicate legacy (non-MFA-capable) authentication.
LEGACY_CLIENT_APPS = {
    "imap4", "pop3", "smtp", "mapi", "exchange activesync",
    "authenticated smtp", "other clients", "exchange web services",
}

# Entra error codes commonly associated with MFA challenges/denials.
MFA_ERROR_CODES = {"50074", "500121", "50076", "50079", "50072"}

# Audit activities that grant standing access — high-value for attackers.
CONSENT_ACTIVITIES = {
    "consent to application", "add oauth2permissiongrant",
    "add app role assignment grant to user", "add delegated permission grant",
}
SP_CREDENTIAL_ACTIVITIES = {
    "add service principal credentials", "update application – certificates and secrets management",
    "update application - certificates and secrets management",
    "update service principal/application",
}
INBOX_RULE_OPS = {"new-inboxrule", "set-inboxrule", "updateinboxrules", "new-transportrule"}
DOWNLOAD_OPS = {"filedownloaded", "filesyncdownloadedfull"}
PRIVILEGED_ROLES = {
    "global administrator", "privileged role administrator", "application administrator",
    "cloud application administrator", "exchange administrator", "security administrator",
    "user administrator", "company administrator",
}

# Heuristic thresholds.
IMPOSSIBLE_TRAVEL_HOURS = 1.0
MFA_FATIGUE_COUNT = 5
SPRAY_DISTINCT_USERS = 5
BRUTE_FAILURES = 8
MASS_DOWNLOAD_COUNT = 50


# --------------------------------------------------------------------------- #
# Tolerant field accessors
# --------------------------------------------------------------------------- #

def _get(rec: dict, *paths: str) -> Any:
    """Return the first present value among dotted paths (case-insensitive top key)."""
    lower = {k.lower(): k for k in rec}
    for path in paths:
        cur: Any = rec
        ok = True
        for i, part in enumerate(path.split(".")):
            if isinstance(cur, dict):
                key = part if part in cur else lower.get(part.lower()) if i == 0 and cur is rec else None
                if key is None:
                    key = part if part in cur else next((k for k in cur if k.lower() == part.lower()), None)
                if key is None:
                    ok = False
                    break
                cur = cur[key]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return None


def _user(r: dict) -> str:
    return str(_get(r, "userPrincipalName", "UserId", "userId", "UserIds",
                    "initiatedBy.user.userPrincipalName", "caller", "Caller") or "unknown")


def _ip(r: dict) -> str:
    return str(_get(r, "ipAddress", "ClientIP", "ClientIPAddress", "callerIpAddress",
                    "initiatedBy.user.ipAddress") or "")


def _op(r: dict) -> str:
    return str(_get(r, "activityDisplayName", "Operation", "Operations",
                    "operationName.value", "operationName") or "")


def _country(r: dict) -> str:
    return str(_get(r, "location.countryOrRegion", "location.country", "Country") or "")


def _client_app(r: dict) -> str:
    return str(_get(r, "clientAppUsed", "ClientAppUsed") or "")


def _is_signin_success(r: dict) -> bool | None:
    code = _get(r, "status.errorCode", "ResultStatus", "status.errorcode")
    if code is None:
        return None
    return str(code) in ("0", "Success", "success")


def _parse_dt(r: dict) -> datetime | None:
    raw = _get(r, "createdDateTime", "activityDateTime", "eventTimestamp",
               "CreationDate", "CreationTime", "TimeGenerated")
    if not raw:
        return None
    s = str(raw).strip().replace("Z", "+00:00")
    for fmt in (None, "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.fromisoformat(s) if fmt is None else datetime.strptime(str(raw), fmt)
        except (ValueError, TypeError):
            continue
    return None


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def _load_records(log_path: str) -> list[dict[str, Any]]:
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    records: list[dict[str, Any]]
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("value", data.get("records", [data]))
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        # Try NDJSON, then CSV.
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if lines and all(ln.lstrip().startswith("{") for ln in lines[:3]):
            records = [json.loads(ln) for ln in lines]
        else:
            records = list(csv.DictReader(io.StringIO(text)))

    # Merge Microsoft 365 UAL AuditData JSON into the row for uniform access.
    for r in records:
        ad = r.get("AuditData") or r.get("auditdata")
        if isinstance(ad, str) and ad.strip().startswith("{"):
            try:
                for k, v in json.loads(ad).items():
                    r.setdefault(k, v)
            except json.JSONDecodeError:
                pass
    return [r for r in records if isinstance(r, dict)]


def _detect_log_type(records: list[dict]) -> str:
    sample = records[0] if records else {}
    keys = {k.lower() for k in sample}
    if "clientappused" in keys or "appdisplayname" in keys:
        return "entra_signin"
    if "activitydisplayname" in keys or "initiatedby" in keys or "targetresources" in keys:
        return "entra_audit"
    if "operationname" in keys and "eventtimestamp" in keys:
        return "azure_activity"
    if "operation" in keys or "workload" in keys or "auditdata" in keys:
        return "m365_ual"
    return "unknown"


# --------------------------------------------------------------------------- #
# Detections (each returns a list of finding dicts)
# --------------------------------------------------------------------------- #

def _finding(title, desc, severity, mitre, iocs, confidence="HIGH", tier=1) -> dict:
    return {"title": title, "description": desc, "severity": severity,
            "confidence": confidence, "evidence_tier": tier,
            "mitre_attack": mitre, "iocs": iocs}


def _detect_impossible_travel(records) -> list[dict]:
    by_user: dict[str, list[tuple[datetime, str, str]]] = defaultdict(list)
    for r in records:
        if _is_signin_success(r) and _parse_dt(r) and _country(r):
            by_user[_user(r)].append((_parse_dt(r), _country(r), _ip(r)))
    out = []
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e[0])
        for (t1, c1, ip1), (t2, c2, ip2) in zip(evs, evs[1:]):
            if c1 != c2:
                hrs = abs((t2 - t1).total_seconds()) / 3600.0
                if hrs <= IMPOSSIBLE_TRAVEL_HOURS:
                    out.append(_finding(
                        "Impossible travel sign-in",
                        f"{user} signed in from {c1} ({ip1}) and {c2} ({ip2}) "
                        f"within {hrs:.2f}h — physically impossible.",
                        "HIGH", ["T1078.004"], [ip1, ip2, user]))
    return out


def _detect_mfa_and_auth(records) -> list[dict]:
    out = []
    fatigue: dict[str, int] = defaultdict(int)
    for r in records:
        code = str(_get(r, "status.errorCode") or "")
        reason = str(_get(r, "status.failureReason", "status.additionalDetails") or "").lower()
        if code in MFA_ERROR_CODES or "mfa" in reason or "multifactor" in reason:
            fatigue[_user(r)] += 1
        if _client_app(r).lower() in LEGACY_CLIENT_APPS:
            out.append(_finding(
                "Legacy authentication (MFA-bypassing protocol)",
                f"{_user(r)} authenticated via legacy client '{_client_app(r)}' from {_ip(r)}.",
                "MEDIUM", ["T1078.004"], [_user(r), _ip(r)], confidence="MEDIUM"))
        risk = str(_get(r, "riskLevelDuringSignIn", "riskState", "riskLevel") or "").lower()
        if risk in ("high", "atrisk", "medium"):
            out.append(_finding(
                f"Risky sign-in ({risk})",
                f"{_user(r)} sign-in flagged risk={risk} from {_ip(r)}.",
                "HIGH" if risk in ("high", "atrisk") else "MEDIUM",
                ["T1078.004"], [_user(r), _ip(r)],
                confidence="HIGH" if risk in ("high", "atrisk") else "MEDIUM"))
    for user, n in fatigue.items():
        if n >= MFA_FATIGUE_COUNT:
            out.append(_finding(
                "MFA fatigue / bombing",
                f"{user} received {n} MFA challenges/denials — consistent with push-bombing.",
                "HIGH", ["T1621", "T1078.004"], [user]))
    return out


def _detect_spray_and_brute(records) -> list[dict]:
    by_ip_users: dict[str, set] = defaultdict(set)
    fails_per_user: dict[str, int] = defaultdict(int)
    success_users: set = set()
    for r in records:
        s = _is_signin_success(r)
        if s is False:
            by_ip_users[_ip(r)].add(_user(r))
            fails_per_user[_user(r)] += 1
        elif s is True:
            success_users.add(_user(r))
    out = []
    for ip, users in by_ip_users.items():
        if ip and len(users) >= SPRAY_DISTINCT_USERS:
            out.append(_finding(
                "Password spray",
                f"IP {ip} produced failed sign-ins against {len(users)} distinct accounts.",
                "HIGH", ["T1110.003"], [ip]))
    for user, n in fails_per_user.items():
        if n >= BRUTE_FAILURES and user in success_users:
            out.append(_finding(
                "Brute force followed by success",
                f"{user} had {n} failed sign-ins then a success — likely credential guessing.",
                "HIGH", ["T1110.001"], [user]))
    return out


def _detect_audit_ops(records) -> list[dict]:
    out = []
    for r in records:
        op = _op(r).lower()
        actor = _user(r)
        if op in CONSENT_ACTIVITIES or "consent" in op and "application" in op:
            target = str(_get(r, "targetResources") or "an application")
            out.append(_finding(
                "Illicit OAuth application consent grant",
                f"{actor} granted OAuth consent ({_op(r)}) to {target} — possible token abuse / "
                "persistence via app permissions.",
                "HIGH", ["T1528", "T1550.001"], [actor]))
        if op in SP_CREDENTIAL_ACTIVITIES or ("service principal" in op and "credential" in op):
            out.append(_finding(
                "Service principal credential added",
                f"{actor} added credentials/secret to a service principal ({_op(r)}) — "
                "standing programmatic access.",
                "HIGH", ["T1098.001"], [actor]))
        if "add member to role" in op or "addrolemember" in op.replace(" ", ""):
            role = str(_get(r, "targetResources") or "").lower()
            if any(pr in role for pr in PRIVILEGED_ROLES) or op.endswith("role."):
                out.append(_finding(
                    "Privileged role assignment",
                    f"{actor} added a member to a privileged directory role ({_op(r)}).",
                    "HIGH", ["T1098.003"], [actor]))
        if op in INBOX_RULE_OPS or "inboxrule" in op.replace(" ", ""):
            out.append(_finding(
                "Suspicious inbox/transport rule created",
                f"{actor} created/modified a mail rule ({_op(r)}) — classic BEC "
                "(auto-forward/hide-replies).",
                "HIGH", ["T1114.003", "T1564.008"], [actor]))
    return out


def _detect_mass_download(records) -> list[dict]:
    dl: dict[str, int] = defaultdict(int)
    for r in records:
        if _op(r).lower() in DOWNLOAD_OPS:
            dl[_user(r)] += 1
    return [
        _finding("Mass file download (possible exfiltration)",
                 f"{user} triggered {n} file-download events.",
                 "HIGH", ["T1530"], [user])
        for user, n in dl.items() if n >= MASS_DOWNLOAD_COUNT
    ]


_DETECTORS = (
    _detect_impossible_travel, _detect_mfa_and_auth, _detect_spray_and_brute,
    _detect_audit_ops, _detect_mass_download,
)


# --------------------------------------------------------------------------- #
# Public tool
# --------------------------------------------------------------------------- #

def analyze_cloud_logs(
    log_path: str,
    log_type: str | None = None,
    *,
    case_dir: str | None = None,
) -> dict[str, Any]:
    """Analyze an Entra ID / Azure / M365 log export for identity-plane attacks.

    Args:
        log_path: Path to a JSON/NDJSON/CSV log export (read-only).
        log_type: Optional hint — entra_signin | entra_audit | azure_activity |
            m365_ual. Auto-detected when omitted; all detectors run regardless.
    """
    start = _time.monotonic()
    if not os.path.isfile(log_path):
        return build_tool_response(
            tool_name="analyze_cloud_logs", data=None, evidence_file=log_path,
            error=f"Log file not found: {log_path}")

    try:
        records = _load_records(log_path)
    except (OSError, ValueError) as e:
        return build_tool_response(
            tool_name="analyze_cloud_logs", data=None, evidence_file=log_path,
            error=f"Failed to parse cloud log: {e}")

    detected_type = log_type or _detect_log_type(records)

    findings: list[dict] = []
    for detector in _DETECTORS:
        try:
            findings.extend(detector(records))
        except Exception as e:  # one bad detector must not sink the analysis
            findings.append(_finding(
                f"Detector error ({detector.__name__})", str(e), "LOW", [], [],
                confidence="LOW", tier=3))

    duration = round(_time.monotonic() - start, 3)
    summary_text = json.dumps({"records": len(records), "findings": findings}, sort_keys=True)
    exec_id, sha = record_in_process_execution(
        case_dir=case_dir, tool_name="analyze_cloud_logs",
        command=["analyze_cloud_logs", log_path, detected_type],
        output_text=summary_text, duration_seconds=duration)

    # Stamp the provenance exec id into each finding's citation.
    for fnd in findings:
        fnd["citation"] = (f"[TOOL: analyze_cloud_logs, exec: {exec_id}, "
                           f"evidence: {os.path.basename(log_path)}, type: {detected_type}]")

    return build_tool_response(
        tool_name="analyze_cloud_logs",
        data={
            "log_type": detected_type,
            "records_analyzed": len(records),
            "findings": findings[:MAX_OUTPUT_ROWS],
            "total_findings": len(findings),
            "truncated": len(findings) > MAX_OUTPUT_ROWS,
            "log_path": log_path,
        },
        evidence_file=log_path,
        output_sha256=sha,
        execution_id=exec_id,
        duration_seconds=duration,
    )
