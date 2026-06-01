#!/usr/bin/env python3
"""
VALKYRIE — Ground-Truth Accuracy Harness
=========================================

Scores a completed investigation's findings against a documented ground-truth
set for a known dataset (e.g. the NIST CFReDS Hacking Case) and emits the
accuracy report the FIND EVIL! rubric requires: precision / recall / F1 plus
explicit **false positives (hallucinated claims)** and **false negatives
(missed artifacts)**.

Design notes
------------
The hardest part of scoring an autonomous IR agent is honoring the rubric's
distinction between *confirmed findings* and *inferences*. We do that here:

* RECALL is computed over the ground-truth items the agent was expected to find.
  An item is a true positive if any of its ``match_any`` tokens appears in the
  finding corpus (descriptions + artifact paths/details + IOC values + citations).

* PRECISION / HALLUCINATION is computed only over **asserted** claims — concrete
  artifact/IOC values the agent presents as fact (verification verdict CONFIRMED,
  or evidence_tier 1/2, or HIGH confidence). A claim that matches no ground-truth
  item and is not on the benign allowlist is a **false positive (hallucination)**.
  Claims explicitly marked as inference (Tier 3 / verdict INFERRED) are reported
  separately and are *never* penalized as hallucinations — inferring is allowed,
  asserting a non-existent artifact is not.

The harness is dependency-free (Python stdlib only) so it runs anywhere the MCP
server runs, and is importable for unit testing.

Usage
-----
    python eval/run_eval.py \
        --findings /cases/<id>/report/findings.json \
        --truth   eval/ground_truth/nist-hacking-case.json \
        [--iocs   /cases/<id>/report/iocs.json] \
        --out     /cases/<id>/report

Writes ``accuracy.json`` and ``ACCURACY.md`` to ``--out``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# Normalization & matching
# --------------------------------------------------------------------------- #

def normalize(text: str) -> str:
    """Lowercase, collapse whitespace, and strip — for tolerant matching."""
    return re.sub(r"\s+", " ", str(text).lower()).strip()


def tokens_match(claim: str, token: str) -> bool:
    """A claim matches a ground-truth/allowlist token if either contains the
    other after normalization (handles 'C:\\...\\malware.exe' vs 'malware.exe'
    and 'Cain & Abel' vs 'cain')."""
    c, t = normalize(claim), normalize(token)
    if not c or not t:
        return False
    return t in c or c in t


def corpus_contains(corpus: str, token: str) -> bool:
    t = normalize(token)
    return bool(t) and t in corpus


# --------------------------------------------------------------------------- #
# Finding ingestion
# --------------------------------------------------------------------------- #

ASSERTED_VERDICTS = {"CONFIRMED"}
INFERRED_VERDICTS = {"INFERRED"}


def _load_findings(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("findings", data.get("data", []))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of findings or {{'findings': [...]}}")
    return data


def _finding_text(f: dict[str, Any]) -> str:
    """Flatten a finding into a single searchable, normalized blob (for recall)."""
    parts: list[str] = [str(f.get("title", "")), str(f.get("description", ""))]
    for art in f.get("artifacts", []) or []:
        if isinstance(art, dict):
            parts += [str(art.get("path", "")), str(art.get("details", "")),
                      str(art.get("value", ""))]
        else:
            parts.append(str(art))
    for ioc in f.get("iocs", []) or []:
        parts.append(ioc.get("value", "") if isinstance(ioc, dict) else str(ioc))
    parts += [str(c) for c in f.get("citations", []) or []]
    return normalize(" \n ".join(parts))


def _is_asserted(f: dict[str, Any]) -> bool:
    """Is this finding presented as fact (vs. an inference/hypothesis)?"""
    verdict = str((f.get("verification") or {}).get("verdict", "")).upper()
    if verdict in INFERRED_VERDICTS:
        return False
    if verdict in ASSERTED_VERDICTS:
        return True
    tier = str(f.get("evidence_tier", "")).strip()
    if tier.startswith("3"):
        return False
    if tier.startswith("1") or tier.startswith("2"):
        return True
    return str(f.get("confidence", "")).upper() == "HIGH"


def _claim_values(f: dict[str, Any]) -> list[str]:
    """Concrete artifact/IOC values a finding asserts (for precision/FP)."""
    vals: list[str] = []
    for art in f.get("artifacts", []) or []:
        if isinstance(art, dict):
            v = art.get("value") or art.get("path")
            if v:
                vals.append(str(v))
        elif art:
            vals.append(str(art))
    for ioc in f.get("iocs", []) or []:
        v = ioc.get("value") if isinstance(ioc, dict) else ioc
        if v:
            vals.append(str(v))
    return vals


def _load_extra_iocs(path: Path) -> list[dict[str, Any]]:
    """Optional iocs.json — a flat list of asserted IOCs treated as claims."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("extracted_iocs", data.get("iocs", data.get("data", [])))
    return data if isinstance(data, list) else []


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def score(
    findings: list[dict[str, Any]],
    truth: dict[str, Any],
    extra_iocs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    items = [it for it in truth.get("items", []) if it.get("required", True)]
    benign = truth.get("benign_allowlist", [])

    corpus = "\n".join(_finding_text(f) for f in findings)

    # ---- Recall: which expected items were found? ----
    matched_items, missed_items = [], []
    for it in items:
        toks = it.get("match_any") or [it.get("value", "")]
        hit = any(corpus_contains(corpus, t) for t in toks)
        (matched_items if hit else missed_items).append(it)

    # ---- Precision: asserted claims that match no ground-truth item ----
    asserted_claims: list[str] = []
    for f in findings:
        if _is_asserted(f):
            asserted_claims.extend(_claim_values(f))
    for ioc in extra_iocs or []:
        v = ioc.get("value") if isinstance(ioc, dict) else ioc
        if v:
            asserted_claims.append(str(v))
    # de-dupe while preserving order
    seen: set[str] = set()
    asserted_claims = [c for c in asserted_claims
                       if not (normalize(c) in seen or seen.add(normalize(c)))]

    all_tokens = [t for it in truth.get("items", []) for t in (it.get("match_any") or [it.get("value", "")])]
    true_claims, false_positives = [], []
    for claim in asserted_claims:
        ok = any(tokens_match(claim, t) for t in all_tokens) or \
             any(tokens_match(claim, b) for b in benign)
        (true_claims if ok else false_positives).append(claim)

    inferred_claims: list[str] = []
    for f in findings:
        if not _is_asserted(f):
            inferred_claims.extend(_claim_values(f))

    tp, fn = len(matched_items), len(missed_items)
    fp = len(false_positives)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = len(true_claims) / (len(true_claims) + fp) if (len(true_claims) + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "dataset": truth.get("dataset", "unknown"),
        "dataset_url": truth.get("dataset_url", ""),
        "generated": datetime.now(timezone.utc).isoformat(),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "counts": {
            "ground_truth_items": len(items),
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "asserted_claims": len(asserted_claims),
            "inferred_claims": len(inferred_claims),
        },
        "matched_items": [{"id": it.get("id"), "description": it.get("description")}
                          for it in matched_items],
        "missed_items": [{"id": it.get("id"), "description": it.get("description"),
                          "source": it.get("source", "")} for it in missed_items],
        "false_positive_claims": false_positives,
        "inferred_claims": inferred_claims,
    }


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #

def render_markdown(r: dict[str, Any]) -> str:
    c = r["counts"]
    lines = [
        f"# Accuracy Report — {r['dataset']}",
        "",
        f"_Generated {r['generated']}_  ",
        f"_Dataset: {r['dataset_url'] or 'n/a'}_",
        "",
        "## Headline metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Precision | **{r['precision']:.2%}** |",
        f"| Recall | **{r['recall']:.2%}** |",
        f"| F1 | **{r['f1']:.2%}** |",
        f"| Ground-truth items | {c['ground_truth_items']} |",
        f"| True positives (found) | {c['true_positives']} |",
        f"| False negatives (missed artifacts) | {c['false_negatives']} |",
        f"| False positives (hallucinated claims) | {c['false_positives']} |",
        f"| Asserted claims scored | {c['asserted_claims']} |",
        f"| Inference claims (not penalized) | {c['inferred_claims']} |",
        "",
        "## Missed artifacts (false negatives)",
        "",
    ]
    if r["missed_items"]:
        lines += ["| GT ID | Expected artifact | Source |", "|-------|-------------------|--------|"]
        lines += [f"| {m['id']} | {m['description']} | {m.get('source','')} |" for m in r["missed_items"]]
    else:
        lines.append("_None — every required ground-truth item was found._")
    lines += ["", "## Hallucinated claims (false positives)", ""]
    if r["false_positive_claims"]:
        lines += ["| # | Asserted value with no ground-truth or benign match |", "|---|---|"]
        lines += [f"| {i+1} | `{v}` |" for i, v in enumerate(r["false_positive_claims"])]
    else:
        lines.append("_None — no asserted claim lacked ground-truth corroboration._")
    lines += [
        "",
        "## Methodology",
        "",
        "Recall is measured over required ground-truth items (an item is found if any of "
        "its `match_any` tokens appears in the finding corpus). Precision is measured only "
        "over **asserted** claims (verdict CONFIRMED, or evidence tier 1/2, or HIGH "
        "confidence); claims explicitly marked as inference (Tier 3 / INFERRED) are listed "
        "separately and never counted as hallucinations. See `eval/run_eval.py`.",
        "",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score VALKYRIE findings vs ground truth.")
    ap.add_argument("--findings", required=True, type=Path)
    ap.add_argument("--truth", required=True, type=Path)
    ap.add_argument("--iocs", type=Path, default=None)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    try:
        findings = _load_findings(args.findings)
        truth = json.loads(args.truth.read_text(encoding="utf-8"))
        extra = _load_extra_iocs(args.iocs) if args.iocs and args.iocs.exists() else []
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    result = score(findings, truth, extra)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "accuracy.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (args.out / "ACCURACY.md").write_text(render_markdown(result), encoding="utf-8")

    print(f"{result['dataset']}: P={result['precision']:.2%} "
          f"R={result['recall']:.2%} F1={result['f1']:.2%} "
          f"(TP={result['counts']['true_positives']} "
          f"FN={result['counts']['false_negatives']} "
          f"FP={result['counts']['false_positives']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
