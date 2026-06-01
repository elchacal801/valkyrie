"""
Tests for the ground-truth accuracy harness (eval/run_eval.py).

Deterministic: scores a fully-known fixture and asserts exact precision/recall/F1
plus correct handling of missed artifacts, hallucinations, and (un-penalized)
inferences.
"""

import json
import sys
from pathlib import Path

import pytest

EVAL_DIR = Path(__file__).parent.parent / "eval"
sys.path.insert(0, str(EVAL_DIR))

import run_eval  # noqa: E402

EXAMPLES = EVAL_DIR / "examples"


def _load(name):
    return json.loads((EXAMPLES / name).read_text())


class TestEvalHarness:

    def test_example_metrics(self):
        findings = _load("example-findings.json")["findings"]
        truth = _load("example-truth.json")
        r = run_eval.score(findings, truth)

        assert r["recall"] == pytest.approx(0.75)          # 3 of 4 required items
        assert r["precision"] == pytest.approx(2 / 3, abs=1e-4)  # 2 true of 3 asserted
        assert r["f1"] == pytest.approx(0.7059, abs=1e-3)

        c = r["counts"]
        assert c["true_positives"] == 3
        assert c["false_negatives"] == 1
        assert c["false_positives"] == 1
        assert c["inferred_claims"] == 1  # apt-maybe.com, not penalized

    def test_missed_and_hallucinated_items_named(self):
        findings = _load("example-findings.json")["findings"]
        truth = _load("example-truth.json")
        r = run_eval.score(findings, truth)

        missed = " ".join(m["description"].lower() for m in r["missed_items"])
        assert "mimikatz" in missed
        assert "192.168.1.99" in r["false_positive_claims"]
        assert "apt-maybe.com" in r["inferred_claims"]

    def test_inference_not_counted_as_hallucination(self):
        """A Tier-3 / inferred claim that matches nothing must not be an FP."""
        findings = [{
            "finding_id": "X", "evidence_tier": 3, "confidence": "LOW",
            "iocs": ["totally-made-up.example"], "description": "speculative",
        }]
        truth = {"items": [{"id": "G", "match_any": ["something"], "required": True}]}
        r = run_eval.score(findings, truth)
        assert r["counts"]["false_positives"] == 0
        assert r["counts"]["inferred_claims"] == 1

    def test_confirmed_verdict_overrides_low_tier(self):
        """An explicit CONFIRMED verdict makes a claim asserted (scored)."""
        findings = [{
            "finding_id": "X", "evidence_tier": 3, "confidence": "LOW",
            "verification": {"verdict": "CONFIRMED"},
            "iocs": ["ghost.exe"], "description": "verified by tool",
        }]
        truth = {"items": [{"id": "G", "match_any": ["real.exe"], "required": True}]}
        r = run_eval.score(findings, truth)
        assert r["counts"]["false_positives"] == 1  # ghost.exe asserted, unmatched

    def test_empty_findings(self):
        truth = _load("example-truth.json")
        r = run_eval.score([], truth)
        assert r["recall"] == 0.0
        assert r["precision"] == 0.0
        assert r["f1"] == 0.0

    def test_markdown_renders_sections(self):
        findings = _load("example-findings.json")["findings"]
        truth = _load("example-truth.json")
        md = run_eval.render_markdown(run_eval.score(findings, truth))
        assert "# Accuracy Report" in md
        assert "Missed artifacts" in md
        assert "Hallucinated claims" in md
        assert "Methodology" in md
