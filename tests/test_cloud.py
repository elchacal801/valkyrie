"""
Tests for the cloud log analyzer (mcp-server/tools/cloud.py) and its integration
with the accuracy harness.
"""

import json
import sys
from pathlib import Path

import pytest

MCP_DIR = str(Path(__file__).parent.parent / "mcp-server")
EVAL_DIR = str(Path(__file__).parent.parent / "eval")
sys.path.insert(0, MCP_DIR)
sys.path.insert(0, EVAL_DIR)

from tools import cloud  # noqa: E402
import run_eval  # noqa: E402

REPO = Path(__file__).parent.parent
SAMPLE = REPO / "eval" / "datasets" / "entra-azure-sample.json"
SAMPLE_TRUTH = REPO / "eval" / "ground_truth" / "entra-azure-sample.json"


def _titles(resp):
    return [f["title"] for f in resp["data"]["findings"]]


class TestCloudDetections:

    def test_sample_triggers_all_detectors(self):
        resp = cloud.analyze_cloud_logs(str(SAMPLE))
        assert resp["status"] == "success"
        assert resp["execution_id"].startswith("EXEC-")
        assert resp["output_sha256"]
        titles = " | ".join(_titles(resp)).lower()
        for expected in [
            "impossible travel", "mfa fatigue", "legacy authentication",
            "risky sign-in", "password spray", "illicit oauth",
            "privileged role assignment", "service principal credential",
            "inbox/transport rule",
        ]:
            assert expected in titles, f"missing detection: {expected}"

    def test_mitre_cloud_mappings_present(self):
        resp = cloud.analyze_cloud_logs(str(SAMPLE))
        codes = {c for f in resp["data"]["findings"] for c in f.get("mitre_attack", [])}
        for code in ["T1078.004", "T1621", "T1110.003", "T1528", "T1098.001", "T1098.003", "T1114.003"]:
            assert code in codes, f"missing ATT&CK mapping {code}"

    def test_missing_file(self):
        resp = cloud.analyze_cloud_logs("/nonexistent/log.json")
        assert resp["status"] == "error"
        assert "not found" in resp["error"].lower()

    def test_graph_value_envelope(self, tmp_path):
        p = tmp_path / "g.json"
        p.write_text(json.dumps({"value": [
            {"userPrincipalName": "x@y.com", "clientAppUsed": "IMAP4",
             "status": {"errorCode": 0}, "createdDateTime": "2026-05-01T00:00:00Z"}
        ]}))
        resp = cloud.analyze_cloud_logs(str(p))
        assert resp["data"]["records_analyzed"] == 1
        assert any("legacy" in t.lower() for t in _titles(resp))

    def test_ndjson(self, tmp_path):
        p = tmp_path / "n.ndjson"
        p.write_text(
            '{"userPrincipalName":"a@b.com","clientAppUsed":"POP3","status":{"errorCode":0},"createdDateTime":"2026-05-01T00:00:00Z"}\n'
            '{"userPrincipalName":"a@b.com","clientAppUsed":"Browser","status":{"errorCode":0},"createdDateTime":"2026-05-01T00:05:00Z"}\n'
        )
        resp = cloud.analyze_cloud_logs(str(p))
        assert resp["data"]["records_analyzed"] == 2

    def test_m365_csv_with_auditdata(self, tmp_path):
        p = tmp_path / "ual.csv"
        p.write_text(
            "CreationDate,UserId,Operation,AuditData\n"
            '2026-05-01T14:00:00,eve@contoso.com,New-InboxRule,"{""Operation"":""New-InboxRule"",""UserId"":""eve@contoso.com""}"\n'
        )
        resp = cloud.analyze_cloud_logs(str(p))
        assert any("inbox" in t.lower() for t in _titles(resp))

    def test_mass_download(self, tmp_path):
        recs = [{"Operation": "FileDownloaded", "UserId": "thief@contoso.com",
                 "CreationTime": "2026-05-01T00:00:00Z"} for _ in range(60)]
        p = tmp_path / "dl.json"
        p.write_text(json.dumps(recs))
        resp = cloud.analyze_cloud_logs(str(p))
        assert any("mass file download" in t.lower() for t in _titles(resp))

    def test_execution_logged_to_audit(self, tmp_path):
        case = tmp_path / "case"
        case.mkdir()
        cloud.analyze_cloud_logs(str(SAMPLE), case_dir=str(case))
        log = (case / "logs" / "tool-execution.jsonl").read_text().strip()
        entry = json.loads(log.splitlines()[-1])
        assert entry["tool_name"] == "analyze_cloud_logs"
        assert entry["execution_id"].startswith("EXEC-")


class TestCloudEvalIntegration:
    """The bundled cloud sample scores cleanly against its ground truth."""

    def test_perfect_score_on_synthetic_sample(self):
        resp = cloud.analyze_cloud_logs(str(SAMPLE))
        findings = resp["data"]["findings"]
        truth = json.loads(SAMPLE_TRUTH.read_text())
        r = run_eval.score(findings, truth)
        assert r["recall"] == pytest.approx(1.0)
        assert r["precision"] == pytest.approx(1.0)
        assert r["f1"] == pytest.approx(1.0)
        assert r["counts"]["false_positives"] == 0
