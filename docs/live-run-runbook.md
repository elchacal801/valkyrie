# VALKYRIE — Live-Run Runbook

How to run VALKYRIE against real evidence and produce the **submission artifacts**
the SANS FIND EVIL! judges expect. Everything in the repo is unit/CI-verified (81
tests); this runbook turns those capabilities into measured results on a real dataset.

## What this produces (and why judges care)

| Artifact | Path | Maps to |
|----------|------|---------|
| Accuracy report (P/R/F1, FP/FN tables) | `report/ACCURACY.md`, `report/accuracy.json` | IR Accuracy |
| Verification ledger (CONFIRMED/INFERRED/**UNVERIFIED**) | `corrections/verification-ledger.json` | Hallucination management |
| Iteration trace with first→final delta | `logs/progress.jsonl` | Persistent Learning Loop |
| Execution-stamped audit log | `logs/tool-execution.jsonl` | Audit-trail quality |
| Investigation report | `report/investigation-report.md` | Documentation / autonomy |

---

## 0. Prerequisites (once)

- **SIFT Workstation** — SANS SIFT VM (OVA) is least-friction; WSL2 works (see `docs/sift-wsl-setup.md`).
- Forensic tools on PATH (verified by `install.sh` Phase 1): `vol`, `mmls`/`fls`/`icat`,
  `log2timeline.py`/`psort.py`, `MFTECmd`, `yara`, `floss`, `rip.pl`/`RECmd`.
- **Claude Code** installed and authenticated; select **Claude Opus 4.8** (`/model`).
- Install VALKYRIE:
  ```bash
  git clone https://github.com/elchacal801/valkyrie.git && cd valkyrie
  ./install.sh          # venv + mcp, deploys hooks, registers the MCP server
  python3 -m pytest tests/ -q     # sanity: 81 passing
  ```

---

## 1. Stage evidence (read-only)

### Run A — NIST CFReDS Hacking Case (disk; head-to-head benchmark)
```bash
mkdir -p /cases/CASE-NIST/evidence
# Download the EnCase/.E01 image set from:
#   https://cfreds.nist.gov/all/NIST/HackingCase
# into /cases/CASE-NIST/evidence/
chmod -R a-w /cases/CASE-NIST/evidence     # read-only backstop
export VALKYRIE_CASE_DIR=/cases/CASE-NIST
export VALKYRIE_EVIDENCE_PATH=/cases/CASE-NIST/evidence
```
> NIST Hacking Case is **disk-only** — it exercises timeline / persistence / registry /
> malware, not memory. That's the apples-to-apples disk benchmark rivals use.

### Run B — Public memory image (showcases memory depth)
Pick a public Windows memory sample **with a documented solution** (e.g. an Ali Hadi or
MemLabs challenge). Stage it the same way under `/cases/CASE-MEM/evidence/`, then populate
`eval/ground_truth/memory-sample.json` `match_any` fields with the published artifacts and
set those items `required: true`.

---

## 2. Investigate + measure

Launch Claude Code in the repo, then drive it with the prompt in the Appendix. The core
commands it will issue:

```text
# Disk benchmark, with the measurable loop scoring each iteration against ground truth:
/investigate --loop CASE-NIST --truth eval/ground_truth/nist-hacking-case.json --max-iterations 4

# Or a single full pass:
/investigate --guided --case-id CASE-NIST --evidence-path /cases/CASE-NIST/evidence

# Memory image:
/investigate --guided --case-id CASE-MEM --evidence-path /cases/CASE-MEM/evidence
```

Phase 5 runs self-correction **and** verification, so every finding lands with a verdict.

---

## 3. Produce the accuracy report

```bash
python eval/run_eval.py \
  --findings /cases/CASE-NIST/report/findings.json \
  --truth   eval/ground_truth/nist-hacking-case.json \
  --out     /cases/CASE-NIST/report
# → report/ACCURACY.md + report/accuracy.json ; prints P/R/F1 (TP/FN/FP)
```
The harness is tolerant of `[...]` or `{"findings":[...]}`. Precision is scored over
**asserted** claims only, so Tier-3 inferences are never counted as hallucinations.

---

## 4. Verify ground truth, then re-score

Cross-check the items flagged `verify: true` in `nist-hacking-case.json` (NIC MAC, email
alias, host name) against the **official CFReDS answer key**. Set confirmed items
`required: true`, fix any value, and re-run step 3. Now the headline F1 is defensible.

---

## 5. Submission artifact checklist

- [ ] `report/ACCURACY.md` with real P/R/F1 and FP/FN tables (per dataset)
- [ ] `corrections/verification-ledger.json` showing ≥1 `UNVERIFIED` catch
- [ ] `logs/progress.jsonl` showing iteration-1 → final F1 improvement
- [ ] `logs/tool-execution.jsonl` (every line has an `execution_id`)
- [ ] `report/investigation-report.md` (Verification Ledger + Audit Trail populated)
- [ ] Dataset provenance documented in `docs/evidence-dataset-docs.md`
- [ ] Demo video: the `UNVERIFIED` finding + the `progress.jsonl` F1 delta on screen

---

## 6. Gotchas

- **Plaso is the slow step.** `generate_timeline` times out at 600s on a full disk; scope
  it with `start_date`/`end_date` around the incident window for the demo.
- **Volatility ISF symbols.** Run `analyze_memory(plugin="banners")` first; if `pslist` is
  empty, VALKYRIE auto-falls back to `psscan`/`netscan` — note the limitation in findings.
- **Disk vs memory.** Don't expect memory findings from the NIST disk case; use Run B for memory.
- **Cost/time.** A full guided NIST run is dominated by timeline generation; budget accordingly.
- **Honesty is the product.** Do not hand-edit `findings.json` to raise the score. A flagged
  `UNVERIFIED` or an honest false negative is worth more to these judges than an inflated number.

---

## Appendix — Claude Code driver prompt

Paste this into Claude Code (running in the repo on SIFT) to drive a full live run. Replace
the case id / paths as needed.

```text
You are operating VALKYRIE, the autonomous IR agent in this repository, for a real
investigation. Goal: produce the SANS FIND EVIL! submission artifacts for the NIST CFReDS
Hacking Case and report measured results. Follow VALKYRIE's own rules in CLAUDE.md and the
skill protocols exactly.

Non-negotiables:
- MCP-first: use mcp__valkyrie__* tools for all forensic operations; never write to evidence.
- Every finding must cite the execution_id of the tool call that produced it.
- Distinguish CONFIRMED vs INFERRED vs UNVERIFIED honestly. If a claim cannot be grounded by
  a fresh tool call, mark it UNVERIFIED — do NOT delete it and do NOT inflate confidence.
- Never fabricate artifacts, ground truth, or scores. If a tool fails, document it and use
  the documented fallback (e.g., pslist -> psscan).

Do this, pausing to show me a short summary after each numbered step:

1. Environment check: confirm the valkyrie MCP server is connected and list its tools;
   confirm VALKYRIE_CASE_DIR=/cases/CASE-NIST and that the evidence directory is readable
   and read-only. Report any missing forensic tools.
2. Run the persistent learning loop on the case, scoring each iteration against ground truth:
   /investigate --loop CASE-NIST --truth eval/ground_truth/nist-hacking-case.json --max-iterations 4
   Ensure Phase 5 runs BOTH self-correction and verification so every finding gets a verdict.
3. Confirm these artifacts exist and are well-formed: report/findings.json,
   corrections/verification-ledger.json, logs/progress.jsonl, logs/tool-execution.jsonl.
   Show me the verdict tally (CONFIRMED / INFERRED / UNVERIFIED) and the first-vs-final F1
   from progress.jsonl.
4. Produce the accuracy report by running, via Bash:
   python eval/run_eval.py --findings /cases/CASE-NIST/report/findings.json \
     --truth eval/ground_truth/nist-hacking-case.json --out /cases/CASE-NIST/report
   Show me report/ACCURACY.md.
5. List every ground-truth item the eval marked as a MISS (false negative) and every
   asserted claim marked as a hallucination (false positive). For each miss, tell me whether
   the artifact is genuinely absent, out of scope for a disk image, or a real gap to fix.
6. Final summary table: total findings by verdict, precision/recall/F1, FP and FN counts,
   and the absolute paths of every artifact in the checklist above.

Do not push anything to git. Stop and ask me before doing anything destructive or anything
that would write outside the case working directory.
```
