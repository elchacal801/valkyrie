# VALKYRIE Accuracy Evaluation

Quantitative, reproducible accuracy scoring against **documented ground truth** —
the FIND EVIL! rubric's IR-Accuracy proof (precision / recall / F1 with explicit
false positives = hallucinated claims and false negatives = missed artifacts).

## Run

```bash
python eval/run_eval.py \
  --findings /cases/<CASE-ID>/report/findings.json \
  --truth    eval/ground_truth/nist-hacking-case.json \
  --out      /cases/<CASE-ID>/report
# optional: --iocs /cases/<CASE-ID>/report/iocs.json
```

Outputs `accuracy.json` (machine-readable) and `ACCURACY.md` (the submission report)
in `--out`. A one-line summary prints to stdout:

```
NIST CFReDS Hacking Case: P=.. R=.. F1=.. (TP=.. FN=.. FP=..)
```

## Scoring model (why it's fair to an *autonomous* agent)

- **Recall** is over the **required** ground-truth items. An item is found if any of
  its `match_any` tokens appears in the finding corpus (descriptions + artifact
  paths/details + IOC values + citations).
- **Precision / hallucination** is computed **only over asserted claims** — concrete
  artifact/IOC values the agent presents as fact (verification verdict `CONFIRMED`,
  or evidence tier 1/2, or HIGH confidence). An asserted claim matching no ground-truth
  item and not on the `benign_allowlist` is a **false positive (hallucination)**.
- Claims explicitly marked as **inference** (Tier 3 / verdict `INFERRED`) are reported
  separately and **never** penalized — inferring is allowed; asserting a non-existent
  artifact is not. This is exactly the rubric's "confirmed vs. inferences" distinction.

## Datasets

| File | Dataset | Status |
|------|---------|--------|
| `ground_truth/nist-hacking-case.json` | NIST CFReDS Hacking Case (disk) | Stable facts encoded; a few values flagged `verify` to reconcile with the official answer key |
| `ground_truth/memory-sample.json` | Public memory image | Template — populate from the chosen image's documented solution |
| `examples/` | Self-test fixture | Fully known; drives `tests/test_eval.py` |

Ground-truth items carry `verify: true` / `required: false` until their exact value is
confirmed against the official solution, so unverified values never skew the headline
number. Datasets themselves are **not** committed — obtain them from
[NIST CFReDS](https://cfreds.nist.gov/) and document provenance per the contest's
dataset-documentation requirement.

## Self-test

```bash
pytest tests/test_eval.py -v
```
