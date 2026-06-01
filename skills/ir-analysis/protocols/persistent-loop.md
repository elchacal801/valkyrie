# Persistent Learning Loop

Run investigation iterations on the **same evidence** until *verifiable* success
criteria are met or progress stagnates — logging every iteration so the agent's
accuracy demonstrably improves from first to final pass. This is the FIND EVIL!
"persistent learning loop" criterion, whose stated success metric is *"demonstrable
improvement in accuracy between first iteration and final iteration on the same
data, with full execution traces preserved."*

The loop **reuses** the existing `--iterate` machinery (Phase-3+ re-run with
versioned `synthesis.vN.json` archives), `self-correction.md`, `verification.md`,
and — when ground truth is available — `eval/run_eval.py`.

---

## Invocation

```
/investigate --loop <case-id> [--max-iterations N] [--truth <ground_truth.json>]
```

- `--max-iterations N` — hard stop (default **5**) so the loop always terminates.
- `--truth <path>` — when provided (benchmarks/demo), each iteration is scored with
  `eval/run_eval.py` and its **F1 is recorded** → the headline first-vs-final delta.
  Without it, the loop uses the internal **grounded-ratio** signal (below).

---

## What "improvement" means here (verifiable, not subjective)

Each iteration computes signals that are grounded in tool re-execution, so progress
is auditable rather than the model simply asserting it got better:

| Signal | Definition | Direction |
|--------|------------|-----------|
| `grounded_ratio` | CONFIRMED ÷ asserted findings (from the verification ledger) | ↑ better |
| `unverified` | count of asserted-but-ungrounded findings | ↓ better |
| `open_high_issues` | unresolved Layer-1/Layer-2 HIGH self-correction issues | ↓ better |
| `kill_chain_coverage` | phases evidenced **or** explicitly marked absent ÷ 7 | ↑ better |
| `f1` (if `--truth`) | eval-harness F1 vs ground truth | ↑ better |

---

## Loop algorithm

```
n = (highest existing synthesis.vN) + 1   # 1 on a fresh case
repeat:
  1. Run/iterate the investigation (Phase 3+ per --iterate semantics) → synthesis + findings
  2. Phase 5: self-correction.md, then verification.md → verification-ledger.json
  3. Compute the signals above (+ F1 if --truth)
  4. Append one record to logs/progress.jsonl (schema below)
  5. SUCCESS?  grounded_ratio == 1.0 (no UNVERIFIED asserted findings)
              AND open_high_issues == 0
              AND every kill-chain phase is evidenced or explicitly marked absent
              → stop (decision = SUCCESS)
  6. STAGNATED?  no new CONFIRMED finding since last iteration
              AND unverified did not decrease
              → stop (decision = STAGNATED)
  7. n >= max-iterations → stop (decision = MAX_ITERATIONS)
  8. otherwise: set next_focus from the open items (see below), n += 1, continue
```

### Deriving `next_focus` (how the agent course-corrects)

The next iteration is **targeted**, not a blind re-run. Build the focus list from the
current iteration's open items, in priority order:

1. **UNVERIFIED asserted findings** → re-run the specific technique that can ground
   them (e.g. re-run `netscan` to confirm a claimed C2), or remove the claim if a
   second grounded attempt still fails.
2. **Open HIGH self-correction issues** → address the temporal/artifact inconsistency.
3. **Missing kill-chain phases** → add the technique that best covers the gap
   (e.g. add `logs` for an un-evidenced Lateral Movement phase).
4. **Contradictions** flagged by `artifact-correlation.md` → re-derive both sides.

Record `next_focus` in the progress record so a judge can see *why* the approach
changed between iterations.

---

## `logs/progress.jsonl` — one record per iteration

```json
{
  "iteration": 1,
  "timestamp": "<ISO-8601>",
  "techniques_run": ["timeline", "memory", "persistence"],
  "findings": {"total": 7, "confirmed": 4, "inferred": 2, "unverified": 1},
  "grounded_ratio": 0.80,
  "open_high_issues": 1,
  "corrections_applied": 2,
  "kill_chain_coverage": "5/7 evidenced, 1 marked absent",
  "accuracy": {"precision": 0.86, "recall": 0.71, "f1": 0.78},
  "cost": {"wall_clock_seconds": 142.7, "tokens": {"total": 93330}},
  "decision": "CONTINUE",
  "next_focus": "re-run netscan to ground F-002 (claimed C2); add logs technique for Lateral Movement"
}
```

The final record's `decision` is one of `SUCCESS | STAGNATED | MAX_ITERATIONS`.

---

## Proving the delta (report integration)

After the loop ends, the report's **Persistent Learning Loop** section summarizes
`progress.jsonl`:

- a per-iteration table of the signals above,
- the **iteration-1 → final** delta for `f1` (or `grounded_ratio` when no ground truth),
- the terminal `decision` and a one-line rationale.

Full execution traces are preserved across iterations by three artifacts already on
disk: the versioned `synthesis.vN.json`, `logs/progress.jsonl`, and the
`execution_id`-stamped `logs/tool-execution.jsonl`.

---

## Guards

- The loop **always terminates** (success, stagnation, or `--max-iterations`).
- It never edits evidence; iterations only re-run read-only forensic techniques.
- A monotonic **regression guard**: if an iteration's `grounded_ratio` *drops* versus
  the previous one, keep the previous iteration's findings as authoritative and stop
  (decision = STAGNATED) — the loop never ships a worse result than it already had.
- Loop state lives entirely in the case directory, so `--resume`/`--loop` can continue
  an interrupted run.
