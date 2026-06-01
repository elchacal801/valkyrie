# Verification Protocol — Per-Finding Grounding

Assign every finding an independent **verdict** — `CONFIRMED`, `INFERRED`, or
`UNVERIFIED` — by re-deriving its central claim from a *fresh tool execution*.
This is VALKYRIE's primary hallucination guard and the direct answer to the
judging question *"are hallucinations caught and flagged? are confirmed findings
distinguished from inferences?"*

This protocol runs in **Phase 5, immediately after `self-correction.md`** (the
3-layer pass fixes detected errors; this pass labels what remains). It is also
run automatically at the end of each persistent-loop iteration.

---

## The anti-"coherence trap" rule (read first)

Recent research shows that iterative self-critique *without new evidence* makes a
model more confident without making it more correct — it talks itself into a
polished but wrong answer. **Therefore verification must be grounded in a new tool
call, never in re-reasoning.** A finding is only `CONFIRMED` when an independent
MCP execution re-produces the artifact. Re-reading your own prior text is not
verification.

---

## Verdict definitions

| Verdict | Meaning | Counts as |
|---------|---------|-----------|
| **CONFIRMED** | An independent tool call re-derived the asserted artifact (file present at path, PID present with matching name, registry key/value present, log entry present, hash matches). | Asserted fact |
| **INFERRED** | An analytical conclusion that is *not directly observable* (ACH leading hypothesis, correlation/attack-narrative claim, AI-adversary likelihood). Legitimately cannot be "looked up". | Inference — reported, never penalized |
| **UNVERIFIED** | An **asserted** claim (Tier 1/2 or HIGH confidence) that an independent tool call could **not** re-derive. | ⚠️ Flagged hallucination risk |

> An `UNVERIFIED` verdict is never silently dropped. Surface it, downgrade its
> confidence, and list it in the Verification Ledger. Catching and flagging the
> claim is worth more to a judge than hiding it.

---

## Verification strategy by artifact type

For each finding, pick the strategy matching its primary artifact and issue a
**new** MCP call. Record the verifier tool, its `execution_id`, and output SHA256.

| Artifact type | Independent re-derivation |
|---------------|---------------------------|
| File / path | `list_files(path=...)` — does the file exist where claimed? |
| Process / PID | `analyze_memory(plugin="pslist")` (or `psscan`) — PID present, name matches? |
| Injected region | `analyze_memory(plugin="malfind"/"vadinfo", pid=...)` — region still reported? |
| Registry key/value | `get_registry_key(key_path=...)` — key exists, value matches? |
| Network connection | `analyze_memory(plugin="netscan")` — endpoint/PID present? |
| Log event | re-parse the specific `.evtx` for the cited Event ID + timestamp |
| File hash | re-`extract_file` (or re-hash the extracted artifact) and compare SHA256 |
| Persistence entry | `check_persistence(...)` — entry still enumerated? |
| Timeline event | `extract_mft` / `generate_timeline` filtered to the cited window |
| Inference (ACH / correlation / AI-tempo) | **No tool re-derivation possible → verdict INFERRED.** Confirm only that it cites the upstream finding IDs it depends on. |

---

## Procedure (per finding)

1. **Classify intent.** Is the finding an asserted observation or an inference?
   (Inference = Tier 3, ACH/correlation/ai-adversary output → verdict `INFERRED`;
   record which upstream finding IDs it rests on; stop.)
2. **Re-derive.** For an asserted finding, run the matching strategy above as a
   **new** MCP call. Capture its `execution_id` and `output_sha256`.
3. **Compare.** Does the fresh output contain the claimed artifact (path, PID+name,
   key+value, endpoint, hash, event)?
   - Match → `CONFIRMED`. Record `verifier_tool`, `verifier_exec_id`, `verifier_output_sha256`.
   - No match → `UNVERIFIED`. Downgrade confidence one level (HIGH→MEDIUM→LOW),
     prepend "⚠️ UNVERIFIED:" to the finding description, and record the attempted tool.
4. **Write back.** Populate the finding's `verification` block (see
   `templates/finding-template.json`) and set `provenance_exec_id` to the original
   producing call.

---

## Output

Write `corrections/verification-ledger.json`:

```json
{
  "case_id": "<CASE-ID>",
  "timestamp": "<ISO-8601>",
  "summary": {"confirmed": 0, "inferred": 0, "unverified": 0, "total": 0},
  "verdicts": [
    {
      "finding_id": "F-001",
      "verdict": "CONFIRMED",
      "provenance_exec_id": "EXEC-3f9a1c-0007",
      "verifier_tool": "list_files",
      "verifier_exec_id": "EXEC-3f9a1c-0019",
      "verifier_output_sha256": "…",
      "note": "evil.exe re-listed at C:\\Windows\\Temp\\"
    },
    {
      "finding_id": "F-002",
      "verdict": "UNVERIFIED",
      "provenance_exec_id": "EXEC-3f9a1c-0008",
      "verifier_tool": "analyze_memory:netscan",
      "verifier_exec_id": "EXEC-3f9a1c-0021",
      "note": "claimed C2 192.168.1.99 not present in re-run netscan — confidence HIGH→MEDIUM, flagged"
    }
  ]
}
```

The final report's **Verification Ledger** and **Audit Trail** sections are
rendered from this file.

---

## Caps and guards

- Verify **every** finding (this is labeling, not remediation — no cap). For very
  large finding sets (>40), verify all CRITICAL/HIGH first, then MEDIUM, then LOW;
  note any LOW findings left at verdict `UNVERIFIED` (pending) in the ledger.
- Verification is **read-only re-derivation** — it never edits evidence and never
  fabricates a confirming result. If the verifier tool errors, the verdict is
  `UNVERIFIED` (not CONFIRMED).
- A `CONFIRMED` verdict **requires** a non-empty `verifier_exec_id`; a finding with
  no recorded verifier execution cannot be CONFIRMED.
- Feeds the persistent loop: a non-zero `unverified` count is a loop continuation
  signal (see `persistent-loop.md`).
