# Independent graphical compiler replay review — source findings

**Date:** 2026-11-03. **Scope:** host-deploy [PR #15](https://github.com/zog144/host-deploy/pull/15) at immutable head `5c9a728c4c253ecf8929cb9c520b7b9ae3b25485`, stacked on [PR #14](https://github.com/zog144/host-deploy/pull/14) at `5a4b3098c188df8de3cd5e7ac9ca4ef66fa3bc6b`. Source-only; no AWS, SSM, SQS, compiler or native protected STATE.

## Positive observations

PR #15's `generic_pipeline._read` reconstructs the complete remote request from the frozen dispatch task, selected source/lane, operation ID, stage name and retained snapshot/pipeline parameters. It rejects changed mode, base generation, targets, graphical predecessor, remote operation and recomputed unkeyed request SHA. It also bounds stage order and ordinal. The existing `graphics_stage_once.require_record` verifies an immutable **per-request+lane+task+catalogue** stage claim, not a per-operation SSM send history. The 216-test [exact-head PR15 workflow](https://github.com/zog144/host-deploy/actions/runs/41651435242) passed.

## Remaining blockers independently reproduced

### B1 — rollback of an unchanged prepared journal replays the original SSM operation

`generic_pipeline.advance` records `submitting` before calling `Host.submit_command` and refuses restart when it sees a retained `submitting` state. However, `generic_pipeline._read` has no independent immutable highwater for the saved operation history. If the journal is restored to a previously valid `prepared` snapshot **after** a successful synthetic `pipeline.submit`, all PR #15 request/ordinal/source/hash checks still pass. The next `advance` calls the synthetic Host `submit_command` a **second time with the same original operation ID**. `graphics_stage_once.require_record` also still passes: it only claims the task once for the *same* original request, and cannot distinguish one vs two SSM commands for the same phase.

**Evidence:** `tests/test_gateway_graphical_replay_invariant.py::test_rollback_of_submitted_pipeline_prepared_state_must_not_send_again`, current strict XFAIL. This is an **attempt replay**, not proof that the image-build producer executes a second compiler pipeline; producer-side idempotency may still reject it. The gateway boundary nonetheless reissued an SSM command when it should have held uncertain.

### B2 — a forged matching snapshot result can select a new recipe snapshot

`_read` compares a completed `recipes.snapshot` result's `recipe_identity` and `artifacts.recipe_snapshot` to the journal's `recipe_identity`. All three are in the **same mutable local journal**. A source-level synthetic rewrite of all three, plus `pipeline.submit.arguments.recipe_snapshot` and its unkeyed hash, passes the new request reconstruction and issues a `pipeline.submit` with the substituted SHA. The original SSM snapshot receipt and command identity were **not independently re-read or authenticated** before using this recipe snapshot. The producer may reject a nonexistent snapshot, but the protected source boundary must not equate local self-consistency with an authenticated producer result.

**Evidence:** `tests/test_gateway_graphical_replay_invariant.py::test_coherently_rewritten_snapshot_history_must_not_submit`, current strict XFAIL. No compiler ran.

### Existing successful boundary (control)

With the honest latest journal recording `submitting`, the existing `advance` code correctly enters uncertain/HOLD and does not resend. The isolated regression `test_actual_submitting_record_remains_uncertain_and_never_auto_retries` passes. PR #15's 216 existing tests remain passing.

[Review-branch CI](https://github.com/zog144/host-deploy/actions/runs/41690321451): **217 passed, 2 expected failures** at `a7508a746bde9c80a63395f3a4e81fec19d2868a`. Strict XFAIL is a **known unresolved security obligation**, not an approved negative test.

## Required correction, next owner: host-deploy Regular + root-control Regular

1. **Per-operation durable native admission/send fence** outside the rollbackable generic-pipeline JSON. Bind original admitted request and frozen protected catalogue identity, Host/installation/lane/current authorized epoch, stage name and ordinal, operation ID and request SHA, write a durable intent **before** the first SendCommand, and never clear/re-issue it on unknown ACK, cancel, failure or reboot. Lock against concurrent alternate admin and poll dispatch. An existing intent with no confirmed command ID must HOLD/reconcile with independently observed original history; it must not call SendCommand again. Test coherent journal restoration, partial publication, same-byte retry, original ID recovery and lost ACK.
2. **Authentic completed producer snapshot history**: before any `pipeline.submit`, verify its selected `recipe_snapshot` against an independently retained/attested original `recipes.snapshot` SSM receipt (original CommandId, request digest, source revision, Host/installation/operation identity, status), not only the locally editable generic journal or a caller-provided `result_sha256`. A copied or coherently rewritten JSON + SHA is not proof. Deny unverifiable/stale/changed receipt, revoked authority or missing remote observation; hold rather than fabricate a snapshot.
3. Preserve the existing root-only original request / stage-once grant, non-root gateway identity, current independently signed checkpoint and protected attester. Do not create a new submission route or use the review tests to authorize one.
4. Add acceptance regressions that **PASS rather than XFAIL** on the corrected code, with at most one simulated SSM SendCommand per original phase under journal rollback, stale generation/snapshot substitution and reboot/unknown acknowledgement; rerun PR #14/#15 exact combined source CI and request independent root-control review before native acceptance.

## Disposition

**PR #15 is correct for request-argument substitution, but not sufficient for full replay/history acceptance. Source security: CHANGES REQUIRED. Native compiler: NO-GO.**

This is a separately authored source inspection and synthetic evidence, **not** independently installed native issuer or compiler evidence. The PR and review branches stay draft/unmerged; no AWS or native operations.
