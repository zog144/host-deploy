# Task C signed-v2 protected-owner consumer — 2026-11-05

**Status: source cross-owner CI PASS; native activation NO-GO.**

## Exact companion source
- Root-control PR #39 selected exact commit `5ad7d5ed72d1b72edc767a658de28506791a74d4` (v2 `TaskCExecutor`).
- Host-install PR #30 selected commit `60ac6c2a84b2f5dd96474bb647ed3cc4665dfbce` (disabled installation selection, not installed here).
- Host-deploy PR #26 contains this source-only consumer on `review/task-c-original-identifiers-call-denial-20261104`; no production repin or activation.
- Signed-v2 workflow: https://github.com/zog144/host-deploy/actions/runs/42033222318 — **56 passed** each on Python 3.12 and 3.13.
- Existing all-SSM paths workflow: https://github.com/zog144/host-deploy/actions/runs/42033222402 — PASS both Python lanes.

## Implemented

`graphics_owner_observation_v2.py` validates root-control's exact `zog-graphical-task-c-owner-observation-v2` schema using domain-separated Ed25519 over canonical bytes. An independently pinned 32-byte public key and its SHA, approved original owner-request digest, exact S3 scope digest, Host ID, installation ID, STATE volume ID and current authority epoch are mandatory. It verifies nonce, original operation ID, original GitHub request SHA, command ID shape, SSM state/status coherence, revocation, and the externally current S3 sequence and hash-linked head. A wrong key, changed source, stale external sequence/head or revoked scope denies. A valid signature is read-only evidence, never a SendCommand grant. No unsigned v1 response is accepted.

`graphics_owner_ipc.py` now recognizes the selected v1 **request** frame with exact original GitHub issue/actor/request identity but accepts only the verified v2 **response**. The request contains neither arbitrary shell, target, credentials nor private signing material. `observe-original` uses the same fixed, bounded Unix stream transport as preflight/stage and never initiates a claim or SSM send. A pending preflight is checked once through read-only observation; success must be independently signed and carry the original SSM CommandId and `ssm_state=success` before the stage proceeds. Pending/failed/uncertain/revoked results hold or deny. Stage returns only the original signed CommandId in allowed pending/success states; failures never masquerade as readiness.

Cross-owner tests consume actual signed outputs of root-control PR #39's `TaskCExecutor`, using its synthetic installed registry, S3 append-only checkpoint and fixed SSM sender. They demonstrate original separate preflight/stage operations, a pending preflight followed by `observe-original` without a second send, and rejection of a previously valid signed observation after S3 history advances. Negative tests cover unsigned v1, altered signed identities, wrong key, stale external S3 witness, duplicate canonical fields, contradictory SSM status and missing native pins.

## Native block and trust dependency

`_trusted_selection_for_original` and `_current_external_history` intentionally refuse runtime use until host-install and root-control supply independently authenticated installed signer/current mapping and a **fresh independently retained S3 checkpoint witness**. This must not come from gateway journaling or an untrusted IPC reply. A correctly signed old observation can still be stale after newer checkpoint transitions, therefore the consumer demands sequence + head equality with the freshly trusted external current history. Root-control's selected v2 executor also rereads S3 under its serialized authority before signing.

The installed trust/witness provider must be reconciled with root-control/host-install's separate S3 and SSM credentials: do not give the gateway owner credentials merely to satisfy witness reads. A protected read-only owner observation or separate trusted checkpoint reader needs independently reviewed anti-rollback and freshness properties.

No native service was started, no AWS/SSM command sent, no gateway IAM isolation proved and no source candidate merged. Until Work demonstrates actual pinned signer/source, current external S3 witness, approved original preflight/result and the normal gateway→protected-owner→SSM path, **graphical compiler submission remains NO-GO**. Legacy direct-SSM helpers must not be selected for graphical work. Optional denial of direct SSM/STS/IMDS to a distinct gateway service principal provides defense in depth; it does not prove the explicitly trusted Host administrator lacks SSM capability.
