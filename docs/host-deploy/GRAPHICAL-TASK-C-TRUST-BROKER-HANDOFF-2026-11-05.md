# Task C trust broker and read-only current-history provider — 2026-11-05

**Disposition: source integration and exact-head source CI PASS; protected broker native admission NO-GO.** This source handoff adds an independent broker protocol, not an installed service.

## Exact companions

- root-control PR #39: `5ad7d5ed72d1b72edc767a658de28506791a74d4`
- host-install PR #30 original checkpoint continuation: `c2b0dda53421632c584542453c7379067ed135ef`
- host-install PR #31 dedicated interpreter candidate: `ebe097b94a68cd4ae8723e13575103c180ea3579`
- host-deploy PR #26: `review/task-c-original-identifiers-call-denial-20261104`

## Implemented host-deploy consumer

`graphics_owner_trust_history.py` adds bounded read-only AF_UNIX stream trust/history request and canonical signed Ed25519 response verification at an independently pinned root-owned endpoint. Exact original GitHub request, issue/actor, preflight or stage operation, fresh nonce, installed signer key, separately approved protected pin SHA, owner-request digest, Host/installation/STATE/epoch, original S3 scope and fresh read-only external sequence/head/revocation are bound. The gateway receives no AWS role, SSM credential, checkpoint write credential, secret, script or arbitrary endpoint. Pin material is rejected unless its exact SHA is independently selected by installed reviewed code. `APPROVED_PIN_SHA256=None` deliberately prevents production use until native protected selection.

`graphics_owner_trust_service.py` is a source-only protected-side evidence assembler using root-control's original operator mapping and independently signed GitHub issuer evidence verifier, plus `S3AppendOnlyCheckpoint.current_witness()` read-only history. It verifies the retained original checkpoint account/bucket/prefix/genesis/scope and original source; same-genesis relocation is denied. Its inputs MUST be installed protected authority, including validated external reservation anchor, original operator/issuer, GetObject-only credentials and exact immutable source. It does not run as a service or install keys, credentials, S3 access or an authority. Native sandbox/peer/role separation is NOT proven.

`graphics_owner_ipc._trusted_selection_for_original` now delegates to this signed broker. `_current_external_history` consumes only the nonce-bound `AttestedSelection`. Broker `TrustUnavailable` and malformed nested `OwnerObservationDenied` are normalized to fail-closed gateway `OwnerUnavailable`/broker `TrustUnavailable`; no v1 unsigned fallback. Original preflight and stage claims plus `observe-original` remain separate, read-only observation never sends a second SSM command.

## Exact-head source tests and regression findings

- Signed-v2 exact-root-source workflow: https://github.com/zog144/host-deploy/actions/runs/42083015122 — PASS Python 3.12 and 3.13.
- All graphical SSM-path source workflow: https://github.com/zog144/host-deploy/actions/runs/42083014777 — PASS.
- Additional signed-v2 source workflow: https://github.com/zog144/host-deploy/actions/runs/42083004755 — PASS.
- Explicit negatives: unpinned/unavailable broker, incorrect Ed25519 key, source/Host/STATE/scope, altered original operation/nonce, missing or stale history, revoked history, duplicate fields, malformed authority epoch and no SSM/write/STS broker calls. Corrected the broker-layer error translation for v2 `OwnerObservationDenied` when the trust row is malformed. Updated real root-control executor integration fixture to return `AttestedSelection`.

## Native admission blocks

1. Root-control + host-install must independently review and install the exact broker source and its dedicated immutable public-key pin, original operator/issuer mapping, current observation key and protected original checkpoint anchor. Current broker source is **not** a native service entrypoint and offers no supported activation path. It is not safe to make a file writable to the gateway or accept a pin supplied by it.
2. The broker must have **GetObject-only** original S3 history credentials, strictly separate from protected owner checkpoint-write/SSM credentials. Work must independently verify original account, region, role, bucket, prefix, scope and genesis tuple against original retained authority and IAM; a signed reply alone cannot establish original installation provenance.
3. Read-only broker and actual fixed owner Unix sockets require independent installed source/RECORD, service peer identity, protected signer custody, role/IMDS/STS/SSM credential denial for gateway principal, and current-state reconciliation after reboot. No source fixture authenticates actual native service identities.
4. Before any live graphical preflight or stage, actual original operator/issuer approval, immutable GitHub event and S3 monotonic claims, signed-v2 accepted original SSM receipt, gateway denied direct sending and originally selected Host/installation/STATE must all be proved. Do not bootstrap a replacement S3 genesis or retry an uncertain send.
5. Existing retained certificate installation and inactive graphical owner units must not be repurposed as a graphical authority. Keep installation and sending disabled until independent acceptance.

**No native service started, no EC2/STATE/IAM/S3 modification, no SSM command or compiler submission, and no source promotion or PR merge.**
