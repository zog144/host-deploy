# Graphical protected owner IPC consumer source handoff — 2026-11-04

This is a **held source candidate**, not a native service, not a production configuration, and not evidence of independent durability or permission separation.

## Origin and exact preflight
- Work preflight: https://github.com/zog144/know-file/blob/451099be64433a013c4c0e76a3dbf335825c0f39/root-control/verification/graphical-owner-admission-preflight-2026-11-04/README.md
- Selected root-control PR #30: `ad5985ee602f24cbb5d45ef259c31d6c5a13e386`.
- Selected host-deploy PR #22 before this change: `12f9fbf8bf9b6800b2a23039c12997c72f2cc0ea`.

## Implemented only in host-deploy source
`src/zog/host_deploy/gateway/graphics_owner_ipc.py` defines a narrow Unix-domain socket client:
- fixed `/run/zog/graphical-operation-owner.sock`, no client-supplied destination, no alternate fallback;
- root-owned non-group/world-writable `/run`, `/run/zog`, socket identity checked with `lstat` (reject symlinks); AF_UNIX `SO_PEERCRED` requires uid 0;
- five-second bounded transport, <=8192-byte single canonical JSON-line response, duplicate JSON key rejection;
- fresh nonce and exact original request ID, operation ID, stage/ordinal, frozen binding digest and remote request digest; **no script, AWS target, credentials, signing keys, or owner-controlled dynamic arguments**;
- accepts only nonce/operation-bound `sent-original` and bounded original CommandId. Malformed/unknown/mismatched replies deny.

**Important:** This only verifies root peer UID and path ownership, not independently selected installed binary provenance, operator authorization, external ledger durability, or AWS credential isolation. The owner must independently reconstruct and authenticate every protected field from its preapproved immutable mapping; a legitimate gateway process still cannot authorize itself by formatting a request.

`tests/test_graphics_owner_ipc_contract.py` adds no-native negative tests for request-shape violations, wrong peer UID, nonce and operation substitution, extra response fields, duplicate JSON keys and valid canonical protocol shape.

## Deliberate activation block
`generic_pipeline._selected_protected_owner_sender` remains the existing unconditional NO-GO stub; **this IPC candidate is NOT connected to the actual send path**. Existing synthetic tests replace the stub. No privileged server, monotonic ledger, operator key, signed observation, SSM-capable owner principal, package installation or AWS IAM policy was implemented.

## Mandatory next work
1. **root-control:** implement installed fixed-code owner service, independent authenticator and key provenance, anti-rollback ledger and single serialized claim/send/revocation path, immutable original operation mapping, exact original SSM command/result reconciliation. The server must treat IPC request as a lookup hint, never as authorization, and must verify operator approval itself.
2. **host-install:** prove protected executable/service/socket source pins and identities, secure monotonic backing store *outside* gateway rollback domain, owner-only credentials, and deny all SendCommand/STS/IMDS credential recovery by the actual gateway principal.
3. **host-deploy:** cross-owner validate response semantics and authenticated owner provenance; provide only an exact canonical original operation lookup to the owner, then bind selected native transport to `_selected_protected_owner_sender` *after* protected installation and credential-separation tests. Retain local send-intent/original CommandId reconciliation, but never use a signed observation to call SSM.
4. **Work native acceptance:** power loss, concurrent calls, revocation, reboot, whole gateway rollback, lost ACK, real SSM readback, and direct SSM/STS/metadata denial by gateway UID.

**GO status:** source adapter authored, **not activated**. Production send and native compiler remain **NO-GO**.
