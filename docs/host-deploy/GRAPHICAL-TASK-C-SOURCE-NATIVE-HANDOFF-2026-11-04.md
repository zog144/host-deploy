# Task C — graphical source-to-native gateway handoff (2026-11-04)

**Status: partial source implementation; native NO-GO.** This document does not authorize an SSM send, IAM change, native installation, or catalogue activation.

## Reviewed baseline

- host-deploy draft PR #23 selected old head: `aad113ac672df74b18abd0286176a352463b52c1`
- root-control selected owner PR #30: `ad5985ee602f24cbb5d45ef259c31d6c5a13e386`
- PR #23 source CI before this work: 59 tests each on Python 3.12/3.13 (run #41836898664).
- PR #23 already identified unfenced `producer_runtime_preflight -> Host.command -> SendCommand` and replaced it with a protected-preflight stub. It also removed the selected graphical stage's direct `Host.submit_command` call and denied the legacy graphical `submit_prepared` route.

## Current source changes on PR #23

- Carries forward `graphics_owner_ipc.py` source from PR #22 and selects a **fixed** `/run/zog/graphical-operation-owner.sock` AF_UNIX client for both original stage submission and its separately claimed preflight.
- Before either selection, `generic_pipeline._protected_original_identifiers` reopens the durable original gateway request, verifies its canonical request digest, `build.submit` operation and immutable GitHub `origin` (repository, issue number, triggering actor). The IPC envelope carries the original GitHub identity, exact request ID/hash, immutable operation ID/stage/ordinal and frozen binding/remote request hashes. It does not carry SSM credentials or shell script. All fields are lookup hints; the root owner must independently authenticate original GitHub authorization, original operation mapping and preapproval.
- Separately domain-separates the preflight operation ID as SHA256 over `zog-graphical-original-preflight-v1:<original request ID>:<stage operation ID>`, truncated to the existing 32-hex operation-ID convention. The native owner must independently *preapprove* this operation ID and its **complete** fixed preflight request; the gateway computation is never an authorization grant.
- Retains existing operation-specific independent root claim semantics, no replay, no gateway direct SSM fallback, uncertain/lost-ACK hold and read-only recovery.
- Adds source tests to check original GitHub issue/request binding, two distinct owner operation IDs, no shell/timeout delegation over IPC, missing-owner denial, and unsigned preflight denial. Updated selected exact-head CI to include the new tests.

## Critical limits that prohibit native GO

1. **Root owner not implemented:** there is currently no installed owner service at the socket, no independent monotonic ledger, no separately protected actual IAM sender, and no root-installed signed original GitHub approval mapping.
2. **Native IPC not yet authenticated at the independently selected authority level:** `SO_PEERCRED` root UID and root-owned paths are necessary but insufficient to prove exact native owner binary/issuer/current checkpoint. The current IPC source carries unsigned responses; preflight responses **always deny** rather than fabricating `authenticated=True`. A real root-control-selected signed response format + independently protected pin/highwater verifier is still needed; do not treat a caller-supplied `authenticated` boolean as proof.
3. **Unreviewed native send preflight acceptance:** root owner needs distinct durable claim and command/result readback for preflight, with revocation linearized against both preflight and stage-send. A stage may not reuse its claim for preflight.
4. **Gateway SSM IAM still unsegregated:** Python source removal cannot deny raw SDK access by a credential-bearing gateway principal; host-install/Work must prove direct SendCommand, STS assume-role and IMDS paths deny for real deployed gateway UID and all legacy helpers.
5. **Native operation request mapping:** current PR #30 fixture cannot consume the new IPC frame directly. The server contract must be jointly reviewed with root-control/host-install, including original GitHub issue/actor/request SHA, immutable preflight ID and response proof, no caller-selected target/payload and no fallback.
6. **Execution evidence:** original-stage and preflight external CommandIds, reboot persistence, concurrent sending, revocation, lost ACK, whole gateway rollback, power loss and installed-byte/source/pin verification remain Work-only.

**Owner handoff:** root-control Regular/Work implement native authority service, signed observations, original immutable owner mapping and monotonic ledger; host-install Work installs protected socket/service/pins and independently separated SSM credentials; host-deploy Regular completes exact source interop once the native owner protocol is accepted; host-deploy Work checks each graphical SSM command and actual gateway-principal denial. Do not merge/activate based on gateway source CI alone.
