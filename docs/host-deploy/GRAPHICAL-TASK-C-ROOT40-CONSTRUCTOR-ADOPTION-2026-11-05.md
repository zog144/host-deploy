# Task C root-control PR40 authentic trust-constructor consumer — 2026-11-05

**Source-only integration PASS; native installation and activation NO-GO.**

## Source selection and change

- host-deploy draft PR #26 selects `zog.root_control.graphical_task_c_trust_authority.installed_readonly_authority()` in `graphics_owner_trust_daemon.installed_runtime()` at exact reviewed root-control PR #40 `b0aea19bd265bbf1bdcf0b90eec18269e3276458`, stacked on original root-control PR #39 `5ad7d5ed72d1b72edc767a658de28506791a74d4`.
- host-install PR #32 `339194dd39933c383041b10a5207be7d9312daab` selects the disabled broker and dedicated Python installation.
- host-deploy constructor implementation `c19944ba03d609fb405cab07aec48cfb691d6aca`; companion selection/workflow `5f9cee972252f6b6808190c9a58cff93cfebff9d`.
- **No gateway-provided approval, replacement S3 origin, CLI/env-selected role, test fixture or alternate constructor** can select native authority. Root-control alone reads original protected operator-purpose signature, independently issuer-signed GitHub origin, exact Host/installation/STATE and gateway identity, broker signer, pinned observation key and separate GetObject-only systemd credential.
- `main()` and `installed_runtime()` both remain blocked because `NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED=False`. Gateway `graphics_owner_trust_history.APPROVED_PIN_SHA256=None` continues to deny read-only broker use. No automatic service enablement or source-only positive test changes those gates.

## Exact-head source verification

- [Host-deploy signed-v2 pinned three-owner workflow #42118947818](https://github.com/zog144/host-deploy/actions/runs/42118947818) — PASS Python 3.12 / 3.13, root PR40 and host-install PR32 exact checkout.
- [Host-deploy all graphical SSM-path workflow #42118947874](https://github.com/zog144/host-deploy/actions/runs/42118947874) — PASS Python 3.12 / 3.13.
- `tests/test_graphics_owner_trust_constructor_pr40.py` asserts no native constructor call when admission disabled, delegates only to the exact selected root constructor in an **explicitly synthetic monkeypatched seam**, rejects malformed selections, verifies companion source pins and confirms original owner's source revision remains distinct.

## Remaining mandatory source-repin handshake

**Root-control PR40 currently hard-pins host-deploy broker source `76416b9d7ef64aac17b75b6ce06b98244fd487e0` and host-install PR32 selects that same old broker head.** PR26 has now changed after that reviewed pin. The upstream provider and installer must independently review this new exact host-deploy head and repin its selected source and manifest/wheel RECORD/unit-byte digests **before native admission**. Do not relax hash equality or accept a wildcard pin. The original root-control PR39 owner and original S3 record remain separate, unchanged authorities. Re-run the exact three-owner source integration on the final mutually selected heads; subsequent source edits require renewed review and no implicit acceptance.

## Native Work gates remain

Before permission to start/enable the broker, independently authenticate true operator-signed broker-purpose approval, issuer-signed original GitHub event, original S3 account/region/bucket/prefix/scope/genesis/**writer role** and separately mounted external anchor, mounted STATE and installation binding, original gateway executable/UID/GID/cgroup/boot identity, installed source/wheel RECORD and Python/unit/socket bytes, independently pinned broker signer and observation key, and fresh **GetObject-only** session. Read-only S3 role must prove existing and missing-next-sequence semantics: `AccessDenied` is never a confirmed end of history, and no default ListBucket grant is authorized.

Verify exact actual gateway service UID/GID/cgroup and kernel IPC peer against the selected original approval. Where a separate gateway-service AWS identity is configured, test its effective `ssm:SendCommand`, `sts:AssumeRole`, IMDS and owner key/read-only-key/credential-file restrictions **as optional defense in depth**, not as a requirement that the trusted Host administrator cannot access SSM. The selected shared-Host model does not claim root administrator isolation. The normal graphical gateway software path must always use the authenticated owner and immutable claims before SSM. GitHub Actions OIDC is separately SQS-dispatch-only. Test original preflight and stage with separate claims, read-only `observe-original`, nonce replay, stale history, revocation, crash/reboot and gateway rollback under independently approved native authorization. Never fabricate a replacement approval or S3 genesis to unblock a fixture. No SSM or graphical compilation on source evidence alone.

**No AWS, EC2, STATE, IAM, S3, key or service changes occurred.**


**Shared Host reconciliation (2026-11-06):** [versioned three-owner trust model](../../graphical-task-c-shared-host-trust-v1.json). Exact source pins, signed-v2 history/verifier code and hard-disabled native broker are unchanged by this documentation update. Service-principal IAM hardening must not be promoted into an impossible proof against the Host administrator, and may not replace operator approval, original S3 history or owner claims.
