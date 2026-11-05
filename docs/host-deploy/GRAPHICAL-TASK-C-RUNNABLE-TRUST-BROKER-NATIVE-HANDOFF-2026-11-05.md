# Task C — runnable trust broker source and disabled installer handoff (2026-11-05)

**Status: source implementation and exact-head tests PASS; native broker activation NOT AUTHORIZED.** This handoff supplements `GRAPHICAL-TASK-C-TRUST-BROKER-HANDOFF-2026-11-05.md`. It does not claim the original graphical authority exists or that Work can enable the broker today.

## Exact selected dependencies

- root-control PR #39: `5ad7d5ed72d1b72edc767a658de28506791a74d4`
- host-install PR #30 original-tuple continuation: `c2b0dda53421632c584542453c7379067ed135ef`
- host-deploy PR #26 source branch: `review/task-c-original-identifiers-call-denial-20261104`, with newly added broker daemon and installation contract
- Currently installed disabled root-control/host-install candidate is **not** a broker installation. Old host-install PR30 gateway pin `c46c6b5819b1f4496de1b860aa2785812244493e` must be explicitly repinned after review, never treated as the new broker source.

## Runnable source implementation delivered

1. `src/zog/host_deploy/gateway/graphics_owner_trust_daemon.py`: strict root-only, systemd socket-activated **AF_UNIX SOCK_STREAM** service entry; exact one inherited fd and name, no self-binding or alternate listener, authenticated peer UID/GID and root-control's installed PID/cgroup/executable starttime witness, one bounded canonical request/response frame, deny-on-error. Calls only protected original operator/GitHub evidence verification and fresh original S3 read-only history via `graphics_owner_trust_service.attest_original`; never creates claims, signs an owner SSM result, issues a command or changes checkpoint history. Handler can be exercised against an independently supplied `InstalledReadOnlyAuthority`. `main()` remains hard denied by `NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED=False`; `installed_runtime()` also holds until a separately reviewed native root/host-install authority provider exists. These are **deliberate native gates**, not missing test configuration.
2. `deploy/graphical-trust-broker/zog-graphical-trust.socket` and `zog-graphical-trust.service`: standalone inactive unit templates, exact `/run/zog/graphical-owner-trust.sock`, root-owned `0660`, bounded socket activation, `ProtectSystem=strict`, empty capabilities, no installation/enablement target, separate **read-only-checkpoint.json** and **broker-private.key** `LoadCredential` slots. No checkpoint-writer or SSM sender credential slots. Host-install must stage the original read-only session and broker key under protected ownership; the gateway must have access to neither.
3. `graphics_owner_trust_install.py`: pure source-byte and disabled-manifest validator. Requires exact fixed set of gateway trusted source module bytes and unit hashes, original Host/installation/STATE/scope, original account/prefix/genesis **and checkpoint writer role**, distinct read-only broker/owner-S3-writer/SSM sender role ARNs, gateway UID/GID/cgroup/image pin, root-control original source and no enabled/admitted boolean. Returns `SOURCE_SELECTION_DISABLED` and all native acceptance booleans False. It does not install anything and cannot self-authorize.
4. Source regressions in `tests/test_graphics_owner_trust_daemon.py` and `tests/test_graphics_owner_trust_install.py`: canonical single-frame, wrong peer, oversized/duplicate request, no-runtime admission, no direct SSM/STS/S3 write, exact no-replacement original authority, changed wheel or unit bytes, role aliasing and no early activation.

## Exact source CI

- [Signed-v2 cross-owner #42087329399](https://github.com/zog144/host-deploy/actions/runs/42087329399): **108 PASS Python 3.12 and 108 PASS Python 3.13**, pinned root-control PR39.
- [All graphical SSM paths #42087329406](https://github.com/zog144/host-deploy/actions/runs/42087329406): **71 PASS each Python lane**.
- These runs cover source fixtures and synthetic root-owned test seams only, not actual installed authority or AWS/IAM.

## Concrete root-control + host-install native contract

**host-install Regular** should select the reviewed host-deploy PR26 exact head, package these five gateway modules in a separately authenticated wheel and verify all wheel RECORD and unit bytes. Install the exact broker unit pair **disabled and inactive** alongside the existing inactive owner pair, without changing existing certificate authority, original retained STATE, or shared Host role. Pin the actual source revisions, original installation, real gateway UID/GID/InvocationID/service image and independent `APPROVED_PIN_SHA256` using protected installation custody. Do not use a gateway-controlled file or env variable as pin authority.

**root-control Regular + host-install Regular** must provide `InstalledReadOnlyAuthority` through an actual reviewed native constructor, including original operator-signed preflight/stage mappings and independently signed GitHub-event receipt, original key epochs, *independently retained* S3 origin tuple and external anchor, pinned owner observation key, broker Ed25519 signing key, protected read-only S3 client and current history witness. The origin must match account, region, bucket, prefix, scope, genesis and original writer role. The read-only role is distinct from the owner writer/SSM roles and must have no SendCommand, checkpoint Put/Delete/overwrite, PassRole or credential-recovery path. Native installer and IAM must verify **actual** GetObject behavior, including how the root-control S3 scanner distinguishes the first missing sequence: missing-object `AccessDenied` must HOLD, not be treated as a successful current head. Never grant unreviewed ListBucket merely to make a missing-key read look like `NoSuchKey`.

**Work** must independently authenticate true original authority bundle and gateway identity, source/RECORD/interpreter/unit bytes, credential and mount custody, then test disabled install, carefully authorized activation, peer identity and fresh nonce, two separate irrevocable operation claims, read-only `observe-original`, changed S3 history, revocation, process crash/reboot and actual gateway principal's SendCommand/STS/IMDS denial. No owner positive SSM action until the separate user-approved native send gate.

**Fail-closed GO decision:** no authentic original graphical authority mapped to the retained installation and no native broker constructor or independently chosen pin has been accepted. Do not flip the admission constant, enable a socket, run a broker on a synthetic original, create a new S3 genesis or perform a graphical SSM send. This source handoff is ready for independent native-provider integration, **not** complete native installation.

No EC2/STATE/AWS/IAM/S3 mutation, key generation, service activation or compilation was performed.
