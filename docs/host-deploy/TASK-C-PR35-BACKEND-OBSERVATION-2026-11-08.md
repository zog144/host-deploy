# Task C registry backend-bound source consumer — 2026-11-08

**Disposition: source integration and exact-pinned cross-owner regression PASS; native admission remains NO-GO.** This is the required follow-up to [host-install PR #35](https://github.com/zog144/host-install/pull/35), whose final source commit is `24376bd784b7efcc1e393188f792c41685e75f79`. It does not install or authenticate the true selected registry Host.

## What the gateway can review now

New `src/zog/host_deploy/gateway/graphics_registry_backend_source.py` calls the exact host-install v2 registrar-mapping verifier, checks its closed **source-only** result contract, and refuses every verified-looking native permission flag. The API returns only `native_accepted=False`, `broker_admission=False`, `ssm_authorized=False`. It does **not** issue a grant or forward mapping JSON/flags into the installed Task C broker.

The selected v2 domain binds enrolled legacy Host/fingerprint, selected signed installation and STATE/registry/ID tuple, AWS instance/region and independent pinned registrar/registry signer. In `root-directory` mode the signed snapshot includes mount IDs/devices, root UUID/PARTUUID, directory inode/UID/GID/mode and marker digest; `mounted-volume` mode has a different field set, EBS identity and mounted-state requirements. Historical v1 mapping is not silently migrated.

Source-negative tests reject mode swaps, signature or marker substitution, mounted directory identity mismatch, copied EC2 identity, injected native authority and attempts to treat an otherwise valid v2 registrar mapping as proof of a protected owner. These tests import host-install's real PR35 fixture and exact root-control PR47 consumer, pinned by the GitHub workflow; they use synthetic signatures and do not read a physical Host.

## Missing AUTHENTICATED native observation: the outstanding Work boundary

**The proposed per-invocation protected native observation provider does not exist and is explicitly disabled** (`NATIVE_BACKEND_OBSERVATION_PROVIDER_INSTALLED=False`, `require_native_backend_observation` denies without exception). A signed mapping proves only the signed record relative to its inputs; even a valid Ed25519 signature is not current /state proof. **Do not** substitute a caller `native_accepted` Boolean or a trusted-looking Python dict.

To enable native admission in a *separate* reviewed installer change, host-install/root-control must independently select an installed privileged reader and authenticate, at the exact current Host and invocation:
- Real host-discover/host-identify enrollment, authenticated AWS IID/account/region and installed Host/installation/STATE/registry identity and public signer pins.
- Actual Linux mount topology from `/proc/self/mountinfo`, block filesystem UUID/PARTUUID, retained `/state` directory descriptor (dev/inode/uid/gid/mode), marker bytes, no path replacement, symlink or nested mount, and current `bootstrap.json` and `installation.json` evidence.
- Installed wheel RECORD/executable, systemd unit/sockets, authenticated peer UID/cgroup, nonce/current boot and bounded freshness, with anti-replay and protected ownership of the observation channel. A gateway-request-supplied mapping, verification flag, path or opaque asserted digest is not authoritative.
- Signed installation storage selection, independent external S3 anchor and two separate root-controlled Task C ledger and authority mounts. A root-directory `/state` shares the Host root filesystem; it is **not** an independent nonrollbackable checkpoint domain. Never substitute the registry `/state` directory for either Task C protected mount.
- Separate signed original operation approval/claim/revocation, GetObject-only trust-broker credentials, write-only owner S3/SSM credentials, real gateway SSM/STS/IMDS denial; no normal path around the protected owner.

Only an independently approved provider/installer that checks those facts may produce a usable native authority result. The current source consumer is **not** wired into the live `graphics_owner_trust_service` to avoid implying an installed observation was accepted. Root-control PR47 must independently adopt and enforce the same fail-closed boundary, then host-install/Work must re-attest the exact new source selections before activation.

## Source test chain and status

- host-deploy PR30 source commit `2d094a3c3fc0d38a0e299304a9b70e4f1516b2f8`; root-control PR47 `aff806b2f68cd2bb79986a22e6fbdbb8b9221c64`; host-install PR35 `24376bd784b7efcc1e393188f792c41685e75f79`.
- [Task C v3 three-owner CI #42485434573](https://github.com/zog144/host-deploy/actions/runs/42485434573): **104 passed** on Python 3.12 and **104 passed** on Python 3.13.
- [Legacy protected signed-v2 CI #42485434561](https://github.com/zog144/host-deploy/actions/runs/42485434561): **115 passed** on each Python lane.
- host-install's native-bound source tests (PR35) also pass per producer handoff; all test fixtures remain synthetic and source-only.

No actual backend observation, registrar signing, S3 history, root-owned mount, IAM change, installed source pin, live service, SSM command, gateway grant, Fonts issue, SQS submit or native acceptance occurred. Both native broker and gateway public pin remain disabled.
