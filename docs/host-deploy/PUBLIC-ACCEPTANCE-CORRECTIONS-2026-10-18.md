# Public migration acceptance repairs — 2026-10-18

**Source owner:** host-deploy Regular. **Disposition:** private source-only repair candidate; **not** permission to publish, use production accounts, install root services, or repoint a retained beacon.

The acceptance baseline was Work's `cc1e8249603f31eb4053143ba8a163e5d8d7583b` report: 441 passed, 14 failed, 14 skipped, three collection errors under UID 65534; focused workflow source run 77 passed, two failed. No claim of acceptance is made for the revised tree until Work reruns those gates.

## Repairs supplied

1. **Certificate renewal syntax:** removed only the duplicated `else`, preserving the controller-owner `geteuid` check **and** same-UID `verify_controller_runtime` call before `build_controller`. Selected broker remains barred by `_require_approved_native_inspection`; source compile and installed renewal entry point must be rerun.
2. **Gateway workflow tests:** the obsolete issue-triggered dispatch expectation is replaced by an inert public workflow assertion. The immutable Node24 action test recognizes both `uses:` and YAML `- uses:`. The public source CI includes `compileall` over source/tests/scripts before pytest.
3. **Companion closure:** a new optional `--include-closure` in `scripts/review_public_companions.py` inspects **all tracked** per-component runtime package files, deployment assets, license texts and pyproject metadata from exact clean public Git checkouts. It provides SHA-256 hashes and explicit dependency conflicts, with `approved=false` always. The historical 48-file descriptor remains untouched/unusable against changed public source; newly required host-discover `certificate_assignment.py` and host-install `certificate_gate.py`, `welcome_readiness.py`, `certificate_lifecycle.py` are no longer excluded from the *reviewed candidate closure*. This is **not** yet a released beacon payload.
4. **Version admission:** the privileged beacon installer validates staged package version metadata and included license files before owner mutation. It rejects `host-discover@0.4.8` requiring `host-install==0.4.4` against proposed `host-install@0.10.0`. After installing, it verifies actual distribution versions, `pip check`, exact source-manifest identity and a release-specific durable ready receipt; an old 0.4.6/0.3.4/0.4.4 marker cannot authorize a different release. The public companion owner must choose and test a **coherent** release set, not suppress pip dependency checks or forge a version.
5. **Operational identifiers:** real account, compiler EC2 instance, adopted workspace and ownership epoch were replaced by synthetic test values; examples now contain deliberately nondeployable account/bucket, AMI, subnet, SG and instance-profile placeholders. The station-production guide uses generic, explicitly nonrunnable project, user, UID/GID, generation, socket and manifest examples. The runtime-configurable legacy default transfer bucket `zog-host-deploy-1` was **not** modified without a separate user/product decision; its documented default still needs review.
6. **Source-only vs privileged fixtures:** atomic writes retain their real root-only `fchown` operation in production. Source unit tests simulate only the ownership setter while retaining regular `fsync`/rename/rollback behavior, and test native permission-denial propagation. They do not create root-owned files as UID65534. True native ownership and certificate/root-control/systemd tests remain separate confined Work acceptance.

The source-only public CI also exercises synthetic hash-bound beacon payloads, companion closure negatives, metadata equivalence, beacon atomic staging and station atomic updates without private companion checkouts. The historical exact-pin payload test is opt-in under `HOST_DEPLOY_HISTORICAL_PIN_ACCEPTANCE=1` with independent private test fixtures, never a public CI requirement.

The `zog-component.json` CLI and package-data declarations now match the eight script entry points and the station/gateway/certificate service units declared in `pyproject.toml`. Wheel/sdist metadata and runtime entry points still require actual Work readback.

## Remaining cross-owner gate

The currently selected new public **host-discover** pyproject requires **host-install==0.4.4**, while the new public **host-install** candidate reports **0.10.0**. This is a real dependency incompatibility—not a test fixture failure. Host-discover/host-install Regular owners must agree on an actually interoperable selected set, including namespace, STATE grant, certificate module imports, service commands and wheel license closure. Once they provide exact immutable revisions, Work must rerun source/native API tests and only then permit host-deploy to regenerate the reviewed `beacon_sources.json` selector from full closure hashes.

Also pending are a clean full source audit on this **new** commit, nonroot tests, confined native privileged tests, an independently reviewed clean-history zero-parent public export, real public GitHub Actions execution, and explicit separate owner GO.

**No live AWS, SQS, SSM, compiler, station, archive, Certbot or nginx resource was changed in this source correction pass.**

## October 18 companion resolution addendum

The host-discover producer supplied exact immutable source
`0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80`, reporting version 0.4.9
and requiring host-install 0.10.0 and host-identify 0.3.4. host-deploy
Regenerated six-component public candidate metadata and the full beacon
source closure (90 content SHA256-pinned files). The former conflicting pins
remain in this document **only as historical acceptance findings**.
The live beacon installation and public publication continue to require
isolated validation and explicit operator approval.
