# Bounded graphical generation chaining — protected source contract

Date: 2026-10-31. Owners: host-deploy Regular and image-build Regular (source); root-control Regular (independent review); Work owners (native).

This draft PR is source-only and stacked on the refreshed first-fonts catalogue PR #7. It is NOT native compiler admission.

## Frozen sequence

Only three tasks are allowed, in this order:

1. graphics-fonts-image-v1 — the protected first catalogue and independently accepted self-hosted base.
2. graphics-xcb-core-image-v1 — selected from the accepted, immutable fonts output generation.
3. graphics-x11-core-image-v1 — selected from the accepted, immutable XCB output generation.

There is no automatic submission, fourth step, manual base-generation override, wildcard recipe, replacement attempt, background compiler retry or project/lane fallback.

Source remains image-build 1f07e83dbd80dacb9bed0d6494c697375f0e26cd. Monthly pin remains the original October 1 source, SHA-256 d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36.

The operator must first approve a canonical root-owned 0600 graphics-generation-chain-policy-v1.json in protected owner-state on the dedicated external 2-GiB volume. It binds exact Host ID, installation, lane owner, Project, original fonts catalogue and install-receipt digests, accepted base generation and receipt, producer source/pin, exact three task names, the fixed 30+2 GiB reservation, and the 21,600-second execution limit. The approval is not a GitHub request field or a replaceable user-supplied JSON file.

## Successor acceptance

The pure resolve_successor function consumes an immutable previous catalogue/receipt and a normalized accepted-generation record. Source-level structure checks require exact previous task/request/pipeline, previous catalogue SHA, selected input, source/pin/Host/lane/installation, a distinct 64-hex accepted image output, canonical manifest, producer and acceptance receipt hashes, success with zero missing evidence and uncertainty=false.

The normalized record is only trustworthy when supplied by the exact installed image-build attester at source `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`. A pipeline.inspect status of completed is not itself accepted-generation evidence. The producer reader independently reopens the genuine image-build generation catalogue/manifest, canonical build-record provenance, source/recipe pin snapshot, installed verification and durable pipeline/remote-operation records. It rejects stale/released/rolled-back/incomplete/foreign results. Its `acceptance_receipt_sha256` is the existing canonical build-record generation-root record ID, and `producer_receipt_sha256` is the SHA-256 of the exact retained completed producer result bytes; neither is a synthesized acceptance file.

Host-deploy's `graphics_generation_attester.installed_capability(...)` is the protected consumer adapter. It reads the root-owned chain policy itself, derives exactly one admitted/completed predecessor request from the durable gateway ledger, revalidates the frozen current lane/dispatch and clean exact source/build-record/controller checkouts using read-only Git commands, then invokes `python -B -s -m zog.image_build.graphical_generation_acceptance` through the lane's frozen Python/PYTHONPATH. Trusted context is sent on stdin. No output generation, recipe path, shell command or context file is accepted from the GitHub request.

The root-only install_next_native operation validates protected file ancestry and exact mode-0600 records, demands the local trusted Host/source/boot/exclusive-idle attester, rereads existing 30-GiB build and 2-GiB external reservation inspectors and invokes the trusted generation-attester capability. It creates only one new immutable successor catalogue and receipt using O_EXCL, fsync, hash reread and no replacement/auto-repair on partial failure. Existing catalogues remain immutable. This is not a compiler authorization.

## Regular-chat gateway binding

The compiler-Host native owner alone validates the original root-owned 0600 fonts catalogue and immutable successor files. The command-center supervisor is **unprivileged** (DynamicUser), cannot read the compiler Host's owner-state, and requires an independently installed root-owned 0444 public signing-key/Host/installation/boot/epoch/policy pin plus a fresh signed compiler-Host export of each selected catalogue. Operator opt-in still requires the exact first-catalogue digest and approved-graphical-chain-policy-sha256; GitHub requests cannot change either.

On each admitted, allowlisted graphical build.submit, the **compiler Host** reads its own protected files with load_installed_step while the **command center** uses graphics_chain_export.load_selected_step to verify the signed export, exact Host/installation/lane, approved original stage, immutable source revision, October pin, expiry and catalogue SHA. The gateway freezes that per-request digest and requires its fsynced stage-once record before dispatch preparation and before generic advancement. A stale, missing, revoked, conflicting or foreign export cannot advance. Other generic tasks retain their separate behaviour.

The acceptance-reader and immutable predecessor-composition source contracts are now implemented at image-build `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`. The original fonts and XCB predecessor remain **kind=image** and never masquerade as the toolchain.

For both graphical successors, `arguments.selection` stays the original accepted stage-2 toolchain generation `first_base_generation_id`; `arguments.graphical_predecessor` is the exact output-generation ID verified by the protected predecessor attester. XCB layers the accepted Fonts image. X11 layers the accepted XCB image, whose output contains inherited Fonts files. Producer `graphical_composition.validate` reopens the canonical immutable predecessor root/manifest, verifies its build-record closure and completed installed verification, checks the original toolchain lineage and finite stage, and merges it into disposable per-package build roots and the new published image without overwriting files. Both IDs, the predecessor manifest digest and build-record record ID are frozen in pipeline/package/generation inputs.

The original image-mode toolchain-kind guard stays intact; the absence or tampering of a predecessor is not permission to use arbitrary image roots.

**Not an authorization to compile:** independent native Stage A admission, accepted Fonts image verification, protected compiler-Host/nonroot gateway trust review, and installed-source attestations are still required. A `pipeline.inspect` success alone cannot advance any protected step.

## Unresolved native gates — NO-GO

Neither the actual accepted base generation, protected chain policy, native predecessor attester nor successor stage files have been installed by this source change. Do not enable its gateway flag, merge the PR, run a canary, submit a compiler job or touch retained hosts based on isolated CI.

Before native enablement: independently attest exact installed image-build/root-control/host-deploy source and wheel RECORD; verify current Host, boot, active managed lane and owner; prove the genuine first base and previous accepted image-generation records, no competing writers, full 30+2 GiB reservation, six-hour deadline, genuine PID1 sidecar/worker containment, HugeTLB denial, FD/mount isolation, cancellation, cleanup, uncertain attempts and reboot hold. Use separately approved disposable infrastructure for native testing.

## Next owner handoffs

image-build Regular + host-deploy Regular: immutable predecessor composition is source-implemented at `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`. Review exact-root ancestry and the protected gateway/export trust boundary independently before native adoption.

root-control Regular: independently review the protected native attester trust model, root-only 0600/O_EXCL safety, state filesystem and symlink provenance, peer process/UID/GID, one-time policy pin, no sibling/retained-Host mutation, duplicate suppression and lifetime/boot constraints.

host-deploy Work + root-control Work + image-build Work: only after the separately approved Stage A canary/worker admission and genuine fonts compilation, prove exact installed bytes and accepted output, then a protected XCB successor; similarly for X11. No substitution of synthetic CI evidence.

Status: source-only, draft/unmerged; native admission NO-GO. Host-deploy issue #5 remains open.


## 2026-10-31 immutable composition source update

Exact producer CI [41254252027](https://github.com/zog144/image-build/actions/runs/41254252027) PASS: 1,793 files / zero preflight findings, 371 source tests passed + 1 skipped, 72 remote-producer tests passed. First-catalogue [PR #7](https://github.com/zog144/host-deploy/pull/7) repinned at `78a772a6542dba660ddaa4223b28593c0251f810` with both exact-head checks PASS. This changes no October pin bytes, fixed 30+2 GiB limits, six-hour deadline or native authority values.


## 2026-10-31 PR #8 + PR #9 integration

The integrated source includes PR #8's non-root signed cross-Host export, shared protected worker-promotion lock, fixed native attester entrypoint, O_EXCL/fsync and durable stage-once/no-replay checks **together with** PR #9's immutable toolchain+predecessor composition source pin `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`. The original October source pin digest remains `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.

**Native NO-GO:** the compiler-Host signing authority and independent public-key pin are not installed; the real authenticated original gateway request/dispatch handoff is not provisioned; full native systemd252 worker/quotas/deadline/containment and root-control re-review are outstanding. CI is source-only and uses fixture key material. No protected work is authorized by this merge.
