# Bounded graphical generation chaining — protected source contract

Date: 2026-10-31. Owners: host-deploy Regular and image-build Regular (source); root-control Regular (independent review); Work owners (native).

This draft PR is source-only and stacked on the refreshed first-fonts catalogue PR #7. It is NOT native compiler admission.

## Frozen sequence

Only three tasks are allowed, in this order:

1. graphics-fonts-image-v1 — the protected first catalogue and independently accepted self-hosted base.
2. graphics-xcb-core-image-v1 — selected from the accepted, immutable fonts output generation.
3. graphics-x11-core-image-v1 — selected from the accepted, immutable XCB output generation.

There is no automatic submission, fourth step, manual base-generation override, wildcard recipe, replacement attempt, background compiler retry or project/lane fallback.

Source remains image-build b0f53dbdec0e88b9b37feb5317398db3d20507dd. Monthly pin remains the original October 1 source, SHA-256 d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36.

The operator must first approve a canonical root-owned 0600 graphics-generation-chain-policy-v1.json in protected owner-state on the dedicated external 2-GiB volume. It binds exact Host ID, installation, lane owner, Project, original fonts catalogue and install-receipt digests, accepted base generation and receipt, producer source/pin, exact three task names, the fixed 30+2 GiB reservation, and the 21,600-second execution limit. The approval is not a GitHub request field or a replaceable user-supplied JSON file.

## Successor acceptance

The pure resolve_successor function consumes an immutable previous catalogue/receipt and a normalized accepted-generation record. Source-level structure checks require exact previous task/request/pipeline, previous catalogue SHA, selected input, source/pin/Host/lane/installation, a distinct 64-hex accepted image output, canonical manifest, producer and acceptance receipt hashes, success with zero missing evidence and uncertainty=false.

The normalized record is only trustworthy when supplied by a separately installed, independently reviewed native image-build attester. A pipeline.inspect status of completed is not itself accepted-generation evidence. The attester must independently reopen the genuine image-build generation catalogue/manifest, canonical provenance, verification and pipeline records, check input/output relationships and file identities, and reject stale/released/rolled-back/incomplete/foreign results. No synthetic fixture, GitHub comment, source hash or arbitrary 64-hex value may become authority.

The root-only install_next_native operation validates protected file ancestry and exact mode-0600 records, demands the local trusted Host/source/boot/exclusive-idle attester, rereads existing 30-GiB build and 2-GiB external reservation inspectors and invokes the trusted generation-attester capability. It creates only one new immutable successor catalogue and receipt using O_EXCL, fsync, hash reread and no replacement/auto-repair on partial failure. Existing catalogues remain immutable. This is not a compiler authorization.

## Regular-chat gateway binding

The supervisor still requires the original reviewed fonts-catalogue file plus exact hash and explicit advance-reviewed-generic opt-in. It may additionally opt in to a single approved-graphical-chain-policy-sha256 supplied by the root-protected operator configuration, not by the GitHub request.

On each admitted, allowlisted graphical build.submit, load_installed_step rechecks the initial root approval and accepted predecessor step-file lineage, and returns a concrete schema-2 task catalogue with an exact immutable generation selection. The gateway durably freezes that per-request catalogue hash, checks it again before advancing, and refuses multiple admitted request identities for the same task/lane. Other generic tasks retain the old behaviour.

Consequently the Regular chat can submit fonts, then XCB after genuinely accepted fonts output and protected promotion, then X11 after genuinely accepted XCB output and promotion — without manually repinning the selected generation each time. The operator's original source/policy pin is never silently replaced. Any missing predecessor means no new stage.

## Unresolved native gates — NO-GO

Neither the actual accepted base generation, protected chain policy, native predecessor attester nor successor stage files have been installed by this source change. Do not enable its gateway flag, merge the PR, run a canary, submit a compiler job or touch retained hosts based on isolated CI.

Before native enablement: independently attest exact installed image-build/root-control/host-deploy source and wheel RECORD; verify current Host, boot, active managed lane and owner; prove the genuine first base and previous accepted image-generation records, no competing writers, full 30+2 GiB reservation, six-hour deadline, genuine PID1 sidecar/worker containment, HugeTLB denial, FD/mount isolation, cancellation, cleanup, uncertain attempts and reboot hold. Use separately approved disposable infrastructure for native testing.

## Next owner handoffs

image-build Regular: produce an independent canonical accepted-generation attester for genuine pipeline/generation/manifest/build-record/verification records. Check that the normalized accepted-generation fields match actual producer contracts; correct the adapter/source contract before native integration.

root-control Regular: independently review the protected native attester trust model, root-only 0600/O_EXCL safety, state filesystem and symlink provenance, peer process/UID/GID, one-time policy pin, no sibling/retained-Host mutation, duplicate suppression and lifetime/boot constraints.

host-deploy Work + root-control Work + image-build Work: only after the separately approved Stage A canary/worker admission and genuine fonts compilation, prove exact installed bytes and accepted output, then a protected XCB successor; similarly for X11. No substitution of synthetic CI evidence.

Status: source-only, draft/unmerged; native admission NO-GO. Host-deploy issue #5 remains open.
