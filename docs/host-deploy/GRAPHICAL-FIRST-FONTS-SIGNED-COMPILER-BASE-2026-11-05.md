# First Fonts signed dual-kind compiler-base consumer — 2026-11-05

**Source integration only. Native admission remains NO-GO.** This document supersedes the stage-two-only compiler-base paragraphs in the earlier PR #7 catalogue handoff, but does not modify historical approved compiler source, original image bytes or the original October monthly pin.

## Exact separately selected revisions

- Original image-build *compiler producer/source* remains `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`. It is not the independently selected new verifier.
- NEW review-only signed compiler acceptance verifier/source: image-build PR #18 `6041a91cef371817bcf72db72c178363fd9bc1d9`.
- Original monthly source pin: `sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.
- Producer handoff: https://github.com/zog144/image-build/blob/6041a91cef371817bcf72db72c178363fd9bc1d9/docs/image-build/first-fonts-producer-evidence-consumer-handoff-2026-11-04.md

## New immutable accepted compiler input

The first Fonts root catalogue consumes the exact byte SHA-256 of the independently root-issued `image-build-compiler-base-acceptance-v1` signed receipt, plus the canonical producer's independently returned `image-build-compiler-base-binding-v1`. It does NOT consume the superseded `image-build-first-fonts-base-observation-v1` stage-two-only record as a job grant.

`graphics_base_acceptance.checked_base` independently verifies canonical signed receipt bytes (bounded, duplicate-free JSON) with the original Ed25519 v1 domain, an independently pinned issuer policy key ID and public key, exact approved receipt SHA, and agreement with the producer source verifier's binding on original generation ID, **original `generation_kind`**, manifest/inventory identity, genuine Build Record root if present, Host/installation/STATE/Project, controller configuration SHA, target ABI, hashes for installed compiler/linker/assembler/headers/CRT/libc paths, native probe record SHA, historical provenance and original acceptance SHA.

- `kind=toolchain` remains stage-two, with authentic Build Record root and `historical_provenance={status:complete,missing:[],retained_evidence_sha256:null}`. The producer verifier must independently reopen and verify this generation.
- `kind=image` remains **image**, even when it contains GCC/binutils and passes native compile/link/run verification. It must declare `historical-gap-declared` with bounded, nonempty missing history and a retained-evidence digest. A present-day capability probe never invents missing stage-two ancestry; `generation_record_sha256` stays null when the original image has no genuine record.
- Both kinds require exact signed, independently approved compiler capability. Neither a signed receipt, a dictionary returned by a caller, an unchanged 64-hex ID nor a local probe alone authorizes execution.

The immutable root-owned fonts-only catalogue now retains `retained_acceptance_sha256` over the *complete* preserved compiler binding and its original kind. The protected nonsecret installation receipt records the original `kind`, STATE volume identity, compiler installed-files SHA, native probe SHA, controller execution-environment SHA, historical-provenance declaration, manifest/inventory, nullable genuine Build Record root and original acceptance receipt SHA.

The shared gateway `image_build_dispatch._remote_request` and `task_catalogue.select_retained` continue to reject missing or mismatched catalogue-frozen retained input. Subsequent package-generation predecessors retain separate `image-build-verified-graphical-predecessor-v1` acceptance, original pipeline/request and dependency edges; they are **not** substituted for the compiler-base certificate. No XCB/X11 task was added to first Fonts catalogue.

## Separate safety and native gates remain

A signed compiler-base certificate is **capability**, never task authorization. Original GitHub issue/request, fixed one-task allowlist, Fonts package/rights/dependency provenance, image-build producer source and monthly pin, managed lane, root-installed immutable catalogue, original operator approval, 30+2 GiB fully backed reservation and six-hour bound, root-control Task C preflight/stage irrevocable claims, S3 monotonic checkpoint, SSM owner-exclusive credentials, and actual gateway IAM/STS/IMDS denial remain distinct, fail-closed gates.

The producer's new code changes original engine/graphical-composition source and is not in the old installed producer. Installing/verifying this new *reader* requires its own source approval and compatible observer-source repin. The protected issuer, original image root, Host/installation/STATE, Ed25519 policy revocation and real native box-control 120-second isolation/compile/link probe remain **Work-only acceptance**. The native installer requires distinct privileged issuer, receipt and producer-binding readers; they must not be fed by GitHub/SQS request parameters or untrusted gateway-local storage.

## Source evidence

- Exact PR #7 consumer source with real PR #18 producer `resolve()` fixture, synthetic Ed25519 image acceptance and negative signature/revocation-like pin/Host/STATE/ABI/byte-binding/history tests.
- https://github.com/zog144/host-deploy/actions/runs/42041016045 — PASS Python 3.12/3.13, **62 source + 2 disposable root-owned installation tests per lane**.
- https://github.com/zog144/host-deploy/actions/runs/42041026236 — PASS both Python versions and same suite.

**Disposition:** no native compiler accepted, no original GitHub issue/SQS, no actual SSM commands, no root-owned catalogue installation on a managed Host, no production source promotion. PR remains draft.
