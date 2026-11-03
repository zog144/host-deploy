# Graphical compiler submission denial — second-pass cross-owner source review
Date: 2026-11-03

**Scope:** Source-only independent *second-pass code inspection* of host-deploy draft PR #14 stacked on PR #11 and image-build draft PR #9. This review is not a separately authenticated reviewer or native approval, and no protected actions were performed. All paths remain draft/unmerged.

## Exact immutable inputs

- host-deploy PR #14 reviewed base: `5a4b3098c188df8de3cd5e7ac9ca4ef66fa3bc6b`.
- host-deploy PR #11 parent: `7d052b340a026497fd32afb82d0a290d1d6bc60e`.
- Original image-build PR #9 source-to-native handoff snapshot **selected for cross-repository tests**: `6b64a7e1b6f9842554bd3b9eee5599e24ca2402c`; status `PREPARED_NOT_SUBMITTABLE`, all inherited and graphical generation receipt slots null, all native/rights/submission flags false.
- image-build PR #9 **current source head during review**: `6b64a7e1b6f9842554bd3b9eee5599e24ca2402c`. This newer head adds source-level host-deploy audit records and is **not silently installed or re-frozen as an admitted compiler generation**. Its 2026-11-03 exact-head public CI and Workspace/Mesa source-intersection workflows pass.
- Mesa PR #8 source reference remains `9cbd652226b863a7b4bb2d6d9539722e1a262508`; the host-deploy root-selected **compiler** source is still `1f07e83dbd80dacb9bed0d6494c697375f0e26cd` under the original October monthly pin.

## Code paths inspected

1. `GatewayConsumer._advance_one_reviewed` reads a protected current graphical key and independent online monotonic checkpoint via `graphics_chain_export.load_selected_step` **before** `prepare_image_build_dispatch`. At restart, its retained frozen dispatch must still have the approved exact catalogue digest.
2. `graphics_chain_export.verify` checks the signature against the selected root-protected current Host pin, exact Host/installation/lane, protected policy, receipt hash and finite catalogue; `load_selected_step` requires fresh Host live epoch proof and a second independent checkpoint. A local signed-looking JSON file or a different Ed25519 public key cannot authorize a stage.
3. `graphics_generation_attester._matching_completed_request` requires the original admitted Host request, frozen same-task/pin/source/lane selection, completed pipeline history and independently authenticated original gateway history. `graphics_generation_chain.install_next_native` is root-only, serializes promotion and consumes the privileged installed capability. Pure `resolve_successor` dictionaries are never native authority.
4. `image_build_dispatch._remote_request` selects one exact task using `task_catalogue.select` and verifies exact managed-lane source revision, original admitted request, monthly pin, lane and provenance owner. `task_catalogue.validate` checks exact, ordered reviewed recipe entries and targets. Only Fonts/XCB/X11 are eligible in the bounded successor chain; Mesa/LLVM/Xvnc have no authorizing catalogue task.

### New independent finding: reconstructed generic stage request was missing

In `generic_pipeline._read`, a retained `pipeline.submit` stage's request hash was **unkeyed** and its source compared to the frozen binding, but its `arguments` and operation were not fully compared with those of the selected immutable task. A synthetic edit to `selection`, `graphical_predecessor`, `targets`, `recipe_snapshot`, or operation could rehash `request_sha256` without altering the root task or bind digest. The next `advance` would have used the altered request in `_stage_binding`/the existing SSM path. This bypass was outside PR #14's earlier source tests.

**Correction on this stacked review branch:** `generic_pipeline._read` reconstitutes each stage using its original `_request(binding, name, operation_id, record)`, requires the entire request to match, verifies the finite chronological stage/ordinal sequence and binds retained snapshot/pipeline identities to the corresponding completed result records. It rejects before `verify_current_target`, `host_factory`, `producer_runtime_preflight` or `host.submit_command`; a recomputed JSON hash is not a new selection grant.

These checks improve journal consistency, but a mutable local receipt is still **not** an independently signed producer attestation. Native compilation must independently verify the original SSM/producer receipt and authenticated gateway history, current Host authority and external checkpoint. No offline test can supply that independent installed evidence.

## New synthetic regressions

- Recomputed digests with substituted base generation, recipe target list, remote operation, source revision, snapshot predecessor and injected `PREPARED_NOT_SUBMITTABLE` flags: **deny before fake SSM call**.
- Recomputed identities for a stale recipe snapshot, changed pipeline ID, missing capabilities phase or fake submit ordinal: **deny**.
- Selected graphical catalogue with wrong source revision, newer PR9 revision substituted for root pin, altered recipe entries, cyclic predecessor, or invented Mesa task: **deny**.
- Signed-looking predecessor dict: pure resolver cannot treat it as a protected installed attestation.
- Fully formed signed X11 export using a **different** Ed25519 Host key, despite a well-shaped catalogue and successor receipt: actual gateway export path denies before prepare/advance.

Workflow `.github/workflows/graphical-submission-independent-review.yml` pins image-build PR9 source `6b64a7e1…`, compiles checked source and runs the new tests with the original PR14 and existing gateway/attester/selection tests. **GitHub Actions #41650011808 PASS: 212 tests at head `56b95a3dfedb5b3c4944f23535ec768a4c631f51`.**

## Disposition

**Negative source boundary corrected and verified: PASS for stated scoped regression suite. Native graphical compiler authorization: NO-GO.** Never use a `PREPARED_NOT_SUBMITTABLE` plan, synthetic selected generation, stale Mesa source, local signed-looking record, or any CI result as an independent operator/issuer grant. The installed protected owner, exact re-frozen PR9/Mesa source, rights determination, accepted compiler/Fonts/XCB/X11/LLVM/Mesa receipts and inheritance, 30+2 GiB/21600s native controls, authenticated cross-Host checkpoint and live SSM/worker recovery are separate acceptance requirements. Draft PRs remain unmerged and no AWS/SSM/compiler/STATE action was taken.
