# First Workspace graphical submission-readiness boundary audit — 2026-11-03

**Owners:** image-build Regular + host-deploy Regular. **Scope:** GitHub source review and synthetic negative tests only. No AWS, SSM, builder, compiler, deployment, key, current pin, protected Host or STATE modification.

## Exact source selection

- image-build PR #9: `6b64a7e1b6f9842554bd3b9eee5599e24ca2402c` (source handoff checkout), **draft**. Its reviewed PR9 *input* identity is still `db13d73a45f8a3be579226656442c331a9f701ea`; later PR9 edits have **not** thereby become independently approved native production source.
- image-build PR #8 Mesa input in handoff: `9cbd652226b863a7b4bb2d6d9539722e1a262508`; **independent native Mesa compilation/rights acceptance is absent**.
- host-deploy PR #8 bounded chain / PR #11 authority hardening: `7d052b340a026497fd32afb82d0a290d1d6bc60e` as the test candidate base. Existing native catalogue software source remains **`1f07e83dbd80dacb9bed0d6494c697375f0e26cd`**, with original October pinned source SHA; it is NOT automatically rebased onto the PR9 source or the PR8 Mesa draft.
- The root-installed chain has finite task names `graphics-fonts-image-v1`, `graphics-xcb-core-image-v1`, `graphics-x11-core-image-v1`. The generic `build.submit` protocol and protected task catalogue do not authorize a Mesa, LLVM, Xvnc or arbitrary script task.

## Cross-contract comparison

1. image-build PR9 `source-to-native-handoff.json` is an **explicit negative handoff**, schema `zog-first-workspace-source-to-native-handoff-v1`, status `PREPARED_NOT_SUBMITTABLE`; all seven predecessor receipt slots (fonts, XCB, X11, zlib-native-environment, ncurses-temporary, LLVM, Mesa) are null. `native_accepted`, `rights_authorized`, `build_submission_allowed`, `canonical_promotion_allowed` are all false. `verify_workspace_native_handoff.verify` rejects invented success claims, substituted PR8 Mesa revisions and forged acceptance bytes. The source-only `refuse_native_readiness` intentionally denies even plausible signed-looking evidence, because it cannot independently authenticate a native accepted generation.
2. host-deploy's `graphics_generation_chain.resolve_successor` is a **pure definition helper, not an attester**. It consumes accepted-generation-shaped dictionaries only inside the protected native owner's separately authenticated `installed_capability` and protected single-writer installation path. Synthetic evidence must never be passed directly to a live compiler. A root-installed successor receipt even declares `compiler_authorized: false` and `installed-not-compiler-admission`.
3. The command-center gateway first requires a fixed current-authority pin and a fresh independently signed antirollback checkpoint, then validates an Ed25519-signed cross-Host catalogue and receipt, obtains a live nonce-bound compiler-Host acknowledgment, rereads current pin, and checks the external checkpoint again. An untrusted or fabricated local cache file is not enough.
4. The existing gateway consumer must obtain that verified export **before** `prepare_image_build_dispatch`; actual generic pipeline advancement requires a frozen prepared dispatch and one-stage-once record. Lost SSM/peer responses never grant a replacement attempt. The source handoff is not a valid `task_catalogue.validate` input, and PR9 cannot silently select a different source revision for the existing lane.
5. For the **later** PR9 Workspace/Mesa native lane, the protected issuer must first authenticate exact source/recipe revisions, rights permissions, compiler tool provenance, inherited toolchain plus zlib/ncurses, genuine predecessor generations with accepted manifests, and installed XKB/font/GLX/ELF/notice output. No part of this source check grants an additional task or activation.

## Added synthetic negative tests

`tests/test_gateway_workspace_submission_boundary.py` runs **actual** PR9 source verifier from a GitHub Actions checkout at its immutable SHA and host-deploy's genuine consumer/export/catalogue/protocol code:

- Held plan flags and null receipts never become a valid task catalogue.
- X11 export missing from cache after synthetic checkpoint inspection => gateway **no prepare, no advance**.
- Self-consistent forged X11 predecessor receipt with an unauthenticated signature => gateway **no prepare, no advance**.
- Non-null X11/XCB receipts and invented authority fields => PR9 verifier rejects; no source-to-catalogue promotion.
- Outdated Mesa source revision => PR9 verifier rejects; `build.submit` with Mesa task is not recognized by protocol.
- X11/LLVM/Mesa and inherited zlib/ncurses generation slots remain null; required dependency edges and rights HOLD remain present.
- Explicitly distinguish the finite existing Fonts→XCB→X11 catalogue from the later LLVM/Mesa/Xvnc source handoff.

[Exact-head synthetic workflow](https://github.com/zog144/host-deploy/actions/workflows/workspace-submission-boundary-source.yml) runs without AWS credentials or real compiler. Synthetic monkeypatch of checkpoint success is deliberately **not** a native authority: it permits testing of the *next* trust boundary, the genuine signed export receiver, against a missing or forged cache entry. It does not permit a compiler launch. Do not claim that all trust controls were independently verified by one test.

## Decision

**Source negative submission boundary: PASS at tested commit, conditional on exact-head workflow. Native graphical build admission: NO-GO.** The source integration cannot make a nonexistent or unaccepted X11 generation into an accepted native generation, cannot select a newer Mesa revision silently, and cannot treat `PREPARED_NOT_SUBMITTABLE` as `build.submit`.

Future positive admission requires a *separate* reviewed task catalogue, exact re-frozen final PR9/PR8 sources and rights, externally authenticated issuer/checkpoint and accepted predecessor receipts, verified source generation provenance, native budget/reservation, 21,600s hard bound, plus SSM/worker recovery acceptance. Do not mutate production pins or launch compiler work in this source-only review.

### Independent source-refreeze (2026-11-03)

The old `54431ea8…` snapshot was a previous source-review input, not the live PR9 head. This independent source suite now checks exact **image-build PR9 `6b64a7e1…`** and refuses any absent or changed checkout identity. host-deploy's existing protected compiler source remains `1f07e83d…`; this is **not** authorization to repin or submit.
