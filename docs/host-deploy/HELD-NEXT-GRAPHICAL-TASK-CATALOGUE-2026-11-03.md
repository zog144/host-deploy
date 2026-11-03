# Future graphical task-catalogue extension — held source proposal

**Date:** November 3, 2026. **Owners:** host-deploy Regular + image-build Regular. **Disposition:** `HELD_NOT_SUBMITTABLE`. This is NOT a root-owned catalogue, task installation, authorized request, approved rights grant, accepted generation, native build or SSM operation.

## Exact review source selection

- Current protected compiler source, unchanged: image-build `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`, October `commit-pin.py` SHA-256 `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.
- Future Workspace **source candidate** selected for this proposal: image-build PR #9 at `a1ad8fd41186d70cc2f7d8f4ebe7b0ae54e4f023`, not a moving PR head or a retained installed generation. Its handoff explicitly identifies its earlier reviewed input `db13d73a45f8a3be579226656442c331a9f701ea`: that distinction remains intact.
- Mesa/LLVM software-GLX **source candidate**: image-build PR #8 at `9cbd652226b863a7b4bb2d6d9539722e1a262508`. The source contains the planned llvmpipe contract, not accepted LLVM/Mesa/mesa-demos compilation.
- Original notices and remaining independent distribution rights: PR9 `project/graphics-first-workspace/selected-component-rights-handoff.json` and `remaining-distribution-evidence-2026-11-03.json`, read at the immutable PR9 source candidate. Original member SHA-256 and proposed notice destinations are **not** rights-holder approval or installed-byte attestation.

There has been no silent repin of `graphics_catalogue_owner.SOURCE`, no change to `protocol.BUILD_TASKS`, `task_catalogue.REVIEWED_IMAGE_TASKS`, `graphics_generation_chain.TASKS`, or the current root-installed catalogue bytes.

## Ordered, non-authoritative proposed stages

| Proposal stage | Prerequisites and source | Intended outputs | Status |
| --- | --- | --- | --- |
| LLVM | Inherited accepted toolchain and X11 lineage; PR8 source. Actual canonical llvm recipe not committed/accepted here | `libLLVM.so`, `llvm-tblgen` | SOURCE_PLAN_NOT_CANONICAL |
| Mesa | PR8 llvmpipe source; independent accepted X11 + LLVM + zlib-native environment | `libGL.so`, `swrast_dri.so` | SOURCE_PLAN_NOT_CANONICAL |
| Xvnc | PR9 `turbovnc-draft`; accepted fonts/XCB/X11/Mesa/zlib; source-pinned XKB, font, OpenSSL, libjpeg-turbo closure | `Xvnc` | DRAFT_NOT_PACKAGE_ADMITTED |
| i3 | PR9 `i3/stages/final` source; X11/XCB/fonts + glib/cairo/pango/libev/yajl/pkg-config closure. Sequenced after Xvnc for review, not inherently dependent on Xvnc for compilation | `i3`, `i3bar`, `i3-msg` | SOURCE_AUTHORED_NATIVE_HELD |
| xterm | PR9 `xterm/stages/final` source; X11/fonts/ncurses, luit and bitmap-font closure | `xterm` | SOURCE_AUTHORED_NATIVE_HELD |
| mesa-demos-smoke | PR8 mesa-demos source plan and accepted Mesa + usable Xvnc/i3/xterm Workspace | `glxgears`, optional `glxinfo` | SOURCE_PLAN_NOT_CANONICAL |

The stage list is a **review plan**, not a new set of request task names. The `depends_on` array expresses the desired staged review order, including sequential integration of i3/xterm after Xvnc; `requires_receipts` expresses authority prerequisites independently. The graph is not a runnable recipe or producer pipeline.

The eventual smoke is limited to a Zog-built `glxgears` animated window through the initial CPU-only Xvnc/noVNC Workspace, optionally `glxinfo -B`; no FPS target, hardware GPU, stress tests, soak, high-core AWS instance or current work submission. A later test must be separately approved and runtime evidence retained.

## Required independent native evidence — currently absent

The JSON candidate sets all accepted-generation and rights/authority/operation receipts to `null`, all installation/submission/worker/smoke booleans to `false`, and the source closure `PREPARED_NOT_SUBMITTABLE`.

Positive future admission is a separate operator decision requiring:

1. Exact, **newly approved** immutable compiler image-build revision and monthly pin, not the source-review SHA alone; accepted immutable base+Fonts+XCB+X11+LLVM+Mesa and inherited zlib/ncurses generation manifests, independently authenticated by the selected protected issuer against original Host/installation/STATE/lane identity.
2. Accepted source-to-installed closure of Mesa llvmpipe/GLX, LLVM/TableGen/GLAPI generator inputs, per-object library link data and no Host header/library/tool/Python module fallback. For Xvnc: selected CMake feature flags and **actual object exclusion** of DRI3 and bundled zlib-ng, xkbcomp/XKB/bitmap fonts/GLX closure and current rights to redistribute selected bundled Xserver/libsha1 sources. For i3/xterm: actual pkg-config/native ELF, 6x13 font, terminfo and licensing evidence.
3. Independent original notices, file-level copyright/rights authorization, installed notice hashes, and explicit selected build features; a signed-looking JSON, original archive notice or GitHub CI result is not authority.
4. Root-installed, current, non-rollbacked signing key/checkpoint, original approved request and immutable stage-once/operation history with a **protected monotonic per-operation send owner**. The local exclusive intent in host-deploy PR #18 is source-level protection against journal-only rollback, not whole-STATE antirollback. Authority rotation/revocation and reproducible reboot/recovery require protected native acceptance.
5. New stage catalogue and issue-task allowlist reviewed **as a separately authorized change**, not an automatic extension. Maintain 30+2 GiB aggregate disk reservation and hard 21,600-second CPU budget as native admission limits; the JSON records requested limits but grants neither capacity nor control.
6. One separately authorized smoke verification after first real Workspace is available, retaining original producer and viewer evidence, not merely a plausible expected-output list.

## Source-only negative gates

`tools/verify_held_graphical_extension.py` validates source pins, held status, exact current host-deploy protected allowlist/source, null receipt slots, required original rights references, fixed staged order and CPU smoke contract. Its independent checkout comparison verifies the exact PR9/PR8 Git HEADs, PR9 handoff `PREPARED_NOT_SUBMITTABLE`, null original generation receipts, rights HOLD, and genuine held package draft locations. `refuse_submission` has **no positive submission branch**.

`tests/test_held_graphical_extension.py` attempts forged accepted receipts, operator approval, signing checkpoint, revoked/changed authority selection, source substitution, enablement of task allowlist, worker/reservation and smoke flags, and out-of-order/Mesa recipe promotion. It invokes the actual gateway protocol to ensure every proposed stage name is rejected as an unreviewed GitHub `build.submit` task. GitHub Actions checks both pinned image-build checkouts and existing graphical source/replay tests. The workflow has no AWS credential, SSM or compiler action.

**Handoff:** image-build Regular should independently compare future exact source and rights/outputs when source closure matures; host-deploy + root-control Regular should separately audit the protected issuer/monotonic current authority and operation owner. Work/native installation is out of scope. No protected authorities were created, replaced, expanded or installed.
