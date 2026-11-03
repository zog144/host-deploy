# Independent source review — held next-generation graphical catalogue

**2026-11-03 · host-deploy + image-build Regular.** Review source: [host-deploy PR #19](https://github.com/zog144/host-deploy/pull/19) head `0fdf8aa75623736fd30f66b7947bd2d37b6ec3e1` and exact image-build PR #9 `a1ad8fd41186d70cc2f7d8f4ebe7b0ae54e4f023`; Mesa/LLVM source PR #8 `9cbd652226b863a7b4bb2d6d9539722e1a262508`.

## Independent findings

PR #19 correctly remained HELD_NOT_SUBMITTABLE and its six proposed LLVM→Mesa→Xvnc→i3→xterm→mesa-demos-smoke stages were absent from the live request task allowlist. Its initial 151 passing source tests did **not** fully verify source package-stage dependency roles: the proposal recorded broad predecessor receipts but not actual Xvnc/i3/xterm build-versus-runtime dependency lists or per-package accepted-generation receipts. A check using the union of the build/runtime dependencies was insufficient: dropping a required *build* package while leaving its runtime entry passed the first review's synthetic negative test.

## Added source evidence and mandatory regressions

`workspace-next-v1.json` now retains the **exact build and runtime package stage lists separately** at the immutable image-build PR #9 source:

- Xvnc: `project/graphics-first-workspace/turbovnc-draft/stages/final/dependencies.py`; selected X11/Xorg, Mesa, pixman, libjpeg-turbo, XKB tools/data, OpenSSL and inherited zlib. The draft is not a canonical native package, and `TVNC_DRI3=OFF`/`TVNC_ZLIBNG=OFF` are configuration intentions, not proof of linked-object exclusions.
- i3: `project/package/i3/stages/final/dependencies.py`; libev, yajl, startup-notification, XCB util core/cursor/xrm/keysyms/wm, XKBcommon and XKB data, libX11, GLib/Cairo/Pango and PCRE2, with a selected Meson/pkg-config and generated-code origin. Its native stage remains unaccepted.
- xterm: `project/package/xterm/stages/final/dependencies.py`; Xt/Xaw/Xmu/Xpm/Xft, inherited ncurses, runtime luit and bitmap font; original xterm 412 source does not by itself prove installed terminfo, font/app-defaults or copyright notice bytes.

**All 37 distinct package-stage accepted-generation receipt slots remain null.** The held plan additionally explicitly requires still-null selected compiler/linker, build tools, Python codegen, XKB/font tools and ordinary utility origins. Source-only package recipe presence and GitHub CI do not establish actual library/ELF provenance.

Stage-specific installed resources are explicitly listed and required for denial checks. These include `usr/bin/Xvnc`, selected `xkbcomp`/XKB data, `6x13.pcf.gz` and `fonts.dir`, Mesa `libGL.so`/`swrast_dri.so`, i3/i3bar/i3-msg, xterm/luit plus `usr/share/terminfo/x/xterm` and `usr/share/X11/app-defaults/XTerm`, `glxgears`/optional `glxinfo`, and selected notice destinations.

Original component-rights evidence is retained as **nine separate NULL approvals** for TurboVNC bundled Xserver, libsha1 and zlib-ng exclusion; LLVM/BLAKE3; Mesa GLAPI generator and llvmpipe; libdrm; and mesa-demos glxgears/glxinfo. The verifier reads the pinned PR #9 `selected-component-rights-handoff.json` and `remaining-distribution-evidence-2026-11-03.json` and checks that every one remains unapproved, with selected compiled-object and installed notice bytes absent. No rights-holder authorization is inferred from original archive-member SHA-256.

The independent verifier now also freezes **exact separate build and runtime arrays**, then compares them directly against the real pinned image-build dependency files via `ast.literal_eval`. This detects missing or substituted predecessor dependencies in either role, not merely membership in their union. Negative tests cover individual missing package-stage entries, absent required XKB/GLX/font/terminfo resources, fabricated package/rights/tool provenance, new submittable task names, source revision substitutions, fake accepted generation/authority/current epoch, unauthorized smoke results and stage ordering.

## Native/authority boundary

`protocol.BUILD_TASKS`, `task_catalogue.REVIEWED_IMAGE_TASKS`, `graphics_generation_chain.TASKS` and root-selected image-build `1f07e83dbd80dacb9bed0d6494c697375f0e26cd` October pin are unchanged. New plans cannot be selected by a caller, installed, or sent to SSM. Genuine accepted X11/LLVM/Mesa/inherited zlib/ncurses/desktop package generation receipts, rights grants, current protected authority and independent monotonic operation claims, genuine compiler tool and native library evidence, budget and reboot recovery remain absent. The `glxgears` smoke requires a later separately approved CPU-only Xvnc Workspace and makes no performance claim.

**Result:** stronger source-review-only DAG and negative evidence. **Native graphics submission: NO-GO.** This review does not approve PR #19 for positive task catalogue installation or native build execution. No SSM, AWS, compiler, protected Host or STATE changes were made.
