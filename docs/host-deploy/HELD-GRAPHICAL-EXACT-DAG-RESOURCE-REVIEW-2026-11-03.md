# Independent future graphical stage-DAG and resource review — November 3, 2026

**Held source review**, host-deploy PR #19. The exact immutable original source inputs remain image-build PR #9 `a1ad8fd41186d70cc2f7d8f4ebe7b0ae54e4f023` and Mesa PR #8 `9cbd652226b863a7b4bb2d6d9539722e1a262508`. Host-deploy's selected installed compiler source `1f07e83d…` and the Fonts/XCB/X11 active task allowlist are **unchanged**.

## Actual package stages vs proposed sequencing

| Future step | Pinned source package | Source-declared build edges | Corrected source-required outputs |
| --- | --- | --- | --- |
| LLVM | PR #8 `project/graphics-drafts/llvm` | 1, including inherited `zlib-native-environment` | `llvm-config`, `libLLVM.so`, LLVM and BLAKE3 original notice outputs |
| Mesa | PR #8 `project/graphics-drafts/mesa` | 11, notably LLVM, libdrm, libX11/Xext/XCB, expat, inherited zlib, Mako, PyYAML, libxshmfence, libXxf86vm | `libGL.so`, `swrast_dri.so`, Mesa and GLAPI original notice outputs |
| Xvnc | PR #9 `turbovnc-draft` | 15, notably Mesa, libjpeg-turbo, pixman, XKB data/compiler, libXfont2, openssl, inherited zlib, X11 and proto | `Xvnc`, `vncserver`, `vncpasswd`, Xserver/libsha1/TurboVNC original notices |
| i3 | PR #9 `project/package/i3` | 16, including libev, YAJL, startup-notification, libxkbcommon, GLib, Cairo, Pango and XCB support | `i3`, `i3bar`, `i3-msg`, **`i3-nagbar`**, original LICENSE |
| xterm | PR #9 `project/package/xterm` | 6, including libXt/Xaw/Xmu/Xpm/Xft and inherited `ncurses-temporary` | `xterm`, **`XTerm` app-defaults**, **`terminfo/x/xterm`**, COPYING |
| mesa-demos smoke | PR #8 `project/graphics-drafts/mesa-demos` | 3, Mesa, libX11, libXext | `glxgears`, `glxinfo`, exact original `glxgears.c`/`glxinfo.c` attribution delivery |

The proposed **step order** LLVM→Mesa→Xvnc→i3→xterm→glxgears is an editorial end-to-end sequence, not a substitute for any package's **direct** build/runtime dependency DAG. In particular `i3` and `xterm` do not become package dependencies of Xvnc simply by following it in a test plan. The source reviewer compares each complete declared dependency array and full installed-output manifest against the immutable source checkout and retains the no-native-generation status.

## Demonstrated missing output (native blocker)

PR #19's LLVM proposal named `usr/bin/llvm-tblgen`, but the exact PR #8 `llvm` **required installed-output manifest does not include it**. The proposal retains the tool as a *future required output* and now has an independently tested `unmanifested_planned_outputs.LLVM=["usr/bin/llvm-tblgen"]` hold. Do not infer that the compiler generated, installed, or admitted this executable. The LLVM owner must either author a reviewed selected build-tool output contract with native bytes or explicitly redesign the generator use and provenance before native source admission.

## Installed resources and tool provenance

The source review binds the actual PR #9 manifest paths for:
- `usr/share/X11/xkb` from xkeyboard-config and `usr/bin/xkbcomp` from xkbcomp;
- `usr/share/fonts/X11/misc/6x13.pcf.gz` and `fonts.dir` from basic-font;
- `usr/share/X11/app-defaults/XTerm` and `usr/share/terminfo/x/xterm` from xterm.

The future compiler must additionally authenticate actual accepted predecessor generations for the selected compiler/binutils/GCC/LLVM TableGen, Meson/Ninja/CMake/pkg-config, Python generator environment (including *Mako and PyYAML*), headers, ELF loading and linker paths, the inherited zlib and ncurses inputs, XKB data, fonts and all direct source-stage libraries. Source CI does not execute any of these.

## Original rights and negative readiness

The exact PR #9 rights supplement and PR #8 Mesa rights matrix both remain unapproved; neither original archive hashes nor drafted installed notice paths are copyright-holder permission. Generated GLAPI/LLVM source attribution, TurboVNC Xserver/libsha1 inclusion, excluded device functionality, selected object maps and native installed notice bytes remain explicit holds.

`project/held-graphical-catalogue/exact-source-dag-review-v1.json` is a comparison record, not a task catalogue. `tools/verify_held_graphical_source_dag.py` reads the real immutable PR #8/#9 dependency and output manifests, and `tests/test_held_graphical_source_dag_review.py` rejects removal of Mako/PyYAML, libdrm, libjpeg-turbo, i3/libev, xterm/luit/ncurses, missing XKB/font/terminfo, missing original notices, invented generation and rights approval, unmanifested LLVM tblgen claims, and unexpected outputs or source origins. It runs only under the existing held-source CI checkout and never invokes a gateway dispatcher or AWS.

**Disposition:** source DAG and resource scope independently reconciled, LLVM selected tool output **NO-GO**, graphics native rights **NO-GO**, current production task authority **unchanged**. No new compiler request, task allowlist, protected generator or smoke-test authorization.
