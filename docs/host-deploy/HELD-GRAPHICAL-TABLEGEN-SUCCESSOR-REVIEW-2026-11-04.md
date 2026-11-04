# Held graphical TableGen successor cross-owner review — 2026-11-04

**Status:** source DAG reconciled; **native generation, installer selection, compiler dispatch, rights and Task API admission remain NO-GO**.

## Immutable source selection and historical holds

Original host-deploy PR #19 source head: `52fe84b6a2e3fa3e3626efae485851b16a762a62`. Independent host-deploy PR #20 source head: `7d091af5673fbc9c767d9d46386d344197d0267a`. Image-build Workspace PR #9 remains `a1ad8fd41186d70cc2f7d8f4ebe7b0ae54e4f023`.

The original PR #19 held plan **continues** to pin the older image-build LLVM/Mesa source `9cbd652226b863a7b4bb2d6d9539722e1a262508` and must continue recording missing `usr/bin/llvm-tblgen`. The separate successor selects corrected image-build PR #8 **`ed6ea94586ceeb13feee905b9e70afcb8963b128`** in `workspace-next-tablegen-successor-v2.json`. Both immutable old and new source trees are checked out in source CI; the unchanged original tar SHA is LLVM 21.1.6 `908bce97be0275943414b45af2e2b20e8f6d5d9266fdc120bd59f096ebc547ad`.

In the successor, and **only the successor**, `usr/bin/llvm-tblgen` is now a selected LLVM required installed output, not an unmanifested source-stage requirement. The source installer builds, tests, stages and requires the executable. Mesa's source configure checks selected-tool presence **after** invoking the original protected toolchain-origin verifier. The native installed TableGen ELF digest, linked compiler provenance, generation receipt and generated-table source/output attestation remain **null**. Mere source `test -x` is not authenticated tool provenance.

## PR #20 role-specific source-DAG holds retained

The successor includes PR #20's independently reviewed **37** held package-stage receipt slots and **5** explicit tool-origin provenance slots; all remain null, not accepted. PR #20's exact Xvnc/i3/xterm build-only and runtime-only dependency arrays and required desktop installed resources are carried into the new candidate and compared against the real immutable image-build PR #9 stage files. PR #19's independent output-manifest verification remains in force, including Xvnc helpers, i3-nagbar, xterm application defaults and terminfo, font and XKB data and notices. The source verification matches the complete LLVM→Mesa→Xvnc→i3→xterm→glxgears six-stage DAG and each selected stage's actual build/runtime predecessor arrays.

LLVM, Mesa and mesa-demos retain original archive and notice hashes, source-DAG predecessor requirements and unresolved generated-code attribution. Both Mesa's original rights matrix and Workspace PR #9's selected component-rights matrix explicitly deny independent redistribution authorization and native installed notice observation. Source review **does not** grant copyright permission.

## Protection and negative-readiness tests

New `tools/verify_held_graphical_tablegen_successor.py` first invokes the legacy PR #19 validator (which checks the actual active host-deploy task allowlist) and its independent old-source DAG verifier; it then compares the successor against **only the permitted source-selection and independent-review-field additions**. It also inspects all three exact image-build checkouts (PR #9, old PR #8, corrected PR #8), the immutable host-deploy PR #20 checkout and actual source build/test/install commands.

Synthetic denial tests reject stale LLVM source SHA, missing build/runtime predecessor, missing notice or installed output, missing Mako/PyYAML, missing XKB/terminfo requirements, fabricated signed-looking TableGen bytes, any tool-origin receipt, missing generation receipt, invented rights approval, changed protected live compiler source or task allowlist, and any compiler/SSM authorization. Existing gateway task-name rejection tests remain part of the source CI.

**No source code path in this successor constructs or submits a worker request.** The selected protected compiler remains `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`. The future small-CPU Xvnc/noVNC `glxgears` smoke stays unauthorized, with no FPS threshold.
