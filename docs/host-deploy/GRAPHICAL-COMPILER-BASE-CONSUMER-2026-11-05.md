# Canonical compiler-base acceptance in graphical catalogue consumer — 2026-11-05

**Source-only; no native generation admitted and no Fonts job submitted.**

## Exact producer inputs

- Original selected image-build compiler producer `1f07e83dbd80dacb9bed0d6494c697375f0e26cd` and October pin bytes `sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36` are unchanged.
- The NEW **read-only reader candidate** is image-build PR #18 `92e4d4c2166a49bbb2d5421660f77f75e881d0a2`. This reader is not in the original installed compiler source; its source/installation requires independent authorization.
- Reader record `image-build-first-fonts-base-observation-v1` means `canonical-base-observed-not-native-admission`, with `catalogue_installed=false` and `native_compiler_authorized=false`. It reports canonical stage-two self-hosted `kind=toolchain`, generation ID, manifest, installed inventory and Build Record root hash. It is NOT the independent Host/installation/STATE authority.
- Subsequent approved graphical outputs use `image-build-verified-graphical-predecessor-v1` with `output_kind=image`, original request/pipeline, verified receipt and immutable output generation. Do not require those *output* generations to be kind=toolchain.

## Consumer changes

`graphics_base_acceptance.checked_base` accepts the exact producer observation only with an independently supplied, installed native base acceptance and exact agreement on Host, project, installation, source, October pin, lane, selected generation, manifestation/installed inventory/Build Record hashes and accepted native receipt. All named fields must match. A mere syntactically plausible `kind=toolchain` record is insufficient.

Root-owned first Fonts catalogue construction now freezes `retained_acceptance_sha256` — the canonical SHA-256 over the *entire* accepted retained-input evidence, including generation ID, `kind=toolchain`, stage 2, manifest/inventory/Build Record and native receipt. The catalogue receipt retains this digest and individual canonical IDs. The managed native installer requires separate callable producer-base and independent-native acceptance readers rather than a gateway-supplied receipt.

`task_catalogue.select_retained` and `image_build_dispatch._remote_request` require complete retained-input evidence whose canonical SHA matches the immutable task catalogue. Missing, changed generation, unrelated accepted receipt, wrong kind/stage or altered original source/lane/pin rejects BEFORE graphical request preparation. The existing task catalogue shape is unchanged for historical configurations; older graphical tasks without a new pinned retained-acceptance digest **cannot** pass this selected graphical request path.

For subsequent **separately authorized** graphical image batches, `retained_generation` handles `kind=image` with the original producer image acceptance contract, not an unconditional `kind=toolchain`. Their own root-owned catalogue input digest must be independently frozen from a genuine producer-native accepted generation and be checked each time; the original compiler base acceptance remains separately available through its retained protected receipt. This does not create any new task, approve a dependency, change source pins, or grant SSM.

## Independent gates unchanged

1. The protected original GitHub issue/actor/request, specific allowlisted task and immutable catalogue bytes remain separately authorized.
2. Fonts→XCB→X11 dependency edges, original accepted predecessor request/pipeline and current Host/installation/STATE require the graphical generation-chain attester and separately installed original owner. No source-only digest can approve them.
3. The exact original image-build source and October source-pin bytes stay frozen, independent from the accepted generation.
4. CPU/time=21,600 seconds and 30+2 GiB reservation (aggregate six hours/32 GiB) stay separately enforced.
5. Graphical stage preflight, immutable protected S3 claim/send fence, actual gateway IAM denial and SSM command reconciliation remain **native Work-only NO-GO**. Never retry lost ACK or substitute manual SSM.
6. No PR merges, source/Host/STATE installation, AWS access, compilation, root privilege outside CI or native acceptance occurred.

**Owner handoff:** host-deploy Work + root-control/host-install Work must independently attest the installed PR #18 reader source, actual canonical generation, original approved compiler Host/installation/STATE, managed lane, approval records and protected source bytes before installing any catalogue or issuing a first Fonts job. Image-build Regular retains producer acceptance record semantics for later batches. Native reader/acceptance dictionaries are privileged capability results, NOT user-provided request JSON.
