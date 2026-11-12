# First Fonts compiler runtime: build-record companion

Source reconciliation: November 12, 2026. This is a **native Work setup and
verification handoff**, not an authorization to submit a job.

## Exact dependency

The original first Fonts recipe producer remains
`image-build@1f07e83dbd80dacb9bed0d6494c697375f0e26cd` and its original
October monthly pin remains unchanged. The producer's checked-in runtime
requirements already select **`build-record` 0.8.2** from
`zog144/build-record@a866c9c4b0dd385045f00ce2de7d809f5b67c104`.
The legacy host-deploy fallback `771af9429e83da40fd503625a6b4ba8329acee35`
is not the First Fonts runtime dependency and must not be selected.

The compiler-purpose receipt reader remains independently reviewed at
`image-build@1616f192ef9d8964a8f37f32a86c69c0242a213c`;
the signed compiler-acceptance consumer remains host-deploy PR29
`b3ac93cd92df1b280f087fbb748263d3371750aa`. The compatible
image-build **execution runtime** is separately selected and must be inspected
on the real Host; retaining the original `kind=image` and historical gaps is
required. A checkout pin alone cannot establish genuine native acceptance.

## Setup on the compiler Host, not host-registry

From an independently inspected **managed compiler lane** obtain its exact
`project_root`, installed `source_root`, `python_executable`, source revision
and specification digest. The native operator explicitly stages the public
source checkout at `<project_root>/companions/build-record`. One possible
first-time staging procedure, performed **on the compiler Host**:

```sh
set -eu
# Set PROJECT_ROOT from the already inspected managed lane record.
test -n "${PROJECT_ROOT:?}"
COMPANION="$PROJECT_ROOT/companions/build-record"
test -d "$PROJECT_ROOT/companions"
test ! -e "$COMPANION" && test ! -L "$COMPANION"
git clone --no-checkout https://github.com/zog144/build-record.git "$COMPANION"
git -C "$COMPANION" checkout --detach a866c9c4b0dd385045f00ce2de7d809f5b67c104
test "$(git -C "$COMPANION" rev-parse --verify HEAD)" = a866c9c4b0dd385045f00ce2de7d809f5b67c104
test -z "$(git -C "$COMPANION" status --porcelain=v1 --untracked-files=all)"
test -f "$COMPANION/src/zog/build_record/__init__.py"
```

If a companion already exists, **inspect and reuse only if its checkout, HEAD,
tree, Python API and source location match**. Never replace, reset or silently
rebind a previously selected lane. An incorrect existing lane binding is a
native HOLD requiring explicit operator review, not a reason to alter historical
operation records or send an SSM command.

After independently checking the source, use the existing
`image_build_lanes.bind_runtime_companion(...)` administrator API with
`repository='zog144/build-record'`, the exact commit above,
`producer_revision='1f07e83dbd80dacb9bed0d6494c697375f0e26cd'`,
`source_root='<project_root>/companions/build-record'`, the actual lane name
and its original specification digest. It is a **one-time binding**, not a
separate approval file.

The producer-side read-only status preflight is `python -B -m
zog.image_build.runtime_preflight --operation pipeline.inspect` with the
selected `--repository-root`, `--python-executable`,
`--component-root build-record=<project_root>/companions/build-record` and
only the provenance/controller/observed-state flags actually selected by that
operation. The `PYTHONPATH` must include the installed image-build runtime
`src` and the pinned companion `src`, as the host-deploy gateway constructs.
The gateway preflight verifies the Git HEAD and clean tree, the correct Python
module import location and API, `build-record` version 0.8.2 and required
revision **before** a producer SendCommand is admitted.

For status-only `pipeline.inspect`, build-record remains required even if
the optional provenance CLI binding is absent.

## Separation from Task C and native acceptance

The trusted `host-registry` gateway has only its existing ordinary
StateDirectory and the two small root-owned first Fonts catalogue/receipt files.
The catalogue carries the exact one-task libpng → FreeType → Fontconfig recipe,
original monthly pin and separately accepted compiler receipt; **do not add
build-record Git state or an approval file to it**. The compiler-side library
belongs to the managed compiler lane, not the gateway, and is not chosen by
GitHub issue contents. No XFS project quotas, 30+2 GiB policy or first-Fonts
21,600-second gate is required. Continue using the approved GitHub issue → FIFO
SQS → single trusted-Host SSM sender, locally fsynced send-once intent and
nonretryable uncertain acknowledgement.

Source tests are **not** evidence of native installation, accepted compiler
issuance, an installed source hash or a successful Fonts build. Verify the
actual lane, interpreter, installed runtime, companion and compiler-purpose
acceptance before authorizing any first submission.
