# Typed compiler restored monthly pin — host-deploy Regular correction

**Date:** October 20, 2026  
**Branch:** `regular/toolchain-gateway-20261019` (draft PR #2)  
**Disposition:** source-only PASS; protected live submission **NO-GO** pending Work.

## New producer-bound binding

Image-build issue #1 restored reviewed October monthly provenance in an immutable,
new exact producer revision, without changing any previous image-build commit.

- Source producer: `zog144/image-build@31e6121cdf9fd05336286529666e2c35cdbe0831`
- Monthly pin: `project/pins/2026-10-01/commit-pin.py`
- Pin SHA-256 (on raw file bytes):
  `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`
- Selector: `project/pins/current.py` → `2026-10-01`
- Producer review: 133 catalogue projects, 139 executable stage recipes
- [Producer restoration review](https://github.com/zog144/image-build/blob/31e6121cdf9fd05336286529666e2c35cdbe0831/docs/image-build/MONTHLY-PIN-RESTORATION-2026-10-20.md)

`gateway/toolchain_task.py` now requires the precise producer+October-pin
combination to select any *new* `toolchain.submit` work. Its historical
`857bb454e64102afa51a93ce0b9f8cce5924b67c` constant remains available
to validate already frozen records, but **historical protected tasks cannot
be used to create new submissions**. A new root-owned task file and a
separate schema-4 controller-backed lane must be staged with the genuine
retained seed generation, reviewed specification identity, approved
lane owner and protected project path. Neither of these values may come
from the GitHub caller, nor may an existing lane be retargeted.

The exact controller and runtime checkouts remain independently pinned to
the producer's reviewed (unchanged) dependency contract:

- box-control: `644170fc441863307092f329bf7e23cb64eb33e2`
- build-record: `a866c9c4b0dd385045f00ce2de7d809f5b67c104`

`image_build_lanes.py` recognizes **both** the earlier typed producer and
the restored producer for this immutable compatibility pair. It retains
the historical default controller/build-record pins for all other legacy
bindings. `image_build_dispatch` and `image_build_execution` require
the exact explicit controller companion for the restored producer and
retain real revision/checkout preflight before execution.

## Source verification

The public source CI now checks out the **actual restored image-build
commit**, confirms the exact Git revision and hashes the pin file bytes
against the reviewed SHA-256, and verifies the active month selector.
This is independent from the host-deploy task data. Isolated tests verify
the new protected task, reject altered source/pin/month and retain
historical task parsing without permitting legacy new submissions.
The source-only tests also exercise distinct lane controller companion
binding, frozen preflight and unchanged historical dispatch compatibility.

No source checkout, host workspace ledger, SSM command or AWS role was
mutated by this correction.

## host-deploy Work — next isolated acceptance

1. Pin **this exact PR #2 head** and the exact producer commit above;
   independently confirm the reviewed pin file checksum and producer
   remote contract/compatibility prerequisites from a clean checkout.
2. Reconcile, **read-only**, the three existing compiler workspace lanes
   and prepared/in-flight requests. Preserve every original request,
   immutable generation, operation ID and controller invocation. Do not
   auto-adopt, repin or clear an uncertain marker.
3. Stage a **new distinct, reviewed schema-4 managed lane** with the actual
   root-owned box-control and build-record sources, protected seed and
   controller-owned project. Install the approved producer revision and
   exact pin without synthesizing an alternative lock.
4. Install a **new root-owned protected task definition** with the exact
   `31e6121c...` source, `d3104eed...` pin, approved owner/lane and
   reviewed specification hash. Verify immutable task digest and root DAC.
5. Exercise the **read-only** producer runtime preflight and
   `toolchain.specification.inspect`, checking the controller UID/GID,
   invocation receipts and exact generation binding, plus no unexpected
   state mutation. Distinguish an isolated readiness PASS from permission
   to start a long compiler job.
6. Only after independent review authorize the exact GitHub
   `toolchain.submit` operation, target lane, request origin and producer
   source. Explicitly review dispatcher/queue/IAM allowlists separately.
   Run the real multi-phase compiler bootstrap with preserved operation
   IDs, interruption/reboot recovery, final manifest and
   `image-build-toolchain-artifact-v1` verification. A green source
   test does **not** authorize that mutation.

**No change** was made to `unstable`, `main`, host runtime, production
IAM permissions, GitHub allowlists, source archive lease or any
already retained compiler workspace state.
