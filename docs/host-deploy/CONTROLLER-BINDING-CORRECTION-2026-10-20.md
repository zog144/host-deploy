# Source-bound controller companion correction — 2026-10-20

**Owner:** host-deploy Regular implementation. **Review:** host-deploy Work,
typed-toolchain PR #2. **Disposition:** corrected source candidate; live
deployment and compiler submission remain NO-GO pending independent acceptance.

## Compatibility evidence

The producer's pinned
`zog144/image-build@857bb454e64102afa51a93ce0b9f8cce5924b67c`
`src/zog/image_build/runtime_requirements.py` declares:

| Component | Historical host-deploy frozen default | Required for new producer |
| --- | --- | --- |
| box-control | `c8e65abde37d6e2d9ce6fd3622e289826a253642` | `644170fc441863307092f329bf7e23cb64eb33e2` |
| build-record | `771af9429e83da40fd503625a6b4ba8329acee35` | `a866c9c4b0dd385045f00ce2de7d809f5b67c104` |

The previous global defaults were *not changed*. The new producer has an
explicit reviewed compatibility mapping, and the new controller choice must
be recorded on an **active managed schema-4 lane**. Historical bindings
without a `controller_companion` field continue to validate against their
original frozen profile and historical box-control revision.

## Binding and preparation contract

`image_build_lanes.bind_controller_companion` is a one-time operation with
an expected lane-specification digest. It requires:

- `producer_revision`: exact image-build source revision above;
- `repository`: `zog144/box-control`;
- `revision`: exactly `644170fc441863307092f329bf7e23cb64eb33e2`;
- `source_root`: exactly `<lane.project_root>/companions/box-control`;
- `expected_specification_sha256`: exact currently retained lane spec.

Binding an unapproved version, repinning an existing companion, or applying
the companion to an unrelated source fails closed. Repeating the same
binding is read-only/idempotent. Historical lane records are not edited by
this source change, and a new lane must be staged for the new producer.

For a new producer dispatch, `binding_for_request` now requires both:

1. an explicitly bound `runtime_companion` for build-record at the exact
   producer-specific revision;
2. an explicitly bound `controller_companion` at the reviewed box-control
   revision when the lane is controller-backed.

The resulting immutable dispatch includes the new
`controller_companion` and freezes its revision into
`runtime_profile.controller_revision`. `image_build_execution._binding`
validates the producer/source pairing and rejects forged or mismatched
controller values. `verify_current_target` additionally compares the
current lane record against the selected frozen companion.

`producer_runtime_preflight` still checks that the actual compiler-host
checkout HEAD is the exact frozen revision and that the producer's
`image-build-runtime-preflight-v1` report includes that exact
`validated_revision`. There is **no fallback** to the historical revision
for the new producer.

## Automated verification

`tests/fixtures/image-build-toolchain-runtime-requirements-857bb454.json`
records the relevant requirements from the exact producer pin.
`tests/test_gateway_dispatch.py` covers new-producer rejection before
explicit approval, successful one-time binding, `_binding`,
`verify_current_target`, and **the actual
`producer_runtime_preflight` verifier** (using a simulated SSM response
derived from pinned producer requirements). The tests also reject a
mismatched controller preflight report, a mutated lane companion, a
different requested revision, and ensure historical requests still resolve
to the original compatibility defaults.

These source tests are not a live checkout, controller or compiler
attestation. Work must independently confirm the fixture against producer
`857bb454...` and run preflight on the actual reviewed checkout/owned lane.

## Work rerun instructions

1. Inspect this PR's **exact** new head commit and the pinned producer's
   actual runtime requirements; compare the complete revisions.
2. Verify existing lane/ledger/ownership state read-only. Do **not**
   replace, repin, or mutate the historical lane; stage a distinct
   producer-bound lane with its real protected seed, monthly provenance,
   build-record checkout, box-control checkout and controller grant.
3. Run host-deploy's real dispatch binding and preflight against the
   pinned producer source, exact controller `644170fc...` and
   build-record `a866c9c4...`. Reject both historical controller revision
   and different reported validated_revision.
4. Verify same workspace/lane ownership, SSM receipt correlation and
   controller/job identities under interruption before any live mutation.
5. Keep PR draft; preserve `unstable`, `main`, existing service
   configuration, and GitHub `build.status`-only operation allowlist.
   Live submit/resume is a separate acceptance and authorization boundary.

No live compiler job, SSM mutation, AWS permission edit or production
deployment was performed as part of this correction.
