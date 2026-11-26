# Project-current receipt parsing and retained request #63 readback

**26 November 2026 · Source-only candidate · No SSM SendCommand or pipeline replay.**

## Selected execution and failure

The active Fonts installation is schema 5, using the existing
`/home/certbot-build-owner/certbot-seed` Project and its selected
controller. The Gateway dispatch format for the new Project-current
execution is **schema 4**; the number 4 here is the *dispatch schema*, not
the superseded schema-4 installation. It stores the request's fixed
repository in `binding.remote_request.source.repository`; the compiler
resolves the selected Project checkout's revision at execution time.

An original Fonts request, `636161e194f02f8216efe14ff8c74cc4`, was
already submitted. Its original SSM CommandId completed, but
`dispatch-observe` rejected its receipt with
`image-build result summary differs from dispatch binding`. Do not
submit this request again, edit its producer pipeline/attempt, repoint
the selected Project, or invent a newer revision.

## New wire contract: normalized-summary-v1

The Project-current wrapper requires the producer's returned
`schema`, `operation_id`, `operation_type`, `source_repository` and
`source_revision` to match the exact original selected request.
It transmits **one bounded normalized result** including identity,
source revision, pipeline ID, status, terminal outcome, failure,
uncertainty, allowed next operations, missing evidence count,
recipe/selected generation, attempts, controller jobs, predecessor,
artifact subset and reconciliation flag.

`result_representation: "normalized-summary-v1"` declares that
`result_sha256` and `result_bytes` cover exactly the bytes of:

```python
json.dumps(receipt["result"], sort_keys=True, separators=(",", ":"),
           ensure_ascii=True, allow_nan=False).encode("ascii")
```

Gateway `image_build_execution.parse_receipt` recomputes **both** the
digest and byte count before granting normalized receipt status.
A corrupted count, hash, missing field, wrong operation, incorrect
repository, malformed uncertainty, out-of-bound artifacts or
mismatched resolved revision fails closed.

The new `source_evidence` record binds the compiler-resolved Git HEAD to
the exact immutable `remote_request` template and the source request
written durably by the original wrapper. Its request SHA-256 is the
digest of canonical JSON with the resolved revision inserted and a
trailing newline. Gateway independently reconstructs this request from
the **frozen** binding and received Git revision, checking exact
repository, revision and source-request digest. The original SSM
CommandId and selected compiler instance are also verified at
observation; the mere presence of a new receipt is not a new dispatch
authorization.

Existing pinned schemas 1–3 continue to require their frozen
`binding.source.repository` and `binding.source.revision`; they do
not resolve a later checkout revision.

The fixed Project-current import bootstrap is deterministically packed
using zlib/base64 in **new only** source-generated commands. This keeps
the protected original SSM script under the existing root-control
32 KiB ceiling without increasing permissions or changing any
historical already-frozen script bytes. Runtime module-origin tests
still verify import from the selected Project, not installed fallback.

## November 26 independent review corrections: terminal and recovery identity

Both Gateway entry points now use the exact same
`project_current_completion()` result classifier for a new schema-4
Project-current dispatch. The canonical wire hash is **not** proof of a
completed pipeline. A terminal successful `pipeline.submit` requires
a valid original 32-hex pipeline ID, `status=completed`,
`terminal_outcome=success`, `uncertainty=false`, no unresolved
`reconciliation_required`, and no failure. Contradictory even
self-consistently rehashed normalized receipts remain
`recovery_blocked`; they cannot create terminal `remote-result.json`.
A genuine pre-pipeline request-validation failure with a structured
failure reason can remain failed without a pipeline ID. The compiler
wrapper now **rejects** invalid/missing/None producer uncertainty and
status/terminal evidence rather than coercing it to false.

The original receipt's claimed source revision and pipeline ID are
retained in a typed `dispatch-observation.json` for **both** observers:
`host-deploy-project-current-legacy-receipt-v1` for the old
unverifiable full-result hash; and
`host-deploy-project-current-normalized-receipt-v1` for a new
authenticated normalized summary. Both store the original CommandId,
compiler instance, frozen request SHA, repository, revision, pipeline,
status, declared hash/size and `producer` claim, with a truthful
`raw_result_digest_verified` bit. Re-polling an original SSM command
cannot replace a different retained source/pipeline/terminal claim.

Before any protected same-operation read-only SSM inspection,
`reconcile_project_observation()` validates the complete retained
typed claim against its original dispatch and target, extracts that
specific original pipeline ID as `expected_pipeline` for the
fixed source-only observer, and compares the independent Host's
revision and pipeline against the original claimed values **before**
any terminal write. A changed revision/pipeline, mismatched Host/
CommandId/request digest, or invalid typed record HOLD without
changing original evidence. The distinct read-only inspection retains
its separately journaled operation and CommandId; it cannot replay
the original build's protected send-once intent.

Disposable CI tests verify a real fixture producer writing its
completed pipeline and attempt, both observers' identical terminal
classification, a self-consistently rehashed false-success receipt,
pre-pipeline failure, missing/invalid uncertainty, an original
CommandId that changes its claimed result, and protected mismatching
or matching source/pipeline readback without a new original SSM send.

## Retained old receipt: incomplete integrity is not success

The **already sent** Project-current wrapper reported the digest and
byte size of the full producer result but put only an eleven-field
summary on the SSM response. That untransmitted raw producer object is
not reconstructible from the old receipt. Reinterpreting its hash as
the hash of the eleven-field summary would be false verification.

For the old receipt format (no `result_representation`) and a
validated schema-4 frozen binding, the parser now checks the outer
original request/digest identity, fixed repository, source-revision
shape, pipeline identity, status, uncertainty and bounded summary
fields. It records a separately typed provisional SSM observation
including the **declared** original result hash and size with
`raw_result_digest_verified=false`. It retains the original
CommandId and marks the Gateway completion `recovery_blocked`.
It does **not** write a terminal `remote-result.json`, authenticate
a nonexistent producer-result payload, infer a revision or replace
the failed attempt/pipeline. A missing, foreign or malformed original
SSM response still fails closed.

**Next native action, after independent review and installation only:**
run the existing supported `dispatch-observe` against the SAME
previously recorded CommandId; inspect the provisional result without
submitting a new command. Independently read back the original
operation's Project-owned pipeline and attempts through the reviewed
protected read-only selected-Host observer. That native evidence, not
the old uncheckable hash, must decide terminal state. Do not use
`pipeline.submit`, `pipeline.resume` or a fabricated replacement
receipt to reconcile request #63.

`build.submit` remains enabled for separately authorized **new**
requests. The current Project/controller verification, durable
Gateway ledger, root-control send-once intent, and no-replay
protections are unchanged.
