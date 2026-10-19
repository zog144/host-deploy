# Typed toolchain gateway implementation checkpoint (2026-10-19)

**Branch:** `regular/toolchain-gateway-20261019` based on `unstable@eba1b6eaae0e73b2469404243a15bc7fcad37b3e`.

**Disposition: SOURCE PREPARATION ONLY — LIVE GATEWAY NO-GO.**

## Reviewed producer boundary

The protected `host-deploy-toolchain-task-v1` file pins exactly
`zog144/image-build@857bb454e64102afa51a93ce0b9f8cce5924b67c`,
`self-hosted-c-cxx-toolchain-v1`, a retained 64-hex host-bootstrap seed
generation, a managed lane/owner, immutable monthly provenance pin, and the
producer's `image-build-toolchain-specification-v1` digest.

The file is read with canonical JSON, duplicate-key rejection, and (when
enabled for deployment) root ownership and non-writable ancestors. GitHub
cannot supply phase paths, controller configuration, seed, provenance,
arbitrary source revisions, or shell commands.

The gateway request protocol parses `toolchain.submit` with just
`{lane, task}` and source; `toolchain.inspect` / `toolchain.resume`
carry `{lane, operation_id}`. These are **parser-level declarations**,
not an execution grant. Explicit dispatch preparation for
`toolchain.submit` currently binds to a read-only producer
`toolchain.specification.inspect` operation. Explicit
`toolchain.inspect` is bound read-only. `toolchain.resume` fails
closed at dispatch preparation until the durable recovery owner has
verified the target operation and its controller evidence.

Do not mistake the specification inspection for an actual compiler
submission. The existing generic pipeline is restricted to
`xcb-support-image-v1`; it does not perform typed toolchain phases.

## Necessary completion before activation

1. Extend reviewed dispatch with a separate durable typed-toolchain
   supervisor. Use `toolchain.specification.inspect`, then a retained
   `toolchain.submit` operation for `cross-bootstrap` with exactly
   the protected seed generation. Follow producer phases in
   `image-build-toolchain-remote-execution-v1` without substituting
   generic `pipeline.submit`.
2. Bind each successor `toolchain.submit` to its *completed*
   predecessor operation ID. Only `final-libc-recover` can select
   the permitted failed `final-libc-publish` predecessor, on reviewed
   recovery evidence.
3. Persist every per-phase operation ID, immutable request hash,
   frozen source/lane/seed/specification and provenance, returned SSM
   CommandId, controller invocation/job IDs, producer pipeline IDs,
   attempt IDs, receipt digest and phase status before progressing.
   A `submitting` marker without retained CommandId remains
   **uncertain**, never automatically submitted a second time.
4. Poll with `toolchain.inspect` against the *same*
   `toolchain.submit` operation ID; `toolchain.resume` requires an
   explicit reviewed decision and must not allocate a new phase
   identity. A caller/runner interruption is not evidence of failure.
5. For completed `final-compiler`, validate
   `image-build-toolchain-artifact-v1` profile, immutable generation,
   exact specification, verification digest and active publication.
   `toolchain_receipt.validate_final_result` provides a
   **structural** receipt check; additionally verify the authenticated
   producer result and immutable generation manifest against the
   producer's `validate_final_manifest` contract before declaring GO.
6. Pin and install the exact producer and approved transitive runtime
   companions on an owned managed lane, run the interpreter/runtime
   preflight, and verify distinct build UID/GID, controller and
   root-control integration, ownership, runner disconnect, long phase
   continuation and reboot recovery.
7. Review the GitHub workflow operation allowlist and AWS issuer
   configuration separately. Enable only the exact task, lane, source
   revision and explicitly reviewed operation set; do not broadly
   enable arbitrary `build.submit` or compiler execution. The last
   live allowlist was `build.status` only.

The `unstable` deployment remains unaffected by this feature-branch
checkpoint. No real EC2, IAM, SQS, SSM, or image-build mutation has been
performed by this branch.

## Implemented supervisor follow-up (feature branch)

The typed supervisor is now implemented in `gateway/toolchain_journal.py`
and `gateway/toolchain_supervisor.py`, using the existing gateway
`verify_current_target`, `producer_runtime_preflight`, `remote_script`,
`parse_receipt`, SSM execution and owner lock. The review-only SSM wrapper
retains allowlisted `toolchain_specification`, `toolchain_execution`,
controller jobs and attempt IDs, instead of dropping these from the result.

For each authorized request:

- The immutable `typed-toolchain.json` journal binds its digest to the
  approved dispatch/task and pins the producer specification identity.
- Each phase submits using a deterministic operation ID. Subsequent
  `toolchain.inspect` calls reference that same original submit ID,
  while each inspection obtains a distinct deterministic observation ID.
- Durable intent `submitting` precedes every SSM SendCommand. Missing
  CommandId and interrupted send enter terminal uncertainty, never retry.
- Each authenticated SSM receipt is archived separately under
  `typed-toolchain-observations/<operation_id>.json` before advancing the
  journal, preserving CommandId, operation/request hash and producer evidence.
- `toolchain-authorize-resume` only permits a pending, evidenced phase to
  execute the producer's `toolchain.resume` against its original ID.
- `toolchain-authorize-recovery` permits `final-libc-recover` only after
  an observed failed `final-libc-publish` explicitly advertises recovery.
- Terminal `final-compiler` completion validates the producer's typed
  artifact contract, selected immutable generation, specification,
  verification identity and activation in the returned evidence.

The consumer's `--advance-reviewed-toolchain` option is independently
disabled by default. Enabling requires `--approved-toolchain-task` and
`--approved-toolchain-task-sha256`, both checked before allocating AWS
clients and rechecked against the protected file during supervision.
The shared durable 15-second advancement reservation limits the rate
across generic and toolchain work.

### Test and acceptance boundary

`tests/test_gateway_typed_toolchain_supervisor.py` covers phase lineage,
SSM interruption, `submitting` recovery, explicit resume,
final-libc recovery and journal tampering using isolated fake SSM.
The PR's public-source CI also compiles all shipped Python and includes
protocol, task and artifact receipt tests.

**Important:** These source tests cannot establish the authenticity of a
remote controller job or independently read the published generation manifest.
A real trusted image-build inspection and direct producer manifest validation
are still required for live GO. GitHub workflow operation and AWS role/queue
allowlists remain untouched. Do not merge/activate as production-ready solely
from green pytest.
