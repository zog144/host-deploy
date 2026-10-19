# Gateway pass 4: durable remote dispatch

Pass 4 connects an admitted gateway request to the existing transport-neutral
image-build remote-operation interface. The implementation keeps the long-polling
SQS consumer separate from command emission: remote preparation, SSM submission,
and observation are explicit administrative operations until live acceptance proves
the boundary.

## Durable SSM identity

The SSM runner exposes three separate operations:

- `submit_command(script)` performs only AWS `SendCommand` and returns the
  durable SSM `CommandId`;
- `inspect_command(command_id)` performs one read-only invocation observation;
- `wait_command(command_id)` waits on an already-known identity and never
  submits a replacement.

The existing `command()` helper remains compatible by calling submit then wait.

For gateway requests, `dispatch.json` freezes the exact remote binding before
SSM mutation. The binding includes the gateway request/workspace identities,
image-build lane, target AWS region/account/instance, deployed source
repository/revision, monthly provenance-pin repository path and identity, managed source/project roots,
server-selected request/result paths, exact image-build remote request, exact argv,
and SHA-256 of the canonical remote request.

The dispatch phases are:

`prepared -> submitting -> submitted`

or, if the SSM mutation may have happened but no command identity was durably
established:

`prepared -> submitting -> submission_uncertain`.

The `submitting` marker is fsynced before `SendCommand`. Only one submitter may
own that phase. A restart or lost SSM reply without a recorded command identity
becomes `submission_uncertain` and never authorizes automatic replay. A later
authoritative recovery of the exact `CommandId` can reconcile that same binding
to `submitted`.

When `submitted` becomes authoritative, gateway completion becomes `pending`.
Local restart reconciliation repairs these transitions only from retained evidence.

## Image-build operation adapter

The adapter maps:

- `build.status -> pipeline.inspect`
- `build.resume -> pipeline.resume`
- `build.cancel -> pipeline.cancel`

`build.submit` is now a **source-gated generic pipeline task only**:
`xcb-support-image-v1`. The generic coordinator freezes a separately
approved catalogue, performs exact deployed `capabilities.inspect`, then
`recipes.snapshot`, `pipeline.submit`, and `pipeline.inspect` with
different durable operation IDs. See [Generic pipeline dispatch](GATEWAY-GENERIC-PIPELINE.md).
Maintained worker task names remain forbidden.

The image-build remote `operation_id` is the gateway `request_id`, so duplicate
or recovered callers converge on the same image-build operation identity.

Preparation requires an admitted request, gateway-owned workspace, active
**managed** image-build lane, exact lane source revision/monthly-pin descriptor, and bound
host identity. Reservation-only lanes cannot execute gateway operations.

### Reviewed generic build selection

A valid and root-approved schema-2 task catalogue permits only the
`xcb-support-image-v1` generic pipeline selection. The producer now
advertises `recipes.snapshot`, `pipeline.submit`, and their distinct
reconciliation operations; **maintained workers are not mapped to generic
pipeline requests**. `dispatch-prepare` freezes the source revision,
monthly pin, managed lane/owner, selected immutable base generation,
exact recipe entries, mode and targets.

Preparation alone never submits an SSM command. Use the separate
`generic-advance`/supervised `--advance-reviewed-generic` pathway, with
the four-stage durable journal, source-bound producer capabilities and
preflight. The default SQS consumer remains admission-only, and the issue
workflow remains configuration-gated (GATEWAY-GITHUB.md). The opt-in supervised consumer refuses to
continue a prepared job automatically if the approved catalogue's
identity changes; the retained request remains available for an
explicitly reviewed recovery decision. See
[GATEWAY-GENERIC-PIPELINE.md](GATEWAY-GENERIC-PIPELINE.md).

## Exact deployed source verification

Before executing the frozen argv, the remote wrapper verifies the managed lane's
`source/` directory itself:

- it must be a Git checkout whose `HEAD` exactly equals the frozen revision;
- `git status --porcelain=v1 --untracked-files=all` must be empty;
- the frozen repository-relative monthly provenance pin must remain inside the checkout, traverse no symlink, and hash to the frozen monthly-pin identity;
- the same absolute pin path is passed to image-build as `--provenance-pin`, with the same digest as `--expected-pin-digest`.

These checks run even when an earlier result file already exists, so retained
results cannot bypass source verification.

The remote request is written atomically and fsynced. Existing request bytes must
match exactly. The image-build result is bounded, canonicalized, atomically
persisted, and reduced to a bounded identity/status receipt returned through SSM.
The full result remains on the image-build host.

## Result and recovery behavior

An SSM observation is persisted separately from gateway state. A successful SSM
command must return a receipt bound to the exact gateway request, source revision,
remote operation, and request digest.

Image-build result status maps as follows:

- `pending -> running`
- `completed -> completed`
- `failed -> failed`
- `released -> cancelled`
- any result with `uncertainty=true -> recovery_blocked`

A terminal SSM failure without a trustworthy image-build receipt also becomes
`recovery_blocked`; it is never converted into an automatic replacement command.

The immutable remote-result receipt records its intended completion state. If the
dispatcher crashes after fsyncing that receipt but before updating `state.json`,
local reconciliation completes the same state transition after restart without
calling AWS or rerunning image-build.

## Administrative commands

Preparation/reconciliation commands:

```text
host-deploy-gateway dispatch-prepare <request-id> [--task-catalogue PATH]
host-deploy-gateway dispatch-status <request-id>
host-deploy-gateway dispatch-reconcile <request-id>
```

Explicit AWS mutation/observation commands:

```text
host-deploy-gateway dispatch-submit <request-id>
host-deploy-gateway dispatch-observe <request-id>
```

`dispatch-submit` is the only pass-4 command here that crosses the SSM mutation
boundary. It requires an already-prepared binding and refuses a submitted,
submitting, or uncertain record. `dispatch-observe` only inspects the previously
recorded SSM `CommandId`.

The persistent SQS consumer remains admission-only **by default**.
It has a separate opt-in `--advance-reviewed-generic` mode requiring an
absolute, root-owned finite catalogue. It advances at most one durable
generic stage per polling iteration. No production instance is configured
to use this opt-in by this source change.

## Remaining live gates

Before automatic gateway dispatch is enabled:

1. Establish the real compiler workspace owner. Use an authentic handoff checkpoint
   if one becomes available; otherwise use the explicit lost-workspace adoption
   contract in `GATEWAY-ADOPTION.md` only after every expected direct writer has
   acknowledged stand-down and the operator has authorized adoption.
2. Create a real managed image-build observation lane and materialize a clean exact
   source checkout for its bound revision.
3. For the first read-only acceptance, no task catalogue is required; bind the
   explicit monthly provenance pin plus the historical observed state and use
   `pipeline.inspect`.
4. Perform the staged read-only `pipeline.inspect` SSM acceptance first.
5. Exercise lost/restarted command observation without issuing a replacement.
6. With the producer's implemented generic recipe snapshots and an independently
   approved fixed task catalogue, exercise the small `xcb-support-image-v1`
   task through `capabilities.inspect`, `recipes.snapshot`, `pipeline.submit`
   and `pipeline.inspect`. Retain each SSM command and controller receipt
   before considering longer compiler work. Maintained-worker mappings
   remain intentionally unsupported.
7. Add explicit gateway `build.retry` protocol semantics instead of treating retry
   as ordinary submit.
8. Complete pass-5 issue reporting before making the workflow operational by
   default.

No pass-4 code is automatically dispatching work from SQS to
`zog-image-build-toolchain`.


## External observed-state inspection

Image-build `3ac6f5c086227d4781608f28f76583e2d24ddac6` adds the
producer-owned `--observed-state-dir` contract. Host-deploy lane schema 3 may bind
one absolute historical state root, such as
`/var/lib/station-access/zog-compiler-view/state`, while retaining the gateway
lane's isolated state as the control/evidence state.

For such a lane:

- only `build.status -> pipeline.inspect` can be prepared;
- the exact observed state path is frozen in `dispatch.json`;
- the generated argv includes `--observed-state-dir`;
- the generated argv omits `--controller-config`;
- target/source/pin/observed-state/argv are all revalidated before SSM submission;
- changing the lane's observed state after preparation is an integrity fault.

The image-build producer resolves pipeline, attempt and generation evidence from the
observed state while writing new remote-operation/provenance/result evidence only in
the isolated lane control state. It suppresses live controller log queries and
rejects all external-state operations except `pipeline.inspect`.

This removes the pass-4 state-universe mismatch without copying or symlinking
historical pipeline evidence.


## Lost-workspace adoption boundary

When the original host-deploy checkpoint cannot be recovered, pass 4 does not
fabricate a handoff archive. The explicit recovery path is documented in
`GATEWAY-ADOPTION.md`.

The adoption operation binds the existing EC2/workspace identity, selected saved
state hashes, operator authorization and an exact writer-acknowledgement set. A
gateway-wide ownership lock serializes adoption. A remote ownership epoch is
compare-and-created before the gateway commits local ownership; lost marker replies
are observed, never blindly replayed.

Successfully adopted workspaces contain `adoption.json` instead of a fabricated
`launch.json`. The ownership epoch is preserved in `host.json`, and all subsequent
host-deploy SSM commands from that workspace verify the exact remote epoch before
running. Generic EC2 start/stop/terminate is not granted by adoption.

This technical epoch fences host-deploy operations. Direct external writers that do
not participate in host-deploy must explicitly stand down before adoption and remain
quiesced until ownership is deliberately transferred.

No live compiler-host adoption is performed by this implementation.
