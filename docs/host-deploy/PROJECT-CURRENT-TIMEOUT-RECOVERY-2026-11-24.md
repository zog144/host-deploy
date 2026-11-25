# Project-current durable submission and timeout recovery

Source owner: host-deploy Regular, draft PR #57 stacked on **PR #54**.
Native owner: host-deploy Work, using the existing approved selected Project
and protected root-control Task C owner. No live request or AWS mutation is
part of this source change.

## Observed failure and unchanged identities

An already accepted request `0f06e78980aeee4f0948a48198dc8276` ran from
the selected Project through the original source `5d093474063b0b11609e8be4b4dc090e531ef760`.
The producer wait was only 240 seconds while the enclosing SSM command
expired after 300 seconds and the controller policy permitted 14,400 seconds.
The Gateway classified the timed-out SSM invocation as terminal failure, even
though image-build pipeline `221e8a102bff4544a686f0d7964b3d1e` and
attempt `image-63dcd6a137f040bc9224dce166a916ed` were still running.

**Do not replay that earlier operation.** The old protected Task C intent,
SSM command and Gateway failure evidence are historical records. New source
cannot automatically change an already-terminal old Gateway record. Work may
use the new *read-only* observation against that original Project and
operation ID; any explicit administrative reclassification of old evidence
needs separate independent review.

## Two bounded control windows

- Controller build policy: 14,400 seconds, unchanged.
- Schema-4 Project-current producer subprocess wait: 14,400 seconds, up from
  240 seconds; exit or TimeoutExpired is reconciled against the already durable
  original remote-operation and pipeline evidence.
- Schema-4 protected root-owner SSM executionTimeout: 14,700 seconds, up
  from 300; 300 seconds headroom covers initial checkout check, bounded
  observation, output serialization and cleanup.
- Existing legacy schema-1/2/3 SSM timeout: remains 300 seconds. No new
  GitHub/SQS input controls these limits. The fixed root-control
  `LocalTaskCJournal` accepts up to 21,600 seconds and still performs
  the *one* O_EXCL/fsynced SendCommand intent.

This uses a single authorized SSM submission; no detached shell process,
new service/user, second pipeline.submit, new SQS entry, automatic
pipeline.resume or broadened controller permissions is introduced.

## Recoverable original producer evidence

The selected Project's immutable
`gateway-requests/<request_id>/request.json` retains the original
operation/request and source revision. Image-build itself retains
`state/image-build/remote-operations/<request_id>/request.json` and
`binding.json`; the latter identifies the pipeline, and its
`state/image-build/pipelines/<pipeline_id>/pipeline.json` owner must match
the exact original request ID, source repository and revision.

If the producer times out after creating a pipeline, the wrapper performs
only bounded, read-only owner-checked observations and returns a
`host-deploy-image-build-receipt-v1` with `status=pending`,
`uncertainty=true`, `terminal_outcome=null`, the retained pipeline ID
and attempt IDs, and `reconciliation_required=true`. If the binding
was not committed before an interruption, the observer can identify up to
4096 immutable pipeline owners without writing another binding or creating
another pipeline. A missing/unsafe/mismatched record is never silently
converted to a confirmed successful build.

An original SSM invocation that `TimedOut`, `Failed` or
`Cancelled` without a valid producer result is classified Gateway
`recovery_blocked`, not a terminal pipeline outcome. A successful SSM
invocation whose producer reports a nonterminal pending/running result is
classified Gateway `running`. These phases do **not** create the immutable
terminal `remote-result.json`, so later controlled observation can reconcile
the same operation without trying another SendCommand.

## Explicit read-only observation and reconciliation

To inspect a retained pipeline on the selected Project Host, generate the
command from reviewed source:

```python
from zog.host_deploy.gateway.project_current_observation import read_only_observation_script
command = read_only_observation_script(
    selected_project_root, "/usr/bin/python3.12",
    "0f06e78980aeee4f0948a48198dc8276",
    pipeline_id="221e8a102bff4544a686f0d7964b3d1e",
)
```

Run **only through the already approved read-only Host inspection workflow**;
do not submit that original operation or run the mutable producer again. The
script uses Python `-I -B`, standard-library JSON/FD/ownership validation
and the *same* persisted source revision and pipeline owner. It prints
`host-deploy-project-current-observation-v1` with the selected Project root,
operation ID, pipeline ID, pipeline state, retained attempts, producer result
state (when present), `mutation=false` and
`execution_authorized=false`. Missing or changed owned evidence fails
closed. The helper does not call the pipeline or controller.

After independently confirming the exact Host/Project provenance,
the trusted **registry Gateway administrator** may invoke the explicit
observation command below **only with the installed protected root-control
inspection owner**. The Gateway is not co-located with the compiler Project:

```python
from zog.host_deploy.gateway.simple_forward import reconcile_project_observation
result = reconcile_project_observation(gateway_root, original_request_id)
```

There is **no caller-supplied observation parameter**. The function itself
checks the original admitted dispatch, unchanged selected Workspace/Host/Project,
protected SSM CommandId and prior pipeline/revision evidence, then sends the fixed observer through a distinct durable protected
root-control inspection operation to the selected compiler Host. Gateway
input cannot supply `terminal_confirmed`, `producer_status`,
`pipeline_status`, `source_revision`, or any status-bearing evidence
dictionary. The compiler observer anchors all Project path ancestors and evidence
files through no-follow directory descriptors, checks opened inode custody,
and rechecks the Project binding before reporting. It requires the actual
compiler Project's protected ownership and matching request,
producer binding, source revision and pipeline owner. Missing or tampered
evidence produces a HOLD, not a terminal result.

**Success now derives from image-build's documented durable publication order.**
Image-build writes each retained attempt's `status.json` as `complete`
for the selected generation, then records the owned `pipeline.json` with
`status=complete` and the *same* 64-hex generation. Once those statuses
and the operation's exact source/pipeline owner are independently read back,
the observer confirms completion even when the **original**
`remote-operations/<operation_id>/result.json` is still pending or absent
because its synchronous producer already timed out. A stale or forged
`result.json` alone is never sufficient to mark a running or incompletely
published pipeline successful. Missing, duplicated or incomplete attempt
status, foreign owner/source, and unsafe evidence custody all HOLD. A
confirmed terminal command failure must likewise retain original
source/pipeline binding, an explicit nonuncertain producer failure result and
a pending (not running) owned pipeline. Unknown or pending outcomes remain
recoverable.

The Gateway persists the new read-only evidence digests and unchanged
original SSM CommandId; provisional observations remain `running` or
`recovery_blocked`. Only independently verified terminal evidence creates
the immutable `remote-result.json`. This is **not** exposed as a new SQS
message or requester-supplied JSON. Ordinary Gateway polling never replays
the original producer. A later poll cannot replace a newer reconciled Project
status with the original SSM control-window `TimedOut` result.

**Native dependency:** the registry Gateway and compiler remain separate.
The Gateway cannot use generic `Host.submit_command` to perform inspection.
A protected root-control `LocalTaskCJournal` must be available to the
trusted owner, with a root-owned directory, an independently reviewed
fixed inspection policy and appropriate SSM principal. Each explicit
inspection writes a local create-only intent before the journal itself
records a distinct immutable send-once operation. Lost acknowledgement
is reconciled from that protected journal, never resent. The owner checks
the frozen request, target, original protected CommandId, Project, expected
pipeline and exact generated script hash; it does not replace or replay the
original build operation. Native Work must verify this exact permission
and installed-byte contract before any SSM inspection; the source-only
candidate is not permission to run one.

## Source acceptance and native HOLD

Regression checks use a synthetic Project producer that durably writes a
pipeline plus attempt before sleeping past a deliberately reduced test wait.
They assert the original ID/attempt survives, Gateway never records a false
terminal failure, and later read-only observation on exactly that
operation/pipeline can see completion **solely after the actual image-build
pipeline and attempts are updated**, without any fabricated terminal
producer result or new submit. Other tests reject forged completed
`result.json` while pipeline is still running, completed pipeline missing
attempt status, a foreign operation/source/pipeline owner, and SSM timeout
with no second send. The gateway's reconciliation API rejects a caller's
terminal JSON entirely; it reopens and verifies the actual local Project. The same test suite retains the queue, root-owner,
admission and acknowledgement-loss invariants.

**Independent source-supported continuation regression:** the source CI also
checks out actual image-build
`bce80b258e445191248d9998620884a79f029013` in a separate
disposable companion directory. It runs the real `RemoteOperations.execute`
default Project `pipeline.submit` against a synthetic generic package
set with the reviewed three target names, deliberately stops the first
controller call after the pipeline is durably prepared, then invokes the
**real** `ImageBuild.resume(original_pipeline_id)` in a fresh isolated
Python process. Image-build itself writes the completed attempt statuses
and the terminal pipeline record. The Gateway's read-only observer then
confirms terminal success **without** changing the original pending
`remote-operations/<original_operation_id>/result.json`, fabricating
a terminal producer result, allocating a new pipeline, or calling another
SSM sender. The test compares the complete pipeline ID inventory before
and after resume. Its recipes are explicitly separate from the real
Fonts catalogue and do not claim the real Fonts stage-pin approval gate
was exercised.

This is a source-only integration fixture, **not** evidence that the
native compiler job has completed or that the failed historical request
can safely be replayed. The native protected controller and versioned
issuer guards retain their own approval requirements.

**Native Work gate:** review/install/attest exact PR #57 on top of PR #54
without dropping PR #51 root-owned SendCommand or PR #53 incomplete-request
reconciliation. Revalidate the installed root journal's 14,700-second
deadline capability and root-owned intent/SSM identities, the selected
Project import, source and package pins, retained pipeline owner, and
existing controller limit. Work should first inspect the already-running
pipeline with the read-only helper; **do not replay request
0f06e78980aeee4f0948a48198dc8276**, issue another GitHub event, submit
a second pipeline, change the queue, or claim native success without a
separately approved acceptance check. The Fonts lane remains under its
existing authorization boundary.


## Nov 25 — split registry Gateway/compiler and unarchived mixed-state recovery

The registry Gateway runs on a different Host than compiler instance
`i-00ad300038a599044`. The active schema-5 first-Fonts lane selects the
**existing certbot-seed Project** at
`/home/certbot-build-owner/certbot-seed`; its owner is UID 24201.
The pending `first-fonts-inherited-migration-v1.json` intent with
`phase=installing` concerns the **different** initialization destination
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`.
The approved schema-4 record and its archive are absent. These separate
Project identities must NOT be conflated or recreated.

PR #57 now makes the Gateway build an immutable read-only observer script
and dispatch it through a distinct, 120-second SSM inspection on the
**frozen compiler instance**, rather than trying to read a Gateway-local
Project. It verifies the returned CommandId, instance ID, successful SSM
result, original operation/pipeline/source binding, selected Project root,
Project-owner UID 24201, evidence digest and terminal attempt records.
The original build CommandId remains unchanged and never replays. The
inspector accepts no caller-supplied status and cannot submit, resume or
compile. An unexpected Host, command identity, ownership, source or
incomplete attempt is HOLD. A historical terminal Gateway failure cannot
be reclassified by this new observation path.

The new **schema-4-archive-free** recovery is deliberately explicit:
`fonts-lane-mixed-recovery-inspect` and
`fonts-lane-mixed-recovery-publish` require the Workspace and **three
independently approved, full SHA-256 values** for the original historical
specification, corrected *initializing* specification, and actual active
*selected certbot-seed* schema-5 specification. The old digest is pinned
in source; the other two must come from independent reviewed evidence,
not from simply echoing the active record or intent. The source verifies
both Workspace/Host and active lane identity, original and corrected
intent digests, schema-5 existing Project selection, root/controller,
separate destination, absence of the original archive, initializer
manifest and three source-tree hashes. Then it performs two read-only
checks on the compiler: `host-install-fonts-project-init --verify` for
the pending **other Project**, and
`existing_project_runtime.inspect()` for the actual certbot-seed
selection. This is not a migration copy, rematerialization or manual
JSON recovery.

Only after all checks pass can an explicitly requested publish create
a protected 0600, create-only, nonauthorizing provenance receipt
`first-fonts-mixed-state-recovery-v1.json`. The original active lane,
pending intent and absent schema-4 archive remain **unchanged**. The publisher performs a **second compiler Host readback under the
publication lock** and refuses a controller/source change between the two
inspections. Even a matching retained receipt proves only historical
read-only provenance, not a fresh immutable compiler-controller identity.
**New direct Gateway build admission for the existing certbot-seed Project
remains explicitly disabled** until a separately reviewed fixed current
controller attestation can be enforced at the actual admission boundary.
This prevents a controller that changed after receipt publication from
obtaining submission authority through local hashes alone.

**Known native HOLD:** the previously observed initializer expected
image-build source revision `620378bd...`, while current
`certbot-seed` had revision `bce80b25...`. Do not falsely accept
`host-install-fonts-project-init --verify` under that mismatch.
The new source allows a supported proof path *without* a schema-4
record, but this live discrepancy must be independently resolved before
publication or authorization of another build. Historical request
`0f06e78980aeee4f0948a48198dc8276` and its prior Gateway
terminal failure remain immutable.

The 14,400-second producer, 14,700-second Project-current control
window, 300-second legacy routes and protected build send-once owner
remain unchanged. Work must first install and attest a separately
reviewed exact source revision; no native SSM command, pipeline replay,
Project write, Gateway start, or Fonts compilation occurred in Regular.


## November 25 independent review corrections — source-only and still HOLD

The corrections after review `2d5792396fea6464cc77b7c9ea37c84b5a403b6f`
retain the original 14,400/14,700-second windows, the original Task C
journal CommandId and the existing pipeline identity.

1. **No unprotected observation sender.** The registry process does not call
   `Host.submit_command` directly for Project inspection. The fixed
   script is compared against the frozen original admitted operation and
   dispatched by the root-control protected owner using a *different*
   one-use inspection operation ID and an O_EXCL/fsynced Gateway attempt
   record. Only a confirmed terminal inspection command may finish its
   attempt; an uncertain acknowledgement cannot create another attempt
   until separately reconciled. The owner contract requires the existing
   protected root-control library and actual root-backed storage. This
   does not manufacture new AWS permission or promise a dedicated SSM
   document; Work must independently verify the selected principal,
   inspection-owner installation and permissible IAM policy.
2. **Anchored file custody.** The embedded standard-library-only observer
   opens every ancestor from the real filesystem root with `O_DIRECTORY`,
   `O_NOFOLLOW` and `dir_fd`, checks opened dev/inode, owner/mode and
   disallows redirects. Every retained request, producer, pipeline and
   attempt JSON file is opened through that Project descriptor and checked
   before/after read. It refuses a changed Project identity at final
   readback. Source tests deliberately exercise symlinked ancestry.
3. **Non-authorizing mixed-state receipt.** The recovery publisher re-observes
   the actual selected controller and other initializing Project while
   holding the publication lock. A changed controller cannot be accepted
   merely because local intent/lane bytes are unchanged. A later drift
   cannot be excluded by a historical receipt: this draft intentionally
   HOLDs new direct forwarding using an existing certbot-seed lane pending
   a separately accepted current-controller admission mechanism. Nothing
   may reinterpret the receipt as permission to submit another build.

The native test has not been performed. Do not issue a new inspection or
build SSM call, unmask the gateway, publish a native mixed-state receipt,
rewrite the historical request, or resume the old pipeline without its
separately reviewed and explicitly authorized procedure.
