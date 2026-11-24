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

After independently confirming the exact Host/Project provenance, a trusted
administrative caller can pass that JSON to
`simple_forward.reconcile_project_observation(gateway_root, request_id,
observation)`. The function checks the original admitted dispatch, protected
SSM CommandId and previously recorded source/pipeline identity. Provisional
observations remain `running` or `recovery_blocked`. Only matching
producer `result.json` containing an unambiguous `completed/success`
or explicit terminal failure may generate an immutable Gateway terminal
receipt. This is **not** exposed as an arbitrary SQS message or requester
field; ordinary Gateway polling never resubmits the operation.

## Source acceptance and native HOLD

Regression checks use a synthetic Project producer that durably writes a
pipeline plus attempt before sleeping past a deliberately reduced test wait.
They assert the original ID/attempt survives, Gateway never records a false
terminal failure, and later read-only observation on exactly that
operation/pipeline can see completion without another submit. Separate tests
cover missing pipeline binding, changed/foreign owner and SSM command timeout
with no second send. The same test suite retains the queue, root-owner,
admission and acknowledgement-loss invariants.

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
