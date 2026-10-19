# Gateway lost-workspace adoption

This is a recovery path for a host whose original durable host-deploy workspace
checkpoint cannot be recovered. It is not a replacement for ordinary
`checkpoint.export(..., handoff=True)` / `claim-handoff`.

Use adoption only after recovery searches have established that an authentic current
handoff is unavailable and an operator has explicitly authorized adoption.

## Safety model

Adoption never invents `launch.json`, historical jobs, build success, generations,
or prior ownership history.

The adoption request binds:

- a new immutable adoption operation ID;
- the historical workspace ID already present on the EC2 host;
- AWS account, region and exact instance ID;
- target owner `host-deploy-gateway`;
- an explicit `missing_original_checkpoint: true` declaration;
- bounded operator authorization text;
- selected saved-state SHA-256 evidence;
- the exact expected writer set;
- one explicit `quiesced: true` acknowledgement for every expected writer.

The gateway re-reads the current EC2 inventory and requires the existing
`ManagedBy=host-deploy` and `ZogWorkspace=<workspace-id>` tags. The retained
inventory binds instance type, state, launch-time observation, selected tags and
attached EBS volume IDs.

A gateway-wide adoption lock serializes local adoption attempts. A remotely
compare-and-created ownership marker at:

`/var/lib/host-deploy/ownership.json`

binds the same workspace, instance, account, region, adoption operation and ownership
epoch.

The remote marker is not claimed to fence arbitrary old scripts that do not
participate in host-deploy. Direct writers must be quiesced before adoption and must
remain quiesced until ownership is deliberately transferred. After adoption,
host-deploy `Host` commands issued with the adopted workspace verify the exact remote
ownership epoch before running their requested SSM script.

## Adoption request

The CLI consumes a bounded JSON file:

```text
host-deploy-gateway adopt-workspace adoption-request.json
```

Shape:

```json
{
  "schema": 1,
  "operation_id": "<new-32-hex-id>",
  "workspace_id": "<existing-32-hex-workspace-id>",
  "name": "zog-image-build-toolchain",
  "profile": null,
  "region": "us-east-1",
  "account_id": "<12-digit-account>",
  "instance_id": "<exact-instance-id>",
  "target_owner": "host-deploy-gateway",
  "missing_original_checkpoint": true,
  "operator_authorization": "<bounded authorization evidence>",
  "saved_state_hashes": {
    "pass3-state": "<64-hex-sha256>",
    "pass3-transport": "<64-hex-sha256>"
  },
  "expected_writer_set": [
    "archive-mirror-work",
    "image-build-work",
    "integrate-observe-work"
  ],
  "writer_acknowledgements": [
    {
      "writer": "archive-mirror-work",
      "acknowledgement": "<bounded stand-down evidence>",
      "quiesced": true
    },
    {
      "writer": "image-build-work",
      "acknowledgement": "<bounded stand-down evidence>",
      "quiesced": true
    },
    {
      "writer": "integrate-observe-work",
      "acknowledgement": "<bounded stand-down evidence>",
      "quiesced": true
    }
  ]
}
```

The expected writer set is chosen by the live acceptance owner. The implementation
requires exact one-for-one acknowledgements; it does not silently add or remove
writers.

## Durable phases and uncertainty

The operation is retained under:

`<gateway-state>/adoptions/<operation-id>.json`

The normal path is:

`prepared -> marker_submitting -> marker_submitted -> marker_confirmed -> owned`

The `marker_submitting` record is fsynced before the remote marker mutation.

If the SSM submission reply is lost, adoption records `marker_uncertain`. Recovery
does **not** resend the ownership mutation. It performs a read-only observation of the
remote marker:

- exact marker present -> continue the same operation;
- marker absent or different -> remain blocked and refuse replacement mutation.

If the process fails after remote marker confirmation but during local workspace
creation, retry completes the same local adoption. Existing partial files must match
the exact retained adoption evidence.

Concurrent callers for the same adoption serialize under the ownership lock and
converge on one remote marker mutation.

## Adopted workspace contents

Only after the remote marker is authoritative and the live EC2 identity is
revalidated does host-deploy commit:

- `workspace.json`;
- `host.json`;
- `adoption.json`;
- `gateway-owner.json`.

There is deliberately no fabricated `launch.json`.

`host.json` carries the ownership epoch and adoption operation identity.
`adoption.json` preserves the missing-checkpoint declaration, operator
authorization, saved-state hashes, writer acknowledgements, live inventory digest
and ownership epoch.

The ordinary gateway ownership marker then makes the workspace eligible for request
admission.

## Lifecycle boundary

Adoption does not grant broad EC2 lifecycle authority.

For an adopted workspace:

- `operate(..., "status")` remains available;
- ordinary `start`, `stop` and `terminate` are rejected.

Pass-4 work may use the already-running host through SSM only after the remote
ownership epoch guard succeeds.

A later lifecycle design would require its own reviewed authority and recovery
contract.

## Handoff after adoption

Checkpoint schema accepts `adoption.json` as the host lineage alternative to
`launch.json`.

Exactly one lineage is required for a host:

- normal provisioned workspace -> `launch.json`;
- explicitly adopted workspace -> `adoption.json`.

Therefore an adopted gateway workspace can later use the existing supported
`release-handoff` / checkpoint / `claim-handoff` path. The adoption lineage and
ownership epoch survive the checkpoint.

## Administrative status

Read retained adoption state without changing AWS:

```text
host-deploy-gateway adoption-status <operation-id>
```

## Live acceptance requirements

Before the first live compiler-host adoption:

1. reconfirm account, region, instance ID, workspace tag and EBS identity;
2. reconfirm all selected saved-state hashes;
3. obtain explicit stand-down acknowledgements from every expected direct writer;
4. confirm no active compiler/build mutation;
5. verify no existing conflicting gateway claim for the instance;
6. preserve the existing pass-3 gateway ledger;
7. use one fresh adoption operation ID;
8. execute `adopt-workspace` once;
9. record the SSM marker command identity and adoption receipt;
10. verify `adoption-status`, the local workspace lineage and remote ownership
    epoch;
11. verify no EC2 lifecycle, build, cleanup, generation or provenance mutation
    occurred as a side effect.

If the operation becomes marker-uncertain and the remote marker cannot be proven
exact, stop. Do not create another adoption request to bypass uncertainty.

No live adoption is performed by this implementation/documentation change.


## Recovery after a definite SSM service rejection

A synchronous AWS `AccessDeniedException` returned by the `SendCommand` API is
different from a timeout or lost response: AWS rejected the request before creating
an SSM command, so there is no command identity to reconcile.

Current code records future occurrences as:

`marker_rejected`

with bounded structured rejection evidence. It does **not** automatically resubmit.

The live pass-4 adoption attempt predates that classification and retained the same
AccessDenied failure as `marker_uncertain`. The explicit recovery command supports
that historical shape only when all of the following are true:

- the retained operation/request bytes still match exactly;
- there is no retained marker CommandId;
- the retained error proves `AccessDeniedException` for `SendCommand` /
  `ssm:SendCommand`;
- current EC2 inventory is byte-for-byte equivalent to the inventory frozen at
  adoption preparation;
- a new read-only observation proves the remote ownership marker is absent;
- there is no conflicting local gateway ownership claim.

Run:

```text
host-deploy-gateway recover-rejected-adoption <same-adoption-request.json>
```

The command performs no ownership-marker mutation. It records a bounded
`definite-send-command-rejection` recovery receipt and moves the retained
operation to:

`marker_retry_authorized`

Only then may the exact same adoption request be passed again to:

```text
host-deploy-gateway adopt-workspace <same-adoption-request.json>
```

That retry performs one new marker submission using the **same operation ID and
ownership epoch**. The retry count is retained.

A true unknown outcome remains protected. Timeout/network/process-loss
`marker_uncertain` records without definite service-rejection evidence are rejected
by `recover-rejected-adoption` and cannot gain retry authority through this path.

If the recovery observation finds the exact ownership marker already present, do
not authorize a retry; resume the ordinary same-operation adoption reconciliation.
If it finds a different marker or live inventory drift, stop.

The recovery command is idempotent after it has reached
`marker_retry_authorized`; repeating the recovery command does not issue a marker
mutation.
