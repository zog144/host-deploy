# Persistent gateway consumer

This is implementation pass 3 of the GitHub-to-EC2 execution gateway. It turns the
SQS FIFO queue into a durable local request ledger on the command-center host. It
does **not** dispatch image-build operations yet; execution adapters are pass 4.

## Durability model

SQS is transport, not the authoritative execution record.

For each validated request the consumer writes:

- `requests/<request-id>/state.json`: the pass-1 immutable request binding and
  state-transition history.
- `requests/<request-id>/transport.json`: bounded SQS delivery and
  acknowledgement evidence.
- `requests/<request-id>/admission.json`: the latest local workspace-admission
  observation.

The request is accepted and `admission=pending` before the SQS message is deleted.
If the process crashes before that durable write, the message remains authoritative
and is redelivered. If it crashes after the durable write but before deletion, the
same request ID and digest are recognized as a duplicate and deletion is retried.
If deletion itself has an ambiguous outcome, `delete_uncertain` is retained and
redelivery remains safe.

The SQS FIFO deduplication window is therefore not relied upon for application
idempotency.

Malformed messages and a request-ID collision with different request bytes are
never acknowledged. A bounded failure record containing the body SHA-256, error,
message identity, and receive count is retained under `failures/`; the original
message is left for the queue's configured redrive policy and dead-letter queue.
The raw malformed body is not copied into local failure evidence.

## Workspace ownership

The dispatcher never operates an arbitrary existing host-deploy workspace.

Transfer from a Work-owned workspace is explicit:

1. The current owner exports a checkpoint with `handoff=True`.
2. host-deploy retires that source workspace *before* publishing the handoff
   checkpoint.
3. `host-deploy-gateway claim-handoff CHECKPOINT` restores it under the gateway
   state directory and writes a durable gateway ownership marker.
4. Pending requests for that exact immutable `workspace_id` may then transition
   from `admission=pending` to `admission=admitted`.

A normal, non-handoff checkpoint is rejected. Interrupted ownership transfer is
recoverable: the prepared ownership record binds the exact checkpoint SHA-256, and
a retry may finish an already-restored workspace but may not substitute another
checkpoint.

Admission obtains the existing host-deploy `workspace.lock`. If another operation
currently holds that lock, the request remains pending; there is no parallel
mutation.

Transfer back out uses:

`host-deploy-gateway release-handoff WORKSPACE_ID OUTPUT`

which exports another retiring handoff checkpoint and marks the old gateway copy
released. The released copy is no longer eligible for gateway admission.

## SQS configuration

The service validates both queues before consuming:

- primary: `zog-build-requests.fifo`
- dead-letter: `zog-build-dead-letter.fifo`
- region: `us-east-1`
- same 12-digit AWS account
- FIFO enabled
- SQS-managed server-side encryption enabled
- primary redrive target equals the expected DLQ
- `maxReceiveCount >= 2`

Either the exact queue ARN or canonical HTTPS queue URL may be configured.

The consumer uses one-message long polling with a 20-second wait and a 60-second
visibility timeout. It never receives from the DLQ for routine inspection;
`queue-status` uses queue attributes only, so administrative inspection does not
increase a dead-letter message's receive count.

## Service installation

The package includes
`zog.host_deploy.gateway/host-deploy-gateway.service` and the console entry point
`host-deploy-gateway`.

The installed system service expects:

`/etc/host-deploy/gateway.env`

with:

```text
ZOG_BUILD_REQUEST_QUEUE_URL=<primary queue ARN or URL>
ZOG_BUILD_DEAD_LETTER_QUEUE_URL=<DLQ ARN or URL>
```

No AWS access keys belong in that file. On EC2, boto3 obtains temporary credentials
from the instance role.

The service keeps durable state in `/var/lib/host-deploy-gateway`, has no
`RuntimeMaxSec`, and does not inherit host-deploy's launch uptime timer. Long
compilations will be owned by the later remote execution adapter/systemd units on
the build host, not by the SQS consumer process.

Useful administrative commands:

```text
host-deploy-gateway queue-status
host-deploy-gateway request <request-id>
host-deploy-gateway reconcile
host-deploy-gateway claim-handoff <checkpoint.zip>
host-deploy-gateway release-handoff <workspace-id> <checkpoint.zip>
```

## IAM boundary

For the initial development acceptance only, the user has approved the shared
`ZogEC2SSMRole` with:

- `sqs:ReceiveMessage`
- `sqs:DeleteMessage`
- `sqs:GetQueueAttributes`
- `sqs:ChangeMessageVisibility`

This is **not** the recommended production configuration.

The eventual deployment guide must use separate least-privilege roles:

- command center: queue consumption plus authorized EC2/SSM orchestration;
- image-build host: build-host capabilities only, with no command-queue
  consumption;
- GitHub dispatcher: primary-queue `sqs:SendMessage` only.

## Pass-3 execution boundary

After admission, `dispatch` remains `not_started`. The consumer does not call
SSM, image-build, systemd-run, or arbitrary subprocesses. Pass 4 must prepare and
persist the exact remote identity/input binding before any remote submission and
must reconcile `submission_uncertain` rather than replaying it.

The known synthetic `host.status` message submitted during pass-2 acceptance is
safe if encountered by this consumer. Its synthetic workspace is not gateway-owned,
so it can only become a durable accepted request with `admission=pending`; no
remote action exists in pass 3.
