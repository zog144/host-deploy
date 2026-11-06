# Configurable public GitHub dispatcher

The issue-opened workflow is public. It validates a bounded request with no AWS
credentials first, then revalidates it in a separate submission job. Submission
requires the repository-admin switch `ZOG_GATEWAY_SUBMIT_ENABLED=true`.
Missing configuration fails closed. Public source CI never requests OIDC credentials.

## Repository deployment variables

Configure these under Settings → Secrets and variables → Actions → Variables:

| Variable | Value |
|---|---|
| `ZOG_GATEWAY_DISPATCH_REVISION` | Reviewed immutable 40-character public host-deploy commit containing the dispatcher |
| `ZOG_GATEWAY_AUTHORIZED_ACTORS` | JSON array of permitted GitHub logins |
| `ZOG_GATEWAY_ALLOWED_OPERATIONS` | JSON array; use `["build.status"]` for read-only Phase A |
| `ZOG_GATEWAY_AWS_REGION` | `us-east-1`, the currently supported gateway region |
| `ZOG_GATEWAY_ROLE_ARN` | Deployment's OIDC submission IAM role ARN |
| `ZOG_GATEWAY_QUEUE_URL` | Deployment's exact `zog-build-requests.fifo` URL or ARN |
| `ZOG_GATEWAY_SUBMIT_ENABLED` | `false` until the deployment's AWS trust and queue are verified; `true` enables submission |

These identifiers are configuration, not AWS credentials. No account number,
instance, live queue URL, machine address or permitted person is built into the
workflow. The existing transport contract deliberately still restricts the region
and FIFO queue name; this change does not create arbitrary-endpoint dispatch.
The role and queue account must agree. Changing allowed operations does not bypass
server-owned lane/task authorization.

The workflow checks out only the configured exact commit and verifies HEAD.
Actions are pinned to immutable commits. No code from issue text, pull requests or
caller-supplied source references is executed on the GitHub runner. The issue's
source reference is input to the gateway protocol, not a checkout instruction.
The actor must match the issue creator, event sender and execution actor. Only
original opened events are accepted; manual workflow reruns cannot resend a request.

## AWS console verification

In the deployment's AWS account, open **IAM → Roles**, select the role named in
`ZOG_GATEWAY_ROLE_ARN`, then inspect **Trust relationships** and **Permissions**.
The GitHub repository is a condition in the role's trust policy, not a separate
AWS resource named after the repository. IAM is global, unlike the regional SQS queue.

The trust must allow `sts:AssumeRoleWithWebIdentity` through
`token.actions.githubusercontent.com`, constrain audience to `sts.amazonaws.com`,
and bind the actual repository OIDC subject to the intended default branch or
protected environment. Read the repository's actual OIDC subject configuration:
new repositories may use immutable owner/repository IDs. Do not copy a legacy
name-only subject or trust an organization-wide wildcard. Recreated repositories
have different identities even when the name is reused.

The role's permissions should allow `sqs:SendMessage` only to the intended primary
queue. The GitHub role needs no SSM, EC2, IAM mutation or queue-consumption access.
The gateway's EC2 instance role separately owns consumption and execution.

If IAM reads are denied, have the authorized account administrator inspect and
provide the exact trust policy and scoped permission evidence. Do not change trust
or enable submissions based only on an assumed role name. No long-lived access key
belongs in repository configuration.

## Submission and recovery

Publish the reviewed workflow on the actual default branch before opening a new
issue. Use the existing gateway issue template: only the v1 marker and fenced JSON
envelope, with no caller-supplied origin. For Phase A allow only build.status and
select the reviewed read-only lane and retained pipeline ID.

The first job validates; only a successful validation and the explicit enabled
switch can start the OIDC submission job. It obtains short-lived credentials,
sends once with the request ID as FIFO deduplication ID, and prints a bounded
receipt. SDK automatic submission retries are disabled. A lost result is uncertain:
inspect the gateway ledger using the original request ID instead of rerunning Actions
or creating a replacement request. Workflow success is not producer execution success.

The command-center retains durable admission, ownership, operation identities and
SSM results. Compilation is never hosted by this workflow. Generic automatic build
advancement remains a separate opt-in; a gateway service upgrade does not enable it.


## Selected shared-Host trust model — 2026-11-06

The GitHub Actions OIDC identity is **outside** the trusted administrative Host and must remain an intentionally minimal dispatch principal, **SQS submission only to the selected FIFO queue**. Its AWS trust policy must constrain the real OIDC issuer/audience/subject and authorized repository/workflow; its effective IAM must not include `ssm:SendCommand`, general `sts:AssumeRole` privilege escalation, `iam:PassRole`, S3 checkpoint writes or root-control owner credentials. The checked-in workflow's `id-token: write` only requests a GitHub OIDC token; it does not establish IAM scope. Work must inspect the *actual* selected AWS role trust and permissions, including resource scope, independently.

After SQS delivery, the normal graphical path is host-deploy gateway → authenticated protected owner → original approved claims/revocation/history → SSM. The administrator of that **same trusted Host** may administer SSM and all local credentials; we do not require an impossible admin-inaccessibility proof. Restricting a separately credentialed gateway service is optional defense in depth, not a replacement for protected claims or a proof against root. The contract is [graphical-task-c-shared-host-trust-v1.json](../../graphical-task-c-shared-host-trust-v1.json). No Actions OIDC permission expansion or SSM send was authorized by this document.
