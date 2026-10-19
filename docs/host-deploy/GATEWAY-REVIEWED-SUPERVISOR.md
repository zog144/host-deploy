# Reviewed generic image-build gateway supervision and progress (2026-10-19)

**Owner:** host-deploy Regular. **Producer pin for source compatibility:**
\`zog144/image-build@0fd3f00cafc7138d3bac9695c87a8ece65821868\`.
**Status:** source-only acceptance candidate. The initial generic build and
unattended AWS activation have **NOT** been authorized on a live compiler.

## Finite catalogue, not a shell interface

Only protocol task \`xcb-support-image-v1\` can select a generic build.
\`task_catalogue.validate\` now enforces exactly five reviewed, lexically
sorted XCB recipes:

| ID | Project | Recipe |
|---|---|---|
| \`xcb-util-final\` | \`xcb-util\` | \`xcb-util/stages/final\` |
| \`xcb-util-image-final\` | \`xcb-util-image\` | \`xcb-util-image/stages/final\` |
| \`xcb-util-keysyms-final\` | \`xcb-util-keysyms\` | \`xcb-util-keysyms/stages/final\` |
| \`xcb-util-wm-final\` | \`xcb-util-wm\` | \`xcb-util-wm/stages/final\` |
| \`xcb-util-xrm-final\` | \`xcb-util-xrm\` | \`xcb-util-xrm/stages/final\` |

Mode is exactly \`image\`; all five targets are required in that order.
Maintained worker aliases, arbitrary names/recipe paths, unexpected
targets, source branches, mutable generations or shell arguments are
rejected even if inserted in a locally edited task file.

A deliberately **invalid/nondeployable** operator template is provided at
\`examples/gateway-xcb-approved-task.template.json\`. It includes the
producer-source compatibility pin but requires review and replacement of
managed lane, lane owner, exact monthly pin SHA-256 and published immutable
base generation. Do not derive them from the GitHub request or invent defaults.
An owner must independently verify current box-control/root-control,
rootfs generation and source/pin against the actual adopted host.

The finalized schema-2 file must be root-owned, without symlinks or
group/world-writable ancestors, and the owner must separately review the
exact canonical SHA-256 reported by the \`task_catalogue.load\` function.
A task-policy identity is frozen into the durable dispatch binding at
preparation; the original gateway request cannot change it.

## Reviewed unattended mode: one supervised consumer

The installed \`host-deploy-gateway.service\` remains **admission-only**.
Automatic advancement is opt-in and belongs to this *same, single* consumer;
never enable a second consumer or a separate unreviewed executor.

After isolated host acceptance and separate owner authorization, the
reviewed alternative invocation is:

\`\`\`text
host-deploy-gateway --state-directory /var/lib/host-deploy-gateway run \
  --advance-reviewed-generic \
  --approved-task-catalogue /etc/host-deploy/approved-generic-tasks.json \
  --approved-task-catalogue-sha256 sha256:REPLACE_WITH_REVIEWED_HASH
\`\`\`

An illustrative **uninstallable until edited** single-service
systemd override is
\`examples/host-deploy-gateway-reviewed-generic.conf\`. The override
replaces the existing \`ExecStart\`; it must not add another running
SQS poller. Work must verify actual systemd service identity, unit
activation, socket/network confinement, root-only task permissions,
IAM/SSM authorization, workspace ownership and the selected production
source pair before applying it.

Unattended startup now *requires* both task file and independently
specified digest; a mismatch is rejected **before even allocating an
AWS client**. Every poll rereads the protected task file and requires
the same canonical digest and content as startup. A changed/revoked
catalogue raises a blocking failure before examining any request.
Service restart cannot accept a replacement file without a separately
changed reviewed digest in the operator-owned systemd policy.

In the enabled mode, the existing SQS consumer only admits authenticated
GitHub requests and advances **at most one** durable stage per poll.
It reconciles saved state before choosing the next task and requires a
managed, gateway-owned lane and its exact source, pin, generation and
runtime companion. Each new stage runs image-build producer runtime
preflight before any SSM mutation, checks the actual deployed source's
\`image-build-remote-capabilities-v1\`, snapshots the exact recipes and
then submits using the immutable recipe-snapshot identity.
Capabilites, snapshot, submit, and each inspect have different IDs.
\`submitting\` is fsynced before SSM SendCommand. A lost SSM response
becomes **uncertain, never automatically resubmitted**. Automatic
\`pipeline.retry\`, cancel and resume are not permitted.

The initial GitHub issue-triggered AWS submission remains separately
controlled by reviewed actor, immutable dispatcher revision, configured
OIDC role and \`ZOG_GATEWAY_SUBMIT_ENABLED\`; enabling supervised
consumer does not itself approve GitHub submission or new IAM grants.

## Durable read-only progress and result retrieval

A new CLI command exposes a bounded, safe projection:

\`\`\`text
host-deploy-gateway --state-directory /var/lib/host-deploy-gateway \
  generic-progress ORIGINAL_32HEX_GATEWAY_REQUEST_ID
\`\`\`

The response is \`host-deploy-generic-progress-v1\`, sourced **only** from
the persisted gateway ledger and \`generic-pipeline.json\`. It is
idempotent and does not invoke SSM, request new controller operations,
retry pipeline submits or mutate any state. Fields include:

- original GitHub request ID, task, source revision, managed lane,
  admission/dispatch/pipeline phases and catalogue SHA-256;
- separate operation IDs and saved SSM CommandIds for each retained
  stage; durable immutable recipe snapshot and pipeline identities;
- the latest **authenticated stored** image-build producer status,
  missing evidence count, outcome flags, a SHA-256 digest of the
  retained producer result and an artifact-name allowlist.

It never displays full SSM stdout, remote shell scripts, AWS credentials,
failure text, project filesystem paths or artifact *values*. An artifact
name or digest is not proof that a rootfs/artifact was published; consumers
must separately verify actual image-build output records. Progress is a
**retained observation** and may be stale until the next successful
supervised \`pipeline.inspect\`. The existing local-owner
\`generic-status\` remains a privileged full journal diagnostic and
must not be exposed directly to a GitHub issue reporter.

The read-only result can later be served by the authenticated
station-access/compiler RPC adapter or a separately approved GitHub
status reporter. **No new GitHub token, webhook, or public progress
endpoint is introduced here.**

## Work acceptance gates

1. Verify exact producer \`0fd3f00c...\` and this consumer's committed
   revision; independently review managed lane UID/GID and trusted
   ownership/source tree, monthly pin hash and retained immutable base
   generation. Build the exact root-owned reviewed catalogue and pin its
   digest in service policy.
2. Run no-credentials Python source tests:
   \`tests/test_gateway_task_catalogue.py\`,
   \`tests/test_gateway_generic_pipeline.py\`,
   \`tests/test_gateway_generic_consumer.py\`,
   \`tests/test_gateway_reviewed_supervisor.py\`,
   \`tests/test_gateway_generic_reporting.py\`. Check disabled default.
3. Verify a changed/revoked task file, wrong pinned hash, unknown task,
   maintained worker selector, wrong lane owner, changed source/pin or
   external-observation-only lane cannot advance to SSM.
4. On an isolated adopted compiler only after separate GO, perform
   capabilities → runtime preflight → five-recipe snapshot → selected
   pipeline.submit → repeated pipeline.inspect, saving request, SSM
   CommandIds, snapshot, pipeline ID and producer receipts through
   process restart. Test a lost reply and reboot without duplicate SSM.
5. Test source-only progress before preparation, while SSM pending,
   after completed/failed/uncertain operations and across process
   restart. Verify raw artifact values and secrets never appear in the
   projected result and no AWS call occurs on read.
6. Approve the GitHub issue/OIDC/SQS trigger and any report-back identity
   **separately**. Do not change the gateway default service, OIDC role,
   SSM permissions or production compiler workspace until accepted.

**Live execution disposition: NO-GO** until these checks produce
authoritative Work evidence. Source implementation is not a claim of
completed EC2, SSM, box-control or image-build acceptance.

## Global bounded unattended cadence

In addition to one stage per SQS poll, the reviewed consumer now persists
`reviewed-generic-advance.json` **before** each supervisor preparation or
pipeline step. Its global minimum interval is **15 seconds** across
restart and repeated queue messages. A malformed marker, symlink,
unexpected backwards clock change or replaced catalogue blocks advancement.
This is not an external timer or background build engine; it is a bounded
operation of the single reviewed SQS consumer under its existing exclusive
`dispatcher_lock`. A crash after reservation cannot authorize duplicate
SSM submission because the per-request `submitting` journal independently
fences uncertain replies. The marker is a safety cadence, not an indication
that the remote build actually ran or completed.
