# Generic image-build pipeline dispatch — source integration (2026-10-19)

**Producer selected for source compatibility:** \`zog144/image-build\`
at \`0fd3f00cafc7138d3bac9695c87a8ece65821868\`. **Consumer**
implementation: host-deploy \`unstable\` following the source commit that adds
\`generic_pipeline.py\`. This is a source contract, not proof that the
command-center currently deploys the selected image-build commit.

**Status:** source-only; SQS acceptance and existing status/resume/cancel remain
intact. Mutating generic builds have **not** been authorized or run on EC2.
The public issue workflow is configuration-gated; see GATEWAY-GITHUB.md.

## Finite protocol and server-side task

Only \`build.submit\` with task name \`xcb-support-image-v1\` is recognized as
a generic build. The older \`stages\`, \`glibc-final\`, \`final-compiler\` and
other maintained worker names do **not** select a generic pipeline.

The root-owned (or otherwise protected) task catalogue is **schema 2**.
Its one task binds: image-build repository and *immutable deployed source commit*,
managed lane and immutable lane owner, monthly pin repository-relative path and
content SHA-256, pin date, five sorted \`{id, project, recipe}\` entries, exact
base generation identity, generic \`mode=image\`, and its five targets.

The supported initial recipe entries are, in lexical order:

| ID | Project | Recipe beneath \`project/package/\` |
|---|---|---|
| \`xcb-util-final\` | \`xcb-util\` | \`xcb-util/stages/final\` |
| \`xcb-util-image-final\` | \`xcb-util-image\` | \`xcb-util-image/stages/final\` |
| \`xcb-util-keysyms-final\` | \`xcb-util-keysyms\` | \`xcb-util-keysyms/stages/final\` |
| \`xcb-util-wm-final\` | \`xcb-util-wm\` | \`xcb-util-wm/stages/final\` |
| \`xcb-util-xrm-final\` | \`xcb-util-xrm\` | \`xcb-util-xrm/stages/final\` |

The 2026-10-01 monthly pin was used by the producer's readiness regression.
**Do not invent a usable base generation or deployed lane ownership**:
Work must bind real canonical values from the adopted compiler host, source
checkout, immutable generation and reviewed lane specification. No arbitrary
GitHub issue parameters may set these.

A request's immutable \`source\` must equal the active lane source, and the
catalogue must independently equal that same source, lane, owner and monthly
pin. An external-observed-state-only lane cannot prepare mutating operations.

## Existing AWS pipeline, not a second build engine

The GitHub issue parser still accepts only authenticated, approved-actor requests
and SQS FIFO. The SQS consumer durably accepts/acknowledges requests and reconciles
admission. **By default** it does **not** start a build. An explicitly
operator-enabled mode `run --advance-reviewed-generic
--approved-task-catalogue /etc/host-deploy/approved-generic-tasks.json`
requires a root-owned, non-group-writable catalogue and performs at most
one supervised stage per poll across admitted, managed-lane requests.
This mode must NOT be enabled until the owner accepts the live runtime and
catalogue. For a reviewed admitted request the manual equivalent is:

\`\`\`text
host-deploy-gateway dispatch-prepare REQUEST_ID --task-catalogue /REVIEWED/task-catalogue.json
host-deploy-gateway generic-status REQUEST_ID
host-deploy-gateway generic-advance REQUEST_ID
\`\`\`

Each \`generic-advance\` invocation performs **one** retained step transition.
A supervised operator may invoke successive steps after examining status. The
existing \`dispatch-submit\` is **explicitly barred** for generic capability-first
requests, so a single SSM command cannot skip a snapshot.

The source plan is:

\`\`\`text
admitted -> frozen catalogue/lane/source/pin
 -> capabilities.inspect  (exact deployed producer, no arguments)
 -> recipes.snapshot      (separate durable operation ID)
 -> pipeline.submit       (separate ID, snapshot predecessor)
 -> pipeline.inspect      (fresh observer operation ID)
 -> completed | failed | pending next inspected observation
\`\`\`

The coordinator stores \`generic-pipeline.json\` under the existing per-request
ledger lock. It persists each exact request/operation ID and its canonical SHA-256
before running the SSM command. Its per-stage journal phases are
\`prepared -> submitting -> submitted -> completed\`.
A process restart after entering \`submitting\`, or a lost SSM reply without an
authoritatively saved \`CommandId\`, transitions to \`uncertain\` and **does not
blindly issue another command**. SSM observation uses the saved CommandId only.
Each request freezes the snapshot identity before pipeline submit and retains
the resulting pipeline ID before inspection. Submission and snapshot IDs are
distinct from each other and from the caller gateway request identity.

Every transition revalidates managed lane/source/runtime/pin/host target.
Producer-owned runtime preflight runs before *every* new SSM submission.
The SSM wrapper rechecks exact clean source Git HEAD and monthly pin bytes on
the producer host, then returns a receipt bound to the full remote request
and result. The bounded capability and snapshot artifacts are preserved in
the receipt. A successful SSM exit alone never establishes snapshot or pipeline
identity.

## Capability gate

The \`capabilities.inspect\` receipt must return
\`image-build-remote-capabilities-v1\`, source-bound to the frozen exact
repository and Git revision, with generic pipeline support, snapshot contract
\`image-build-recipe-snapshot-v1\`, \`recipes.snapshot\` required for submit,
the selected generic mode, \`pipeline.submit\`, advertised recovery operations,
and \`automatic_retry=false\`. Maintained worker execute equivalence must
remain explicitly false. The producer's own \`recipes.snapshot\` owns actual
recipe-content/materialization validation.

## Operational controls still pending owner acceptance

- Automatic dispatch remains **off by default**. The optional bounded
  `run --advance-reviewed-generic` path is implemented but not activated in
  the installed service. Its catalogue must be root-owned with secure ancestors.
  Actual service activation still requires a reviewed UID, IAM/SSM boundary,
  protected task file, rate bound and owner GO. Manual `generic-advance`
  is also available under the exclusive gateway dispatcher lock.
- Issue-triggered AWS OIDC/SQS submission requires the explicit repository
  deployment switch and reviewed OIDC/queue configuration in GATEWAY-GITHUB.md.
  Phase A enables only build.status; generic build authorization remains separate.
- Automatic retry, cancel, resume and manual \`pipeline.retry\` are distinct
  operations and **not** implemented as generic-submit continuation. Existing
  read-only/status and authorized \`build.cancel\`/\`build.resume\` remain
  separate requested operations. Do not treat a failed generic submit as an
  invitation to repeat it.
- Bounded progress is available through \`generic-status\` (original request
  ID, stage, command ID, snapshot and pipeline identity, producer summary).
  Posting back to GitHub Issues needs a separately approved reporter identity.

## Isolated Work acceptance

1. Pin exact deployed image-build Git commit and five real recipe directories;
   confirm 2026-10 monthly pin, immutable base generation, box-control and
   root-control runtime, managed lane ownership and current workload epoch.
2. Execute offline protocol/catalogue and staged ledger regression tests, including
   loss immediately after the SSM \`submitting\` marker, restart, wrong
   capabilities, wrong source, wrong snapshot and unknown pipeline identities.
3. On an isolated adopted compiler host, perform source-bound capabilities,
   producer preflight, five-recipe snapshot, generic \`mode=image\` submit,
   and bounded inspect, preserving actual image-build controller job/artifact
   evidence. First mutate only under separate live-acceptance authorization.
4. Demonstrate SSM lost reply/uncertain reconciliation **without** second
   submission, and distinguish protected runtime/state/permission faults.
5. Test the reviewed GitHub trigger, request reporting, and explicit owner-managed
   timer only when allowed. No main/production trigger, AWS permission expansion,
   source generation substitution, or existing workspace re-adoption without GO.

**No live AWS command, build, root-control mutation, GitHub OIDC dispatch, or
public workflow activation occurred in this Regular source pass.**
