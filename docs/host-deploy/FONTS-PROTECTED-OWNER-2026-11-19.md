# Fixed Fonts forwarding to protected root-control Task C owner

**Scope:** Source-only successor to host-deploy PR #48, coordinated with the
installed root-control Task C trusted-host owner. This change does **not**
authorize a new build, enable the Gateway, or create another GitHub issue.

**Selected installation candidate:** host-install [PR #46](https://github.com/zog144/host-install/pull/46)
stages the one root-backed `zog-task-c-gateway.service`, with its `ExecStart`
using `/opt/zog/task-c/venv/bin/host-deploy-gateway`. Its five-source ordinary
installation puts host-deploy PR #51, root-control PR #53, box-control PR #21,
image-build PR #24 and host-install together in that **same Python venv**.
The root-control owner is **not** imported from a separate Gateway interpreter;
no unconditional root-control dependency is added to host-deploy's general
package metadata. The installer separately verifies the selected root-control
journal Git blob and precreates `/var/lib/zog-task-c/operations` as root:root
0700. This is a proposed source selection, not completed Host installation.

## Retained request and exact handoff

The retained already-authorized request is
`f7c27b65c8bdfad9a740bc90335348cf`. On the actual Host it was
reported **prepared** (no SSM CommandId). The old CLI command
`host-deploy-gateway dispatch-submit` had called the legacy
`image_build_execution.submit_prepared` route, which correctly blocked
legacy graphical SSM submission. The fixed Project-current Fonts route was
not connected to the protected owner.

For **schema-4 Project-current** Fonts only,
`image_build_execution.submit_prepared` now calls
`simple_forward.advance` on the **same retained** request. The original
protected-graphical legacy denial continues to apply to other schemas.
The SQS consumer's explicit `--forward-supported` path uses the same
`simple_forward.advance` and does not invoke SSM directly.

`fonts_owner_sender.ready` inspects the root-control Task C journal before
the gateway commits a send intent. Opening the real journal may create its
root-owned `.lock` file, so this is **SSM-nonmutating**, not strictly filesystem
read-only. A missing root-owned owner, previous
claim, cancelled operation or unsafe journal **leaves the dispatch prepared**.
Once ready, the gateway durably fsyncs its original request's send intent.
`fonts_owner_sender.submit_once` then reopens the original authorization,
original request SHA-256, existing Project/controller, fixed Fonts task,
fixed SSM Host/document/300s deadline and exact generated script.
It delegates **one** request to
`zog.root_control.task_c_trusted_host.LocalTaskCJournal.submit_once`.
Root-control's existing root-owned `0700` journal provides a second
local irreversible operation fence before calling its fixed sender,
recording the same request ID and resulting SSM CommandId. This is not a
new request, signed approval or alternate shell/document/instance interface.

The current accepted schema-4 lane continues using its selected Project's
current image-build checkout and package pins. No source revision,
historical monthly-pin or origin-lane check is reintroduced.

If SSM acknowledgement is lost after the owner's intent is recorded,
the dispatch becomes **submission_uncertain**. Neither the gateway nor the
protected owner resends. A root administrator must inspect both retained
journals and any known CommandId before reconciling. Reposting the issue or
fabricating another request ID is not recovery.

## Work connection — read-only readiness first

The Gateway was left stopped and no Fonts build was submitted by these
source changes. Before a native `dispatch-submit`:

1. Review and stage host-install PR #46's *exact five-source* candidate and
   confirm the actual `/opt/zog/task-c/venv/bin/python` imports both the
   selected host-deploy Gateway and root-control Task C journal. Verify
   the installed distributions, dependency closure, Git-source pins and
   actual installed `RECORD` bytes. Then verify the selected existing
   `certbot-seed` Project and controller,
   and confirm the actual image-build module resolves under that Project's
   `source/src/zog/image_build/remote_operations.py`. Confirm the installed
   image-build successor supports current-Project implicit inputs.
2. Confirm that the **protected root-control owner** is installed at the
   reviewed root-control PR #53 source, and that
   `zog.root_control.task_c_trusted_host.LocalTaskCJournal` resolves from
   the **same Task C venv** as the installed host-deploy CLI. Its existing
   `/var/lib/zog-task-c/operations` must be prepared as root-owned
   `0700` with the owner journal's exact local file conventions; do not
   synthesize an approval file, owner journal or replacement request.
3. With an authenticated **root-owned owner execution context** using the
   selected Task C venv CLI, perform nonmutating `dispatch-status` and
   `request` inspection for
   `f7c27b65c8bdfad9a740bc90335348cf`. It must be the already
   admitted `build.submit`, fixed `graphics-fonts-image-v1` task and
   `gateway-first-fonts-runtime` lane, with a prepared schema-4
   dispatch, no prior Gateway attempt/CommandId and no root-control
   operation intent or cancellation. Also confirm the current owned Host
   maps to the intended compiler and fixed `AWS-RunShellScript` document.
4. **Only when a live build is separately authorized**, the supported
   root-owner CLI path is:
   ```sh
   /opt/zog/task-c/venv/bin/host-deploy-gateway \
     --state-directory /var/lib/host-deploy-gateway \
     dispatch-submit f7c27b65c8bdfad9a740bc90335348cf
   ```
   This is **mutating**: it calls the one authorized root-control sender
   and may immediately submit a real Fonts build. It must not be used
   for import or readiness testing. Reinspect the same request and
   root-control journal afterward, then observe the retained CommandId.
   Do not call the old SSM route or create a new GitHub issue.

The **generic host-deploy** `host-deploy-gateway.service` still uses
`DynamicUser=yes` and is **not** the unit selected for Task C. Do not grant
that unprivileged service access to this root-owned journal. The proposed
host-install PR #46 unit is instead `zog-task-c-gateway.service`, a **root-backed
static service**, with `ExecStart` pointing to the Task C venv and no
`[Install]` section. It remains **inactive** after staging; no service is
started or enabled by the installer. Before any separately authorized live
submission, Work must verify that the actual installed unit uses that exact
reviewed service identity, has only the protected state/journal write paths,
and imports the installed owner. For the retained prepared request, a root
administrator may explicitly execute the same venv CLI while the service
remains stopped. Do not run a second independent sender or enable a direct-SSM
fallback. No command in this document authorizes a live SSM operation.

## Source acceptance

- Focused fixed-forward and gateway tests use fake SSM and a stateful
  root-control journal interface, including owner-unavailable holding the
  original request, exact digest/target/script checks, CommandId readback,
  legacy graphical denial and lost-acknowledgement no-resend.
- Independent root-runner test imports the exact root-control Task C journal
  and verifies its actual `submit_once` operation, protected file
  persistence, and rejection of a repeated original operation with fake SSM.
- No live AWS, systemd, Queue, SSM or Fonts operation occurs in CI.
