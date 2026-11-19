# Fixed Fonts forwarding to protected root-control Task C owner

**Scope:** Source-only successor to host-deploy PR #48, coordinated with the
installed root-control Task C trusted-host owner. This change does **not**
authorize a new build, enable the Gateway, or create another GitHub issue.

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

`fonts_owner_sender.ready` reads the root-control Task C journal before
the gateway commits a send intent. A missing root-owned owner, previous
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

1. Review and install the exact host-deploy candidate on top of PR #48,
   verify the selected existing `certbot-seed` Project and controller,
   and confirm the actual image-build module resolves under that Project's
   `source/src/zog/image_build/remote_operations.py`. Confirm the installed
   image-build successor supports current-Project implicit inputs.
2. Confirm that the **protected root-control owner** is installed at the
   reviewed source and that
   `zog.root_control.task_c_trusted_host.LocalTaskCJournal` resolves to
   that runtime. Its existing
   `/var/lib/zog-task-c/operations` must be prepared as root-owned
   `0700` with the owner journal's exact local file conventions; do not
   synthesize an approval file, owner journal or replacement request.
3. With an authenticated **root-owned owner execution context**, perform
   read-only `dispatch-status` and `request` inspection for
   `f7c27b65c8bdfad9a740bc90335348cf`. It must be the already
   admitted `build.submit`, fixed `graphics-fonts-image-v1` task and
   `gateway-first-fonts-runtime` lane, with a prepared schema-4
   dispatch, no prior Gateway attempt/CommandId and no root-control
   operation intent or cancellation. Also confirm the current owned Host
   maps to the intended compiler and fixed `AWS-RunShellScript` document.
4. **Only when a live build is separately authorized**, the supported
   root-owner CLI path is:
   ```sh
   host-deploy-gateway --state-directory /var/lib/host-deploy-gateway \
     dispatch-submit f7c27b65c8bdfad9a740bc90335348cf
   ```
   This is **mutating**: it calls the one authorized root-control sender
   and may immediately submit a real Fonts build. It must not be used
   for import or readiness testing. Reinspect the same request and
   root-control journal afterward, then observe the retained CommandId.
   Do not call the old SSM route or create a new GitHub issue.

The installed Gateway systemd unit uses `DynamicUser=yes`; that
unprivileged service **must not** be granted direct access to the root-owned
journal. Its automatic queue-forwarding mode will fail closed until a
separately installed and authenticated protected-owner invocation path
is approved. For the retained, already prepared request, Work may invoke
the reviewed root-owner CLI explicitly while the queue service remains
stopped. Do not silently change the Gateway's service identity or permissions.

## Source acceptance

- Focused fixed-forward and gateway tests use fake SSM and a stateful
  root-control journal interface, including owner-unavailable holding the
  original request, exact digest/target/script checks, CommandId readback,
  legacy graphical denial and lost-acknowledgement no-resend.
- Independent root-runner test imports the exact root-control Task C journal
  and verifies its actual `submit_once` operation, protected file
  persistence, and rejection of a repeated original operation with fake SSM.
- No live AWS, systemd, Queue, SSM or Fonts operation occurs in CI.
