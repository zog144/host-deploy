# Current schema-5 Fonts deployment: Project/controller admission (Nov 25)

**Source candidate only. No native submission is authorized by this document.**

## Binding

The current first Fonts installation is the explicitly selected schema-5
`gateway-first-fonts-runtime` existing Project:

- Project: `/home/certbot-build-owner/certbot-seed`
- Controller: `/home/certbot-build-owner/certbot-seed/controller-gateway-first-fonts-runtime-inherited-v1.json`
- Source and package pins: **current Project checkout**, resolved when the
  protected, new operation executes. Historical source metadata on the lane
  is not a fixed current build pin.
- Authority: actual active lane specification, its selected lane-specific
  controller bytes, owned Workspace/Host, admitted fixed Fonts task, protected
  root-control Task C sender and durable operation ledger.

The Nov14 schema-4 prepared migration, archived schema-4 evidence, separate
initialized destination, old initialization manifest, migration receipts,
and original SSM CommandIds are **historical evidence, not current schema-5
verification or admission prerequisites**. The historical code is preserved
but not used for new current-Project admissions. Original command/pipeline
records remain uncertain or terminal exactly as retained: **no replay**.

## Source correction in PR #61

The old `gateway.project_current.verify_approved_lane` demanded an obsolete
mixed-state recovery receipt for the existing Project and then denied all
new builds. It now requires **active schema 5**, `managed`,
`project_selection=existing`, the exact selected `certbot-seed` root,
matching lane-specific controller and source/package/state paths, and
consistent Workspace/Host identity, including the exact approved compiler
instance. It does not require any schema-4 file.

`host-deploy fonts-lane-verify` (`fonts_lane_profile.verify`) now has a
separate **current schema-5** verification branch. It reads the same
current active lane and expected controller SHA-256 without asking for
historical migration/archive/receipt evidence. Its nonauthorizing report
explicitly states `installed_controller_verified=false` and
`native_readback_required=true`. The actual controller is verified in the
protected compiler command, not claimed from a Gateway-local file. A truly
historical migrated destination remains inspectable through its distinct
legacy verification branch and is never treated as the current selection.

The Gateway freezes the SHA-256 of the **exact expected controller bytes**
generated from the active schema-5 specification into every **new** protected
Project-current dispatch binding. Those bindings use the same immutable
request ID, target, task, and durable ledger / root-control send-once
contract already reviewed in PR #57; no new AWS principal, document,
generic SSM relay, user account, or alternative target is introduced.

The **same authorized SSM operation**, *before* creating
`gateway-requests/<operation_id>/request.json` or invoking
image-build, opens the selected Project from `/` using O_NOFOLLOW
directory descriptors and checks that each ancestor is a safe real
directory. It checks the existing controller's fixed basename, type,
one-link/private custody, inode/readback stability, and the exact
frozen SHA-256. The selected source and `.git` directories are
also opened via no-follow descriptors, with a minimal Git environment
(not inherited `GIT_DIR`, `GIT_WORK_TREE` or other `GIT_*`).
A missing, modified or redirected controller or selected checkout
**fails before producer mutation**.

Historical already-frozen Project-current dispatch bindings **without**
the new checksum continue using their original script source/argv.
They remain available for read-only observation of the same retained
request and pipeline; neither schema-4 installation migration nor a
new original SSM send is performed. New original commands must have
new request identities: the once-only journal forbids replay of old ones.

The new controller verification is composed from reviewed source into the
same fixed SSM script. Comment-only and blank lines (not multiline string
contents) are removed **only for new current-schema-5 scripts** to keep the
entire submitted shell command inside root-control's existing **32 KiB**
limit. The original fixed script remains byte-for-byte unchanged for frozen
historical dispatches. Tests cover both the size bound and the real root
journal's one-submit/no-replay behavior; there is no increased command
allowance or extra execution/sender path.

### Security boundary

This is **execution-time verification within the protected send-once
original SSM command**. Gateway-local admission validates owned lane
selection but does not pretend that registry filesystem reads are a
fresh compiler-side installed-controller attestation. The actual
controller is checked on the selected compiler Host immediately before
that operation's producer begins. The root-control compiler child remains
subject to inherited kernel SO_PEERCRED identity, isolation, and its
durable job and cgroup limits. No project-owned code runs before the
controller preflight.

A successful protected SSM submission is not a successful compilation.
The response still must validate the original request ID, source/attempt
evidence and terminal pipeline outcome. The 14,400-s producer deadline,
14,700-s control window, same-pipeline inspection and no-replay
recovery remain unchanged.

## Native Work acceptance plan — separate authorization

1. Read and attest exact accepted host-deploy/root-control/source code,
   root-owner LocalTaskCJournal installation, protected Gateway units,
   IAM role, and the selected actual schema-5 lane record.
2. Check that `certbot-seed` actually exists with its expected private
   Project root, current image-build source/module, package pins and
   controller bytes. A source-only test does not establish this. Any
   mismatch is HOLD, without rewriting the old Project or controller.
3. Run authorized **read-only readiness** against the exact current
   Project and original Gateway/compiler Host boundary. Do not use the
   Nov14 initializer `--verify`, source restore, migration receipt or
   old pipeline to establish current readiness.
4. Independently approve a **NEW** build.submit request ID and its
   finite Fonts task/target. Only then allow the ordinary GitHub
   webhook/SQS → Gateway durable dispatch → protected root-control
   journal → selected compiler path to execute the one new request.
   Preserve request `0f06e78980aeee4f0948a48198dc8276`
   and its previous uncertain pipeline intact.
5. Read back the same new CommandId, root-control child identity,
   immutable Project pipeline/attempt records and final generation
   outcome. Recovery may inspect the SAME operation, never submit it
   again automatically.

**No native Host changes, SSM commands, deployments, controller writes,
source updates or Fonts submissions were made by the Regular source work.**
