# Nonroot typed compiler execution binding — Regular implementation

Date: 2026-10-21  
Target: draft host-deploy PR #2, `regular/toolchain-gateway-20261019`  
Source request: [image-build Work nonroot binding handoff](https://github.com/zog144/know-file/blob/423be610f6ed5da41baa1ba1b5bd7350d72a309b/image-build/handoffs/nonroot-compiler-execution-binding-2026-10-21.md)

**Status: source acceptance PASS; native isolated controller/SSM execution NO-GO.**
No IAM, production SSM, compiler job, controller service, root-control socket,
host bootstrap or historical compiler lane was modified.

## Versioned durable execution identity

`host-deploy-compiler-execution-v1` is a one-time **protected lane-owned**
binding with exactly these fields:

- `schema`: `host-deploy-compiler-execution-v1`;
- `controller_uid`, `controller_gid`: positive numeric, nonroot kernel owner;
- `controller_home`: exact canonical home of that passwd entry;
- `project_root`: canonical controller Project strictly beneath that home;
- `build_uid`, `build_gid`: separate numeric build worker identities;
- `socket_path`: reviewed `/run/zog/root-control.sock`;
- `source_revision`: the exact reviewed image-build producer;
- `build_record_revision`, `box_control_revision`: the exact companions;
- `python_executable`: exact pinned interpreter path;
- `task_catalogue_identity`: exact digest of the protected root-owned task.

All numeric identities are **deployment-provided**. There is no embedded
host UID/GID, controller username, global root-only fallback, station-access
UID-970 state, guessed home, or caller-supplied shell command.

The existing schema-4 lane retains its prepared history. **Only** a new,
active managed lane bound to restored image-build
`31e6121cdf9fd05336286529666e2c35cdbe0831` may accept
`bind_compiler_execution_identity(...)`. This operation requires the
retained lane specification digest and both exact reviewed companion
bindings, is idempotent for the same identity, and rejects rebinding or
a historical/source-incompatible lane. No existing lane is upgraded in
place.

`image_build_dispatch.binding_for_request` requires this binding for
each *new* typed `toolchain.submit`, then saves it in the immutable gateway
dispatch **before** any remote operation. The normal typed journal hashes
the entire frozen dispatch. The same original identity survives
`toolchain.specification.inspect`, each `toolchain.submit`,
`toolchain.inspect`, and `toolchain.resume` phase. At each dispatch,
`verify_current_target` compares current protected lane owner identity
and all companions with those frozen values. Identity drift blocks
submission/recovery instead of allocating a new operation.

The earlier producer `857bb454e64102afa51a93ce0b9f8cce5924b67c`
and its historical frozen dispatches remain readable, but cannot select
new compiler work. Old generic and status operations retain their
historical semantics.

## Fixed root-to-nonroot transport transition

Root SSM remains the gateway **transport**, not the producer identity.
The root-controlled wrapper still verifies exact Git checkout, clean
source and reviewed monthly pin, writes the original protected 0700/0600
gateway request and result journal, and retains the SSM CommandId.

Before a **producer** process launches, a fixed embedded server-owned
launcher checks the local passwd home/primary GID, nonzero and disjoint
build owner, canonical Project inside that home, root-owned and
non-writable source/companion directories, executable path, and the exact
root-owned socket/group access. It rejects a symlink, wrong UID/GID,
group-writable source, world-writable socket or missing grant.

`subprocess.run` applies actual kernel
`user=<controller_uid>`, `group=<controller_gid>`,
`extra_groups=()`, `cwd=<passwd-home>`, and a fresh bounded
environment containing only trusted HOME/USER/LOGNAME, fixed PATH,
PYTHONDONTWRITEBYTECODE, LANG and exact pinned module PYTHONPATH. Inherited
AWS credentials, LD_PRELOAD, inherited HOME and supplementary groups
cannot enter the producer. No general sudo/shell/runuser callback is
accepted from GitHub.

### Host-owned durable request registry

A source security review tightened the new typed binding: its immutable
request/result path is now fixed beneath
`/var/lib/host-deploy/typed-toolchain-requests/<workspace_id>/<operation_id>/`,
**not** beneath the controller-owned Project. The root wrapper creates any
missing registry directories as root with 0700 permissions, checks each
parent for no symlinks, root ownership and no group/other write, and
atomically fsyncs each request and result. Only the exact sealed request
bytes are inherited by the controller process; no root registry directory
descriptor or writable path crosses the UID boundary.

Historical prepared requests without the new identity retain their
original `<Project>/gateway-requests/<operation_id>` paths. The new
registry selection is frozen in the dispatch and preserved by each
typed phase (specification, submit, inspect, resume).

For producer runtime preflight, the root transport checks the checkout
first; then it runs the real image-build
`zog.image_build.runtime_preflight` under those nonroot credentials and
still validates the producer's exact returned readiness contract.

For submit, inspect and resume, the root wrapper preserves the original
on-disk request/result as root-owned and supplies the nonroot producer
only its exact JSON request bytes through an inherited, write-sealed
Linux `memfd` (`F_SEAL_WRITE/GROW/SHRINK/SEAL`). The nonroot producer
reads its supported existing CLI request-file argument via
`/proc/self/fd/<n>`, without getting directory write access to the
root-owned gateway registry or secrets. The wrapper checks the original
request hash and retained result identities and archives bounded
authenticated SSM receipts.

Workers remain controller-owned operations mediated by
box-control/root-control; the launcher does **not** execute a build worker
directly as root or substitute for root-control's build-identity grant.

## Pinned source and compatibility tuple

- host-deploy source: use **the exact head of draft PR #2** published with
  this document;
- image-build:
  `31e6121cdf9fd05336286529666e2c35cdbe0831`;
- monthly pin: `project/pins/2026-10-01/commit-pin.py`,
  `sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`;
- box-control: `644170fc441863307092f329bf7e23cb64eb33e2`;
- build-record: `a866c9c4b0dd385045f00ce2de7d809f5b67c104`;
- corrected root-control executable: `e4f25110c854c000bdde5ec564c8119370da9a52`;
- root-control documentation-only review head:
  `8a9583924109ef324eb80071953151c8c7e20b33`
  (not a substitute for the pinned executable commit);
- toolchain specification:
  `sha256:ba8986219065627c939adf49ee0bf200bfc94f85b0bbe280aecdaff8349ffc1c`;
- retained seed generation:
  `98455384bdabb42ac6ea0c0b08a55d2673a2cd507c46fd75e971605b8660e9f8`
  (reviewed by Work; not automatically selected by this source change).

The seed and specification identities must be bound in the **actual**
root-owned protected task after independent Work review; none is inferred
from the public GitHub issue or generated by this integration.

## Source and limited native CI

- Source-only CI checks exact upstream source/pin, public packaging,
  protected task, control binding, identity drift and historical
  dispatch compatibility.
- `tests/test_gateway_compiler_nonroot.py` covers nonzero and distinct
  numeric identities, correct canonical home/Project/socket, exact source
  revisions and protected task digest; the trusted launcher is not
  replaceable by arbitrary GitHub arguments.
- `tests/test_gateway_dispatch.py` additionally verifies one-time
  binding, duplicate idempotency, mismatch rejection, frozen same-operation
  identities across specification/submit/inspect/resume, and a fail-closed
  changed lane record.
- The **separate** credential-free
  `native-compiler-identity.yml` workflow executes one actual Linux
  root-to-nonroot subprocess using two ephemeral CI accounts and a
  disposable local Unix socket. It verifies getuid/getgid/getgroups,
  unspoofed passwd HOME, no inherited root variable, root-only source
  integrity, socket DAC and sealed `memfd` request read-through.
  It does not connect a real root-control daemon. This isolated job
  does not weaken the general source-only workflow's no-sudo guard.

CI completion and exact counts are recorded in PR #2. No genuine retained
compiler job has run under this new binding.

## Box-control/root-control Regular — required contract review

Please confirm, against the exact reviewed companion revisions:

1. This is a valid controller Project home and actual kernel peer UID
   for root-control's Project-specific socket grant; determine whether
   the socket's root-owned primary group/0660 interface is supported
   for the authorized controller without supplementary groups.
2. The selected box-control controller's state is truly inside the
   passwd home, not `HOME`-spoofed, and the separate build UID/GID grant
   is authorized by root-control and cannot write source, registry or task.
3. Source checkouts in `<project>/source` and
   `<project>/companions/{build-record,box-control}` can be root-owned
   readable directories beneath an owner-controlled Project; review
   parent replacement, symlink and Project registration semantics.
4. Restarts/uncertain outcomes, selected invocation evidence and
   long-running build worker startup remain matched to the original
   controller Project and durable operation identities.
5. Confirm exact compatible root-control revision and
   host-install-provisioned identities/socket ownership. Do not add a
   privileged general-purpose command API as a workaround.

This review is an **owner dependency**, not implied approval from local CI.

## Host-deploy Work — native isolated deployment procedure

1. Read the published Work seed-recovery observation, account/instance
   ownership epoch, legacy lane records, active SSM CommandIds and pending
   uncertainty **before** touching the host. Do not clear markers,
   adopt a different controller or retarget any existing lane.
2. Provision a **new** independent, approved nonroot controller account
   (numeric UID/GID, actual passwd home, canonical Project), and a
   separate build UID/GID. Confirm root-control grants and local
   identity/permission policy with both controller owners.
3. Stage root-owned, immutable clean checkouts for the exact
   image-build, build-record and box-control commits, the approved
   Python interpreter and immutable October pin. Verify source
   readability as controller and non-writability as the build UID.
4. Deploy reviewed root-control socket/Project grant; inspect its
   ownership, group, mode, kernel SO_PEERCRED behavior and real
   accepted/rejected controller invocations. Reject root caller,
   wrong UID, wrong Project, build UID, supplementary groups and
   spoofed HOME. Do not use the old root-only socket.
5. Independently reopen the retained seed in the lane-local
   immutable generation store, without reacquiring/replacing it.
   Bind the exact source/spec/seed to a **new** protected task.
   Freeze `compiler_execution_identity` on the **new** schema-4 lane.
6. Run **read-only** image-build preflight and a finite
   `toolchain.specification.inspect` through actual root SSM ->
   nonroot controller, checking boot/InvocationID, original request ID,
   socket peer, Project owner, environment and no mutation. Perform
   interruption/reboot and mismatched/replayed identity rejection.
7. Preserve all durable SSM/controller/job receipts. Obtain a **separate,
   specific first-compiler submission approval** before opening the
   GitHub SQS operation allowlist, sending `toolchain.submit`, or
   performing any compiler bootstrap. Never enable unattended long
   jobs or production promotion based only on this source proof.

**Gate:** isolated native owner/peer acceptance is still **NO-GO** until
box-control/root-control Regular review plus host-deploy Work evidence.

## Corrected root-control and recursive protected source — October 21 follow-up

Root-control's [review of the original launcher](https://github.com/zog144/root-control/issues/8#issuecomment-6322028776)
identified the previously proposed `62dca363...` socket implementation
as incompatible with the new root-owned primary-group socket contract.
Root-control corrected its group listener to **root:controller-primary-GID
0660**, checked the exact passwd primary GID before changing socket
ownership, and kept strict Linux `SO_PEERCRED` admission limited to the
configured **nonroot controller UID**. Its executable source is pinned to
`e4f25110c854c000bdde5ec564c8119370da9a52`; the subsequent
`8a9583924109ef324eb80071953151c8c7e20b33` only records the
source review and native checklist.

Host-deploy now publishes `host-deploy-compiler-execution-v2`. The new
version explicitly binds `root_control_revision` to that exact corrected
executable commit. An attempted different root-control pin, including
the former incompatible source or documentation head, is rejected before
new submission. The earlier `host-deploy-compiler-execution-v1` can
still be validated **only for frozen historical reads**; the fixed
producer launcher refuses to run new work with v1. There is no
in-place migration or request ID reassignment.

The kernel identity check now verifies both **UID and primary GID** of
the actual passwd home, the Project and every intervening Project
directory. None may be a symlink or group/other writable. Every
descendant in the root-owned image-build, build-record and box-control
checkout trees is scanned with `lstat`: only immutable root-owned
regular files or directories are admitted, all must be non-writable to
group/others, readable by the nonroot controller, with directory
traversal permitted. Symlinks anywhere under these trees, special
nodes, writable subdirectories, files owned by the controller, missing
readability or overly large traversal fail closed. The companion
parent directories are separately protected, and the root-controlled
request/result registry remains outside the controller's Project.

Isolated source tests assert wrong source revision and historical
version rejection, and real Linux CI with temporary accounts exercises
mismatched home and Project GIDs, writable or UID-substituted nested
source files, symlink substitution, unreadable files, and valid
recursive ownership under actual UID/GID switching.

**Native limitation:** these checks do not attest that the installed
root-control daemon's executable bytes really match `e4f25110...`,
nor do they prove immutable bind mounts prevent the controller from
renaming a top-level checkout under an owner-controlled parent after
a successful traversal. Before native acceptance, host-install and
host-deploy Work must verify immutable mounting and installation
provenance, actual NSS, socket SO_PEERCRED, Project ancestry,
separate build grants and the original preserved operation identities.
No live toolchain or root-control activation follows from green CI.
