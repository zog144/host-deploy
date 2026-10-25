# Fresh isolated cross-bootstrap — reviewed host-deploy binding candidate

Date: 2026-10-25  
Owner: host-deploy Regular  
Tracking: [host-deploy #5](https://github.com/zog144/host-deploy/issues/5)  
Branch: `regular/toolchain-gateway-20261019` (draft PR #2)  
Disposition: **source-only candidate; Stage A native admission required. No submission in this review.**

## Approved limit and preserved historical fault

The user authorized exactly **one newly authenticated durable
`toolchain.submit` for `cross-bootstrap`**, on the existing EC2 host,
under an **overall six-hour execution limit and no more than 32 GiB
additional disk**, while preserving all existing workload reservations.
The controller may inspect/resume **that same pending new operation** only;
`temporary-userspace` and all later phases are not authorized.
No new EC2, old compiler resume, historical controller recovery, production
promotion or extra typed submission follows from this source merge.

Historical request `371da99f23764180aad37d8e4e83595b` and its
old `image-build@31e6121...`, `box-control@644170fc...`,
`root-control@e4f25110...`, pipeline/attempt/job/resource/InvocationID,
original seed and old `bad-setting` evidence remain frozen.
Review [host-deploy #4](https://github.com/zog144/host-deploy/issues/4)
and [root-control #10](https://github.com/zog144/root-control/issues/10);
this change neither adjudicates nor clears historical uncertainty.

## Fresh exact source tuple (not an installed tuple)

| Source | Exact candidate |
| --- | --- |
| image-build | `53ad8c2166e6b73dffbc722c2e47ccf3593612ec` |
| box-control | `b7934882cfacd2fbfd60c7964713ed3dde7f9460` |
| root-control executable | `19d423cdf16531474de5680117867e12b5bb0620` |
| build-record | `a866c9c4b0dd385045f00ce2de7d809f5b67c104` |
| October monthly lock | `project/pins/2026-10-01/commit-pin.py` · `sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36` |

The checked image-build source `53ad8c...` retains
`runtime_requirements.BUILD_RECORD.validated_revision=a866c9c4...`,
with the required `make_record`, `Store`, `verify_artifacts` and
model API. That is a **producer-declared source compatibility checkpoint**,
not evidence that the companion is installed and native-compatible.
The newer producer does **not** itself retarget its
`BOX_CONTROL.validated_revision`: it still advertises
`644170fc...`, while this fresh candidate independently selects
`b7934882...`. This deliberate, narrowly scoped distinction is checked
during preflight: the root SSM shell verifies the actual b7934882 Git
HEAD/clean checkout, and image-build's read-only runtime smoke verifies
its actual API and version. Host-deploy validates the known source-declared
old compatibility field without misrepresenting it as the installed
revision. **Do not generalize this allowance to another producer/controller
pair.** Controller owners must independently approve the corrected API and
native root-control grant.

## Durable isolated identity and operation

New owner-only schema `host-deploy-compiler-execution-v3` requires exact
producer/box-control/root-control/build-record source revisions; a new
controller nonroot UID/primary GID and *actual passwd home*; Project strictly
beneath that home; a distinct build UID/primary GID; a pinned Python
interpreter; root-owned, recursively non-writable immutable source and
companion trees; exact protected task digest; and a **dedicated**
`/run/zog/root-control-<new-lane>.sock` that is not the original shared
`/run/zog/root-control.sock`. The corresponding new root-control listener
must be installed/attested independently as root:controller-primary-GID
mode `0660` and authenticate exact `SO_PEERCRED` UID.

The protected schema-4 managed lane specification must match the frozen
socket, build UID/GID, resource reservation and source tuple.
Each `bind_compiler_execution_identity` is one-time and idempotent only
for byte-identical scope. Dispatch preparation and
`verify_current_target` reject changed lane/worker/socket/source/task
identity before a new SSM request. The root SSM launcher keeps root-only
request/result journals and passes immutable request bytes by a sealed
`memfd`; it drops to the controller UID/GID with no supplementary groups,
no inherited root environment and the real home.

`fresh_scope` must be exactly:

```json
{
  "schema": "host-deploy-fresh-cross-bootstrap-v1",
  "phase": "cross-bootstrap",
  "execution_limit_seconds": 21600,
  "additional_disk_bytes": 34359738368,
  "existing_host_only": true,
  "automatic_later_phases": false
}
```

The lane binds a controller per-command execution timeout **no more than
21,600 seconds** and additional disk reservation **no more than
34,359,738,368 bytes**. This is not a claim that static
per-command timeouts automatically enforce an overall wall-clock
watchdog across multiple controller jobs or prevent capacity overuse.
**Work must verify a host-owned enforced overall execution deadline and
disk observation/stop mechanism before submission**, with original
reservations and Certbot/station work protected.

The durable typed supervisor still supports the original historical
multiphase journal records. For this **fresh v3 operation only**, a terminal
successful cross-bootstrap sets the journal's scoped status to completed
without allocating `temporary-userspace`. It does not manufacture
a final self-hosted toolchain artifact receipt, release or promotion.
A lost SSM reply remains uncertain and may not be resubmitted.

## Native owner/Work acceptance before Stage B

1. Read and hash the unchanged historical request/ledger/controller state.
   No stop/reset/reload or retry of the old `ExecStartEx` job.
2. Confirm existing-host identity, capacity and fresh reserved resources
   with no unfinished writer for the new root; do not borrow historic
   writable state or displace existing workloads.
3. Independently approve and install **new** owner/group, distinct
   controller socket, protected box-control Project, build UID/GID,
   immutable source mounts and new generated durable owner/epoch/IDs.
   Verify actual root-control executable bytes at bc52f2e9, controller
   SO_PEERCRED, wrong-UID/group/Project rejection and build worker cgroup
   mount/network/security policy. Do not modify the shared daemon.
4. Independently verify 13,256-item host-bootstrap seed manifest and
   archive SHA-256 inventory; import immutable generation into the **new**
   catalogue with a new accepted generation selection. No old mutable
   pipeline/attempt/worker Project import.
5. Verify actual clean immutable Git HEAD and Python module RECORD for the
   exact candidate tuple, selected producer
   `image-build-toolchain-remote-execution-v1` and real
   `toolchain.specification.inspect` / `capabilities.inspect`.
   Reject if newer box-control smoke, build-record API or selected
   root-control grant is incompatible.
6. Freeze a separate root-owned task with new imported seed generation
   and a new admission receipt, including new request ID,
   exact lane/project/host, controller/build UID/GID,
   reviewed overall time/disk cost limits. Prove only one user-authorized
   cross-bootstrap source/seed/phase is admitted.
7. Execute exactly one newly admitted SSM/GitHub typed submission
   **only when Stage A all passes**. On unknown result,
   inspect the original *new* request/CommandId; do not retry with a
   different identity. Read-only inspect and separately authorized
   same-operation resume may continue pending cross-bootstrap.
8. Stop after cross-bootstrap completion or on native uncertainty.
   Report jobs, invocation IDs, exit, cleanup, manifest/output hashes,
   elapsed usage and actual cloud cost. No later phase, release or merge
   authorization is implied.

## Source acceptance boundary

Public CI source tests cover the reviewed tuples, exact scope, forbidden
historical/shared socket selection, immutable dispatch drift, stop-after-
cross-bootstrap, and actual disposable Linux nonroot transition through
a separate root-owned Unix socket. They **do not** reproduce live root-
control SO_PEERCRED, installer and cgroup execution, immutable rootfs
import, host ownership/epoch, no competing writers, overall execution
deadline, or running certificate/station reservations.

PR #2 remains **draft**. Its merge review and native acceptance remain
separate. No AWS/SSM submission, new infrastructure or service changes
were made by Regular implementation.

## Root-control #11 restricted sidecar correction and no-reload native hold

The root-control build-only role was implemented on the exact new executable
source `19d423cdf16531474de5680117867e12b5bb0620` (documentation review
head `231bb7a64df2e1f645fcdfae8e953d83cf932816`).
The earlier `bc52f2e9...` build backend alone was **not safe** for this
new socket: its general `systemd_*` / issuer / application APIs remained
reachable by an otherwise correctly authenticated controller UID.
The new role is `build-only-project-v1`, startup-frozen to the exact
Project and peer UID/primary GID; all forbidden RPCs are denied before
backend execution. Existing shared root-control remains unchanged.
[Owner implementation and CI handoff](https://github.com/zog144/know-file/blob/7effc2dc3d742e1a98465bfcebd4a5bf4e208faf/root-control/handoffs/fresh-compiler-build-only-project-implementation-2026-10-25.md).

New **host-deploy source contracts**, not yet installed:

- `gateway/fresh_sidecar_install.py` forms a fixed, authenticated
  `zog-fresh-cross-bootstrap-oct25-controller.service` transient
  service request for PID1 `StartTransientUnit`, mode `fail` (no replace).
  The proposed candidate exact root-owned role environment is
  `ROOT_CONTROL_ROLE=build-only-project-v1`,
  `ROOT_CONTROL_AUTHORIZED_PROJECT=/home/zog-cross-owner/fresh-cross-bootstrap-oct25`,
  `ROOT_CONTROL_SOCKET=/run/zog/root-control-fresh-cross-bootstrap-oct25.sock`,
  `ROOT_CONTROL_CONTROLLER_UID=<approved actual UID>`,
  `ROOT_CONTROL_SOCKET_GID=<approved actual primary GID>`,
  plus reviewed immutable Python source. `ExecStart` is a fixed
  reload-compatible `python -B -m zog.root_control`, `Type=exec`,
  journal logging and bounded restart; there is **no** `ExecStartEx`,
  `daemon-reload`, disk unit-file installation, shell command from GitHub,
  or shared socket fallback. The start operation demands a trusted
  root-owned host-owner backend with old-state validation, verified
  installed bytes/NSS, no existing sidecar/socket, and fresh PID1
  InvocationID/role/socket readback; it is **not** an SSM gateway operation.
  Its use on the retained host is not yet authorized by source CI.
- `gateway/fresh_budget_guard.py` freezes one exact request/host/Project,
  root-owned sidecar and watchdog receipts, persistent UTC and monotonic
  start/deadline, protected disk baseline and independent monitor identity.
  It fails closed on exceeding 21,600 seconds overall or
  34,359,738,368 bytes additional *monitored* disk; stale heartbeat,
  reboot/boot-ID drift, clock rollback, monitor inactivity or foreign
  Project yields **uncertainty and a fresh-Project-only stop request**.
  `watch_once` offers serialized root-owned journal commits, not an
  automatically scheduled monitor. It must be installed as a host-owned,
  independently running and reboot-reactivated service with verified
  underlying quotas and safe cancellation; do not use GitHub Work's
  polling loop as the only watchdog.
- `toolchain_supervisor.advance` now **refuses any fresh v3 transition**
  absent an injected, authenticated host-owned native budget owner,
  even when source CI and generic gateway admission passed. Historical
  v1/v2 controller operations retain their own old contracts.

**Mandatory native Stage A still NO-GO until:** the existing host-owned
installer has an independently reviewed exact `StartTransientUnit`
D-Bus backend and root-only authority; the new locked NSS identities have
been approved and collision-tested; the source/module/wheel bytes, fresh
Project, dedicated socket, peer/GID rejects and unit InvocationID have been
attested; the host-owned boot reactivation hook was installed/tested
*without touching the original PID1 unit*; the aggregate watchdog, quota,
real cancellation and restart/uncertainty fixture pass; the immutable
host-bootstrap seed+archive inventory is imported and revalidated under
a new generation; and old controller/fragment/workload readback hashes
match before and after. The trusted installer backend is deliberately not
routed through a generic unprivileged caller or GitHub/SSM shell.

See the [seven-step root-control owner's native sequence](https://github.com/zog144/know-file/blob/8be3433dd816e30c34c845c26e9a9d1937e3f90d/root-control/handoffs/fresh-cross-bootstrap-stage-a-controller-review-2026-10-25.md).
No source pass authorizes starting the sidecar or submitting a compiler job.
