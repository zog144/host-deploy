# Native worker storage admission — implementation and Work contract

**2026-10-28 · host-deploy #5 / root-control #11**

**Status: source candidate; NOT native accepted. No Stage B compiler.**
This source is confined to the new build-only sidecar. The old controller,
historical bad-setting unit, and original gateway request #4 are frozen.

## Purpose

An earlier `fresh_aggregate_disk.validate()` could structurally accept
`unaccounted_writable_roots=[]` if the caller supplied an apparently trusted
dictionary. The preactivation implementation also manufactured a temporary
empty list in memory to reuse that validator. That is **not trusted native
proof** and is no longer used for live arm/watch authorization.

`fresh_native_storage_verifier.inspect_live()` is a root-only read of the
**current** PID1/worker/kernel state. Its fixed call path comes from
`fresh_native_owner.NativeOwner.verify_live_storage()`, which must re-verify
the reviewed sidecar PLAN, immutable installed source bytes, NSS, historical
baseline, exact protected v2 admission and sidecar PID1 identity before
inspecting the worker. Nothing in the public GitHub/SSM command envelope or
the producer's JSON may set a verified flag, override a process, a path, or an
approved writer class. All classes remain explicitly outstanding in native
`inspect_external_native` and `validate_pre_activation`.

The helper fails closed unless all these native observations agree:

- Exact `host_id`, installed `boot_id` == kernel boot UUID, reviewed-plan
  digest, fresh Project path, v2 dedicated storage scope and request ID.
- Both fully allocated 30-GiB / 2-GiB loop-backed ext4 images, exact
  `Project/state` device+inode bind, protected rootfs import, real namespace
  journal backing and independent devices.
- Exact active root-control PID1 MainPID, root UID, **exact sidecar service
  cgroup under the protected parent slice**, and an unchanged twice-sampled
  descendant PID inventory.
- At least one actual live finite worker. Every discovered other process
  must be an approved nonroot build UID/GID inside the frozen descendant
  cgroup. Unknown root/foreign principals fail.
- Each worker's real `/proc/PID/root` resolves to the approved 30-GiB
  imported rootfs; `/proc/PID/mountinfo` and stat through that root prove
  that source, output, /tmp, /var/tmp and /run are bounded ext4 mounts. Only
  the fixed pseudo-filesystem paths are accepted as writable outside it.
- Cgroup `memory.swap.max=0` and finite `memory.max`, and every opened
  **writable** regular/directory file descriptor must be on the bounded
  build device or an identified in-memory memfd; foreign host regular FDs
  and writable devices other than exact /dev/null are refused.

The result is `live-evidence-only`, with exact host/boot/Project/request,
controller PID, observed worker PIDs and kernel backing. It is **NOT** a
durable permission to start arbitrary future workers or a certificate that
the original total-host-writes budget is met. Existing shared-host overhead
is excluded only under the separately approved dedicated-storage policy.

## Protected fixed operation

`python3 -B -m zog.host_deploy.gateway.fresh_native_owner inspect-native-worker-storage`

This has **no arguments**, no generic root shell, no process start/mount,
and no gateway/SSM request. It returns read-only, JSON-formatted evidence,
and fails unless the installed native owner is root, the external state and
exact reviewed receipts are already installed, and a real live finite worker
is observable. Missing worker => NO-GO, not empty success.

The same inspection is required by `arm_approved()` BEFORE creating the
timer/budget checkpoint and by `NativeOwner.sample_exact()` on every
watchdog cycle. On a failed worker witness, the watchdog produces
`sidecar_active=False` so the durable budget state transitions to UNCERTAIN
and cancellation instead of merely throwing away the observation. A
failure before arm leaves the budget unarmed and the compiler unauthorized.

## Root-control companion

[Root-control draft PR #14](https://github.com/zog144/root-control/pull/14)
adds `BuildBackend.inspect_fresh_worker_native()` and the read-only kernel
observer `fresh_native_worker_witness.inspect` on a branch created from
host-deploy's *exact currently pinned* root-control source revision
`cacacbee66c0401e04dfe702d6b90e87215280d0`. It calls existing
`BuildBackend.observe` to verify PID1's fixed service properties, then
reads actual MainPID/cgroup/UID/GID/root/guest mounts, memory/swap and boot.
It returns `live-process-only-not-admission` and exposes no new remote
authorization endpoint. **The root-control executable pin is NOT yet
advanced**: independent source review/Work acceptance is needed first.

## Required sequence before native acceptance

1. Independently approve and prove a **disposable** native Stage A worker
   canary, installed byte-for-byte from exact reviewed successor source,
   with approved nonroot roles. Do not start a real cross-bootstrap as a
   canary. Confirm every process/cgroup/mount, writable FD, PID1 property,
   log backing, ENOSPC and memory-swap negative.
2. Fix any source defects on the relevant Regular branch. Reconcile the
   protected root-control pin only after reviewing PR #14 and its exact
   installation hash, never silently repin historical v1/v2.
3. Observe a live finite canary on the target fresh host **before arming**:
   this interface deliberately does not accept an empty worker inventory.
   The current runtime cannot arm an empty lane using this positive witness.
   Its safe bootstrapping procedure/authorization and no-replay behavior need
   separate Work review; **do not bypass the gate with a fake worker or an
   empty writer list**.
4. Re-inspect on every later worker lifecycle and separately prove the
   overall six-hour PID1 deadline, dual watcher loss, exact cgroup.kill,
   journald disk-full, reboot and same-request no-replay. Any uncertain PID
   or namespace change must block/cancel the fresh lane.
5. Only after all gates and old-unit baseline hashes pass may the one
   separately authorized fresh `toolchain.submit(cross-bootstrap)` be
   considered. No additional phases, EC2 resources or retained-host changes
   were performed in this source pass.

The existing 32-GiB budget remains a **dedicated** 30+2-GiB reservation,
not a cap on routine shared-host service writes.
