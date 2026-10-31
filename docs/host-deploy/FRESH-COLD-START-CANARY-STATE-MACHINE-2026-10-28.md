# Fresh compiler cold-start/canary: exact production ordering, native NO-GO

2026-10-28 · [host-deploy #5](https://github.com/zog144/host-deploy/issues/5) · [root-control #11](https://github.com/zog144/root-control/issues/11)

## Why existing production admission cannot start

Prior host-deploy `arm_approved()` calls `verify_live_storage()`, whose
kernel inspector requires at least one worker PID. root-control should not
start that worker before the independent six-hour deadline timer and
protected budget are durably armed. Starting the worker early or claiming
an empty process list is proof of *future* worker containment would both
violate the security boundary. A canary is a real finite, isolated worker,
not a fixture or synthetic worker receipt.

**Important scope:** current source commits add a read-only kernel-backed
empty-lane witness and explicit phase policy. The actual protected root-only
launch gate, durable state writer, canary start, canary acceptance record,
root-control companion installed source pin and host-deploy arm/watch
integration are **not yet adopted**. Consequently the existing live-only
`arm_approved` keeps rejecting an empty lane; no production transition or
cross-bootstrap is unlocked by the new evidence modules.

## Required phase sequence (only with independently accepted future source)

1. **Prearm-empty:** verify exact host, live boot UUID, Project, native
   installation/STATE, accepted root-control and host-deploy executable bytes,
   protected old baseline, two fully allocated 30+2-GiB images, registration
   and journal mounts, sidecar PID1 service and correct parent cgroup. Read
   every PID beneath the parent cgroup TWICE with no symlink following.
   Exactly the trusted root controller MainPID may be present. Independently
   enumerate root-control bounded job records: any attempted/unfinished job
   rejects idle. Result is `empty-prearm-only`, not launch permission.
2. **Arm first:** a separately reviewed root-control *start gate* must already
   be installed and bound to the same host/boot/Project/source/installed bytes
   and capable of REFUSING all fresh worker starts before the ledger exists.
   The protected host owner starts the exact systemd 252 monotonic timer
   (21,600 s less 30 s), verifies its live paired stop unit/expiry, then
   fsyncs the one-shot protected budget (same host/boot/Project/request).
   No start is possible in the timer-start/budget-write gap. Any uncertain
   D-Bus reply or fsync failure is held for review, never blindly retried.
3. **Armed idle:** after the durable budget and live timer are both verified,
   empty native census is now an authorized *idle observation*; it does NOT
   imply the next executable is safe. Six-hour time and watchdog checks keep
   advancing during idle; idle never resets, extends or pauses the deadline.
4. **Exactly one reviewed canary grant:** the native owner reviews and freezes
   the fixed canary job ID, resource ID, canonical command/executable and
   argument digest, rootfs/seed bytes, UID/GID, source/output/scratch mounts,
   boot ID, request ID, Project, timer, memory/swap/cgroup and finite runtime.
   This is separately signed/installed root-owned authority, not a
   GitHub/SSM-supplied `canary: true` switch. It must not choose a generic
   shell or permit real cross-bootstrap. The root-control start gate checks
   the active budget, monotonic deadline, current watchdog, exact canary
   identity, and claims one attempt durably under a shared lock BEFORE PID1
   `StartTransientUnit`; it may not admit two simultaneous first canaries.
5. **Canary-start-attempted:** a missing MainPID is temporarily distinguishable
   from an escaped worker only while the matching protected one-shot
   `start_attempted` record is the same host/boot/Project/request/job and
   no older than **10 seconds**. The native owner must still observe the
   entire process census; any unexpected worker fails immediately. After
   ten seconds, missing worker becomes UNCERTAIN/cancel, never allowed idle.
6. **Canary live:** inspect actual systemd transient properties and frozen
   invocation ID; full root-control PR #14 and host-deploy kernel witnesses
   must read all descendant PIDs, mount layers, exact RootDirectory inode/dev,
   source/output/tmp/run bindings, FD write handles, pseudo mounts, cgroups,
   memory/swap and namespaced journald. Any unverified process/foreign write,
   missing PID, or process census race triggers exact fresh-slice cancellation.
   A live canary receipt is **not** authority for future workers.
7. **Canary clean idle:** stop and positively observe all canary descendants
   gone, terminal journal/InvocationID and root-control
   `process_cleanup_complete=True` after unit release. Only the protected
   host owner may persist a one-time canary acceptance bound to actual
   host/boot/source/plan/worker policy, current budget and verified native
   canary evidence. If no such acceptance or cleanup, absence of a worker is
   **unexpected missing worker**, never an allowed idle interval.
8. **Compiler launch and later idle:** every compiler job requires current
   one-time operator authorization plus same-boot accepted canary, a fresh
   root-control start-gate readback of the active budget/timer, frozen job
   identity and durable start attempt. A ten-second missing-PID allowance
   applies only to its exact start attempt. Each running worker is rechecked
   live on every watchdog cycle (and on PID1 activation); after termination,
   only authenticated complete cleanup permits `compiler-clean-idle`.
   One canary cannot establish permanent blanket containment authority.
9. **Deadline/failure/reboot:** any uncertain phase, timer/monitor loss,
   full journald, expired deadline, missing worker outside protected pending,
   changed host/boot/Project/source, reused nonce, unexpected concurrent
   worker or reboot blocks further starts and enters existing durable
   cancel/reconciliation. Reboot cannot import an old canary acceptance.

## New source-level phase and evidence interfaces

- `fresh_native_storage_verifier.inspect_empty()`: real native root/boot,
  30+2-GiB backing, verified journal, controller MainPID, twin PID census,
  and NO incomplete attempted job in the bounded registration directory.
  Status `verified-empty-lane-not-start-authority`; no writer class is
  cleared and no compiler may be launched from this receipt.
- root-control `BuildBackend.inspect_fresh_idle_native()` on draft PR #14:
  independently verifies fixed fresh role/Project, PID1 controller MainPID,
  cgroup and double census. Returns
  `native-empty-only-not-admission`, with `future_workers_verified=False`.
- `fresh_cold_start_policy.classify()`: pure fail-closed phase schema for
  `prearm-empty`, `armed-idle`, bounded ten-second canary/worker starts,
  `canary-live`, `canary-clean-idle`, `compiler-live`,
  `compiler-clean-idle`. Every branch explicitly returns
  `compiler_admission=False`. The function never accepts an external JSON
  field as native grant; only the future protected owner may construct
  arguments from the kernel and durable local records.
- Existing `inspect_live()` remains mandatory for active workers. The
  production `arm_approved()` and watchdog are intentionally **NOT**
  switched to accepting new `inspect_empty()` results until the independent
  root-control start gate, native canary producer and lock/durability model
  are implemented and accepted.

## Required native Work acceptance

Use only the approved disposable systemd 252 test environment. Negative tests:
missing worker with no pending attempt; pending beyond 10 seconds; two starts
racing on one canary; forged job marker/owner, wrong command, stale nonce/boot;
worker appears during second census; FD/mount/hugepage escapes; canary exits
before live witness; clean idle with incomplete job cleanup; untrusted
`canary_verified` JSON; crash after deadline timer before budget write;
ENOSPC during start intent; reboot; stopped/expired timer and original #4
hash preservation. Do not use a dummy canary receipt to authorize compiler.

**Current disposition:** NO-GO for production admission; source foundations
and tests are reviewable in draft PRs. No retained host mutation, compiler
submission, canary start, new EC2 resource, PR merge or adoption of
unreviewed root-control source pins.
