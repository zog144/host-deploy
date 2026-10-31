# Fresh-v3 guarded cold-start implementation and native Work acceptance

**Date:** 2026-10-28. **Owner:** host-deploy Regular + root-control Regular.
**Issue:** host-deploy #5; root-control #11.
**Branch:** host-deploy draft PR #2, root-control draft PR #14.

## Scope and authorization

The owner authorized **six hours** and **32 GiB of additional dedicated
compiler storage reservation**, with normal shared-host management overhead
outside this storage allowance. The original cross-bootstrap is NOT authorized
to run until independent disposable-host native verification of all Stage A
gates succeeds. This implementation does not modify retained EC2, historical
compiler #4, shared PID1/default journald/SSM, or an existing controller.

**Exact root-control source successor:**
`4a6ef2252c06a92cbab2550c4fec24a48438a4ba`.
Host-deploy's *fresh-only* source pin, restricted workflow checkout, native
identity regression and `fresh_canary_owner.REQUIRED_GATE_REVISION` all
reference that exact commit. The full protected installed-source tree hash,
UID/GID, host/boot, registration, Project mounts and old baseline are still
independently checked at runtime. A source-only pin move does not install
these bytes or authorize a canary.

## Production cold-start flow (new source)

1. **Prepare before arming:** host-deploy root owner checks reviewed
   `reviewed-plan.json`, `reviewed-admission.json`, original old baseline,
   exact pinned installed source, controller service/PID1 identity and
   both quota images. `storage_verifier.inspect_empty()` requires exactly
   the trusted controller MainPID in two stable fresh-slice cgroup enumerations
   with no incomplete previously attempted root-control job.
2. **Arm protected deadline first:** `arm_approved` explicitly verifies the
   new guarded root-control installed revision and native empty lane. It writes
   the fsynced one-shot deadline attempt, starts/verifies the systemd 252 timer
   and writes the fsynced six-hour budget checkpoint. Only then does
   `fresh_canary_owner.arm_empty()` create protected
   `owner-state/fresh-start-phase.json` with `armed-idle`.
   If interrupted, absent phase/grant cannot authorize a worker.
3. **Separately reviewed canary intent:** root-only
   `reviewed-canary-intent.json` must be externally reviewed/installed in
   the 2-GiB owner-state image and match the frozen host/boot/Project/plan/
   request and registered 30-GiB build root ID. The canonical canary is
   **`/usr/bin/sleep 30`**, working directory `/`, PATH only, no network,
   nonroot build UID/GID, runtime 40s, termination grace 3s, 16 threads and
   128 MiB memory. No generic shell, command override or supplied grant.
   The fixed native `grant-canary` operation rechecks kernel-empty/clock/
   budget and fsyncs exactly one `fresh-start-grant.json` entry.
4. **Enforced root-control pre-start:** all fresh
   `BuildBackend.start()` invocations take an exclusive lock on the same
   protected `owner-state/fresh-start.lock`. The trusted gate reads the
   independently protected grant, budget record, same-boot PID1 deadline
   timer, canonical request digest, exact job ID, source/Project and
   `armed-idle` phase. It writes and fsyncs exactly one
   `fresh-canary-claim.json` (O_EXCL) and a durable
   `canary-start-attempted` phase BEFORE the irreversible systemd
   `StartTransientUnit`. A second request, changed command/boot/clock,
   uncertain prior claim or expired budget is refused. After preparing
   filesystem mounts and worker properties, the gate checks the budget,
   heartbeat, PID1 timer and same claim AGAIN immediately before PID1.
   The same lock prevents a watchdog budget-stop race.
5. **Bounded pending:** the native watchdog accepts missing MainPID for at
   most TEN seconds when it sees the exact claimed job, backed by a second
   kernel cgroup/quota witness. No job or a stale/wrong claimed worker is not
   idle; it fails closed into the existing durable cancellation path.
6. **Live canary:** on first verified running worker inside the ten-second
   window, the watchdog records actual PID1 invocation ID/MainPID and full
   native rootfs inode, writable mount layers, FD, cgroup and memory/swap
   evidence as `canary-live-witness.json`. It fsyncs the transition to
   `canary-live`; future watchdog ticks repeat the full native witness.
   Evidence is not blanket authority for future jobs.
7. **Terminal canary and cleanup:** when the finite process exits, PID1
   status must show successful exit 0 with the same InvocationID. The
   protected owner durably stores `canary-terminal.json`. A transient
   absence is allowed only in a bounded **ten-second** cleanup handoff and
   with a fresh empty *pending* cgroup census; it is NOT authorized idle.
   After root-control has released the finite unit and persisted
   `process_cleanup_complete=True`, a full clean empty-lane witness can
   persist `canary-accepted.json` and the `canary-clean-idle` phase.
   Interrupted, changed-boot, failed exit and incomplete cleanup never
   create this acceptance.
8. **First compiler only:** `grant-compiler` reads a separately protected,
   reviewed canonical compiler intent and same-boot `canary-accepted.json`.
   It replaces the already-consumed canary grant under the same lock,
   without replacing its original claim. Root-control independently reads
   and hashes the *actual* accepted canary record before authorizing one
   exact compiler job; it writes `fresh-compiler-claim.json` exclusively
   and rechecks PID1/budget at start. Compiler live/terminal/clean phases
   require independent native PID1 and worker evidence. No generic
   or second compiler start is authorized.
9. **Idle watchdog and failures:** `sample_exact` obtains its phase only
   from the protected owner-state and actual kernel, not an SSM/GitHub flag.
   The budget watchdog and hard-deadline cancellation take the shared
   launch lock before updating the active budget. Only `armed-idle`,
   native `canary-clean-idle`, and fully cleaned `compiler-clean-idle`
   can be reported as active without a worker. The overall six-hour timer
   NEVER pauses/resets during idle. Wrong or absent phase, foreign writes,
   PID1/journal/SSM errors, ENOSPC, failed witness, boot change, tampered
   record or deadline timeout retain the existing fail-closed
   `UNCERTAIN/cgroup.kill` behavior. No old request replay.

## Native acceptance still required — NOT A PRODUCTION GO

Source and mock/fixture CI demonstrate admitted property shapes, durable
claim ordering and negative tests. They do **not** prove actual:
- installed source/tree SHA and systemd 252 sidecar adoption;
- two quota-backed mounts, journal namespace and rootfs/FD/hugetlbfs escapes;
- a real disposable canary start and <=10s MainPID witness;
- actual PID1 live, terminal and post-cleanup readback before its AddRef
  disappears, including the 10s handoff timing;
- ENOSPC during claim/budget fsync, cancel and positive stop receipt;
- two concurrent compiler claims, timeout/clock races;
- full six-hour watchdog death/independent timer, cancellation, reboot
  and no-replay;
- unchanged original #4 host/workload identity.

**Disposition:** Both PRs remain DRAFT and UNMERGED. The retained host
requires explicit native Work review and installation authorization. Do not
submit a fresh cross-bootstrap merely because source CI is green.
