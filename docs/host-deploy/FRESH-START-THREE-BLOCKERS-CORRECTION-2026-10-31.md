# Native startup safety review — three blockers corrected in host-deploy source

2026-10-31. Owner: host-deploy Regular. Independent re-review: root-control Regular.
Tracking: host-deploy #5, root-control #11, draft host-deploy PR #2.
Stacked first graphical catalogue: draft host-deploy PR #7.

## Original independent review and accepted boundaries

Root-control Regular review at
[host-deploy #5 comment 6544850201](https://github.com/zog144/host-deploy/issues/5#issuecomment-6544850201)
identified three source blockers in the earlier
`7ea672d1aa60396c3f72eadd084bdc9ac92f98fb` implementation:

1. An allegedly 20-second systemd startup wait began only after bus
   connection and could accept a cached `JobRemoved(done)` after a long
   synchronous fsync callback.
2. Sidecar readiness only checked an active PID and socket pathname. It
   did not authenticate the actual executable, user, cgroup, live
   listening Unix endpoint and process-held socket FD.
3. Each systemctl or procfs read could independently consume time,
   allowing late success beyond the 15-second readiness budget.

The earlier durable original-attempt marker, exact PID1 bus sender and
job path, separate watchdog and sidecar, historical compiler isolation
and one-shot explicit reconciliation remain mandatory. None of these
changes clears native worker containment or permits compilation.

## Corrected source contracts

**20s systemd startup:** `fresh_pid1_job.connect_and_wait()` establishes
the monotonic deadline **before** `MessageBus.connect()`. The same clock
budget covers connection, D-Bus AddMatch/GetNameOwner/Subscribe, the
single fixed `StartTransientUnit`, exact early/late JobRemoved, and
the protected method-ACK callback. Every reply and cached completion
is checked against the deadline **after** its work. The callback is
additionally bounded by an exclusive Linux SIGALRM deadline while
fsyncing the protected job identity; a timed out, interrupted or
partially written ACK is **uncertain** and may NEVER be retried with
a second start. The Linux kernel cannot guarantee that SIGALRM
interrupts a thread stuck in uninterruptible kernel D-state; the
native outer watchdog/cancellation remains a separate prerequisite.
No claim that the kernel has magically bounded D-state is made.

**15s full PID1/readiness:** both watchdog and sidecar obtain one
monotonic deadline. All PID1 `systemctl show` reads use the
**remaining** timeout, and the exact `/proc/PID` cmdline, environment,
executable inode, UID/GID and cgroup metadata are read by a fixed
`-I -B` isolated Python child using `subprocess.run(timeout=remaining)`.
That child is killable if procfs, socket inspection or peer connection
stalls. After **each** PID1/proc readback, and immediately before
success, remaining time is checked. Three complete, stable PID1 + proc
witnesses are required (the third is a full post-readiness
reverification) within the same deadline. No new 15-second allowance is
created per iteration; an over-budget readback cannot become a pass.

**Sidecar identity and listening socket:** each witness requires
`LoadState=loaded`, `ActiveState=active`, `SubState=running`,
`Type=exec`, `Restart=no`, `NRestarts=0`, exact log namespace,
positive MainPID and canonical InvocationID, exact
`/<dedicated>.slice/<fixed>.service` cgroup and live
`/proc/PID/cgroup`, root real/effective/saved UID/GID, the
already-reviewed Python executable inode, exact argv and required
environment variables. A fixed root-owned mode 0660 socket with the
correct controller GID is necessary **but not sufficient**.
The witness also checks `/proc/net/unix` for a unique listening
AF_UNIX stream entry at the fixed socket path; requires its **kernel
socket inode** to appear as an FD held by this exact MainPID; and
connects without sending protocol payload to check `SO_PEERCRED`
(PID=MainPID, UID=0, GID=0). This explicitly avoids the invalid
assertion that the filesystem pathname inode equals kernel socket fd
inode. The original `/proc/PID/root` registration source/destination
device and inode proof remains required in every round. The helper's
bounded procfs reader reads seq_file contents **to EOF**; an earlier
single short raw read could miss later Unix-listener rows.

**One-shot reconciliation:** the method-accepted original watchdog job
ACK is still mandatory; without it there is NO way to approve
reconciliation. If a durable `JobRemoved(done)` completion exists,
the exact original Host/boot/plan/job digest must match. If its
receipt is absent, the review explicitly reports
`original_job_completion=unconfirmed`, **not** an inferred success,
and a separate root-owned operator approval must name that precise
uncertainty and the unchanged currently running PID1/proc witness.
Any mismatched/invalid completion is hard NO-GO. A previously
created/partial `WATCHDOG_RECONCILED` marker prevents automatic
restart or replacement. A second `StartTransientUnit` is forbidden.

## Tests and acceptance handoff

Source/isolated regressions now exercise stalled system-bus connect,
cached early `JobRemoved(done)` with synthetic slow fsync ACK, real
Linux SIGALRM-interrupted callback, no resubmission on failed fsync,
expired PID1/proc/socket reads, three stable witnesses, wrong sidecar
PID1 lifecycle/cgroup/namespace, real positive AF_UNIX listener with
SO_PEERCRED, stale-but-correctly-owned pathname, bound but
non-listening socket, wrong process/UID/mode and short-chunk procfs
seq_file completion. All source tests remain non-admissive; privileged
PID1 252 acceptance has not been run by Regular.

**Root-control Regular** must independently re-review exact latest
source and regressions; return a new explicit pass/finding rather than
treating CI as native acceptance. **host-deploy Work + root-control
Work** may resume on an approved disposable systemd 252 Host only
after that review, with exact installed module/wheel RECORD attestation,
actual D-Bus sender/job and connection timeout, slow/interrupted
ACK and persisted failure markers, real PID1 watchdog/runtime,
real root-control Unix listener peer provenance, unexpected socket
replacement/worker restart, out-of-budget readbacks, one-shot
same-boot uncertain completion approval and reboot invalidation.
Previously accepted 30+2 GiB storage evidence is bounded to its
native tested scope. The remaining HugeTLB, real worker mount/FD,
quota/ENOSPC, deadline, cancellation, cleanup and reboot gates are
separate. The historical compiler #4 and its state remain untouched;
do not submit the fonts task until ALL gates and catalogue
installation actually pass.

No EC2, SSM, PID1, real issuer/credential, root installation,
compiler, canary, durable native catalogue hash or PR merge is
performed by this Regular source correction.
