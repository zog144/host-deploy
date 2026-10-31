# Protected watchdog and sidecar startup — bounded PID1 completion, readiness and reconciliation

2026-10-31. host-deploy Regular implementation; root-control lifecycle review.
Tracking: host-deploy #5, root-control #11, draft host-deploy PR #2.

## Native incident: confirmed boundaries, not inferred success

[October 31 protected installation report](https://github.com/zog144/know-file/blob/de3929cde0ef68abf98f84beabd71001a4596732/host-deploy/verification/watchdog-native-start-2026-10-31/README.md):
on the disposable AL2023/XFS systemd 252 host, the exact installed source,
wheel RECORD, protected absent-history baseline and fully backed **30+2 GiB**
disks passed. The selected protected installer called `install_approved`
**once**, wrote the cron schedule and durable watchdog start-attempt marker,
but failed its immediate active/MainPID observation before sidecar startup.
Later independent readback showed the watchdog **active/running**,
MainPID `27692`, InvocationID `fe2964b5f16a41259be65ec2705da8d5`,
ControlGroup `/system.slice/zogfreshcrossbootstrapoct25-watchdog.service`.
The exact rejected immediate PID1 property snapshot was **not** recorded,
so the individual failing field and precise race mechanism are not proven.
That later active state was **not** accepted as installer completion. The
controller unit remained not-found and the original watchdog attempted
record was preserved. The disposable instance/root volume were then
independently deleted. No historical compiler replay, new compiler
submission or retained-host changes occurred.

## Source correction: completion is different from readiness

`fresh_pid1_job.start_and_wait()` is now shared by the exact independent
watchdog and one fixed root-control sidecar. It:
- registers a system-bus D-Bus **JobRemoved** signal match and systemd
  `Subscribe` **before** `StartTransientUnit`; verifies systemd's
  exact unique bus sender via `GetNameOwner` and rejects forged signals;
- catches completed job signals even when they arrive **before** PID1's
  `StartTransientUnit` method reply;
- matches the returned /org/freedesktop/systemd1/job/N object path
  and exact fixed unit (not just a job ID, arbitrary sender or any signal);
- uses a single **maximum 20-second** deadline including bus
  subscription, method reply and job completion. `done` is the only
  accepted result; failed/timeout/replaced/lost reply remains uncertain;
- invokes the owner's synchronous `on_ack` while the same start attempt
  is live so the exact job path is fsynced; it never retries D-Bus.

The watchdog installer now durably writes:
`independent-watchdog-attempt.json` **before** PID1; then the exact
`independent-watchdog-job.json` on accepted method reply;
`independent-watchdog-job-completion.json` once the job is authentically
`done` and *before* unit readiness; and
`independent-watchdog-result.json` only when the exact live process
passes the full identity witness. Any failure attempts to fsync
`independent-watchdog-failure.json`, including job path, sanitized
job outcome (or unknown), original attempt hash and a fixed **nonsecret**
PID1 property snapshot. If diagnostics themselves fail, the original
attempt remains and installation is still **NO-GO**.

**Readiness:** after job completion the owner waits at most **15 seconds**,
requiring two stable PID1+proc observations of a running watchdog
in the precise `/system.slice/<watchdog>.service` cgroup, strict
`LoadState=loaded`, `ActiveState=active`, `SubState=running`,
`Type=exec`, `Restart=always`, `NRestarts=0`, exact
`LogNamespace`, positive MainPID, nonempty canonical InvocationID,
frozen Python executable inode and original `/proc/PID/cmdline`,
required `/proc/PID/environ` entries and cgroup-v2 association.
No environment/token data is copied to the receipt or logs. Invalid
identity, changed PID/invocation, prior restart or timeout refuses,
not relaxes, the original predicate.

**Sidecar:** the same bounded JobRemoved completion is required for its
own `StartTransientUnit`; the original `sidecar-install.json`
attempted marker retains the accepted job path. The owner then waits
up to **15 seconds** for a stable active MainPID/InvocationID and the
expected socket to appear. The existing socket ownership and namespace
rootfs registration/mount attestation is unchanged. A missing socket,
foreign socket, failed process or readiness timeout preserves the
sidecar attempted marker and a new nonsecret
`sidecar-start-failure.json` snapshot, never a generic restart.

## Recover an uncertain original attempted watchdog — selected only

Regular `install`, `watch`, `watch-loop`, `recover`, `arm`,
cron and worker RPC **do not reconcile, retry or restart** a watchdog.
There is **no** default auto-continuation when the unit later appears
active.

On the **same Host and boot**, a privileged operator may explicitly run
the read-only `inspect-watchdog-attempt` operation. It independently
checks the original protected plan/source/NSS and attempted marker
identity, exact method-accepted immutable JobPath, actual PID1 unit
identity and matching live `/proc` executable, argv, environment,
cgroup, InvocationID and MainPID. It reports a **nonsecret,
non-authorizing** review receipt.

Only after independent native review may a separately root-owned
0600 `independent-watchdog-reconcile-approval.json` be installed with
**exactly** these fields:
`schema=host-deploy-fresh-watchdog-reconcile-approval-v1`,
`status=operator-approved`, `allow_continue_original=true`,
`host_id`, `boot_id`, `plan_sha256`, `attempt_sha256`,
`job_path`, `job_record_sha256`, `invocation_id`, `main_pid`
and `evidence_sha256`, all matching independent current evidence.
`reconcile-install` then:
1. revalidates the exact reviewed sidecar plan/source and old baseline,
   unchanged fixed cron schedule, budget directory, both loop quotas,
   Project/state bind, journal and protected issuer/owner context;
2. refuses any earlier sidecar attempted/active unit/socket, activation
   receipt or already-consumed reconciliation marker;
3. re-reads the original exact live watchdog identity **again** and
   refuses changed evidence or an unreviewed approval;
4. exclusively fsyncs `independent-watchdog-reconciled.json`
   **before** a new sidecar start;
5. invokes only the original `sidecar.install()` protected once-only
   backend; the watchdog itself is **never** started again.
   If this new sidecar attempt fails, it retains all attempted, job and
   failure records for another explicit separate review. The original
   watchdog reconciliation marker cannot be used twice.

Missing accepted PID1 job path, wrong boot/source/plan, any PID1 restart,
unknown old invocation, incomplete approval, socket collision or
ambiguous D-Bus result is **NO-GO**. The previous October 31 host was
deleted, so this is a forward-looking safe recovery contract—not an
attempt to resurrect or adopt that disposed instance.

## Source CI and native acceptance

The public and restricted CI include genuine dbus-next 0.2.3
message models with JobRemoved before/after the StartTransientUnit reply,
failed job result, bounded method/job timeout, spoofed-sender rejection,
sidecar socket-delay/active PID stabilization, invalid identity,
strict one-shot protected reconciliation and no double-start.
These are synthetic and filesystem-owner fixtures: no actual systemd
manager or external host was mutated.

**Native NO-GO remains:** independently review installed exact module
bytes and wheel RECORD, observe actual systemd 252 D-Bus Subscribe/
GetNameOwner/AddMatch/JobRemoved and PID1 job path, positive and delayed
watchdog activation, NRestarts and /proc argv/env identity, interruption
at each durable marker, snapshot persistence, timeout/reconciliation
with independently installed operator approval, sidecar delayed socket
and PID1 identity, and reboot invalidation. Then continue the
separately approved HugeTLB, real worker mounts/FD, ENOSPC, deadlines,
cancellation, cleanup and reboot gates. The six-hour/30+2-GiB contract,
existing historical compiler protection and no-auto-replay remain unchanged.
No native Work acceptance, EC2 change, PR merge, canary or compiler submission
is made by this Regular source work.
