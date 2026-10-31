# Decision: fixed 32-GiB dedicated compiler storage on retained shared host

**Decision date:** 2026-10-27. **Owner:** explicit user instruction in host-deploy Regular/Work thread.
**Issue:** [host-deploy #5](https://github.com/zog144/host-deploy/issues/5)
**Branch:** `regular/toolchain-gateway-20261019`, draft [PR #2](https://github.com/zog144/host-deploy/pull/2).

## Accepted revised scope (NOT the former strict all-host-writes budget)

The owner chose the retained **shared host**, with **32 GiB as an upper bound on
additional dedicated compiler storage reservation**. This is NOT a 32-GiB cap
on total EC2 host-rootfs allocations, cumulative physical I/O, ordinary
shared-host PID1/default-journald/SSM/crond events, or filesystem metadata
outside the dedicated storage images. Those shared-host effects remain
observable and operationally protected by existing host free-space/reservation
preflights, but **are not charged to this dedicated storage allowance**.

| In scope, bounded | Limit | Enforcement |
| --- | ---: | --- |
| Fresh compiler build root, imported rootfs, source/output, workspace, scratch and finite worker logs | **30 GiB** | Fully preallocated file-backed ext4 plus mount/namespace/cgroup rules |
| Fresh protected owner state, journal namespace, controller logs, metadata and budget records | **2 GiB** | Separate fully preallocated ext4 loop image; actual persistent+volatile journal backing must be proved |
| **Maximum new dedicated file reservation** | **32 GiB total** | Both image files counted once; no additional dedicated data files or new EC2/EBS |

The image files reside on the existing host, and their contents and in-image
filesystem metadata occupy the already-reserved bytes. Shared rootfs
directory/index/block metadata, installer I/O and routine host-service
allocations are specifically outside the revised *dedicated reservation*
metric. Worker writes may NOT exploit this exclusion: any fresh worker output
or new compiler-owned mutable storage outside the two bounded images remains
a source or native acceptance failure.

### Policy identity, no silent retrospective adoption

- New native aggregate storage policy:
  `fresh_aggregate_disk.SCHEMA = host-deploy-fresh-dedicated-storage-v2`;
  `BUDGET_SCOPE = fresh-dedicated-reservation-32gib-v1`.
- Root-only reviewed admission must now be
  `host-deploy-fresh-native-admission-dedicated-v2`, with the same exact
  `budget_scope` field. Older strict-total authorizations/receipts
  fail closed, even if their request or Project would otherwise match.
- Fresh durable six-hour budget schema is versioned separately to
  `host-deploy-fresh-dedicated-storage-budget-v2`. No original #4 replay.
- The two image limits remain 30 GiB and 2 GiB; a source-only claim of
  verified backing is insufficient. `inspect_external_pool_native()` keeps
  fixed `DEDICATED_UNVERIFIED_WRITERS` outstanding and
  `validate_pre_activation` never authorizes compiler admission.
- `validate` checks both image reservations, actual protected class roots,
  nonempty writer escapes, exact `budget_scope`, and a fixed transparent
  `excluded_shared_host_overhead` list. No arbitrary exemptions or
  caller-supplied disk paths.
- Host-write diagnostics continue to enumerate the excluded shared writers.
  Exclusion is a deliberate policy distinction, NOT a claim that they use
  the 2-GiB image.

**Six-hour limit remains unchanged.** A single 21,600-second overall deadline
is enforced by fixed monotonic PID1 timer (triggered 30 seconds early) plus
independent watchdog and cron, with frozen fresh-only cgroup cancellation.
Runtime quota sampling stops when actual 30-GiB build image occupancy reaches
its cap; host-wide disk delta is NOT falsely used as a dedicated budget metric.
Native timer/cancellation/ENOSPC proof remains separate and mandatory.

## Completed disposable read-only PID1 observation

GitHub Actions: [Fresh shared-host read-only PID1 preflight,
run 40589218507](https://github.com/zog144/host-deploy/actions/runs/40589218507),
job `122488746095`, source revision `f6cc37dd509fca6f542e361ab1411cb175706ba6`.
This used an ephemeral **github-hosted** Ubuntu runner, no existing EC2/SSM
connection, no compiler job, no rootfs image creation, and no host mount or
PID1 unit modifications. The exact fixed
`fresh_native_owner inspect-host-write-surfaces` command ran successfully
as root; preflight and diagnostic both passed.

- Runner kernel `6.17.0-1022-azure`, actual PID1 `systemd`, matching
  PID1/self mount namespace `mnt:[4026531832]`.
- Native audit status:
  `evidence-only-no-aggregate-admission`;
  `additional_shared_host_write_limit_verified: false`.
- Sampled PID1 mount roots: `/var/log/journal` on
  **ext4 /dev/root, device 8:1, inode 84615**;
  `/run/log/journal` on **tmpfs, device 0:28, inode 109**;
  `/etc/cron.d` on **ext4 /dev/root, device 8:1, inode 275**;
  `/var/spool/cron` on **ext4 /dev/root, device 8:1, inode 84624**.
- Twenty-five fixed sample paths were inspected across five classes:
  six PID1/default journal, four SSM, four cron, six installer/metadata,
  five worker temporary/coredump paths. Absent SSM paths on this runner
  mean **not observed here**, NOT that EC2 SSM is bounded or absent.
- No 30/2-GiB images were created on the disposable runner. **This is not
  native storage-quota, worker mount, journald namespace, ENOSPC, timer,
  cancellation or reboot acceptance** and cannot authorize Stage B.

## Next Work-only native acceptance gates (all still blocking)

Independently prove on approved disposable systemd environment: exact
fresh Project/state/registration inode+major:minor backing; root-control
worker PID and all descendants' real mountinfo/cgroups, tmp/run, swap
and coredump negatives; per-worker and journal namespace log backing;
2-GiB and 30-GiB bounded filesystems including metadata and exhaustion;
fixed 21,600-second deadline under PID1 and dual watchdog loss;
exact new cgroup.kill; reboot/no replay and unchanged historical hashes.
Compare protected old shared controller before/after any native test.

Only **after** native source and execution gates pass may a separately
authorized one-time fresh `toolchain.submit(cross-bootstrap)` be considered.
PR #2 stays draft/unmerged. Old compiler #4 is frozen.
