# Fresh cross-bootstrap: enforceable 32-GiB storage boundary and native blockers

**2026-10-27** · host-deploy Regular · [issue #5](https://github.com/zog144/host-deploy/issues/5) · [draft PR #2](https://github.com/zog144/host-deploy/pull/2)

**Disposition:** source improvements in review. **Stage A final admission and Stage B cross-bootstrap remain NO-GO.** No retained EC2/PID1/SSM/system, historical #4 operation, or new compiler task changed by this source work.

## Immutable owner limits

The existing protected execution v3 has one six-hour limit (21,600 seconds) enforced through a fixed PID1 monotonic timer plus cron/independent watchdog and fresh-cgroup-only cancellation. New kernel-backed capacity is strictly **30 GiB build image + 2 GiB external owner/journald image = 32 GiB total**; each is fully allocated with `nodiscard` and examined through kernel loop/mount readbacks. No separate 32-GiB allowance per image, reboot, job or controller.

## Corrected storage/installer ordering

An independent installer must proceed through these distinguishable stages. Each is a protected local host-owned operation, **not** a GitHub/SSM-supplied root shell:

1. Review existing-host old-lane reservation and authorized total 32-GiB capacity; create pre-approved, collision-free controller/build UIDs and exact immutable source, old baseline and admission records. Final compiler admission is still withheld.
2. `prepare-external`: one-shot preallocate, mkfs with nodiscard and attach the fixed 2-GiB external image. The returned **pool** receipt is not journald/admission attestation.
3. Stage the exact protected plan and root-owned preauthorization/admission identity under the external pool. `prepare-work`: verifies source/NSS/old baseline, reduces originally approved remaining space by the already-allocated 2-GiB image, creates the one-time 30-GiB worker image and binds fixed `/home/zog-cross-owner/fresh-cross-bootstrap-oct25/work/state` into `/home/zog-cross-owner/fresh-cross-bootstrap-oct25/state`. The first filesystem write under Project/state must **follow** this attested mount. It saves a durable mount attempt *before* `mount --bind` and rejects foreign descendant mounts, wrong loop source, same-device-but-different-inode and unprotected state roots. An interrupted mount cannot be blindly retried.
4. Only after Project/state has the correct mount, import the independently verified immutable Amazon Linux seed, build/source/output attempts and manifests into the new bounded Project. **Never stage them in an unmounted Project/state.**
5. `prepare-journal`: install BOTH separately verified namespace-backed persistent and volatile journal binds onto the 2-GiB volume **before** any fresh namespaced journald/socket activation; ensure no existing journal is shadowed.
6. `install`: perform genuine kernel readback of both images, Project/state and journal, then apply **preactivation-only** validation. This permits the fixed, independently reviewed root-only watchdog and build-only sidecar to start in order to collect live PID1/registration evidence. The returned preactivation receipt explicitly retains all unresolved writer classes and is **never** sufficient for `arm` or a compiler job.
7. Independently inspect the actual sidecar PID, socket credentials, `BindPaths` to external/build-resources, namespace journald file backing, worker source/producer policy and Project mounts. Only once all additional write classes have actual enforceable accounting (including shared-host side effects), provide a reviewed native inspector revision capable of returning **no** unaccounted writable roots. `arm` and every `toolchain_supervisor.advance` continue to demand strict `aggregate.validate` and active deadline/watchdog/cgroup guards.

On reboot, only the **same** quota images can be reattached; Project/state's host bind and journal binds do not automatically survive. The existing request must stay blocked/uncertain without a separately reviewed recovery and live proof. No automatic compilation replay, new source pins, or historic job cleanup.

## Cross-owner unresolved host writes: NOT hard-capped by these images

**Root-control source** `c03815b18efc96797ba868f2412f073f758a6cad` currently uses `PrivateTmp=true` for fresh workers in `src/zog/root_control/build.py`. systemd service-private host `/tmp`/ `/var/tmp` can be writable **outside** the 30-GiB image even when RootDirectory, Project/state and nested worker slice are correct. Root-control Regular must supply a reviewed fresh-only policy ensuring ALL temporary directories either resolve into the quota image or into separately bounded kernel-backed storage, with systemd 252 native mountinfo and ENOSPC proof. The compiler's root/source/output workspaces, temporary files, caches, run-time writable paths, coredumps and per-worker systemd side effects must be enumerated and tested, not inferred from a slice label.

**Host/shared-system source:** PID1's *own* service/start/stop notices, cron-daemon activity, default journal, installed `/etc/cron.d` entry, external image/mountpoint directory metadata, SSM/system transport logs and any native bootstrap writes are not automatically inside either image. `LogNamespace` on fresh units does **not** relocate PID1/default-journal output. The 30+2-GiB images consume the full allowance: there is **zero hard-capped external margin** for these other bytes. Ordinary `du`, periodic FreeSpace, JSON assertions, or a pre-provisioned free-space estimate are not a hard cap. The two-image scheme is therefore **not** a sufficient proof of the absolute 32-GiB *additional host writes* condition on a shared host.

**Required policy decision:** provide a native kernel-backed envelope for every attributable additional host-write class (without altering/fencing the shared historical controller), or change the operational environment/budget design under new explicit review and authorization. Reducing the image sizes to leave headroom still does not kernel-cap shared/default writes. A new EBS resource, global default-journal relocation, shared daemon changes or weakened allowance is **not authorized by #5** and cannot be assumed.

## Exact acceptance tests

Use independently reviewed disposable Linux/systemd 252 tests before any retained-host installation: verify initial quota reservation/Project-state-before-seed ordering; crash between bind intent and mount; foreign mount, symlink and wrong loop negatives; namespaced persistent/volatile journald file inodes before start, heavy stream and ENOSPC/restart/fallback; actual root-control registration writes; all worker PID/cgroup/mountinfo/fd paths including private `/tmp`; both watchdogs lost, timer firing under disk-full and exact cgroup.kill; reboot (no unintended auto-resume) and old/shared hash/InvocationID unchanged. Record absolute destination/major:minor/inode/mount namespace and actual bytes. **Do not claim native success from source CI.**

Draft PR #2 remains unmerged; Stage B `toolchain.submit(cross-bootstrap)` remains prohibited until every kernel and controller gate passes. Never replay old #4.

## 2026-10-27 source follow-up: imported roots are build data, not owner logs

A further cross-source inspection of `root-control@c03815b1` `BuildBackend.register()` found that the protected `/var/lib/zog/build-resources` directory contains `registration.json`, jobs **and an actual copied immutable build root filesystem** (`shutil.copytree(prepared_root, path / 'root')`). Placing that entire directory in the 2-GiB external log/owner-state pool risks ENOSPC during legitimate rootfs preparation. Fresh-only `fresh_sidecar_install.REGISTRATION_SOURCE` is now the 30-GiB image's protected `controller-build-resources` directory. The exact new transient root-control unit alone binds this into its `/var/lib/zog/build-resources`; the historical shared directory remains untouched. The live sidecar `MainPID` device/inode check still applies and now checks **30-GiB build** backing.

The quota image's mount root must remain **root-owned, 0755 and non-writable by both fresh nonroot UIDs**. Project/state (controller-owned 0700) and the copied source/output workspaces have their own narrowly assigned write permissions, while controller-build-resources stays root-owned 0700. Making the 30-GiB image root owned by the build user would allow that user to rename the root-owned registration import directory merely by controlling its parent. The native Work acceptance must test a fresh nonroot worker's attempt to rename/replace that directory fails, and that image-build source/output/seed preparations still work through the explicitly selected state bind.


## 2026-10-27 reprise: budget-directory conflict and exact shared-host writer ledger

**Reproduced preparation boundary.** `prepare-external` already creates
`external/owner-state/budget` as root-owned private directory. It must not be
created a second time by `install`, `prepare-work`, or `arm`. All three
operations now use an explicit read-only `_budget_directory_prepared()` guard:
exact directory under owner-state, root ownership/mode, actual external
filesystem mount, same filesystem device, and **empty before first arming**.
A missing, redirected, pre-populated, substituted, or interrupted directory
fails closed without deleting or replacing anything. `prepare-work` performs
this check **before** allocating the 30-GiB work image. `install` validates the
work volume, Project state bind, and real bounded journald source before
installing the cron file. Tests exercise an actual prepared temporary
directory and absence, non-empty, missing-mount, and foreign-device negatives.

**Explicit unresolved write ledger in source**
(`fresh_aggregate_disk.UNVERIFIED_WRITERS`):

| Writer class | Expected backing / risk | Status |
| --- | --- | --- |
| Worker mounts, outputs and workspaces | 30-GiB ext4 quota and kernel namespace | Root-control + native witness required |
| Worker private /tmp, /var/tmp and coredumps | PID1 PrivateTmp/host filesystem may escape the image | NO-GO |
| Root-control registration and imported rootfs | Fixed sidecar private bind into 30-GiB pool | Native PID/inode proof required |
| Namespaced journald | Fixed persistent + volatile binds in 2-GiB pool | Native 252/ENOSPC/reboot proof required |
| **PID1 and default journald** | Shared rootfs/log filesystem, independent of LogNamespace | **Unbounded, NO-GO** |
| **SSM transport and agent records** | Shared host logs/state outside both loop images | **Unbounded, NO-GO** |
| **Cron daemon and schedule** | External cron program output capped; daemon events and /etc/cron.d are not | **Unbounded, NO-GO** |
| **Installer and filesystem metadata** | Host-side image names, loop/mountpoint metadata, bootstrap files, journal side effects | **Unbounded, NO-GO** |
| **Other attributable host writes** | Background shared services, kernel crash/core and unspecified writers | **Unbounded until classified, NO-GO** |

The fixed 30 + 2 GiB kernel image **capacity** covers image contents and
their ext4 metadata, but not every host-root filesystem write triggered by
allocating or using the images. A periodic sampling process, copied JSON
receipt or heuristic baseline delta is not a kernel-enforced *total* bound.
At the present exact cap, no independently enforceable byte budget exists
for host PID1/default journal/SSM/crond/metadata outside the images.

**Engineering disposition:** The current retained *shared host* design cannot
honestly certify an absolute 32-GiB **additional host-write** ceiling solely
from these two images. Completing that specific proof needs a separately
authorized/reviewed kernel-enforced host-wide accounting/isolation boundary
that covers shared writers, or an explicit change to the allowed accounting
scope or host architecture. A small estimated reserve within 32 GiB is not
sufficient without kernel enforcement over the residual host writes.
This decision is not authority to change default host journald, SSM,
partitioning, allocate a new EC2 resource, or touch the historical Project.

**Six-hour enforcement:** The fixed monotonic PID1 timer remains independent
of the two user-space monitors and targets only the accepted fresh slice,
with a 30-second safety margin. The exact real PID1 firing, reboot,
combined watchdog-loss, ENOSPC fallback and all-descendants termination
must still pass disposable native acceptance. No source-only assertion
counts as that acceptance.

**Final admission remains NO-GO:** `validate_pre_activation` returns only
`preactivation-only` with the full explicit unresolved writer list.
`aggregate.validate` (used by `arm` and native watchdog) rejects any
nonempty list. No fake empty list, flag override or source-only test permits
the new cross-bootstrap until those source+native blockers are resolved.
