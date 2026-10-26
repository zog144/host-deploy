# Fresh cross-bootstrap: concrete privileged host installation owner

**Date:** 2026-10-26  
**Owner:** host-deploy Regular / protected host-install + controller reviewer  
**Tracking:** [host-deploy #5](https://github.com/zog144/host-deploy/issues/5) · [draft PR #2](https://github.com/zog144/host-deploy/pull/2)  
**Disposition:** Executable privileged owner source, **NOT installed or natively accepted on retained host**. Source review does not authorize new live controller/SSM/compilation.

## What is now implemented (not interfaces alone)

`fresh_native_owner.py` is a real, root-only Linux systemd owner with four tightly limited CLI verbs:

- `install`: reads **only** the reviewed, root-owned `0600` `reviewed-plan.json` and `reviewed-admission.json` under `/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25`; rejects unexpected fields, the original historical request `371da99f23764180aad37d8e4e83595b`, source digest or boot drift, missing NSS identities, wrong primary GIDs, mutable executable trees, changed shared-controller baseline and incomplete seed/capability receipt binding. Registers a root-owned `/etc/cron.d/zog-fresh-cross-bootstrap-oct25` entry, preallocates the dedicated **32 GiB** quota filesystem, restricts its mount to the independent build UID/GID, then invokes the fixed protected `StartTransientUnit` sidecar installer. It durably records `prepared` and `attempted` **before** making the PID1 request, and persists activation readback afterward. No shared `daemon-reload`, old unit reset or arbitrarily supplied command.
- `arm`: **separately and exactly once** reads the protected admission/request ID, current boot, original newly installed sidecar InvocationID/socket, scheduler, quota and distinct systemd slice. Freezes the exact request/host/Project/UTC+monotonic deadline/disk baseline and immutable cancellation ID before any remote compiler execution. It is never called by the GitHub request.
- `watch`: invoked as root **once per minute** by the existing active `crond`, independent of a running ChatGPT Work session or image-build compiler. Reads the real ext4 mount `statvfs`, current Linux boot and monotonic/UTC time, real crond and sidecar state. Calls the fsync-protected one-attempt `fresh_budget_guard.watch_once`. Its cancellation backend checks only the fixed `zogfreshcrossbootstrapoct25.slice` cgroup and writes `cgroup.kill` through the kernel; it never targets an old PID, generic systemd unit, shared control socket or arbitrary Project. A lost cancel acknowledgment is recovered through the same read-only kernel `cgroup.events` inspection and original cancellation identity, never a second kill call.
- `recover`: invoked by the same root-owned cron policy at `@reboot`. Validates and reattaches **only the existing accepted quota image**, writes a new durable boot-ID/recovery receipt, and reconciles the prior original request with no replacement ID or automatic compiler replay. A changed boot ID forces an active budget into protected uncertainty and exact fresh-only stop/recovery. **The transient controller is deliberately not silently reactivated after a new boot;** a fresh independently authenticated boot/controller activation and baseline is needed. Reboot is fail-closed, not an automatic continuation.

`fresh_quota_volume.py` provides a real **kernel-enforced** quota boundary by allocating one new 34,359,738,368-byte root-owned ext4 loop filesystem with `posix_fallocate`, fixed `mkfs.ext4` target (the newly exclusive image), fixed `losetup` and `mount`. No existing partition, rootfs, EBS volume, historic Project or mutable seed is formatted. The active filesystem is independently checked by `findmnt`, `losetup`, backing-file `st_blocks`, quota size and `statvfs`; mount is reattached on reboot without reformatting. Writes are kernel-limited by filesystem capacity even if a periodic accounting process is delayed. Native admission must prove *every* authorized mutable compiler output/temporary path lies under that mount; this code cannot force an unreviewed image-build worker's mount namespace into compliance.

`fresh_sidecar_install.py` and `fresh_sidecar_dbus.py` now bind `Slice=zogfreshcrossbootstrapoct25.slice` to the exact build-only transient daemon, with actual D-Bus wire-tested `StartTransientUnit`. This is a **new host-management service** only, with no shared PID1 reload. The separately reviewed `root-control@19d423cdf16531474de5680117867e12b5bb0620` role remains strictly build-only for the one Project.

## Immutable inputs and native responsibilities

The protected installer owner expects these prepared **local** materials, produced by host-install/host-deploy Work after independent verification, never fetched from an Issue comment as authority:

| Host-owned input | Required evidence |
| --- | --- |
| `reviewed-plan.json` | exact `sidecar.review_plan` output; approved controller/build UID **and primary GID**; absolute source/interpreter/Project; immutable source checksums; root-control source `19d423cd…`; exact boot ID, shared controller baseline |
| `reviewed-admission.json` | new request ID **different from historical**; same plan/host; verified immutable seed identity and archive manifest digest; typed capability digest; reserved post-workload disk capacity; exactly one writable root under the fixed quota mount; fixed fresh slice |
| `legacy-baseline.json` | independently captured existing shared controller `systemctl show` identity and historical bad-setting checkpoint, compared before and after. Work separately attests full historical file hashes and fragment; this source does not establish those facts itself |
| Root-owned source & NSS | source and companion trees protected recursively; approved controller `24301:24301` and worker `24302:24302` **proposed, never allocated by this code**; verified no collision and distinct controller/worker home/Project |
| Running native scheduler | `crond.service` must already exist and run; installer adds only a fixed new cron.d file, without starting/restarting crond or calling shared PID1 `daemon-reload` |

The fixed CLI commands on a properly staged native host use the reviewed, protected Python module (not an arbitrary root shell from SSM):
```bash
python3 -B -m zog.host_deploy.gateway.fresh_native_owner install
python3 -B -m zog.host_deploy.gateway.fresh_native_owner arm
# The root-owned cron.d schedule runs "watch" each minute and "recover" at reboot.
```
**These commands are implementation documentation, not an instruction to execute them on the retained host without independent Stage A admission.** The host-owned installation must preserve original request #4, its source/seed/InvocationID and bad-setting evidence. No compiler submit, automatic later phase, new EC2, or unreviewed reset/cleanup is permitted.

## Acceptance and explicit NO-GO conditions

The sources now include real syscalls, protected on-disk state transitions and scheduler creation. Offline regressions test the exact cron policy, boot receipt, root scope, frozen request exclusion, native install ordering, bounded arming, kernel cgroup cancellation (using disposable simulated cgroup files) and unsafe external writable-root denial. **They are not live filesystem or PID1 acceptance.**

Native Work must test on an isolated disposable host before the retained host: exact installed source/RECORD, root-owned baseline and NSS; safe 32 GiB allocation only after explicit capacity review; kernel mount enforcement and exhaustion with all worker writable roots under the new mount; proper `StartTransientUnit` and `Slice` support; sidecar socket SO_PEERCRED wrong-UID/group/Project negatives; compiler worker cgroup containment in the fresh slice; supervised `crond` stop/restart and reboot/reattach uncertainty; 6-hour deadline and 32-GiB exceed/cancellation with crash-injection. **The source currently fails closed on reboot rather than automatically recreating an accepted controller; normal post-reboot continuation needs a distinct reviewed reactivation policy.** No live submission while this gate is missing.

Keep [PR #2](https://github.com/zog144/host-deploy/pull/2) draft. Source success alone is not native Stage A acceptance and does not authorize the first `toolchain.submit` or reuse the original compiler.
