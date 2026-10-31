# Fresh v3 containment pin and aggregate ceiling — 2026-10-26

**Owner:** host-deploy Regular / protected installer; **tracking:** [#5](https://github.com/zog144/host-deploy/issues/5), [draft PR #2](https://github.com/zog144/host-deploy/pull/2).

**Status:** source correction for review. NO host mutation, PID1 activation, original compiler replay or new compiler submission. **Native Stage A and subsequent new cross-bootstrap admission remain NO-GO** pending independently authenticated kernel and journald observations.

## 1. Exact parent-contained controller

Fresh-only `host-deploy-compiler-execution-v3` now pins root-control executable **`97481da26ae1294c9bf474f93f2ed90b4512b9b1`**, and the existing unchanged reviewed box-control `b7934882cfacd2fbfd60c7964713ed3dde7f9460`. The source contract from [root-control #11](https://github.com/zog144/root-control/issues/11#issuecomment-6427828345) makes every new `zogfreshcrossbootstrapoct25-build<job>.slice` a hierarchical child of the source-fixed `zogfreshcrossbootstrapoct25.slice`. It checks PID1 loaded/active parent before start, checks actual service `Slice` and `ControlGroup` on observe, blocks misplaced cleanup, and retains old shared-controller semantics. This pin change does not alter historical v1/v2 revision or any stored compiler request.

## 2. Independent hard overall-time expiry

The fresh budget still carries one immutable 21,600-second UTC/monotonic deadline in the protected ledger, and root-owned cron plus the separate five-second PID1 watchdog keep its fsync-first cancellation record reconciled. Additional `fresh_deadline_timer.py` now creates one **fixed** transient PID1 monotonic `OnActiveUSec` timer, attached to one fixed auxiliary oneshot `hard-stop` service outside the compiler slice, with a **30-second conservative margin**. It is **durably marked attempted before PID1**, armed **before** the protected budget start, and requires PID1 actual `Unit`, `ActiveState` and `NextElapseUSecMonotonic` readback before arming. The fixed oneshot uses the same **original request and cancellation ID** and calls the crash-safe root-owned `watch_once` ledger; a lost cancellation ack is inspected and never reissued. No daemon reload or caller-selected timer/service/command exists. Reboot remains fail-closed: no automatic continuation after transient units disappear.

**Native proof remains required** for actual PID1 timer deadline, fallback when both userspace monitors stop, schedule drift, force-kill of *all* descendants and preservation of shared PID1/old `bad-setting` evidence. Source serialization tests are not a live PID1 timing guarantee.

## 3. One 32-GiB TOTAL disk envelope, not two allowances

The first 32-GiB ext4 build image was **not a total host bound**: fresh host-owned state, metadata, journald and controller/worker logs were external to it. `fresh_aggregate_disk.py` now divides the **same** 34,359,738,368-byte allowance into:

| Kernel-bounded pool | Frozen maximum |
| --- | ---: |
| Dedicated worker build ext4 image | **30 GiB (32,212,254,720 bytes)** |
| Independent owner/journal/log/metadata ext4 image | **2 GiB (2,147,483,648 bytes)** |
| **Combined bound** | **32 GiB (34,359,738,368 bytes)** |

The fixed `prepare-external` entrypoint creates **only** a new fully preallocated 2-GiB ext4 image and mounts its fixed directory before any reviewed plan is staged. `fresh_quota_volume` now allocates **30 GiB**, not 32. Root-owned installer records and budget journals have moved to the accounting mount. After reboot the fixed existing external image is reattached **first**, then the unchanged build image; neither is reinitialized. Native readback uses `findmnt`, `losetup`, exact images, retained allocated blocks and filesystem capacity. The admission gate rejects missing quotas, overflow, unbounded classes, and foreign writable roots. Aggregate capacity is checked before installer activation, at independent watchdog sampling and again before the one-time `arm` transition.

**Important source-level blocker intentionally preserved:** there is not yet verified native containment of every new worker's writable artifacts and **all** journald output in the external accounting mount. `inspect_external_native` explicitly reports `worker-mounts-unverified` and `journald-namespace-unverified`; `aggregate.validate` consequently **refuses activation and arming**. A filesystem with six correctly named directories is not proof that PID1/worker logs physically land there. Operator must independently prove journald namespace+storage path actual kernel backing, and controller owner may need to add worker `LogNamespace` or equivalent fixed logging routing. This is *not* resolved by supplying a `kernel_enforced: true` JSON field.

Additional root-owned bootstrap paths (including cron definition, transient systemd metadata and initial log namespace backing) must be included in the **total** reserved accounting proof, not silently treated as free. A proposal to move every new durable byte into the bounded pool is necessary before native admission.

## Work and controller-owner responsibilities

1. **Root-control reviewer:** independently verify source-fixed parent/child hierarchy under the installed `97481da2…` and supply a reviewed way to force all new worker journald and other external writes into the bounded accounting filesystem. No generic privileged RPC or journal-leak exception.
2. **Protected installer Work:** verify the source candidate, stage a disposable **existing-resource** real systemd/Linux environment, and show actual `StartTransientUnit` timer/sidecar/watchdog reply, expired budget kill, nested cgroups and `/proc/<pid>/cgroup` for all descendants. Verify ext4 30+2 GiB capacity, external writable mounts/journald namespace backing and every extra host-owned byte. Run reboot and simultaneous-monitor-loss negatives with original cancellation ID retained.
3. **Host-deploy Regular:** accept native findings, make any necessary precise source correction, then return independent Stage A acceptance/NO-GO. Historical request `371da99f…`, its original InvocationID, shared controller and old `bad-setting` fragment must be identical before and after. Never submit original compiler or any later phase.

The previous fresh build scope is unchanged: **one new `toolchain.submit(cross-bootstrap)` only after all admission gates**, six hours, overall +32 GiB, no new EC2. Draft PR #2 must remain unmerged until independent review.
