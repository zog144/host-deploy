# Explicit absent-history support for disposable compiler acceptance

Status: source-only review; native systemd 252 acceptance, installed-byte attestation, HueTLB activation and compiler admission remain NO-GO.

Owners: host-deploy Regular (protected native owner) with root-control Regular for consumer review; host-deploy Work + root-control Work perform disposable acceptance. Tracking [host-deploy #5](https://github.com/zog144/host-deploy/issues/5) and [root-control #11](https://github.com/zog144/root-control/issues/11).

## Why this exists

The original retained compiler preservation baseline is deliberately strict: exactly one previously observed historical compiler unit has `LoadState=bad-setting`, and the shared controller's exact current PID1 observation is frozen. A freshly provisioned, disposable systemd 252 acceptance machine does not have that historical compiler, so the native preflight observed `LoadState=not-found`. Replacing `bad-setting` with `not-found` in the **old** format would weaken retained-host preservation, and no Work test may fabricate an old historical unit. Instead, `_legacy()` now supports two **noninterchangeable, exact** formats. No automatic fallback or detection selects a different one.

## Original retained-host format — unchanged

Continue using the five exact keys `shared_unit`, `root_control_show`, `historical_unit`, `historical_show`, `historical_bad_setting_sha256` in `owner-state/legacy-baseline.json`. The historical observation must be exactly `bad-setting`, its canonical JSON+`\n` SHA-256 must match the original, and the actual root-control and historical PID1 systemctl observations must both match. Any absence or changed PID1 state is a hard failure. No path in the new mode can downgrade an already selected retained baseline.

## New disposable-only baseline

The trusted native owner must independently establish the machine is a **new disposable acceptance host with no retained compiler history**; do not infer this from the absence of one unit alone. This decision is made in the protected installer/approval review, before any state is prepared or systemd activation begins.

A root:root 0600 immutable/frozen `owner-state/legacy-baseline.json` may use these exact keys (all others rejected):

```json
{
  "schema": "host-deploy-fresh-disposable-absent-history-v1",
  "mode": "absent-history",
  "host_id": "<independently authenticated disposable Host ID>",
  "boot_id": "<actual /proc/sys/kernel/random/boot_id>",
  "shared_unit": "zog-root-control.service",
  "root_control_show": {"...": "exact full systemctl show observation"},
  "historical_unit": "zog-image-build-original@build.service",
  "historical_show": {
    "LoadState": "not-found",
    "ActiveState": "inactive",
    "MainPID": "0",
    "InvocationID": "",
    "ControlGroup": "",
    "FragmentPath": ""
  },
  "historical_not_found_sha256": "sha256:<SHA-256 of canonical historical_show JSON followed by newline>"
}
```

The actual `historical_show` object must use all the fields returned by the native, read-only `systemctl show <reviewed historical unit> --property=LoadState,ActiveState,MainPID,InvocationID,ControlGroup,Environment,FragmentPath,Unit,NextElapseUSecMonotonic,LogNamespace`. The example is a **shape illustration only**, not permission to hardcode or invent the output. Match the observed values exactly. The selected historical unit is an independently reviewed fixed unit ID, never a caller supplied alternate at runtime.

The baseline SHA-256 is `sha256: + SHA256(json.dumps(baseline, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n')`; the exact resulting digest must equal `reviewed-plan.json -> installed.legacy_baseline_sha256`. This continues to bind *all* installer, arm, watchdog, quota, HugeTLB activation, and cleanup calls through their existing `NativeOwner.validate_old_baseline()` hooks.

## Separate protected operator approval

A second **independently provisioned** root:root 0600 file at `owner-state/disposable-absent-history-approval.json` is required. It must have *exactly*:

```json
{
  "schema": "host-deploy-fresh-disposable-absent-history-approval-v1",
  "status": "operator-approved",
  "scope": "one-fresh-systemd252-disposable-native-acceptance",
  "allow_absent_history": true,
  "host_id": "<same independently proved disposable Host ID>",
  "boot_id": "<same current boot ID>",
  "plan_sha256": "<exact reviewed sidecar plan digest>",
  "legacy_baseline_sha256": "<SHA-256 of approved baseline>",
  "shared_unit": "<exact shared controller unit>",
  "historical_unit": "<exact reviewed absent historical unit>"
}
```

The native owner validates the second approval **before** consulting PID1. It rejects missing/extra keys, changes to the Host, boot ID, source plan, historical unit, local baseline digest or any non-`operator-approved` status. Current `shared_unit` and historical `systemctl show` are then compared to the pinned snapshots. Reboots cannot reuse the previous approval, even if PID1 happens to produce the same `not-found` text.

This approval file must be independently created only after Work checks the actual cloud/Host identity, the absence of retained builds, receipts, deployed artifacts or historical compiler state, and the disposable nature of the test machine. The source cannot prove a cloud instance's disposal status from `LoadState=not-found` alone. The record does not authorize a compiler job, canary, new cross-bootstrap, cgroup root change or reboot on its own.

## Native successor sequence

1. In **read-only preflight**, capture the exact Host ID, source module/wheel-RECORD pins, boot ID, PID1 systemd 252, shared-controller `systemctl show`, historical unit `not-found`, and the absence of retained build/process/job/history and state. Stop if the host is not independently verified disposable.
2. Operator reviews and installs the exact new baseline and **separately approved** absent-history record into the protected new 2-GiB owner store. Preserve original upstream/retained history; never create a `bad-setting` fixture or reuse its request ID.
3. Freeze the sidecar plan and hashes after the two records exist. Run the existing supported preflight and protected installer; `validate_old_baseline()` must hash-readback the same baseline and real PID1 shared/historical observations at each call. Do not waive prior source/ownership/STATE/record bindings.
4. Separately (already authorized only on the disposable machine), complete native HugeTLB root activation with its **own independent** approval and boot-bound receipt; then verify real cgroup2 controller files, preserved shared PID1 state, slice inode/lifetime, limit zeroing, and reboot invalidation.
5. After both prerequisite gates, continue Work's mount/FD, hugepage-allocation negative, 30+2-GiB quotas, six-hour deadline, cancellation, nested cleanup and reboot tests. Any unknown provenance or missing observation means NO-GO and a narrow Regular defect report.

The historical compiler #4 must never be replayed, the retained Host remains unchanged, and no native acceptance or compiler submission is implied by passing source CI.
