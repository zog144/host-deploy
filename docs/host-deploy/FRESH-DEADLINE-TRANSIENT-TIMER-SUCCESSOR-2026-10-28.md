# Fresh compiler six-hour deadline — systemd 252 transient D-Bus correction

2026-10-28 · host-deploy #5 · draft PR #2

## Reproduced source defect and exact correction

Native PID1 rejected the hard-deadline timer's D-Bus `Unit` argument because
`org.freedesktop.systemd1.Timer.Unit` is a **read-only** property.
The previous `OnActiveUSec` member is also a **readback name**, not a
transient timer setter. They cannot be used as `StartTransientUnit`
property keys.

The corrected fixed `fresh_deadline_timer.message()` supplies ONLY:

- `Description` (string);
- `TimersMonotonic` (D-Bus `a(st)`) with precisely
  `("OnActiveSec", (21600 - 30) * 1000000)`;
- `AccuracyUSec` (unsigned 64-bit microseconds) = `1000000`.

No `Unit` setter is included. The fixed
`zogfreshcrossbootstrapoct25-deadline.timer` automatically activates
`zogfreshcrossbootstrapoct25-deadline.service` by its identical
basename. The auxiliary service remains the fixed root-owned
`fresh_native_owner hard-stop`, outside the compiler slice, with the
existing frozen identity check and no generic D-Bus service submission.

This syntax is verified against **upstream systemd v252**
`src/core/dbus-timer.c`: the writable transient `TimersMonotonic` accepts
`a(st)` and `OnActiveSec`; `AccuracyUSec` is writable. The `Unit`
D-Bus property appears in the read-only vtable. Neither the six-hour
runtime budget nor its thirty-second early margin is changed.

## Source and disposable native acceptance

The required public and protected tests assert that the marshalled
`StartTransientUnit` message contains the **exact three** approved
timer properties and one auxiliary same-basename cancellation service.
The native action is isolated in
`.github/workflows/fresh-deadline-pid1-native.yml` and its fixed script
`tests/native/test_fresh_deadline_transient_pid1.py`.

The native script refuses execution unless ALL conditions hold:
effective UID 0, real systemd PID1, `RUNNER_ENVIRONMENT=github-hosted`,
`GITHUB_ACTIONS=true`, and a safe decimal GitHub run ID. It substitutes
a **unique two-second dummy timer** and a same-basename inert
`/usr/bin/touch` one-shot. It uses the exact production timer property
names/signatures and systemd D-Bus `StartTransientUnit`; then verifies
PID1 readback `Timer.Unit` names the inferred service, the monotonic
timer is active, and the inert service actually fired. It stops both
ephemeral units and removes the one disposable temporary file, even on
error. It cannot start `hard-stop` or the actual six-hour timer.

**Native evidence:** GitHub Actions
[run 40693277474](https://github.com/zog144/host-deploy/actions/runs/40693277474),
job `122833301544`, exact source
`7880740bc10c87e0e817bc98ec69d8f4636779a3`.
All job steps PASS; stdout:
`PASS: native PID1 accepted TimersMonotonic, inferred same-name service,
and executed inert 2-second timer`.

This is real native acceptance of the D-Bus property shape on a disposable
GitHub-hosted Linux PID1. It **does not** mean that systemd 252 was
executed on the actual retained host, that a six-hour timer was observed
for six hours, or that full disk/journal/worker/cgroup/reboot Stage A
acceptance succeeded.

## Disposition and follow-up

A lost or failed historical timer start reply remains uncertain: the
existing durable attempt marker forbids blind retries or replacement
starts. Existing canonical host/boot/plan/request/cancellation binding
remains unchanged. Do NOT reset historical #4 or any attempted new timer
to retry this correction.

Native Stage A remains NO-GO until the exact fresh environment is
independently observed. Next source owner is the queued
host-deploy/root-control Regular worker-witness adoption and safe
cold-start/canary ordering under root-control PR #14 and host-deploy PR #2.
This follow-up does **not** authorize a compiler/canary start on the
retained host. The separate cross-host issuer bridge queue under
root-control #12 remains queued.
