# Host-deploy #5 — strict total host write accounting: engineering disposition

**Date:** 2026-10-27. **Scope:** one fresh cross-bootstrap on the retained shared host.
**Pull request:** draft #2, `regular/toolchain-gateway-20261019`.
**Decision:** NOT ADMISSIBLE under the literal existing six-hour / +32-GiB total additional-host-write contract. No compiler submission permitted.

## Verified architecture boundary

Existing source already provisions two fully allocated loop-backed ext4 image
files on the existing shared host: 30 GiB for build/import/workspace state and
2 GiB for the host-owned state and namespaced journal. Kernel mount/inode
inspection and pre-activation guards prove narrower statements about the two
isolated filesystems. They do not provide a quota on the shared host root
filesystem or its ordinary journal metadata.

The accepted fresh-only root-control successor is
`cacacbee66c0401e04dfe702d6b90e87215280d0`; it corrected worker
`PrivateTmp=False`, bounded `/tmp`, `/var/tmp`, `/run` mounts and the
`MemorySwapMax=0` source policy. Host-deploy's exact fresh-v3 source pin is
updated in this branch. Work must still prove actual PID1 service, worker PID
mounts and all descendant cgroups; source tests are not native acceptance.

### Three quantities that must not be conflated

1. **Reserved image-file size:** exactly 30 + 2 GiB = 32 GiB. The two images
   cap their own ext4 file/data/metadata capacity, and `posix_fallocate`
   reserves that amount on the host filesystem.
2. **Additional shared-host *allocated* bytes:** includes ordinary host root
   filesystem metadata from creating/fallocate/mounting images and directories;
   root-owned cron schedule/installer state; default journald and PID1;
   SSM transport/agent; and unrelated or correlated changes to existing
   shared files. These are not charged against either loop image.
3. **Cumulative physical writes / write amplification:** overwriting even
   one bounded file repeatedly can generate more than 32 GiB of actual write
   I/O. A disk-space quota is not an I/O-byte cap, and blkio/cgroup I/O
   counters are not persistent capacity quotas.

The current user requirement explicitly covers the second category. Claiming
that #1 alone establishes #2 or #3 would be misleading.

## Why the retained shared-host design cannot meet the literal guarantee

Let the additional-host allocation obligation be `T = W + E + H`, where
`W <= 30 GiB` and `E <= 2 GiB` are the two hard-limited images.
`H` consists of additional bytes in the original host filesystem caused by
PID1/default journald, SSM, crond, installer/kernel mount/fs metadata and
other attributable writes. No current kernel quota limits `H`.
Since the images may legally reach their full 32 GiB, ANY positive `H`
violates `T <= 32 GiB`.

A 30+1+1 GiB split may reserve nominal headroom but cannot enforce `H <=
1 GiB`. A wall-clock sampler, disk free-space monitor, cgroup I/O write
counter, journal rate limit, or hash of shared directories cannot retroactively
undo the excess write. There is also no reliable source identity that tags
one shared PID1/default-journal allocation as belonging uniquely to the new
compiler while preserving existing unrelated host activity.

A global rootfs quota or switching host-wide journal/SSM/crond storage into
new quota pools may affect historical workloads. The current authorization
specifically freezes the existing shared host/PID1/default services,
forbids additional EC2 resources and disallows tampering with historical
compiler #4. Thus such a change is **not** a permissible silent source fix.

### Admissible engineering alternatives requiring a NEW decision

**A — preserve literal strict TOTAL budget.**
Provide a separately approved native execution/isolation environment with
an actual **kernel-enforced ceiling on ALL relevant host-side persistent
allocations**, including its own PID1, default journal, transport, boot
and metadata paths; independently prove the host/outer-launch side effects
cannot escape the same ceiling. An isolated guest filesystem alone is NOT
sufficient if its outer shared host still emits unaccounted writes. Use a
fully isolated disk/accounting boundary that includes the launch controller,
or define an explicitly measured and kernel-bounded outer-host allowance.
This may require a different physical/virtual deployment topology and
separate authorization.

**B — retain current shared EC2 host and two-image topology.**
Obtain explicit approval to change **what is bounded** to `32 GiB maximum
additional *dedicated storage reservation* for the fresh compiler`, with
ordinary host management/default-journal/SSM metadata excluded from that
storage budget. Keep six-hour and exact fresh-cgroup cancellation guarantees.
Such approval does not retroactively satisfy the original **total host
allocation** requirement; the source/runtime would need a renamed contract,
revised acceptance tests and new explicit authorization. Do not infer it from
the original six-hour/32-GiB authorization.

**C — preserve both the original strict budget and current shared topology.**
Remain NO-GO and run only read-only/disposable acceptance diagnostics; no
cross-bootstrap. This is the current safe default.

## New read-only native accounting witness

`fresh_host_write_audit.inspect()` and the fixed protected
`python -B -m zog.host_deploy.gateway.fresh_native_owner inspect-host-write-surfaces`
operation record representative host-write paths from **PID1 mountinfo**, with
real inode/dev/mountpoint/fstype/source and explicit missing/symlink statuses.
The tool has NO path arguments, NO quota-mutating action and NO mechanism to
produce a GO receipt. Each fixed sample class remains unverified even if a
sample exists on a familiar filesystem. Missing paths are **not** proof that
their writer cannot create files later.

Work can run this on a reviewed disposable systemd machine without touching
old request #4, to publish a native evidence record. A new attempt to bind
shared host paths or zero an accounting class still needs independent owner
review and explicit authorization.

## Six-hour independent deadline acceptance

The immutable overall deadline continues to be armed via fixed PID1 monotonic
`OnActiveUSec=(21600-30)*1e6` before the durable request ledger enters
`active`. Its separately named root-owned oneshot is outside the fresh
slice; when journald/external state is full, it uses the frozen marker and
exact fresh `cgroup.kill` as the limited fallback. The independent 5-second
PID1 watchdog plus protected cron monitor fail closed; reboot does not
resubmit. Source tests verify message shape and transitions, not actual
PID1 delivery/time under simultaneous monitor failures. Native disposition
is required before any 6-hour GO claim.

## Source constraints preserved

- Draft PR #2 remains open/unmerged; no old issue #4 replay/cleanup.
- No change to shared PID1 configuration, default journald, SSM, cron or
  historical root-control service; only a new read-only diagnostic added.
- No new EC2, disk/image provisioning, reboot, SSM action, compilation,
  protected grant elevation, or user-authorization reinterpretation.
- `aggregate.validate` still rejects `UNVERIFIED_WRITERS`; no
  default-journal/SSM/cron/host-metadata writer class is silently certified.

**Issue #5 should stay open** as a scope/architecture decision requiring
approval plus native acceptance, not be labeled fully solved merely
because every source CI workflow passes.
