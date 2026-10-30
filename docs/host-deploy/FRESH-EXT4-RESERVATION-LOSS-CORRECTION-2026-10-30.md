# Fresh-v3 external ext4 reservation loss: source correction and native retest

2026-10-30 · host-deploy Regular · host-deploy #5 · root-control #11
Source branch: draft PR #2 (not merged or deployed).

## Native finding and boundary

Reference independent [source report](https://github.com/zog144/know-file/blob/f6bc1a6e95f03ff54f20766b33cc41135e82ea3b/host-deploy/verification/absent-history-reservation-native-2026-10-30/README.md).
Disposable AL2023 systemd 252, XFS root: the newly created
`/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25/external.img`
was 2,147,483,648 B in apparent size, but at the subsequent strict
`prepare_work` readback it held only 2,113,949,696 allocated bytes
(`st_blocks=4128808`), a **33,533,952 B / 32 MiB shortfall**.
`filefrag` showed actual logical holes. The original `prepare_external`
succeeded; there was no 30-GiB work image, controller MainPID, worker,
canary, compiler, HugeTLB activation receipt or watchdog attempt.
The disposable instance and EBS root were deleted after review.

The report does **not** establish the exact kernel operation that punched
the holes. ext4's lazy inode table initialization can run in the background
after first mount and issue zeroout operations on a loop device; the
underlying regular-file-backed loop on XFS can lose allocation. This is a
plausible mechanism, NOT a measured diagnosis. An ext4 mount without
the `discard` option and an untriggered fstrim timer do not rule out
metadata zeroing or all types of hole punching.

## Correction: creation-only reservation, not weaker admission

Both fixed images (external **2 GiB**, compiler work **30 GiB**) now:
1. Create the exact root-only, freshly absent image using O_EXCL and
   `posix_fallocate`; capture its original device + inode;
2. Format once with
   `mkfs.ext4 -F -m 0 -E nodiscard,lazy_itable_init=0,lazy_journal_init=0`.
   These settings explicitly disable the formatter's TRIM and force inode
   table and journal initialization during formatting instead of deferring
   background initialization until/after mounting;
3. **Before attaching a loop device or mounting ext4**, finish the
   originally approved one-time backing reservation with
   `_complete_new_ext4_reservation()`. This refuses nonroot actors,
   a mounted image, changed inode/device, wrong size/ownership/mode,
   symlinked or multiply linked files, and file identity replacement.
   `posix_fallocate` allocates only missing blocks; it does NOT overwrite
   ext4 superblocks, metadata, journal or original bytes. File fsync and
   exact `st_blocks * 512 >= image_bytes` readback are mandatory.
   This is part of **initial creation**, never a later repair API;
4. Attach the same frozen loop image and mount
   `nosuid,nodev,nodiscard`, making ext4 discard explicitly disabled;
5. Force initial ext4 metadata/directory operations to backing storage
   with `sync --file-system <fresh mount>`. Re-check the exact allocation
   through the unchanged `quota.inspect()` or
   `aggregate.inspect_external_pool_native()` after initial setup.
   Before work-image allocation, `prepare_work()` still independently
   demands the complete external 2-GiB backing allocation.

The dedicated reservation contract remains exactly **30 + 2 = 32 GiB**.
No initial acceptance field is synthesized; no
`DEDICATED_UNVERIFIED_WRITERS` class or worker/mount/FD proof is
cleared; no CPU deadline or authority pin is relaxed.

**Critical refusal:** neither `inspect_external_pool_native()`,
`inspect_external_native()`, `quota.inspect()`,
`prepare_work()`, nor either `reattach_*_after_boot()` ever calls
`_complete_new_ext4_reservation()`, `fallocate`, `mkfs` or an
automatic hole-filling repair. Any loss of backing **after mount** or
during protected owner record / journal / reboot activity must still
produce the original strict NO-GO. Keep that specific evidence and
review the kernel/storage cause instead of retrying or replacing.

## Source regression proof

`tests/test_gateway_fresh_reservation.py` exercises:
- a real 64-MiB sparse regular file, original device/inode preservation,
  allocation to the exact size and byte-for-byte preservation of formatted
  metadata sentinel;
- refusal to write if image already mounted, creator unprivileged, wrong
  inode or insecure mode;
- the negative case in which allocation does not happen: NO-GO, no false
  receipt;
- actual unprivileged `mkfs.ext4` on a temporary 32-MiB file with the
  chosen e2fsprogs options and valid on-disk superblock;
- exact ordering: finish only before first `losetup` and mount,
  eager initialization on BOTH pools, no post-mount/reboot repair;
- **incident-shaped test** on the CI host filesystem: reserve an initial
  64-MiB file, punch a 32-MiB hole with util-linux fallocate and confirm
  `quota.inspect()` raises its existing sparse-backend refusal without
  silently filling the hole.

The public and restricted workflows include the new test. Source checks
cannot reproduce the production AL2023 XFS + ext4 loop + systemd 252
background mount/journal behavior: that remains a native gate.

## Independent native acceptance procedure (Work owners)

Use a **new independently approved disposable systemd 252 Host**; old
instance and volume are gone. Preserve the same exact historical absence
baseline and current operator-approved protected data. Attest exact source,
wheels/RECORD, HostIdentity, boot and root-only image path. Start clean:
**never** reuse the prior sparse image, an uncertain operation or
historical compiler request #4.

1. Verify host backing filesystem is actually XFS and inspect initial
   root available bytes; retain approved six-hour/32-GiB boundary.
2. Provision the 2-GiB image **once** using the new owner source. Record
   `stat -c '%s %b %B %d %i' external.img`, `filefrag -v`,
   `findmnt -o SOURCE,FSTYPE,OPTIONS` and the owner-preparation receipt.
   Confirm zero logical holes and all 2 GiB genuinely allocated.
3. After writing each protected baseline, owner plan, admission, and
   staging record, re-read the **same** image device/inode, allocation
   and ext4 mount options. Keep periodic readbacks during the native test
   to catch delayed zeroout. No script may call fallocate in recovery.
4. Execute `prepare_work` using exact reviewed inputs. It must pass the
   strict pre-existing external reservation gate, create a separately
   proven 30-GiB **fully backed** work image, and preserve the same
   ext4 metadata and backing limits. Measure both images under
   subsequent project-state and journal operations.
5. Complete independent journal persistent/volatile bind activation,
   sidecar and HugeTLB prerequisites only after each earlier gate passes
   and any separately required shared PID1/controller authority is
   present. Record ext4 backing before and after actual journal writes.
6. Exercise mount/FD/hugetlb/cgroup worker containment, one-shot canary
   claim, deadline, quota/ENOSPC, cancellation, cleanup and reboot **only**
   after the preceding native prerequisites pass. On reboot do not
   reallocate either image. Verify full backing again before recovery,
   and reject any changed Host/boot policy/authority.
7. On ANY shortfall, preserve the fail-closed exact error, log filesystem
   timing/metadata and stop. Do not retry by running the one-time
   completion helper on a mounted/previous image.

**State:** source candidate only; no new native acceptance or production
compiler admission. Both issues and draft PRs remain OPEN/DRAFT.
