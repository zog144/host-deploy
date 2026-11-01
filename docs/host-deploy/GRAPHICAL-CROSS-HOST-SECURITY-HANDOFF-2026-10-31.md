# Graphical chained predecessor: cross-Host source/security correction

Date: 2026-10-31. Source-only review candidate, stacked on draft PR #7.

## Finished source contracts

- image-build `16b6788db4ee1b8d57ad37171a0918346b948871` has canonical graphics composition: original self-hosted toolchain remains immutable and is the sole compiler base; the exact accepted Fonts/XCB image is a separately validated overlay in disposable package environments and output. The stage-two guard is intact and `image-build` source CI 41254166475 passed. **PR #7 / #8 still freeze earlier producer `efb7110006cafeb170da5c2606dccfeb17b6055b`; do not execute a composed task until the protected consumer source is explicitly repinned and exact-head revalidated, preserving original October monthly pin `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.**
- host-deploy command-center is a non-root DynamicUser with no direct access to compiler Host 0600 `owner-state`. A separately installed 0444 root-owned public-key/Host/installation/boot/epoch/source/policy pin authenticates a signed, bounded, short-lived (<15-minute) read-only compiler-Host catalogue export. Wrong Host, boot, source, epoch, signer, timestamp, digest or task is rejected. Cache/transport is untrusted. Neither a signed transport envelope nor a catalogue grants admission.
- Protected native promotion has a fixed public entrypoint (no caller callbacks) and derives native owner/idle acceptance from the real fresh-native-owner plan, existing budget and worker claim lock. It does not change the first catalogue. Original accepted Fonts source proof is reopened on promotion to X11. Each O_EXCL file is fsynced and then the directory fsynced; missing counterpart after interruption is irrevocable HOLD until explicit independent reconciliation, never silent auto-replay.
- The command-center persists one original admitted request per exact lane/task under a shared lock before any dispatch preparation; the administrative and normal supervisor path share this gate. Direct generic advancement insists the original ledger already exists. Old admitted stage identities, changed frozen catalogue digest, replaced missing file, symlink and partial record are blocked. Non-graphical generic tasks remain separate.

## Installation and native blockers — mandatory NO-GO

The following are **not installed or proven** by PR #8 source CI:

1. **Host signing authority and transport.** The trusted compiler root owner must independently install/authenticate the private Ed25519 key, provision and monotonically revoke the corresponding command-center public pin, bind a genuine owner epoch/boot and current Host/installation/lane, and carry the signed catalogue via an authorized Host channel. `sign_host_export` is a source primitive, *not* a protected installer or transport. A gateway-cached unsigned or stale response is always rejected.
2. **Authenticated original gateway request history on the compiler Host.** The producer acceptance adapter now reads fixed protected `owner-state/authenticated-gateway-history`; root-control/host-deploy native installer must arrange an independently authenticated, non-replaceable copy or narrow verified observation of the exact original admitted gateway request/dispatch digest. No browser/SSM/GitHub JSON is permitted to substitute. At present the native file/peer provenance and separate source installation are **not implemented/accepted**.
3. **Native worker owner lock and boot admission.** Stage A fresh systemd-252 PID1, real worker/cgroup/FD/HugeTLB containment, startup/sidecar and 30+2 GiB six-hour reservations, idle census and reboot hold remain Work gates. Source tests use temporary ephemeral root fixtures only. The signed export has no authority to promote or compile.
4. **Cross-repo source repin.** The composition revision `16b6788d...` must be bound through reviewed PR #7 and PR #8, along with the exact matching installed source/wheel RECORD and original October pin. It may need producer attestations on new image-build records. PR #8 is draft/unmerged, native NO-GO.

## Independent re-review

**root-control Regular**: independently verify the compiler owner trust root, shared lock identity/reboot/worker admission, no caller-supplied attester, root 0600 file/O_EXCL durability, signed cross-Host pin and Native no-replay semantics. **image-build Regular**: recheck producer composition attester and exact source revision. **host-deploy Regular**: correct review findings before returning to Work. Native owner installation and real compiler acceptance are not authorized here.

No EC2/SSM/worker, running Hosts, reserved budgets or production root state were modified by this Regular source-only pass.
