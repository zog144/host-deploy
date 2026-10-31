# First protected graphical task catalogue — fonts-only source and native installation contract

2026-10-31. Owners: host-deploy Regular + image-build Regular (definition),
host-deploy Work + root-control Work (protected installation).
Source branch: `regular/first-graphics-catalogue-20261031`, stacked
on host-deploy draft PR #2.

## Exact verified source inputs

- **Image-build source:** `b0f53dbdec0e88b9b37feb5317398db3d20507dd`,
  verified as immutable GitHub source. This is a *source revision*, never
  a self-hosted rootfs/generation ID.
- **October pin:** `project/pins/2026-10-01/commit-pin.py`, original
  271,790-byte file at that exact image-build revision. SHA-256
  `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.
  The original monthly pin is not a synthesized recipe snapshot.
- **First finite task:** `graphics-fonts-image-v1`, schema-2
  `task_catalogue`, fixed sorted entries `fontconfig-final`,
  `freetype-final`, `libpng-final`; fixed image-generation target
  order `libpng-final`, `freetype-final`, `fontconfig-final`.
  No other task is installed in the first catalogue. XCB/X11/XCB-support
  must wait for accepted predecessor output generations and separate
  root-protected repinning.
- **Dedicated compiler reservation:** EXACTLY 30 GiB fully backed build
  image + 2 GiB fully backed external accounting image = 32 GiB.
  Independent six-hour (21,600-second) deadline. Normal shared-host
  management overhead remains outside this dedicated reservation;
  neither allowance enlarges existing bounded compiler execution.
- **Native storage:** the original 30+2 GiB images are inspected by
  `quota.inspect()` and `aggregate.inspect_external_pool_native()`.
  Their usable ext4 block capacity may be slightly less than 30+2
  GiB, but the images themselves must have exactly the fully backed
  reserved lengths. No reallocation/repair on observation or reboot.

## Deliberately unresolved authority values — NOT placeholders to install

**The native accepted self-hosted base generation ID (64 lowercase hex),
its actual canonical accepted generation receipt/digest, the approved
managed schema-4 lane ID, exact provenance Host owner, Project root and
installation identity remain to be independently established by Work.**

Do **NOT** substitute `b0f53dbd...`, the October pin hash, an old image
generation, an arbitrary 64-hex string, or a source-CI fixture for the
real accepted generation. Source code and passing tests do not establish
native acceptance.

The operator-reviewed first catalogue approval must be independently
installed as an exact root-only mode-0600 file:
`<protected 2-GiB external mount>/owner-state/graphics-foundation-approval-v1.json`.
It freezes:
`host_id`, `installation_id`, `lane`, `lane_owner`,
`project_root`, `accepted_base_generation_id`,
`accepted_base_receipt_sha256`, exact `source_revision`,
`monthly_pin_identity`, `task_allowlist=["graphics-fonts-image-v1"]`,
`work_bytes=32212254720`, `external_bytes=2147483648`,
`dedicated_storage_bytes=34359738368`,
`execution_limit_seconds=21600` and the exact approval schema.

## How to perform the protected native installation, separately

The owner implementation `zog.host_deploy.gateway.graphics_catalogue_owner`
provides `prepare(...)` (pure source validation) and
`install_native(...)` (one-shot root-only protected installation).
No SSM endpoint, browser action, root shell fallback, cron, restart,
or automatic compiler submission invokes this module.

**host-deploy Work + root-control Work native preflight:**

1. Independently recover/verify the accepted self-hosted base from the
   actual image-build generation catalogue and canonical provenance root:
   `kind=toolchain`, accepted output/generation ID, accepted report SHA,
   original source revision and verified supply-chain identity. Refuse if
   any acceptance metadata is absent, stale, rolled back or a toolchain
   source commit is offered as the generation ID.
2. Attest the real HostIdentity and installation, current boot, exact
   root-control/host-deploy installed source bytes and wheel RECORD,
   independently installed reviewed managed schema-4 lane record
   (`state=active`), `provenance_host_id`, immutable image-build source
   and original October pin bytes. The lane and operator root approval
   must name the SAME Host, Project, lane owner and generation receipt.
3. Verify 30-GiB/2-GiB kernel-backed loops, mount/Project binding,
   available dedicated reservation, root-only owner-state and no
   historical or competing writer. The `DEDICATED_UNVERIFIED_WRITERS`
   native checks are **not** cleared by merely installing a catalogue.
   Recheck Stage A native systemd252 startup/cold-canary/quotas/deadline
   before ANY compiler admission. Existing Stage A remains NO-GO until
   independent acceptance completes.
4. Have the protected root installer read the exact mode-0600 approval,
   not caller-submitted JSON. Feed `install_native` only independent
   installed-source/Host, managed-lane, accepted-generation and
   original-monthly-pin attesters. If any required evidence is missing,
   abort WITHOUT writing a catalogue.
5. The code exclusively creates the fixed root-owned mode-0600
   `graphics-foundation-catalogue-v1.json` on protected external STATE,
   fsyncs it, uses `task_catalogue.load(require_root_owned=True)`
   to verify hash and exact finite one-task selection, then writes a
   separate nonsecret root-owned 0600 installation receipt with
   `catalogue_sha256`, approval digest, real accepted base/receipt,
   source/pin, lane/Host owner and 30+2 GiB budget. Independently
   reread and hash both files, wheel RECORD, storage and owner lineage
   and publish their exact identities. On interrupted write/uncertain
   receipt, **do not** overwrite, delete, retarget or automatically
   retry; save evidence for explicit review.
6. Only AFTER complete native guarded admission and successful
   installation can an ordinary Regular chat select the exact
   `graphics-fonts-image-v1` task through reviewed GitHub Actions
   OIDC/SQS. This catalogue **does not submit it**. The single
   compiler canary/lane owner and request authorization must independently
   permit that operation. XCB and X11 still require their own reviewed
   predecessor generation and one-at-a-time root-owned repin.

## Source CI versus protected installation

The dedicated `graphics-first-catalogue.yml` workflow checks out the
exact `image-build@b0f53dbd...` source, independently hashes the
original October pin, checks finite recipe/target selection,
mutable/lost/stale base and owner rejection, source/lane/allowlist and
reservation negatives, plus actual `sudo` root-owned O_EXCL/mode-0600
catalogue and receipt writes in a **throwaway test directory**.
All accepted generation, lane, external quota, source attester
callbacks in tests are **synthetic fixtures**. These tests do not
contact AWS, change PID1, install in the real external STATE, or exercise
an approved disposable managed Host.

**Disposition:** source-level owner contract only until Work supplies
the exact real accepted generation and managed lane/Host provenance
and the independent native gates pass. The final installed catalogue
SHA-256 cannot be known or truthfully pinned before those bytes exist.
No real graphical compilation, protected Host installation, EC2/SSM,
controller restart, Work admission or PR merge performed.
