# First Fonts — ordinary catalogue installation without a policy file (2026-11-12)

**Source-only implementation.** No native Host, filesystem, quota, AWS or compiler operation was performed.

## Chosen installation model

The trusted `host-registry` administrator installs **one** reviewed Fonts catalogue in the existing systemd gateway service's root-owned `StateDirectory=host-deploy-gateway`, already provisioned by host-install PR #35. The installer does not create another application's policy directory, invent approvals, or require a new storage volume.

**Only two durable files are written**, under `/var/lib/host-deploy-gateway`:

- `first-fonts-catalogue-v1.json` — the one-task immutable libpng → FreeType → Fontconfig recipe selection, source pin and accepted compiler receipt reference used by the existing task catalogue loader.
- `first-fonts-catalogue-receipt-v1.json` — short record of the actual installed catalogue SHA-256, selected generation/receipt, Host/installation/lane and `compiler_authorized=false`. This is installation evidence, **not a per-operation approval or authority**.

The former `/var/lib/zog/fonts/graphics-foundation-approval-v1.json` is **not read, written or required**. No replacement Fonts policy file is introduced.

The native installer API is `graphics_catalogue_owner.install_native(lane_name=..., generation_id=..., read_managed_lane=..., read_accepted_base=..., read_installed_pin=..., attest_installed_source=..., attest_host_identity=..., read_compiler_base_receipt=..., read_compiler_base_issuer=..., read_compiler_base_binding=...)`. Work obtains these reader callbacks from the already-installed genuine producer, compiler acceptance and managed lane systems. The selected `lane_name` and `generation_id` are explicit arguments to the supervised install operation, not fields copied from an independent JSON approval file.

The actual checks remain meaningful:
- `monthly_pin_identity` is compared against the exact pre-reviewed source SHA and **the bytes** of the installed monthly pin. It remains in the task definition because source reproducibility matters, not as an arbitrary policy marker.
- The selected `generation_id` and accepted receipt SHA are compared against the independently verified signed compiler-purpose receipt and producer binding, retaining the source generation's original `kind=image` or `kind=toolchain`.
- The managed lane's source/Host identity is compared with that receipt and native installed identity. Unknown source, unsupported task, changed recipe, different accepted compiler, wrong issuer or changed pin is rejected.
- The installation is root-only, must find an already installed private root-owned gateway `StateDirectory`, creates the two files with `O_EXCL | O_NOFOLLOW`, verifies the catalogue's actual SHA through the existing root-owned loader, and fsyncs the files and directory. Partial/duplicate installations refuse overwrite.

## Removed conditions

No XFS project-quota inspection, no `fonts_resource_admission` module, no enforced 30 GiB + 2 GiB storage reservation or free-space gate, and no special six-hour execution limit are included in the first Fonts catalogue, installer, or PR #17 source preparation. The deleted approval and budget fields are not merely left set to `false` or `null` in another policy file.

This change does **not** remove the application's normal AWS service authentication, fixed compiler Host/document/recipe selection, durable one-attempt SSM journal, source/compiler integrity checks or ordinary OS/job-management failure handling. Other unrelated legacy fresh-bootstrap budget modules elsewhere in the repository are not selected by this first-Fonts catalogue.

## Native next step

Work should verify exact package/source bytes and the current accepted compiler generation, install the two catalogue files via the genuine trusted readers in the existing service StateDirectory, record the resulting catalogue SHA-256 in the reviewed gateway selection, and inspect the installed catalogue. Then a separately authorized original GitHub issue may be submitted using GitHub Actions → FIFO SQS → trusted Host dispatcher → selected compiler. **No issue, queue request, SSM or compilation was initiated by this source review.**
