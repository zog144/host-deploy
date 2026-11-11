# First-Fonts compiler and trusted-Host Task C reconciliation — November 11, 2026

**Status: source-only candidate; native Fonts admission and SSM submission HOLD.**

## Current selections

The original compiler producer remains immutable image-build `1f07e83dbd80dacb9bed0d6494c697375f0e26cd` and October source pin `sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.

- Compiler-purpose reader: image-build [PR #20](https://github.com/zog144/image-build/pull/20), exactly `1616f192ef9d8964a8f37f32a86c69c0242a213c`.
- Reviewed signature/binding consumer: host-deploy [PR #29](https://github.com/zog144/host-deploy/pull/29), exactly `b3ac93cd92df1b280f087fbb748263d3371750aa`. The PR #7 catalogue-specific owner is allowed to extend this source but must retain the exact PR #29 *compiler acceptance consumer* bytes.
- Native dispatch architecture: host-deploy [PR #30](https://github.com/zog144/host-deploy/pull/30), exactly `0fd2db17698423d4cd30b296fc9f78e83cee145c`, **trusted-Host single gateway**, not original protected stream broker.
- [image-build PR #17](https://github.com/zog144/image-build/pull/17) prepares the held original GitHub issue protocol without issuing a real request. It pins the eventual selected PR #7 commit independently; PR #7 deliberately does not pin PR #17's moving head, avoiding a circular frozen-commit dependency.

## Real producer/consumer compatibility correction

The existing compiler-purpose reader `compiler_base_acceptance.resolve` requires an exact independently trusted Ed25519 receipt SHA-256 in the original `pipeline.submit` request for the Fonts catalogue. The earlier PR #7 emitted only `mode`, `selection` and `targets` and therefore could not compile even if the native catalogue were accepted.

`graphics_catalogue_owner.prepare` now freezes **`arguments.compiler_base = bound_base["accepted_receipt_sha256"]`** in the *root-owned* one-task catalogue. `task_catalogue.validate` requires a canonical SHA-256 digest for this exact Fonts task, and no arbitrarily injected approval, SSM owner or command field. `task_catalogue.select_retained` compares the frozen receipt against independently verified retained-generation evidence. The reviewed trusted-Host `generic_pipeline._request` carries the **whole** frozen `task["arguments"]` into the generated `pipeline.submit` request along with the original server-observed recipe snapshot. The GitHub issue chooses only the task/lane and cannot substitute a compiler digest, generation, target, script or IAM role.

The native selected input remains original `kind=image` with explicit historical-provenance gaps; genuine stage-two `kind=toolchain` remains possible separately. Accepted compiler bytes, 64-bit GNU/Zog ABI, runtime witness, header and linker search traces, installed inventory/manifests, mount/namespace/UID/GID restrictions and bounded real native probe **remain mandatory**. Compiler-purpose signature enrollment is a separate compiler trust decision, **not a Task C operator-signed installation approval** and cannot be reused as a Task C SSM permission.

## November 11 trusted-Host Task C selection

The selected Task C is the existing GitHub `issues.opened` → Actions/OIDC → FIFO SQS → host-deploy dispatcher → **trusted host-registry gateway** → fixed `AWS-RunShellScript` / SSM route. The gateway uses the already trusted Host's normal instance IAM role, reopens the current designated compiler Host/region/account, and fsyncs one local send-intent per frozen original operation before exactly **one** `SendCommand` SDK attempt. Lost acknowledgement, duplicate, uncertain recovery or reboot **holds**, never retries blindly. Original event actor/issue/request/source/recipe snapshot and SSM CommandId remain durable. Ordinary root-owned local application state, existing Host data directories and local source/RECORD identity are sufficient storage/installation boundaries in the revised threat model.

There is **no** mandatory Task C S3 bucket/genesis/anchor/retention/highwater, separate S3 writer/reader roles, distinct owner-only SSM role, operator-signed Task C storage-establishment approval, installer-signed Task C commit, independently protected storage volume or broker socket. Historical unselected owner/broker modules are not active route dependencies; source-only CI rejects imports of those modules into the selected Task C path. Host IAM permission scope and real task/target/timeout allowlist still require Work's live verification.

The existing Fonts dedicated **30 GiB work + 2 GiB external** budget and six-hour maximum describe the **compiler worker resource reservation**, not a mandatory disk/volume for Task C or each host-registry application. A root-owned one-task catalogue and exact nonreplacing installed receipt still require separate native filesystem and selected Host/installation/managed lane verification. The old PR #7 preliminary worker-resource inspector remains a dedicated worker admission check, not evidence that Task C needs separate EBS storage.

## Source-only negative coverage / next native gate

The PR #7 workflow checks original October pin/source, PR #20 actual observed isolation, exact PR #29 shared compiler consumer and immutable PR #30 trusted-Host generic pipeline/local intent/SSM route. Tests reject omitted/forged `compiler_base`, altered base kind or signed-looking evidence, mismatched original generation, changed ABI/mount evidence, task expansion, injected arbitrary SSM owner, lost original signed compiler binding, imported Task C broker, removed send-once fsync or unfrozen trusted target.

**NOT NATIVE GO:** no enrolled authentic compiler-purpose grant/receipt or current signed selected generation, native manifest/ELF reinspection, configured installed gateway/Host IAM/SSM permissions, selected root-owned catalogue/receipt, independently measured 30+2 GiB reservation, one-action native send-intent/reboot/uncertain-ACK acceptance, original issue authorization, or compiler run has been established here. Synthetic CI has no production signature or SSM permission. Source consistency is a prerequisite, not a request to create the GitHub issue.

**Exit for Regular:** source-compatible first-Fonts catalogue and compiler reader selection prepared for Work native acceptance; no S3/separate owner/installation-signer Task C gate retained or claimed; **no task submitted and no immutable Fonts generation accepted**.
