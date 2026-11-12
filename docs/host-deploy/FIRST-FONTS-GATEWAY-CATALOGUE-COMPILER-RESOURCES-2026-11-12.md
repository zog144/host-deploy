# First Fonts — separate gateway catalogue installation from compiler-Host admission (2026-11-12)

**Source policy:** the trusted `host-registry` gateway installs only a small root-owned, hash-pinned, one-task Fonts catalogue and a receipt. The gateway does **not** need 32 GiB of available filesystem space, an XFS project quota, a loopback image, a 30-GiB work directory, or a 2-GiB external accounting directory.

## Gateway role

`graphics_catalogue_owner.install_native` verifies the reviewed source, immutable monthly pin, accepted compiler-generation receipt and managed lane identity, then writes `/var/lib/zog/fonts/graphics-foundation-catalogue-v1.json` and its receipt with root-owned nonreplacing O_EXCL and fsync. The catalogue contains exactly `graphics-fonts-image-v1` with immutable libpng → FreeType → Fontconfig targets and the selected accepted compiler receipt. The installer **never calls** `fonts_resource_admission.checked()`, `inspect_native()`, `statvfs()`, or an arbitrary resource reader. It does not create quotas, execute compilation or submit AWS SSM. A small amount of space to write these metadata files is the only ordinary local filesystem requirement.

The catalogue's 30 GiB work, 2 GiB external and 21,600-second execution policy remains frozen as **compiler-job policy**, not an assertion that these resources are present on `host-registry`. The installed receipt explicitly says `resource_admission_location=compiler-host-before-build` and `compiler_resource_admitted=false`.

## Compiler Host role

On the selected **compiler Host**, after the gateway has installed the immutable catalogue but **before** image-build task allocation or the first mutating compile action, the independent resource admission must inspect actual compiler filesystem and namespace conditions. The existing `fonts_resource_admission` reader is a compiler-Host-local function. It is *not* an authorization source for gateway catalogue installation.

Its reviewed XFS project quota mode checks 30 GiB work and 2 GiB external hard ceilings, enforced worker writable roots, same compiler root filesystem and sufficient compiler Host headroom, along with the 21,600-second operation deadline. It does not prove exclusive capacity against other Host writers. An ext4 compiler Host or an XFS Host without project quotas is still NO-GO under that reader pending a separately reviewed compiler-side enforcement mechanism; this never justifies resizing `host-registry`.

The source does **not yet prove** an installed image-build producer is consuming that specific compiler-side observation as an authoritative preallocation gate. Work must authenticate the actual compiler Host/installation/STATE, selected real capacity and mounts, accepted input generation, result observation and enforcement before authorizing a live build. A successful gateway catalogue install does not satisfy these native gates.

## Acceptance and handoff

Source acceptance tests ensure the root-owned O_EXCL installation succeeds using a small disposable directory without a quota or free-space read, even with a fail-if-called resource inspector; they retain the original compiler budget policy and tamper/duplicate protection. In Work, install and verify the exact accepted catalogue SHA on the gateway without changing its storage. Then verify and enforce resource admission on the compiler Host before triggering the first authorized Github Actions → FIFO SQS → trusted-Host SSM operation. Lost SSM acknowledgment is a HOLD, not permission to send again.

**No local/remote Host storage, quota, AWS IAM, SQS, SSM, or build action is performed by this source work.**
