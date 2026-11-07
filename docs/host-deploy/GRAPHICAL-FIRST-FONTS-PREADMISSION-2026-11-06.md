# First Fonts catalogue and GitHub→FIFO SQS source pre-admission — 2026-11-06

**Disposition: SOURCE-REVIEWED, PREPARED_NOT_SUBMITTABLE. Immutable *definition* reviewed; no genuine installed catalogue bytes, native owner admission, real IAM permissions or signed compiler image approval are claimed.**

## Exact frozen source identities

- Draft host-deploy PR #7 one-task catalogue; original producer **image-build `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`**, source recipe `project/bootstrap/graphics-fonts.py`.
- Immutable October `project/pins/2026-10-01/commit-pin.py` SHA-256: `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`. No source substitution from older `b0f53dbd...`.
- Independently selected signed compiler-base reader: image-build PR #20 `1616f192ef9d8964a8f37f32a86c69c0242a213c`. Initial compiler may retain original `kind=image` (with historical gaps) or `kind=toolchain`, **only with actual independently signed Ed25519 receipt, canonical generation and native probe evidence**. A synthetic signature, receipt hash, source commit or past compilation cannot establish admission.
- Image-build PR #17 preparation source `324b1469cb490a571d428cadd9ce72bbec5507b4`: status `PREPARED_NOT_SUBMITTABLE`, all original issue, queue acknowledgement, native admission and output IDs null. **Its reviewer references are stale** (`78a772a...` PR7 and `c46c6b...` Task C), and its original stage-two-only prose is superseded by the signed dual-kind acceptance. Treat this record as a historical held preparation; do **not** repurpose as approval without image-build Regular's independent exact-head revision/review.
- Host-deploy PR #26 protected owner source selection `02db124609b92396ff89fa628d8ddc9383e05f4b` (not an installed owner). This source checks original GitHub event/request digest and uses separate `preflight-original` and stage `submit-original` claims and read-only `observe-original` over the protected AF_UNIX IPC. It cannot confer IAM authorization by itself.

## Fixed catalogue and source closure

The first root-owned schema-2 catalogue must contain **exactly one task**: `graphics-fonts-image-v1`. Its *sorted recipe identity entries* are `fontconfig-final`, `freetype-final`, `libpng-final`. The actual producer plan stages and targets execute `libpng-final → freetype-final → fontconfig-final`.

| Project | Exact release | Upstream archive SHA-256 | In-graph build prerequisite |
|---|---|---|---|
| libpng | 1.6.58 | `28eb403f51f0f7405249132cecfe82ea5c0ef97f1b32c5a65828814ae0d34775` | inherited accepted zlib/toolchain |
| FreeType | 2.14.3 | `36bc4f1cc413335368ee656c42afca65c5a3987e8768cc28cf11ba775e785a5f` | `libpng-final`, inherited zlib/bzip2 |
| Fontconfig | 2.18.3 | `4f7b554a38cdf78c033f666c8871f3749e14a094f65a07f630c91ed0b43d35e3` | `freetype-final`, inherited Expat/gperf |

Source recipe dependencies declare both build and runtime edges for the two predecessor links. Each uses one checksum-pinned archive source, no selected extra patch, DESTDIR installation, an explicit test command; FreeType excludes HarfBuzz/Brotli and requires zlib/bzip2/PNG. Required inherited tools/capabilities (GCC, make, Python, pkgconf, Meson/Ninja, zlib, bzip2, Expat, gperf, headers/libs and stage-specific build tools) **must** be independently verified in the actual accepted generation, not silently fulfilled by the compiler Host or runner. Source CI does not prove archive download at run time, target binaries, runtime tests or no Host fallback.

Rights/notice evidence is **hash-addressed but not cleared for public release**: exact `license.py` records for all three projects are `status=declared`; component reviews include explicit `status=unresolved`. Original LICENSE/COPYING/FTL/GPL/component notices are declared and output preservation is designed to verify extracted/archive bytes. The per-file public distribution/patch/source retention and installed notice evidence remain external release gates. Do not change a `declared` or `unresolved` finding to `reviewed` merely for Fonts submission.

## Bound resources (do not conflate scopes)

The reviewed catalogue approval requires exactly **30 GiB work image + 2 GiB external accounting image = 32 GiB dedicated**, and **21,600 seconds**. It is immutable schema-2 and the installer uses root-only existing-STATE O_EXCL, 0600, fsync, non-replacement. There is **no genuine fixed catalogue SHA** until the independently accepted original generation, signed receipt, managed lane and installed Host/STATE are selected. The native quota/external-pool inspectors must prove exact backing and actual mounts, noncompeting writers, controller deadline and recovery. Shared-host PID1/journald/SSM/cron external writes are explicitly **outside** this dedicated 32 GiB scope in `fresh_aggregate_disk`; the global six-hour/32-GiB operating envelope is a **separate** accounting/owner Work gate. Never count the dedicated reservation as proof that *all* Host writes are bounded.

## GitHub→FIFO SQS→protected owner dispatch review

The normal contract remains:

1. A **future separately approved, original** `issues.opened` event in `zog144/host-deploy` carries a marker and narrowly typed issue intent (not server-owned `origin`). The action checks first run attempt, authorized original actor, repository/event identity, configured dispatch SHA, exact allowed operation/source, and opt-in; no issue has been opened by this review.
2. The GitHub Actions **submit** job alone requests short-lived GitHub OIDC AWS credentials from a configured repository-admin role, with the checkout pinned to `ZOG_GATEWAY_DISPATCH_REVISION`. Only if `ZOG_GATEWAY_SUBMIT_ENABLED` is true does it invoke one validated SQS send. It uses FIFO `MessageGroupId=workspace_id`, `MessageDeduplicationId=request_id` and an SDK single-attempt policy. Lost/uncertain ACK is an investigation hold, **not retry authorization**.
3. The separately selected SQS consumer admits the original immutable request, managed Host and exact one-task root-owned catalogue; subsequent original preflight and stage SSM operations must go **only through** the root-control independently protected owner, with irrevocable claims, signed-v2 result, fresh S3 sequence and owner-exclusive SSM credentials. A source test cannot prove a deployed gateway lacks effective SendCommand rights.

**AWS permissions source-vs-reality:** repository workflow/settings show *requested* OIDC access and SQS API use, but neither actual STS principal nor live IAM trust/policies are accessible through GitHub's repository reads. **Actual permissions NOT CONFIRMED.** Before any opt-in/issue, Work must obtain independently verified live evidence, tied to the exact Host/account/installation and active principal, of:

- GitHub OIDC role trust condition `aud`/`sub`, repository/ref or selected environment, role ARN/account, exact FIFO queue ARN, `sqs:SendMessage` allow only for that queue, no SSM/STS escalation or wildcard SQS powers.
- Gateway/dispatcher SQS consumer receive/delete/change visibility/get-attributes and DLQ read-attributes permissions as needed; effective gateway UID and *all* credential sources denied `ssm:SendCommand`, `sts:AssumeRole`, `iam:PassRole`, owner signer/session access and instance-profile/IMDS escalation.
- Protected owner **only** has separately scoped SSM send/read evidence, under independently signed original operation plus nonrollbackable S3 history; broker's GetObject-only original scope is distinct from checkpoint writer/SSM sender and cannot acquire write or sender authority.
- Live role identity (STS), IAM role and attached/inline policies, boundaries, session policies, resource policy, KMS implications if any, CloudTrail/audited negative probes and exact queue account and Region `us-east-1`. Existing shared EC2 role with broad SSM rights is **not** evidence of gateway denial; native UID-to-credential isolation must be measured and enforced.

## Review exit and outstanding holds

**Source result:** fixed one-task definition, source/rights declaration identities, dependency edges, original pin, dual-kind compiler acceptance contract, budget ceiling, OIDC/FIFO single-attempt shape and protected-owner normal call path are reviewed and covered by pinned GitHub Actions source regressions.

**Native and operator HOLD:** authentic compiler-base signed receipt/probe, actual Host/installation/STATE and lane, protected approval, signed original GitHub issue/event, installed immutable catalogue/hash, source and rights release evidence, exact aggregate live accounting and quota, native protected owner, S3 checkpoint genesis/history, separated AWS IAM/credentials and explicit one-time operator submission remain unaccepted. No GitHub issue, SQS send, SSM command, compiler execution, catalogue installation, or source promotion occurred.
