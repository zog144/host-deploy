# host-deploy documentation traceability

**Migration stage:** navigation established, detailed source texts preserved.

| Existing source | Assigned manual chapter(s) | Disposition |
|---|---|---|
| [ARTIFACTS.md](ARTIFACTS.md) | Jobs, compiler lanes and storage | Retained pending status and contract reconciliation |
| [AUTHENTICATION.md](AUTHENTICATION.md) | Authentication and ownership | Retained pending status and contract reconciliation |
| [CLOUD-DEADLINE.md](CLOUD-DEADLINE.md) | Jobs, compiler lanes and storage | Retained pending status and contract reconciliation |
| [DISCOVERY.md](DISCOVERY.md) | Host inventory and provisioning | Retained pending status and contract reconciliation |
| [GATEWAY-ADOPTION.md](GATEWAY-ADOPTION.md) | Authentication and ownership; Compiler gateway and dispatch; Recovery, reboot and runbooks | Retained pending status and contract reconciliation |
| [GATEWAY-CONSUMER.md](GATEWAY-CONSUMER.md) | Compiler gateway and dispatch | Retained pending status and contract reconciliation |
| [GATEWAY-DISPATCH.md](GATEWAY-DISPATCH.md) | Compiler gateway and dispatch | Retained pending status and contract reconciliation |
| [GATEWAY-GITHUB.md](GATEWAY-GITHUB.md) | Compiler gateway and dispatch; Interface reference | Retained pending status and contract reconciliation |
| [GATEWAY-PROTOCOL.md](GATEWAY-PROTOCOL.md) | Compiler gateway and dispatch; Interface reference | Retained pending status and contract reconciliation |
| [IMAGE-BUILD-LANES.md](IMAGE-BUILD-LANES.md) | Jobs, compiler lanes and storage | Retained pending status and contract reconciliation |
| [JOBS.md](JOBS.md) | Jobs, compiler lanes and storage | Retained pending status and contract reconciliation |
| [REBOOT.md](REBOOT.md) | Recovery, reboot and runbooks | Retained pending status and contract reconciliation |
| [RECOVERY.md](RECOVERY.md) | Recovery, reboot and runbooks | Retained pending status and contract reconciliation |
| [S3.md](S3.md) | Jobs, compiler lanes and storage | Retained pending status and contract reconciliation |
| [STARTER-RECIPES.md](STARTER-RECIPES.md) | Host inventory and provisioning | Retained pending status and contract reconciliation |
| [STATION-DEPLOYMENT-JOBS.md](STATION-DEPLOYMENT-JOBS.md) | Jobs, compiler lanes and storage; Deployment integration | Retained pending status and contract reconciliation |

**Source coverage:** 16/16 Markdown documents. Do not delete sources until all requirements, examples, references and historical statuses have been reconciled.

## Editorial consolidation progress — 2026-10-12

This pass replaces the listed canonical chapter placeholders with substantive summaries of current source contracts. The original reference documents remain at their stable paths for exact schemas, historical status and implementation-specific details. A synthesized chapter is not yet a deletion authorization for any referenced file.

| Synthesized reader chapter | Primary preserved evidence | Status |
|---|---|---|
| [Compiler gateway and dispatch](guide/compiler-gateway-and-dispatch.md) | GATEWAY-PROTOCOL.md · GATEWAY-CONSUMER.md · GATEWAY-DISPATCH.md · GATEWAY-ADOPTION.md · guide/compiler-owner-rpc.md | Reader synthesis committed; original detail preserved |
| [Authentication and ownership](guide/authentication-and-ownership.md) | AUTHENTICATION.md · GATEWAY-CONSUMER.md · GATEWAY-ADOPTION.md · RECOVERY.md · guide/compiler-owner-rpc.md | Reader synthesis committed; original detail preserved |

**Editorial boundary:** The remaining manual chapters still need full synthesis. The retained documents must be compared line-by-line for unique requirements, example validity, duplicate claims, implemented-versus-historical status and explicit acceptance evidence before any source deletion. Machine-readable schemas and release provenance remain standalone. Source change does not establish production deployment or stable-release readiness.

## Editorial consolidation progress — 2026-10-12, continuation

The following chapter entry points now contain substantive synthesis of the preserved detailed sources. Unique versioned contracts, source evidence and historical acceptance declarations remain under their existing paths; the prose has **not** authorized deletion of any original document or production deployment.

| Reader chapter | Important preserved sources | Status |
|---|---|---|
| [Recovery, reboot and runbooks](guide/recovery-reboot-and-runbooks.md) | RECOVERY.md · GATEWAY-ADOPTION.md · GATEWAY-DISPATCH.md · REBOOT.md · CLOUD-DEADLINE.md | Synthesized; detailed contract retained |
| [Jobs, compiler lanes and storage](guide/jobs-compiler-lanes-and-storage.md) | IMAGE-BUILD-LANES.md · JOBS.md · ARTIFACTS.md · GATEWAY-DISPATCH.md | Synthesized; detailed contract retained |

**Unresolved editorial work:** Reconcile source claims and examples against the current implementation before replacing detailed files; complete the remaining chapter summaries; audit duplicate or superseded requirements separately from live acceptance. This is documentation review, not a component release candidate.

## Requirement-family reconciliation — 2026-10-12

Host-deploy's new architecture/provisioning chapter consolidates the current ownership narrative. Historical remote-job/gateway contracts remain separately authoritative for exact API and recovery details.

| ID / requirement family | Reader synthesis | Retained detail | Deduplication disposition |
|---|---|---|---|
| **HD-HOST-01** — EC2 account/region/instance and workspace UUID, verified inventory | [Provisioning](guide/host-inventory-and-provisioning.md) | [Canonical manual](README.md), [Discovery](DISCOVERY.md) | Retain authoritative provisioning CLI, signed beacon installer and ownership tests |
| **HD-OWN-02** — Controller handoff versus exceptional lost-workspace adoption | [Authentication](guide/authentication-and-ownership.md), [Recovery](guide/recovery-reboot-and-runbooks.md) | [Recovery](RECOVERY.md), [Adoption](GATEWAY-ADOPTION.md) | Preserve exact marker/epoch and old-writer quiescence requirements |
| **HD-SSM-03** — Queue admission, SSM CommandId, uncertainty and immutable receipts | [Gateway](guide/compiler-gateway-and-dispatch.md) | [Gateway protocol](GATEWAY-PROTOCOL.md), [Dispatch](GATEWAY-DISPATCH.md) | Retain closed wire schema, dispatch identity and durable ledger |
| **HD-RPC-04** — Owner-host mTLS RPC and observer-versus-mutation authorization | [Compiler RPC](guide/compiler-owner-rpc.md) | [Compiler owner RPC](guide/compiler-owner-rpc.md) | Keep independently versioned reviewed candidate; source CI is not production cutover |
| **HD-JOB-05** — Jobs, exact compiler source pins/lanes and content-bound transfer | [Lanes](guide/jobs-compiler-lanes-and-storage.md) | [Jobs](JOBS.md), [Lanes](IMAGE-BUILD-LANES.md), [Artifacts](ARTIFACTS.md) | Keep separate mutable lane state, transport limits and frozen records |
| **HD-OPS-06** — Normal reboot, outcome uncertainty, guest-versus-cloud deadline | [Recovery](guide/recovery-reboot-and-runbooks.md) | [Reboot](REBOOT.md), [Deadline](CLOUD-DEADLINE.md) | Guest timer is not AWS cost ceiling; cloud scheduler not implemented in the dated report |

**Retirement gate:** Inventory every unique requirement, denial, schema field, identity, exception and acceptance result in a source file before deletion. Match its current or historical status against an exact source revision; preserve dated evidence in know-file, update inbound links, and validate CI and release-build export. This matrix retires no original documents.

## Cross-repository audit clarification — 2026-10-12

The canonical documentation entry remains [README.md](README.md), with thematic chapters in [guide/](guide/). The later [INDEX.md](INDEX.md) is only a compatibility entry and does not define an alternate hierarchy. [Architecture](architecture.md) and [verification](verification.md) are supplemental high-level synopses, not replacement schema contracts or proof of new acceptance. The original source-coverage figures above refer to the preserved detailed documents, and are unchanged by these additional navigational pages. No historical or canonical source is retired by this clarification.
