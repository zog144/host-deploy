# host-deploy technical manual

Reader-facing chapters organize the existing documentation by enduring concepts and workflows, rather than implementation chronology. Exact contracts, schemas and evidence remain in their original documents until reviewed for safe consolidation.

## Architecture at a glance

Host-deploy owns **cloud-host provisioning, durable controller workspaces, remote execution transport and recovery**. It is neither box-control's local application supervisor nor image-build's compiler/publisher. Its remote host identity is bound to an AWS account, region, instance and immutable host-deploy workspace UUID. An attached graphical station-access Workspace is a different entity despite the shared English term.

A caller may prepare and inspect a bounded job without taking over the host; the owner must still verify inventory, selected source, request identity, registered execution lane and the current controller ownership epoch before a remote side effect. A Work container reconnects through an explicitly retired checkpoint handoff. Exceptional adoption of a lost original checkpoint requires operator authorization, all old writers quiesced, matching AWS inventory and an exact remote owner marker: it is **not** an automatic recovery shortcut.

The system has three distinct planes:

- **Infrastructure plane:** EC2/SSM, durable host workspace, identity tags, uptime/deadline policy and optional artifact transport.
- **Execution plane:** finite trusted jobs, reboot phases, source-pinned image-build lanes, durable SSM CommandIds and exact result receipts.
- **Integration plane:** authenticated host-discover installation, command-center/gateway admission and the narrowly scoped compiler-owner RPC for station-access observation.

See [host inventory and provisioning](guide/host-inventory-and-provisioning.md), [authorization and ownership](guide/authentication-and-ownership.md), [gateway and dispatch](guide/compiler-gateway-and-dispatch.md), and [recovery and reboot](guide/recovery-reboot-and-runbooks.md). Source/CI acceptance is separate from deploying a new service or authorizing a production cutover.

## Chapters

- [Host inventory and provisioning](guide/host-inventory-and-provisioning.md)
- [Authentication and ownership](guide/authentication-and-ownership.md)
- [Compiler gateway and dispatch](guide/compiler-gateway-and-dispatch.md)
- [Compiler owner RPC for station-access](guide/compiler-owner-rpc.md)
- [Jobs, compiler lanes and storage](guide/jobs-compiler-lanes-and-storage.md)
- [Deployment integration](guide/deployment-integration.md)
- [Production station/archive composition and compiler RPC identity rotation](guide/station-production-contract.md)
- [Protected certificate delivery bridge](guide/certificate-delivery.md)
- [Authorized certificate renewal timer](guide/certificate-renewal.md)
- [Recovery, reboot and runbooks](guide/recovery-reboot-and-runbooks.md)
- [Interface reference](guide/interface-reference.md)


## Supplemental cross-cutting synopses

- [Architecture and ownership](architecture.md) summarizes trust boundaries and cross-program responsibilities; follow the thematic chapters above and their linked detail for exact contracts.
- [Verification and release evidence](verification.md) summarizes evidence levels and untested deployment gates; historical acceptance remains version- and environment-scoped.

## Coverage and status

[Traceability map](TRACEABILITY.md) records all retained source documents and chapter assignments. Consult the root README and current code for operational status; historical reports and proposals must not be presented as deployed behavior.
