# Deployment integration and authenticated host services

## Installation is not enrollment

Host-deploy can prepare a signed host-discover installation on an already owned AWS host, but its package transfer and SSM success do not automatically approve the Host key or prove signed heartbeats reached the command center. Station-access owns key approval, registry state and saved desired beacon destinations. The installed daemon identity remains independently governed by host-install/host-identify.

## Bounded station deployment jobs

The [station deployment job contract](../STATION-DEPLOYMENT-JOBS.md) limits current administration actions to supported read-only host inspection and reviewed destination-configuration changes. Such a job binds a known enrolled host, exact AWS inventory and host-deploy workspace, expected installed version, primary registry preservation and a time-limited review/confirmation. A completed remote job is **not** evidence that the new recipient has approved the host or granted archival/DNS privileges.

## Compiler-owned station observation

The compiler owner RPC is installed on the existing host-deploy owner machine and authenticates station-access via mTLS. Station's observer identity receives only `compiler.status` and `dispatch.status`, not generalized SSM submission or a new gateway writer. Deployment of the TLS listener, firewall and station application network route requires isolated live acceptance, not merely a source/CI pass.

## Cutover and rollback remain owned

Immutable station software publication, persistent station-data migration, separately owned archive storage, host-discover mirror-live export and nginx/443 routing belong to an explicitly reviewed production cutover. Host-deploy must not overwrite the live command-center service because an isolated client test succeeds; maintain original backups and single-writer fencing.

## Exact reference material

- [STATION-DEPLOYMENT-JOBS.md](../STATION-DEPLOYMENT-JOBS.md)
- [DISCOVERY.md](../DISCOVERY.md)
- [GATEWAY-ADOPTION.md](../GATEWAY-ADOPTION.md)

The original documents retain exact machine schemas, historical implementation status and tests. A document describing an installed source feature does not imply operator-authorized host deployment.
