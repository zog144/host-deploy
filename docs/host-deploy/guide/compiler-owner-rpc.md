# Compiler owner RPC v1 — station-access integration contract

**Status:** source candidate; isolated acceptance required. Does not authorize production cutover.

## Boundary and reachability

The RPC is implemented by `zog.host_deploy.gateway.compiler_rpc` and runs on the **existing host-deploy owner/registry host**, not in the compiler container and not in station-access. It reads the adopted `/var/lib/host-deploy-gateway` owner ledger; all compiler mutations call the existing host-deploy gateway dispatch machinery. It does not re-adopt, create a compiler workspace, accept raw SSM documents, or permit arbitrary shell/filesystem paths.

Run `host-deploy-compiler-rpc --config /etc/host-deploy/compiler-rpc.json`. The TLS listener must be reachable from the station application network namespace through a routed, firewall-restricted address. **Loopback inside a station application's network namespace is not the host's loopback.** Avoid host-directory socket grants and the old host-discover gateway. A network path over mutual TLS is deliberately chosen; the client must verify the server hostname and chain. The server requires a trusted client certificate **and** a SHA-256 fingerprint in its configured allowlist; each fingerprint has exact method scopes.

Provision server key/cert and a private CA for approved station clients via a separate secure procedure; do not put private keys in images, repository source, application artifacts, or read-only host-export directories. Station's observer certificate gets only `compiler.status` and `dispatch.status` scopes. A separately reviewed principal must hold the mutation certificate; station web access is not an implicit mutation grant. Enable only the required firewall route and deny other ingress to the RPC port. Rotating a client certificate requires an explicit allowlist update.

## Immutable ownership

Configuration pins the already adopted `workspace_id`, `ownership_epoch`, `instance_id`, `account_id` and `region`. Before each request the service re-reads the owner marker, ownership record, workspace, host and adoption metadata. Missing, released, corrupt, epoch-changed or different-target evidence fails closed. The local observation reports only owner-ledger visibility, **not live EC2 health**. Existing SSM producer submission verifies the remote epoch through host-deploy's guarded Host transport; RPC does not bypass it.

A separate RPC process can restart without affecting request identity. The gateway request ledger, not the RPC's in-memory state, owns durable operations and SSM CommandIds. Do not run a competing host-deploy gateway against copied state. Do not modify the old failed request or reset prepared/uncertain entries.

## Wire protocol

Transport: HTTPS with mutual TLS, HTTP/1.1 POST **only** to `/v1/compiler/rpc`.

Request, maximum 4 KiB including JSON encoding:

```json
{
  "schema": "host-deploy-compiler-rpc-v1",
  "operation": "compiler.status",
  "parameters": {}
}
```

The accepted operations and exact parameter schemas are:

| Operation | Scope | Parameters | Side effect |
| --- | --- | --- | --- |
| `compiler.status` | observation | `{}` | Local adopted owner ledger read |
| `dispatch.status` | observation | `{"request_id":"<canonical-32-hex>"}` | Local ledger read |
| `dispatch.prepare` | separate mutation | same request_id | Calls existing admitted-request dispatch preparation, no raw operation input |
| `dispatch.submit` | separate mutation | same request_id | Calls existing exact bound submission and preflight, never raw SSM |
| `dispatch.observe` | separate mutation | same request_id | Performs existing submitted-command observation/reconciliation |

Every method requires an exact certificate scope of the same name. A read-only client cannot elevate its scope by changing `operation`. Mutation methods may only reference previously **admitted** gateway requests for the bound workspace. Direct creation or injection of requests over RPC is not supported. Mutation methods are not a generic station user-facing compiler build endpoint. A future origin/auth policy for station-originated new admitted requests needs a separate design and approval.

Successful response:

```json
{
  "schema": "host-deploy-compiler-rpc-v1",
  "status": "completed",
  "result": {
    "workspace_id": "<configured-owned-workspace>",
    "ownership": "owned",
    "compiler": "registered",
    "visibility": "owner-ledger"
  }
}
```

Errors use the same schema with `"status": "<safe-category>"`. Expected categories include `not-owned`, `ownership-epoch-mismatch`, `unavailable`, `uncertain`, `not-authorized`, `invalid-operation`. No raw AWS response, SSM output, compiler path, secret, bearer credential, source bytes, or private host identity is returned. HTTP response bodies are bounded to 8 KiB and are `Cache-Control: no-store`.

## Sample administrative configuration

This JSON is a **synthetic, non-deployable illustration**: replace every angle-bracket placeholder with independently approved immutable identities and actual protected certificate files. The values and paths are examples, not an instruction to write secrets. Do not copy the document into a service configuration without completing owner and mTLS preflight:

```json
{
  "schema": 1,
  "state_directory": "/var/lib/host-deploy-gateway",
  "workspace_id": "<owned-workspace-uuid>",
  "ownership_epoch": "<ownership-epoch>",
  "instance_id": "<verified-ec2-instance-id>",
  "account_id": "<verified-aws-account-id>",
  "region": "us-east-1",
  "listen": {"host": "127.0.0.1", "port": 9443},
  "tls": {
    "certificate": "/etc/host-deploy/compiler-rpc/server.pem",
    "private_key": "/etc/host-deploy/compiler-rpc/server.key",
    "client_ca": "/etc/host-deploy/compiler-rpc/client-ca.pem"
  },
  "clients": [
    {
      "certificate_sha256": "<lowercase-sha256-of-client-cert-DER>",
      "scopes": ["compiler.status", "dispatch.status"]
    }
  ]
}
```

The listener address must be changed to an explicitly controlled, reachable interface for station's namespace. A local-only `127.0.0.1` bind is useful for initial owner-host tests **only**; it does not establish station reachability. Install `host-deploy-compiler-rpc.service` through a reviewed owner-host deployment. Service manages its own process restart; systemd launch identity and durable state remain host-deploy-owned.

## Station-access consumer contract

Replace `compiler_gateway:create_gateway` with a namespaced, explicit `zog.station_access` client that:

- Reads a fixed owner-provided HTTPS endpoint from durable application configuration, and **verifies** the server TLS chain and hostname.
- Loads an **observer-only** mTLS client identity from a private durable mount rather than a read-only host capability; neither browser nor frontend receives the certificate.
- Calls only `compiler.status` and `dispatch.status` for compiler visibility. Mutations require a separate reviewed station authorization and client scope.
- Maps sanitized categories into bounded UI/API results, refuses missing owner/gateway, and never falls back to the legacy direct-writer factory or compiler bootstrap socket.
- Never selects a workspace, host, SSM document, shell string, arbitrary path, or AWS credentials from browser parameters.

## Source acceptance and live gate

Offline tests must cover mTLS, missing certificates, read-only scope refusal, owner/epoch/host tampering, allowed observations, typed request rejection, replay identity, sanitized errors, and restart recovery. Tests do **not** prove that the owner-host listener can be reached from station's separate network namespace or that certificates and host firewall have been deployed.

In the adopted production host-deploy workspace, use a **separate** isolated station candidate and:
1. Verify the original owner epoch/marker and the active compiler host identity without re-adopting.
2. Deploy the read-only RPC listener on a controlled interface, configure client certificate trust and scopes and verify namespace network reachability.
3. Confirm observer-only RPC works with the candidate and rejects requests lacking client identity or mutation scope.
4. Rehearse one **separately authorized**, already admitted mutation request, verify one SSM command, immutable receipt, and idempotent retry/restart.
5. Preserve existing station production services, nginx, DNS, copied state and backups; do **not** switch 443 or migrate production SQLite/archive data in this acceptance pass.

**Outstanding blockers:** station-access namespaced consumer integration; secure certificate deployment and namespace network/firewall reachability; isolated live RPC acceptance; production persistent state migration/composition; root-control/box-control production service and host-capability rollout; restart/reboot and application rehearsal.
