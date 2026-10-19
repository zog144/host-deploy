# Interface reference and call boundaries

## Select the right interface

The human `host-deploy` CLI owns provisioning, status, generic jobs, reboot workflows, bounded transfer and checkpoint handoff for the saved workspace. The gateway closed request protocol is a different machine-facing interface with fixed producer operations and durable admission/dispatch IDs. The compiler owner RPC is yet another HTTPS/mTLS surface attached to that owner, not the application runtime controller.

## Gateway origin and durable request

The [GitHub origin contract](../GATEWAY-GITHUB.md) authenticates the initiating workflow/event actor before temporary credentials are granted; an untrusted issue body or displayed actor field cannot prove authorization. The [gateway protocol](../GATEWAY-PROTOCOL.md) validates a closed request shape and exact workspace/resource identity. SQS delivery/deduplication is transport only; the gateway ledger provides identity and acceptance ordering.

## SSM execution and RPC scope

The [dispatch contract](../GATEWAY-DISPATCH.md) records an immutable remote job operation, source revision, provenance pin and SSM command identity, and distinguishes prepare, submit, observe, completion and uncertain submission. The [compiler owner RPC](compiler-owner-rpc.md) exposes fixed read-only methods and separately permissioned guarded mutation scopes; station-access's certificate must only contain observer scopes.

## Compatibility and verification

Check `capabilities.inspect` from the exact image-build producer revision rather than trusting historical pass-4 restrictions on generic submit. Source tests of gateway/wire schemas, request replay, SSM fault handling and TLS prove protocol behavior; live ownership epoch fencing, routed TLS and compiler results need independent acceptance.

## Exact reference material

- [GATEWAY-GITHUB.md](../GATEWAY-GITHUB.md)
- [GATEWAY-PROTOCOL.md](../GATEWAY-PROTOCOL.md)
- [GATEWAY-DISPATCH.md](../GATEWAY-DISPATCH.md)
- [GATEWAY-CONSUMER.md](../GATEWAY-CONSUMER.md)

The original documents retain exact machine schemas, historical implementation status and tests. A document describing an installed source feature does not imply operator-authorized host deployment.
