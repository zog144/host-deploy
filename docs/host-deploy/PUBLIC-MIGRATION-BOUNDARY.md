# Source-only migration versus live execution activation

**Default after public source publication: no AWS-side effects or gateway
activation.**

The GitHub issue/SQS gateway is an operational control plane:
`issues: opened` can cause an OIDC role assumption and SQS message submission
if `ZOG_GATEWAY_SUBMIT_ENABLED=true`. It must not become active merely by
moving a source branch to default `main`. The initial public export disabled the issue trigger. The subsequently authorized
configuration-gated workflow is described in GATEWAY-GITHUB.md. Publishing it does
not set the live submission switch or authorize generic compilation.

## Separation of gates

- **Source export**: dual first-party license, rights/privacy scan for every
  included byte, no private history or archived fixtures, no cloud credentials,
  public-compatible source references, bounded read-only source CI and clean
  history `unstable` publication.
- **Companion alignment**: recover public exact Git identities, validate
  `beacon_sources.json` hashes, immutable image-build lane descriptions,
  compiler RPC identity, selected certificate issuer inspection and full
  component test parity.
- **Gateway activation**: immutable authorized-actor list, GitHub OIDC trust
  conditions, read-only validation first, explicit SQS SendMessage role/queue
  bindings, consumer ownership/epoch and accepted remote protocol; live
  provisioning/SSM tests use isolated AWS resources with cleanup evidence.
- **Binary/rootfs release**: separate licensing, actual compiled-output
  closure, notices and native acceptance; not in scope.

An existing command-center gateway must not be migrated/restarted implicitly.
The original private repository and its operationally pinned history are
retained until an independently authorized service cutover.
