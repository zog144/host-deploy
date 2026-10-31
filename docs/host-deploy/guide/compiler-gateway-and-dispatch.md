# Compiler gateway and remote dispatch

## Responsibility and trust boundaries

Host-deploy coordinates authorized operations against an **already owned** command-center/compiler host. It does not grant station-access a second direct EC2/SSM writer, and a syntactically valid gateway request is not authorization. The gateway is a composition of independently validated parts: the GitHub origin/actor decision, durable SQS transport admission, an exact owned workspace, a server-selected remote operation and observation of an immutable execution identity.

The [gateway protocol](../GATEWAY-PROTOCOL.md) requires a closed schema, canonical request/workspace IDs and restricted operations; unknown fields, arbitrary shell commands, paths and environment overrides fail. The GitHub trigger actor is an audit field, not proof of the event actor: GitHub Actions must authorize the trusted event identity **before** assuming an AWS role. The consumer validates again at the command center.

## Transport is not the ledger

The long-polling SQS FIFO consumer stores immutable request bytes/digest, transition history, transport evidence and workspace-admission evidence. SQS deduplication is not the idempotency boundary. A durable accepted/admission-pending record survives redelivery after an interrupted deletion; a different payload reusing the same request ID is an integrity conflict. Malformed messages are not acknowledged as valid work or passed to an execution shell. The old [consumer acceptance](../GATEWAY-CONSUMER.md) describes queue configuration and initial pass limitations; those limitations are historical, not a substitute for current source/CI acceptance.

The durable request state separates **acceptance**, **admission**, **dispatch**, **completion** and **reporting**. Treat a successfully received queue message as neither an authorized mutation nor an observed completed build.

## Ownership is explicit and epoch-bound

A normal gateway workspace must be transferred by a retiring checkpoint/handoff, and only one owner can mutate it. If the authentic original checkpoint is genuinely unavailable, the explicit [lost-workspace adoption procedure](../GATEWAY-ADOPTION.md) requires operator authorization, saved-state digests, quiescence acknowledgements for every expected writer, live AWS inventory/tag agreement and an exact remote ownership marker. The gateway does **not** invent past jobs, generations or `launch.json` to fill missing history.

The adopted workspace and its remote ownership epoch remain bound. Absent/mismatched marker or uncertain submission stops further mutation. An adopted workspace may permit guarded SSM operations while intentionally refusing ordinary lifecycle start/stop/terminate.

## Exact dispatch and SSM uncertainty

The [durable dispatch contract](../GATEWAY-DISPATCH.md) freezes the request and workspace identities, lane, target EC2 identity, deployed source revision, monthly pin, authorized request/result paths, exact image-build operation request/argv and digest **before** the SSM side effect.

The transport separates `submit_command` (one SendCommand), `inspect_command` (observation by existing CommandId), and `wait_command` (wait without resubmitting). A durable `submitting` marker precedes SendCommand. If its response is lost without a recorded CommandId, `submission_uncertain` blocks automatic replay; authoritative recovery of that same ID can reconcile it. A terminal SSM result without a trustworthy image-build receipt is not proof of safe completion.

The remote wrapper checks the exact deployed checkout revision and cleanliness, verifies the frozen provenance pin under the checkout, and binds the request/result bytes. Duplicate or recovered execution must not substitute a new source tree. Pass-4 materials originally mapped `build.status/resume/cancel` to image-build remote operations and explicitly rejected `build.submit` pending a producer-owned recipe snapshot/task mapping. **That was a pass-specific limit, not a statement about all later revisions.** Confirm the current producer and consumer's implemented capability contracts before claiming submission is enabled.

## Station-access compiler owner RPC

The newer [compiler owner RPC contract](compiler-owner-rpc.md) proposes an HTTPS mutual-TLS bridge at the existing host-deploy owner service, rather than inside the application container. It pins the adopted workspace/epoch, requires an allowlisted client certificate with exact method scopes, and permits read-only `compiler.status` / `dispatch.status` separately from guarded `dispatch.prepare/submit/observe`. Station web login is **not** automatically a compiler mutation scope. No operation accepts raw SSM documents or creates arbitrary requests.

The RPC document marks its acceptance status as **source candidate; isolated live acceptance required**. Thus an API shape or passing code test does not authorize a production cutover or a replacement owner. The station application's network namespace must reach the routed TLS endpoint; its own loopback is not host loopback.

## Review and operational evidence

Before an owner-gateway production cutover, establish the exact source pins, request/SSM identity, quiesced old writers, remote epoch fencing, immutable result receipts, TLS/service identity, station scopes, secret-free durable mounts and a rollback path. Test failure and uncertainty states, not only happy-path dispatch.

### Primary contracts

- [Request envelope and durable state](../GATEWAY-PROTOCOL.md)
- [SQS consumer and handoff](../GATEWAY-CONSUMER.md)
- [SSM dispatch/receipt phases](../GATEWAY-DISPATCH.md)
- [Lost-workspace adoption and uncertainty](../GATEWAY-ADOPTION.md)
- [Compiler owner RPC candidate](compiler-owner-rpc.md)
- [Remote control recovery](../RECOVERY.md)


## Reviewed graphical foundation submissions

The generic image pipeline has four finite graphical selectors. Three are the
foundation batches used before the existing XCB/i3 support task:

- `graphics-fonts-image-v1` — libpng, FreeType and Fontconfig;
- `graphics-xcb-core-image-v1` — Check/libevdev test support, xorgproto,
  libXau/libXdmcp, xcb-proto and libxcb;
- `graphics-x11-core-image-v1` — the reviewed consumer-driven X11 core;
- `xcb-support-image-v1` — the later xcb-util/i3 support phase already present.

A GitHub issue selects only one of these names and a canonical lane. It cannot
supply recipe paths, targets, environment, shell commands, a monthly pin or a base
generation. The root-owned task catalogue binds all of those values, including the
exact image-build commit, lane owner, monthly-pin identity and immutable 64-hex base
generation. Changing any of them changes the catalogue identity and requires owner
review.

Foundation publication is intentionally sequential. The fonts task is admitted
against an independently accepted self-hosted image generation. The XCB task must
be repinned by the protected owner to the accepted fonts output generation, and the
X11 task must be repinned to the accepted XCB output generation. The public request
contract does not accept a caller-selected `selection` field and must not be
extended to do so merely to avoid that review boundary.

Source support is not native admission. Before enabling `build.submit` for one of
these tasks, the protected compiler owner must have current native acceptance, the
dedicated lane/capacity reservation must be live, the exact root-owned catalogue
must be installed and hash-pinned, and the deployed image-build source must match
the catalogue revision. A successful GitHub/OIDC/SQS send proves transport only;
it does not prove compiler admission or compilation success.
