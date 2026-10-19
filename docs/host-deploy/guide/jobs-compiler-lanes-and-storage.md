# Jobs, compiler lanes and storage

## One host, independently owned projects

A host-deploy **image-build lane** is a reserved execution namespace with its own box-control/image-build project and durable state, not a compiler stage in the recipe graph. Each lane binds a unique name, exact repository revision, original monthly provenance pin path and digest, host/project provenance identity, resource limits and disk reservation. The same EC2 machine and root-control daemon may host several lanes, but mutable pipeline, attempt, generation and controller state **must not be shared**.

Reservation-only lanes represent pre-existing owner-controlled projects for admission accounting; selecting a reservation does not entitle the gateway to manage that project. A managed lane requires deliberate owner admission and source binding. See [concurrent lanes](../IMAGE-BUILD-LANES.md).

## Finite compiler execution and command identity

Generic background jobs can run as independent systemd services and survive a disconnected caller. The source ZIP and JSON argv recipe are trusted inputs, not a general sandbox. Job commands, output collection, cancellation and shutdown use saved identity and a bounded execution/host deadline. Work callers must inspect the original job ID rather than resubmit a replacement after losing a command response.

The gateway adds a second identity layer: a uniquely bound external request/owned workspace and exact image-build operation ID. Its durable dispatch captures the deployment checkout and provenance pin digest before a remote SSM command, then maps accepted operation states to the returned image-build receipt. Passing queue admission never by itself proves a compiler stage ran. See [gateway](compiler-gateway-and-dispatch.md).

## Source pin versus recipe snapshot

The **original monthly provenance pin** identifies the committed source selection under the deployed repository. It differs from a later materialized recipe-snapshot pin bundled for an image-build pipeline. The gateway must verify the deployed source checkout and original pin bytes, while image-build independently validates its consumed snapshot; the two hashes must not be conflated.

No writer may update a running lane's source or controller data to accommodate a new monthly pin under an existing operation. A new source/review creates new immutable inputs and authorized new work.

## Artifact publication and transfers

Separate source/test output identities, temporary uploads, frozen result archives and published artifact references. The [resumable transfer implementation](../ARTIFACTS.md) verifies prefixes/content digests and atomically publishes complete objects. A lost chunk reply should not change the artifact identity. SSM byte limits are still present; the filesystem artifact store can serve as an explicit test backend, while S3 support and live acceptance carry their own permissions and constraints. Checkpoints of the workspace do not automatically preserve partial local result bytes.

## Resource and cost boundaries

Lane admission tracks memory/tasks/CPU weight, durable disk reservation, root-control socket and command deadlines. A shared host can still be exhausted by incorrectly accounted workloads, so resource plans must be reviewed globally before admitting concurrent jobs. The guest's uptime timer protects against some abandoned runs but is not AWS-guaranteed cost enforcement; the future cloud-side shutdown plan is separate. Stopping a host with active or uncertain jobs requires explicit safety handling.

## Exact reference material

- [Image-build lane identity and reservations](../IMAGE-BUILD-LANES.md)
- [Generic background job lifecycle](../JOBS.md)
- [Artifact transfer and publication](../ARTIFACTS.md)
- [Gateway dispatch and durable SSM identity](../GATEWAY-DISPATCH.md)
- [Cloud deadline limits](../CLOUD-DEADLINE.md)
- [Recovery/reboot runbook](recovery-reboot-and-runbooks.md)

Source-level tests and preparation cannot establish live performance, resource isolation under contention or complete cloud-credential authorization. Retain those as external acceptance requirements.
