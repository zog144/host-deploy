# Concurrent image-build lanes

Host-deploy can track multiple independent image-build/box-control projects on one
development host. A lane is an execution namespace, not a compiler stage.

Each lane binds:

- a unique lane/project basename;
- an exact authorized source repository and immutable commit;
- the image-build-owned repository-relative path to the original reviewed monthly provenance pin;
- the exact `sha256:` identity of that monthly pin's bytes;
- explicit provenance host/project scopes;
- per-build MemoryMax, TasksMax and CPUWeight;
- a disk reservation;
- the root-control socket and finite-build deadlines.

Before remote execution, host-deploy verifies the exact bound monthly-pin path/digest inside the clean checkout and image-build independently validates/captures the same explicit `--provenance-pin` through build-record provenance. The monthly provenance pin is distinct from any later materialized recipe-snapshot `commit-pin.py`. A lane has its own project root and state:

```text
/var/lib/zog/image-build-lanes/<lane>/
    controller.json
    source/
    state/
        image-build/
        build-job/
        build-resource/
```

Mutable pipeline, attempt, generation and controller state is never shared between
lanes. The host/root-control daemon, archive-mirror and underlying EC2 hardware may be
shared.

## Existing Work lane

An already-running Work-owned project can be represented without host-deploy
modifying it. Use the historical lane `mode: "reservation"` with that project's
actual absolute root and the disk reservation it needs. The mode name is retained
for compatibility; it does not reserve host RAM.

Activating a reservation-only lane checks disk admission and retains the identity
record only: it does not create directories, upload `controller.json`, change the
Work source checkout, or enable remote operations for that lane. This is the recommended transition for the
current `zog-compiler-view` project while the regular-chat rebuild uses a new
`mode: "managed"` lane.

## Commands

Prepare a durable lane specification without touching the host:

```sh
host-deploy lane-prepare --workspace HOST --lane rebuild-oct1 --spec lane.json
```

Activate it after capacity admission:

```sh
host-deploy lane-activate --workspace HOST --lane rebuild-oct1
```

Activation checks the active lane disk reservations against observed filesystem free
space; it does not sum per-lane memory values, measure host RAM or use either to deny
activation. Managed-lane activation creates project/state/source directories and
installs a nonsecret controller configuration. It does not fetch source or start a
compiler.

Inspect or retire admission:

```sh
host-deploy lane-inspect --workspace HOST --lane rebuild-oct1
host-deploy lane-retire --workspace HOST --lane rebuild-oct1
```

Retirement does not delete state.

`lane-command` produces the exact argv for the image-build remote-operation adapter.
The command uses `PYTHONPATH=<lane-source>/src` so execution comes from the lane's
deployed source checkout, not an unrelated globally installed image-build.

## Scheduling

The finite build request supports optional systemd `CPUWeight` in addition to the
existing MemoryMax/TasksMax. Because one image-build lane serializes its pipeline
command checkpoints, per-job weight provides the initial lane scheduling priority.

A normal policy for concurrent development is:

- leading Work lane: independently reviewed CPU and runtime-memory policy;
- clean/rebuild lane: lower CPU weight, a separately verified runtime memory limit
  where the controller actually applies one, and lower compiler parallelism.

CPUWeight is work-conserving: the rebuild may use idle CPU but yields relative share
when leading-edge work is active.

### Compatibility and runtime-limit boundary

There is **no lane schema migration**. Schemas 1-4 retain their exact
`resource_policy.memory_maximum_bytes` key, validation, serialized bytes and
specification SHA-256 identity. It is deprecated **as an aggregate reservation
or host-capacity guarantee**. Managed lanes still pass it unmodified as
`resource_limits["memory-maximum-bytes"]` to the controller; that is a
*requested per-execution setting*, whose actual systemd/cgroup enforcement must
be verified by the execution-control owner on the selected runtime. On
reservation-only lanes the value is legacy bookkeeping and cannot constrain
the separately owned Work project. Neither value gates lane activation.

Existing lane files are never rewritten by this source update. Historical
`record.capacity.memory_bytes` values remain readable; new activation capacity
snapshots contain `disk_free_bytes` only. Disk reservation checks remain.
Do not confuse the configured controller request with evidence that a live
compilation was limited. Observe the actual transient service/cgroup's
`MemoryMax`/`memory.max` (and applicable job/scope identity) during native acceptance.

Disk remains separately admitted because independent lanes retain independent roots,
attempts and generations. Cross-lane source-byte reuse should happen through
archive-mirror rather than writable cache/state sharing.

## Gateway boundary

SQS/GitHub authorization remains outside this module. The gateway may:

1. authorize and materialize an exact repository commit for a lane;
2. write a versioned image-build remote request;
3. execute the argv returned by `remote_operation_argv`;
4. publish the bounded JSON result;
5. repeat inspection/resume using the same lane and operation identities.

A dispatcher restart never authorizes a replacement image-build pipeline. Recovery is
performed by `zog.image_build.remote_operations` against durable lane state.

An existing Work project can be represented as a lane using its existing absolute
project root, provided its basename is unique. Preparing/recording that lane does not
move its state.


## Read-only external observation state

Lane specification schema 3 adds an optional server-owned `observed_state_dir`.

When absent, the managed lane behaves normally: image-build reads and writes its own
isolated `state_dir` and receives the lane controller configuration.

When present:

- the value must be an absolute path and must differ from the lane control state;
- the lane remains managed and owns its normal isolated project/state/source paths;
- `remote_operation_argv()` passes `--observed-state-dir <path>`;
- `--controller-config` is deliberately omitted for that remote operation;
- host-deploy gateway dispatch permits only `build.status -> pipeline.inspect`;
- resume, cancel and submit are rejected before SSM mutation;
- the observed path is frozen in the immutable gateway dispatch binding and cannot
  be substituted after preparation.

Image-build owns the final live path checks and read-only semantics. Host-deploy
does not copy, symlink or import retained pipeline evidence into the isolated lane.

Historical schema-2 lanes remain executable without external observation state.
Schema-1 lanes remain readable but cannot execute pass-4 remote operations because
they lack the explicit monthly provenance-pin descriptor.

## First Fonts source-owned profile

The first Fonts managed-lane identity is reserved for the reviewed
`fonts-lane-profile` / `fonts-lane-verify` / `fonts-lane-prepare` /
`fonts-lane-activate` workflow; unlike a generic `lane-prepare --spec`, it
never accepts a caller-generated full specification. See
[the first Fonts source-owned preparation contract](FIRST-FONTS-SOURCE-OWNED-LANE-PROFILE-2026-11-13.md).
Preparation is local and does not activate a Host or prove worker resource limits.
