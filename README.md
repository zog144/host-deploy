# host-deploy

**Development source only.** Publishing this repository does not enable an AWS
execution gateway, change live IAM/SQS/SSM/DNS, approve compiled binaries or
rootfs downloads, or authorize live deployment with public companion revisions.
Public source operation and live gateway activation have separate authorization
and acceptance gates; see [migration boundaries](docs/host-deploy/PUBLIC-MIGRATION-BOUNDARY.md).


**Documentation:** [technical manual](docs/host-deploy/README.md) · [architecture](docs/host-deploy/architecture.md) · [verification and evidence](docs/host-deploy/verification.md). These consolidate current boundaries while preserving historical implementation-pass reports and their original acceptance scope.

Host-deploy provisions and manages workspace-owned AWS EC2 development hosts,
runs durable background jobs through AWS Systems Manager (SSM), and collects
verified results. Zog uses it for box-control/systemd acceptance, image-build
compilation hosts, reboot tests, and installing the host-discover beaconer.
It is infrastructure tooling, not the application runtime controller.

Current package version: **0.10.6**. The exact six public companion revisions
are frozen in [the publisher manifest](public-companion-publisher.json).
Their 2,187 tracked files and all 90 beacon file hashes have been verified;
the selected beacon packages build and install together as host-identify 0.3.4,
host-discover 0.4.9 and host-install 0.10.0. Source, package and confined native
fixture acceptance passed. No companion source is vendored.

These checks do not authorize production deployment or establish full live
STATE/mount/NSS, issuer, or reboot integration. Historical revisions in the
runtime guides describe earlier compatibility checkpoints; they are not the
current public source selector. See [companion scope](docs/host-deploy/PUBLIC-COMPANIONS.md).

## Requirements and installation

The local controller needs Linux, Python 3.11+, boto3, outbound AWS API access,
and your own AWS credentials. AWS CLI is optional. Targets need an SSM-capable
image/agent, an instance profile, network access to SSM, and systemd for jobs.
Signed beacon installation additionally requires an existing Python 3.12+
interpreter with venv/pip on the target.

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e . pytest
host-deploy --help
host-deploy init --workspace /work/compiler-state --name compiler --profile zog-development --region us-east-1
host-deploy doctor --workspace /work/compiler-state
```

These commands assume a configured AWS profile. `credentials-import` can import
an explicitly supplied credential file; keep it outside the source tree. For an
isolated environment plus workspace setup, the repository's `bootstrap.py` is
an alternative; see `python bootstrap.py --help` and
[authentication](docs/host-deploy/AUTHENTICATION.md).

AWS subnet, security group, image and instance profile must already exist.
The tool does not create the account's networking or IAM setup. Permissions must
cover the selected EC2/SSM operations, plus optional S3 workflows. `doctor` checks
STS identity and EC2 read access, not every permission needed by later mutations.

## Provision a host

Copy and edit `examples/systemd-host.json` for your own account and region. Its
AMI/subnet/security-group/profile values are deployment-specific examples.
Choose compute, disk and `maximum_uptime_minutes` for the work: the small sample
host is not a full-toolchain build specification.

```sh
host-deploy provision --workspace /work/compiler-state --spec /work/host.json --no-discovery --dry-run
host-deploy provision --workspace /work/compiler-state --spec /work/host.json --no-discovery
host-deploy start --workspace /work/compiler-state
host-deploy status --workspace /work/compiler-state
```

Provisioning creates billable resources. `start` waits for EC2, SSM, cloud-init
and the configured uptime timer. `--no-discovery` permits host/image preparation
before the Python 3.12 and command-center prerequisites exist. Provisioning
otherwise enables discovery and requires explicit registry readiness configuration.

Each initialized workspace gets a stable UUID and one host. Saved account identity
and the `ManagedBy=host-deploy` / `ZogWorkspace` tags guard later operations.
Repeated provisioning recovers the recorded launch; it does not silently allocate
a replacement after termination. Initialize a new workspace for a new host.
Use checkpoint handoff to transfer ownership between environments rather than
operating cloned workspace copies concurrently.

## Jobs, recovery and shutdown

A job recipe describes argv, environment, timeout and result paths; see
`examples/background-job.json`, [starter recipes](docs/host-deploy/STARTER-RECIPES.md) and
[jobs](docs/host-deploy/JOBS.md). The ZIP must contain the files the recipe invokes.

```sh
host-deploy job-submit --workspace /work/compiler-state --job build-1 --source /work/source.zip --recipe /work/recipe.json
host-deploy job-status --workspace /work/compiler-state --job build-1
host-deploy job-collect --workspace /work/compiler-state --job build-1 --output /work/build-results
```

Jobs run under remote systemd supervision and can outlive the calling Work
session. Preserve local job records before reconnecting; inspect an existing job
before submitting another. `job-cancel` targets a recorded job. Generic jobs do
not automatically stop their host. SSM transfer has size limits; use the optional
S3 backend for larger payloads after configuring [S3 storage](docs/host-deploy/S3.md).

| Commands | Purpose |
| --- | --- |
| `checkpoint-export`, `checkpoint-restore` | Transfer durable workspace/job state; `--handoff` retires the sender |
| `reboot-submit`, `reboot-status`, `reboot-resume`, `reboot-collect`, `reboot-abandon` | Two-phase reboot acceptance and explicit recovery |
| `job-publish`, `storage-results`, `storage-fetch` | Publish/recover results through configured S3 storage |
| `artifact-init`, `artifact-publish`, `artifact-fetch`, `artifact-prune` | Local artifact-store workflow |
| `run`, `recover` | Older dedicated systemd acceptance ZIP workflow |
| `doctor --remote` | Inspect tools on an already running owned host |

Each subcommand supports `--help`. See [recovery](docs/host-deploy/RECOVERY.md),
[reboots](docs/host-deploy/REBOOT.md) and [artifacts](docs/host-deploy/ARTIFACTS.md) before those workflows.
The older `run` command expects its historical bundle layout; use generic jobs
with an explicit recipe for current component checkouts.

```sh
host-deploy stop --workspace /work/compiler-state
host-deploy terminate --workspace /work/compiler-state --instance-id i-EXACT-OWNED-INSTANCE
```

Stop retains billable EBS storage. Terminate deletes the selected owned instance
and its root disk. Stop/terminate reject active or uncertain jobs unless the
operator explicitly requests `--force`. The host uptime timer is a local systemd
power-off mechanism, not an AWS-side guaranteed deadline or spending cap.

## Signed discovery

Before installation, retrieve the exact companions:

```sh
# Retrieve exact compatible public source revisions for host-identify, host-discover and host-install.
# See docs/host-deploy/PUBLIC-COMPANIONS.md; historical private pins are not valid in the new public repositories.
```

Pass `/work/dependencies/zog144` as --source (or set
HOST_DEPLOY_SOURCE_DIRECTORY). The installer checks each allowlisted source file
against beacon_sources.json before any remote upload. Added unlisted files are
not shipped; changed, missing or symlinked required files are rejected. The
deterministic payload records both commits and uses the canonical service unit.
This source change has local compatibility tests; it is not a live deployment.


With the matching command-center protocol/database deployed and the owned host
running with Python 3.12+, install its beaconer:

```sh
host-deploy host-install --source /work/dependencies/zog144 --workspace /work/compiler-state --server-ready --server https://registry.example.test --system-ca
host-deploy discover-status --workspace /work/compiler-state
```

Replace the example HTTPS origin. `host-install` and `install-discover` are
aliases. `--server-ready` acknowledges the server prerequisites; it does not
migrate or verify its database. Compare the public fingerprint through a trusted
channel and explicitly approve the exact key in station-access. Service-active,
pending, binding-received and signed-accepted are distinct states.

For an existing host, use the [discovery migration procedure](docs/host-deploy/DISCOVERY.md),
including `--migrate` where required. Preserve its identity and registry UUID.
Installation never approves a fingerprint, elects an archive provider, or grants
archive access. Registry endpoint defaults are specific to the Zog development
environment; configure your own deployment explicitly.

## Source and persisted state

`src/zog/host_deploy/` contains the CLI, AWS provisioning, job/reboot/recovery code and
the verified payload assembler `beacon_payload.py`. `examples/` holds host/recipe examples; `tests/` holds local
fixtures. Install from the current source package as shown above. This component
project is for development and validation only and is blocked from direct PyPI
upload; public Python publication is through the aggregate `zog` distribution
assembled by `release-build`. Generated component wheels are build artifacts and
are not kept in this source repository; build them into an external output
directory when local validation requires a wheel.

A workspace's `workspace.json`, `launch.json`, `host.json`, job records and result
manifests are recovery inputs. Keep workspace state outside this repository.
On target hosts, beacon releases live beneath `/opt/host-discover/releases`,
private identity state beneath `/var/lib/host-discover/identity`, and scoped
consumer credentials beneath `/var/lib/host-discover/credentials`. Do not copy
those identities into reusable images or source archives.

## Tests and limitations

```sh
python -m pytest -q tests
```

The local suite exercises AWS/SSM fixtures, activation failure, ownership,
transfer, job and recovery logic without provisioning hosts. Live acceptance is
separate; the dated `ACCEPTANCE*.md` files report the checks actually performed.

AWS is the implemented cloud provider. Cross-machine distributed workspace
locking, automatic remote-state backups, remote-directory pruning, guaranteed
cloud-side deadlines, and a complete archive-mirror/rootfs deployment are not
provided. Preserve failure evidence and inspect uncertain launch outcomes rather
than deleting saved intent and retrying a fresh launch.

## Local verification

Retrieve the pinned companion sources as above, then run:

```sh
HOST_DEPLOY_SOURCE_DIRECTORY=/work/dependencies/zog144 python -m pytest -q tests
```

The suite checks payload integrity and the actual installer probe with the selected
beacon in pending, binding-received and signed-accepted states using local fixtures.
It does not contact AWS or prove live service activation.

Station-access integration: [bounded deployment jobs](docs/host-deploy/STATION-DEPLOYMENT-JOBS.md).

## Explicit deployment configuration

Host-deploy 0.10.6 retains the 0.10.5 explicit-configuration boundary: it has no default command-center domain or bundled live registry
workspace. Copy and edit [the daemon example](examples/host-discover.example.json)
and select it with `--configuration-file`. For automatic enrollment during
provisioning, use [the provisioning example](examples/registry-provision.example.json).
Keep real configuration outside the source checkout. Existing signed installations
retain their configured server when no replacement is supplied. See [DISCOVERY.md](docs/host-deploy/DISCOVERY.md)
for migration identity checks and readiness prerequisites.


Private integration evidence and historical source pins are maintained separately;
they are not included in this public development-source tree.

## Prepared image-build lane Python binding (Pass 4)

Managed image-build gateway dispatches use lane specification schema 4. The
server-controlled `python_executable` is an absolute target-host path such as
`/usr/bin/python3.12`. It is persisted with the lane, frozen in each newly
prepared dispatch, and used for both the SSM receipt wrapper and image-build
producer. Request and GitHub-issue callers cannot select an interpreter.

For a **prepared, unactivated, managed schema-3 lane only**, an operator may
upgrade the exact retained specification with `lane-bind-python`. The operation
does not contact or mutate the compiler host, does not activate a lane, and does
not change an existing gateway request or dispatch. Inspect the original record
and compute its canonical specification SHA-256:

```sh
host-deploy lane-inspect --workspace /path/to/adopted-workspace --lane gateway-pass4-readonly > /tmp/lane-before.json
python3 -c 'import hashlib,json,sys; s=json.load(open(sys.argv[1]))["specification"]; print("sha256:"+hashlib.sha256(json.dumps(s,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")).hexdigest())' /tmp/lane-before.json
```

Supply the printed digest **and** the approved target-host interpreter path:

```sh
host-deploy lane-bind-python \
  --workspace /path/to/adopted-workspace \
  --lane gateway-pass4-readonly \
  --python-executable /usr/bin/python3.12 \
  --expected-specification-sha256 sha256:<original-specification-digest>
```

The saved `runtime_binding_upgrade` retains the original schema and
specification digest. Identical retries are read-only; conflicting retries,
stale digests, symlinked records, reservation-only lanes, active/retired lanes,
and partly initialized records are rejected. Schema-3 records remain readable.
Prepared schema-1 gateway dispatch bindings are never rewritten or newly
submitted by the schema-2 runtime path; existing submitted operations remain
observable for recovery.

After the explicit migration, verify the installed interpreter and imports
and activate the lane under its existing ownership guard. No replacement
workspace adoption or build submission is implied by this procedure. A
different interpreter for an active lane requires a separately reviewed
replacement/retirement procedure, not direct JSON editing.


## Gateway Pass-4 runtime closure preflight

A successful import of `zog.image_build.remote_operations` alone does **not**
prove that the retained CLI operation can run: provenance imports
`zog.build_record` later during `Provenance.capture_pin`. Before an explicit
gateway dispatch crosses the durable `submitting` boundary, `host-deploy`
now probes the bound Python interpreter for the capabilities selected by its
**immutable producer argv**:

- `--provenance-pin`: import `zog.build_record` and verify `make_record`,
  `Store`, and `model.digest`.
- `--provenance-host-id`: import the declared `zog.host_identify` component.
- `--controller-config`: import `zog.box_control` and its required
  `RootControlSystemdTransport` and controller API. Read-only historical
  `--observed-state-dir` operations do not select the controller check.

The probe imports modules and reports resolved module paths; it does not call
`remote_operations.main`, capture provenance, create a pipeline, or write
build state. Python bytecode writes are suppressed for this check. A failed
import/API check leaves a **prepared** dispatch prepared: there is no producer
SSM submission, no SSM CommandId, and no automatic retry. The bounded
preflight itself is a separate SSM observation on the existing owned host.

Installation remains a *reviewed deployment responsibility*, not an automatic
`pip install` side effect of the dispatch. For the pinned image-build
`3ac6f5c086227d4781608f28f76583e2d24ddac6`, its
`zog-component.json` declares `box-control`, `build-record`, and
`host-identify`. Build-record's public component manifest has no further
Zog component dependencies, but the complete approved closure must include
transitive external requirements. Prepare an explicit manifest of exact
companion Git revisions and/or immutable wheel SHA-256s, their dependency
closure, selected interpreter path, import-path observations, and installation
commands. Install only from those approved artifacts into the lane's bound
interpreter environment (for Pass 4, `/usr/bin/python3.12`), never from moving
sibling heads or by changing the system-default `python3` executable.

This source-level check cannot attest a companion's source commit merely from
an importable module or reported package version. The Work connection must
verify each installed artifact against its approved pin and record evidence.
The retained failed gateway request and its CommandId must not be replayed,
reset, or modified; a corrected read-only inspection requires a newly
authorized request. Producer-side smoke coverage for real CLI startup and
provenance capture belongs in the exact-companion image-build test matrix.


### Producer-owned runtime preflight (Pass-4 follow-up)

Beginning with the reviewed producer source
`zog144/image-build@cba7107d1f1165262ce5f291001751c03ef742ff`,
`host-deploy` consumes `image-build-runtime-preflight-v1` rather than
considering a generic module import sufficient. The immutable selected
interpreter is used to execute:

```text
python -B -m zog.image_build.runtime_preflight
```

The binding is **schema 3** and includes the operation profile, exact
image-build source revision, selected interpreter, and explicitly bound
build-record checkout. For the external historical `pipeline.inspect`,
the producer profile requires only build-record: compatibility checkpoint
`zog144/build-record@771af9429e83da40fd503625a6b4ba8329acee35`,
version 0.8.2. It must be staged below the lane-owned
`<project-root>/companions/build-record` as an exact, clean checkout with
its required `src` directory. Host-deploy checks both Git HEAD identities
and clean checkouts before invoking the producer-owned preflight.

The existing active lane may bind its reviewed companion exactly once by
the explicit operator command below, provided it already binds the matching
new producer revision. **Do not rewrite the active lane's image-build revision
to migrate an old checkout**, and do not re-adopt the host. If the producer
revision does not match, stop for a reviewed new-lane/replacement plan.

```sh
host-deploy lane-bind-companion \
  --workspace /path/to/owned-workspace \
  --lane gateway-pass4-readonly \
  --producer-revision cba7107d1f1165262ce5f291001751c03ef742ff \
  --repository zog144/build-record \
  --revision 771af9429e83da40fd503625a6b4ba8329acee35 \
  --source-root /var/lib/zog/image-build-lanes/gateway-pass4-readonly/companions/build-record \
  --expected-specification-sha256 sha256:<verified-current-lane-spec-digest>
```

This metadata operation is local and never installs dependencies or submits
a compiler command. Deploying/staging the exact companion checkout is an
independent reviewed host-deploy Work operation. The remote preflight runs
while the dispatch is still prepared, and its bounded readiness report
is retained separately in the gateway request's `runtime-preflight.json`
journal with the immutable binding digest. A failed probe leaves the dispatch
prepared; it does not submit the producer request. The probe itself is a
separate authenticated/ownership-guarded SSM command.

For controller-backed mode, producer compatibility additionally pins
`box-control@c8e65abde37d6e2d9ce6fd3622e289826a253642` at the
lane's `companions/box-control` checkout with source path
`box-control/src`, and `dbus-next==0.2.3` in the selected Python
environment. These are **not** required for external historical
`pipeline.inspect`. They must be staged and validated independently.

Existing schema-1/2 dispatch bindings remain readable for observation;
their prepared variants are not submitted under the new producer-preflight
contract. Previously failed production requests and their recorded SSM CommandIds must
remain untouched; use the operator's protected ledger to identify them.
A corrected inspection needs a fresh authorized gateway request.
