# Station/archive production owner contract — 2026-10-13

**Status:** Illustrative public product contract, not a runnable deployment recipe.
Every REVIEWED_/REPLACE_WITH_ placeholder must be replaced using independently
approved current-host evidence. No commands in this document authorize
operations against an existing host. Source and test implementation only. No deployment, portal switch,
rootfs rebuild, archive placement or live certificate issuance is implied.

This contract implements the host-deploy work in the archive-mirror owner handoff.
It does **not** put archive-mirror under a second boot supervisor. Portal requests
are independent of role selection; archive start/stop belongs to host-discover,
after an actual elected role, valid renewed lease and ready storage.

## Supported components

- \`zog.station_access.production_composition.render\` prepares the two exact
  application specifications, with pinned \`software_view\` and mandatory archive
  ownership guard.
- \`zog.box_control.BoxControl(Project(...))\` provides actual
  \`application_preparation\`, \`issue_application_request_id\`,
  \`request_application_launch\`, \`application_request_result\`, and root-control
  mount/credential observations. Do not manipulate project state files directly.
- \`zog.archive_mirror.storage_ownership bind\` binds a reviewed archive
  preparation revision to the *actual controller-issued* storage/grant values.
- \`host-discover\` must become the exclusive role-driven archive launcher. The
  controller only executes bounded selected application lifecycle requests.
- \`zog.host_deploy.station_production\` freezes a reviewable production
  composition and can submit **only the independent station portal** at boot.

Do not use the rehearsal's root-only project directory, local custom socket,
fabricated storage ID, blanket \`chown -R\`, or a replacement host-deploy
compiler workspace.

## Immutable production composition

The operator first creates an empty, owned project directory inside the
dedicated *non-root* controller account's home. A root-controlled service
must already provision the approved project access, identity grants and
\`/etc/zog/host-bindings.json\`. The application templates must already have
been rendered into this intended project by station-access's supported
composition command.

Prepare a JSON manifest with these **required exact** top-level fields
and no extra keys:

\`\`\`json
{
  "schema": "zog-host-deploy-station-production-v1",
  "project": {
    "root": "<absolute-unprivileged-home>/project",
    "home": "<absolute-unprivileged-home>",
    "service_user": "<actual-nonroot-project-owner>",
    "controller": "box-control/RootControlSystemdTransport"
  },
  "sources": {
    "station-access": "<40-hex-commit>",
    "archive-mirror": "<40-hex-commit>",
    "box-control": "<40-hex-commit>",
    "root-control": "<40-hex-commit>",
    "host-discover": "<40-hex-commit>",
    "image-build": "<40-hex-commit>"
  },
  "image": {
    "rootfs": "sha256:<64-hex>",
    "generation": "<actual-controller-generation>"
  },
  "applications": {
    "station-access": {
      "specification_sha256": "sha256:<64-hex>",
      "software_view": "sha256:<64-hex>",
      "storage_id": "<32-hex-controller-id>",
      "grant": {"grant_id": "<32-hex>", "grant_version": 1, "uid": 10001, "gid": 10001},
      "mount": {
        "path": "<absolute-under-project-root>/state/<real-station-storage>",
        "device": 1, "inode": 1
      },
      "preparation_revision": "<real-preparation-revision>"
    },
    "archive-mirror": {
      "specification_sha256": "sha256:<64-hex>",
      "software_view": "sha256:<64-hex>",
      "storage_id": "<different-32-hex-controller-id>",
      "grant": {"grant_id": "<different-32-hex>", "grant_version": 1, "uid": 10002, "gid": 10002},
      "mount": {
        "path": "<absolute-under-project-root>/state/<real-archive-storage>",
        "device": 2, "inode": 2
      },
      "preparation_revision": "<actual-archive-ownership-binding-revision>"
    }
  },
  "host_bindings": {
    "policy_sha256": "sha256:<digest-of-root-owned-policy>",
    "mirror_live": "/run/zog-host/mirror-live"
  },
  "compiler_rpc": {
    "config_directory": "/var/lib/station-access/compiler-rpc",
    "workspace_id": "<already-adopted-workspace>",
    "ownership_epoch": "<existing-ownership-epoch>",
    "scopes": ["compiler.status", "dispatch.status"]
  },
  "services": {
    "station": "boot-independent",
    "archive": "host-discover-lease-selected",
    "root_control": "systemd",
    "box_control": "controller-requests"
  }
}
\`\`\`

**All angle-bracket values and example device/inode numbers are
non-deployable placeholders.** The actual storage IDs, grant IDs and
mount identities must be read from controller/root-control acceptance
evidence and checked against the live filesystem. Do not manufacture them.
The compiler workspace/epoch must come from the retained owner, not user input.
Do not put secret bytes into this manifest.

## Deployment and recovery procedure

After rendering and reviewing both software views, run the supported empty
preparation through box-control for both applications. Copy production
state into **new, separate persistent** destination mounts using the
supported two-destination migration interface. Submit a separately reviewed
archive application specification with a *new* preparation revision that
invokes \`zog.archive_mirror.storage_ownership bind\` using real issued IDs,
then refresh that preparation until **ready**.

Record the exact image generation, software view digests, application
spec digests, grant IDs/UIDs and persistent storage IDs/devices/inodes.
Use a new non-root-owned directory for the production manifest journal:

\`\`\`sh
host-deploy-station-production prepare \
  --directory /home/REVIEWED_CONTROLLER_USER/.local/state/zog-station-production \
  --manifest /secure/operator-reviewed/production-manifest.json

host-deploy-station-production inspect \
  --directory /home/REVIEWED_CONTROLLER_USER/.local/state/zog-station-production
\`\`\`

### Controller execution grant field mapping

The manifest records `grant.grant_version` while the authoritative box-control
`zog-execution-identity-v1` execution binding records `version`. These are
the same version identity, **not** two separate version numbers. The
`preparation_gate` compares the manifest's `grant_version` to the producer's
numeric `version`, alongside exact `schema`, `project`, `application`,
`grant_id`, numeric `uid` and numeric `gid`. A missing, wrongly typed or
mismatched field blocks launch with `persistent-identity-mismatch`. Do not
rewrite box-control's authority records or the already-prepared production
manifest to adjust this mapping.

On an isolated acceptance host, Work should run the manifest gate against
`/home/REVIEWED_CONTROLLER_USER/station-project/state/REVIEWED_DEPLOYMENT_JOURNAL`
using the intended `BoxControl(Project("/home/REVIEWED_CONTROLLER_USER/station-project"))`
instance. Confirm both application preparations independently and retain the
unchanged manifest digest. This verification does not authorize the station
boot unit, archive broker, or port-443 traffic switch. Historical owner-specific preparation and cutover evidence is retained privately; these placeholders are not permission to operate on any deployed project.

The retained manifest is immutable. Identical apply is idempotent. A
changed source, software view, grant, storage, project or epoch is **blocked**
until an explicit newly reviewed migration; no implicit overwrite or new
storage initialization.

## Explicit controller runtime binding and bounded evaluation

The root-control transport must be an independently reviewed dedicated Unix socket, such as
`/run/REVIEWED_ROOT_CONTROL_INSTANCE/control.sock`, **not** box-control's default
`/run/zog/root-control.sock`. For illustration only, the reviewed image generation is
`REVIEWED_PUBLISHED_GENERATION_DIGEST`.
An example controlled project is
`/home/REVIEWED_CONTROLLER_USER/station-project` (service reviewed non-root service UID/GID).
The expected manifest digest is
`sha256:REVIEWED_MANIFEST_DIGEST`.

Provision a **root-owned, non-group/world-writable, regular** JSON binding at
`/etc/zog/station-production-controller.json`, with exact fields (no extras):

```json
{
  "schema": "zog-station-controller-runtime-v1",
  "project_root": "/home/REVIEWED_CONTROLLER_USER/station-project",
  "service_user": "<reviewed-controller-user>",
  "generation": "REVIEWED_PUBLISHED_GENERATION_DIGEST",
  "manifest_sha256": "sha256:REVIEWED_MANIFEST_DIGEST",
  "root_control_socket": "/run/REVIEWED_ROOT_CONTROL_INSTANCE/control.sock",
  "python_executable": "/usr/bin/python3.12"
}
```

The command reads the existing manifest, verifies every binding field, checks
the **actual running** interpreter path, refuses a symlinked or missing socket,
and then constructs `BoxControl(Project(exact_project),
systemd_transport=RootControlSystemdTransport(exact_socket),
image_provider=PinnedPublishedImage(exact_generation))`. The public
`published_selection` contract checks the actual immutable image generation.
No active-image fallback, default socket substitution, or source checkout
substitution is permitted. The project remains under the reviewed non-root UID.

The controller issues opaque signed `r1-<hex-time>-<32-hex>-<64-hex-HMAC>`
request identities (112-ish characters); host-deploy preserves them **whole**.
New issuance requires the reviewed shape; existing retained legacy controller
IDs remain replayable only through the controller's own authentication and
retention rules, within the producer's bounded 200-character envelope.
Host-deploy does **not** generate, modify, verify HMAC, shorten or re-sign
controller identities. It persists the exact issued identity before requesting
a launch, and lost replies reuse the same retained identity. A new boot ID
requires a prior durable, satisfied result; uncertain outcomes block a new
request rather than producing a duplicate.

Use this read-only preparation/host-path gate plus a single explicit boot request
only after Work confirms no unapproved replacement of the running portal:

```sh
/usr/bin/python3.12 -B -m zog.host_deploy.station_production inspect \
  --directory /home/REVIEWED_CONTROLLER_USER/station-project/state/REVIEWED_DEPLOYMENT_JOURNAL

/usr/bin/python3.12 -B -m zog.host_deploy.station_production boot-request \
  --directory /home/REVIEWED_CONTROLLER_USER/station-project/state/REVIEWED_DEPLOYMENT_JOURNAL \
  --controller-binding /etc/zog/station-production-controller.json

/usr/bin/python3.12 -B -m zog.host_deploy.station_production evaluate \
  --directory /home/REVIEWED_CONTROLLER_USER/station-project/state/REVIEWED_DEPLOYMENT_JOURNAL \
  --controller-binding /etc/zog/station-production-controller.json
```

The first step is read-only. The boot command queues a durable, idempotent
**station-only** request; it does not itself evaluate or prove the portal is
serving. The evaluator calls the existing `BoxControl.evaluate` contract
through the dedicated socket, using box-control's project lock, root-control
reconnection, published generation and recovery semantics. Each invocation
must complete successfully inside the systemd timeout; all errors fail closed.
The evaluator does **not** select archive roles, issue archive launch requests,
or override host-discover's exclusive signed-lease authority. Station preparation
and mount gates remain independent of archive preparation and lease election.
Archive readiness remains a separate cutover prerequisite.

Three units are packaged:

- `station-portal@.service`: oneshot boot-request, root-control dependency,
  bounded on-failure retry using its retained controller ID.
- `station-evaluator@.service`: oneshot controlled evaluation, max 90 seconds.
- `station-evaluator@.timer`: starts evaluation after boot and again 1 minute
  after the previous invocation becomes inactive (no overlapping evaluations).

For the reviewed service identity, provision root-owned, nonsecret file
`/etc/zog/station-production-REPLACE_WITH_REVIEWED_USER.env` with the two fixed values:

```ini
ZOG_STATION_PLAN_DIRECTORY=/home/REVIEWED_CONTROLLER_USER/station-project/state/REVIEWED_DEPLOYMENT_JOURNAL
ZOG_STATION_CONTROLLER_BINDING=/etc/zog/station-production-controller.json
PYTHONPATH=/opt/zog/REVIEWED_HOST_DEPLOY_CHECKOUT/src:/opt/zog/REVIEWED_BOX_CONTROL_CHECKOUT/box-control/src:/opt/zog/REVIEWED_IMAGE_BUILD_CHECKOUT/src
```

The source-root placeholders must be replaced by the exact reviewed, verified
Git checkout paths staged by Work. No moving `unstable` paths or unpinned pip
packages. Stage all units from the same accepted host-deploy commit; supply
the unit files as `/etc/systemd/system/station-portal@.service`,
`/etc/systemd/system/station-evaluator@.service`, and
`/etc/systemd/system/station-evaluator@.timer`.

```sh
sudo systemctl daemon-reload
sudo systemctl cat zog-station-production-root-control.service
sudo systemctl cat station-portal@REPLACE_WITH_REVIEWED_USER.service
sudo systemctl cat station-evaluator@REPLACE_WITH_REVIEWED_USER.service
sudo systemctl cat station-evaluator@REPLACE_WITH_REVIEWED_USER.timer
```

**Inspect only; do not enable these units merely because the files exist.**
Work must separately confirm the dedicated root-control service dependency,
actual socket reachability under the reviewed non-root UID, published-generation availability,
import path identities, persistent manifest and observed device/inodes. A
reviewed operator action can then start/enable the units, record the exact
boot request token and evaluation results, test repeated starts and controller
reconnection, and perform a coordinated reboot. Production portal health
requires real HTTP/login and mount evidence, not a successful `evaluate`.

This command requires the exact reviewed station application.py SHA-256,
software-view selection, ready station portal preparation, matching station
grant/storage identity, current station host mount device/inode and the actual
current boot ID. **Archive preparation and role election never gate the shared
station portal boot.** Archive readiness is a separate host-discover lifecycle
gate; both applications must still pass their respective preparation and
mount checks before coordinated traffic cutover.

**No archive server or scheduler systemd boot unit** may be added.
Host-discover exclusively selects and withdraws the role.

Missing root-control grants/NSS activation, storage, preparation, mirrored
lease, ownership binder, certificate or trust, controller liveness and
kernel-mount backing must be reported as blocked by the respective
authoritative owner; do not infer readiness from this immutable manifest,
a queued launch, or from the existence of a path. The module's host-path
device/inode probe is only a preflight, **not** a guest kernel mount
observation. Work must additionally collect controller
\`observe_application_runtime_mounts\` and credentials from live launched
programs, plus real lease checks for archive server and scheduler.

## Distinct station compiler RPC identity and trust transition

The accepted RPC is already source-implemented and was isolated-test
accepted. Do **not** rebuild its protocol. Provision an independently
issued station-observer client certificate for the production app,
with only \`compiler.status\` and \`dispatch.status\` scopes.

The earlier acceptance CA *signing private key* was discarded. Create
new station client trust under a separately protected issuance authority,
and make an **additive** trust transition before revoking anything.
A replacement client CA file must contain every currently trusted CA plus
the newly approved station issuer. Do not remove the old CA or approved
client fingerprints in the first change.

Use \`host-deploy-rpc-identity-plan\` with the existing protected RPC JSON,
the old public trust bundle, the proposed additive trust bundle and the
new public client certificate:

\`\`\`sh
host-deploy-rpc-identity-plan \
  --server-config /etc/host-deploy/compiler-rpc.json \
  --new-client-certificate /secure/issued/station-observer.pem \
  --current-client-ca /etc/host-deploy/compiler-rpc/client-ca.pem \
  --additive-client-ca /secure/issued/client-ca-additive.pem
\`\`\`

This read-only tool checks X.509 chain trust and >=24-hour remaining client
validity using OpenSSL, calculates its DER SHA-256 fingerprint, ensures
the old trust certificate set is retained, and proposes the *existing*
server configuration plus exactly one observer-only fingerprint. It never
copies private keys or applies/reloads the server configuration.
Keep the resulting report restricted because it contains deployment
configuration paths (not private key bytes). Operator review, certificate
issuance, CA key retention, client key placement, server trust update and
actual restart/validation belong to host-deploy Work.

Station's protected client identity is provided under
\`/var/lib/station-access/compiler-rpc\` inside station-owned persistent
data and is checked by station-access under the actual station execution
UID; archive programs must not receive it. Preserve the original approved
server hostname/CA validation and all previously accepted client identities
during addition. The new trust bundle and server CA trust are separate:
do not silently change the **client's server-CA trust**. A subsequent
operator-reviewed step may revoke an old client fingerprint and remove
its CA when no approved users depend upon it; collect new/old success,
expiration and explicit revocation evidence first.

## Work acceptance and traffic switch

Owner operations, application placement and all live checks remain with the
host-deploy Work connection, coordinated with box-control/root-control and
host-discover. Recheck latest revisions and adopted owner before deployment.
Required live evidence includes:

- retained project, software selection and **distinct** stable storage
  identities; correct managed grants and NSS identity after restart;
- root-owned host binding policy and kernel-backed mounted identities;
- station portal independently launches and its real HTTP/login succeeds;
- host-discover publishes renewed lease evidence and exclusively places
  archive server + scheduler; withdrawal stops only archive and preserves
  station;
- proof archive ownership marker comes from actual controller-issued grant,
  and source database/archive copied from fresh quiesced checkpoint once;
- new observer mTLS principal reaches host-registry; old approved clients
  continue to work; expired/untrusted/wrong-scope/missing principal blocked;
- both controller and host reboot/recovery retain storage and known
  request identities, never duplicate launches or reconstruct unknown state.

The production switch still requires browser/CSRF/proxy acceptance and the
explicit single-writer final migration/cutover checkpoint. **Do not switch
nginx/443 or accept live production writes solely on the basis of these
source tests.** If the new DB has accepted writes, rollback must account for
those writes; restoring the old checkpoint blindly loses data.
