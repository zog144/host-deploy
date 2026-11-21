# First Fonts: inherited effective process identity (migration source draft)

**Selected architecture:** the GitHub → SQS → gateway → SSM → image-build →
box-control → root-control build path must not select a different user/group.
The original `gateway-first-fonts-runtime` schema-4 record, its previously
approved SHA-256 and project root remain **historical evidence only**. The
legacy execution fields (UID/GID 24202 and the owner path containing
`certbot-build-owner`) can no longer authorize execution or account creation.
No new named build owner or worker should be created.

## Verified blockers and ownership

- **host-deploy** historically includes `controller.execution_user_id` /
  `execution_group_id` in the lane schema, writes them in `_controller()`,
  and checked the chosen worker's passwd home before installing directories.
  The gateway could accept already-active legacy records independently of
  activation. The first Fonts gateway and activation paths now reject this
  old account-selection model. The new candidate controller schema 5 has
  `execution_identity: inherit` and no UID/GID selectors.
- **image-build** pinned producer `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`
  requires numeric user/group in `configuration.configured_runner()` and
  forwards them via `box_control_adapter.BoxControlExecutionAdapter` and
  `register_build_root`. This immutable producer is **not compatible** with
  schema 5. A revised reviewed producer and companion binding are required
  before activation; do **not** silently replace the retained source revision.
- **box-control** `build_protocol.canonical_request()` currently demands
  numeric UID/GID, mirroring the privileged backend. Owner must update the
  selected build request/registration contract and its checkpoint migration.
- **root-control** `build.canonical_request()`, `BuildBackend.register/prepare/start`
  currently accept the requested user/group, alter ownership and explicitly
  set transient systemd `User`/`Group`. Any inherited-identity implementation
  must derive its nonroot principal from the **authenticated executing peer**
  (e.g. verified kernel `SO_PEERCRED`), never arbitrary request fields. Systemd
  privilege separation must remain equivalent or stronger. A root-owned SSM
  agent/privileged daemon must never be mistaken for an unprivileged compiler.

## Supported host-deploy source-only preview

Once Work has found the **actual original** owning workspace with its approved
lane JSON (it may not synthesize one), the owner can run:

```sh
host-deploy fonts-lane-verify --workspace OWNER
host-deploy fonts-lane-migration-preview --workspace OWNER \
  --project-root /reviewed/accessible/location/gateway-first-fonts-runtime
```

This does not access AWS or change any Host. It verifies the historical full
specification SHA-256, original Host/workspace, source and monthly pin, and
reuses provenance and generic resource policy. It builds a schema-5 candidate
with the supplied, **explicitly reviewed project location**. This path must
not be guessed from an account's home. It reports the candidate full SHA-256,
original full SHA-256 and `status: review-required-not-executable`.

If the candidate is accepted for source review, save the **separate** staged
manifest, without replacing the historical lane:

```sh
host-deploy fonts-lane-migration-stage --workspace OWNER \
  --project-root /reviewed/accessible/location/gateway-first-fonts-runtime
```

The staged manifest is `OWNER/first-fonts-inherited-execution-migration-v1.json`.
Identical staging is idempotent; changing the selected path or digest rejects.
Neither command creates a project, changes filesystem ownership, activates a
lane, writes a controller, or submits a compilation. The original record is
retained byte-for-byte; its historical SHA-256 is not reused as the new digest.

**No deployable corrected digest can be reported until the actual historical
record and a compatible, immutable replacement image-build revision are
available.** The preview digest computed against the old producer is a
non-executable migration proposal, not a claim that the old source supports it.

## Effective filesystem authorization

Use `zog.host_deploy.effective_project_access.inspect(project_root)` from the
**actual nonroot process** intending to compile. The function obtains
`os.geteuid()/os.getegid()`, checks canonical path/traversal and effective
read/write/create permissions. It never queries NSS for a named alternate
account, switches user/group, creates directories or fixes ownership. It
rejects a privileged root process rather than quietly elevating compilation.
A root-owned SSM inspection is **not** a substitute for testing the executing
principal; the root-control owner must define the authenticated nonroot
service-to-build handoff before native acceptance.

## Migration completion (remaining program-owner work)

1. Approve compatible `image-build`, `box-control` and `root-control` source
   revisions, verifying that callers cannot provide a UID/GID override and
   that the new transient process runs only as its authenticated nonroot
   effective principal. Cover absent named build accounts and access failures.
2. Obtain the actual original lane record, authenticate its existing digest,
   then generate the candidate in the existing workspace. Stage a new
   generation/record through a reviewed migration which retains the old
   record as evidence. Bind its reviewed producer/companions and report the
   resulting final new SHA-256. **Do not** overwrite the original lane or use
   its digest as authorization after migration.
3. Execute native access checks under the *selected* actual controller/process
   principal, confirm installed socket/namespace/permissions and existing
   disk admission, then activate via a separately authorized, digest-bound
   new-runtime path. Do not submit via SSM while identity compatibility is
   uncertain. No extra quota, old six-hour special deadline or memory-cgroup
   investigation is a new first-Fonts gate.

At this source revision, both the old first-Fonts activation path and the
first-Fonts gateway selection path **hold**. The new schema-5 lane is also
explicitly non-executable pending the coordinated producer/runtime change.
