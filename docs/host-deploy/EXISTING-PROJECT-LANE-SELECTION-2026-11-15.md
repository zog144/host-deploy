# Use an existing verified image-build Project for a new managed lane

**Source selection contract — November 15, 2026.** This workflow is not a
Fonts-only Project initializer and does not choose a root filesystem generation.

The same reviewed lane preparation/activation commands now support either a
new lane-root directory (the retained default) or an **already present Project**
selected by the installer. No Project is selected implicitly by directory age,
latest modified time, pathname suffix or a new-project allocation heuristic.

## Contract

Create a normal **schema-5** lane specification with
`image_build_lanes.specification(..., existing_project=True,
project_root=<exact-installed-project-root>)`. All ordinary source revision,
host, provenance Project ID, monthly pin, interpreter and resource-policy fields
are still required. The resulting specification has
`"project_selection": "existing"` and a code-derived SHA-256. It never contains
a requested UID/GID. Existing schema-5 records without that field preserve
their exact original bytes and digests.

Only an inherited-identity managed lane may use this selection. Its Project
path must be absolute and lexically canonical. A Project no longer has to be
named after the *lane*. An already registered, non-retired lane owning the
Project root remains an error: use that lane or obtain a separately reviewed
controller-supported multi-lane contract before attempting to register another
name. This patch does **not** authorize multiple conflicting registrations.

Before writing a lane record, `lane-prepare` obtains read-only evidence from
the **actual configured Host**, using its effective process credentials
(including UID/GID 0 when inherited). It requires:

- A real, traversable Project root and existing `package/`, `application/`,
  `catalogue/`, `state/` and `source/` directories; no symlinks or foreign
  entries in those paths.
- A clean installed `source/` Git checkout at the exact selected immutable
  executable revision; it does not create, move, replace or check out source.
- Actual effective filesystem access to the Project directories, selected
  Python interpreter and configured root-control Unix socket.
- An exact report of the Project root, real basename-derived controller
  Project identity, installed source revision, controller filename/digest
  and executing UID/GID. This SSM identity is **not** proof of the later
  finite compiler-child identity.

`lane-prepare` saves a normal prepared lane record and the native inspection
report. A repeated, identical preparation inspects again and returns the same
record. Changed input fields, missing Project files, a dirty source checkout,
or another lane already owning that root are errors; **nothing is repaired by
preparation**.

## Normal activation and recovery

Activate with the same standard command:

```sh
host-deploy lane-prepare --workspace "$WORKSPACE" --lane "$LANE" --spec "$SPEC_JSON"
host-deploy lane-inspect --workspace "$WORKSPACE" --lane "$LANE"
host-deploy lane-activate --workspace "$WORKSPACE" --lane "$LANE" \
  --expected-specification-sha256 "$REVIEWED_SPEC_SHA256"
host-deploy lane-inspect --workspace "$WORKSPACE" --lane "$LANE"
```

Compute `REVIEWED_SPEC_SHA256` using
`image_build_lanes.specification_sha256(selected_spec)`, **not a guessed
digest**. Use the authenticated selected Host and Project in the specification,
not a default Fonts name or a fabricated Project.

For a selected existing Project, normal activation repeats the native
read-only source/layout/socket verification, checks ordinary disk admission,
then saves a durable exact activation intent in the controller workspace
**before** the only Project write. It exclusively creates
`controller-<lane>-inherited-v1.json` under the Project root with the
source-generated schema-5 controller bytes. Existing `controller.json` and
all original package, application, catalogue, generation, state and source
contents remain untouched. The lane record is marked active only after
independent exact controller readback.

An identical active activation is read-only/idempotent. If remote execution
loses its SSM acknowledgement, the next call can only **inspect** the expected
file and finalize a complete original write; it never blindly issues another
write. A missing/foreign/partial controller with a retained intent is a HOLD
for investigation. No user switching, `chown`, privilege escalation or spare
worker account is involved.

Normal `lane-command` uses the selected Project's `source/`, `state/` and
lane-specific controller config. The original October pin is sourced from the
reviewed retained artifact for the identity-free Fonts producer regardless
of the lane's name. All original signed compiler-base acceptance checks remain
separate from this Project/lane preparation.

## What this does **not** decide

This code does not select one of the retained compiler generations, certify
which later image is usable as a bootable rootfs, migrate the already-created
`gateway-first-fonts-runtime` Project, issue a replacement signed acceptance
receipt, or authorize a GitHub issue, SQS receive or real compilation.
The installer must separately authenticate whichever retained generation and
actual rootfs manifest it eventually selects. If the selected existing Project
does not yet have the reviewed identity-free source checkout, normal reviewed
source installation is a prerequisite: lane preparation will report the
mismatch, not silently create an alternative Project or check out source.
