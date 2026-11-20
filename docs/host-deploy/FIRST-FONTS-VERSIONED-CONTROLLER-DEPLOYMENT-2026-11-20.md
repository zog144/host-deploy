# First Fonts — versioned inherited-controller deployment and admission

November 20, 2026 · host-deploy Regular · PR #35 source-only supplement

## Decision and current HOLD

The first Fonts lane may run only through the exact inherited-peer-v2
controller + box-control + image-build producer tuple, installed as
independently reviewed immutable bytes and bound to the selected service.
Source compilation does not prove native deployment acceptance.
No certbot-build-owner, certbot-build-worker, synthetic UID/GID,
User/Group selector from RPC, new account, direct SSM compilation or root
build is allowed.

**Root-control #48 remains a blocker:** the inspected combined root-control
PR #51 source at d9dfd6c02a5a96750f1213bf663cdceab72f1efd still
permits root for finite-build execution and uses the daemon process
identity in some paths. That cannot be first-Fonts execution authority.
Box-control PR #21's proposed build_contract: zog-build-inherited-peer-v2
and the image-build successor are candidates until the authenticated peer
to nonroot child contract is accepted and verified. The historical
schema-4 lane, UID-required image-build revision and associated hashes
remain evidence only. No production release ID or digest is invented.

## Supported exact version selection

The source module zog.host_deploy.fonts_versioned_runtime defines a
read-only selection with these required fields.

- schema = zog-first-fonts-versioned-controller-selection-v1;
  contract = zog-build-inherited-peer-v2; release_id = new 32–64 lowercase hex.
- sources: exactly root-control, box-control and image-build, each with
  immutable 40-hex Git commit and SHA-256 of a clean tracked byte tree.
  source_tree_sha256() inventories each tracked path, byte size and SHA-256,
  then hashes the canonical sorted inventory. inspect_sources() rejects
  dirty revisions, missing files, mismatched hashes and overlapping checkouts.
- service: exact staged unit name and SHA-256, canonical
  /etc/systemd/system/<unit-name>, and one fixed ExecStart executable under
  /opt/zog/compiler-runtime/versions/<release_id>/bin/. The executable
  must be included in the immutable installed-file inventory.
- files: named absolute paths/byte sizes/SHA-256 of the installed controller
  executable, root-control/box-control/image-build modules and all three
  installed distribution RECORDs. List any additional dependency/launcher
  bytes required by the actual selected runtime. The independently reviewed
  installed_tree_sha256 additionally binds **every file, directory and mode**
  in the entire selected immutable version, catching omitted dependency
  bytes, additional mutable files or symlinks. Source review must verify
  the complete installed distribution closure, not just the minimum six.
- rollback: a protected independent copy of the original unit and old
  runtime tree under /opt/zog/compiler-runtime/rollback/<release_id>/,
  with full original runtime tree SHA-256. Any unsafe, symlinked, aliased,
  mutable or missing rollback bytes cause HOLD.
- lane: the actual candidate schema-5 specification SHA-256, exact name
  gateway-first-fonts-runtime, and enabled: false. Historical schema-4
  files, original source, pin, identity and digest are never rewritten.

The selected package tree and staged systemd unit are root-owned,
non-group/world-writable regular files. Installed modules/RECORD and service
bytes must match the reviewed hashes. No imported ambient PYTHONPATH,
separately installed component or mutable branch may substitute.

## Deployment and rollback path — host-install Regular / Work

1. Inspect the **current** root-control service, installed interpreter,
   unit bytes, root-control/box-control/image-build installed distributions,
   RECORD and original operation state. Arrange an owner-reviewed inactive
   maintenance window. Preserve original unit and the entire actual old
   runtime as independently protected root-owned bytes, including provenance,
   before touching the selected unit. Never overwrite or alias the original.
2. Select one exact reviewed compatible source tuple. Verify Git commit and
   clean checkout SHA-256 for each selected source. Install dependencies
   normally in a newly versioned runtime under
   /opt/zog/compiler-runtime/versions/<release_id>/, not in the currently
   selected venv. Stage a static unit with an ExecStart naming only that
   release's immutable executable. Do not start or enable the unit.
3. Construct the versioned selection JSON from reviewed source and actual
   installed byte readback, including backup inventory. Save it as a
   root-owned, non-group-writable file under
   /var/lib/zog/compiler-runtime/selections/<release_id>.json.
   Independently review the SHA-256 of the entire JSON *file*; calculating
   a hash of whatever happens to be installed is not independent approval.
4. With the old unit still selected, use the trusted root Host to perform
   read-only inspection, supplying the independently approved file SHA-256:

   ~~~sh
   host-deploy fonts-runtime-inspect \
     --selection /var/lib/zog/compiler-runtime/selections/<release_id>.json \
     --expected-selection-sha256 <reviewed-64-hex-file-sha256> \
     --phase staged
   ~~~

   This confirms the original unit is still live, staged unit contents
   and executable/module/RECORD hashes match, and the separately retained
   rollback runtime tree matches its previously reviewed SHA-256.
   The command never writes, starts, stops, enables or sends anything.
5. Only after operator/native install approval may the privileged installer
   select the staged unit through its separately reviewed atomic interface.
   Confirm systemd's **actual loaded** unit and process identify the selected
   release, then run the same inspection with --phase selected; it requires
   the active unit to match the staged SHA-256 while rollback remains intact.
   No first-Fonts job is authorized by this service selection.
6. If the new service cannot operate or be attested, restore the original
   unit/runtime using the protected installer rollback transaction. Preserve
   old records and uncertain operations, never force replay, and reattest
   the old installed unit, bytes and service identity. Never invent a new
   worker or invoke direct SSM as a fallback.

## Mandatory nonroot compiler child witness

A root-owned root-control daemon may supervise units; its compiler child
must not execute as root. The **actual authenticated box-control peer** must
be nonroot, read using kernel SO_PEERCRED by root-control. Root-control
must reject root peers and derive transient-unit User/Group exclusively
**server-side from those verified peer credentials**. It must not take an
identity selection from SSM, caller JSON, username, home, session or daemon
os.geteuid(). Identity-free build registration and lifecycle requests use
the exact inherited-peer-v2 version; old records remain inspection-only.

Before any real Fonts compilation, run a separately authorized *safe,
non-compiling child probe* through the accepted controller. Verify the
actual child PID and stable /proc/<pid>/stat start time, kernel status
effective UID and GID (second fields of Uid and Gid), real systemd unit
cgroup, matching nonroot root-control authenticated peer, saved operation/
registration identity and cgroup/namespace/NoNewPrivileges controls.
The source inspect_child_identity() validates the real kernel child EUID,
EGID, start time and cgroup and rejects zero or mismatched credentials.
It returns execution_authorized: false deliberately: root-control must
add and prove the **authenticated owner-to-child linkage** independently,
not a user-supplied peer UID/GID argument or fabricated JSON record.
A root SSM process's UID cannot substitute for this evidence.

**Admission stays HOLD** until exact reviewed controller/producer source,
installed-byte/RECORD hashes, unit/rollback selection, accepted nonroot
peer-derived root-control contract (root explicitly rejected), real child
EUID/EGID and cgroup, retained Project/lane/pin provenance and separately
authorized lane activation all pass. No root compilation can be admitted.
The current draft root-control PR #51 does not pass this gate.

## CI and native handoff boundary

The focused GitHub workflow fonts-versioned-runtime-admission.yml runs
source-only tests for exact Git trees, selection integrity, installed module
and RECORD bytes, rollback preservation, foreign/tampered files and actual
kernel-child UID/GID/proc readback. Privileged CI tests use disposable local
directories only. Tests do not call a live Host, start systemd, send SSM or
compile Fonts. Native Work must inspect the currently installed service and
choose the exact accepted implementation; a source CI pass is not admission.

This PR does not change an actual Host, add accounts, enable the Fonts lane,
install a controller, delete a retained operation or authorize compilation.
