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

**The reviewed source candidate is now root-control PR #55**, box-control's
inherited-peer-v2 successor and image-build's matching producer. Root-control
PR #55 adds kernel SO_PEERCRED-bound, nonroot build ownership and a native
child-observation contract in source. These revisions are not yet proof of
a selected, installed systemd service or an actually running nonroot
compiler child. The historical schema-4 lane, UID-required producer and
associated hashes remain evidence only.

## Exact pinned candidate — 2026-11-21

The supported source tuple is **exactly**:

| Component | Git commit | Complete clean tracked source-tree SHA-256 |
| --- | --- | --- |
| root-control | `58b5a94311d771bb1c5f4c3e9c6191b44d6565c9` | `0ffddcfb39a9cc5295cc67196362e2dcb57301ed70199c502af1203e20c2d097` |
| box-control | `ad61fa6a4e9c3176149720868cb008e0512dbec9` | `9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00` |
| image-build | `ff968a431dd2067e7d0e1f17d6e547f2779f647a` | `e0aacfb08a8b0ef9b1883080ece7d93673906263bee30caa09a285e7a1466310` |

The hashes were measured by the exact-revision clean-checkout
`source_tree_sha256()` algorithm on GitHub Actions on November 21, 2026.
PR #35's `SELECTED_SOURCES`, manifest validator and CI now reject any other
commit or clean-tree digest. Changing a tuple requires another reviewed code
revision; it cannot be selected through an untrusted runtime manifest.

**Installed hashes are not yet available.** No versioned combined runtime,
actual installed module and distribution RECORD hashes, complete installed
tree digest, selected service unit or independent rollback inventory has
been attested on the target Host. Never fill those manifest fields with
source Git hashes, CI mock-install hashes or zeros. Native staging and
readback must supply the exact installed values. Thus the Fonts lane
remains disabled even though the source pins above are fixed.

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
  executable, three critical **real module paths**
  (`zog/root_control/build.py`, `zog/box_control/build_jobs.py`,
  `zog/image_build/box_control_adapter.py`) and distribution RECORDs.
  The selection accepts either one `zog-record` for the real combined Zog
  wheel, or **all three** component-specific RECORD roles. Mixed/partial
  RECORD closures, bogus module paths, duplicate role names or ambiguous
  installed locations fail. Include all additional dependency/launcher bytes
  required by the actual selected runtime. The reviewed
  `installed_tree_sha256` binds **every file, directory and mode** in the
  entire selected immutable version, catching omitted dependencies, extra
  mutable bytes and symlinks. The read-only inspector additionally parses
  the actual installed distribution RECORD CSV and requires each of the
  three critical modules to be named exactly once with its real SHA-256
  (URL-safe base64) and byte length; even a manifest that hashes a stale
  RECORD and the full runtime tree consistently is rejected. Merely providing
  Git source hashes cannot satisfy installed-module or RECORD attestation.
- rollback: a protected independent copy of the original unit and old
  runtime tree under /opt/zog/compiler-runtime/rollback/<release_id>/,
  with full original runtime tree SHA-256. Any unsafe, unexpected-linked, aliased,
  mutable or missing rollback bytes cause HOLD; the four reviewed literal legacy
  venv links are handled only by the separate inventory defined below.
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
3. Under the protected root owner, *read* the staged release's real
   byte inventory with:

   ~~~sh
   host-deploy fonts-runtime-inventory --release-id <release_id>
   ~~~

   This captures each critical module path, SHA-256 and size, all actual
   installed distribution RECORD hashes, and the complete immutable
   runtime inventory/tree SHA-256. It rejects missing or ambiguous modules,
   missing RECORDs, linked/mutable/foreign-owned files and unsafe directories.
   The response deliberately declares `independently_reviewed: false`,
   `execution_authorized: false` and `fonts_lane_enabled: false`. It is
   evidence only, not an approved installed tuple.

   Construct the versioned selection JSON from this actual evidence,
   reviewed clean source pins and independently verified **existing** service
   and backup unit bytes. Do not guess the installed byte hashes or copy a
   hypothetical source package inventory into the installed selection.
   Save the canonical JSON as a root-owned, non-group-writable file under
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
The selected root-control PR #55 source is only a candidate until installed
native SO_PEERCRED, actual child EUID/EGID and cgroup checks pass.

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


## November 21: mandatory complete effective service composition

Host-install PR #49 and host-deploy PR #35 now bind the entire compiler unit composition, not merely the main fragment. The actual service is zog-certbot-seed-root.service. Two active drop-ins, 60-boot-a-restrictive-import.conf and 70-fonts-combined-runtime.conf, reset ExecStart in lexical order. gateway-mounts.conf adds Requires/After, while issuer-persistence.conf adds ExecStartPre and ReadOnlyPaths. The original fragment hash is ee3284eb9c317092312bc632ac2eebb68c4c5d36684ad4b5e86c6dd129a2d72d. Full original per-drop-in hash evidence is in the host-install PR #49 handoff.

The versioned selection now requires a composition object containing sorted exact original_dropins and selected_dropins (name, SHA-256, size, mode, root UID/GID), plus original_effective and selected_effective dictionaries covering ExecStart, ExecStartPre, ReadOnlyPaths, Requires, and After. The inspector requires the exact on-disk staged, rollback and active drop-in sets, parses ordered ExecStart= resets, and checks systemd's actually loaded FragmentPath, DropInPaths and effective properties. Foreign/changed drop-ins HOLD. Selected manager-effective path= must equal the version-owned executable and cannot retain the old /opt/zog/fonts-controller-d9dfd6c0-20261114 runtime.

This deliberately tightens the uninstalled draft selection schema. Native installed hashes and the approved canonical selection-file hash must be established from new genuine staging evidence, not guessed. The original compiler service was active during observation. The four symlinks inside the old runtime were a preservation HOLD; the later strict legacy-only inventory correction below allows exactly those links without rewriting or flattening. Native Python-chain attestation is still required. The source correction performs no Host command, service start, compilation or SSM operation.

The mandatory composition additionally carries original_fragment and selected_fragment objects, each with exact path, SHA-256, byte size, mode, root UID/GID. The read-only inspector verifies these fields for staged, preserved and active fragment files, not merely the older service.staged_sha256 and rollback.unit_sha256 fields. Both fragment bindings must agree with the existing service/rollback path and digest fields. This is source-selection review metadata; actual installed values must be measured independently.


## November 21 — legacy rollback literal symlink inventory

The previously selected strict `_retained_tree_sha256` continues to reject all links in new immutable controller releases. Only the **old runtime and the independently retained rollback copy** use `zog-compiler-legacy-rollback-inventory-v1`. Its allowlist is exactly four literal links relative to the original runtime: `venv/lib64 -> lib`, `venv/bin/python -> python3.12`, `venv/bin/python3 -> python3.12`, and `venv/bin/python3.12 -> /usr/bin/python3.12`. Unexpected or changed links, escaping relative paths, cycles, hardlinked regular files, unprotected files, or differences between original and saved trees fail.

The canonical reviewed rollback selection now includes `original_runtime` (the existing untouched path), `legacy_inventory_schema`, `legacy_inventory_sha256`, the independently calculated `runtime_tree_sha256`, and the `python_interpreter_chain`. The external interpreter chain begins at `/usr/bin/python3.12` and records each literal symlink target, ending with complete final regular interpreter SHA-256, size, ownership and mode. It is inspected again at readback/restore; it must not be invented from a Git hash or an CI fixture. No original link is dereferenced, flattened or rewritten to fabricate a clean venv.

The read-only inspector compares the true original runtime and protected rollback copy with the approved tree/inventory hashes and external Python chain, while still checking newly selected software with its independent no-symlink inventory. Native Work must approve the actual interpreter-chain evidence, installed RECORD and full unit/drop-in composition during an inactive maintenance window before performing selection/restore or reboot recovery. The Fonts lane remains disabled; no Host command, SSM, service start or compile was authorized by this source correction.

## November 21 — stable systemd argv/flags, volatile process evidence

**Owners:** host-deploy Regular PR #35 and host-install Regular PR #49.

Raw systemctl show values for ExecStart and ExecStartPre contain two types of
information. The executable path, complete manager-serialized argv[], and
execution flags are stable unit configuration; pid, start_time, stop_time,
code, and status are process observations and may legitimately change between
starts or across a reboot. The raw manager string must NOT be an approval key.

The reviewed composition.original_effective and composition.selected_effective
now contain **stable typed command identities**, rather than raw manager
strings. ExecStart is a list with exactly one command object; ExecStartPre is
an ordered list of zero or more. Each command object has these exact keys:

- path: absolute manager-reported executable path
- argv: complete manager-serialized argv[] string
- flags: a map with ignore_errors ("yes" or "no") and flags (the manager
  execution flags string; empty when absent)

ReadOnlyPaths, Requires and After remain reviewed string properties. The
verifier compares complete ordered ExecStart and ExecStartPre commands after
on-disk drop-in resets and against systemd's loaded effective identity. It
rejects changed path, argv, flags, added/removed/reordered prestart commands,
foreign drop-ins and unknown manager fields. A leading '-' unit command prefix
requires matching manager ignore_errors=yes; unsupported flags fail closed.

### Exact producer contract for host-install PR #49

Host-deploy provides fonts_unit_composition.normalize_loaded_commands(raw).
The input is the five raw systemd properties. It returns
(stable_effective, process_metadata), where each ExecStart/ExecStartPre entry
in stable_effective is the command object above; process_metadata is a
separate per-command list of observed PID/time/exit fields.

Host-install should persist stable_effective as original_loaded_properties
in the preserved receipt, and as composition.original_effective in the
independently reviewed selection. The selected_effective must be measured
from the actual selected manager and pinned independently. Save
process_metadata as a **separate** observational field such as
original_loaded_process_metadata; an optional raw readback may also be
retained as audit evidence, but neither should be compared or hashed into
immutable selection approval.

Update host-install compiler_controller_versioned_install.py functions
_current_manager_composition(), preserve(), select() and restore() to use
this normalized contract. The old raw ExecStart/ExecStartPre equality and
single-argv regex cannot remain the admission check. The updated
fonts_unit_composition.verify_loaded() reports both stable effective command
selection and separate process_metadata; fonts_versioned_runtime.inspect_installed()
returns manager_process_metadata outside the selection SHA-256.

Regressions cover changed PIDs/timestamps on both commands passing, and
changed main/prestart argv, execution flags or command count failing.
The host-deploy source intentionally rejects the prior raw-string manifest
format until host-install's matching producer is updated. Do not bypass the
gate or activate the controller/Fonts lane during the source correction.

No maintenance window, live unit switch, interrupted recovery, request
replay, SSM submission or compiler work was performed.
