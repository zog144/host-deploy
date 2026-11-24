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

**The reviewed source candidate is now the root-peer successor on root-control
PR #55**, box-control's inherited-peer-v2 successor and image-build's
matching producer. This root-control revision derives the execution identity
from kernel SO_PEERCRED and permits an authenticated **exact 0:0 peer** without
switching to an alternate account. A 0:nonzero or nonzero:0 pair is invalid.
The selected source and its schema-2 protected registration/job records
must be installed and independently attested. Source review alone does not
authenticate any real child, approve a compiler run, or establish that systemd
uses the intended version. The historical schema-4 lane, UID-required producer and
associated hashes remain evidence only.

## Exact pinned candidate — 2026-11-21

The supported source tuple is **exactly**:

| Component | Git commit | Complete clean tracked source-tree SHA-256 |
| --- | --- | --- |
| root-control | `a672f007b33f83bf70970e3a571fd443366bd93f` | `c9475afdc6545adc963203f1ef00f77bd5aa542e2bf6337f660a5b64d0800989` |
| box-control | `ad61fa6a4e9c3176149720868cb008e0512dbec9` | `9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00` |
| image-build | `0eeb8a1cc73ae2b8410e29865c36ea1e0643b75a` | `f17598d995888927e66504d2c1ca65ae675c1efb6ac1208e7de1ce9cdd409688` |

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

## Root-control authenticated child identity witness (including exact 0:0)

The root-owned root-control daemon may supervise units. For an actual build
child, root-control must authenticate the incoming box-control Unix socket
using kernel SO_PEERCRED, bind the immutable peer UID/GID to its schema-2
registration and job records, and derive any transient systemd User/Group
exclusively from that saved identity. A kernel-authenticated **0:0** principal
is admissible under this policy; a mixed-zero identity or caller-specified
UID/GID, User/Group, worker account or alternate execution principal is not.

The read-only host-deploy child inspector now requires the original selected
Project path and root-control's existing build_root_id and job_id. It does
**not** accept caller-supplied peer_uid/peer_gid or a purported trusted
evidence object. It reads the protected root-owned root-control records from
/var/lib/zog/build-resources/<SHA256(Project path)>/<build_root_id>,
verifies schema-2 registration/job association, matching execution_identity,
registered service unit and absence of identity fields in the job request,
then independently observes the actual /proc child twice. The recorded
peer identity must exactly equal all four actual UID/GID values; the PID,
start-time ticks and cgroup must remain stable and match the selected unit.
If a protected record is missing, untrusted, modified, a symlink, or does not
bind that exact job and child unit, inspection fails.

The result reports real/effective/saved/filesystem UID/GID, peer UID/GID,
root_identity_observed, PID, start time, cgroup, and source of the protected
root-control evidence. It **always** reports execution_authorized=false.
In particular, a successful observation of root 0:0 does not authorize
root compilation by itself or allow a job to be replayed. Root-control's
selected installed-byte pin, actual authenticated socket peer, Project/
operation binding and the normal controller lifecycle are independent native
admission requirements.

The read-only controller and Project access probes also report an existing
effective 0:0 principal accurately; mixed-zero values still fail. Neither
probe switches identity, opens an account, sends a build or grants authority.

**Admission remains HOLD** until the reviewed source tuple, host-install
exact selected service/runtime/RECORD/rollback attestations, protected
root-control peer-to-child evidence, stable native systemd 252 child readback,
retained Project/generation/pin provenance and separately authorized lane
activation are all accepted. The Fonts lane remains disabled.

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


## November 22 — guarded selected inspection during reboot-safe transaction

Host-install PR #49 now keeps a separate persistent deny-by-default `zzzz-zog-compiler-transaction-guard.conf` systemd drop-in during multi-file selection and restoration. Its exact [Unit] `ConditionPathExists=/opt/zog/compiler-runtime/rollback/<release>/startup-permit` points to a permit that the installer must **never create**; absent permit means reboot cannot start a unit while the guard is present, even after the temporary fragment mask has been replaced.

The read-only versioned controller inspector supports the explicit `transaction_guard=True` option **only** for `phase="selected"`. In this mode it checks the exact root-owned guard bytes, mode 0644, absent permit, full selected+rollback installed inventories and the loaded manager's complete `DropInPaths` including the guard. The normal `inspect_installed(...phase="selected")` remains strictly unchanged and rejects any extra drop-in. Selected executable, stable `ExecStart`/`ExecStartPre` commands, permissions and immutable bytes must still match the independently approved selection.

The installer verifies the guarded selected composition before fsyncing the `selected` transaction and removing the startup guard. Similarly, restoration must verify the original loaded command/drop-in composition with the guard present, durably commit `restored`, then remove it. Crash/power-loss before the durable commit must leave the guard in place; after a commit but before guard cleanup the service remains conservatively unavailable until explicit recovery. No activation, SSM or compilation is permitted by this source change.

Native Work must check the actual systemd 252 `ConditionPathExists` behavior through reboot and confirm the guard cannot be overridden by other drop-ins. This source acceptance alone is not native Host admission.


### Startup guard ordering

The temporary guard is `zzzz-zog-compiler-transaction-guard.conf`, deliberately placed last among reviewed drop-ins. Since a later `ConditionPathExists=` reset could erase the deny-by-default condition, the guarded inspector fails closed on any drop-in whose name sorts after the guard. Only the guarded selected inspection accepts the one exact additional file; normal selected inspection still requires the original approved drop-in set without extras. Source tests include a later malicious condition reset.


## November 22 — selector-free normal SSM → Project-current → box-control audit

The source CI checks the exact Project-current gateway producer from host-deploy
PR #54 at 5d093474063b0b11609e8be4b4dc090e531ef760, image-build PR #31
at bce80b258e445191248d9998620884a79f029013, and box-control PR #21
at ad61fa6a4e9c3176149720868cb008e0512dbec9, plus the newly selected
root-control root-peer successor at
a672f007b33f83bf70970e3a571fd443366bd93f.

The normal SSM Project-current envelope selects pipeline.submit with only
the approved mode/targets. The producer's BoxControlExecutionAdapter
constructs the typed build registration, command, environment, timeout,
resource and isolation arguments; it never sets UID/GID/User/Group on the
request. Both the actual box-control and root-control canonical request
validators reject injected identity selectors. The controller still owns
the kernel-authenticated peer identity and corresponding transient unit.
Historical identity-bearing schema-3 records remain blocked from implicit
translation, not reinterpreted as normal schema-4 Project-current requests.

This audit is source-only. No live SSM → box-control operation, new attempt,
controller installation, protected journal change or compilation occurred.
Host-install PR #49 must update its source selection to the **exact new
root-control commit and measured source-tree hash**, reattest the installed
module/RECORD and entire versioned runtime, preserve existing rollback
evidence, and complete a separate approved native acceptance. Do not
automatically repin an existing installation or rewrite an accepted receipt.

## November 23 — independent issuer persistence verification

Source owner: host-deploy PR #35, coordinated with host-install PR #49.

The read-only host-deploy verifier still checks all of these independently
from the installer's selected/restore transaction:

1. Original and selected **fragment** bytes, root-owned regular-file
   metadata and the exact staged/active unit paths and hashes; saved old
   fragment remains distinct from new selected unit.
2. Exact original/selected **drop-in** names, ordering, byte SHA-256, size,
   root ownership and mode. The manager-loaded FragmentPath, DropInPaths,
   LoadState, ExecStart, ExecStartPre, ReadOnlyPaths, Requires and After must
   match the reviewed stable effective selection. PIDs, timestamps and exit
   status remain separate process observations, not approval digests.
3. During selected-phase guarded inspection, the exact last, protected
   deny-by-default compiler startup guard and absence of a startup permit.
4. For **zog-certbot-seed-root.service** specifically, an independently
   verified original and selected **issuer-persistence.conf** is mandatory.
   Both drop-ins must have identical SHA-256/size/bytes and root-owned DAC
   metadata. The issuer prestart entries must still be present in both
   manager-effective ExecStartPre command lists with matching executable,
   argv and non-ignored execution flags. Issuer ReadOnlyPaths must be
   preserved and both Requires/After must retain all previous backing
   mount dependencies. The verifier rejects missing, replaced, weakened or
   unselected-service issuer restrictions. This check does not trust a
   host-install approval result in place of checking the actual source and
   selected unit/drop-in files.

The `inspect_installed()` readback reports
`issuer_persistence.verified`, the original/selected unit digests, the
issuer drop-in digest and `native_issuer_storage_verified=false`,
`startup_authorized=false`. Its existing `execution_authorized=false`
and disabled Fonts lane remain unchanged.

**Important separation:** host-install PR #49's approved replacement-unit
binding is not itself a modification or acceptance of the installed
issuer-persistence prestart helper. The independent issuer persistence owner
must still identify and attest the actual helper's source and installed
bytes, original issuer mount/STATE/grants, DAC, protected issuer storage,
systemd 252 cold-start and reboot restrictions. No native start, restoration,
maintenance window, SSM send, request replay or Fonts compilation is
authorized by these source tests.

## November 24 — narrow retirement of previous compiler runtime

The original versioned compiler uses
`/opt/zog/fonts-controller-d9dfd6c0-20261114`, which is separately
preserved in the protected original runtime/rollback inventory. The new
`ExecStart` selects the immutable version under
`/opt/zog/compiler-runtime/versions/<release>/bin`; the old compiler
tree must NOT remain in its selected executable or systemd effective
command/restriction strings. This old compiler is **not** the independent
issuer application tree `/opt/zog/certbot-seed-oct21`, whose read-only
mount protection remains mandatory.

An earlier independent issuer verifier compared ALL original and selected
`ExecStartPre` entries for equality and required ALL original
`ReadOnlyPaths` entries to be present in the selected unit. Those generic
comparisons unintentionally retained the old compiler's prestart or read-only
tree even when it had no relationship to issuer storage. The new comparison
takes a **narrow evidence-bound exception**:

- `rollback.original_runtime` must be exactly
  `/opt/zog/fonts-controller-d9dfd6c0-20261114` and is still protected
  by the complete original/saved runtime inventory. Only original
  `ExecStartPre` commands whose executable or complete argv token resolves
  within that exact old compiler path may disappear. All other original
  prestart command identities must remain present.
- Only the old compiler directory itself and its child paths may disappear
  from original effective `ReadOnlyPaths`. Unrelated names with a similar
  prefix are not eligible, and unrelated original issuer/application paths,
  including `/opt/zog/certbot-seed-oct21`, remain mandatory.
- The **original and selected issuer-persistence.conf** must remain
  root-owned and byte-identical to its reviewed metadata. Every issuer
  `ExecStartPre` entry declared by that drop-in must still appear in both
  manager-effective command lists, with the same executable/argv and
  nonignored flags. Every issuer `ReadOnlyPaths` entry in the protected
  drop-in must remain; no issuer storage paths are exempted by retirement.
- `Requires` and `After` retain the entire previously reviewed backing
  dependency set. The verifier does NOT guess that a mount dependency can
  disappear merely because an unrelated old compiler path is retired.
- The rest of PR #35 still verifies selected/rollback fragment hashes,
  selected root-owned executable, complete installed module/RECORD and runtime
  tree, actual loaded systemd manager properties, selected guard/drop-ins,
  and independent actual child identity. The return still states
  `execution_authorized=false`, `native_issuer_storage_verified=false`,
  `startup_authorized=false`, and the Fonts lane remains disabled.

This amendment is only in host-deploy's **read-only issuer verifier**.
**Matching host-install Regular source review is required before the
already-staged release can be admitted**: its
`compiler_issuer_persistence_binding.reviewed_replacement_binding()`
currently compares the entire old/new effective prestart command lists and
the entire old/new read-only path sets, and must narrow those comparisons to
the *same* exact retired compiler tree while retaining issuer drop-in
prestarts, issuer storage paths, backing mounts, immutable baseline,
protected transaction and approved unit bytes. Because this policy is
source-hash-pinned and installed beside the issuer startup helper, a
matching change must have its **new source/installed-byte SHA-256 independently
reviewed and attested**. Do not patch existing protected staged policy bytes
or silently relabel an old helper rollback record. Work must hold selected
startup until both programs' installed bytes and evidence agree.

Native systemd 252, issuer backing filesystem identity/UUID, protected
grant, certificate data owner/DAC, source/policy hashes, reboot recovery,
0:0 child fixture and issuer helper rollback remain separate host-install
Work acceptance. No live unit, transaction, previous failed attempt or
Fonts request was changed in Regular.

## November 24 — independent review of revised issuer policy path normalization

The exact host-install PR #49 source head
`5c335a202f3b00e78e859983aa38854c40d88c51` independently hashes to
15,573 bytes / SHA-256
`3607f36bb40ea093433224749570de47f607dc43e965b2e7aee49e88ef953bc7`
for `compiler_issuer_persistence_binding.py`. The original and successor
helper SHA-256 values remain unchanged. The reviewed policy correctly checks
the unmodified issuer drop-in prestart and readonly entries in both original
and selected manager-effective selections, retains the full `Requires`
and `After` dependencies, and distinguishes protected rollback evidence
from the current staged source/installed byte pin.

**Source review HOLD:** The policy's
`_within_compiler(token, root)` currently accepts any string that equals
the retired root or starts with `root + "/"`, without rejecting
`.`, `..`, or repeated path separators. For example,
`/opt/zog/fonts-controller-d9dfd6c0-20261114/../certbot-seed-oct21`
passes that textual test even though its normalized pathname resolves
outside the retiring compiler directory. This must **not** become an
exemption for an issuer prestart or read-only mount. The independent
host-deploy verifier was further corrected to require canonical absolute
paths in the retired-runtime exemption, and both prestart and readonly
tests now reject traversal, dot segments and repeated separators.

Host-install Regular must match that narrow canonical-path rule in
`compiler_issuer_persistence_binding.py`, rerun focused/AL2023 tests,
record the changed policy source SHA-256 and use a new reviewed policy
version in the immutable staged-policy history (not overwrite old
`approved-binding.py` or prior policy record). The installer currently
pins the prior host-deploy verifier revision: repin to the reviewed
corrected head once accepted. Keep historical `record.json` revisions,
content-addressed policy files, protected original helper, original issuer
baseline, existing issuer storage mount/UUID/grants and all old compiler
receipts preserved.

No native selection, service start, systemd 252 fixture, issuer storage
mutation, reboot or Fonts compilation is authorized by this review.
