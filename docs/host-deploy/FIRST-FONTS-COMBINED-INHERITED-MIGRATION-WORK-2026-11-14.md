# First Fonts: exact combined source and recoverable inherited-process migration

**November 14, 2026 · Source contract for host-deploy PR #36 · Work native execution NOT performed**

The old schema-4 lane is **not executable authority**. Preserve the actual retained
`gateway-first-fonts-runtime.json` bytes and approved specification digest
`sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2`.
No alternate `certbot-build-owner`/`certbot-build-worker` selection, UID/GID
options, `sudo`, `runuser`, setuid or systemd `User=`/`Group=` changes are used.
The compiler child inherits its actual running controller's effective identity,
**including UID 0 if that is how the administrator runs the service**. A probe
in an SSM shell measures *that SSM process*, not an installed build child.

## One exact selection per installed program

| Program | Reviewed commit | Role |
|---|---|---|
| root-control PR #49 | `6b9c4592438ff488646e59f025813d919119ab12` | Combined trusted-Host Task C and identity-free build backend in **one** installation |
| host-install PR #38 | `a0745915f934dfff658a9b848d48c94894dcfb68` | Combined Task C, existing copy migrator and prepared-only initialization in **one** installation |
| box-control PR #20 | `fdafbfb3032847b73c77abd9d90d769e43fddf85` | No selectable build UID/GID in registration or operations |
| image-build PR #23 | `620378bdd8075daeb5eaad45eedea4af7db36423` | Identity-free executable with separately retained original October pin |
| build-record | `a866c9c4b0dd385045f00ce2de7d809f5b67c104` | Producer-required companion |
| host-deploy PR #36 | **Exact final CI-approved head** (read PR head, do not use moving branch) | Historical lane migration and source-bound gateway/catalogue |

The original image-build `1f07e83dbd80dacb9bed0d6494c697375f0e26cd`
is a **distinct retained provenance input**, not an additional installed
producer. Its `project/pins/2026-10-01/commit-pin.py` remains excluded from the
new public checkout, and its original digest remains
`sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.
The accepted compiler generation
`3805294fc8ccd9589aa75d3a6c5cb9367b7baf84b6ce131a84adafed7d34f9dc`
remains `kind=image`; its acceptance receipt SHA-256 remains
`a205c07bde4e6cf61e48061affd9a0b40c3a101e18dff67a9871995a3a2afafc`.
Do not reissue the receipt or reinterpret the original lane's old accounts.

## Selected Work procedure — do not enable the gateway or submit a job

The two hosts, original workspace and original lane record must be authenticated
first; **do not recreate the missing old lane**. Install the pinned, source-tested
revisions using their existing package/wheel installation procedures with the
gateway inactive. Verify wheel RECORD and actual installed root-control/host-install
modules and service identities before native operations. Check the compiler is
quiesced and record original Project and STATE evidence. The instructions below
are source-selected maintenance operations and still require Work's native
authorization for copy and remote installation.

1. Read the immutable original lane and plan, **without editing JSON**:

   ```sh
   host-deploy fonts-lane-verify --workspace "$WORKSPACE"
   host-deploy fonts-lane-migration-plan --workspace "$WORKSPACE" > "$WORKSPACE/fonts-plan-for-review.json"
   OLD_DIGEST='sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2'
   NEW_DIGEST="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["corrected_specification_sha256"])' "$WORKSPACE/fonts-plan-for-review.json")"
   ```

   `NEW_DIGEST` is **calculated from the authenticated actual old specification
   by host-deploy**, not selected or typed by an operator. Inspect the entire
   plan and source/Host/copy destination before continuing.

2. **ONLY when the historical Project genuinely exists**, on the compiler Host, through its **existing authorized administrator process**,
   run the reviewed copy migrator *as-is*, with no identity switching. The
   destination is fixed at
   `/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`:

   ```sh
   host-install-fonts-project-migrate --inspect
   host-install-fonts-project-migrate --stage
   host-install-fonts-project-migrate --commit
   host-install-fonts-project-migrate --verify
   ```

   These steps are a copy, not a move. Preserve the original private-home
   Project and both historical accounts until any unrelated Certbot/service
   dependencies have been audited. Record the old/new byte inventory and
   original/new effective ownership. **Do not** edit the copied `controller.json`;
   it remains archival provenance.

**Recovery of the Project already initialized on the compiler (Work evidence
from November 14, updated SSM report):**

The original initializer **already committed** the real Project at
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`. Its
`.first-fonts-initialization-v1.json` is authentic, and its canonical
manifest SHA-256 is
`535c0c283599c8ad3e256d4cdf8db5bb4b16bf1350dfec59de10ebde52d79cb7`.
The source, box-control and build-record trees were verified. The missing
`package`, `application` and `catalogue` directories are a **layout
completion** task, not a reason to stage or commit a new initialization.

After installing and verifying the newly reviewed host-install PR #38
revision in the **selected maintenance interpreter** and making its
`host-install-fonts-project-init` entrypoint available to the selected
SSM command process, run the following against the **existing Project**
under that process's inherited identity:

```sh
host-install-fonts-project-init --verify
# Confirm the historical manifest SHA and all three reviewed Git identities.
# The current native instance may report layout_complete=false and exactly
# package/application/catalogue as missing.
host-install-fonts-project-init --complete-layout
host-install-fonts-project-init --verify
```

The `--complete-layout` operation reauthenticates the original initializer
manifest and source checkouts before any mutation, refuses symlinks, foreign
or nonempty runtime directories and pre-existing controller configurations,
and creates only the missing directories with the current process identity.
It can resume an interrupted earlier completion or succeed again without
rewriting existing files. The manifest bytes/SHA, copied-source=false claim
and original prepared schema-4 lane remain unchanged. A bad readback or
uncertain SSM acknowledgement requires inspecting the original command and
doing a read-only verify; never delete or reinitialize the Project.

Once `--verify` reports `layout_complete=true`,
`missing_layout_directories=[]`, `runtime_layout.status=ready` and
`controllers_present=[]`, run the **existing**
`fonts-lane-migration-stage --prepared-initialize` below, then retain the
genuine October pin and activate the separately generated inherited
controller. Do not run `--stage` or `--commit` on this already published
Project. Do not manually create directories, edit the manifest, substitute
copy-migration evidence or bypass host-deploy's partial-state check.

**Prepared but never materialized on other Hosts (initial creation):**

The approved original lane is `prepared`, and native SSM found **both**
`/home/certbot-build-owner/gateway-first-fonts-runtime` and
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime` absent. This
is NOT a failed copy migration. Do **not** create the old path or manufacture
a copy receipt. In this case select the separate owner-supported initializer
from host-install PR #38, which accepts three **real clean immutable Git
checkouts** acquired via the ordinary reviewed source mechanism. Example
inputs are placeholders for authenticated actual source trees; do not
construct an empty `source` directory to satisfy validation:

```sh
host-install-fonts-project-init --inspect
host-install-fonts-project-init --stage \
  --source-checkout "$REVIEWED_IMAGE_BUILD_CHECKOUT" \
  --box-control-checkout "$REVIEWED_BOX_CONTROL_CHECKOUT" \
  --build-record-checkout "$REVIEWED_BUILD_RECORD_CHECKOUT"
host-install-fonts-project-init --commit
host-install-fonts-project-init --verify
```

The initializer rejects a present historical project or a conflicting
pending/destination tree. Its `zog-fonts-project-first-initialization-v1`
report describes **actual installation of the new source**; it expressly
does not claim a historical copy, a historical controller, or a compilation.
After a successful verified initialization, use this *different* host-deploy
stage command:

```sh
host-deploy fonts-lane-migration-stage --prepared-initialize \
  --workspace "$WORKSPACE" \
  --expected-original-specification-sha256 "$OLD_DIGEST" \
  --expected-corrected-specification-sha256 "$NEW_DIGEST"
```

This requires the original lane to be **prepared**, and binds the real init
manifest/reviewed source tree identities in a distinct intent schema. A
missing Project for an original `active` lane is recovery, never initialization.
Old schema-4 record bytes stay untouched. Do not also run the copied-source
stage command below.

The original monthly pin is **not** present in the new source checkout, nor
can the new revision be assumed to contain the original Git commit; the
revisions have diverged. Obtain the genuine pin from the **original Git
provenance object** in a separately reviewed bare repository, with the exact
original commit fetched (no checkout of the old source anywhere in Project):

```sh
GIT_DIR='/var/lib/zog/image-build/provenance/original-image-build.git'
# Acquire the bare provenance repository by the reviewed original source
# acquisition mechanism; inspect its origin and actual commit object.
git --git-dir="$GIT_DIR" rev-parse --verify \
  '1f07e83dbd80dacb9bed0d6494c697375f0e26cd^{commit}'
python3 -m zog.host_deploy.fonts_pin_retention \
  --retain-from-provenance --provenance-git-dir "$GIT_DIR"
```

The command verifies the original Git origin, the exact commit and regular
tracked pin blob, original schema/month, digest
`d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`,
and writes the verified artifact only into the initialized Project state.
Do not fabricate pin bytes, create an old `source` directory or write an
unverified JSON. The initialized Project already contains the exact new
producer and companion Git checkouts; **skip the copy-path source replacement
step 5**. Continue at controller activation in step 6.

The previously active-but-missing case is **HOLD** pending recovery, regardless
of the presence of valid bare Git objects or installer checkouts.

3. **Copy path only:** while copied `source` still points to the *original* immutable producer,
   stage the verified data copy in the original owning host-deploy workspace:

   ```sh
   host-deploy fonts-lane-migration-stage --workspace "$WORKSPACE" \
     --expected-original-specification-sha256 "$OLD_DIGEST" \
     --expected-corrected-specification-sha256 "$NEW_DIGEST"
   ```

   This command invokes host-install's **read-only** `--verify` through the
   selected SSM Host and records the verified source-tree digest, workspace,
   Host, both specification digests and ordinary disk admission in
   `first-fonts-inherited-migration-v1.json`. Retrying a matching stage is
   read-only; conflicting evidence holds. Do not stage after replacing the
   copied original source checkout, because host-install must compare the
   original source and copy first.

4. **Copy path only:** still on the compiler Host and before replacing the copied checkout, capture
   the historical pin into its **existing** content-addressed build-record
   artifact store:

   ```sh
   python3 -m zog.host_deploy.fonts_pin_retention --retain
   ```

   This verifies the original clean Git revision, schema, month, exact pin
   bytes and SHA-256, publishes only absent pin bytes without overwrite, and
   leaves the original private-home source untouched. Inspect its result.

5. **Copy path only:** install the exact new producer **into the copied Project** using normal
   Git source-acquisition facilities and existing process identity. For a
   pre-existing authenticated checkout with the reviewed origin available:

   ```sh
   P='/var/lib/zog/image-build/projects/gateway-first-fonts-runtime'
   git -C "$P/source" fetch --no-tags origin 620378bdd8075daeb5eaad45eedea4af7db36423
   git -C "$P/source" checkout --detach 620378bdd8075daeb5eaad45eedea4af7db36423
   git -C "$P/source" status --porcelain=v1 --untracked-files=all
   ```

   Prepare **separate clean, exact** checked-out companions at
   `$P/companions/box-control` (`fdafbfb...`) and
   `$P/companions/build-record` (`a866c9c...`) using their owners' ordinary
   source checkout/install mechanisms. Do not overwrite existing foreign trees
   or move the original historical source from its private home. The corrected
   executable source **must not** contain the prohibited October pin file;
   host-deploy independently checks its absence, clean Git source identities,
   companion commits and the content-addressed pin before installing anything.

6. Invoke the digest-bound, idempotent controller and workspace migration:

   ```sh
   host-deploy fonts-lane-migration-activate --workspace "$WORKSPACE" \
     --expected-corrected-specification-sha256 "$NEW_DIGEST"
   host-deploy fonts-lane-verify --workspace "$WORKSPACE"
   host-deploy lane-inspect --workspace "$WORKSPACE" --lane gateway-first-fonts-runtime
   ```

   Activation reads back exact source, companions and original retained pin,
   checks actual installed socket/filesystem access, and creates **only**
   `$P/controller-inherited-v1.json` (new exact bytes, O_EXCL/fsync). It never
   changes the old copied `$P/controller.json`. Before any remote creation it
   durably changes local intent to `installing`. A lost SSM acknowledgement
   causes HOLD. Repeating activation when `installing` does **read-only**
   recovery and only finalizes if the new controller is already complete;
   otherwise Work must reconcile the original SSM command. There is no
   untracked resubmission or overwrite. Before replacing the live lane pointer,
   the original schema-4 JSON bytes are fsynced unchanged under
   `$WORKSPACE/first-fonts-original-evidence/<old spec SHA>.json`.

   The corrected active schema-5 lane gets generated source-specific
   `runtime_companion`, `controller_companion`, source root, controller path,
   state path, old/new specification digests, original byte archive SHA and
   **either verified historical-copy evidence or separate genuine
   first-initialization evidence (never a synthetic copy receipt)**. Repeated activation must verify the installed result
   and return without any file rewrite. Local history inspection continues to
   verify old SHA and exact original evidence. **An active lane record is not
   a compiler-child credential proof or permission to submit a job.**

7. Reauthenticate the existing signed compiler-base receipt and original
   producer binding **unchanged**; use the native owner
   `graphics_catalogue_owner.install_native` with *installed trusted readers*
   to generate the new catalogue and SHA-256 receipt. It now selects the
   identity-free executable revision, schema-5 lane and calculated spec digest,
   while keeping the original compiler-base `kind=image`, generation and
   Ed25519 acceptance receipt. It still uses the original retained pin bytes.
   The two root-owned files stay in the gateway's existing StateDirectory:
   `first-fonts-catalogue-v1.json` and `first-fonts-catalogue-receipt-v1.json`.
   The **receipt contents** are versioned v2 and bind the new source/digest;
   the old v1 installed files, if present, are a **conflict and HOLD**, never
   silently replaced. Work must separately review any historical catalogue
   before changing the installed selection. The gateway stays inactive.

8. Work independently reads the installed root-control service MainPID and
   process EUID/EGID, validates the `--verify-access` check **in the actual
   executing process context** (not a different SSM/root substitute), and
   reviews the root-control owner's opt-in disposable native child probe
   `acceptance/build_inherited_identity.py` where separately authorized.
   It must show the *real child* inherits the real parent EUID/EGID, including
   when parent UID is 0. Review root-control's systemd properties, cgroup,
   source selection and actual application path. Re-run the **read-only**
   gateway readiness tool with submission settings still off.

**No SQS receive, GitHub issue, compiler run, or account cleanup is authorized
by this source task.** The runtime identity and full original/current receipt
are established by Work's actual native evidence, not a green source CI check.
