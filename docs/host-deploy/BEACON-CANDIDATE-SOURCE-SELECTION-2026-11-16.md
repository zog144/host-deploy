# Candidate beacon source selection, separate from public release

**Source candidate:** host-deploy PR #43. This selection is for the
`/state/host-discover/identity` fresh beacon installation work. It does not
change the released public publisher baseline or authorize deployment by itself.

## Two different source selections

- `public-companion-publisher.json` and
  `docs/host-deploy/public-companion-git-objects-2026-10-18.json` are the
  **existing released** six-component Git commit/tree/file-object index.
  Their previous host-discover, host-identify and host-install commits,
  recorded versions, tree SHA-1s, tracked file counts and publication status
  remain fixed. The publisher's historical
  `beacon_descriptor_git_blob_sha1` is for the **historical descriptor**,
  not a requirement that the candidate descriptor equal that old blob.
- `src/zog/host_deploy/beacon_sources.json` is independently bound to
  the **exact new three-component candidate source**. It includes every
  tracked first-party runtime module, deployment/systemd files, package
  metadata and license/notice files required by the installer, SHA-256
  hashes of the exact source file bytes, plus the declared distribution
  versions and dependency requirements.

| Component | Exact Git commit | Version | Selected files |
|---|---|---:|---:|
| host-discover | `a6f3f402cee87eb7079d94c7eb36474930d45444` | 0.4.14 | 36 |
| host-identify | `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b` | 0.3.5 | 17 |
| host-install | `71643eef03739749c7c272f7c6be23d7063a51d8` | 0.14.9 | 53 |

Host-discover declares `host-identify==0.3.5` and
`host-install==0.14.9`, matching the selected candidate metadata.
Host-identify's third-party dependencies and security-tested constraints
are also retained; there is no invented alternative package version.

## Explicit local candidate source directory

Check out the three named repositories at exactly the commits above under
one **explicit** directory:

```text
/candidate/beacon/
    host-discover/  # exact clean Git checkout
    host-identify/  # exact clean Git checkout
    host-install/   # exact clean Git checkout
```

Validate source bytes, Git HEAD/cleanliness, required files, versions,
license closure and dependencies without changing installed Host state:

```sh
python scripts/beacon_candidate_selection.py \
  --source /candidate/beacon \
  --verify src/zog/host_deploy/beacon_sources.json

HOST_DEPLOY_CANDIDATE_SOURCE_DIRECTORY=/candidate/beacon \
  python -m pytest -q tests/test_public_publisher_selection.py \
  tests/test_beacon_candidate_source.py tests/test_beacon_payload.py
```

Installer-side source selection must pass the directory explicitly:
`discovery.install(..., source=Path("/candidate/beacon"), ...)`,
or the equivalent `host-deploy install-discover --source` invocation.
The tested `beacon_payload.payload(source=directory)` compares all pinned
bytes before remote Host access, creates the version manifest and packages
only selected source files; it does **not** infer this candidate from the
released public publisher or a default directory.

The [Beacon candidate source pins GitHub Actions workflow](
../../.github/workflows/beacon-candidate-pins.yml) checks out each exact
public commit and runs these source tests with the explicit directory
and no credentials.

## Distinct native gate

The Unix-domain socket/integration test is deliberately **retained** for a
native runner that permits socket creation/binding. An environment refusing
Unix sockets may prevent running that test, but that is a **sandbox capability
failure**, not evidence of a changed Git commit, invalid SHA-256 pin,
missing packaged file or dependency conflict.

No real beacon replacement, Host identity recreation, enrollment,
systemd activation, or protected socket test was performed by the source CI.
The Work connection chat must still check the native installer, service,
filesystem ownership and actual enrollment with the candidate installed
before declaring native acceptance.

## Pending review and deployment owner boundary — 2026-11-17

This is a **candidate-only exact-byte selection**, not production approval.
The host-discover PR #10 and host-install PR #45 source heads must be independently reviewed; GitHub source CI is not a signed owner review. The selected source hashes are fixed above so the installer can be reviewed and tested together. The public release manifest and live Host are unchanged.

The fresh identity key and pending enrollment must be retained byte-for-byte.
The revised host-discover controller writes `mirror-role.json` and `mirror-role.lock` under the sibling `/state/host-discover/roles` directory. The installer now prepares that exact derived directory using the installed service account, `0700`, with safe root-owned parent traversal, validates any existing role state, and adds its path to systemd `ReadWritePaths`. If older role entries exist in the identity directory, the reviewed consumer relocates them under its own per-role migration lock without regenerating keys or clearing an enrollment. A missing or unsafe role directory blocks startup before role operations.

The protected admission source resolves the local NSS `host-discover` UID/GID and verifies the kernel `SO_PEERCRED` of the client and the root-owned socket's group/mode. The selected package is **not** evidence of a live socket. Root-side socket unit deployment/startup, exact service account identity, and successful protected request/reply must be tested by Work after pinned installation. The separate retained-identity root migration UID policy is not altered by PR #45.

Native Work must first snapshot key/binding/marker inode and public fingerprint and record existing pending enrollment; install the exact reviewed candidate **without rerunning the fresh bootstrap**, then exercise restart, same-fingerprint enrollment resume, protected socket activation and SO_PEERCRED exchange, and reconnect/restart regressions. No production repin or actual Host mutation is authorized by this branch.
