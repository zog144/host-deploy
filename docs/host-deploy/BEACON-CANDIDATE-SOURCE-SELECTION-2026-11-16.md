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
| host-discover | `10db0fbb2126cb868af7c5e2f79c2bab3c17ea0e` | 0.4.14 | 35 |
| host-identify | `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b` | 0.3.5 | 17 |
| host-install | `c8ff1722f9e0c6df755e637047a5be3baa90a82b` | 0.14.9 | 76 |

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
or the equivalent `host-deploy discover-install --source` invocation.
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
