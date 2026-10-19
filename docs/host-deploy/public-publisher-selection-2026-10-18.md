# Six-component public source publisher selection — 2026-10-18

**Owner:** host-deploy Regular. **Disposition: SOURCE-REVIEW-ONLY, publication NO-GO.**

This private source-review candidate repins the existing public source selection
without changing running deployments, production beacon owners, SQS or SSM.
All six exact, immutable revisions are recorded in:

- [publisher selection](../../public-companion-publisher.json): six public
  commit SHAs, root Git tree OIDs, file counts, and selected three-package
  dependency versions. It does not authorize live deployment.
- [Git file index](public-companion-git-objects-2026-10-18.json): 2,187 Git
  blob SHA-1 values, modes and sizes bound to the six commit/tree objects.
  **These are Git object hashes, not content SHA-256 values.** They permit
  exact clean-checkout and byte identity validation for every tracked file.
- [beacon_sources.json](../../src/zog/host_deploy/beacon_sources.json):
  **90 actual content SHA-256 values** from the three reviewed exact public
  beacon source trees, inclusive of new modules, service assets, PyPI metadata
  and license/notice files. Retained schema 1 for the existing
  hash-verifying beacon_payload transport.

## Exact frozen component set

| Program | Commit | Git-tracked files | Beacon SHA-256 files |
|---|---|---:|---:|
| root-control | 3a2dd9c935e332e811adaccedf04b16bd2de1ea7 | 62 | n/a |
| box-control | dec2def825a474675def51df44d75d534e76508f | 174 | n/a |
| image-build | 0fd3f00cafc7138d3bac9695c87a8ece65821868 | 1730 | n/a |
| host-identify | 1a5eac0b255c995022db6a3a4c0051efffa748cc | 34 | 15 |
| host-discover | **0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80** | 79 | 33 |
| host-install | 325b6c95320d04ad14b987f25e07c1361b7e6f04 | 108 | 42 |

The new host-discover pyproject declares version **0.4.9** with
\`host-identify==0.3.4\` and \`host-install==0.10.0\`, matching both selected
package versions. The incompatible 0.4.8 → 0.4.4 dependency is no longer in
the pinned host-discover source. Previous allowlist paths remain present:
36 of 48 old values are byte-identical and 12 changed; the new closure adds
42 previously missing files (including license texts and all first-party
runtime modules). No historical SHA-256 value was silently relabeled.

The beacon bundle retains the normal pinned-file byte validation:
\`beacon_payload.payload()\` reads exactly the manifest's selected source
paths, rejects altered/missing/symlinked files, verifies each SHA-256, and
writes an immutable deterministic ZIP. The root-owned installer separately
checks full package metadata, package version constraints, original manifest
provenance, and \`pip check\`, and writes a version/source-bound ready receipt
only after validation. Nothing installs source merely because the selector
JSON exists.

## Reproducibility, acceptance and separation of authority

Every new beacon SHA-256 was calculated from a file retrieved by its exact
40-hex Git commit; the Git blob SHA-1 returned by that retrieval was checked
against the pinned immutable recursive tree entry. All six Git trees were
untruncated and contained only normal \`100644\` / executable \`100755\` file
entries. The complete Git object index is an immutable file identity check,
not a substitute for an independently executed **full SHA-256 hash and native
ABI/installer acceptance** of the root-control/box-control/image-build source
trees. Work should recheck the exact selected byte manifests using clean
Git checkouts, \`git rev-parse HEAD\`, \`git rev-parse HEAD^{tree}\`, SHA-256,
isolated Python package import/resolution, and the accepted runtime identities.
No branch-name fallback or private historical source substitution is allowed.

Source-only regression test:
\`python -m pytest -q tests/test_public_publisher_selection.py
tests/test_beacon_payload.py tests/test_public_companion_review.py\`.

This revision **does not** export private Git history, build new image-build
rootfs, rerun native STATE/lease/authentication, enable a gateway issue
trigger, transfer the live compiler workspace, activate AWS/SQS, or publish
anything to public \`zog144/host-deploy\`. Those are separate owner Work gates.
