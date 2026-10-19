# Public companion identity review — 2026-10-18

**Owner:** host-deploy Regular. **Status:** private source-review candidate; replacement commits NOT ACCEPTED. No AWS or production mutation.

All six original version-share-handoff.json commits are absent from the new public repositories. The comparison below pins exact public candidate commits (not moving branches). For beacon components, old and public Git trees were compared by exact path, file mode and Git blob SHA. A matching blob SHA proves byte identity, not compatibility with changed APIs. None of the trees was truncated.

| Component | Old private pin (prefix) | Public candidate (exact SHA) | Beacon allowlist comparison |
|---|---|---|---|
| root-control | ae6ffea9 | 3a2dd9c935e332e811adaccedf04b16bd2de1ea7 | not in beacon list; broker/grants tests pending |
| box-control | 85243de4 | dec2def825a474675def51df44d75d534e76508f | not in beacon list; project/runtime tests pending |
| image-build | 3ac6f5c0 | 0fd3f00cafc7138d3bac9695c87a8ece65821868 | not in beacon list; producer tests pending, newer since first review |
| host-identify | adc0e141 | 1a5eac0b255c995022db6a3a4c0051efffa748cc | 9/10 identical |
| host-discover | 31ce7800 | 341255fd0ebdee5eedfd4be9a40829ec17391887 | 11/18 identical |
| host-install | 14dab557 | 325b6c95320d04ad14b987f25e07c1361b7e6f04 | 16/20 identical |

**Differing allowlisted paths:**

- host-identify: pyproject.toml
- host-discover: src/zog/host_discover/__init__.py; box_bridge.py; daemon.py; destinations.py; managed_transport.py; roles.py; pyproject.toml
- host-install: src/zog/host_install/__init__.py; artifact.py; cli.py; pyproject.toml

Thus 36 of 48 files are byte-identical and 12 changed. No historical SHA-256 file allowance has been replaced, and no public revision is accepted as a usable beacon/installer pin yet.

## Offline, fail-closed source review

The new scripts/review_public_companions.py accepts the historical beacon_sources.json and a candidate-selection JSON containing exact clean local public checkout directories, repository names and 40-character commits for host-identify, host-discover and host-install. It verifies Git HEAD, tree cleanliness, canonical source paths, no symlinks, and computes SHA-256 of every allowlisted file. It writes a non-overwriting, review-only JSON report and *always* returns UNAPPROVED-SOURCE-REVIEW, never a production-ready beacon_sources.json replacement. It makes no network, AWS or privileged calls.

The JSON candidate-selection file has schema zog-host-deploy-public-companion-review-v1 and packages mapping three names to objects with exactly repository, commit and directory fields. Example invocation:

```sh
python scripts/review_public_companions.py \
  --historical src/zog/host_deploy/beacon_sources.json \
  --candidates /review/selected-clean-revisions.json \
  --output /review/new-hashes.json
```

Actual file-byte SHA-256 comparisons and packaging/ABI tests are still required in a clean environment. In particular, verify host-identify signature authority; host-discover managed transport, daemon roles and beacon payload; host-install STATE and nonroot identities; box-control/root-control lifecycle and grant semantics; and image-build immutable remote operation. Negative tests must reject missing, stale, tampered or symlinked source. Do not promote changed filenames merely because they exist.

## Historical source and execution boundary

The private candidate excludes version-share-handoff.json (historical, unreachable public revisions), and examples/reboot-smoke.zip (generated binary); the frozen original private repo and know-file review preserve historical provenance. The reproducible examples/build-reboot-smoke.py source builder remains. No live source selector or SSM marker was rewritten. GitHub Actions source CI does not fetch companions or use a private token; the installed gateway's operational owner epoch is unchanged.

**NO-GO:** Full 146-file content/rights/security audit, any missing public replacement checks, source tests, clean-history export, public CI readback, and separate owner GO are outstanding. Do not publish, enable issue-triggered AWS/SQS or promote main based on this review.

## October 18 amended exact source candidate

The earlier historical comparison remains as recorded above, but the current
private candidate now pins **host-discover `0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80`**,
version **0.4.9**, with `host-identify==0.3.4` and `host-install==0.10.0`.
The other five selected immutable public commits are unchanged. The new
`public-companion-publisher.json`, complete six-component Git file object
index and regenerated `beacon_sources.json` contain exact source metadata.
The beacon file closure has grown from 48 to 90 content SHA-256 entries.
This resolves the version declaration mismatch and missing package source
allowlist from the private source candidate, **not** live installation, native
acceptance, a clean history export, or public release authorization.
See [six-component publisher selection](public-publisher-selection-2026-10-18.md).
