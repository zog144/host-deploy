# host-deploy development instructions

The development repository is https://github.com/zog144/host-deploy (public source).

User rule: commit each new implementation pass to this repository. Use version-share
using explicitly approved exact public source revisions where possible, inspect status before publication, and report
the resulting commit and validation. Never claim a pass is published if upload fails.
Preserve concurrent changes; do not force an update over another controller's work.

Keep AWS/GitHub credentials, private beacon identities, and live host workspace state
outside the source tree. Use standalone host-discover and host-identify pins; do not recreate a beacon
source bundle. The payload assembler verifies the allowlist in
src/zog/host_deploy/beacon_sources.json. Refresh pins/hashes together after testing.

Run the relevant tests before committing implementation changes. Default local suite:
`python3 -m pytest -q tests`. Live AWS acceptance is separate and must be reported
separately from local tests. Do not infer live compatibility from historical evidence.

Private historical acceptance documents are not part of the public source tree.
A passing source CI job is not a live AWS deployment authorization.

## Source hygiene (user policy, 2026-10-03)

Apply the installed `zog-source-hygiene` skill before publishing. Keep original Zog
implementation in Git; retrieve external dependencies from pinned sources. Document
narrow exceptions for necessary patches, legal notices and fixtures. Do not commit
wheels, eggs, generated bundles, dependency trees or transport archives. Keep required
fixtures readable and generate payloads outside the checkout. Preserve maintained
migrations and required notices; send chat evidence/handoffs to know-file. Review the
actual outgoing file list; ignore rules alone do not remove tracked artifacts.
