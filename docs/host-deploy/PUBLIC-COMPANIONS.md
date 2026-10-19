# Public companion revisions and acceptance scope

The current exact public selector is `public-companion-publisher.json` and the
90-file beacon allowlist is `src/zog/host_deploy/beacon_sources.json`. All six
Git revisions, trees and 2,187 tracked files were verified against clean exact
checkouts. The beacon packages built and installed together; dependency checks,
required installed imports, notices, service assets and source-bound readiness
receipt passed. Selected controller/producer and confined STATE/admission/beacon
fixtures passed. The corrected host-deploy suite passed 537 nonroot tests,
110 source-CI selection tests and 15 confined native delivery tests.

These are source/package/fixture results, not production activation approval.
Live STATE mounts, NSS provisioning, full controller/issuer lifecycle and reboot
integration remain separate acceptance gates. Source publication and deployment
require separate decisions; publishing code never transfers ownership or permits
replay of uncertain requests. See [migration boundary](PUBLIC-MIGRATION-BOUNDARY.md).

Older compatibility revisions retained in guides are historical contract context,
not installation defaults. Do not substitute them for the current manifest or
silently alter allowlisted hashes. Any future repin must verify clean immutable
sources, paired APIs, package metadata, hash closure and negative drift tests.

## October 18 exact public candidate — superseding historical source identities

The reviewed private source candidate now pins all six public commits in
`public-companion-publisher.json`; the complete 2,187-file Git object index is
`docs/host-deploy/public-companion-git-objects-2026-10-18.json`.
The three-package beacon descriptor contains **90 SHA-256-pinned files** from
`host-identify@1a5eac0`, `host-discover@0f2c6fd`, and
`host-install@325b6c9`, including package metadata, notices, missing certificate
modules and packaged systemd assets. New host-discover declares 0.4.9 with
`host-install==0.10.0` and `host-identify==0.3.4`; that declared-version
conflict is corrected in the candidate. These have passed the scoped checks above; they do not constitute
full production interoperability or publication GO. The historical identity
limitations above describe the original private source and do not negate this
new source-only repin.
