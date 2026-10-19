# Verification, recovery and release evidence

Host-deploy has fixture-driven local tests and separately documented AWS acceptance. Keep these separate in release claims, especially when gateway, credentials or station production composition changes.

## Verification layers

| Layer | Required evidence | Interpretation |
| --- | --- | --- |
| Local test suite | Source revision, pinned companion versions, `pytest` result | AWS and SSM behavior may be simulated |
| Payload integrity | Exact allowlisted source files and digests | Does not prove a running remote service |
| Remote acceptance | EC2 instance/account binding, SSM receipt, command exit, collected evidence | Covers the specific submitted operation only |
| Reboot recovery | Preserved checkpoint, changed boot identity, phase receipts | Normal reboot, not sudden power loss |
| Gateway dispatch | Admitted immutable request, frozen lane/producer/interpreter binding, prepared/send/observe evidence | No implicit resubmission of an uncertain send |
| Production composition | Verified client/server identity and permissions, protected state, installation and runtime observations | Needs its own explicit cutover authorization |

## Routine checks

The [component manual](README.md) defines verification boundaries; exact local installation/test commands must be checked against the selected source revision or installed command help, not inferred from the aggregate root README. Pin and retrieve companions before running the tests requiring them. Record exact commits, dependencies, selected Python, and environment rather than assuming the latest sibling checkout is compatible.

Use [jobs](JOBS.md), [reboots](REBOOT.md), [recovery](RECOVERY.md), and [artifacts](ARTIFACTS.md) to reproduce bounded non-production operations. [S3](S3.md) uses separately configured credentials and permissions. A guest uptime timer is not an AWS billing cap: see [cloud deadline investigation](CLOUD-DEADLINE.md).

## Claims that require live evidence

Signed discovery has distinct installer, service-active, pending enrollment and signed-accepted states. Gateway source closure requires more than a successful import, and a prepared dispatch is not a completed producer operation. Station deployment probing does not prove software installation or health.

When reporting an acceptance, identify **what was actually executed**, what was deliberately not exercised, exact revisions/instance, and durable receipts. Historical reports and handoffs reside in a separately retained private evidence archive, not included in this public manual; do not fold them into an undated current-state guarantee.

## Change-review checklist

1. Verify expected host/workspace/command identities before state-changing actions.
2. Freeze exact source revisions and their transitive runtime requirements.
3. Preserve an existing operation on uncertain submission; recover rather than retry blindly.
4. Confirm scope of IAM, filesystem credentials, transport and registry approvals independently.
5. Record locally reproducible tests and exact live acceptance, including explicitly untested gates.
