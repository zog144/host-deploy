# Host inventory and provisioning

## Purpose and host ownership

Host-deploy provisions development/acceptance EC2 instances and coordinates remote trusted commands via AWS Systems Manager. It keeps an independently initialized **workspace UUID** and a saved cloud identity for each managed host. The saved AWS account/region/instance and EC2 tags `ManagedBy=host-deploy` and `ZogWorkspace=<workspace-id>` must agree with observed inventory before an operation. This is not the graphical station-access workspace used for TurboVNC.

An ordinary managed host is one owned EC2 instance associated with its workspace, not a mutable label-to-IP mapping. Provisioning or reusing a stopped host has cost and data-lifetime consequences; a terminated machine does not silently become a replacement under the old workspace. Initialize a distinct identity for replacement infrastructure.

## Prerequisites and operator configuration

The local controller uses Python, boto3, valid AWS credentials and API access. The target requires a suitable reviewed AMI, subnet/security group and instance role, SSM Agent connectivity, systemd and enough disk, memory and uptime budget for its workload. Configuration examples are **development templates**, not portable production infrastructure: `examples/systemd-host.json` uses small fixture resources and must be reviewed for the selected account, region and task.

The [component manual](../README.md), [interface reference](interface-reference.md) and [authentication/ownership](authentication-and-ownership.md) chapters describe installation and the `host-deploy init`/`doctor`/`provision`/`start` responsibilities; use the pinned CLI's own `--help` for exact flags. Dry-run/preflight checks precede billable allocation; a successful `doctor` or STS identity read does not prove SSM, EC2 mutation, S3, instance-role, host runtime or cross-service permissions. Source archives, credentials, checkpoints and resulting durable state must reside in separately controlled paths, not copied into a Git release.

## Provision, admit and operate

1. Initialize a dedicated workspace with expected cloud account, region and identity; review the host spec, tags, image, storage, network, IAM and allowed uptime.
2. Perform available read-only inventory/preflight checks. Confirm a usable SSM-capable target rather than assuming that EC2 "running" means the guest is ready.
3. Explicitly provision/start only after authorization and ensure observed instance/workspace ownership agrees with the saved record.
4. Wait for SSM and required guest services; check cloud-init and the guest uptime timer before submitting finite jobs.
5. Reserve compiler lanes and required memory/disk budgets **without sharing mutable image-build project state** between independent lanes.
6. Persist job/request/SSM command and artifact identities before disconnecting. Inspect previous accepted work on return; do not allocate another host or resubmit a command merely because a reply was lost.
7. Stop or terminate only after resolving running/uncertain jobs and preserving checkpoints, receipts and any remaining attached resources.

The [generic job contract](../JOBS.md) uses trusted ZIP sources and argv recipes; it is **not** a sandbox for untrusted arbitrary users. Jobs may outlive the calling Work container. Small-box sample resources in [starter recipes](../STARTER-RECIPES.md) are for targeted acceptance, not a recommendation for LFS compiler workloads.

## Registered host discovery and enrollment

Installing a host-discover beacon is an **explicit supported host operation**, not something that happens by copying station-access source to a host. The [signed discovery installer](../DISCOVERY.md) requires the matching command center readiness, reviewed exact host-discover/host-identify source pins, suitable target Python, account/instance binding and appropriate public/custom CA trust. The host creates its durable key locally; the command center must separately approve the fingerprint. Saving an installation receipt does not grant archive collection, DNS authority or remote compiler control.

An existing bearer reporter migration needs the dedicated migration procedure and identity continuity safeguards. Do not treat earlier version-specific source instructions as proof that a live host is running those exact versions. Host-install owns boot/disk identity, host-identify owns keys, and station-access owns registry approval.

## Gateway-owned compiler host is special

A Work-owned compiler workspace must be transferred through an authentic retiring checkpoint before a gateway becomes its writer. Lost-workspace adoption is a separate exceptional procedure with explicit old-writer quiescence, inventory/epoch verification and owner marker durability. A source-only gateway or RPC test does not authorize a cutover or a second writer over the same compiler project.

For gateway ownership, admission and remote dispatch consult [authentication and ownership](authentication-and-ownership.md), [compiler gateway](compiler-gateway-and-dispatch.md) and [recovery](recovery-reboot-and-runbooks.md). A station-access mTLS observer reads owner-ledger state but does not inherit host-deploy's SSM mutation authority.

## Resource, security and recovery cautions

- **Uptime timer:** guest-systemd enforced, not a guaranteed AWS-side billing stop; [cloud deadline research](../CLOUD-DEADLINE.md) is not enabled.
- **Credentials:** default SDK chain, explicit credential storage and assumed roles require separate controlled review; do not export credentials in job logs.
- **Artifacts:** source/result transfers are content bound and may be resumable, but SSM limits and optional S3 acceptance differ; read [artifact handling](../ARTIFACTS.md).
- **Checkpoints:** restoring copied active checkpoints can create two writers; follow [retiring handoff](../RECOVERY.md), or [explicit lost-workspace adoption](../GATEWAY-ADOPTION.md) only when justified.
- **Boot tests:** normal two-phase reboot with changed boot ID is not sudden power-loss testing; read [reboot acceptance](../REBOOT.md).

## Authoritative references

- [Canonical host-deploy manual and provisioning boundaries](../README.md)
- [Signed host-discover installation](../DISCOVERY.md)
- [Starter recipes and acceptance-host sizing](../STARTER-RECIPES.md)
- [Durable job and artifact transport](../JOBS.md), [artifacts](../ARTIFACTS.md)
- [Cloud/owner authorization](authentication-and-ownership.md)
- [Concurrent compiler lanes](jobs-compiler-lanes-and-storage.md)
- [Ownership handoff and recovery](recovery-reboot-and-runbooks.md)

These are reader-facing instructions, not operator approval to provision AWS resources or modify a current host.
