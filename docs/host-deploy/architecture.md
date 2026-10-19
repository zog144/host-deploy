# Architecture and trust boundaries

Host-deploy owns cloud development infrastructure and durable remote execution transport. It is not the application runtime controller, the image-build producer, the station registry, or the host's root identity authority.

## Components

| Component | Responsibility | Important limit |
| --- | --- | --- |
| Local workspace | Persist host identity, AWS binding, job intent and recovery records | Cloned active workspaces cannot safely own the same host concurrently |
| EC2 provisioning | Create/start/stop an explicitly tagged owned development instance | Dry-run and `doctor` do not guarantee full later authorization |
| SSM transport | Submit bounded commands and observe their remote receipts | Submission uncertainty must never trigger blind resend |
| Remote systemd job | Run an explicit recipe and preserve results across caller disconnect | Does not automatically shut down the host |
| Checkpoint/handoff | Transfer durable workspace ownership | Restoring does not itself create a new instance |
| Reboot workflow | Two-phase normal reboot and reconnect observations | Does not simulate abrupt power loss |
| Signed discovery installer | Stage exact vetted companion sources and preserve host identity | Cannot approve registry key or grant archive role |
| Gateway and image-build lanes | Authorized queue/ledger, lane bindings and durable remote producer dispatch | Importability alone does not prove source pin or dependency closure |
| Station deployment adapter | Constrained station operations with persisted intent/receipt | Not a general remote shell |

The primary operational references are [jobs](JOBS.md), [recovery](RECOVERY.md), [discovery](DISCOVERY.md), [gateway dispatch](GATEWAY-DISPATCH.md), [lanes](IMAGE-BUILD-LANES.md), and [station deployment jobs](STATION-DEPLOYMENT-JOBS.md).

## Durable identity and request boundaries

An initialized workspace has a stable UUID and recorded AWS ownership constraints. The running host is independently identified by EC2 instance and account. Remote submissions retain their request IDs, SSM command IDs, and immutable selected source/operation bindings. Once the send boundary is uncertain, the correct next action is observation/recovery, not a fresh submission using mutable settings.

For gateway work, separate authorization and SQS intake from persistent consumer, prepared dispatch and SSM remote execution. A saved failed or uncertain operation cannot simply be overwritten after changing a checkout or interpreter. Lost-workspace [adoption](GATEWAY-ADOPTION.md) is exceptional and evidence-bound.

## Separate Zog owners

- `image-build` controls build recipes, rootfs semantics and the producer-owned runtime preflight.
- `box-control` / `root-control` control application runtime units and lifecycle.
- `host-identify` controls host identity, while `host-discover` transports authorized signed observations.
- `station-access` owns operator-facing registry, approval and station integrations.

Deployment, source pinning, and permissions must be reviewed together at each integration point. Passing host-deploy transport tests does not establish the other programs' semantic acceptance.
