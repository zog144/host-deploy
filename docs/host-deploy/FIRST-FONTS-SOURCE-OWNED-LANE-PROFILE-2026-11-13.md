# First Fonts — source-owned lane preparation (2026-11-13)

**Scope: source-only reviewed workflow.** This is not compiler authorization, a new accepted base, catalogue readiness, or permission to send SSM work. The owner remains the *existing* host-deploy workspace for the compiler Host. This design does **not** recover an absent historical prepared record by inventing one: it provides a **distinct, explicitly reviewed new preparation path** when the authoritative owner has established that no earlier record exists.

## Fixed source profile

`host-deploy fonts-lane-profile` displays the reviewed, versioned `host-deploy-first-fonts-managed-lane-v2` selection without accessing AWS:

- Lane: `gateway-first-fonts-runtime`, schema 4, mode `managed`, project root `/var/lib/zog/image-build-lanes/gateway-first-fonts-runtime`.
- Producer: `zog144/image-build@1f07e83dbd80dacb9bed0d6494c697375f0e26cd`.
- October provenance pin: `project/pins/2026-10-01/commit-pin.py` at SHA-256 `d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.
- Producer-required build-record source: `a866c9c4b0dd385045f00ce2de7d809f5b67c104`, checked against `image_build_lanes.expected_build_record_revision`.

The v2 profile intentionally drops the obsolete `worker_resource_gate` object that was included in the uninstalled PR #33 v1 source. Its canonical profile hash therefore changes; old source snapshots and any historically saved v1 profile metadata must not be silently rewritten or treated as v2. The remote controller-facts schema and generic lane-record schema do **not** change. The lane name and project root are **code-derived**, not flags. Generic `lane-prepare --spec` still works for unrelated lanes, but refuses this reserved first-Fonts lane identity. No CLI override can change the producer, monthly pin, root, mode or companion selection. The owner-controlled controller facts are *not* accepted as an arbitrary lane spec.

## Runtime facts: separate, explicit read-only verification

Before a new lane can be prepared, the selected compiler Host must have an independently reviewed **root-owned, non-symlink, non-group/world-writable** controller-facts file at `/etc/zog/first-fonts-controller-facts-v1.json`. It is an installed Host configuration input (not a lane record, catalogue, compiler receipt, or an activation step); its native installation/approval belongs to Work and the controller owner. The verifier does **not** create it or assume that it already exists.

The file has exactly these fields:

| Field | Authority / validation |
| --- | --- |
| `schema` | `host-deploy-first-fonts-controller-facts-v1` |
| `workspace_id`, `account_id`, `region`, `instance_id` | Must equal the existing owner workspace's `workspace.json` + `host.json`; SSM reads the **selected** Host, not an arbitrary caller-selected target |
| `provenance_host_id` | Existing reviewed Host identity recorded in the trusted Host configuration; strict bounded identifier, not an inferred EC2 ID |
| `provenance_project_id` | Reviewed **new** box-control project identity, checked distinct from all retained lane project IDs; not copied from the accepted compiler-base project |
| `observed_state_dir` | Explicit `null` (new lane-local state) or an approved absolute, existing observed state directory distinct from the lane's control state |
| `python_executable` | Normalized absolute executable path verified on the compiler Host |
| `controller` | Exactly `socket_path`, `execution_user_id`, `execution_group_id`, `startup_timeout_seconds`, `execution_timeout_seconds`, `termination_grace_seconds`, `wait_timeout_seconds`, `transport_timeout_seconds`; socket must exist and be a socket, UID/GID must exist on Host, values satisfy lane validation |
| `resource_policy` | Exactly `memory_maximum_bytes`, `thread_count_maximum`, `cpu_weight`, `disk_reservation_bytes`, with existing schema-4 validation. This is configuration, **not** proof of effective limits |

No source/pin/compiler generation or catalogue override fields are permitted in this configuration. It contains **no secrets**. The Host/root filesystem and root-owned configuration are inside Zog's approved trusted-Host boundary; no additional signatures or storage service are introduced. The separate authenticated receipt reader still has to prove that the accepted compiler base belongs to the selected Host and original project. Do not use an arbitrary unreviewed project ID or edit the compiler's accepted receipt to match these facts.

The explicit `host-deploy fonts-lane-verify --workspace OWNER` command uses the workspace's existing Host identity and read-only SSM execution to inspect that root-owned file and check the selected controller socket, UID/GID, Python path and observed state path. Successful verification atomically records `OWNER/first-fonts-verified-facts-v1.json`, including the exact workspace/Host binding, canonical facts SHA-256 and capture time. Preparation requires a matching, unmodified and at-most-3600-second-old verification; missing, stale or changed inputs **hold**.

The verifier may contact the compiler Host, but executes no installation, directory creation, service activation, queue consumption or build. This is deliberately a **different** command from preparation. If the root-owned controller facts or required installed runtime do not yet exist, native Work must establish and review them first, not fabricate a verification response.

## Local preparation and explicit activation

After verification, the authorized owner runs:

```sh
host-deploy fonts-lane-profile
host-deploy fonts-lane-verify --workspace OWNER
host-deploy fonts-lane-prepare --workspace OWNER
```

`fonts-lane-prepare` **never instantiates Host, AWS or SSM**. Under the existing workspace lock it validates the recent observation and *every* `image-build-lanes/*.json` record (including prepared/retired, not only active), rejects corrupt/symlinked history, compares project roots and provenance Project IDs, invokes `fonts_lane_review.review`, and writes only:

```
OWNER/image-build-lanes/gateway-first-fonts-runtime.json
```

The record is schema 4, `state=prepared`, with a frozen full specification, canonical SHA-256, and versioned profile/verified-facts/Host-binding metadata. Identical re-preparation returns the existing record without rewriting it; altered facts, conflicting identities or another matching active Fonts lane **hold**. Preparation does not create `source/`, `state/`, `controller.json` or any other directory on the compiler Host. It never authorizes a compiler-purpose receipt or a catalogue.

Only after explicit digest review may Work select activation:

```sh
host-deploy fonts-lane-activate --workspace OWNER \
  --expected-specification-sha256 sha256:<reviewed-64-hex>
```

Activation rechecks the complete prepared specification hash, current owner workspace/Host identity, recent verified facts, source profile and every retained lane before using the existing `image_build_lanes.activate` remote project/controller installer. Ordinary `lane-activate` without the expected digest is rejected for this reserved lane. The exact source revision and monthly pin are never rewritten in an older lane.

## Independent acceptance boundaries

The accepted compiler base remains **generation** `3805294fc8ccd9589aa75d3a6c5cb9367b7baf84b6ce131a84adafed7d34f9dc`, **kind `image`**, signed receipt digest `a205c07bde4e6cf61e48061affd9a0b40c3a101e18dff67a9871995a3a2afafc`, on compiler EC2 Host `i-00ad300038a599044`. Verification of that receipt, its original compiler project, issuer, accepted source and runtime identity is a separate gate **after** lane preparation. A prepared or active lane does not imply acceptance.

The former Fonts-specific work-space, external-accounting and fixed worker-duration prerequisites were **removed from first-Fonts acceptance**. The profile declares **no Fonts-specific quota, fixed worker deadline or separate resource-admission gate**; neither preparation nor catalogue readiness is conditional on such an envelope. The general lane `disk_reservation_bytes` check is still applied during activation, and ordinary controller timeout fields are still validated as configured. Those general checks must not be interpreted as reinstating the retired Fonts prerequisites.

The schema-4 `resource_policy.memory_maximum_bytes` field is retained for compatibility and passed through to the controller as a requested runtime setting; it is **not** an aggregate host-RAM reservation or evidence of effective `memory.max` enforcement (see PR #32). Investigation of the actual running compiler's per-compilation memory enforcement belongs to the separate execution-control review and **is not a new first-Fonts prerequisite**. No gateway catalogue file, activation, FIFO message, SSM build or Fonts compilation is part of this source pass.

## Source acceptance

Run `python -m pytest -q tests/test_fonts_lane_profile.py tests/test_image_build_lanes.py`, plus the supported Python 3.12/3.13 CI matrix and the existing exact-tuple tests. Unit tests use synthetic Host facts only and must not access AWS. Native Work must authenticate the owning workspace, confirm no matching old prepared record exists, establish the root-owned controller-facts source with the controller owner, run read-only verification, inspect the generated full digest/identities, and only subsequently activate. If any prerequisite is unavailable, report **HOLD** rather than reconstructing an original lane from the historic digest.
