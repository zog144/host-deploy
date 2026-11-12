# First Fonts — retained compiler project versus execution-lane binding (2026-11-12)

**Owner: host-deploy Regular → host-deploy Work connection. SOURCE-ONLY. Native installation, gateway configuration and dispatch remain HOLD.**

## Current observed Host facts (Work handoff)

- Gateway: `i-0b7b456d4cea414af`, installed `zog-task-c-gateway.service` is static/inactive. Neither `/var/lib/host-deploy-gateway/first-fonts-catalogue-v1.json` nor `first-fonts-catalogue-receipt-v1.json` exists, and no catalogue CLI flags are installed. Do not start, enable or run `--once`.
- Compiler: `i-00ad300038a599044`, original retained generation `3805294f…`; exact root-owned `0400` accepted receipt SHA-256 `a205c07bde4e6cf61e48061affd9a0b40c3a101e18dff67a9871995a3a2afafc`. The independently protected issuer is present. Prior native signed acceptance—not a source SHA—is the source of compiler authority.
- Read-only checks were SSM `83b4dced-4dac-4b08-bc09-1c73b87541ba` (compiler), `8f7b5437-e799-4889-93ba-bda3a885ecdf` (gateway state), and `ebb85747-a979-41a0-8400-75b6158f9006` (installed module hashes). No modifications occurred.

## Installed source tuple and compatibility

Previously observed installed gateway source blobs, in `zog.host_deploy`:

| Module | Git blob SHA-1 | Reviewed source |
| --- | --- | --- |
| `gateway/task_catalogue.py` | `c96218c9312fd5447aa386711438e9b458008d16` | PR #30 |
| `image_build_lanes.py` | `998354c9ca6458c2df5d08a282c0a5c54c4ab01b` | PR #30 / PR #7 |
| `gateway/graphics_catalogue_owner.py` | `b1446781fccba653ff0146a6d15f6cda35ad8ffa` | PR #30 / former PR #7 |
| `gateway/graphics_base_acceptance.py` | `fab7f59bb43afdc057339a9e80d7d3b548b4d5b2` | independently pinned PR #29 consumer |

This was a **coherent PR #30 source selection** at the time of the read-only Host inspection, not a random splice. PR #7 used a different `task_catalogue.py` blob `c7a02b950d78edf656d5478b2e01234a77191ab2` because PR #30 additionally retains XCB/X11 graphical-predecessor enforcement. The target `fonts` recipe map and compiler-base receipt rule agree. An exact-pinned source test has now passed with the source tuple using the real PR #7 synthetic signed compiler fixtures. Source CI does NOT prove the installed Host environment is complete; Work must still verify wheel/venv dependency closure, imported source bytes and genuine readers.

**The PR #7 owner has since been extended to support separate original compiler and execution-lane provenance.** The installed `b144678…` owner does **not** have this new capability. Stage a complete reviewed wheel/runtime using host-install; **never patch `/opt/zog/task-c/venv` in place**. Recheck the exact selected tuple after companion pin updates. The native service stays inactive.

## Why the existing lanes cannot be relabelled

The execution lane is not merely informational: `image_build_dispatch.verify_current_target` compares its installed `source_revision`, monthly pin path and monthly pin identity with the immutable dispatch. The original first-Fonts source is `image-build@1f07e83dbd80dacb9bed0d6494c697375f0e26cd`, October pin path `project/pins/2026-10-01/commit-pin.py` and digest `sha256:d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36`.

The two active retained lanes described in Work's handoff do not satisfy **both** the exact revision and digest. One has the correct pin with the wrong source revision; the other has neither. Rewriting either source revision or pin in its retained file would falsify past operations and is **not permitted**.

Separately, the accepted compiler's signed receipt binds its **original** `project_id`, Host, installation and probe. A new Fonts execution lane should normally have a **distinct** project ID and root, not impersonate that original compiler project. Old owner code wrongly required the destination lane's `provenance_project_id` to equal the compiler's original project. The revised owner permits `read_compiler_base_origin_lane(generation_id)` from a trusted retained-lane reader, while continuing to check the signed original receipt against that original project using the **unchanged** independently reviewed `graphics_base_acceptance.checked_base`. It separately checks the destination lane against the reviewed Fonts source and October pin, and requires the same authenticated Host but distinct roots/project IDs for genuinely separate lanes. No new signed approval, per-task policy file, or fabricated receipt is created.

## Review a distinct lane (no state mutation in Regular)

`fonts_lane_review.review(retained_records)` returns `NO_MATCHING_ACTIVE_LANE_REVIEW_REQUIRED` unless exactly one **active** managed schema-4 lane matches the reviewed source and pin. The read-only `review(retained_records, proposed_spec)` validates the proposed schema-4 `image_build_lanes` specification, refuses reuse of any existing lane name, project root or project ID, and yields the canonical **`image_build_lanes.specification_sha256(proposed_spec)`** together with `DISTINCT_LANE_PROPOSAL_NOT_PREPARED`. It never writes or activates a lane.

The intended execution lane must be managed, have a unique operator-selected name/project root/project ID, and bind exactly the original `SOURCE` and `PIN_PATH`/`PIN_SHA256` above. The actual `provenance_host_id`, `python_executable`, observed STATE path, controller identity, execution UID/GID, and normal lane `resource_policy` and controller timeouts **must be derived from authenticated existing native Host data**, not invented in a source handoff. The first-Fonts-specific 30+2 GiB/XFS/six-hour policy is gone; ordinary existing lane schema fields are not permission to restore those special gates.

**There is no trustworthy exact proposed lane digest yet**, because the full real specification and retained identities have not been supplied here. Claiming a digest from placeholders would defeat the purpose of that binding. Work must publish the actual validated full spec/digest and obtain review **before** calling the existing `image_build_lanes.prepare`, `activate`, or changing any active binding. Existing old lane files must remain byte-identical.

## Native sequence after both source and lane gates

1. Re-stage the coherent reviewed host-deploy/host-install runtime as a standard selected wheel, leaving `zog-task-c-gateway.service` inactive and disabled. Verify module Git blob hashes, pinned compiler reader, original source revision, installed pin bytes and Python dependency closure, including `pip check`.
2. Read the original accepted compiler's real issuer/receipt and its original retained lane/project identity. Read both existing lanes and all their specifications/digests without mutation. Review the distinct new lane specification and digest with the source helper, then use the normal authenticated lane `prepare`/`activate` lifecycle **only after separate approval**.
3. Use the installed trusted `read_managed_lane(lane_name)` for the new execution lane and `read_compiler_base_origin_lane(generation_id)` for the old accepted compiler project. Independently read the genuine root-owned signed compiler receipt, issuer policy and protected producer binding; `checked_base` must validate all original signed fields, including project ID, Host and installation. This is a distinct source/target binding, not an approval-file override.
4. Install **exactly** `/var/lib/host-deploy-gateway/first-fonts-catalogue-v1.json` and `first-fonts-catalogue-receipt-v1.json` through `graphics_catalogue_owner.install_native`. Require root ownership, mode 0600, O_EXCL, fsync, catalogue digest agreement and exact task `graphics-fonts-image-v1`; verify receipt generation, issuer, source and managed lane.
5. Only after the files exist, configure the already-staged unit with `--advance-reviewed-generic`, `--approved-task-catalogue` and the exact installed `--approved-task-catalogue-sha256` flags. Rerun **read-only** readiness checks and leave the static unit **inactive**. Do not run the queue consumer, `run --once`, SendMessage or SendCommand.

**No Host files, retained lanes, installation, SQS/SSM, AWS IAM, compiler job or service state were changed in Regular source review.**
