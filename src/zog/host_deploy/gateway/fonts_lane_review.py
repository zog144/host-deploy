"""Read-only first Fonts managed-lane reconciliation.

A historical lane's source revision and monthly pin are immutable identity
inputs. Never edit its JSON to make a catalogue pass. A distinct replacement
lane may be reviewed using image_build_lanes.specification()/prepare() later,
but this module neither writes nor activates anything.
"""
from .. import image_build_lanes
from . import graphics_catalogue_owner as fonts


class FontsLaneHeld(ValueError):
    """A selected original producer lane is absent or ambiguous."""


def _record(record):
    if (type(record) is not dict or
            set(record) < {"schema", "lane", "specification", "state"} or
            record["state"] not in ("prepared", "active", "retired")):
        raise FontsLaneHeld("invalid retained lane record")
    spec = image_build_lanes.validate(record["specification"])
    if (record["lane"] != spec["lane"]
            or record["schema"] != spec["schema"]):
        raise FontsLaneHeld("foreign or inconsistent retained lane")
    return spec


def _matches(spec):
    return (
        spec["schema"] == image_build_lanes.SCHEMA
        and spec["mode"] == "managed"
        and spec["source_repository"] == fonts.REPOSITORY
        and spec["source_revision"] == fonts.SOURCE
        and spec["monthly_pin_repository_path"] == fonts.PIN_PATH
        and spec["monthly_pin_identity"] == "sha256:" + fonts.PIN_SHA256
    )


def review(records, proposed_spec=None):
    """Report existing matching lane, or a distinct unprepared proposal.

    In both cases the digest covers the COMPLETE validated specification,
    including controller configuration and actual identity and runtime fields.
    Without an actual proposed specification, there is no genuine digest to
    invent. The returned result never represents native admission.
    """
    if type(records) is not list:
        raise FontsLaneHeld("retained lane records must be an exact list")
    known = {}
    for record in records:
        spec = _record(record)
        lane = spec["lane"]
        if lane in known:
            raise FontsLaneHeld("duplicate retained lane identity")
        known[lane] = (record["state"], spec)
    matched = [(name, spec) for name, (state, spec) in known.items()
               if state == "active" and _matches(spec)]
    if len(matched) > 1:
        raise FontsLaneHeld("multiple existing active first-Fonts lanes")
    if matched:
        if proposed_spec is not None:
            raise FontsLaneHeld("existing matching lane; no replacement permitted")
        name, spec = matched[0]
        return {
            "status": "MATCHING_ACTIVE_LANE_SOURCE_ONLY",
            "lane": name,
            "specification_sha256": image_build_lanes.specification_sha256(spec),
            "source_revision": fonts.SOURCE,
            "monthly_pin_identity": "sha256:" + fonts.PIN_SHA256,
            "mutated": False,
        }
    if proposed_spec is None:
        return {
            "status": "NO_MATCHING_ACTIVE_LANE_REVIEW_REQUIRED",
            "examined": len(known),
            "mutated": False,
        }
    try:
        spec = image_build_lanes.validate(proposed_spec)
    except (KeyError, TypeError, ValueError) as exc:
        raise FontsLaneHeld("proposed lane is invalid") from exc
    if not _matches(spec):
        raise FontsLaneHeld("proposed lane has different compiler source or pin")
    if spec["lane"] in known:
        raise FontsLaneHeld("cannot replace or rebind any existing lane")
    for _, (_, old) in known.items():
        if (spec["project_root"] == old["project_root"]
                or spec["provenance_project_id"] == old["provenance_project_id"]):
            raise FontsLaneHeld("new lane must own a distinct project identity")
    return {
        "status": "DISTINCT_LANE_PROPOSAL_NOT_PREPARED",
        "lane": spec["lane"],
        "specification_sha256": image_build_lanes.specification_sha256(spec),
        "source_revision": fonts.SOURCE,
        "monthly_pin_identity": "sha256:" + fonts.PIN_SHA256,
        "mutated": False,
    }
