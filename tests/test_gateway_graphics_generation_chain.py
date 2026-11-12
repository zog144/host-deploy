"""Synthetic source checks for bounded fonts -> XCB -> X11 predecessor selection.

These fixtures do not authenticate a real producer or grant compiler admission.
"""
from copy import deepcopy
import json

import pytest

from zog.host_deploy.gateway import graphics_generation_chain as chain
from zog.host_deploy.gateway import graphics_catalogue_owner as first
from zog.host_deploy.gateway import task_catalogue

BASE = "a" * 64
FONTS = "b" * 64
XCB = "c" * 64
OWNER = "fixture-host"
LANE = "graphical-test-lane"


def catalogue(task, generation):
    fixed = task_catalogue.REVIEWED_IMAGE_TASKS[task]
    data = {"schema": task_catalogue.SCHEMA, "tasks": {task: {
        "source_repository": first.REPOSITORY,
        "source_revision": first.SOURCE, "lane": LANE,
        "lane_owner": OWNER,
        "monthly_pin_repository_path": first.PIN_PATH,
        "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
        "pin_date": first.PIN_DATE,
        "entries": [{"id": n, "project": p, "recipe": r}
                    for n, p, r in fixed["entries"]],
        "arguments": {
            "mode": "image",
            "selection": BASE,
            # Exact accepted compiler receipt remains fixture-only, not an
            # authorization by this synthetic predecessor-chain test.
            **({"compiler_base": "sha256:" + "4" * 64}
               if task == chain.TASKS[0] else {}),
            **({"graphical_predecessor": generation}
               if task != chain.TASKS[0] else {}),
            "targets": list(fixed["targets"]),
        },
    }}}
    return task_catalogue.validate(data)


def scenario():
    fonts = catalogue(chain.TASKS[0], BASE)
    first_receipt = {
        "schema": first.RECEIPT_SCHEMA,
        "catalogue_sha256": chain._hash(fonts),
        "accepted_base_generation_id": BASE,
        "accepted_base_receipt_sha256": "sha256:" + "4" * 64,
        "source_revision": first.SOURCE,
        "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
        "host_id": OWNER, "installation_id": "fixture-install",
        "lane": LANE, "lane_owner": OWNER,
        "task_allowlist": [chain.TASKS[0]], "compiler_authorized": False,
        "status": "installed-catalogue-not-native-compiler-admission",
    }
    policy = {
        "schema": chain.SCHEMA, "host_id": OWNER,
        "installation_id": "fixture-install",
        "lane": LANE, "lane_owner": OWNER,
        "project_root": "/home/owner/" + LANE,
        "source_revision": first.SOURCE,
        "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
        "first_catalogue_sha256": chain._hash(fonts),
        "first_receipt_sha256": chain._hash(first_receipt),
        "first_base_generation_id": BASE,
        "first_base_receipt_sha256": "sha256:" + "4" * 64,
        "task_allowlist": list(chain.TASKS), "max_generations": 3,
        "work_bytes": 30 * 1024**3, "external_bytes": 2 * 1024**3,
        "dedicated_storage_bytes": 32 * 1024**3,
        "execution_limit_seconds": 21600,
    }
    return policy, fonts, first_receipt


def evidence(policy, task, catalogue_value, output, *, request_id="1" * 32):
    return {
        "schema": chain.EVIDENCE, "task": task,
        "host_id": policy["host_id"],
        "installation_id": policy["installation_id"],
        "lane": policy["lane"], "lane_owner": policy["lane_owner"],
        "project_root": policy["project_root"],
        "source_revision": first.SOURCE,
        "monthly_pin_identity": policy["monthly_pin_identity"],
        "request_id": request_id, "pipeline_id": "2" * 32,
        "predecessor_catalogue_sha256": chain._hash(catalogue_value),
        "input_generation_id":
            catalogue_value["tasks"][task]["arguments"]["selection"],
        "output_generation_id": output, "output_kind": "image",
        "generation_manifest_sha256": "sha256:" + "3" * 64,
        "acceptance_receipt_sha256": "sha256:" + "4" * 64,
        "producer_receipt_sha256": "sha256:" + "5" * 64,
        "status": "accepted", "terminal_outcome": "success",
        "uncertainty": False, "missing_evidence_count": 0,
    }


def promote(policy, predecessor, previous, installed, proof):
    return chain.resolve_successor(
        policy=policy, previous_task=predecessor,
        previous_catalogue=previous, previous_receipt=installed,
        accepted_generation=proof)


def test_finite_successors_never_rewrite_fonts_or_autosubmit():
    p, original, installed = scenario()
    original_raw = chain._canonical(original)
    first_proof = evidence(p, chain.TASKS[0], original, FONTS)
    xcb = promote(p, chain.TASKS[0], original, installed, first_proof)
    assert xcb["next_task"] == chain.TASKS[1]
    assert xcb["compiler_authorized"] is False
    assert set(xcb["catalogue"]["tasks"]) == {chain.TASKS[1]}
    assert xcb["catalogue"]["tasks"][chain.TASKS[1]]["arguments"]["selection"] == BASE
    assert xcb["catalogue"]["tasks"][chain.TASKS[1]]["arguments"]["graphical_predecessor"] == FONTS
    assert xcb["catalogue_sha256"] == chain._hash(xcb["catalogue"])
    assert chain._canonical(original) == original_raw

    second_proof = evidence(
        p, chain.TASKS[1], xcb["catalogue"], XCB, request_id="6" * 32)
    x11 = promote(p, chain.TASKS[1], xcb["catalogue"],
                  xcb["receipt"], second_proof)
    assert x11["next_task"] == chain.TASKS[2]
    assert x11["catalogue"]["tasks"][chain.TASKS[2]]["arguments"]["selection"] == BASE
    assert x11["catalogue"]["tasks"][chain.TASKS[2]]["arguments"]["graphical_predecessor"] == XCB
    assert x11["receipt"]["previous_catalogue_sha256"] == xcb["catalogue_sha256"]
    assert x11["receipt"]["predecessor_pipeline_id"] == second_proof["pipeline_id"]
    assert set(x11["catalogue"]["tasks"]) == {chain.TASKS[2]}
    with pytest.raises(chain.ChainBlocked):
        promote(p, chain.TASKS[2], x11["catalogue"], x11["receipt"],
                second_proof)
    assert all("selection" in v["arguments"] for v in x11["catalogue"]["tasks"].values())


@pytest.mark.parametrize("name,bad", [
    ("status", "completed"), ("uncertainty", True),
    ("terminal_outcome", "failed"), ("missing_evidence_count", 1),
    ("task", chain.TASKS[1]), ("lane", "other-lane"),
    ("lane_owner", "other-host"), ("host_id", "other-host"),
    ("installation_id", "other-install"),
    ("source_revision", "f" * 40),
    ("monthly_pin_identity", "sha256:" + "0" * 64),
    ("predecessor_catalogue_sha256", "sha256:" + "0" * 64),
    ("input_generation_id", FONTS), ("output_generation_id", BASE),
    ("output_generation_id", "BAD"),
    ("generation_manifest_sha256", "sha256:BAD"),
    ("acceptance_receipt_sha256", "sha256:BAD"),
    ("producer_receipt_sha256", "sha256:BAD"),
    ("pipeline_id", "BAD"), ("request_id", "BAD"),
    ("output_kind", "toolchain"),
])
def test_rejects_forged_or_incomplete_predecessor(name, bad):
    p, old, receipt = scenario()
    proof = evidence(p, chain.TASKS[0], old, FONTS)
    proof[name] = bad
    with pytest.raises(chain.ChainBlocked):
        promote(p, chain.TASKS[0], old, receipt, proof)


def test_absent_or_extra_evidence_fails_closed():
    p, old, receipt = scenario()
    proof = evidence(p, chain.TASKS[0], old, FONTS)
    for changed in (dict(proof, extra_field="data"),
                    {k:v for k,v in proof.items() if k != "pipeline_id"}):
        with pytest.raises(chain.ChainBlocked):
            promote(p, chain.TASKS[0], old, receipt, changed)


@pytest.mark.parametrize("field,new", [
    ("max_generations", 4), ("task_allowlist", list(reversed(chain.TASKS))),
    ("execution_limit_seconds", 21601),
    ("work_bytes", 29 * 1024**3),
    ("first_base_generation_id", FONTS),
    ("source_revision", "f" * 40),
    ("first_catalogue_sha256", "sha256:" + "0" * 64),
])
def test_policy_drift_refused(field, new):
    p, cat, receipt = scenario()
    p[field] = new
    with pytest.raises(chain.ChainBlocked):
        promote(p, chain.TASKS[0], cat, receipt,
                evidence(scenario()[0], chain.TASKS[0], cat, FONTS))


def test_predecessor_receipt_drift_refused():
    p, cat, receipt = scenario()
    proof = evidence(p, chain.TASKS[0], cat, FONTS)
    for field, value in (("host_id", "different"),
                         ("compiler_authorized", True),
                         ("accepted_base_generation_id", FONTS)):
        bad = dict(receipt, **{field: value})
        with pytest.raises(chain.ChainBlocked):
            promote(p, chain.TASKS[0], cat, bad, proof)


def test_cycle_and_wrong_predecessor_refused():
    p, cat, receipt = scenario()
    for output in (BASE, "a" * 64):
        with pytest.raises(chain.ChainBlocked):
            promote(p, chain.TASKS[0], cat, receipt,
                    evidence(p, chain.TASKS[0], cat, output))
    with pytest.raises(chain.ChainBlocked):
        promote(p, "xcb-support-image-v1", cat, receipt,
                evidence(p, chain.TASKS[0], cat, FONTS))


def test_root_native_operation_denies_nonroot_before_trusted_read(monkeypatch):
    seen = []
    monkeypatch.setattr(chain.os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError):
        chain._install_with_attesters(
            previous_task=chain.TASKS[0],
            attest_native_owner=lambda _: seen.append("owner"),
            attest_accepted_predecessor=lambda *args: seen.append("producer"))
    assert seen == []


def test_source_has_no_submission_or_mutable_global_catalogue():
    import inspect
    s = inspect.getsource(chain)
    assert "toolchain.submit(" not in s
    assert "build.submit(" not in s
    assert "StartTransientUnit" not in s
    assert "O_EXCL" in s
    assert "require_root_owned=True" in s
    assert "attest_accepted_predecessor(" in s
    assert '"compiler_authorized": False' in s
