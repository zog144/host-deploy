"""Read-only durable generic build progress: secret-free and restart stable."""
import json
from copy import deepcopy

import pytest

from zog.host_deploy.gateway import generic_reporting as reports
from zog.host_deploy.gateway import consumer

RID = "a" * 32
SRC = "b" * 40
SNAPSHOT = "sha256:" + "c" * 64
PIPELINE = "d" * 32


def configure(monkeypatch, *, record=None, dispatch=True):
    request = {
        "request_id": RID,
        "operation": "build.submit",
        "parameters": {"lane": "lane-xcb", "task": "xcb-support-image-v1"},
        "source": {"repository": "zog144/image-build", "commit": SRC},
    }
    state = {"request": request,
             "states": {"admission": "admitted", "dispatch": "prepared"}}
    binding = {
        "request_id": RID,
        "lane": "lane-xcb",
        "source": {"repository": "zog144/image-build", "revision": SRC},
        "task_catalogue_identity": "sha256:" + "e" * 64,
    }
    seen = []
    monkeypatch.setattr(reports, "load_request",
                        lambda root, ident: seen.append(("load", ident)) or state)
    monkeypatch.setattr(reports, "load_dispatch",
                        lambda root, ident: seen.append(("dispatch", ident)) or
                        ({"phase": "prepared", "binding": binding} if dispatch else None))
    if record is not None:
        monkeypatch.setattr(reports, "generic_status",
                            lambda root, ident: seen.append(("status", ident)) or record)
    return seen, request, binding


def step(*, name="submit", phase="completed", result=None):
    operation_id = "f" * 32
    request = {"operation": "pipeline.submit", "operation_id": operation_id}
    return {
        "name": name, "phase": phase, "operation_id": operation_id,
        "command_id": "command-001", "request": request,
        "result": {"result": result} if result is not None else None,
    }


def receipt():
    return {
        "operation_id": "f" * 32,
        "operation_type": "pipeline.submit",
        "status": "pending", "uncertainty": False,
        "missing_evidence_count": 2,
        "pipeline_id": PIPELINE, "recipe_identity": SNAPSHOT,
        "artifacts": {
            "artifact_digest": "sha256:" + "f"*64,
            "credential_hint": "SENSITIVE_UNSAFE_VALUE_NOT_TO_EXPOSE",
        },
        "failure": None,
    }


def test_preparation_and_admission_are_read_only(monkeypatch, tmp_path):
    seen, _, _ = configure(monkeypatch, dispatch=False)
    status = reports.progress(tmp_path, RID)
    assert status["phase"] == "not_started"
    assert status["pipeline_id"] is None
    assert seen == [("load", RID), ("dispatch", RID)]


def test_durable_report_redacts_remote_values_and_preserves_command_identity(monkeypatch, tmp_path):
    record = {
        "phase": "running", "recipe_identity": SNAPSHOT,
        "pipeline_id": PIPELINE, "stages": [step(result=receipt())],
    }
    seen, _, _ = configure(monkeypatch, record=record)
    before = deepcopy(record)
    report = reports.progress(tmp_path, RID)
    assert report["request_id"] == RID
    assert report["source_revision"] == SRC
    assert report["task"] == "xcb-support-image-v1"
    assert report["current_operation"]["ssm_command_id"] == "command-001"
    assert report["result"]["operation"] == "pipeline.submit"
    assert report["result"]["pipeline_id"] == PIPELINE
    assert report["result"]["missing_evidence_count"] == 2
    assert report["result"]["artifact_names"] == ["artifact_digest", "credential_hint"]
    assert report["result"]["result_sha256"].startswith("sha256:")
    assert report["terminal"] is False
    assert "SENSITIVE_UNSAFE_VALUE_NOT_TO_EXPOSE" not in json.dumps(report)
    assert before == record
    assert seen == [("load", RID), ("dispatch", RID), ("status", RID)]
    assert reports.progress(tmp_path, RID) == report  # restart/read replay is identical


def test_terminal_uncertainty_is_reported_without_new_mutation(monkeypatch, tmp_path):
    record = {"phase": "uncertain", "recipe_identity": None,
              "pipeline_id": None, "stages": [
                  step(name="capabilities", phase="uncertain"),
              ]}
    configure(monkeypatch, record=record)
    report = reports.progress(tmp_path, RID)
    assert report["terminal"] and report["uncertain"]
    assert report["result"] is None
    assert report["stages"][0]["phase"] == "uncertain"


@pytest.mark.parametrize("mutation", [
    {"operation_id": "0" * 32},
    {"operation_type": "worker.submit"},
    {"status": "invented"},
    {"uncertainty": "false"},
    {"missing_evidence_count": -1},
    {"pipeline_id": "/etc/passwd"},
    {"recipe_identity": "latest"},
    {"artifacts": {"secret/path": "unsafe"}},
])
def test_incompatible_retained_receipt_fails_closed(monkeypatch, tmp_path, mutation):
    payload = {**receipt(), **mutation}
    configure(monkeypatch, record={
        "phase": "running", "recipe_identity": SNAPSHOT,
        "pipeline_id": PIPELINE, "stages": [step(result=payload)],
    })
    with pytest.raises(RuntimeError):
        reports.progress(tmp_path, RID)


def test_nonbuild_request_and_invalid_request_id_rejected(monkeypatch, tmp_path):
    _, request, _ = configure(monkeypatch, dispatch=False)
    with pytest.raises(ValueError):
        reports.progress(tmp_path, "../" + RID)
    request["operation"] = "host.status"
    with pytest.raises(ValueError):
        reports.progress(tmp_path, RID)


def test_generic_progress_cli_does_not_create_aws_client(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        consumer, "generic_progress",
        lambda root, ident: {"schema": reports.SCHEMA, "request_id": ident},
    )
    monkeypatch.setattr(consumer, "_client",
                        lambda: pytest.fail("progress must never use AWS"))
    consumer.main([
        "--state-directory", str(tmp_path), "generic-progress", RID,
    ])
    assert json.loads(capsys.readouterr().out)["request_id"] == RID
