"""Isolated typed-toolchain SSM supervisor, interruption and receipt tests."""
import json
from contextlib import contextmanager

import pytest

from zog.host_deploy.gateway import toolchain_supervisor as supervisor
from zog.host_deploy.gateway import toolchain_journal as journal

GATEWAY = "a" * 32
SOURCE = {"repository": "zog144/image-build", "revision": "b" * 40}
SPEC = "sha256:" + "c" * 64
GEN = "d" * 64
VERIFY = "sha256:" + "e" * 64


def frozen_binding():
    return {
        "request_id": GATEWAY, "task_catalogue_identity": "sha256:" + "f" * 64,
        "source": SOURCE, "task": {
            "seed_generation": "a" * 64, "specification_identity": SPEC,
        },
    }


def fake_result(stage):
    request = stage["remote_request"]
    operation = request["operation"]
    if operation == "toolchain.specification.inspect":
        return {
            "status": "completed", "uncertainty": False,
            "artifacts": {"toolchain_specification": {
                "contract": "image-build-toolchain-specification-v1",
                "identity": SPEC,
                "bootstrap_pipeline": {
                    "remote_execution_status": "available",
                    "remote_execution": {"phases": list(journal.PHASES[:6])
                                         + [journal.RECOVERY]
                                         + list(journal.PHASES[6:])},
                },
            }},
        }
    kind = operation.split(".")[-1]
    phase = (request["arguments"]["phase"] if kind == "submit"
             else stage["test_phase"])
    submission_id = (request["operation_id"] if kind == "submit"
                     else request["arguments"]["operation_id"])
    predecessor = (
        request.get("predecessor") if kind == "submit"
        else stage["test_predecessor"]
    )
    status = "pending" if kind == "submit" else "completed"
    artifact = None
    if phase == "final-compiler" and status == "completed":
        artifact = {
            "contract": "image-build-toolchain-artifact-v1",
            "profile": "self-hosted-c-cxx-toolchain-v1",
            "specification": SPEC, "verification": VERIFY,
            "activation": "toolchain-active",
        }
    outputs = {"generation": GEN}
    if artifact is not None:
        outputs["toolchain_artifact"] = artifact
    return {
        "status": status, "uncertainty": False,
        "terminal_outcome": "success" if status == "completed" else None,
        "selected_generation": GEN,
        "attempt_ids": ["attempt-kept"],
        "allowed_next_operations": (["toolchain.inspect", "toolchain.resume"]
                                    if status == "pending" else ["toolchain.inspect"]),
        "artifacts": {"toolchain_execution": {
            "contract": "image-build-toolchain-remote-execution-v1",
            "phase": phase, "operation_id": submission_id,
            "specification": {"identity": SPEC,
                "contract": "image-build-toolchain-specification-v1",
                "profile": "self-hosted-c-cxx-toolchain-v1"},
            "predecessor": predecessor, "controller_jobs": [
                {"job_id": "controller-kept", "invocation_id": "invocation-kept"}
            ], "pipelines": [{"pipeline_id": "pipeline-kept"}],
            "outputs": outputs,
        }},
    }


def fixture(tmp_path, monkeypatch):
    bound = frozen_binding()

    @contextmanager
    def lock(root, request_id):
        assert request_id == GATEWAY
        yield tmp_path

    monkeypatch.setattr(supervisor, "request_lock", lock)
    monkeypatch.setattr(supervisor, "binding", lambda root, req: bound)
    monkeypatch.setattr(supervisor, "verify_current_target", lambda root, b: {})
    monkeypatch.setattr(supervisor, "producer_runtime_preflight",
                        lambda host, stage: None)

    def stage_bound(b, e):
        return {"remote_request": e["request"],
                "test_phase": e["phase"],
                "test_predecessor": (
                    next((p["predecessor"] for p in
                          supervisor.status(tmp_path, GATEWAY)["phases"]
                          if p["name"] == e["phase"]), None)),
                "test_id": e["operation_id"]}

    monkeypatch.setattr(supervisor, "stage_binding", stage_bound)
    monkeypatch.setattr(supervisor, "remote_script", lambda stage: json.dumps(stage))
    monkeypatch.setattr(
        supervisor, "parse_receipt",
        lambda raw, stage: {
            "result": json.loads(raw),
            "result_sha256": "0" * 64,
        },
    )
    class Host:
        commands = {}
        sends = 0
        timeout = False

        def __init__(self, configuration):
            pass

        def submit_command(self, script, seconds):
            self.__class__.sends += 1
            if self.__class__.timeout:
                raise ConnectionError("caller connection lost during SendCommand")
            command = "ssm-" + str(self.__class__.sends)
            stage = json.loads(script)
            self.__class__.commands[command] = fake_result(stage)
            return command

        def inspect_command(self, command_id):
            return {"Status": "Success",
                    "StandardOutputContent": json.dumps(
                        self.__class__.commands[command_id])}
    return Host


def walk(root, host, until, maximum=180):
    last = None
    for _ in range(maximum):
        last = supervisor.advance(root, GATEWAY, host_factory=host)
        if until(last):
            return last
    raise AssertionError("typed toolchain supervisor did not make progress")


def test_full_phase_lineage_and_final_receipt(tmp_path, monkeypatch):
    host = fixture(tmp_path, monkeypatch)
    result = walk(tmp_path, host, lambda value: value["status"] == "completed")
    assert [p["name"] for p in result["phases"]] == list(journal.PHASES)
    assert result["artifact_receipt"]["generation"] == GEN
    assert result["artifact_receipt"]["verification"] == VERIFY
    assert all(p["evidence"]["controller_jobs"][0]["job_id"] ==
               "controller-kept" for p in result["phases"])
    assert result["observations"] > len(journal.PHASES)
    assert len(list((tmp_path / supervisor.OBSERVATION_DIR).glob("*.json"))) == (
        result["observations"])
    sends = host.sends
    assert supervisor.advance(tmp_path, GATEWAY, host_factory=host)["status"] == "completed"
    assert host.sends == sends


def test_send_command_interruption_cannot_allocate_duplicate(tmp_path, monkeypatch):
    host = fixture(tmp_path, monkeypatch)
    walk(tmp_path, host, lambda j: j["current"] is not None
         and j["current"]["state"] == "prepared")
    host.timeout = True
    with pytest.raises(ConnectionError):
        supervisor.advance(tmp_path, GATEWAY, host_factory=host)
    assert host.sends == 1
    assert supervisor.status(tmp_path, GATEWAY)["status"] == "uncertain"
    for _ in range(3):
        assert supervisor.advance(tmp_path, GATEWAY, host_factory=host)["status"] == "uncertain"
    assert host.sends == 1


def test_submitting_journal_recovery_never_reissues(tmp_path, monkeypatch):
    host = fixture(tmp_path, monkeypatch)
    value = walk(tmp_path, host, lambda j: j["current"] is not None)
    value["current"]["state"] = "submitting"
    journal.persist(tmp_path, value)
    result = supervisor.advance(tmp_path, GATEWAY, host_factory=host)
    assert result["status"] == "uncertain"
    assert host.sends == 0


def test_explicit_resume_is_required(tmp_path, monkeypatch):
    host = fixture(tmp_path, monkeypatch)
    state = walk(tmp_path, host, lambda j: j["phases"]
                 and j["phases"][-1]["status"] == "pending"
                 and j["current"] is None)
    assert state["phases"][-1]["name"] == "cross-bootstrap"
    with pytest.raises(RuntimeError):
        supervisor.authorize_resume(tmp_path, GATEWAY, "final-compiler")
    supervisor.authorize_resume(tmp_path, GATEWAY, "cross-bootstrap")
    event = supervisor.advance(tmp_path, GATEWAY, host_factory=host)["current"]
    assert event["request"]["operation"] == "toolchain.resume"
    assert event["request"]["arguments"] == {
        "operation_id": state["phases"][-1]["operation_id"]}
