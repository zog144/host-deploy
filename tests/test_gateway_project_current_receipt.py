"""Project-current normalized receipt, old CommandId readback, no replay."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from test_gateway_project_current import project, selected, intent, target, git
from test_gateway_simple_forward import approved, admit
from zog.host_deploy.gateway import (
    project_current, image_build_execution as execution, simple_forward,
)
from zog.host_deploy.gateway.ledger import (
    prepare_dispatch, load_dispatch, load_request,
    mark_dispatch_submitting, mark_dispatch_submitted,
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


# Copied from image-build remote_operations.py::_base_result at exact
# accepted revision 50698663f3ffc7058c85748a455df1531cfd0355 (body unchanged).
# Keep wrapper-only reconciliation_required OUT of this producer fixture.
_PRODUCER_BASE = "RESULT_SCHEMA = \"image-build-remote-result-v1\"\nMAX_MISSING = 24\ndef _base_result(\n    request,\n    *,\n    status,\n    terminal_outcome,\n    uncertainty=False,\n    failure=None,\n    missing_evidence=None,\n    allowed_next_operations=None,\n    pipeline_id=None,\n):\n    return {\n        \"schema\": RESULT_SCHEMA,\n        \"operation_id\": request[\"operation_id\"],\n        \"operation_type\": request[\"operation\"],\n        \"source_repository\": request[\"source\"][\"repository\"],\n        \"source_revision\": request[\"source\"][\"revision\"],\n        \"recipe_identity\": None,\n        \"pipeline_id\": pipeline_id,\n        \"attempt_ids\": [],\n        \"selected_generation\": None,\n        \"package\": None,\n        \"stage\": None,\n        \"phase\": None,\n        \"status\": status,\n        \"terminal_outcome\": terminal_outcome,\n        \"failure\": failure,\n        \"controller_jobs\": [],\n        \"log_locators\": [],\n        \"artifacts\": {},\n        \"provenance\": {},\n        \"uncertainty\": bool(uncertainty),\n        \"missing_evidence\": list(missing_evidence or [])[:MAX_MISSING],\n        \"allowed_next_operations\": list(allowed_next_operations or []),\n        \"predecessor\": request.get(\"predecessor\"),\n    }\n"


# Exact method bodies copied from accepted image-build 50698663; this
# disposable producer reads real local execution/observation files through
# the actual evidence collector and pipeline-summary result constructor.
# Only storage setup and unrelated command-view/owner lookups are fixture stubs.
_PRODUCER_EVIDENCE = "    def _evidence(self, record):\n        commands = []\n        failures = []\n        missing = []\n        observations = {}\n        for attempt in self._attempt_paths(record):\n            if not attempt.exists():\n                missing.append(\n                    {\n                        \"kind\": \"attempt-directory\",\n                        \"locator\": str(attempt.relative_to(self.observed_state)),\n                    }\n                )\n                continue\n            try:\n                page = read_build_commands(attempt, limit=MAX_COMMANDS)\n                commands.extend(page[\"commands\"])\n            except Exception:\n                missing.append(\n                    {\n                        \"kind\": \"command-view\",\n                        \"locator\": str(attempt.relative_to(self.observed_state)),\n                    }\n                )\n            for path in sorted(attempt.rglob(\"*.execution.json\")):\n                try:\n                    value = json.loads(path.read_text())\n                except (OSError, ValueError, TypeError):\n                    continue\n                if (\n                    value.get(\"cleanup_complete\") is True\n                    and type(value.get(\"exit_code\")) is int\n                    and value[\"exit_code\"] != 0\n                ):\n                    failures.append(\n                        {\n                            \"kind\": \"command-exit\",\n                            \"exit_code\": value[\"exit_code\"],\n                            \"journal_reference\": value.get(\"journal_reference\"),\n                            \"process_cleanup_complete\": value.get(\n                                \"process_cleanup_complete\"\n                            ),\n                            \"locator\": str(path.relative_to(self.observed_state)),\n                        }\n                    )\n            for path in sorted(attempt.rglob(\"*.observation.json\")):\n                try:\n                    value = json.loads(path.read_text())\n                except (OSError, ValueError, TypeError):\n                    continue\n                if value.get(\"job_id\"):\n                    observations[value[\"job_id\"]] = {\n                        key: value.get(key)\n                        for key in (\n                            \"state\",\n                            \"outcome\",\n                            \"exit_code\",\n                            \"signal\",\n                            \"journal_reference\",\n                            \"process_cleanup_complete\",\n                        )\n                        if key in value\n                    }\n                if value.get(\"outcome\") in {\n                    \"nonzero-exit\",\n                    \"signal\",\n                    \"timeout\",\n                    \"fault\",\n                    \"cancelled\",\n                    \"unknown\",\n                }:\n                    failures.append(\n                        {\n                            \"kind\": \"controller-outcome\",\n                            \"outcome\": value.get(\"outcome\"),\n                            \"job_id\": value.get(\"job_id\"),\n                            \"exit_code\": value.get(\"exit_code\"),\n                            \"signal\": value.get(\"signal\"),\n                            \"journal_reference\": value.get(\"journal_reference\"),\n                            \"process_cleanup_complete\": value.get(\n                                \"process_cleanup_complete\"\n                            ),\n                            \"locator\": str(path.relative_to(self.observed_state)),\n                        }\n                    )\n        commands = commands[:MAX_COMMANDS]\n        missing = missing[:MAX_MISSING]\n        jobs = []\n        for command in commands:\n            if command.get(\"job_id\"):\n                job = {\n                    \"job_id\": command[\"job_id\"],\n                    \"request_id\": command.get(\"request_id\"),\n                    \"attempt_id\": command.get(\"attempt_id\"),\n                    \"package\": command.get(\"package\"),\n                    \"stage\": command.get(\"stage_id\"),\n                    \"phase\": command.get(\"phase\"),\n                    \"command_index\": command.get(\"command_index\"),\n                    \"command_key\": command.get(\"command_key\"),\n                    \"command\": command.get(\"command\"),\n                }\n                job.update(observations.get(command[\"job_id\"], {}))\n                excerpt = self._log_excerpt(command[\"job_id\"])\n                if excerpt is not None:\n                    job[\"log_excerpt\"] = excerpt\n                jobs.append(job)\n        return commands, jobs, failures, missing\n"
_PRODUCER_PIPELINE_SUMMARY = "    def _pipeline_summary(self, request, pipeline_id, *, raised=None):\n        try:\n            record, pipeline_record_digest = self._inspect_pipeline_record(\n                pipeline_id\n            )\n        except Exception as error:\n            result = self._base_result(\n                request,\n                status=\"pending\",\n                terminal_outcome=None,\n                uncertainty=True,\n                failure={\"type\": type(error).__name__, \"reason\": str(error)},\n                missing_evidence=[{\"kind\": \"pipeline-record\", \"locator\": pipeline_id}],\n                allowed_next_operations=[\"pipeline.inspect\"],\n                pipeline_id=pipeline_id,\n            )\n            if self.external_observed_state:\n                result[\"artifacts\"][\"observation_source\"] = {\n                    \"kind\": \"external-state\"\n                }\n            return result\n        commands, jobs, failures, missing = self._evidence(record)\n        status = record.get(\"status\")\n        uncertainty = False\n        outcome = None\n        allowed = []\n        failure = None\n        if status == \"complete\":\n            remote_status = \"completed\"\n            outcome = \"success\"\n        elif status == \"released\":\n            remote_status = \"released\"\n            outcome = \"released\"\n            allowed = [\"pipeline.inspect\"]\n        else:\n            unknown = any(item.get(\"outcome\") == \"unknown\" for item in failures)\n            terminal = [\n                item\n                for item in failures\n                if item.get(\"kind\") == \"command-exit\"\n                or (\n                    item.get(\"outcome\") not in (None, \"unknown\")\n                    and item.get(\"process_cleanup_complete\") is not False\n                )\n            ]\n            if terminal:\n                remote_status = \"failed\"\n                outcome = terminal[-1].get(\"outcome\") or \"nonzero-exit\"\n                failure = terminal[-1]\n                allowed = [\"pipeline.retry\", \"pipeline.inspect\"]\n            else:\n                remote_status = \"pending\"\n                uncertainty = unknown or \"unknown\" in str(record.get(\"error\", \"\")).lower()\n                failure = (\n                    {\"type\": type(raised).__name__, \"reason\": str(raised)}\n                    if raised is not None\n                    else (\n                        {\"type\": \"pending\", \"reason\": record.get(\"error\")}\n                        if record.get(\"error\")\n                        else None\n                    )\n                )\n                allowed = [\"pipeline.resume\", \"pipeline.inspect\", \"pipeline.cancel\"]\n        if status == \"complete\":\n            allowed = [\"pipeline.inspect\"]\n        result = self._base_result(\n            request,\n            status=remote_status,\n            terminal_outcome=outcome,\n            uncertainty=uncertainty,\n            failure=failure,\n            missing_evidence=missing,\n            allowed_next_operations=allowed,\n            pipeline_id=pipeline_id,\n        )\n        if self.external_observed_state:\n            result[\"allowed_next_operations\"] = [\"pipeline.inspect\"]\n            result[\"artifacts\"][\"observation_source\"] = {\n                \"kind\": \"external-state\",\n                \"pipeline_record_sha256\": pipeline_record_digest,\n            }\n        owner = self._pipeline_owner(record)\n        if owner and owner.get(\"recipe_snapshot\"):\n            result[\"recipe_identity\"] = owner[\"recipe_snapshot\"]\n            result[\"artifacts\"][\"recipe_snapshot\"] = owner[\n                \"recipe_snapshot\"\n            ]\n        result[\"attempt_ids\"] = sorted(record.get(\"attempts\", {}).values())\n        result[\"controller_jobs\"] = jobs[:MAX_COMMANDS]\n        result[\"log_locators\"] = [\n            {\n                \"job_id\": item.get(\"job_id\"),\n                \"journal_reference\": item.get(\"journal_reference\"),\n                \"locator\": item.get(\"locator\"),\n            }\n            for item in failures\n            if item.get(\"journal_reference\") or item.get(\"locator\")\n        ][:MAX_COMMANDS]\n        result[\"package\"] = jobs[-1].get(\"package\") if jobs else None\n        result[\"stage\"] = jobs[-1].get(\"stage\") if jobs else None\n        result[\"phase\"] = jobs[-1].get(\"phase\") if jobs else None\n        if record.get(\"generation\"):\n            result[\"selected_generation\"] = record[\"generation\"]\n            try:\n                selection = self._observed_generation(record[\"generation\"])\n                result[\"artifacts\"].update({\n                    \"generation_manifest\": str(\n                        selection.root.parent.relative_to(self.observed_state)\n                        / \"manifest.json\"\n                    ),\n                    \"generation_inventory_digest\": \"sha256:\"\n                    + identity(selection.manifest[\"outputs\"]),\n                })\n                result[\"provenance\"] = {\n                    key: selection.manifest[key]\n                    for key in (\"build_record\", \"verification_execution\")\n                    if key in selection.manifest\n                }\n                if record.get(\"observation_snapshot\"):\n                    result[\"provenance\"][\"observation_snapshot\"] = record[\n                        \"observation_snapshot\"\n                    ]\n                    result[\"provenance\"][\"build_trace\"] = {\n                        \"snapshot\": record[\"observation_snapshot\"]\n                    }\n            except Exception:\n                result[\"missing_evidence\"].append(\n                    {\"kind\": \"generation\", \"locator\": record[\"generation\"]}\n                )\n        return result\n"
_PRODUCER_ATTEMPT_PATHS = "    def _attempt_paths(self, record):\n        root = self.observed_state / \"image-build\" / \"attempts\"\n        return [root / name for name in record.get(\"attempts\", {}).values()]\n"


def _terminal_failure_module(kind):
    setup = r'''
import json, sys
from pathlib import Path
MAX_COMMANDS = 24
def read_build_commands(attempt, limit):
    return {"commands": []}

'''
    class_source = r'''
class Producer:
    _base_result = staticmethod(_base_result)
    external_observed_state = False
    def __init__(self, state):
        self.observed_state = state
    def _inspect_pipeline_record(self, pipeline_id):
        path = self.observed_state / "image-build/pipelines" / pipeline_id / "pipeline.json"
        return json.loads(path.read_text()), "fixture-digest"
    def _pipeline_owner(self, record):
        return record["owner"]
'''
    main_source = r'''
def main():
    path = Path(sys.argv[-1])
    req = json.loads(path.read_text())
    state = path.parents[2] / "state"
    pipeline = "a" * 32
    attempt = "image-original-fonts-final"
    pipeline_dir = state / "image-build/pipelines" / pipeline
    pipeline_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "pipeline_id": pipeline, "status": "pending",
        "attempts": {"fontconfig-final": attempt},
        "owner": {"operation_id": req["operation_id"],
                  "source_repository": req["source"]["repository"],
                  "source_revision": req["source"]["revision"]},
    }
    (pipeline_dir / "pipeline.json").write_text(json.dumps(record))
    attempt_dir = state / "image-build/attempts" / attempt
    attempt_dir.mkdir(parents=True, exist_ok=True)
    if KIND == "command-exit":
        evidence = {"cleanup_complete": True, "exit_code": 7,
                    "journal_reference": "journal:original-command",
                    "process_cleanup_complete": True}
        name = "failure.execution.json"
    else:
        evidence = {"state": "completed", "outcome": "nonzero-exit",
                    "job_id": "original-controller-job", "exit_code": 9,
                    "signal": None, "journal_reference": "journal:original-controller",
                    "process_cleanup_complete": True}
        if KIND == "controller-unknown":
            evidence.update(state="unknown", outcome="unknown",
                            exit_code=None, process_cleanup_complete=False)
        if KIND == "controller-cleanup-pending":
            evidence["process_cleanup_complete"] = False
        name = "failure.observation.json"
    (attempt_dir / name).write_text(json.dumps(evidence))
    print(json.dumps(Producer(state)._pipeline_summary(req, pipeline)))
'''
    return (setup + _PRODUCER_BASE + "\nKIND = " + repr(kind) + "\n"
            + class_source + _PRODUCER_ATTEMPT_PATHS + _PRODUCER_EVIDENCE
            + _PRODUCER_PIPELINE_SUMMARY + main_source)


def receipt_fixture(tmp_path, *, request_id="a" * 32,
                    actual_terminal=False, producer_case=None):
    root, source, controller = project(tmp_path)
    (source / "project/package/pins.txt").write_text("sha256:" + "a" * 64)
    if actual_terminal or producer_case is not None:
        # A real disposable Project producer writes its original immutable
        # pipeline and completed attempt, rather than tests patching stdout
        # from pending into a pretend successful build.
        module = source / "src/zog/image_build/remote_operations.py"
        module.write_text(
            "import json,sys\nfrom pathlib import Path\n" + _PRODUCER_BASE +
            "def main():\n"
            " req_path=Path(sys.argv[-1])\n"
            " req=json.loads(req_path.read_text())\n"
            " root=req_path.parents[2]\n"
            " op=req['operation_id']\n"
            " pipeline='a'*32\n"
            " attempt='image-original-fonts-final'\n"
            " generation='b'*64\n"
            " state=root/'state/image-build'\n"
            " op_dir=state/'remote-operations'/op\n"
            " op_dir.mkdir(parents=True,exist_ok=True)\n"
            " (op_dir/'request.json').write_text(json.dumps(req))\n"
            " (op_dir/'binding.json').write_text(json.dumps({'pipeline_id':pipeline}))\n"
            " pipe_dir=state/'pipelines'/pipeline\n"
            " pipe_dir.mkdir(parents=True,exist_ok=True)\n"
            " record={'schema':1,'pipeline_id':pipeline,'status':'complete',"
            "'operation':'image','arguments':req['arguments'],"
            "'attempts':{'fontconfig-final':attempt},'generation':generation,"
            "'owner':{'contract':req['schema'],'operation_id':op,"
            "'source_repository':req['source']['repository'],"
            "'source_revision':req['source']['revision']}}\n"
            " (pipe_dir/'pipeline.json').write_text(json.dumps(record))\n"
            " attempt_dir=state/'attempts'/attempt\n"
            " attempt_dir.mkdir(parents=True,exist_ok=True)\n"
            " (attempt_dir/'status.json').write_text(json.dumps("
            "{'status':'complete','generation':generation}))\n"
            + (" result=_base_result(req,status='failed',"
               "terminal_outcome='request-error',failure={'type':'ImageBuildError',"
               "'reason':'validated request rejected'})\n"
               if producer_case == "request-error" else
               " result=_base_result(req,status='pending',terminal_outcome=None,"
               "pipeline_id=pipeline,uncertainty=True,"
               "missing_evidence=[{'kind':'pipeline-record','locator':pipeline}],"
               "allowed_next_operations=['pipeline.inspect'])\n"
               if producer_case == "unknown" else
               " result=_base_result(req,status='completed',terminal_outcome='success',"
               "pipeline_id=pipeline,missing_evidence=[{'kind':'generation',"
               "'locator':generation}])\n"
               if producer_case == "missing-evidence" else
               " result=_base_result(req,status='pending',terminal_outcome=None,"
               "pipeline_id=pipeline,allowed_next_operations=['pipeline.inspect'])\n"
               if producer_case == "pending" else
               " result=_base_result(req,status='completed',terminal_outcome='success',"
               "pipeline_id=pipeline,allowed_next_operations=['pipeline.inspect'])\n")
            + " result['attempt_ids']=[attempt] if result['pipeline_id'] else []\n"
            " print(json.dumps(result))\n"
        )
        if producer_case == "request-error":
            # The real producer's exception path returns _base_result
            # before any pipeline exists; do not seed a fake pipeline.
            module.write_text(
                "import json,sys\nfrom pathlib import Path\n" + _PRODUCER_BASE +
                "def main():\n"
                " req=json.loads(Path(sys.argv[-1]).read_text())\n"
                " print(json.dumps(_base_result(req,status='failed',"
                "terminal_outcome='request-error',failure={'type':'ImageBuildError',"
                "'reason':'validated request rejected'},allowed_next_operations=[])))\n")
    if producer_case in ("command-exit", "controller-outcome",
                         "controller-unknown", "controller-cleanup-pending"):
        module.write_text(_terminal_failure_module(producer_case))
    git(source, "add", ".")
    git(source, "commit", "-qm", "sha256 recipe snapshot for parser")
    spec, record = selected(root, controller, historic=False)
    binding = project_current.binding(intent(request_id), record, spec, target())
    command = project_current.remote_script(binding)
    assert len(command.encode("utf-8")) <= 32768
    result = subprocess.run(command, shell=True, capture_output=True,
                            text=True, timeout=25)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout.strip().splitlines()[-1])
    return root, binding, receipt, result.stdout


def _gateway_with_frozen_original(root, request, binding):
    admit(root, request)
    prepare_dispatch(root, request["request_id"], binding)
    mark_dispatch_submitting(root, request["request_id"])
    mark_dispatch_submitted(root, request["request_id"], "original-fonts-ssm-command")
    return load_dispatch(root, request["request_id"])


def _observe_original(root, request, binding, receipt, path, monkeypatch):
    from zog.host_deploy.gateway import image_build_execution
    monkeypatch.setattr(simple_forward, "verify_current_target",
                        lambda *_: target())
    monkeypatch.setattr(image_build_execution, "verify_current_target",
                        lambda *_: target())
    seen = []
    class Host:
        def __init__(self, configuration):
            assert configuration == target()
        def inspect_command(self, command_id):
            seen.append(command_id)
            return {
                "CommandId": "original-fonts-ssm-command",
                "InstanceId": target()["instance_id"],
                "Status": "Success",
                "StandardOutputContent": json.dumps(receipt),
            }
        def submit_command(self, *args, **kwargs):
            pytest.fail("original Fonts request was replayed")
    if path == "forward":
        actual = simple_forward.advance(root, request["request_id"], host_factory=Host)
        phase = actual["phase"]
    else:
        state, obs, retained = image_build_execution.observe_submitted(
            root, request["request_id"], host_factory=Host)
        phase = state["states"]["completion"]
    assert seen == ["original-fonts-ssm-command"]
    return phase


def _rehash(receipt):
    receipt = copy.deepcopy(receipt)
    raw = _canonical(receipt["result"])
    receipt["result_sha256"] = hashlib.sha256(raw).hexdigest()
    receipt["result_bytes"] = len(raw)
    return receipt


def _legacy(receipt):
    old = copy.deepcopy(receipt)
    old.pop("result_representation")
    old["result"] = {key: receipt["result"][key] for key in (
        "status", "pipeline_id", "source_revision", "recipe_identity",
        "selected_generation", "terminal_outcome", "failure",
        "allowed_next_operations", "uncertainty", "attempt_ids",
        "reconciliation_required",
    )}
    # The REAL old wrapper hashed produced, not the reduced summary; those
    # producer bytes were never transmitted. Their digest is not computable
    # from the old receipt. Do not fake a matching digest.
    old["result_sha256"] = "f" * 64
    old["result_bytes"] = 8192
    return old


def test_current_normalized_receipt_verifies_exact_wire_result_and_source(tmp_path):
    root, binding, receipt, output = receipt_fixture(tmp_path)
    assert receipt["result_representation"] == "normalized-summary-v1"
    assert receipt["result"]["source_repository"] == "zog144/image-build"
    assert receipt["result"]["source_revision"] == git(root / "source",
                                                        "rev-parse", "HEAD")
    assert receipt["result"]["schema"] == "image-build-remote-result-v1"
    assert receipt["result"]["operation_id"] == binding["request_id"]
    assert receipt["result"]["operation_type"] == "pipeline.submit"
    assert receipt["result"]["missing_evidence_count"] == 0
    assert receipt["result"]["allowed_next_operations"] == []
    assert receipt["result"]["attempt_ids"] == []
    assert receipt["result"]["controller_jobs"] == []
    assert receipt["result"]["uncertainty"] is False
    assert receipt["result"]["failure"] is None
    raw = _canonical(receipt["result"])
    assert receipt["result_bytes"] == len(raw)
    assert receipt["result_sha256"] == hashlib.sha256(raw).hexdigest()
    source = receipt["result"]["source_evidence"]
    requested = copy.deepcopy(binding["remote_request"])
    requested["source"]["revision"] = receipt["result"]["source_revision"]
    assert source == {
        "schema": "host-deploy-project-current-source-v1",
        "repository": "zog144/image-build",
        "revision": receipt["result"]["source_revision"],
        "request_sha256": hashlib.sha256(_canonical(requested) + b"\n").hexdigest(),
    }
    assert execution.parse_receipt(output, binding) == receipt
    assert execution.completion_for_receipt(receipt) == "running"


@pytest.mark.parametrize("alter", [
    "hash", "byte-count", "repo", "wrong-revision", "source-request",
    "source-schema", "operation", "request-id", "frozen-template", "missing-evidence",
    "missing-identity", "uncertainty-type",
])
def test_normalized_receipt_rejects_rehashed_tampering_and_wrong_binding(
        tmp_path, alter):
    root, binding, receipt, _ = receipt_fixture(tmp_path)
    modified = copy.deepcopy(receipt)
    if alter == "hash":
        modified["result_sha256"] = "0" * 64
    elif alter == "byte-count":
        modified["result_bytes"] += 1
    elif alter == "repo":
        modified["result"]["source_repository"] = "unreviewed/repo"
        modified = _rehash(modified)
    elif alter == "wrong-revision":
        modified["result"]["source_revision"] = "f" * 40
        modified = _rehash(modified)
    elif alter == "source-request":
        modified["result"]["source_evidence"]["request_sha256"] = "f" * 64
        modified = _rehash(modified)
    elif alter == "source-schema":
        modified["result"]["source_evidence"]["schema"] = "not-reviewed"
        modified = _rehash(modified)
    elif alter == "operation":
        modified["result"]["operation_id"] = "b" * 32
        modified = _rehash(modified)
    elif alter == "request-id":
        modified["request_id"] = "b" * 32
    elif alter == "frozen-template":
        modified["remote_request_sha256"] = "0" * 64
    elif alter == "missing-evidence":
        del modified["result"]["missing_evidence_count"]
        modified = _rehash(modified)
    elif alter == "missing-identity":
        del modified["result"]["source_repository"]
        modified = _rehash(modified)
    else:
        modified["result"]["uncertainty"] = "false"
        modified = _rehash(modified)
    with pytest.raises(RuntimeError):
        execution.parse_receipt(json.dumps(modified), binding)


def test_pinned_source_contract_is_unchanged_for_historical_binding(monkeypatch, tmp_path):
    root, selected_binding, receipt, output = receipt_fixture(tmp_path)
    from zog.host_deploy.gateway import image_build_execution as legacy
    pinned = dict(selected_binding, schema=3, source={
        "repository": "zog144/image-build",
        "revision": receipt["result"]["source_revision"],
    })
    # Synthetic shape isolates the existing legacy pinned-source branch,
    # whose complete immutable binding format is separately source-tested.
    monkeypatch.setattr(legacy, "_binding", lambda value: value["binding"])
    old = copy.deepcopy(receipt)
    old.pop("result_representation")
    assert legacy.parse_receipt(json.dumps(old), pinned) == old
    pinned["source"] = {**pinned["source"], "revision": "f" * 40}
    with pytest.raises(RuntimeError, match="result summary differs"):
        legacy.parse_receipt(json.dumps(old), pinned)


def test_already_sent_legacy_receipt_is_observed_without_false_digest_or_replay(
        tmp_path, monkeypatch):
    request = approved()
    compiler, binding, receipt, output = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    old = _legacy(receipt)
    assert execution.parse_receipt(json.dumps(old), binding) == old
    gateway = tmp_path / "gateway"
    admit(gateway, request)
    prepare_dispatch(gateway, request["request_id"], binding)
    mark_dispatch_submitting(gateway, request["request_id"])
    mark_dispatch_submitted(gateway, request["request_id"],
                            "retained-original-command-63")
    frozen = load_dispatch(gateway, request["request_id"])
    calls = []
    monkeypatch.setattr(execution, "verify_current_target",
                        lambda *_: target())

    class Host:
        def __init__(self, configuration):
            assert configuration == target()
        def inspect_command(self, command_id):
            calls.append(command_id)
            return {
                "CommandId": "retained-original-command-63",
                "InstanceId": target()["instance_id"],
                "Status": "Success",
                "StandardOutputContent": json.dumps(old),
            }
        def submit_command(self, *args, **kwargs):
            pytest.fail("legacy receipt observation attempted command replay")

    state, observation, retained = execution.observe_submitted(
        gateway, request["request_id"], host_factory=Host)
    assert state["states"]["completion"] == "recovery_blocked"
    assert observation["observation"]["raw_result_digest_verified"] is False
    assert observation["observation"]["declared_result_sha256"] == "f" * 64
    assert observation["observation"]["source_revision"] == (
        receipt["result"]["source_revision"])
    assert observation["observation"]["selected_project_observation_required"]
    assert retained is None
    assert not (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert calls == ["retained-original-command-63"]


@pytest.mark.parametrize("mutation", ["wrong-command", "wrong-instance",
                                      "wrong-request", "wrong-repository",
                                      "bad-revision", "oversized-count"])
def test_legacy_readback_never_trusts_foreign_identity_or_creates_terminal(
        tmp_path, monkeypatch, mutation):
    request = approved()
    _, binding, receipt, output = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    old = _legacy(receipt)
    if mutation == "wrong-request":
        old["request_id"] = "e" * 32
    elif mutation == "wrong-repository":
        altered = dict(binding, remote_request={
            **binding["remote_request"],
            "source": {"repository": "foreign/source"},
        })
        monkeypatch.setattr(execution, "_binding",
                            lambda _: altered)
    elif mutation == "bad-revision":
        old["result"]["source_revision"] = "non-git"
    elif mutation == "oversized-count":
        old["result_bytes"] = 999999
    gateway = tmp_path / "gateway"
    admit(gateway, request)
    prepare_dispatch(gateway, request["request_id"], binding)
    mark_dispatch_submitting(gateway, request["request_id"])
    mark_dispatch_submitted(gateway, request["request_id"], "original-command")
    frozen = load_dispatch(gateway, request["request_id"])
    monkeypatch.setattr(execution, "verify_current_target",
                        lambda *_: target())
    class Host:
        def __init__(self, cfg):
            pass
        def inspect_command(self, command_id):
            return {
                "CommandId": ("foreign-command" if mutation == "wrong-command"
                              else "original-command"),
                "InstanceId": ("i-fffffffffffffffff" if
                               mutation == "wrong-instance" else target()["instance_id"]),
                "Status": "Success",
                "StandardOutputContent": json.dumps(old),
            }
        def submit_command(self, *args, **kwargs):
            pytest.fail("replay")
    with pytest.raises(RuntimeError):
        execution.observe_submitted(
            gateway, request["request_id"], host_factory=Host)
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert not (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()



@pytest.mark.parametrize("observer", ["forward", "direct"])
def test_rehashed_contradictory_completed_receipt_cannot_be_terminal(
        tmp_path, monkeypatch, observer):
    request = approved()
    compiler, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    receipt["result"].update(
        status="completed", pipeline_id=None, terminal_outcome=None,
        uncertainty=False, reconciliation_required=True)
    receipt = _rehash(receipt)
    assert execution.parse_receipt(json.dumps(receipt), binding) == receipt
    assert execution.project_current_completion(receipt) == "recovery_blocked"
    gateway = tmp_path / ("gateway-" + observer)
    original = _gateway_with_frozen_original(gateway, request, binding)
    phase = _observe_original(gateway, request, binding, receipt,
                              observer, monkeypatch)
    assert phase == "recovery_blocked"
    assert load_dispatch(gateway, request["request_id"]) == original
    path = gateway / "requests" / request["request_id"]
    claim = json.loads((path / "dispatch-observation.json").read_text())["observation"]
    assert claim["schema"] == "host-deploy-project-current-normalized-receipt-v1"
    assert claim["raw_result_digest_verified"] is True
    assert claim["pipeline_id"] is None
    assert claim["source_revision"] == receipt["result"]["source_revision"]
    assert not (path / "remote-result.json").exists()


@pytest.mark.parametrize("observer", ["forward", "direct"])
def test_valid_terminal_pipeline_classification_agrees_across_observers(
        tmp_path, monkeypatch, observer):
    request = approved()
    compiler, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"], actual_terminal=True)
    assert (compiler / "state/image-build/pipelines" /
            ("a" * 32) / "pipeline.json").is_file()
    assert (compiler / "state/image-build/attempts" /
            "image-original-fonts-final/status.json").is_file()
    assert receipt["result"]["terminal_outcome"] == "success"
    assert receipt["result"]["attempt_ids"] == ["image-original-fonts-final"]
    assert execution.parse_receipt(json.dumps(receipt), binding) == receipt
    assert execution.project_current_completion(receipt) == "completed"
    gateway = tmp_path / ("gateway-" + observer)
    original = _gateway_with_frozen_original(gateway, request, binding)
    phase = _observe_original(gateway, request, binding, receipt,
                              observer, monkeypatch)
    assert phase == "completed"
    assert load_dispatch(gateway, request["request_id"]) == original
    saved = json.loads((gateway / "requests" / request["request_id"] /
                       "remote-result.json").read_text())
    assert saved["completion"] == "completed"
    assert saved["result"]["result_sha256"] == receipt["result_sha256"]


def _project_readback_report(binding, *, revision=None, pipeline=None):
    from zog.host_deploy.gateway.project_current_observation import (
        OBSERVATION_SCHEMA,
    )
    revision = revision or git(Path(binding["project_root"]) / "source",
                               "rev-parse", "HEAD")
    pipeline = pipeline or "a" * 32
    attempt = "image-original-fonts-final"
    evidence = {
        "request_sha256": "a" * 64,
        "pipeline_sha256": "b" * 64,
        "attempt_statuses": {attempt: "c" * 64},
    }
    evidence["evidence_sha256"] = hashlib.sha256(
        _canonical(evidence)).hexdigest()
    return {
        "schema": OBSERVATION_SCHEMA,
        "project_root": binding["project_root"],
        "project_owner_uid": os.geteuid(),
        "request_id": binding["request_id"],
        "operation_id": binding["request_id"],
        "source_revision": revision,
        "pipeline_id": pipeline,
        "pipeline_status": "complete",
        "attempt_ids": [attempt],
        "evidence": evidence,
        "evidence_source": "local-selected-project",
        "producer_status": "completed",
        "terminal_outcome": "success",
        "terminal_confirmed": True,
        "uncertainty": False,
        "mutation": False,
        "execution_authorized": False,
    }


@pytest.mark.parametrize("format", ["legacy", "normalized"])
@pytest.mark.parametrize("difference", ["same", "foreign-source",
                                          "foreign-pipeline", "changed-target",
                                          "changed-request-digest"])
def test_protected_reconcile_requires_original_ssm_receipt_pipeline_and_source(
        tmp_path, monkeypatch, format, difference):
    request = approved()
    compiler, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    if format == "legacy":
        receipt = _legacy(receipt)
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    # Both direct and queue observers must retain a typed original claim,
    # which cannot be erased by read-only reconciliation.
    _observe_original(gateway, request, binding, receipt, "direct", monkeypatch)
    saved_path = gateway / "requests" / request["request_id"] / "dispatch-observation.json"
    recorded = saved_path.read_bytes()
    claim = json.loads(recorded)["observation"]
    assert claim["pipeline_id"] == receipt["result"]["pipeline_id"]
    assert claim["source_revision"] == receipt["result"]["source_revision"]
    assert claim["raw_result_digest_verified"] == (format == "normalized")
    if difference == "changed-target":
        claim["compiler_instance_id"] = "i-fffffffffffffffff"
    if difference == "changed-request-digest":
        claim["remote_request_sha256"] = "f" * 64
    if difference in ("changed-target", "changed-request-digest"):
        retained = json.loads(recorded)
        retained["observation"] = claim
        saved_path.write_text(json.dumps(retained))
        recorded = saved_path.read_bytes()

    report = _project_readback_report(
        binding,
        revision=("f" * 40 if difference == "foreign-source" else None),
        pipeline=("e" * 32 if difference == "foreign-pipeline" else None))
    from zog.host_deploy.gateway import fonts_inspection_owner
    from zog.host_deploy.gateway import project_current_observation as observe
    checked = []
    monkeypatch.setattr(simple_forward, "FIRST_FONTS_COMPILER_PROJECT_UID",
                        os.geteuid())
    def selected_script(root, python, request_id, *, pipeline_id=None):
        checked.append((root, request_id, pipeline_id))
        return "read-only-fixed-original-project-inspection"
    monkeypatch.setattr(observe, "read_only_observation_script", selected_script)
    sent = []
    def authorized_inspection(*args, **kwargs):
        sent.append(kwargs)
        return (1, "protected-read-only-inspection")
    monkeypatch.setattr(fonts_inspection_owner, "submit_or_recover",
                        authorized_inspection)
    monkeypatch.setattr(fonts_inspection_owner, "finish",
                        lambda *args, **kwargs: None)
    class Host:
        def __init__(self, cfg):
            assert cfg == target()
        def inspect_command(self, command_id):
            assert command_id == "protected-read-only-inspection"
            return {
                "CommandId": command_id,
                "InstanceId": target()["instance_id"],
                "Status": "Success",
                "StandardOutputContent": json.dumps(report),
            }
        def submit_command(self, *args, **kwargs):
            pytest.fail("original build SSM SendCommand was replayed")
    if difference == "same":
        out = simple_forward.reconcile_project_observation(
            gateway, request["request_id"], host_factory=Host)
        assert out["phase"] == "completed"
        assert checked == [(binding["project_root"],
                            request["request_id"], "a" * 32)]
        assert len(sent) == 1
        assert (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()
    else:
        with pytest.raises(simple_forward.ForwardingDenied):
            simple_forward.reconcile_project_observation(
                gateway, request["request_id"], host_factory=Host)
        assert not (gateway / "requests" / request["request_id"] /
                    "remote-result.json").exists()
        assert saved_path.read_bytes() == recorded
        if difference in ("foreign-source", "foreign-pipeline"):
            assert checked == [(binding["project_root"],
                                request["request_id"], "a" * 32)]
    assert load_dispatch(gateway, request["request_id"]) == frozen



@pytest.mark.parametrize("observer", ["forward", "direct"])
def test_same_original_command_cannot_change_source_pipeline_or_terminal_claim(
        tmp_path, monkeypatch, observer):
    request = approved()
    compiler, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    assert _observe_original(gateway, request, binding, receipt,
                             observer, monkeypatch) == "running"
    obs_path = gateway / "requests" / request["request_id"] / "dispatch-observation.json"
    before = obs_path.read_bytes()

    # The original SSM command cannot change from a pending producer to an
    # apparently completed one on a later read; even a self-consistently
    # rehashed new receipt for the same CommandId is not new evidence.
    later = copy.deepcopy(receipt)
    later["result"].update(status="completed", terminal_outcome="success",
                           uncertainty=False, reconciliation_required=False)
    later = _rehash(later)
    assert execution.parse_receipt(json.dumps(later), binding) == later
    assert execution.project_current_completion(later) == "completed"
    with pytest.raises(RuntimeError, match="original SSM receipt"):
        _observe_original(gateway, request, binding, later, observer, monkeypatch)
    assert obs_path.read_bytes() == before
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert not (obs_path.parent / "remote-result.json").exists()


@pytest.mark.parametrize("observer", ["forward", "direct"])
def test_failed_pre_pipeline_request_is_consistently_non_successful(
        tmp_path, monkeypatch, observer):
    request = approved()
    _, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"], producer_case="request-error")
    assert receipt["result"]["terminal_outcome"] == "request-error"
    assert receipt["result"]["reconciliation_required"] is False
    assert execution.parse_receipt(json.dumps(receipt), binding) == receipt
    assert execution.project_current_completion(receipt) == "failed"
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    assert _observe_original(gateway, request, binding, receipt,
                             observer, monkeypatch) == "failed"
    assert load_dispatch(gateway, request["request_id"]) == frozen
    result = json.loads((gateway / "requests" / request["request_id"] /
                        "remote-result.json").read_text())
    assert result["completion"] == "failed"
    assert result["result"]["result"]["failure"]["type"] == "ImageBuildError"


@pytest.mark.parametrize("producer_uncertainty", ["none", "string", "missing"])
def test_project_wrapper_rejects_invalid_uncertainty_instead_of_coercing_false(
        tmp_path, producer_uncertainty):
    root, source, controller = project(tmp_path)
    module = source / "src/zog/image_build/remote_operations.py"
    old = module.read_text()
    if producer_uncertainty == "none":
        new = old.replace("'uncertainty':False", "'uncertainty':None")
    elif producer_uncertainty == "string":
        new = old.replace("'uncertainty':False", "'uncertainty':'false'")
    else:
        new = old.replace("'uncertainty':False,", "")
    assert new != old
    module.write_text(new)
    git(source, "add", ".")
    git(source, "commit", "-qm", "malformed synthetic producer")
    spec, lane = selected(root, controller, historic=False)
    original = project_current.binding(intent("7" * 32), lane, spec, target())
    actual = subprocess.run(project_current.remote_script(original), shell=True,
                            capture_output=True, text=True, timeout=25)
    assert actual.returncode != 0
    assert "producer status invalid" in actual.stderr
    assert '"result_representation"' not in actual.stdout



@pytest.mark.parametrize("observer", ["forward", "direct"])
@pytest.mark.parametrize("producer_case,expected", [
    ("pending", "running"),
    ("unknown", "recovery_blocked"),
    ("missing-evidence", "recovery_blocked"),
])
def test_accepted_producer_without_wrapper_flag_never_invents_success(
        tmp_path, monkeypatch, observer, producer_case, expected):
    request = approved()
    _, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"], producer_case=producer_case)
    assert receipt["result"]["reconciliation_required"] is (
        producer_case != "pending")
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    assert _observe_original(gateway, request, binding, receipt,
                             observer, monkeypatch) == expected
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert not (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()


@pytest.mark.parametrize("format", ["legacy", "normalized"])
@pytest.mark.parametrize("observer", ["forward", "direct"])
def test_original_claim_survives_nonterminal_readback_and_later_polls(
        tmp_path, monkeypatch, format, observer):
    request = approved()
    _, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    if format == "legacy":
        receipt = _legacy(receipt)
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    _observe_original(gateway, request, binding, receipt, observer, monkeypatch)
    directory = gateway / "requests" / request["request_id"]
    claim_path = directory / "original-ssm-receipt-claim.json"
    claim_bytes = claim_path.read_bytes()
    claim = json.loads(claim_bytes)["claim"]
    assert claim["raw_result_digest_verified"] is (format == "normalized")
    report = _project_readback_report(binding)
    report.update(terminal_confirmed=False, uncertainty=True,
                  producer_status="pending", terminal_outcome=None,
                  pipeline_status="pending")
    from zog.host_deploy.gateway import fonts_inspection_owner
    from zog.host_deploy.gateway import project_current_observation as observe
    monkeypatch.setattr(simple_forward, "FIRST_FONTS_COMPILER_PROJECT_UID",
                        os.geteuid())
    inspections = []
    def authorized(*args, **kwargs):
        assert kwargs["pipeline_id"] == claim["pipeline_id"]
        assert kwargs["original_command_id"] == frozen["command_id"]
        inspections.append(kwargs)
        return len(inspections), "read-only-" + str(len(inspections))
    monkeypatch.setattr(fonts_inspection_owner, "submit_or_recover", authorized)
    monkeypatch.setattr(fonts_inspection_owner, "finish", lambda *a, **kw: None)
    monkeypatch.setattr(observe, "read_only_observation_script",
                        lambda *a, **kw: "fixed-read-only-script")

    class InspectionHost:
        def __init__(self, config):
            assert config == target()
        def inspect_command(self, command_id):
            assert command_id.startswith("read-only-")
            return {"CommandId": command_id,
                    "InstanceId": target()["instance_id"], "Status": "Success",
                    "StandardOutputContent": json.dumps(report)}
        def submit_command(self, *a, **kw):
            pytest.fail("original SSM build replayed")
    assert simple_forward.reconcile_project_observation(
        gateway, request["request_id"], host_factory=InspectionHost)["phase"] == "running"
    latest_path = directory / "dispatch-observation.json"
    latest = latest_path.read_bytes()

    # Status-only and temporarily absent polls in BOTH callers cannot erase
    # the more recent protected readback or regress its completion state.
    for status in (None, "InProgress", "TimedOut"):
        class PollHost:
            def __init__(self, config):
                assert config == target()
            def inspect_command(self, command_id):
                assert command_id == frozen["command_id"]
                return None if status is None else {
                    "CommandId": command_id, "InstanceId": target()["instance_id"],
                    "Status": status}
            def submit_command(self, *a, **kw):
                pytest.fail("poll replayed original SSM")
        direct, _, _ = execution.observe_submitted(
            gateway, request["request_id"], host_factory=PollHost)
        assert direct["states"]["completion"] == "running"
        assert simple_forward.advance(
            gateway, request["request_id"], host_factory=PollHost)["phase"] == "running"
        assert latest_path.read_bytes() == latest
        assert claim_path.read_bytes() == claim_bytes

    for route in ("direct", "forward"):
        assert _observe_original(gateway, request, binding, receipt,
                                 route, monkeypatch) == "running"
        # Independently valid/rehashed altered receipts from the SAME C
        # must be denied even after reconciliation advanced latest state.
        for field, value in (
                ("source_revision", "f" * 40), ("pipeline_id", "e" * 32),
                ("status", "completed")):
            later = copy.deepcopy(receipt)
            later["result"][field] = value
            if field == "status":
                later["result"].update(terminal_outcome="success",
                                       reconciliation_required=False)
            if format == "normalized":
                if field == "source_revision":
                    template = copy.deepcopy(binding["remote_request"])
                    template["source"]["revision"] = value
                    later["result"]["source_evidence"].update(
                        revision=value, request_sha256=hashlib.sha256(
                            _canonical(template) + b"\n").hexdigest())
                later = _rehash(later)
            assert execution.parse_receipt(json.dumps(later), binding) == later
            with pytest.raises(RuntimeError, match="original SSM receipt"):
                _observe_original(gateway, request, binding, later, route, monkeypatch)
            assert latest_path.read_bytes() == latest
            assert claim_path.read_bytes() == claim_bytes
            assert not (directory / "remote-result.json").exists()

    # Repeated same-operation inspection can legitimately reach terminal.
    report.update(terminal_confirmed=True, uncertainty=False,
                  producer_status="completed", terminal_outcome="success",
                  pipeline_status="complete")
    assert simple_forward.reconcile_project_observation(
        gateway, request["request_id"], host_factory=InspectionHost)["phase"] == "completed"
    assert claim_path.read_bytes() == claim_bytes
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert len(inspections) == 2


def test_original_receipt_claim_creation_is_atomic_under_request_lock(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from zog.host_deploy.gateway.ledger import LedgerConflict, record_project_poll
    request = approved()
    _, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    changed = copy.deepcopy(receipt)
    changed["result"]["pipeline_id"] = "e" * 32
    changed = _rehash(changed)
    barrier = Barrier(2)
    def poll(value):
        verified = execution.parse_receipt(json.dumps(value), binding)
        claim = execution.project_receipt_observation(
            verified, binding, frozen["command_id"], target()["instance_id"])
        barrier.wait(timeout=10)
        try:
            record_project_poll(gateway, request["request_id"], observation=claim,
                                claim=claim, completion="running")
            return "accepted", claim
        except LedgerConflict:
            return "conflict", claim
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(poll, [receipt, changed]))
    assert sorted(status for status, _ in results) == ["accepted", "conflict"]
    winner = next(claim for status, claim in results if status == "accepted")
    directory = gateway / "requests" / request["request_id"]
    assert json.loads((directory / "original-ssm-receipt-claim.json").read_text())[
        "claim"] == winner
    assert json.loads((directory / "dispatch-observation.json").read_text())[
        "observation"] == winner
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert not (directory / "remote-result.json").exists()



@pytest.mark.parametrize("format", ["legacy", "normalized"])
@pytest.mark.parametrize("old_latest", ["typed", "reconciled"])
def test_upgrade_requires_authenticated_original_readback_without_erasing_old_evidence(
        tmp_path, monkeypatch, format, old_latest):
    request = approved()
    _, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"])
    if format == "legacy":
        receipt = _legacy(receipt)
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    _observe_original(gateway, request, binding, receipt, "direct", monkeypatch)
    directory = gateway / "requests" / request["request_id"]
    claim_path = directory / "original-ssm-receipt-claim.json"
    latest_path = directory / "dispatch-observation.json"
    original = json.loads(claim_path.read_text())["claim"]
    # Simulate the previous source version's on-disk layout in disposable
    # fixtures only. No native evidence is removed by the new code.
    claim_path.unlink()
    latest = json.loads(latest_path.read_text())
    if old_latest == "typed":
        latest["observation"].pop("receipt_sha256")
    else:
        latest["observation"] = {
            "schema": "host-deploy-direct-ssm-observation-v1",
            "status": "reconciled-project",
            "command_id": frozen["command_id"],
            "inspection_command_id": "retained-read-only",
            "compiler_instance_id": target()["instance_id"],
            "producer": original["producer"],
        }
    latest_path.write_text(json.dumps(latest))
    prior = latest_path.read_bytes()
    class Absent:
        def __init__(self, config):
            assert config == target()
        def inspect_command(self, command_id):
            assert command_id == frozen["command_id"]
            return None
    execution.observe_submitted(gateway, request["request_id"], host_factory=Absent)
    assert not claim_path.exists()
    assert latest_path.read_bytes() == prior
    foreign = copy.deepcopy(receipt)
    foreign["result"]["pipeline_id"] = "e" * 32
    if format == "normalized":
        foreign = _rehash(foreign)
    with pytest.raises(RuntimeError):
        _observe_original(gateway, request, binding, foreign, "direct", monkeypatch)
    assert not claim_path.exists()
    assert latest_path.read_bytes() == prior
    _observe_original(gateway, request, binding, receipt, "direct", monkeypatch)
    assert json.loads(claim_path.read_text())["claim"] == original
    assert latest_path.read_bytes() == prior
    assert load_dispatch(gateway, request["request_id"]) == frozen
    assert not (directory / "remote-result.json").exists()



@pytest.mark.parametrize("observer", ["forward", "direct"])
@pytest.mark.parametrize("kind", ["command-exit", "controller-outcome"])
def test_actual_pipeline_summary_terminal_failure_retains_original_evidence(
        tmp_path, monkeypatch, observer, kind):
    request = approved()
    compiler, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"], producer_case=kind)
    result = receipt["result"]
    failure = result["failure"]
    assert result["status"] == "failed"
    assert result["terminal_outcome"] == "nonzero-exit"
    assert result["uncertainty"] is False
    assert result["reconciliation_required"] is False
    assert result["missing_evidence_count"] == 0
    assert failure["kind"] == kind
    assert failure["exit_code"] == (7 if kind == "command-exit" else 9)
    assert failure["process_cleanup_complete"] is True
    assert failure["journal_reference"].startswith("journal:original-")
    assert "type" not in failure and "reason" not in failure
    evidence_path = compiler / "state" / failure["locator"]
    local = json.loads(evidence_path.read_text())
    assert failure["exit_code"] == local["exit_code"]
    assert failure["journal_reference"] == local["journal_reference"]
    if kind == "controller-outcome":
        assert failure["job_id"] == local["job_id"]
        assert failure["outcome"] == local["outcome"]
        assert failure["signal"] == local["signal"]
    assert execution.parse_receipt(json.dumps(receipt), binding) == receipt
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    assert _observe_original(gateway, request, binding, receipt,
                             observer, monkeypatch) == "failed"
    directory = gateway / "requests" / request["request_id"]
    saved = json.loads((directory / "remote-result.json").read_text())
    assert saved["completion"] == "failed"
    assert saved["result"]["result"]["failure"] == failure
    assert load_dispatch(gateway, request["request_id"]) == frozen


@pytest.mark.parametrize("observer", ["forward", "direct"])
@pytest.mark.parametrize("kind", ["controller-unknown", "controller-cleanup-pending"])
def test_actual_unresolved_controller_summary_remains_nonterminal(
        tmp_path, monkeypatch, observer, kind):
    request = approved()
    _, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"], producer_case=kind)
    assert receipt["result"]["status"] == "pending"
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    assert _observe_original(gateway, request, binding, receipt,
                             observer, monkeypatch) in {"running", "recovery_blocked"}
    assert not (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()
    assert load_dispatch(gateway, request["request_id"]) == frozen


@pytest.mark.parametrize("observer", ["forward", "direct"])
@pytest.mark.parametrize("damage", [
    "generic-text", "missing-cleanup", "cleanup-false", "zero-exit",
    "boolean-exit", "unknown-outcome", "contradictory-outcome", "foreign-attempt",
    "traversal", "missing-job", "unbounded-journal", "unlisted-attempt",
])
def test_rehashed_invalid_terminal_failure_never_creates_terminal_result(
        tmp_path, monkeypatch, observer, damage):
    request = approved()
    _, binding, receipt, _ = receipt_fixture(
        tmp_path, request_id=request["request_id"],
        producer_case="controller-outcome")
    result = receipt["result"]
    failure = result["failure"]
    if damage == "generic-text":
        result["failure"] = {"type": "Anything", "reason": "nonzero exit"}
    elif damage == "missing-cleanup":
        del failure["process_cleanup_complete"]
    elif damage == "cleanup-false":
        failure["process_cleanup_complete"] = False
    elif damage == "zero-exit":
        failure["exit_code"] = 0
    elif damage == "boolean-exit":
        failure["exit_code"] = True
    elif damage == "unknown-outcome":
        failure["outcome"] = result["terminal_outcome"] = "unknown"
    elif damage == "contradictory-outcome":
        result["terminal_outcome"] = "timeout"
    elif damage == "foreign-attempt":
        failure["locator"] = "image-build/attempts/foreign/failure.observation.json"
    elif damage == "traversal":
        failure["locator"] = ("image-build/attempts/image-original-fonts-final/"
                              "../foreign/failure.observation.json")
    elif damage == "missing-job":
        failure["job_id"] = None
    elif damage == "unbounded-journal":
        failure["journal_reference"] = "x" * 4097
    elif damage == "unlisted-attempt":
        result["attempt_ids"] = []
    receipt = _rehash(receipt)
    assert execution.parse_receipt(json.dumps(receipt), binding) == receipt
    gateway = tmp_path / "gateway"
    frozen = _gateway_with_frozen_original(gateway, request, binding)
    assert _observe_original(gateway, request, binding, receipt,
                             observer, monkeypatch) == "recovery_blocked"
    assert not (gateway / "requests" / request["request_id"] /
                "remote-result.json").exists()
    assert load_dispatch(gateway, request["request_id"]) == frozen
