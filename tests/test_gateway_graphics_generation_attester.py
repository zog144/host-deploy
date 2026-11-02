"""Protected gateway-to-image-build graphical predecessor attester."""
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as first
from zog.host_deploy.gateway import graphics_generation_attester as attester
from zog.host_deploy.gateway import graphics_generation_chain as chain


REQUEST = "a" * 32
PIPELINE = "b" * 32
INPUT = "c" * 64
CATALOGUE = "sha256:" + "d" * 64
HOST = "host-fixture"
LANE = "graphics-fixture"
PROJECT_ROOT = "/var/lib/zog/image-build-lanes/" + LANE


def policy():
    return {
        "schema": chain.SCHEMA,
        "host_id": HOST,
        "installation_id": "installation-fixture",
        "lane": LANE,
        "lane_owner": HOST,
        "project_root": PROJECT_ROOT,
        "source_revision": first.SOURCE,
        "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
        "first_catalogue_sha256": "sha256:" + "1" * 64,
        "first_receipt_sha256": "sha256:" + "2" * 64,
        "first_base_generation_id": "3" * 64,
        "first_base_receipt_sha256": "sha256:" + "4" * 64,
        "task_allowlist": list(chain.TASKS),
        "work_bytes": 30 * 1024**3,
        "external_bytes": 2 * 1024**3,
        "dedicated_storage_bytes": 32 * 1024**3,
        "execution_limit_seconds": 21600,
        "max_generations": 3,
    }


def binding():
    source_root = PROJECT_ROOT + "/source"
    companion = PROJECT_ROOT + "/companions/build-record"
    state = PROJECT_ROOT + "/state"
    pin = source_root + "/" + first.PIN_PATH
    return {
        "schema": 3,
        "lane": LANE,
        "source": {
            "repository": first.REPOSITORY, "revision": first.SOURCE
        },
        "monthly_pin_repository_path": first.PIN_PATH,
        "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
        "project_root": PROJECT_ROOT,
        "source_root": source_root,
        "observed_state_dir": None,
        "task_catalogue_identity": CATALOGUE,
        "task": {
            "source_repository": first.REPOSITORY,
            "source_revision": first.SOURCE,
            "lane": LANE,
            "lane_owner": HOST,
            "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
            "arguments": {"mode": "image", "selection": INPUT},
        },
        "python_executable": "/usr/bin/python3",
        "runtime_companion": {
            "schema": 1,
            "repository": "zog144/build-record",
            "revision": "e" * 40,
            "source_root": companion,
            "producer_revision": first.SOURCE,
        },
        "runtime_profile": {
            "controller": False,
            "controller_revision": None,
            "controller_source_root": None,
        },
        "argv": [
            "env",
            "PYTHONPATH=" + source_root + "/src:" + companion + "/src",
            "/usr/bin/python3",
            "-m", "zog.image_build.remote_operations",
            "--state-dir", state,
            "--provenance-host-id", HOST,
            "--provenance-project-id", "project-fixture",
            "--provenance-pin", pin,
            "--expected-pin-digest", "sha256:" + first.PIN_SHA256,
        ],
    }


def evidence():
    return {
        "schema": chain.EVIDENCE,
        "task": chain.TASKS[0],
        "host_id": HOST,
        "installation_id": "installation-fixture",
        "lane": LANE,
        "lane_owner": HOST,
        "project_root": PROJECT_ROOT,
        "source_revision": first.SOURCE,
        "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
        "request_id": REQUEST,
        "pipeline_id": PIPELINE,
        "predecessor_catalogue_sha256": CATALOGUE,
        "input_generation_id": INPUT,
        "output_generation_id": "f" * 64,
        "output_kind": "image",
        "generation_manifest_sha256": "sha256:" + "5" * 64,
        "acceptance_receipt_sha256": "sha256:" + "6" * 64,
        "producer_receipt_sha256": "sha256:" + "7" * 64,
        "status": "accepted",
        "terminal_outcome": "success",
        "uncertainty": False,
        "missing_evidence_count": 0,
    }


def install_fakes(tmp_path, monkeypatch, *, requests=1, phase="completed"):
    root = tmp_path / "gateway"
    for index in range(requests):
        (root / "requests" / (REQUEST if index == 0 else "9" * 32)).mkdir(
            parents=True
        )
    p = policy()
    state = {
        "request": {
            "request_id": REQUEST,
            "operation": "build.submit",
            "source": {
                "repository": first.REPOSITORY, "commit": first.SOURCE
            },
            "parameters": {"task": chain.TASKS[0], "lane": LANE},
        },
        "states": {"admission": "admitted"},
    }
    monkeypatch.setattr(
        attester, "load_request",
        lambda root, ident: {
            **state,
            "request": {**state["request"], "request_id": ident},
        },
    )
    b = binding()
    monkeypatch.setattr(
        attester, "load_dispatch",
        lambda root, ident: {"phase": "prepared", "binding": b},
    )
    monkeypatch.setattr(
        attester.image_build_execution, "_binding",
        lambda record: record["binding"],
    )
    monkeypatch.setattr(
        attester, "verify_current_target", lambda root, selected: object()
    )
    monkeypatch.setattr(
        attester.generic_pipeline, "status",
        lambda root, ident: {
            "phase": phase,
            "pipeline_id": PIPELINE,
            "stages": [{"phase": "completed"}],
        },
    )
    from zog.host_deploy.gateway import graphics_attester_import as import_boundary
    monkeypatch.setattr(import_boundary, "verify", lambda **kw: {
        "python": "/usr/bin/python3",
        "module_roots": ["/usr/lib/zog/graphical-attester/image-build",
                         "/usr/lib/zog/graphical-attester/build-record"],
        "source_revision": first.SOURCE,
        "monthly_pin_identity": "sha256:" + first.PIN_SHA256,
    })
    monkeypatch.setattr(attester.os, "geteuid", lambda: 0)
    from zog.host_deploy.gateway import graphics_gateway_history as history
    monkeypatch.setattr(history, "verify_history", lambda *args: True)
    return root, p


def test_installed_capability_has_no_output_generation_argument(tmp_path, monkeypatch):
    monkeypatch.setattr(attester.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        chain, "_read_locked", lambda path: policy()
    )
    monkeypatch.setattr(
        __import__(
            "zog.host_deploy.gateway.fresh_budget_guard",
            fromlist=["_protected_root"],
        ),
        "_protected_root", lambda path: True,
    )
    capability = attester.installed_capability(tmp_path)
    assert list(inspect.signature(capability).parameters) == [
        "previous_task", "predecessor_catalogue_sha256", "input_generation_id"
    ]


def test_exact_completed_gateway_context_invokes_installed_attester(
    tmp_path, monkeypatch
):
    root, p = install_fakes(tmp_path, monkeypatch)
    captured = {}
    expected = evidence()

    def run(command, **kwargs):
        captured["command"] = command
        captured["input"] = kwargs["input"]
        captured["env"] = kwargs["env"]
        return SimpleNamespace(
            returncode=0,
            stdout=attester._canonical(expected) + b"\n",
            stderr=b"",
        )

    monkeypatch.setattr(attester, "_run", run)
    result = attester._attest(
        root, p, chain.TASKS[0], CATALOGUE, INPUT
    )
    assert result == expected
    context = json.loads(captured["input"])
    assert context["request_id"] == REQUEST
    assert context["pipeline_id"] == PIPELINE
    assert context["input_generation_id"] == INPUT
    assert "output_generation_id" not in context
    assert captured["command"][:6] == [
        "/usr/bin/python3", "-I", "-S", "-B", "-c",
        __import__("zog.host_deploy.gateway.graphics_attester_import",
                   fromlist=["BOOTSTRAP"]).BOOTSTRAP,
    ]
    assert captured["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    assert captured["env"]["PYTHONNOUSERSITE"] == "1"
    assert "PYTHONPATH" not in captured["env"]
    assert captured["command"][6].startswith("[")


def test_ambiguous_or_incomplete_request_never_invokes_producer(
    tmp_path, monkeypatch
):
    root, p = install_fakes(tmp_path, monkeypatch, requests=2)
    monkeypatch.setattr(
        attester, "_run",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("producer invoked")
        ),
    )
    with pytest.raises(attester.GraphicalAttesterBlocked, match="ambiguous"):
        attester._attest(root, p, chain.TASKS[0], CATALOGUE, INPUT)

    root, p = install_fakes(tmp_path / "other", monkeypatch, phase="running")
    with pytest.raises(attester.GraphicalAttesterBlocked, match="not durably completed"):
        attester._attest(root, p, chain.TASKS[0], CATALOGUE, INPUT)


def test_wrong_catalogue_or_input_binding_is_rejected(tmp_path, monkeypatch):
    root, p = install_fakes(tmp_path, monkeypatch)
    with pytest.raises(attester.GraphicalAttesterBlocked, match="dispatch differs"):
        attester._attest(
            root, p, chain.TASKS[0], "sha256:" + "8" * 64, INPUT
        )
    with pytest.raises(attester.GraphicalAttesterBlocked, match="dispatch differs"):
        attester._attest(root, p, chain.TASKS[0], CATALOGUE, "8" * 64)


def test_failed_or_context_mismatched_producer_output_is_rejected(
    tmp_path, monkeypatch
):
    root, p = install_fakes(tmp_path, monkeypatch)
    monkeypatch.setattr(
        attester, "_run",
        lambda *a, **k: SimpleNamespace(
            returncode=1, stdout=b"", stderr=b"rejected"
        ),
    )
    with pytest.raises(attester.GraphicalAttesterBlocked, match="clean evidence"):
        attester._attest(root, p, chain.TASKS[0], CATALOGUE, INPUT)

    changed = evidence()
    changed["pipeline_id"] = "8" * 32
    monkeypatch.setattr(
        attester, "_run",
        lambda *a, **k: SimpleNamespace(
            returncode=0,
            stdout=attester._canonical(changed),
            stderr=b"",
        ),
    )
    with pytest.raises(attester.GraphicalAttesterBlocked, match="gateway context"):
        attester._attest(root, p, chain.TASKS[0], CATALOGUE, INPUT)


def test_nonroot_stops_before_ledger_read(tmp_path, monkeypatch):
    monkeypatch.setattr(attester.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        attester, "load_request",
        lambda *args: (_ for _ in ()).throw(AssertionError("ledger read")),
    )
    with pytest.raises(PermissionError):
        attester._attest(
            tmp_path, policy(), chain.TASKS[0], CATALOGUE, INPUT
        )


def test_checkout_verifier_uses_read_only_git_commands(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    commands = []
    revision = "a" * 40

    def run(command, **kwargs):
        commands.append(command)
        args = command[3:]
        if args[:2] == ["rev-parse", "--verify"]:
            return SimpleNamespace(
                returncode=0, stdout=(revision + "\n").encode(), stderr=b""
            )
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(attester, "_run", run)
    monkeypatch.setattr(
        attester.Path, "is_file",
        lambda self: True if str(self) == attester.GIT else Path.exists(self),
    )
    attester._verify_checkout(checkout, revision)
    flat = [" ".join(command) for command in commands]
    assert any("diff-index --cached --quiet" in command for command in flat)
    assert any("diff-files --quiet" in command for command in flat)
    assert any("ls-files --others --exclude-standard -z" in command for command in flat)
    assert all(" status " not in (" " + command + " ") for command in flat)
    assert all("--refresh" not in command for command in flat)



def test_project_mutation_cannot_become_root_import_and_blocks_race(tmp_path, monkeypatch):
    root, p = install_fakes(tmp_path, monkeypatch)
    from zog.host_deploy.gateway import graphics_attester_import as importer
    pin = {"python": "/usr/bin/python3",
           "module_roots": ["/usr/lib/zog/graphical-attester/image-build",
                            "/usr/lib/zog/graphical-attester/build-record"]}
    calls = []
    def verify(**kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            raise importer.ImportBoundaryBlocked("changed after first verification")
        return pin
    monkeypatch.setattr(importer, "verify", verify)
    ran = []
    def run(argv, **kw):
        ran.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout=attester._canonical(evidence()),
                               stderr=b"")
    monkeypatch.setattr(attester, "_run", run)
    with pytest.raises(importer.ImportBoundaryBlocked):
        attester._attest(root, p, chain.TASKS[0], CATALOGUE, INPUT)
    assert len(ran) == 1
    assert ran[0][0][:5] == ["/usr/bin/python3", "-I", "-S", "-B", "-c"]
    assert "PYTHONPATH" not in ran[0][1]["env"]
    assert len(calls) == 2


def test_missing_protected_import_prevents_any_root_exec(tmp_path, monkeypatch):
    root, p = install_fakes(tmp_path, monkeypatch)
    from zog.host_deploy.gateway import graphics_attester_import as importer
    monkeypatch.setattr(importer, "verify", lambda **kw: (
        (_ for _ in ()).throw(importer.ImportBoundaryBlocked("no installed pin"))))
    monkeypatch.setattr(attester, "_run", lambda *a, **kw:
        pytest.fail("never execute mutable Project"))
    with pytest.raises(importer.ImportBoundaryBlocked):
        attester._attest(root, p, chain.TASKS[0], CATALOGUE, INPUT)
