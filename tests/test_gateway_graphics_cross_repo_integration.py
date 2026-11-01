"""Cross-repository immutable predecessor + signed command-center source contract.

Runs only against the exact image-build checkout pinned by GitHub Actions.
No native Host, real key, SSM, compiler or root state is used.
"""
import os
from pathlib import Path
import subprocess
import pytest

from zog.host_deploy.gateway import graphics_catalogue_owner as first
from zog.host_deploy.gateway import graphics_generation_chain as chain
from zog.host_deploy.gateway import graphics_chain_export as export
from zog.host_deploy.gateway import task_catalogue

SOURCE = "1f07e83dbd80dacb9bed0d6494c697375f0e26cd"
OCTOBER_PIN = "d3104eeddbbbe63fe3279c58ce9807f3b5250632ecdca4826abc028bcf923b36"


def _checkout():
    path = os.environ.get("ZOG_GRAPHICAL_PRODUCER_SOURCE_ROOT")
    if not path:
        pytest.skip("exact producer source checkout is required")
    root = Path(path).resolve()
    assert root.is_dir() and not root.is_symlink()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    assert head == SOURCE
    return root


def test_producer_accepted_targets_exactly_match_protected_successors():
    _checkout()
    from zog.image_build import graphical_composition as producer
    assert first.SOURCE == SOURCE
    assert first.PIN_SHA256 == OCTOBER_PIN
    assert producer.CONTRACT == "image-build-graphical-predecessor-composition-v1"
    assert chain.TASKS == (
        "graphics-fonts-image-v1",
        "graphics-xcb-core-image-v1",
        "graphics-x11-core-image-v1",
    )
    assert tuple(task_catalogue.REVIEWED_IMAGE_TASKS[chain.TASKS[0]]["targets"]) == producer.FONTS
    assert tuple(task_catalogue.REVIEWED_IMAGE_TASKS[chain.TASKS[1]]["targets"]) == producer.XCB
    assert tuple(task_catalogue.REVIEWED_IMAGE_TASKS[chain.TASKS[2]]["targets"]) == producer.X11
    assert producer.input_fields(None) == {}
    bound = {"generation": "b"*64, "manifest_sha256": "sha256:" + "c"*64,
             "build_record": "sha256:" + "d"*64, "stage": "fonts"}
    assert producer.input_fields(bound) == {
        "graphical_predecessor": "b"*64,
        "graphical_predecessor_manifest_sha256": "sha256:"+"c"*64,
        "graphical_predecessor_record": "sha256:"+"d"*64,
        "graphical_composition_contract": producer.CONTRACT,
    }


def test_signed_export_and_nonroot_supervisor_share_original_source_pin():
    _checkout()
    import inspect
    from zog.host_deploy.gateway import consumer
    assert "source_revision" in export._PIN
    assert "monthly_pin_identity" in export._PIN
    assert first.SOURCE == SOURCE
    assert first.PIN_PATH == "project/pins/2026-10-01/commit-pin.py"
    assert "load_selected_step" in inspect.getsource(consumer.GatewayConsumer._advance_one_reviewed)
    assert "load_installed_step" not in inspect.getsource(consumer.GatewayConsumer._advance_one_reviewed)
    assert list(inspect.signature(chain.install_next_native).parameters) == ["previous_task"]


def test_strict_original_toolchain_guard_still_in_producer():
    _checkout()
    from zog.image_build.engine import ImageBuild
    import inspect
    source = inspect.getsource(ImageBuild._ensure)
    assert 'toolchain.manifest["kind"] != "toolchain"' in source
    assert "ordinary builds require a promoted second-stage toolchain" in source
    assert "graphical_predecessor" in source
