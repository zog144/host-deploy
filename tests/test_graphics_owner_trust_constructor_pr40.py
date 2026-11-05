"""Cross-owner constructor wiring against the exact root-control PR40 source.

Positive cases use synthetic protected objects only and never start a service.
The native admission switch and public-pin selection remain OFF.
"""
from pathlib import Path

import pytest

from zog.host_deploy.gateway import graphics_owner_trust_daemon as daemon
from zog.host_deploy.gateway import graphics_owner_trust_history as history

ROOT40 = "c603eee47e8e43ed0e1b46052337a35ce9836e7c"
HOSTINSTALL32 = "9a91fa2e3eba1e41e5b4d8f201ee30a7be14814d"
SELECTED_REVIEWED_BROKER = "0ea6d583fa441527f45dabbbf542731560644a72"


def _authority():
    return daemon.InstalledReadOnlyAuthority(
        registry=object(), issuer_evidence={}, issuer_public_key=b"a"*32,
        observation_public_key=b"b"*32, checkpoint=object(), signed_pin={},
        broker_signer=object(), installed_source_sha256="c"*64,
        original_checkpoint={}, gateway_uid=15310, gateway_gid=15311,
        gateway_executable_sha256="sha256:"+"d"*64,
        gateway_cgroup="/system.slice/zog-graphical-gateway.service")


def test_native_default_denies_without_importing_or_choosing_authority(monkeypatch):
    from zog.root_control import graphical_task_c_trust_authority as root
    monkeypatch.setattr(root, "installed_readonly_authority",
                        lambda: pytest.fail("original authority reached"))
    assert daemon.NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED is False
    with pytest.raises(history.TrustUnavailable):
        daemon.installed_runtime()
    assert history.APPROVED_PIN_SHA256 is None


def test_exact_root_pr40_constructor_is_selected_without_gateway_fallback(monkeypatch):
    from zog.root_control import graphical_task_c_trust_authority as root
    assert root.OWNER_SOURCE == "5ad7d5ed72d1b72edc767a658de28506791a74d4"
    assert root.BROKER_SOURCE == SELECTED_REVIEWED_BROKER
    expected=_authority()
    calls=[]
    monkeypatch.setattr(root, "installed_readonly_authority",
                        lambda: calls.append("selected-root-constructor") or expected)
    # Source-only seam, NOT a production activation or installed credential.
    monkeypatch.setattr(daemon, "NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED", True)
    assert daemon.installed_runtime() is expected
    assert calls == ["selected-root-constructor"]
    assert history.APPROVED_PIN_SHA256 is None


@pytest.mark.parametrize("wrong", [None, {}, "approved", object()])
def test_bad_selected_constructor_result_denies(monkeypatch, wrong):
    from zog.root_control import graphical_task_c_trust_authority as root
    monkeypatch.setattr(root, "installed_readonly_authority", lambda: wrong)
    monkeypatch.setattr(daemon, "NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED", True)
    with pytest.raises(history.TrustUnavailable):
        daemon.installed_runtime()


def test_pinned_root_and_install_sources_keep_broker_disabled():
    root=(Path(__file__).resolve().parents[1]/
          "companion-root-control/src/zog/root_control/graphical_task_c_trust_authority.py")
    install=(Path(__file__).resolve().parents[1]/
             "companion-host-install/src/zog/host_install/graphical_readonly_trust_broker_install.py")
    assert root.is_file() and install.is_file()
    root_bytes=root.read_text()
    install_bytes=install.read_text()
    assert "def installed_readonly_authority():" in root_bytes
    assert "GetObjectOnly(" in root_bytes
    assert "read_original_record()" in root_bytes
    assert "original_checkpoint_installation" not in root_bytes or "read_original_record" in root_bytes
    assert f'ROOT_PROVIDER_SOURCE = "{ROOT40}"' in install_bytes
    assert f'BROKER_SOURCE = "{SELECTED_REVIEWED_BROKER}"' in install_bytes
    assert 'state" != "NOT_INSTALLED"' not in install_bytes
    assert "review_disabled_source(" in install_bytes
    assert "NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED = False" in (
        Path(__file__).resolve().parents[1]/
        "src/zog/host_deploy/gateway/graphics_owner_trust_daemon.py").read_text()
