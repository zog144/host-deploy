"""Cross-owner constructor wiring against the exact root-control PR40 source.

Positive cases use synthetic protected objects only and never start a service.
The native admission switch and public-pin selection remain OFF.
"""
import inspect

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
    # Use imported companion modules, not a repository-specific checkout path.
    # GitHub Actions independently verifies the exact checkout SHAs.
    from zog.root_control import graphical_task_c_trust_authority as root
    from zog.host_install import graphical_readonly_trust_broker_install as install

    assert root.OWNER_SOURCE == "5ad7d5ed72d1b72edc767a658de28506791a74d4"
    assert root.BROKER_SOURCE == SELECTED_REVIEWED_BROKER
    assert install.ROOT_PROVIDER_SOURCE == ROOT40
    assert install.BROKER_SOURCE == SELECTED_REVIEWED_BROKER
    assert install.ROOT_MODULE == root.__name__
    assert inspect.isfunction(root.installed_readonly_authority)
    assert inspect.isfunction(install.review_disabled_source)
    root_source = inspect.getsource(root)
    install_source = inspect.getsource(install)
    assert "GetObjectOnly(" in root_source
    assert "read_original_record()" in root_source
    assert 'selection["state"] != "NOT_INSTALLED"' in install_source
    assert "NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED = False" in (
        inspect.getsource(daemon))
    assert daemon.NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED is False
    assert history.APPROVED_PIN_SHA256 is None
