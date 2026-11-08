"""PR35 + Task C protected backend-bound registry mapping source-only denial."""
import copy
import sys
from pathlib import Path

import pytest
from zog.host_deploy.gateway import graphics_registry_backend_source as gateway
from zog.host_deploy.gateway.graphics_owner_trust_history import TrustUnavailable
from zog.host_install.graphical_registry_identity_mapping_v2 import SCHEMA as IDENTITY_V2

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"companions/host-install/tests"))
sys.path.insert(0,str(ROOT/"companions/root-control/tests"))
from test_graphical_registry_identity_mapping_v2 import source


@pytest.mark.parametrize("backend",("root-directory","mounted-volume"))
def test_correct_signed_mapping_remains_source_only(backend):
    args,signed,_=source(backend)
    result=gateway.review_signed_mapping(**args,signed_mapping=signed)
    assert IDENTITY_V2=="zog-registry-native-identity-mapping-v2"
    assert result=={
        "schema":gateway.SCHEMA,
        "backend":backend,
        "host_install_source":"24376bd784b7efcc1e393188f792c41685e75f79",
        "source_mapping_verified":True,
        "native_accepted":False,
        "broker_admission":False,
        "ssm_authorized":False,
    }
    assert gateway.NATIVE_BACKEND_OBSERVATION_PROVIDER_INSTALLED is False
    with pytest.raises(TrustUnavailable,match="not installed"):
        gateway.require_native_backend_observation(
            signed_mapping=signed,observation=args["observation"],
            native_accepted=True,broker_admission=True,ssm_authorized=True)


@pytest.mark.parametrize("backend",("root-directory","mounted-volume"))
@pytest.mark.parametrize("mutation",("wrong_mode","marker","inode_or_mount",
                                      "host","signature","claimed_auth"))
def test_backend_mismatch_or_fabricated_authority_fails_closed(backend,mutation):
    args,signed,_=source(backend)
    args=copy.deepcopy(args);signed=copy.deepcopy(signed)
    if mutation=="wrong_mode":
        args["backend"]="mounted-volume" if backend=="root-directory" else "root-directory"
    elif mutation=="marker":
        args["observation"]["state_marker_sha256"]="sha256:"+"f"*64
    elif mutation=="inode_or_mount":
        field="state_inode" if backend=="root-directory" else "state_mount_id"
        args["observation"][field]+=1
    elif mutation=="host":
        args["observation"]["aws_instance_id"]="i-00000000000000000"
    elif mutation=="signature":
        signed["signature_ed25519"]="AA=="
    elif mutation=="claimed_auth":
        signed["native_accepted"]=True
    with pytest.raises(TrustUnavailable):
        gateway.review_signed_mapping(**args,signed_mapping=signed)


def test_source_review_is_not_native_owner_or_backend_provider():
    from zog.host_deploy.gateway import graphics_owner_trust_history as trust
    from zog.host_deploy.gateway import graphics_owner_trust_daemon as daemon
    assert trust.APPROVED_PIN_SHA256 is None
    assert daemon.NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED is False
    assert gateway.NATIVE_BACKEND_OBSERVATION_PROVIDER_INSTALLED is False
    assert "raise TrustUnavailable(" in (
        ROOT/"src/zog/host_deploy/gateway/graphics_registry_backend_source.py"
    ).read_text()
