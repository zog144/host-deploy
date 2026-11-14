import pytest
from zog.host_deploy import image_build_lanes as lanes


def test_first_fonts_inherited_schema_has_no_account_selector():
    old = dict(schema=4, lane="gateway-first-fonts-runtime", mode="managed",
               source_repository="zog144/image-build", source_revision="a"*40,
               monthly_pin_repository_path="monthly/pin.py",
               monthly_pin_identity="sha256:"+"b"*64, observed_state_dir=None,
               python_executable="/usr/bin/python3", provenance_host_id="old-host",
               provenance_project_id="old-project",
               project_root="/home/certbot-build-owner/gateway-first-fonts-runtime",
               resource_policy=dict(memory_maximum_bytes=2**30,thread_count_maximum=64,
                                    cpu_weight=100,disk_reservation_bytes=2**30),
               controller=dict(socket_path="/run/zog/root-control.sock",
                               execution_user_id=24202,execution_group_id=24202,
                               startup_timeout_seconds=30,execution_timeout_seconds=3600,
                               termination_grace_seconds=10,wait_timeout_seconds=0,
                               transport_timeout_seconds=45))
    former = lanes.specification_sha256(old)
    new = lanes.corrected_first_fonts_specification(old)
    assert lanes.specification_sha256(old) == former
    assert new["schema"] == 5
    assert lanes.specification_sha256(new) != former
    assert new["project_root"] == "/var/lib/zog/image-build-lanes/gateway-first-fonts-runtime"
    assert "execution_user_id" not in new["controller"]
    assert "execution_group_id" not in new["controller"]
    assert "execution_user_id" not in lanes._controller(new)
    with pytest.raises(RuntimeError,match="historical"):
        lanes._controller(old)
    with pytest.raises(RuntimeError,match="historical"):
        lanes.remote_operation_argv({"state":"active","specification":old}, "/tmp/request.json")
    new["controller"]["execution_user_id"] = 24202
    with pytest.raises(ValueError,match="controller"):
        lanes.validate(new)
