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
    assert new["project_root"] == "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
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


def test_inherited_controller_inspection_accepts_process_uid_zero():
    import json
    from zog.host_deploy import fonts_lane_runtime
    legacy = dict(schema=4, lane="gateway-first-fonts-runtime", mode="managed",
                  source_repository="zog144/image-build", source_revision="a"*40,
                  monthly_pin_repository_path="monthly/pin.py",
                  monthly_pin_identity="sha256:"+"b"*64,
                  observed_state_dir=None, python_executable="/usr/bin/python3",
                  provenance_host_id="historical-host", provenance_project_id="historical-project",
                  project_root="/home/certbot-build-owner/gateway-first-fonts-runtime",
                  resource_policy=dict(memory_maximum_bytes=2**30,
                                       thread_count_maximum=64,cpu_weight=100,
                                       disk_reservation_bytes=2**30),
                  controller=dict(socket_path="/run/zog/root-control.sock",
                                  execution_user_id=24202,execution_group_id=24202,
                                  startup_timeout_seconds=30,execution_timeout_seconds=3600,
                                  termination_grace_seconds=10,wait_timeout_seconds=0,
                                  transport_timeout_seconds=45))
    corrected = lanes.corrected_first_fonts_specification(legacy)
    source = fonts_lane_runtime.script(corrected)
    assert "uid,gid=os.geteuid(),os.getegid()" in source
    assert "if uid==0 or gid==0:" not in source
    assert "privileged execution context is not an authorized compiler" not in source
    assert "os.setuid" not in source and "os.setgid" not in source
    assert "st.st_uid!=uid" not in source and "st.st_gid!=gid" not in source
    assert "effective_ids=True" in source
    payload=dict(status="complete",project_root=corrected["project_root"],
                 socket_path=corrected["controller"]["socket_path"],
                 python_executable=corrected["python_executable"],
                 controller_sha256=fonts_lane_runtime.expected_controller_sha256(corrected),
                 effective_user_id=0,effective_group_id=0)
    class Host:
        def command(self, command):
            assert "python3 -c" in command
            return json.dumps(payload)
    assert fonts_lane_runtime.inspect(Host(),corrected)==payload
    payload["effective_user_id"]=-1
    with pytest.raises(RuntimeError,match="current execution context"):
        fonts_lane_runtime.inspect(Host(),corrected)


def test_migration_destination_matches_reviewed_host_install_contract():
    assert str(lanes.FIRST_FONTS_MIGRATED_ROOT) == (
        "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime")
    assert str(lanes.DEFAULT_ROOT) != str(lanes.FIRST_FONTS_MIGRATED_ROOT.parent)
