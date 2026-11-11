"""Existing root-backed Fonts project quota contract, no AWS or disk provisioning."""
import copy
import pytest
from zog.host_deploy.gateway import fonts_resource_admission as quota

def valid():
    return {"schema":quota.SCHEMA,"host_id":"host","installation_id":"install",
            "lane":"fonts","root_filesystem_id":"a"*64,
            "work":{"path":quota.WORK_ROOT,"filesystem_id":"a"*64,
                    "backend":"xfs-project-quota","project_id":1001,
                    "hard_bytes":quota.WORK_BYTES,
                    "quota_active":True,"inheritance_verified":True,
                    "real_directory":True,"same_host_root_filesystem":True,
                    "kernel_verified":True},
            "external":{"path":quota.EXTERNAL_ROOT,"filesystem_id":"a"*64,
                    "backend":"xfs-project-quota","project_id":1002,
                    "hard_bytes":quota.EXTERNAL_BYTES,
                    "quota_active":True,"inheritance_verified":True,
                    "real_directory":True,"same_host_root_filesystem":True,
                    "kernel_verified":True},
            "worker_writable_roots":[quota.WORK_ROOT,quota.EXTERNAL_ROOT],
            "deadline_seconds":21600,"deadline_enforced":True,
            "observation_status":"live-kernel-observed"}

def check(v):
    return quota.checked(v,current_host_id="host",
                         current_installation_id="install",expected_lane="fonts")

def test_exact_ceiling_no_extra_ebs_or_loop():
    a=check(valid())
    assert a["work_bytes"]==30*1024**3
    assert a["external_bytes"]==2*1024**3
    assert a["total_bytes"]==32*1024**3
    assert a["execution_limit_seconds"]==21600
    assert a["backend"]=="existing-root-filesystem-project-quota"
    with pytest.raises(quota.FontsResourceHold):
        quota.inspect_native()

@pytest.mark.parametrize("mutation",[
    lambda x:x.update(observation_status="source-claimed"),
    lambda x:x.update(deadline_enforced=False),
    lambda x:x.update(deadline_seconds=21601),
    lambda x:x.update(host_id="other"),
    lambda x:x["work"].update(backend="fallocate-only"),
    lambda x:x["work"].update(backend="separate-ebs-volume"),
    lambda x:x["work"].update(hard_bytes=31*1024**3),
    lambda x:x["external"].update(hard_bytes=3*1024**3),
    lambda x:x["external"].update(project_id=1001),
    lambda x:x["external"].update(filesystem_id="b"*64),
    lambda x:x["work"].update(quota_active=False),
    lambda x:x["work"].update(inheritance_verified=False),
    lambda x:x["work"].update(same_host_root_filesystem=False),
    lambda x:x.update(worker_writable_roots=[quota.WORK_ROOT,quota.EXTERNAL_ROOT,"/tmp"]),
    lambda x:x.update(worker_writable_roots=[quota.WORK_ROOT]),
    lambda x:x.update(worker_writable_roots=[quota.WORK_ROOT,quota.EXTERNAL_ROOT,quota.WORK_ROOT]),
])
def test_unsafe_or_unenforced_resource_admission_denied(mutation):
    value=copy.deepcopy(valid())
    mutation(value)
    with pytest.raises(quota.FontsResourceHold):
        check(value)
