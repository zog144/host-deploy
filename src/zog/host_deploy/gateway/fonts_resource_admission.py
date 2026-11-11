"""Existing-filesystem Fonts resource admission, with no loop/EBS prerequisite.

The only positive input is a *live, independently installed root inspector's*
readback of two enforced directory quotas on the existing Host filesystem.
Neither a caller-supplied JSON flag nor a preallocated file is a quota.
The 30+2 GiB limits are ceilings on actual compiler-owned writes; the
21,600-second operation deadline is a separate installed controller check.
This module performs no storage mutation, mount, SSM operation or dispatch.
"""
from __future__ import annotations

from pathlib import Path
import re

SCHEMA="zog-fonts-root-backed-resource-admission-v1"
WORK_BYTES=30*1024**3
EXTERNAL_BYTES=2*1024**3
TOTAL_BYTES=WORK_BYTES+EXTERNAL_BYTES
TIME_SECONDS=21600
WORK_ROOT="/var/lib/zog/fonts/work"
EXTERNAL_ROOT="/var/lib/zog/fonts/external"
HEX=re.compile(r"[a-f0-9]{64}\Z")

class FontsResourceHold(RuntimeError):
    pass

def hold():
    raise FontsResourceHold("native first-Fonts resource admission not established")

def checked(readback, *, current_host_id, current_installation_id, expected_lane):
    """Validate a privileged native observation without claiming it is authentic.

    Caller must bind this API to an independently installed inspector reading
    actual stat/mountinfo/project-quota and worker namespace state at invocation.
    A dictionary provided by a GitHub request or fixture has NO authority.
    """
    expected={
        "schema","host_id","installation_id","lane","root_filesystem_id",
        "work","external","worker_writable_roots","deadline_seconds",
        "deadline_enforced","observation_status"}
    if type(readback) is not dict or set(readback)!=expected or readback["schema"]!=SCHEMA:
        hold()
    for key,selected in (("host_id",current_host_id),
                         ("installation_id",current_installation_id),
                         ("lane",expected_lane)):
        if (type(selected) is not str or not selected or
                readback[key]!=selected):
            hold()
    if (type(readback["root_filesystem_id"]) is not str or
            HEX.fullmatch(readback["root_filesystem_id"]) is None
            or readback["deadline_seconds"]!=TIME_SECONDS
            or readback["deadline_enforced"] is not True
            or readback["observation_status"]!="live-kernel-observed"):
        hold()
    roots=[]
    for key,root,limit in (("work",WORK_ROOT,WORK_BYTES),
                           ("external",EXTERNAL_ROOT,EXTERNAL_BYTES)):
        value=readback[key]
        if (type(value) is not dict or set(value)!={
            "path","filesystem_id","backend","project_id","hard_bytes",
            "quota_active","inheritance_verified","real_directory",
            "same_host_root_filesystem","kernel_verified"}
            or value["path"]!=root
            or value["filesystem_id"]!=readback["root_filesystem_id"]
            or value["backend"] not in ("xfs-project-quota","ext4-project-quota")
            or type(value["project_id"]) is not int or value["project_id"]<=0
            or type(value["hard_bytes"]) is not int or value["hard_bytes"]!=limit
            or any(value[field] is not True for field in (
                "quota_active","inheritance_verified","real_directory",
                "same_host_root_filesystem","kernel_verified"))):
            hold()
        roots.append(value)
    if roots[0]["project_id"]==roots[1]["project_id"]:
        hold()
    observed=readback["worker_writable_roots"]
    if (type(observed) is not list or not observed
            or len(set(observed))!=len(observed)
            or any(type(p) is not str or not p.startswith("/")
                   or ".." in Path(p).parts for p in observed)
            or not any(p==WORK_ROOT for p in observed)
            or not any(p==EXTERNAL_ROOT for p in observed)
            or not all(any(p==root or p.startswith(root+"/")
                            for root in (WORK_ROOT,EXTERNAL_ROOT))
                       for p in observed)):
        hold()
    # Source-level compatibility only. The installed inspector must prove all
    # compiler and program writable mounts fall inside these real quota roots.
    return {"schema":SCHEMA,"work_bytes":WORK_BYTES,
            "external_bytes":EXTERNAL_BYTES,"total_bytes":TOTAL_BYTES,
            "execution_limit_seconds":TIME_SECONDS,
            "backend":"existing-root-filesystem-project-quota",
            "host_id":current_host_id,"installation_id":current_installation_id,
            "lane":expected_lane,"root_filesystem_id":readback["root_filesystem_id"],
            "status":"native-observation-shape-checked"}


def inspect_native():
    """No invented universal inspector: native provider must verify quotas.

    In particular, free-space and fallocate reports alone do not prove
    actual limits. Native installation may call checked() only after obtaining
    its independent quota/namespace/Host evidence from a reviewed provider.
    """
    hold()
