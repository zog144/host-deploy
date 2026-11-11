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
        "work","external","available_bytes","worker_writable_roots","deadline_seconds",
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
            or type(readback["available_bytes"]) is not int
            or readback["available_bytes"] < TOTAL_BYTES
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


def inspect_native(*, host_id, installation_id, lane,
                   worker_writable_roots, deadline_enforced):
    """Read XFS project quotas directly from the Linux kernel, without writes.

    This reader supports XFS root filesystems with prjquota active. Other
    backends are deliberately unsupported until separately reviewed. The
    trusted controller must independently report every worker writable root
    and the installed execution deadline: neither comes from GitHub/SQS.
    """
    import ctypes
    import fcntl
    import os
    import struct
    import stat

    if os.geteuid() != 0:
        hold()
    # The actual current root mount, not a supplied mount identity or a
    # caller-selected device. Do not treat overlay or nested bind mounts as
    # independent quota enforcement.
    try:
        lines=Path("/proc/self/mountinfo").read_text().splitlines()
        mounts=[]
        for line in lines:
            left,sep,right=line.partition(" - ")
            if not sep:
                hold()
            a,b=left.split(),right.split()
            if len(a)<6 or len(b)<3:
                hold()
            mounts.append((a[4],a[2],a[5],b[0],b[1],b[2]))
        roots=[entry for entry in mounts if entry[0]=="/"]
        if len(roots)!=1 or roots[0][3]!="xfs":
            hold()
        options=set((roots[0][2]+","+roots[0][5]).split(","))
        if not options.intersection({"prjquota","pquota"}):
            hold()
        if options.intersection({"pqnoenforce","prjquotanoenforce"}):
            hold()
        root_stat=os.stat("/")
        fs=os.statvfs("/")
        free_bytes=fs.f_bavail*fs.f_frsize
        if free_bytes<TOTAL_BYTES:
            hold()
        # Each root is a real, root-owned directory on the same filesystem
        # without any nested independent mount or symlink substitution.
        observed={}
        mount_points={m[0] for m in mounts}
        # Linux FS_IOC_FSGETXATTR, struct fsxattr (28 bytes).
        FS_IOC_FSGETXATTR=0x801c581f
        FS_XFLAG_PROJINHERIT=0x00000200
        class DiskQuota(ctypes.Structure):
            _fields_=[
                ("d_version",ctypes.c_int8),("d_flags",ctypes.c_int8),
                ("d_fieldmask",ctypes.c_uint16),("d_id",ctypes.c_uint32),
                ("d_blk_hardlimit",ctypes.c_uint64),
                ("d_blk_softlimit",ctypes.c_uint64),
                ("d_ino_hardlimit",ctypes.c_uint64),
                ("d_ino_softlimit",ctypes.c_uint64),
                ("d_bcount",ctypes.c_uint64),("d_icount",ctypes.c_uint64),
                ("d_itimer",ctypes.c_int32),("d_btimer",ctypes.c_int32),
                ("d_iwarns",ctypes.c_uint16),("d_bwarns",ctypes.c_uint16),
                ("d_itimer_hi",ctypes.c_int8),("d_btimer_hi",ctypes.c_int8),
                ("d_rtbtimer_hi",ctypes.c_int8),("d_padding2",ctypes.c_int8),
                ("d_rtb_hardlimit",ctypes.c_uint64),
                ("d_rtb_softlimit",ctypes.c_uint64),
                ("d_rtbcount",ctypes.c_uint64),
                ("d_rtbtimer",ctypes.c_int32),
                ("d_rtbwarns",ctypes.c_uint16),
                ("d_padding3",ctypes.c_int16),
                ("d_padding4",ctypes.c_char*8),
            ]
        libc=ctypes.CDLL(None,use_errno=True)
        quotactl=libc.quotactl
        quotactl.argtypes=[ctypes.c_int,ctypes.c_char_p,
                           ctypes.c_int,ctypes.c_void_p]
        quotactl.restype=ctypes.c_int
        # QCMD(Q_XGETQUOTA, PRJQUOTA) from linux/quota.h and dqblk_xfs.h.
        cmd=(((ord("X")<<8)+3)<<8)|2
        for name,path,limit in (("work",WORK_ROOT,WORK_BYTES),
                                ("external",EXTERNAL_ROOT,EXTERNAL_BYTES)):
            directory=Path(path)
            if not directory.is_dir() or directory.is_symlink():
                hold()
            # No symlinked ancestors; check all source directories.
            if any(parent.is_symlink() for parent in directory.parents):
                hold()
            st=directory.stat()
            if (st.st_dev!=root_stat.st_dev or st.st_uid!=0 or
                    not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022 or
                    path in mount_points):
                hold()
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|
                       os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                raw=fcntl.ioctl(fd,FS_IOC_FSGETXATTR,b"\0"*28)
            finally:
                os.close(fd)
            flags,_,_,project_id,_,_=struct.unpack("=IIIII8s",raw)
            if not flags & FS_XFLAG_PROJINHERIT or project_id<=0:
                hold()
            dq=DiskQuota()
            if quotactl(cmd, b"/",project_id,ctypes.byref(dq))!=0:
                hold()
            # fs_disk_quota block hard limit uses 512-byte basic blocks.
            hard_bytes=int(dq.d_blk_hardlimit)*512
            if dq.d_id!=project_id or hard_bytes!=limit:
                hold()
            observed[name]={
                "path":path,"filesystem_id":format(root_stat.st_dev,"064x"),
                "backend":"xfs-project-quota","project_id":project_id,
                "hard_bytes":hard_bytes,
                "quota_active":True,"inheritance_verified":True,
                "real_directory":True,"same_host_root_filesystem":True,
                "kernel_verified":True}
        receipt={
            "schema":SCHEMA,"host_id":host_id,
            "installation_id":installation_id,"lane":lane,
            "root_filesystem_id":format(root_stat.st_dev,"064x"),
            "work":observed["work"],"external":observed["external"],
            "available_bytes":free_bytes,
            "worker_writable_roots":worker_writable_roots,
            "deadline_seconds":TIME_SECONDS,
            "deadline_enforced":deadline_enforced,
            "observation_status":"live-kernel-observed",
        }
        checked(receipt,current_host_id=host_id,
                current_installation_id=installation_id,
                expected_lane=lane)
        return receipt
    except (OSError,ValueError,TypeError,IndexError,OverflowError) as exc:
        raise FontsResourceHold("native kernel quota observation unavailable") from exc
