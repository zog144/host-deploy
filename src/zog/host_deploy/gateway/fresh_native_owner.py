"""Actual privileged Linux owner for the single fresh compiler sidecar.

NO network request API. Only an independently installed, 0600 root-owned
reviewed-plan.json can select the fixed build-only sidecar. No daemon-reload,
legacy systemd mutation, old controller recovery, or generic shell execution.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time
import uuid

from . import fresh_budget_guard as budget
from . import fresh_quota_volume as quota
from . import fresh_sidecar_dbus as dbus
from . import fresh_sidecar_install as sidecar

STATE = Path("/var/lib/zog/host-deploy/fresh-cross-bootstrap-oct25")
PLAN_PATH = STATE / "reviewed-plan.json"
INSTALL_PATH = STATE / "sidecar-install.json"
BASELINE_PATH = STATE / "legacy-baseline.json"
BUDGET_DIR = STATE / "budget"
CRON_PATH = Path("/etc/cron.d/zog-fresh-cross-bootstrap-oct25")
CGROUP = Path("/sys/fs/cgroup/zog-fresh-cross-bootstrap-oct25.slice")
SLICE_UNIT = "zog-fresh-cross-bootstrap-oct25.slice"
CRON_SERVICE = "crond.service"
SCHEMA = "host-deploy-native-sidecar-owner-v1"


def _root():
    if os.geteuid() != 0:
        raise PermissionError("host owner must run with effective root")
    if not os.path.isdir("/sys/fs/cgroup") or not Path("/proc/1/comm").read_text().strip() == "systemd":
        raise RuntimeError("requires the actual Linux systemd host")
    budget._protected_root(STATE)


def _bytes(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _file(path):
    # Fails closed on missing, link, nonroot, hardlink or size/mode mismatch.
    root = budget._protected_root(path.parent)
    fd = os.open(root / path.name, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_size > 131072):
            raise PermissionError("invalid protected host-owner file")
        return os.read(fd, st.st_size + 1)
    finally:
        os.close(fd)


def _store(path, obj, *, exclusive=False):
    _root()
    payload = _bytes(obj)
    budget._protected_root(path.parent)
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_EXCL | os.O_CREAT, 0o600)
        try:
            if os.write(fd, payload) != len(payload):
                raise OSError("short protected host receipt write")
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        temp = path.parent / (".host-" + uuid.uuid4().hex)
        fd = os.open(temp, os.O_WRONLY | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            if os.write(fd, payload) != len(payload):
                raise OSError("short protected host receipt write")
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.replace(temp, path)
        finally:
            if temp.exists():
                temp.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_json(path):
    return json.loads(_file(path))


def _command(args, *, timeout=15):
    # Read-only exact machine metadata; never accepts a shell or arbitrary unit.
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=timeout, env={"PATH": "/usr/bin:/usr/sbin:/bin:/sbin",
                                                "LC_ALL": "C"}).stdout.strip()


def _show(unit):
    if unit not in (sidecar.UNIT, SLICE_UNIT, CRON_SERVICE,
                    "root-control.service"):
        raise ValueError("unapproved systemd readback target")
    raw = _command(["/usr/bin/systemctl", "show", unit,
                    "--property=LoadState,ActiveState,MainPID,InvocationID,"
                    "ControlGroup,Environment,FragmentPath"])
    return dict(row.split("=", 1) for row in raw.splitlines() if "=" in row)


def _boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _protected_tree(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise PermissionError("immutable executable tree location changed")
    for cursor in [path, *path.parents]:
        st = cursor.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022):
            raise PermissionError("executable tree has unprotected ancestry")
    digest = hashlib.sha256()
    for parent, dirs, names in os.walk(path, followlinks=False):
        for name in sorted(dirs + names):
            entry = Path(parent) / name
            st = entry.lstat()
            if (st.st_uid != 0 or st.st_mode & 0o022
                    or (not stat.S_ISDIR(st.st_mode) and not stat.S_ISREG(st.st_mode))
                    or st.st_nlink != (st.st_nlink if stat.S_ISDIR(st.st_mode) else 1)):
                raise PermissionError("unsafe source/companion tree entry")
            digest.update(str(entry.relative_to(path)).encode() + b"\0")
            if stat.S_ISREG(st.st_mode):
                digest.update(entry.read_bytes())
    return _sha(digest.digest())


def _legacy():
    # Root-only local baseline checkpoint may include more identifiers;
    # do not silently substitute a changed shared InvocationID.
    old = _show("root-control.service")
    historic = _read_json(BASELINE_PATH)
    if set(historic) != {"root_control_show", "historical_bad_setting_sha256"}:
        raise RuntimeError("legacy baseline contract is incomplete")
    if old != historic["root_control_show"]:
        raise RuntimeError("shared controller PID1 identity changed")
    if not isinstance(historic["historical_bad_setting_sha256"], str):
        raise RuntimeError("historical bad-setting evidence missing")
    return _sha(_bytes(historic))


def _slice_identity():
    unit = _show(SLICE_UNIT)
    if (unit.get("ActiveState") != "active"
            or unit.get("ControlGroup") != "/" + SLICE_UNIT):
        raise RuntimeError("exclusive new compiler slice not active")
    return unit


def _events():
    _slice_identity()
    path = CGROUP / "cgroup.events"
    text = path.read_text()
    fields = dict(x.split() for x in text.splitlines() if len(x.split()) == 2)
    if fields.get("populated") not in ("0", "1"):
        raise RuntimeError("fresh compiler cgroup populated status unavailable")
    return fields


class NativeOwner:
    """Concrete host-owned installer, quota monitor and scoped cancel backend."""

    def is_trusted_native_owner(self):
        _root()
        return True

    def validate_old_baseline(self, expected):
        if _legacy() != expected:
            raise RuntimeError("historical controller/bad-setting evidence changed")

    def verify_source_and_nss(self, plan):
        _root()
        binding = plan["identity"]
        controller = pwd.getpwuid(binding["controller_uid"])
        build = pwd.getpwuid(binding["build_uid"])
        if (controller.pw_gid != binding["controller_gid"]
                or build.pw_gid != binding["build_gid"]
                or controller.pw_uid == build.pw_uid
                or controller.pw_dir != binding["controller_home"]
                or binding["project_root"] != str(
                    Path(controller.pw_dir) / sidecar.PROJECT)):
            raise PermissionError("fresh nonroot principals/primary groups differ")
        for path in (Path(controller.pw_dir), Path(binding["project_root"])):
            st = path.lstat()
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid != controller.pw_uid
                    or st.st_gid != controller.pw_gid or st.st_mode & 0o022
                    or path.resolve(strict=True) != path):
                raise PermissionError("fresh owner home/Project not protected")
        python = Path(binding["python_executable"])
        st = python.stat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
                or st.st_mode & 0o022):
            raise PermissionError("unexpected sidecar interpreter")
        installed = plan["installed"]
        if _protected_tree(installed["root_control_python_root"]) != installed[
                "root_control_tree_sha256"]:
            raise PermissionError("installed root-control executable bytes changed")
        if installed["boot_id"] != _boot():
            raise RuntimeError("installation selected another native boot")
        self.validate_old_baseline(installed["legacy_baseline_sha256"])

    def read_unit(self, unit):
        data = _show(unit)
        return None if data.get("LoadState") == "not-found" else data

    def socket_exists(self, socket):
        return os.path.lexists(socket)

    def prepare_once(self, plan):
        _store(INSTALL_PATH, {
            "schema": SCHEMA, "state": "prepared",
            "plan_sha256": plan["sha256"], "boot_id": _boot(),
        }, exclusive=True)
        return {"state": "prepared", "plan_sha256": plan["sha256"], "durable": True}

    def mark_start_attempt(self, digest):
        record = _read_json(INSTALL_PATH)
        if (record.get("state") != "prepared" or record.get("plan_sha256") != digest
                or record.get("boot_id") != _boot()):
            raise RuntimeError("fresh sidecar attempted marker uncertain")
        record["state"] = "attempted"
        _store(INSTALL_PATH, record)
        return {"state": "attempted", "plan_sha256": digest, "durable": True}

    def start_transient(self, unit, mode, properties):
        _root()
        if _read_json(INSTALL_PATH).get("state") != "attempted":
            raise PermissionError("transient start requires durable attempted receipt")
        return dbus.start_exact_sidecar(unit, mode, properties)

    def observe_unit(self, unit):
        data = self.read_unit(unit)
        if data is None:
            raise RuntimeError("sidecar PID1 entry is absent after start")
        values = dict(item.split("=", 1) for item in data.get(
            "Environment", "").split() if "=" in item)
        expected = _read_json(PLAN_PATH)
        fd = os.stat(sidecar.SOCKET, follow_symlinks=False)
        if (not stat.S_ISSOCK(fd.st_mode) or fd.st_uid != 0
                or fd.st_gid != expected["identity"]["controller_gid"]
                or stat.S_IMODE(fd.st_mode) != 0o660):
            raise RuntimeError("unexpected fresh controller socket ownership")
        return {
            "unit": unit, "active": data.get("ActiveState") == "active",
            "invocation_id": data.get("InvocationID"),
            "project_root": values.get("ROOT_CONTROL_AUTHORIZED_PROJECT"),
            "socket": values.get("ROOT_CONTROL_SOCKET"),
            "role": values.get("ROOT_CONTROL_ROLE"),
        }

    def sample_exact(self, x):
        _root()
        result = quota.inspect()
        return {
            "host_id": x["host_id"], "project_root": x["project_root"],
            "boot_id": _boot(), "now_seconds": int(time.time()),
            "monotonic_seconds": int(time.monotonic()),
            "used_bytes": result["used_bytes"],
            "monitor_receipt_sha256": x["monitor_receipt_sha256"],
            "watchdog_active": _show(CRON_SERVICE).get("ActiveState") == "active"
                and verify_schedule(), 
            "sidecar_active": _show(sidecar.UNIT).get("ActiveState") == "active",
        }

    def cancel_exact_project(self, project, request, *, reason, cancellation_id):
        _root()
        x = budget.read(BUDGET_DIR, request)
        if (project != x["project_root"] or reason != x["stop_reason"]
                or cancellation_id != x["cancellation_id"]
                or x["status"] != "stop_attempted"):
            raise PermissionError("fresh cancellation grant differs from frozen attempt")
        if _events()["populated"] == "1":
            # Exact kernel cgroup.kill, never kill a shared controller or
            # caller-selected PID/unit. Native admission must first prove
            # ALL fresh build jobs are descendants of this exclusive slice.
            with (CGROUP / "cgroup.kill").open("w") as stream:
                stream.write("1\n")
                stream.flush()
        return self.inspect_cancel_exact_project(
            project, request, cancellation_id=cancellation_id)

    def inspect_cancel_exact_project(self, project, request, *, cancellation_id):
        x = budget.read(BUDGET_DIR, request)
        if (project != x["project_root"] or x["cancellation_id"] != cancellation_id
                or x["status"] not in ("stop_attempted", "stopped")):
            raise PermissionError("foreign cancellation observation")
        if _events()["populated"] != "0":
            return None
        return {"confirmed": True, "cancellation_id": cancellation_id,
                "request_id": request, "project_root": project,
                "evidence": "kernel-cgroup.events-populated-0"}


def verify_schedule():
    """Require exact root-owned cron file and running native scheduler."""
    st = CRON_PATH.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o644):
        raise PermissionError("fresh watchdog cron file untrusted")
    return CRON_PATH.read_text() == schedule_text()


def schedule_text():
    """Cron entry is fixed; includes one-minute checks and boot reconciliation.

    Scheduled code loads from the root-owned accepted Python installation,
    not via a caller-supplied PYTHONPATH or mutable working directory.
    """
    reviewed = _read_json(PLAN_PATH)
    binary = reviewed["identity"]["python_executable"]
    source = reviewed["installed"]["host_deploy_python_root"]
    # host_deploy_python_root is a separately reviewed installer addition.
    for path in (binary, source):
        if (not path.startswith("/") or ".." in Path(path).parts
                or "\n" in path or " " in path):
            raise PermissionError("unreviewed scheduler executable path")
    prefix = "PYTHONPATH=" + source + " " + binary + " -B -m zog.host_deploy.gateway.fresh_native_owner"
    return ("SHELL=/bin/sh\nPATH=/usr/sbin:/usr/bin:/bin\n"
            "* * * * * root " + prefix + " watch\n"
            "@reboot root " + prefix + " recover\n")


def install_schedule():
    """Actual persistent crond hook; requires crond ALREADY running.

    Does not daemon-reload, enable/restart crond, or install arbitrary jobs.
    Native acceptance must demonstrate crond honors this cron.d syntax.
    """
    _root()
    if _show(CRON_SERVICE).get("ActiveState") != "active":
        raise RuntimeError("native crond must already be active")
    if CRON_PATH.exists() or CRON_PATH.is_symlink():
        raise RuntimeError("watchdog schedule exists; no overwrite")
    data = schedule_text().encode()
    temp = CRON_PATH.parent / (".zog-fresh-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("short native schedule write")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, CRON_PATH)
    dfd = os.open(CRON_PATH.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    if not verify_schedule():
        raise RuntimeError("installed watchdog scheduler differs")


def watch():
    _root()
    owner = NativeOwner()
    if not verify_schedule():
        raise RuntimeError("host-owned watchdog schedule changed")
    if _show(CRON_SERVICE).get("ActiveState") != "active":
        raise RuntimeError("native scheduler not running")
    budget._protected_root(BUDGET_DIR)
    requests = sorted(p.stem for p in BUDGET_DIR.glob("*.json"))
    if len(requests) > 1:
        raise RuntimeError("only one newly approved cross-bootstrap request allowed")
    for request in requests:
        if not budget._HEX.fullmatch(request):
            raise RuntimeError("unreviewed budget filename")
        budget.watch_once(BUDGET_DIR, request, native_owner=owner)


def recover():
    """Actual @reboot recovery: restore quota and inspect, never replay jobs.

    A changed boot ID makes an in-flight compiler budget fail closed. The
    owner does NOT resubmit cross-bootstrap or blindly restore a transient
    controller after a power loss without a reviewed fresh-boot receipt.
    """
    _root()
    if not verify_schedule():
        raise RuntimeError("untrusted reboot hook")
    quota.reattach_after_boot()
    watch()


def main():
    # Fixed root-owned cron entrypoint; no user supplied Project/request or
    # executable. No remote dispatch, no generic root shell.
    if len(sys.argv) != 2 or sys.argv[1] not in ("watch", "recover"):
        raise SystemExit("use only fixed root-owned watch or recover entrypoint")
    if sys.argv[1] == "recover":
        recover()
    else:
        watch()


if __name__ == "__main__":
    main()
