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
import re
import stat
import subprocess
import sys
import time
import uuid

from . import fresh_budget_guard as budget
from . import fresh_quota_volume as quota
from . import fresh_sidecar_dbus as dbus
from . import fresh_sidecar_install as sidecar
from . import fresh_watchdog_service as independent_watchdog
from . import fresh_deadline_timer as hard_deadline
from . import fresh_aggregate_disk as aggregate
from . import fresh_journal_backing as journal_backing
from . import fresh_project_state as project_state
from . import fresh_host_write_audit as host_write_audit

STATE = Path(aggregate.EXTERNAL_MOUNT) / "owner-state"
PLAN_PATH = STATE / "reviewed-plan.json"
INSTALL_PATH = STATE / "sidecar-install.json"
BASELINE_PATH = STATE / "legacy-baseline.json"
BUDGET_DIR = STATE / "budget"
CRON_PATH = Path("/etc/cron.d/zog-fresh-cross-bootstrap-oct25")
WATCHDOG_ATTEMPT = STATE / "independent-watchdog-attempt.json"
DEADLINE_ATTEMPT = STATE / "hard-deadline-attempt.json"
CGROUP = Path("/sys/fs/cgroup/zogfreshcrossbootstrapoct25.slice")
SLICE_UNIT = sidecar.SLICE_UNIT
CRON_SERVICE = "crond.service"
CRON_LOG = aggregate.EXTERNAL_MOUNT + "/controller-logs/cron.log"
SCHEMA = "host-deploy-native-sidecar-owner-v1"
HISTORICAL_REQUEST_ID = "371da99f23764180aad37d8e4e83595b"


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
    known = {sidecar.UNIT, independent_watchdog.UNIT,
             hard_deadline.UNIT, SLICE_UNIT, CRON_SERVICE,
             journal_backing.JOURNAL_SERVICE, *journal_backing.JOURNAL_SOCKETS,
             "root-control.service", "zog-root-control.service",
             "zog-certbot-seed-root.service"}
    if unit not in known:
        # The historical unit identity comes only from an exact protected
        # root-only baseline, never from a GitHub/SSM request.
        historic = _read_json(BASELINE_PATH)
        if (unit != historic.get("historical_unit")
                or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}\.service", unit)):
            raise ValueError("unapproved systemd readback target")
    raw = _command(["/usr/bin/systemctl", "show", unit,
                    "--property=LoadState,ActiveState,MainPID,InvocationID,"
                    "ControlGroup,Environment,FragmentPath,Unit,NextElapseUSecMonotonic,LogNamespace"])
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
                    or (stat.S_ISREG(st.st_mode) and st.st_nlink != 1)):
                raise PermissionError("unsafe source/companion tree entry")
            digest.update(str(entry.relative_to(path)).encode() + b"\0")
            if stat.S_ISREG(st.st_mode):
                digest.update(entry.read_bytes())
    return "sha256:" + digest.hexdigest()


def _legacy():
    """Compare live shared PID1 and the frozen original bad-setting unit."""
    historic = _read_json(BASELINE_PATH)
    if (type(historic) is not dict or set(historic) != {
            "shared_unit", "root_control_show", "historical_unit",
            "historical_show", "historical_bad_setting_sha256"}
            or historic["shared_unit"] not in (
                "root-control.service", "zog-root-control.service",
                "zog-certbot-seed-root.service")
            or not isinstance(historic["historical_show"], dict)
            or historic["historical_show"].get("LoadState") != "bad-setting"
            or _sha(_bytes(historic["historical_show"])) !=
                historic["historical_bad_setting_sha256"]):
        raise RuntimeError("historical bad-setting baseline is incomplete")
    if _show(historic["shared_unit"]) != historic["root_control_show"]:
        raise RuntimeError("shared controller PID/InvocationID/fragment changed")
    if _show(historic["historical_unit"]) != historic["historical_show"]:
        raise RuntimeError("historical bad-setting PID1 evidence changed")
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
        if _protected_tree(installed["host_deploy_python_root"]) != installed[
                "host_deploy_tree_sha256"]:
            raise PermissionError("installed host-deploy native owner source changed")
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
        pid = data.get("MainPID", "")
        if (not pid.isdecimal() or int(pid) < 2
                or data.get("LogNamespace") != sidecar.LOG_NAMESPACE):
            raise RuntimeError("fresh controller PID/log namespace not attested")
        registration_source = Path(sidecar.REGISTRATION_SOURCE)
        registration_visible = Path("/proc") / pid / "root" / sidecar.REGISTRATION_DEST.lstrip("/")
        # Actual controller PID's mount namespace must see the NEW bounded
        # registration inode, never the shared historical host directory.
        original = registration_source.lstat()
        seen = registration_visible.stat()
        if (not stat.S_ISDIR(original.st_mode)
                or not stat.S_ISDIR(seen.st_mode)
                or original.st_dev != seen.st_dev
                or original.st_ino != seen.st_ino):
            raise RuntimeError("root-control imported build root escaped 30GiB pool")
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
        project_state.inspect(_read_json(PLAN_PATH)["identity"]["controller_uid"])
        external = aggregate.inspect_external_native()
        aggregate.validate(
            result, external, host_owner_verified=self.is_trusted_native_owner())
        return {
            "host_id": x["host_id"], "project_root": x["project_root"],
            "boot_id": _boot(), "now_seconds": int(time.time()),
            "monotonic_seconds": int(time.monotonic()),
            "used_bytes": result["used_bytes"],
            "monitor_receipt_sha256": x["monitor_receipt_sha256"],
            # Cron failure must reach budget.watch_once via independent PID1
            # watchdog, not preemptively escape the cancellation path.
            "watchdog_active": (_show(CRON_SERVICE).get("ActiveState") == "active"
                and verify_schedule()
                and _show(independent_watchdog.UNIT).get("ActiveState") == "active"
                and _show(independent_watchdog.UNIT).get("MainPID") not in (
                    None, "", "0")),
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
            "* * * * * root " + prefix + " watch >>" + CRON_LOG + " 2>&1\n"
            "@reboot root " + prefix + " recover >>" + CRON_LOG + " 2>&1\n")


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
    # NEVER return early on crond/schedule loss: the separate PID1 watchdog
    # must observe that failure in sample_exact and durably cancel the fresh
    # compiler. A missing schedule is not a reason to omit the budget check.
    budget._protected_root(BUDGET_DIR)
    requests = sorted(p.stem for p in BUDGET_DIR.glob("*.json"))
    if len(requests) > 1:
        raise RuntimeError("only one newly approved cross-bootstrap request allowed")
    for request in requests:
        if not budget._HEX.fullmatch(request):
            raise RuntimeError("unreviewed budget filename")
        budget.watch_once(BUDGET_DIR, request, native_owner=owner)


def watch_loop():
    """Independent PID1-supervised fast watchdog, not scheduled by crond.

    Systemd Restart=always makes it an independent enforcement path for
    crond outages. On errors, let PID1 restart rather than silently exiting.
    Native acceptance must test actual PID1 restart and missed deadline.
    """
    _root()
    while True:
        watch()
        time.sleep(independent_watchdog.INTERVAL_SECONDS)


def hard_stop():
    """Fixed PID1 deadline: never rely solely on writable quota metadata.

    Stage A must prove the timer executes within its 30-second safety margin.
    The frozen timer intent is fsynced before the timer starts and binds the
    same original request/project/cgroup. If the journal is full at expiry,
    directly issue the kernel's exact fresh-parent kill without another
    arbitrary host operation; normal ledger reconciliation remains uncertain.
    """
    _root()
    plan = _read_json(PLAN_PATH)
    a = _admission(plan)
    marker = _read_json(DEADLINE_ATTEMPT)
    expected = budget._digest({
        "schema": budget.SCHEMA, "request_id": a["request_id"],
        "host_id": a["host_id"], "project_root": plan["project_root"],
    })
    if (type(marker) is not dict
            or set(marker) != {
                "schema", "plan_sha256", "request_id", "host_id",
                "project_root", "cancellation_id", "boot_id", "state"}
            or marker["schema"] != "host-deploy-fresh-hard-deadline-attempt-v1"
            or marker["plan_sha256"] != plan["sha256"]
            or marker["request_id"] != a["request_id"]
            or marker["host_id"] != a["host_id"]
            or marker["project_root"] != plan["project_root"]
            or marker["cancellation_id"] != expected
            or marker["boot_id"] != _boot()
            or marker["state"] != "attempted"):
        raise RuntimeError("PID1 hard deadline authority changed")

    class KernelDeadlineOwner(NativeOwner):
        def sample_exact(self, x):
            result = super().sample_exact(x)
            result["now_seconds"] = max(
                result["now_seconds"], x["deadline_seconds"])
            result["monotonic_seconds"] = max(
                result["monotonic_seconds"],
                x["started_monotonic_seconds"] + budget.DEADLINE_SECONDS)
            return result

    try:
        record = budget.read(BUDGET_DIR, a["request_id"])
        if (record["cancellation_id"] != expected
                or record["boot_id"] != marker["boot_id"]):
            raise RuntimeError("deadline budget identity changed")
        budget.watch_once(BUDGET_DIR, record["request_id"],
                          native_owner=KernelDeadlineOwner())
    except OSError:
        # Disk-full/failed-fsync exception only. The already-durable timer
        # intent is enough to enforce the fixed parent cgroup boundary;
        # do not invent a successful cancellation receipt.
        if _events()["populated"] == "1":
            with (CGROUP / "cgroup.kill").open("w") as stream:
                stream.write("1\n")
                stream.flush()
        raise RuntimeError(
            "kernel deadline stop issued/uncertain; ledger requires native "
            "reconciliation; no new submission permitted")



def recover():
    """Actual @reboot recovery: restore quota and inspect, never replay jobs.

    A changed boot ID makes an in-flight compiler budget fail closed. The
    owner does NOT resubmit cross-bootstrap or blindly restore a transient
    controller after a power loss without a reviewed fresh-boot receipt.
    """
    if os.geteuid() != 0:
        raise PermissionError("reboot recovery requires protected native root")
    # Reattach the small accounting pool first: all owner state and the
    # original budget journal live there, never on unbounded host storage.
    aggregate.reattach_external_after_boot()
    _root()
    if not verify_schedule():
        raise RuntimeError("untrusted reboot hook")
    volume = quota.reattach_after_boot()
    # Mounts installed on the previous boot are not persistent. Do not
    # silently restore a host-wide Project bind: a new boot needs a separate
    # reviewed native binding. Until then, the existing request must fail
    # closed and watchdog inspection cannot resume work.
    try:
        project_state.inspect(_read_json(PLAN_PATH)["identity"]["controller_uid"])
        state_status = "verified"
    except (OSError, RuntimeError, PermissionError, KeyError, ValueError):
        state_status = "project-state-bind-unverified-no-replay"
    # Every boot is independently identified; we do not trust a transient
    # pre-reboot PID1 InvocationID or assume running compiler services survived.
    # No auto-submit, cleanup, old-controller reset or silent new sidecar start.
    journal = STATE / ("reboot-" + _boot() + ".json")
    if not journal.exists():
        _store(journal, {
            "schema": "host-deploy-fresh-boot-recovery-v1",
            "boot_id": _boot(),
            "quota_image": str(quota.IMAGE),
            "quota_capacity_bytes": volume["capacity_bytes"],
            "status": "observed-reboot-needs-fresh-controller-attestation",
            "project_state": state_status,
        }, exclusive=True)
    else:
        recorded = _read_json(journal)
        if (recorded.get("boot_id") != _boot()
                or recorded.get("quota_image") != str(quota.IMAGE)):
            raise RuntimeError("reboot checkpoint drift")
    # The native watchdog transitions any in-flight original new request to
    # uncertain/stop_requested due to changed boot-id. Its original immutable
    # cancellation ID is inspected only; no replacement compiler submission.
    watch()



ADMISSION_PATH = STATE / "reviewed-admission.json"



def _budget_directory_prepared(*, require_empty):
    """Read-only receipt for the already precreated budget directory.

    prepare-external creates owner-state/budget exactly once INSIDE the
    bounded 2-GiB pool. prepare-work and install must consume this existing
    directory, never mkdir it again or silently repair interrupted state.
    An unexpected record, lock, foreign inode or a missing directory is an
    explicit NO-GO before a build volume or new PID1 unit can be started.
    """
    if BUDGET_DIR != STATE / "budget":
        raise PermissionError("fresh budget path differs from reviewed owner-state")
    root = budget._protected_root(BUDGET_DIR)
    parent = budget._protected_root(STATE)
    observed = root.lstat()
    if (not stat.S_ISDIR(observed.st_mode) or root.is_symlink()
            or observed.st_uid != 0 or observed.st_gid != 0
            or stat.S_IMODE(observed.st_mode) != 0o700
            or observed.st_dev != parent.stat().st_dev):
        raise PermissionError("preexisting budget directory is not the bounded owner directory")
    from .fresh_aggregate_disk import EXTERNAL_MOUNT
    # Same-device comparison can succeed on the underlying host directory
    # when the external image has NOT been mounted. Refuse that fallback.
    if not os.path.ismount(EXTERNAL_MOUNT):
        raise RuntimeError("budget backing external accounting filesystem absent")
    if parent.stat().st_dev != Path(EXTERNAL_MOUNT).stat().st_dev:
        raise PermissionError("budget directory is not backed by 2-GiB external pool")
    if require_empty and any(root.iterdir()):
        raise RuntimeError("budget directory contains an existing/uncertain request; no replay")
    return root


def _admission(plan):
    """Admission receipt is a root-owned, exact-structure authorization.

    It is intentionally not created by the gateway or GitHub dispatcher.
    The native protected installer must provide it only after independent
    seed/source/host/capacity and no-old-job-mutation review.
    """
    a = _read_json(ADMISSION_PATH)
    if (type(a) is not dict or set(a) != {
            "schema", "plan_sha256", "host_id", "request_id",
            "seed_generation", "seed_manifest_sha256",
            "capabilities_sha256", "available_after_reservations_bytes",
            "writable_roots", "fresh_slice", "budget_scope"}):
        raise RuntimeError("fresh admission receipt incomplete")
    if (a["schema"] != "host-deploy-fresh-native-admission-dedicated-v2"
            or a["budget_scope"] != aggregate.BUDGET_SCOPE
            or a["plan_sha256"] != plan["sha256"]
            or a["host_id"] != plan["host_id"]
            or a["fresh_slice"] != SLICE_UNIT
            or a["writable_roots"] != [str(quota.MOUNT)]
            or type(a["available_after_reservations_bytes"]) is not int
            or a["available_after_reservations_bytes"] < budget.ADDITIONAL_DISK_BYTES
            or not budget._HEX.fullmatch(a["request_id"])
            or a["request_id"] == HISTORICAL_REQUEST_ID
            or not all(isinstance(a[field], str) and (
                a[field].startswith("sha256:") and len(a[field]) == 71)
                for field in ("seed_manifest_sha256", "capabilities_sha256"))
            or not isinstance(a["seed_generation"], str)
            or not a["seed_generation"]):
        raise RuntimeError("fresh native admission differs from reviewed authority")
    return a


def prepare_work():
    """Once-only Stage A storage: quota and Project/state BEFORE seed import.

    This consumes a protected independently reviewed admission identity, but
    cannot install a controller, arm a budget, or submit a compiler job. The
    exact immutable seed must be imported only AFTER this bind is proven.
    """
    _root()
    plan = _read_json(PLAN_PATH)
    if sidecar.review_plan(plan["identity"], plan["installed"]) != plan:
        raise RuntimeError("reviewed native storage binding changed")
    a = _admission(plan)
    owner = NativeOwner()
    owner.verify_source_and_nss(plan)
    owner.validate_old_baseline(plan["installed"]["legacy_baseline_sha256"])
    aggregate.inspect_external_pool_native()
    # Catch the exact pre-created budget-directory conflict BEFORE the first
    # 30-GiB allocation. Do not create it here: provision_external already did.
    _budget_directory_prepared(require_empty=True)
    # The original host capacity authorization includes BOTH pools. The
    # external 2-GiB image has already been fully allocated, so enforce the
    # remaining 30-GiB budget against the current host backing filesystem.
    available = a["available_after_reservations_bytes"] - aggregate.EXTERNAL_BYTES
    if available < aggregate.BUILD_BYTES:
        raise RuntimeError("approved host capacity cannot cover both pools")
    volume = quota.provision(
        available_after_reservations_bytes=available,
        mounted_writable_roots=a["writable_roots"])
    state = project_state.install_bind(plan["identity"]["controller_uid"])
    owner.validate_old_baseline(plan["installed"]["legacy_baseline_sha256"])
    return {"schema": SCHEMA, "phase": "storage-prepared-only",
            "work_capacity_bytes": volume["capacity_bytes"],
            "project_state": state, "compiler_authorized": False}


def install_approved():
    """Real once-only privileged installation using fixed local receipts.

    Destructive creation is restricted to the previously empty new quota
    image and new transient sidecar. Nothing changes the original controller.
    """
    _root()
    plan = _read_json(PLAN_PATH)
    if sidecar.review_plan(plan["identity"], plan["installed"]) != plan:
        raise RuntimeError("reviewed native sidecar plan changed")
    a = _admission(plan)
    owner = NativeOwner()
    owner.verify_source_and_nss(plan)
    owner.validate_old_baseline(plan["installed"]["legacy_baseline_sha256"])
    if _sha(schedule_text().encode()) != plan["installed"]["watchdog_receipt_sha256"]:
        raise RuntimeError("unreviewed watchdog schedule source")
    # Consume the exact prepared 0700 root-owned directory; do not mkdir,
    # reset, delete, or replace even after an interrupted preparation.
    _budget_directory_prepared(require_empty=True)
    directory_fd = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    # This is inspection-only. Build quota + exact Project/state bind MUST
    # already be in place before the separately verified immutable seed import.
    # Never create the quota here or the earlier import may escape to host disk.
    volume = quota.inspect()
    if volume["capacity_bytes"] > aggregate.BUILD_BYTES:
        raise RuntimeError("fresh kernel quota limit exceeded")
    project_state.inspect(plan["identity"]["controller_uid"])
    external = aggregate.inspect_external_native()
    # Observe only the protected sidecar; it must start before Work can attest
    # its live registration mount. This pre-activation path is not an aggregate
    # admission, and never clears the mandatory strict arm/watch gates.
    aggregate.validate_pre_activation(
        volume, external, host_owner_verified=owner.is_trusted_native_owner())
    # Verify ALL fixed backing before installing /etc/cron.d or starting
    # native PID1 units. No ordinary shared-host side effects on failed
    # preactivation storage proof.
    install_schedule()
    # Start a distinct PID1-supervised watchdog outside the compiler slice,
    # not through cron. A PID1 reply lost after this durable marker is an
    # UNCERTAIN installation, never permission for a second start.
    if _show(independent_watchdog.UNIT).get("LoadState") != "not-found":
        raise RuntimeError("independent watchdog already present")
    if WATCHDOG_ATTEMPT.exists() or WATCHDOG_ATTEMPT.is_symlink():
        raise RuntimeError("watchdog attempted-start already recorded")
    _store(WATCHDOG_ATTEMPT, {
        "schema": "host-deploy-fresh-watchdog-start-attempt-v1",
        "plan_sha256": plan["sha256"], "boot_id": _boot(),
        "state": "attempted",
    }, exclusive=True)
    independent_watchdog.start(plan)
    active_watchdog = _show(independent_watchdog.UNIT)
    if (active_watchdog.get("ActiveState") != "active"
            or active_watchdog.get("MainPID") in (None, "", "0")
            or active_watchdog.get("ControlGroup", "").startswith(
                "/" + sidecar.SLICE_UNIT)):
        raise RuntimeError("independent PID1 watchdog activation unproven")
    # The top of the quota image is ROOT-owned and not writable by either
    # isolated nonroot UID. Otherwise the build UID could rename the protected
    # imported rootfs/registration directory despite that child being root
    # owned. root-control grants write access only to specific copied source
    # and output workspaces inside the bounded Project/state mount.
    os.chown(quota.MOUNT, 0, 0)
    os.chmod(quota.MOUNT, 0o755)
    receipt = sidecar.install(plan, host_owner=owner)
    _store(STATE / "activation.json", receipt, exclusive=True)
    owner.validate_old_baseline(plan["installed"]["legacy_baseline_sha256"])
    return receipt


def arm_approved():
    """Durably arm one admitted new request AFTER kernel + cgroup acceptance."""
    _root()
    plan = _read_json(PLAN_PATH)
    a = _admission(plan)
    owner = NativeOwner()
    owner.validate_old_baseline(plan["installed"]["legacy_baseline_sha256"])
    if _read_json(STATE / "activation.json")["plan_sha256"] != plan["sha256"]:
        raise RuntimeError("sidecar activation not authenticated")
    if (not verify_schedule()
            or _show(CRON_SERVICE).get("ActiveState") != "active"
            or _show(independent_watchdog.UNIT).get("ActiveState") != "active"
            or _show(independent_watchdog.UNIT).get("MainPID") in (None, "", "0")
            or _read_json(WATCHDOG_ATTEMPT).get("plan_sha256") != plan["sha256"]):
        raise RuntimeError("independent PID1 and reboot-persistent watchdog missing")
    _budget_directory_prepared(require_empty=True)
    if owner.observe_unit(sidecar.UNIT)["active"] is not True:
        raise RuntimeError("sidecar not active")
    _slice_identity()
    current = quota.inspect()
    project_state.inspect(plan["identity"]["controller_uid"])
    if current["capacity_bytes"] > aggregate.BUILD_BYTES:
        raise RuntimeError("kernel disk quota not active")
    # Every root-owned journal, metadata artifact and new process log must
    # have independently verified kernel backing in the OTHER bounded pool.
    external = aggregate.inspect_external_native()
    aggregate.validate(
        current, external, host_owner_verified=owner.is_trusted_native_owner())
    # Install an independent PID1-monotonic overall deadline BEFORE
    # recording the new budget start. Its deadline is strictly earlier
    # than the allowed 21,600-second span even if both watchdogs die.
    if DEADLINE_ATTEMPT.exists() or DEADLINE_ATTEMPT.is_symlink():
        raise RuntimeError("hard deadline has already been attempted")
    if _show(hard_deadline.UNIT).get("LoadState") != "not-found":
        raise RuntimeError("hard deadline transient timer already exists")
    # Root-owned, fsynced timer intent must carry the exact same
    # cancellation identity even if the accounting filesystem fills before
    # the independent kernel timer fires.
    cancellation_id = budget._digest({
        "schema": budget.SCHEMA, "request_id": a["request_id"],
        "host_id": a["host_id"], "project_root": plan["project_root"],
    })
    _store(DEADLINE_ATTEMPT, {
        "schema": "host-deploy-fresh-hard-deadline-attempt-v1",
        "plan_sha256": plan["sha256"], "request_id": a["request_id"],
        "host_id": a["host_id"], "project_root": plan["project_root"],
        "cancellation_id": cancellation_id,
        "boot_id": _boot(), "state": "attempted",
    }, exclusive=True)
    hard_deadline.start(plan)
    timer = _show(hard_deadline.UNIT)
    if (timer.get("LoadState") != "loaded"
            or timer.get("ActiveState") != "active"
            or timer.get("Unit") != hard_deadline.STOP_UNIT
            or not timer.get("NextElapseUSecMonotonic", "").isdigit()
            or int(timer["NextElapseUSecMonotonic"]) <= int(time.monotonic()*1e6)):
        raise RuntimeError("independent kernel-backed deadline timer unverified")
    x = budget.begin(
        request_id=a["request_id"], host_id=a["host_id"],
        project_root=plan["project_root"], boot_id=_boot(),
        now_seconds=int(time.time()), monotonic_seconds=int(time.monotonic()),
        used_bytes=current["used_bytes"], sidecar_plan_sha256=plan["sha256"],
        monitor_receipt_sha256=plan["installed"]["watchdog_receipt_sha256"])
    budget.write_once(BUDGET_DIR, x)
    return {"request_id": x["request_id"], "status": x["status"],
            "budget_scope": aggregate.BUDGET_SCOPE,
            "deadline_seconds": x["deadline_seconds"],
            "dedicated_build_capacity_bytes": current["capacity_bytes"],
            "dedicated_total_reserved_bytes": aggregate.TOTAL_BYTES}


def prepare_journal():
    """One-shot exact journal bind backing before any fresh PID1 activation."""
    _root()
    return journal_backing.install_binds_before_activation()


def prepare_external():
    """Privileged once-only 2-GiB accounting pool BEFORE operator stages plan.

    Does not allocate the compiler volume, start services, mutate shared
    controller, or authorize compilation.
    """
    if os.geteuid() != 0:
        raise PermissionError("protected native owner required")
    available = os.statvfs(aggregate.EXTERNAL_MOUNT.rsplit("/", 1)[0])
    remaining = available.f_bavail * available.f_frsize
    return aggregate.provision_external(
        available_after_reservations_bytes=remaining)


def inspect_host_write_surfaces():
    """One fixed, read-only native diagnostic, safe BEFORE any pool allocation.

    This diagnostic cannot prepare storage, arm a compiler, or mutate PID1.
    Unlike the protected owner mutations, it must not require mounted
    owner-state: Work needs evidence before choosing the disk topology.
    """
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise PermissionError("native root with PID1 systemd required")
    return host_write_audit.inspect()


def main():
    # Fixed root-owned cron entrypoint; no user supplied Project/request or
    # executable. No remote dispatch, no generic root shell.
    if len(sys.argv) != 2 or sys.argv[1] not in ("prepare-external", "prepare-work", "prepare-journal", "install", "arm", "watch", "watch-loop", "hard-stop", "recover", "inspect-host-write-surfaces"):
        raise SystemExit("use only fixed root-owned watch or recover entrypoint")
    if sys.argv[1] == "inspect-host-write-surfaces":
        sys.stdout.write(_bytes(inspect_host_write_surfaces()).decode("ascii"))
    elif sys.argv[1] == "prepare-external":
        prepare_external()
    elif sys.argv[1] == "prepare-work":
        prepare_work()
    elif sys.argv[1] == "prepare-journal":
        prepare_journal()
    elif sys.argv[1] == "recover":
        recover()
    elif sys.argv[1] == "install":
        install_approved()
    elif sys.argv[1] == "arm":
        arm_approved()
    elif sys.argv[1] == "watch-loop":
        watch_loop()
    elif sys.argv[1] == "hard-stop":
        hard_stop()
    else:
        watch()


if __name__ == "__main__":
    main()
