"""Offline composer for a *candidate* fixed read-only two-Project inventory.

This script has no sender. A caller cannot run it on the compiler using this
module; any future SSM dispatch requires its own accepted protected root
owner, script-byte hash and immutable operation. The output is diagnostic,
NEVER an authenticated replacement-writer or build admission receipt.
"""
import hashlib
import re
import shlex

from . import fonts_lane_supersession_audit as audit
from . import fonts_lane_recovery as recovery
from . import existing_project_runtime

_OBSERVER = r"""
import hashlib, json, os, stat, subprocess
from pathlib import Path

SCHEMA = 'host-deploy-first-fonts-native-pair-inventory-v1'

def checked_dir(parent, name):
    if (not name or name in ('.','..') or '/' in name):
        raise ValueError('invalid reviewed Project component')
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(named.st_mode):
        raise ValueError('symlink or foreign Project ancestry')
    nextfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    opened = os.fstat(nextfd)
    if ((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid,
         opened.st_gid) != (named.st_dev, named.st_ino, named.st_mode,
                           named.st_uid, named.st_gid)):
        os.close(nextfd)
        raise ValueError('Project directory changed during inspection')
    sticky_root = (opened.st_uid == 0 and stat.S_IMODE(opened.st_mode) == 0o1777)
    if opened.st_mode & 0o022 and not sticky_root:
        os.close(nextfd)
        raise ValueError('writable Project ancestry')
    return nextfd

def open_root(path):
    if (not isinstance(path,str) or not path.startswith('/') or
            path == '/' or os.path.normpath(path) != path):
        raise ValueError('noncanonical selected Project root')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(path).parts[1:]:
            new = checked_dir(fd, part)
            os.close(fd)
            fd = new
        return fd, os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise

def read_file(root, name):
    # Only known file basenames (no traversal). A missing file is reported
    # independently from a foreign symlink, hardlink, pipe or unsafe mode.
    if not isinstance(name,str) or '/' in name or name in ('','.','..'):
        raise ValueError('foreign native evidence name')
    try:
        named = os.stat(name, dir_fd=root, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
            or named.st_mode & 0o022 or not 0 < named.st_size <= 1048576):
        raise ValueError('unsafe Project evidence')
    filefd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root)
    try:
        before = os.fstat(filefd)
        if ((named.st_dev, named.st_ino, named.st_mode, named.st_uid,
             named.st_gid, named.st_size) !=
            (before.st_dev, before.st_ino, before.st_mode,
             before.st_uid, before.st_gid, before.st_size)):
            raise ValueError('Project evidence inode changed')
        raw = os.read(filefd, 1048577)
        after = os.fstat(filefd)
        still = os.stat(name, dir_fd=root, follow_symlinks=False)
        if (len(raw) != before.st_size or
            (before.st_dev, before.st_ino, before.st_mtime_ns,
             before.st_ctime_ns, before.st_size) !=
            (after.st_dev, after.st_ino, after.st_mtime_ns,
             after.st_ctime_ns, after.st_size) or
            (still.st_dev, still.st_ino, still.st_mode, still.st_uid) !=
            (before.st_dev, before.st_ino, before.st_mode, before.st_uid)):
            raise ValueError('Project evidence changed during read')
        return raw
    finally:
        os.close(filefd)

def git_head(path, root):
    # Git -C rev-parse is read-only, with optional lock-taking prohibited;
    # reject redirecting source/.git before using the fixed invocation.
    source = checked_dir(root, 'source')
    try:
        git = checked_dir(source, '.git')
        os.close(git)
        command = ['git','-C',path+'/source','rev-parse','--verify','HEAD']
        environment = {
            'PATH':'/usr/bin:/bin', 'HOME':'/nonexistent',
            'GIT_OPTIONAL_LOCKS':'0', 'GIT_CONFIG_NOSYSTEM':'1',
            'GIT_CONFIG_GLOBAL':'/dev/null',
        }
        done = subprocess.run(command, capture_output=True, text=True,
                              env=environment, timeout=12, check=False)
        revision = done.stdout.strip()
        if done.returncode != 0 or not __import__('re').fullmatch(
                '[0-9a-f]{40,64}', revision):
            raise ValueError('selected Project Git HEAD cannot be verified')
        return revision
    finally:
        os.close(source)

def project(path, controller_name, manifest_name):
    root, opened = open_root(path)
    try:
        controller = read_file(root, controller_name)
        manifest = read_file(root, manifest_name) if manifest_name else None
        source = git_head(path, root)
        result = {
            'project_root':path,
            'device':opened.st_dev,
            'inode':opened.st_ino,
            'owner_uid':opened.st_uid,
            'owner_gid':opened.st_gid,
            'mode':stat.S_IMODE(opened.st_mode),
            'controller_filename':controller_name,
            'controller_present':controller is not None,
            'controller_sha256':(hashlib.sha256(controller).hexdigest()
                                 if controller is not None else None),
            'manifest_sha256':(hashlib.sha256(manifest).hexdigest()
                               if manifest is not None else None),
            'source_head':source,
        }
        # Recheck same inode through the full nofollow ancestry after
        # observation; even a diagnostic report must not silently move roots.
        again, end = open_root(path)
        try:
            if (end.st_dev, end.st_ino, end.st_uid, end.st_mode) != (
                    opened.st_dev,opened.st_ino,opened.st_uid,opened.st_mode):
                raise ValueError('selected Project changed during inventory')
        finally:
            os.close(again)
        return result
    finally:
        os.close(root)

a = project(ACTIVE, ACTIVE_CONTROLLER, None)
b = project(DESTINATION, 'controller-inherited-v1.json',
            '.first-fonts-initialization-v1.json')
print(json.dumps({
    'schema':SCHEMA, 'status':'diagnostic-only',
    'workspace_id':WORKSPACE_ID,
    'compiler_instance_id':COMPILER_INSTANCE,
    'active':a, 'initialized_destination':b,
    'expected_active_controller_sha256':EXPECTED_ACTIVE_CONTROLLER,
    'expected_original_manifest_sha256':EXPECTED_MANIFEST,
    'mutation':False,'ssm_send_authorized':False,
    'execution_authorized':False,'compilation_authorized':False,
},sort_keys=True))
"""


def native_read_only_script(registry_report):
    """Return candidate command bytes only; NOT permission to send or trust it."""
    if (type(registry_report) is not dict or
            registry_report.get("schema") != audit.SCHEMA or
            registry_report.get("status") != "supersession-unproven" or
            registry_report.get("selected_project_root") != audit.CURRENT or
            registry_report.get("prior_initialization_project_root") != audit.DESTINATION or
            registry_report.get("compiler_target", {}).get("instance_id") !=
                recovery.COMPILER_INSTANCE or
            registry_report.get("execution_authorized") is not False or
            registry_report.get("ssm_send_authorized") is not False or
            not re.fullmatch("[0-9a-f]{64}",
                             str(registry_report.get("selected_expected_controller_sha256"))) or
            not re.fullmatch("[0-9a-f]{64}",
                             str(registry_report.get("prior_initialization_manifest_sha256")))):
        raise ValueError("candidate native inventory requires authentic local audit selection")
    # The report is still caller-side input. A later protected root owner
    # MUST repeat exact local selection + script SHA under authenticated
    # native dispatch. No sender exists here.
    setup = (
        "ACTIVE=" + repr(audit.CURRENT) + "\n"
        "DESTINATION=" + repr(audit.DESTINATION) + "\n"
        "ACTIVE_CONTROLLER=" + repr(
            registry_report["selected_controller_path"].removeprefix(
                audit.CURRENT + "/")) + "\n"
        "EXPECTED_ACTIVE_CONTROLLER=" + repr(
            registry_report["selected_expected_controller_sha256"]) + "\n"
        "EXPECTED_MANIFEST=" + repr(
            registry_report["prior_initialization_manifest_sha256"]) + "\n"
        "COMPILER_INSTANCE=" + repr(recovery.COMPILER_INSTANCE) + "\n"
        "WORKSPACE_ID=" + repr(registry_report["workspace_id"]) + "\n"
    )
    if (registry_report["selected_controller_path"] !=
            audit.CURRENT + "/controller-" + audit.LANE + "-inherited-v1.json" or
            not re.fullmatch("[0-9a-f]{32}", registry_report["workspace_id"])):
        raise ValueError("candidate native controller or workspace differs")
    return "python3 -I -B -c " + shlex.quote(setup + _OBSERVER)


def candidate_script_sha256(registry_report):
    return hashlib.sha256(native_read_only_script(
        registry_report).encode("utf-8")).hexdigest()
