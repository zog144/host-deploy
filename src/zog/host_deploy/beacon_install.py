"""Root-only remote staging helper. No host secrets leave this process."""
import argparse
import contextlib
import hashlib
import re
import tomllib
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

BASE = Path('/opt/host-discover')
CONFIG = Path('/etc/host-discover/configuration.json')
UNIT = Path('/etc/systemd/system/host-discover.service')
IDENTITY = '/var/lib/host-discover/identity'
CREDENTIALS = '/var/lib/host-discover/credentials'

def run(args, **kw):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw).stdout.strip()

def safe_path(path):
    for p in [*reversed(path.parents),path]:
        if p.is_symlink(): raise ValueError('Symlink installation path')
        if p.exists():
            s=p.stat()
            if s.st_uid != 0 or s.st_mode & 0o022: raise ValueError('Unsafe installation ownership/mode')

def _set_atomic_owner(fd, uid, gid):
    """Privileged production ownership step; source mocks override ONLY this."""
    os.fchown(fd, uid, gid)


def atomic(path, data, mode=0o640, gid=0):
    safe_path(path.parent)
    if path.is_symlink(): raise ValueError('Symlink destination')
    fd,name=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode);_set_atomic_owner(f.fileno(),0,gid)
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(name):os.unlink(name)

def candidate(old, request):
    from urllib.parse import urlsplit
    settings=request.get('settings',{})
    if not isinstance(settings, dict):raise ValueError('Installer configuration must be a JSON object')
    if {'token','password','private_key'} & set(settings):raise ValueError('Do not supply secrets in installer configuration')
    cloud=request['cloud']
    if old and (old.get('provider')!='aws' or old.get('cloud')!=cloud):raise ValueError('Installed cloud identity mismatch')
    if old.get('token') and not request['migrate']:raise ValueError('Bearer installation requires --migrate')
    if request.get('expected_host_id') and old.get('host_id') and old['host_id']!=request['expected_host_id']:raise ValueError('Registry UUID differs from receipt')
    for k in ('host_id','identity_directory','credential_directory','station_login_file','mirror_box_control'):
        if k in old and k in settings and old[k]!=settings[k]:raise ValueError('Cannot replace existing identity or runtime ownership settings')
    value=old | settings
    value.pop('token',None)
    if value.get('cloud',cloud)!=cloud:raise ValueError('Configured cloud identity mismatch')
    if value.get('provider','aws')!='aws':raise ValueError('AWS provider required')
    server=request.get('server') if request.get('server') is not None else value.get('server')
    if not isinstance(server,str) or not server or any(c.isspace() for c in server):
        raise ValueError('An explicit HTTPS server is required for a fresh installation')
    o=urlsplit(server)
    try: o.port
    except ValueError: raise ValueError('HTTPS origin required') from None
    if o.scheme!='https' or not o.hostname or o.username or o.password or o.path not in ('','/') or o.query or o.fragment:raise ValueError('HTTPS origin required')
    if old.get('server') and old['server'].rstrip('/')!=server.rstrip('/') and not request['migrate']:raise ValueError('Server change requires --migrate')
    value.update(server=server.rstrip('/'),provider='aws',cloud=cloud)
    # The selected state locations may be ordinary directories, including
    # /state/host-discover/identity when /state is not a separate mount.
    # Keep an installed identity at its original location across reinstalls.
    for name,default in (('identity_directory',IDENTITY),('credential_directory',CREDENTIALS)):
        if old and name in settings and settings[name]!=old.get(name,default):
            raise ValueError('Cannot replace existing identity or runtime ownership settings')
        path=value.setdefault(name,default)
        if (type(path) is not str or not path.startswith('/') or path=='/'
                or str(Path(path))!=path or '..' in Path(path).parts):
            raise ValueError('State directory must be an absolute normalized path')
    identity=Path(value['identity_directory']);credentials=Path(value['credential_directory'])
    if (identity==credentials or identity in credentials.parents
            or credentials in identity.parents):
        raise ValueError('Identity and credential directories must be separate')
    if value.get('host_id'):uuid.UUID(value['host_id'])
    if request['system_ca']:value.pop('ca_file',None)
    if request.get('ca_path'):value['ca_file']=request['ca_path']
    return value

def _prepare_state_parent(parent):
    """Create only missing root-owned ancestors, traversable despite umask."""
    safe_path(parent)
    missing=[]
    current=parent
    while not current.exists():
        missing.append(current)
        current=current.parent
    for path in reversed(missing):
        path.mkdir(mode=0o755)
        path.chmod(0o755)
        safe_path(path)
    safe_path(parent)


def role_directory(value):
    """Fresh /state identities store controller intent in a sibling tree.

    This is an installer-selected local path, not a caller-supplied escape
    hatch. Unmigrated identities retain their historical runtime selection.
    """
    identity = Path(value["identity_directory"])
    if (identity.is_relative_to("/state")
            and value.get("identity_mode", "legacy-bootstrap") == "legacy-bootstrap"):
        return str(identity.parent / "roles")
    return None


def state_directories(value):
    try:u=pwd.getpwnam('host-discover')
    except KeyError:
        run(['useradd','--system','--no-create-home','--shell','/sbin/nologin','host-discover']);u=pwd.getpwnam('host-discover')
    try:g=grp.getgrnam('archive-consumers')
    except KeyError:
        run(['groupadd','--system','archive-consumers']);g=grp.getgrnam('archive-consumers')
    roles = role_directory(value)
    if roles:
        directory = Path(roles)
        credentials = Path(value["credential_directory"])
        identity = Path(value["identity_directory"])
        if (directory == credentials or directory in credentials.parents
                or credentials in directory.parents or directory == identity):
            raise ValueError("Role and credential state directories must not overlap")
    selected = [(value['identity_directory'],0o700,u.pw_gid),
                (value['credential_directory'],0o750,g.gr_gid)]
    if roles:
        selected.append((roles, 0o700, u.pw_gid))
    for name,mode,gid in selected:
        p=Path(name)
        # Only root-owned, non-writable, nonsymlink ancestors may be created.
        # Create the identity directory before the host-discover fingerprint
        # invocation: fresh legacy-bootstrap must not provision its own parent.
        _prepare_state_parent(p.parent)
        if p.is_symlink():raise ValueError('Symlink state directory')
        if not p.exists():
            p.mkdir(mode=mode)
            os.chown(p,u.pw_uid,gid)
            p.chmod(mode)  # mkdir is masked by the installer's umask
        st=p.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=u.pw_uid
                or st.st_gid!=gid or stat.S_IMODE(st.st_mode)!=mode):
            raise ValueError('Unsafe existing state directory')
        for f in p.iterdir():
            st=f.lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1
                    or st.st_uid!=u.pw_uid
                    or stat.S_IMODE(st.st_mode)!=(0o600 if name==value['identity_directory'] else 0o640)):
                raise ValueError('Unsafe existing state file')
    safe_path(CONFIG.parent)
    new_config_parent=not CONFIG.parent.exists()
    CONFIG.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
    os.chown(CONFIG.parent,0,u.pw_gid)
    if new_config_parent:CONFIG.parent.chmod(0o750)
    safe_path(CONFIG.parent)
    return u

# Runs as service user, outputs only public/sanitized observations.
PROBE = '''import json,sys,time
from pathlib import Path
from zog.host_discover.daemon import validate_configuration,collect,announce,identity_key
from zog.host_identify import storage,signatures
c=validate_configuration(json.loads(Path(sys.argv[1]).read_text()))
k=identity_key(c); fingerprint=signatures.fingerprint(k.public_key())
p=Path(c['identity_directory'])/'binding.json'
before=json.loads(storage.read_owned(p,0o600)) if p.exists() else {}
announce(c,collect(c))
after=json.loads(storage.read_owned(p,0o600)) if p.exists() else {}
a=Path(c['credential_directory'])/'archive.json'
grant=json.loads(storage.read_owned(a,0o640)) if a.exists() else {}
from zog.host_discover.roles import Controller
role=Controller(c).status()
print(json.dumps(dict(fingerprint=fingerprint,host_id=after.get('host_id') or c.get('host_id'),enrollment='approved' if after else 'pending',heartbeat='signed-accepted' if before else 'binding-received' if after else 'pending',archive_access='granted' if grant.get('expires_at',0)>time.time() else 'not-granted',mirror_state=role['state'])))
'''

PACKAGES = ("host-identify", "host-install", "host-discover")
VERSION_PROBE = (
    "import json,importlib.metadata as m;"
    "print(json.dumps({name:m.version(name) for name in "
    "('host-identify','host-install','host-discover')}))"
)


def _release_versions(release):
    """Require actual complete package metadata before any host mutation.

    Repository revisions remain pinned by beacon_payload; this checks the
    staged distributable versions and included license texts. It cannot
    authorize changing the live beacon source selector.
    """
    expected = {}
    requirements = {}
    for name in PACKAGES:
        package = release / name
        source = package / "pyproject.toml"
        if source.is_symlink() or not source.is_file():
            raise ValueError("Incomplete beacon package metadata: " + name)
        meta = tomllib.loads(source.read_text())["project"]
        if meta.get("name", "").lower() != name:
            raise ValueError("Beacon distribution identity mismatch: " + name)
        version = meta.get("version")
        if version is None:
            init = package / "src" / "zog" / name.replace("-", "_") / "__init__.py"
            if init.is_symlink() or not init.is_file():
                raise ValueError("Missing beacon package version: " + name)
            found = re.search(r'(?m)^__version__\s*=\s*["\x27]([^"\x27]+)["\x27]', init.read_text())
            if found is None:
                raise ValueError("Unresolved beacon package version: " + name)
            version = found.group(1)
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
            raise ValueError("Invalid beacon distribution version: " + name)
        for pattern in meta.get("license-files", []):
            matches = list(package.glob(pattern))
            if not matches or any(not p.is_file() or p.is_symlink() for p in matches):
                raise ValueError("Missing beacon source license file: " + name)
        expected[name] = version
        requirements[name] = meta.get("dependencies", [])
    for name, deps in requirements.items():
        for dependency in deps:
            for target in PACKAGES:
                match = re.fullmatch(re.escape(target) + r"==([0-9]+(?:\.[0-9]+){1,3})",
                                     dependency.strip(), re.IGNORECASE)
                if match and expected[target] != match.group(1):
                    raise ValueError("Conflicting beacon companion versions: " +
                                     name + " requires " + dependency +
                                     ", selected " + target + "==" + expected[target])
    return expected


def _check_staged_versions(release, expected):
    python = str(release / "venv/bin/python")
    actual = json.loads(run([python, "-c", VERSION_PROBE]))
    if type(actual) is not dict or actual != expected:
        raise ValueError("Installed beacon versions differ from source metadata")
    run([python, "-m", "pip", "check"], timeout=30)
    manifest_file = release / "beacon-source-versions.json"
    if manifest_file.is_symlink() or not manifest_file.is_file():
        raise ValueError("Missing exact beacon source provenance descriptor")
    manifest_bytes = manifest_file.read_bytes()
    if len(manifest_bytes) > 65536:
        raise ValueError("Oversized beacon source provenance descriptor")
    manifest = json.loads(manifest_bytes)
    if (type(manifest) is not dict or manifest.get("schema") != 1
            or set(manifest.get("packages", {})) != set(PACKAGES)
            or any(not re.fullmatch(r"[0-9a-f]{40}",
                         manifest["packages"][name].get("commit", ""))
                   for name in PACKAGES)):
        raise ValueError("Invalid beacon source provenance descriptor")
    digest = hashlib.sha256(json.dumps({
        "versions": expected,
        "source_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }, sort_keys=True).encode()).hexdigest()
    return ("beacon-release-v1 sha256:" + digest + " " +
            " ".join(name + "=" + expected[name] for name in PACKAGES) + "\n").encode()


def service_unit(source, venv, value):
    """Bind systemd write access to the selected state directories."""
    unit = source.replace('/opt/host-discover/venv', str(venv))
    selected = [value['identity_directory'], value['credential_directory']]
    roles = role_directory(value)
    if roles:
        selected.append(roles)
    write_paths = " ".join(
        path.replace("\\", "\\x5c").replace(" ", "\\x20")
        for path in selected)
    updated, count = re.subn(r'(?m)^ReadWritePaths=.*$',
                             lambda _: 'ReadWritePaths=' + write_paths, unit)
    if count > 1:
        raise ValueError('Beacon service unit has duplicate ReadWritePaths directives')
    if count == 1:
        return updated
    service, count = re.subn(r'(?m)^\[Service\]\s*$',
                             '[Service]\nReadWritePaths=' + write_paths, unit, count=1)
    if count != 1:
        raise ValueError('Beacon service unit has no Service section')
    return service


def install(request, release):
    # Python/version and disk checks precede service or identity changes.
    python=request['python']
    run([python,'-c','import sys,venv; assert sys.version_info >= (3,12), "Python 3.12 required"'])
    if shutil.disk_usage('/opt').free<512*1024**2:raise ValueError('At least 512 MiB free required')
    safe_path(BASE);safe_path(CONFIG);safe_path(UNIT)
    old=json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    value=candidate(old,request)
    # Fail before activation if explicit CA path is unavailable or invalid.
    import ssl
    ssl.create_default_context(cafile=value.get('ca_file') or None)
    expected_versions = _release_versions(release)
    owner=BASE/'identity-owner.json'
    if owner.exists():
        if json.loads(owner.read_text())['cloud']!=request['cloud']:raise ValueError('Identity belongs to another instance')
    elif not old:
        # Fresh bootstrap must not consume an orphan key at the *selected*
        # location. Hard-coded /var/lib checks miss custom identity paths.
        for name in (value['identity_directory'],value['credential_directory']):
            p=Path(name);safe_path(p.parent)
            # The leaf is intentionally service-owned rather than root-owned;
            # never follow a symlink here or read an orphan credential outside
            # the selected state root.
            if p.is_symlink() or (p.exists() and not p.is_dir()):
                raise ValueError('Unsafe existing state directory')
            if p.exists() and any(p.iterdir()):
                raise ValueError('Unbound existing identity state: refuse image-cloned or orphan state')
    if not owner.exists():atomic(owner,json.dumps({'cloud':request['cloud']}).encode(),0o600)
    u=state_directories(value)
    venv=release/'venv'
    if not (release/'ready').exists():
        run([python,'-m','venv',str(venv)])
        run([str(venv/'bin/python'),'-m','pip','install','--disable-pip-version-check','-c',str(release/'requirements-security-tested.txt'),str(release/'host-identify'),str(release/'host-install'),str(release/'host-discover')],timeout=600)
    receipt = _check_staged_versions(release, expected_versions)
    if (release/'ready').exists():
        if (release/'ready').is_symlink() or (release/'ready').read_bytes() != receipt:
            raise ValueError('Existing beacon ready receipt does not match exact package closure')
    else:
        atomic(release/'ready',receipt,0o644)
    executable=str(venv/'bin/python')
    staged=release/'configuration.json'
    atomic(staged,json.dumps(value).encode(),gid=u.pw_gid)
    # Generate missing key and validate existing key with the service UID; never copy it.
    fingerprint=run(['runuser','-u','host-discover','-g','host-discover','-G','archive-consumers','--',executable,'-m','zog.host_discover','--configuration',str(staged),'--fingerprint'])
    unit=service_unit((release/'deployment/signed-identity/host-discover.service').read_text(),venv,value)
    # Preserve administrator drop-ins. Keep a root-only rollback reference, including legacy token.
    backup=BASE/'rollback'/uuid.uuid4().hex;backup.mkdir(parents=True,mode=0o700)
    for p in (CONFIG,UNIT):
        if p.exists():atomic(backup/p.name,p.read_bytes(),0o600)
    was_active=subprocess.run(['systemctl','is-active','--quiet','host-discover.service']).returncode==0
    was_enabled=subprocess.run(['systemctl','is-enabled','--quiet','host-discover.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    run(['systemctl','stop','host-discover.service']) if UNIT.exists() else None
    # Persist transaction before switch. If interrupted, retries keep state and never restore an old key.
    atomic(BASE/'activation.json',json.dumps({'release':str(release),'rollback':str(backup),'phase':'activating'}).encode(),0o600)
    try:
        atomic(CONFIG,json.dumps(value).encode(),gid=u.pw_gid)
        atomic(UNIT,unit.encode(),0o644)
        run(['systemctl','daemon-reload'])
        result=json.loads(run(['runuser','-u','host-discover','-g','host-discover','-G','archive-consumers','--',executable,'-c',PROBE,str(CONFIG)],timeout=90))
        if request.get('expected_host_id') and result.get('host_id')!=request['expected_host_id']:raise ValueError('Signed binding differs from saved UUID')
        run(['systemctl','enable','host-discover.service']);run(['systemctl','restart','host-discover.service']);run(['systemctl','is-active','--quiet','host-discover.service'])
    except Exception:
        # Preserve identity/roles. Roll back only service/config, never private state.
        subprocess.run(['systemctl','stop','host-discover.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for p in (CONFIG,UNIT):
            saved=backup/p.name
            if saved.exists():atomic(p,saved.read_bytes(),0o644 if p==UNIT else 0o640,gid=0 if p==UNIT else u.pw_gid)
            elif p.exists():p.unlink()
        run(['systemctl','daemon-reload'])
        if not was_enabled:subprocess.run(['systemctl','disable','host-discover.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if was_active:run(['systemctl','restart','host-discover.service'])
        raise
    result.update(daemon='installed',service='active',enabled=True,release=str(release),server=value['server'],fingerprint=fingerprint)
    atomic(BASE/'activation.json',json.dumps({'release':str(release),'rollback':str(backup),'phase':'installed','result':result}).encode(),0o600)
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--release',required=True);a=p.parse_args()
    try:
        BASE.mkdir(mode=0o755,parents=True,exist_ok=True);safe_path(BASE)
        fd=os.open(BASE/'install.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            result=install(json.loads(Path(a.request).read_text()),Path(a.release))
        print(json.dumps(result))
    except Exception as e:
        print('Beacon installation failed ('+type(e).__name__+'); existing state retained. Check Python >=3.12, server pass3 readiness, package access and protected path ownership.',file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__':main()
