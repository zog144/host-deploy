import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from zog.host_deploy import beacon_install as b

@pytest.fixture
def target(tmp_path,monkeypatch):
    base=tmp_path/'opt';base.mkdir()
    cfg=tmp_path/'etc/configuration.json';cfg.parent.mkdir()
    unit=tmp_path/'system/host-discover.service';unit.parent.mkdir()
    ident=tmp_path/'state/identity';cred=tmp_path/'state/credentials'
    monkeypatch.setattr(b,'BASE',base);monkeypatch.setattr(b,'CONFIG',cfg);monkeypatch.setattr(b,'UNIT',unit)
    monkeypatch.setattr(b,'IDENTITY',str(ident));monkeypatch.setattr(b,'CREDENTIALS',str(cred))
    monkeypatch.setattr(b,'safe_path',lambda _:None)
    # Source-only ownership simulation: preserve all atomic/fchmod/fsync/rename
    # behavior without requesting a root-owned inode as an ordinary UID.
    monkeypatch.setattr(b, '_set_atomic_owner', lambda fd, uid, gid: None)
    def directories():
        ident.mkdir(parents=True,exist_ok=True);cred.mkdir(exist_ok=True)
        return SimpleNamespace(pw_gid=0)
    monkeypatch.setattr(b,'state_directories',directories)
    monkeypatch.setattr(b.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0))
    release=base/'release';release.mkdir()
    (release/'beacon-source-versions.json').write_text(json.dumps({
        "schema": 1,
        "packages": {
            name: {"repository": "example/" + name, "commit": "a"*40, "files": {}}
            for name in ("host-identify", "host-install", "host-discover")
        },
    }))
    template=release/'deployment/signed-identity';template.mkdir(parents=True)
    (template/'host-discover.service').write_text('ExecStart=/opt/host-discover/venv/bin/host-discover\n')
    old={'server':'https://registry.test','cloud':{'account_id':'1','instance_id':'i-1','region':'r'},'provider':'aws','host_id':'00000000-0000-4000-8000-000000000001','token':'legacy-secret'}
    cfg.write_text(json.dumps(old));unit.write_text('old-unit')
    request={'cloud':old['cloud'],'migrate':True,'system_ca':True,'python':'python3.12','expected_host_id':old['host_id']}
    calls=[]
    def run(args,**kw):
        calls.append(args)
        if b.VERSION_PROBE in args:
            return json.dumps({
                "host-identify": "0.3.4",
                "host-install": "0.4.4",
                "host-discover": "0.4.6",
            })
        if '--fingerprint' in args:
            key=ident/'identity.pem'
            if not key.exists():key.write_text('preserved-key')
            return 'public-fingerprint'
        if '-c' in args and b.PROBE in args:return json.dumps({'host_id':old['host_id'],'enrollment':'pending','heartbeat':'pending'})
        return ''
    monkeypatch.setattr(b,'run',run)
    monkeypatch.setattr(b,'_release_versions', lambda release: {
        "host-identify": "0.3.4", "host-install": "0.4.4", "host-discover": "0.4.6",
    })
    return request,release,cfg,unit,ident,calls,run

def test_staging_failure_keeps_old_service_and_configuration(target,monkeypatch):
    req,release,cfg,unit,ident,calls,run=target
    before=cfg.read_bytes()
    def fail(args,**kw):
        if 'pip' in args:raise RuntimeError('dependency unavailable')
        return run(args,**kw)
    monkeypatch.setattr(b,'run',fail)
    with pytest.raises(RuntimeError):b.install(req,release)
    assert cfg.read_bytes()==before and unit.read_text()=='old-unit'
    assert not any('systemctl' in a for a in calls)

def test_failed_probe_restores_old_config_and_preserves_key(target,monkeypatch):
    req,release,cfg,unit,ident,calls,run=target;before=cfg.read_bytes()
    def fail(args,**kw):
        if b.PROBE in args:raise RuntimeError('TLS unavailable')
        return run(args,**kw)
    monkeypatch.setattr(b,'run',fail)
    with pytest.raises(RuntimeError):b.install(req,release)
    assert cfg.read_bytes()==before and unit.read_text()=='old-unit'
    assert (ident/'identity.pem').read_text()=='preserved-key'

def test_reinstall_twice_preserves_key_role_and_claim(target):
    req,release,cfg,unit,ident,calls,run=target
    first=b.install(req,release)
    (ident/'mirror-role.json').write_text('durable-request-id')
    second=b.install(req,release)
    assert first['fingerprint']==second['fingerprint']=='public-fingerprint'
    assert first['heartbeat']==second['heartbeat']=='pending'
    assert (ident/'mirror-role.json').read_text()=='durable-request-id'
    assert (ident/'identity.pem').read_text()=='preserved-key'
    assert 'token' not in json.loads(cfg.read_text())
    stops=[i for i,a in enumerate(calls) if a[:2]==['systemctl','stop']]
    probes=[i for i,a in enumerate(calls) if b.PROBE in a]
    assert all(s<p for s,p in zip(stops,probes))
    assert str(release/'venv') in unit.read_text()

def test_privileged_owner_assignment_failure_aborts_atomic_replace(target, monkeypatch):
    req, release, cfg, unit, ident, calls, run = target
    existing = cfg.read_bytes()
    def denied(fd, uid, gid):
        raise PermissionError("native-only owner assignment unavailable")
    monkeypatch.setattr(b, "_set_atomic_owner", denied)
    with pytest.raises(PermissionError, match="native-only"):
        b.atomic(cfg, b"bad-change", 0o640)
    assert cfg.read_bytes() == existing

def test_conflicting_selected_public_versions_block_before_any_owner_state(tmp_path):
    from pathlib import Path
    def package(name, version, deps=()):
        root = tmp_path / name
        (root / "src/zog" / name.replace("-", "_")).mkdir(parents=True, exist_ok=True)
        (root / "src/zog" / name.replace("-", "_") / "__init__.py").write_text(
            '__version__ = "' + version + '"\n'
        )
        (root / "LICENSE").write_text("fixture")
        (root / "pyproject.toml").write_text(
            '[project]\nname = "' + name + '"\nversion = "' + version + '"\n'
            'license-files = ["LICENSE"]\n'
            'dependencies = ' + json.dumps(list(deps)) + '\n'
        )
    package("host-identify", "0.3.4")
    package("host-install", "0.10.0")
    package("host-discover", "0.4.8",
            ("host-identify==0.3.4", "host-install==0.4.4"))
    with pytest.raises(ValueError, match="Conflicting beacon companion versions"):
        b._release_versions(tmp_path)
    package("host-discover", "0.4.8",
            ("host-identify==0.3.4", "host-install==0.10.0"))
    assert b._release_versions(tmp_path)["host-install"] == "0.10.0"
    (tmp_path / "host-install/LICENSE").unlink()
    with pytest.raises(ValueError, match="license file"):
        b._release_versions(tmp_path)


def test_stale_ready_receipt_blocks_reinstall_without_touching_service(target):
    req, release, cfg, unit, ident, calls, run = target
    (release / "ready").write_text(
        "host-discover=0.4.6 host-identify=0.3.4 host-install=0.4.4\n"
    )
    before = cfg.read_bytes()
    with pytest.raises(ValueError, match="ready receipt"):
        b.install(req, release)
    assert cfg.read_bytes() == before
    assert unit.read_text() == "old-unit"
    assert not any(args[:2] == ['systemctl', 'stop'] for args in calls)
