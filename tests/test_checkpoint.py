import json
import zipfile

import pytest
from zog.host_deploy import checkpoint
from zog.host_deploy.workspace import initialize, locked


def test_handoff_preserves_identity_and_retires_source(tmp_path):
    source = tmp_path/'source'
    value = initialize(source, 'example', 'development', 'us-east-1')
    (source/'aws.txt').write_text('must never export')
    archive = tmp_path/'state.zip'
    checkpoint.export(source, archive, handoff=True)
    with pytest.raises(RuntimeError, match='retired'):
        with locked(source): pass
    with zipfile.ZipFile(archive) as data:
        assert data.namelist() == ['checkpoint.json', 'workspace.json']
    target = tmp_path/'target'
    checkpoint.restore(archive, target)
    assert json.loads((target/'workspace.json').read_text()) == value
    with locked(target): pass
    with pytest.raises(ValueError, match='new destination'):
        checkpoint.restore(archive, target)


def test_damaged_checkpoint_never_publishes_workspace(tmp_path):
    initialize(tmp_path/'source', 'example', 'development', 'us-east-1')
    checkpoint.export(tmp_path/'source', tmp_path/'good.zip')
    with zipfile.ZipFile(tmp_path/'good.zip') as source, zipfile.ZipFile(tmp_path/'bad.zip', 'w') as output:
        for name in source.namelist():
            data = source.read(name)
            if name == 'workspace.json': data = data.replace(b'example', b'altered')
            output.writestr(name, data)
    with pytest.raises(ValueError, match='hash mismatch'):
        checkpoint.restore(tmp_path/'bad.zip', tmp_path/'target')
    assert not (tmp_path/'target').exists()


def test_unexpected_path_is_rejected(tmp_path):
    with zipfile.ZipFile(tmp_path/'bad.zip', 'w') as output:
        output.writestr('checkpoint.json', '{}')
        output.writestr('../outside', 'bad')
    with pytest.raises(ValueError, match='path'):
        checkpoint.restore(tmp_path/'bad.zip', tmp_path/'target')
    assert not (tmp_path/'outside').exists()


def test_failed_publication_keeps_retirement_recoverable(tmp_path, monkeypatch):
    source = tmp_path/'source'
    initialize(source, 'example', 'development', 'us-east-1')
    original = checkpoint.os.link
    monkeypatch.setattr(checkpoint.os, 'link', lambda *args: (_ for _ in ()).throw(OSError('disk fault')))
    with pytest.raises(OSError): checkpoint.export(source, tmp_path/'one.zip', handoff=True)
    assert (source/'retired.json').exists()
    monkeypatch.setattr(checkpoint.os, 'link', original)
    checkpoint.export(source, tmp_path/'two.zip', handoff=True)
    checkpoint.restore(tmp_path/'two.zip', tmp_path/'target')


def test_checkpoint_preserves_reboot_workflow(tmp_path):
    from zog.host_deploy.workspace import save
    import uuid
    source=tmp_path/'source'
    workspace=initialize(source,'reboot','development','us-east-1')
    host={key:workspace[key] for key in ['workspace_id','profile','region']}
    host.update(instance_id='i-test',account_id='123')
    save(source/'host.json',host)
    save(source/'launch.json',{'instance_id':'i-test','account_id':'123'})
    identity=uuid.uuid4().hex
    record={'name':'recovery','workflow_id':identity,'host':host,
            'remote_directory':'/var/lib/host-deploy/reboots/'+identity,
            'observed':{'phase':'reboot_wait','before_boot_id':'boot-one'}}
    save(source/'reboots/recovery.json',record)
    checkpoint.export(source,tmp_path/'checkpoint.zip')
    checkpoint.restore(tmp_path/'checkpoint.zip',tmp_path/'restored')
    assert json.loads((tmp_path/'restored/reboots/recovery.json').read_text())==record


def test_checkpoint_preserves_image_build_lane_record(tmp_path):
    from zog.host_deploy.image_build_lanes import specification
    from zog.host_deploy.workspace import save

    source = tmp_path/'source'
    initialize(source, 'lane', 'development', 'us-east-1')
    spec = specification(
        'lane-a',
        source_repository='zog144/image-build',
        source_revision='1'*40,
        monthly_pin_repository_path='project/pins/2026-10-01/commit-pin.py',
        monthly_pin_identity='sha256:' + '2'*64,
        provenance_host_id='host-a',
        provenance_project_id='project-a',
        memory_maximum_bytes=1024,
        thread_count_maximum=1,
        cpu_weight=100,
        disk_reservation_bytes=1024,
        execution_user_id=1000,
        execution_group_id=1000,
        project_root='/var/lib/zog/image-build-lanes/lane-a',
    )
    record = {
        'schema': 1,
        'lane': 'lane-a',
        'specification': spec,
        'state': 'prepared',
    }
    save(source/'image-build-lanes/lane-a.json', record)

    archive = tmp_path/'checkpoint.zip'
    checkpoint.export(source, archive, handoff=True)
    target = tmp_path/'restored'
    checkpoint.restore(archive, target)

    assert json.loads(
        (target/'image-build-lanes/lane-a.json').read_text()
    ) == record
