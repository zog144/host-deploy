"""Portable local state, validated before atomic publication. No AWS credentials files."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import uuid
import zipfile

from .workspace import load, locked, save

MAXIMUM_BYTES = 16 * 1024 * 1024


def allowed(name):
    return name in {
        'workspace.json',
        'host.json',
        'launch.json',
        'adoption.json',
        'storage.json',
        'host-discover-install.json',
    } or bool(re.fullmatch(r'(jobs|reboots|image-build-lanes)/[A-Za-z0-9_-]{1,80}\.json', name))


def validate(files):
    if 'workspace.json' not in files or any(not allowed(name) for name in files):
        raise ValueError('Unexpected or missing checkpoint files')
    values = {name: json.loads(data) for name, data in files.items()}
    workspace = values['workspace.json']
    if workspace.get('schema') != 1 or uuid.UUID(workspace['workspace_id']).hex != workspace['workspace_id']:
        raise ValueError('Invalid workspace identity')
    host = values.get('host.json')
    if host:
        if any(host.get(key) != workspace[key] for key in ['workspace_id', 'profile', 'region']):
            raise ValueError('Checkpoint host identity mismatch')
        launch = values.get('launch.json')
        adoption = values.get('adoption.json')
        if (launch is None) == (adoption is None):
            raise ValueError('Checkpoint host requires exactly one launch or adoption lineage')
        if launch is not None:
            if launch.get('instance_id') != host['instance_id'] or launch.get('account_id') != host['account_id']:
                raise ValueError('Checkpoint launch identity mismatch')
        else:
            required = {
                'schema',
                'operation_id',
                'workspace_id',
                'instance_id',
                'account_id',
                'region',
                'owner',
                'ownership_epoch',
                'request_sha256',
                'inventory_sha256',
                'missing_original_checkpoint',
                'operator_authorization',
                'saved_state_hashes',
                'expected_writer_set',
                'writer_acknowledgements',
                'adopted_at',
            }
            if (
                not isinstance(adoption, dict)
                or set(adoption) != required
                or adoption.get('schema') != 1
                or adoption.get('owner') != 'host-deploy-gateway'
                or adoption.get('missing_original_checkpoint') is not True
                or adoption.get('workspace_id') != workspace['workspace_id']
                or adoption.get('instance_id') != host.get('instance_id')
                or adoption.get('account_id') != host.get('account_id')
                or adoption.get('region') != host.get('region')
                or adoption.get('ownership_epoch') != host.get('ownership_epoch')
                or adoption.get('operation_id') != host.get('adoption_operation_id')
                or not re.fullmatch(r'[0-9a-f]{32}', str(adoption.get('operation_id', '')))
                or not re.fullmatch(r'[0-9a-f]{64}', str(adoption.get('request_sha256', '')))
                or not re.fullmatch(r'[0-9a-f]{64}', str(adoption.get('inventory_sha256', '')))
                or not isinstance(adoption.get('operator_authorization'), str)
                or not adoption.get('operator_authorization')
                or not isinstance(adoption.get('saved_state_hashes'), dict)
                or not adoption.get('saved_state_hashes')
                or any(
                    not isinstance(name, str)
                    or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}', name)
                    or not isinstance(digest, str)
                    or not re.fullmatch(r'[0-9a-f]{64}', digest)
                    for name, digest in adoption.get('saved_state_hashes', {}).items()
                )
            ):
                raise ValueError('Checkpoint adoption lineage mismatch')
    discovery = values.get('host-discover-install.json')
    if discovery:
        if not host or any(discovery.get(key) != host.get(key) for key in ('instance_id','account_id','region')):
            raise ValueError('Checkpoint discovery identity mismatch')
        if 'token' in discovery:
            raise ValueError('Enrollment credentials do not belong in checkpoints')
    for name, job in values.items():
        if name.startswith('image-build-lanes/'):
            from .image_build_lanes import validate as validate_lane
            lane = job.get('lane')
            if (
                job.get('schema') not in {1, 2, 3}
                or not isinstance(lane, str)
                or lane + '.json' != Path(name).name
            ):
                raise ValueError('Checkpoint image-build lane identity mismatch')
            validate_lane(job.get('specification'))
            if job.get('state') not in {'prepared', 'active', 'retired'}:
                raise ValueError('Checkpoint image-build lane state mismatch')
            continue
        if name.startswith('reboots/'):
            identity = job['workflow_id']
            if uuid.UUID(identity).hex != identity or not host or job['host'] != host:
                raise ValueError('Checkpoint reboot identity mismatch')
            if name != 'reboots/' + job['name'] + '.json' or job['remote_directory'] != '/var/lib/host-deploy/reboots/' + identity:
                raise ValueError('Checkpoint reboot path mismatch')
            continue
        if not name.startswith('jobs/'):
            continue
        identity = job['job_id']
        if uuid.UUID(identity).hex != identity or not host or job['host'] != host:
            raise ValueError('Checkpoint job identity mismatch')
        if name != 'jobs/' + job['name'] + '.json' or job['remote_directory'] != '/var/lib/host-deploy/jobs/' + identity or job['unit'] != 'host-deploy-job-' + identity + '.service':
            raise ValueError('Checkpoint job path mismatch')
    return workspace


def export(directory, output, handoff=False):
    output = Path(output).absolute()
    with locked(directory, allow_retired=True) as root:
        # A retired workspace may export the same frozen state again after a lost reply.
        load(root)
        paths = [p for p in root.glob('*.json') if allowed(p.name)]
        for folder in ['jobs','reboots','image-build-lanes']:
            if (root/folder).is_symlink():
                raise ValueError('Unsafe checkpoint input')
            paths += list((root/folder).glob('*.json'))
        files = {}
        for path in paths:
            name = path.relative_to(root).as_posix()
            if path.is_symlink() or not allowed(name):
                raise ValueError('Unsafe checkpoint input')
            files[name] = path.read_bytes()
        if sum(map(len, files.values())) > MAXIMUM_BYTES:
            raise ValueError('Checkpoint exceeds 16 MiB')
        workspace = validate(files)
        if output.exists():
            raise ValueError('Checkpoint output already exists')
        output.parent.mkdir(parents=True, exist_ok=True)
        metadata = {'schema': 1, 'workspace_id': workspace['workspace_id'],
                    'handoff': bool(handoff),
                    'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
        descriptor, temporary = tempfile.mkstemp(dir=output.parent)
        try:
            with os.fdopen(descriptor, 'w+b') as stream:
                with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr('checkpoint.json', json.dumps(metadata))
                    for name, data in files.items():
                        archive.writestr(name, data)
                stream.flush()
                os.fsync(stream.fileno())
            if handoff:
                # Retire before publishing: a crash may retire early, never too late.
                save(root/'retired.json', {'checkpoint': str(output), 'workspace_id': workspace['workspace_id']})
            os.link(temporary, output)
            descriptor = os.open(output.parent, os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        finally:
            os.unlink(temporary)
        return {'checkpoint': str(output), 'workspace_id': workspace['workspace_id'], 'retired': (root/'retired.json').exists()}


def restore(archive, directory):
    target = Path(directory).absolute()
    if target.exists():
        raise ValueError('Restore requires a new destination directory')
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        names = [item.filename for item in entries]
        if len(names) != len(set(names)) or sum(item.file_size for item in entries) > MAXIMUM_BYTES:
            raise ValueError('Duplicate or oversized checkpoint')
        if 'checkpoint.json' not in names or any(name != 'checkpoint.json' and not allowed(name) for name in names):
            raise ValueError('Unexpected checkpoint path')
        metadata = json.loads(source.read('checkpoint.json'))
        files = {name: source.read(name) for name in names if name != 'checkpoint.json'}
    if metadata.get('schema') != 1 or (
        'handoff' in metadata and type(metadata['handoff']) is not bool
    ) or metadata.get('files') != {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}:
        raise ValueError('Checkpoint hash mismatch')
    workspace = validate(files)
    if metadata['workspace_id'] != workspace['workspace_id']:
        raise ValueError('Checkpoint identity mismatch')
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.restore-', dir=target.parent))
    try:
        for name, data in files.items():
            save(staging/name, json.loads(data))
        descriptor = os.open(staging, os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        # Reserve the target without replacing any pre-existing destination.
        target.mkdir(mode=0o700)
        try:
            os.replace(staging, target)
        except BaseException:
            target.rmdir()
            raise
        descriptor = os.open(target.parent, os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if staging.exists(): shutil.rmtree(staging)
    return {'workspace': str(target), 'workspace_id': workspace['workspace_id'], 'restored': True}
