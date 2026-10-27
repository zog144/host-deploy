"""Real disposable-runner storage probes; never compiler admission.

Run only by the dedicated GitHub-hosted workflow. No retained host, credentials,
controller, compiler request, default journal reconfiguration or shared reload.
"""
import errno
import json
import os
from pathlib import Path
import subprocess
import time

from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate
from zog.host_deploy.gateway import fresh_quota_volume as quota
from zog.host_deploy.gateway import fresh_journal_backing as journal


def command(*argv):
    return subprocess.run(argv, check=True, text=True, capture_output=True,
                          timeout=120).stdout.strip()


def emit(name, value):
    print(json.dumps({'probe': name, 'evidence': value}), flush=True)


def identity(path):
    p = Path(path)
    s = p.stat()
    return {'path': str(p), 'device': f'{os.major(s.st_dev)}:{os.minor(s.st_dev)}',
            'inode': s.st_ino, 'size': s.st_size, 'allocated': s.st_blocks * 512,
            'mount': command('findmnt', '-n', '-o', 'TARGET,SOURCE,FSTYPE,MAJ:MIN', '-T', str(p))}


def exhaust(path, *, retain=False):
    """Allocate actual filesystem blocks until kernel ENOSPC; no mocked limits."""
    leaf = Path(path) / 'acceptance-enospc'
    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    allocated = 0
    observed = False
    try:
        # Large extents for speed, then prove one more block fails.
        for step in (8 * 1024**2, 4096):
            while True:
                try:
                    os.posix_fallocate(fd, allocated, step)
                    allocated += step
                except OSError as error:
                    if error.errno != errno.ENOSPC:
                        raise
                    observed = True
                    break
        os.fsync(fd)
        emit('kernel-enospc', {'mount': str(path), 'allocated_payload': allocated,
                              'enospc': observed, 'inode': os.fstat(fd).st_ino})
        assert observed
    finally:
        os.close(fd)
        if not retain:
            leaf.unlink()
        d = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(d)
        os.close(d)


def main():
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    # Never operate on an existing installation, even on a hosted runner.
    base = quota.IMAGE.parent
    assert not base.exists() and not quota.MOUNT.parent.exists()
    free = os.statvfs('/var/lib')
    available = free.f_bavail * free.f_frsize
    emit('preflight', {'pid1': 'systemd', 'free_bytes': available,
                      'version': command('systemctl', '--version').splitlines()[0]})
    assert available >= aggregate.TOTAL_BYTES + 4 * 1024**3, 'insufficient disposable capacity'
    base.mkdir(parents=True, mode=0o700)
    external = Path(aggregate.EXTERNAL_MOUNT)
    external.mkdir(mode=0o700)
    quota.MOUNT.mkdir(parents=True, mode=0o700)
    emit('external-preparation', aggregate.provision_external(
        available_after_reservations_bytes=aggregate.TOTAL_BYTES))
    emit('worker-preparation', quota.provision(
        available_after_reservations_bytes=aggregate.BUILD_BYTES,
        mounted_writable_roots=[str(quota.MOUNT)]))
    for path in (quota.IMAGE, base / 'external.img', quota.MOUNT, external):
        emit('backing-identity', identity(path))
    exhaust(quota.MOUNT)
    exhaust(external)
    # Real preparation entry point, before any namespace activation.
    for target in journal.targets():
        assert not target.exists(), 'unexpected pre-existing journal target'
        target.mkdir(parents=True, mode=0o700)
    emit('journal-binds', journal.install_binds_before_activation())
    marker = 'zog-native-storage-acceptance-marker'
    command('systemd-run', '--unit=zog-native-storage-probe.service', '--wait',
            '--property=LogNamespace=' + journal.LOG_NAMESPACE,
            '--property=StandardOutput=journal', '--property=StandardError=journal',
            '/usr/bin/printf', marker + '\n')
    # Ensure journal data reached its actual persistent or volatile backing.
    command('journalctl', '--namespace=' + journal.LOG_NAMESPACE, '--sync')
    output = command('journalctl', '--namespace=' + journal.LOG_NAMESPACE,
                     '-u', 'zog-native-storage-probe.service', '--no-pager', '-o', 'cat')
    assert marker in output
    for target in journal.targets():
        emit('journal-target', identity(target))
    files = list(journal.JOURNAL_SOURCE.rglob('*.journal'))
    assert files, 'no actual journal file observed'
    for path in files:
        assert path.stat().st_dev == external.stat().st_dev
        emit('journal-file', identity(path))
    # Hold ENOSPC while journald is active; exercise namespace restart with
    # fixed mounts still present. No default journal changes or vacuuming.
    exhaust(external, retain=True)
    full_marker = 'zog-native-full-journal-no-default-spill'
    try:
        command('systemd-run', '--unit=zog-native-storage-full.service', '--wait',
                '--property=LogNamespace=' + journal.LOG_NAMESPACE,
                '--property=StandardOutput=journal', '--property=StandardError=journal',
                '/usr/bin/printf', full_marker + '\n')
        command('systemctl', 'restart', journal.JOURNAL_SERVICE)
        emit('journal-full-restart', journal.inspect())
        default = command('journalctl', '-u', 'zog-native-storage-full.service',
                          '--no-pager', '-o', 'json')
        records = [json.loads(line) for line in default.splitlines() if line]
        matches = [{k: row.get(k) for k in ('MESSAGE', '_TRANSPORT', '_SYSTEMD_UNIT', 'SYSLOG_IDENTIFIER')}
                   for row in records if full_marker in str(row.get('MESSAGE', ''))]
        emit('default-journal-marker-records', matches)
        # PID1 lifecycle descriptions include command argv. They are excluded
        # shared-host overhead, not evidence that worker stdout escaped.
        assert not any(row.get('_TRANSPORT') == 'stdout' for row in matches), 'namespace stdout spilled into default journal'
        emit('default-journal-negative', {'payload_absent': True})
        for path in journal.JOURNAL_SOURCE.rglob('*.journal'):
            assert path.stat().st_dev == external.stat().st_dev
            emit('full-journal-file', identity(path))
    finally:
        (external / 'acceptance-enospc').unlink()
    command('systemctl', 'restart', journal.JOURNAL_SERVICE)
    emit('journal-after-release', journal.inspect())
    emit('journal-service', command('systemctl', 'show', journal.JOURNAL_SERVICE,
                                   '-p', 'MainPID,ControlGroup,InvocationID,LogsDirectory'))
    emit('result', {'storage_and_journal_probe': 'PASS', 'compiler_admission': False,
                    'untested': ['controller-workers',
                                 'six-hour-deadline', 'cancellation', 'reboot']})


if __name__ == '__main__':
    main()
