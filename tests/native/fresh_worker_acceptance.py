"""Disposable finite BuildBackend component probe, never compiler admission.

Directly exercises the exact restricted backend with native PID1 and a static
90-second canary. No daemon/socket authorization or six-hour acceptance claim.
The private registration bind exists only in this harness mount namespace.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from zog.host_deploy.gateway import fresh_aggregate_disk as aggregate
from zog.host_deploy.gateway import fresh_quota_volume as quota
from zog.host_deploy.gateway import fresh_journal_backing as journal
from zog.host_deploy.gateway import fresh_native_storage_verifier as witness

PROJECT = quota.MOUNT.parent
RESOURCE = 'a' * 32
JOB = 'b' * 32
UID = 24302
OWNER = 24301


def command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=120).stdout.strip()


def emit(name, value):
    print(json.dumps({'probe': name, 'evidence': value}), flush=True)


def ident(path):
    s = Path(path).stat()
    return {'path': str(path), 'device': f'{os.major(s.st_dev)}:{os.minor(s.st_dev)}',
            'inode': s.st_ino}


def setup():
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    from zog.root_control.build import BuildBackend  # full companion import before allocating
    assert not quota.IMAGE.parent.exists() and not PROJECT.exists()
    emit('systemd', command('systemctl', '--version').splitlines()[0])
    assert os.statvfs('/var/lib').f_bavail * os.statvfs('/var/lib').f_frsize >= 36 * 1024**3
    for uid, name in ((OWNER, 'zog-native-owner'), (UID, 'zog-native-worker')):
        command('groupadd', '-g', str(uid), name)
        command('useradd', '-M', '-u', str(uid), '-g', str(uid), '-s', '/usr/sbin/nologin', name)
    quota.IMAGE.parent.mkdir(parents=True, mode=0o700)
    Path(aggregate.EXTERNAL_MOUNT).mkdir(mode=0o700)
    quota.MOUNT.mkdir(parents=True, mode=0o700)
    os.chown(PROJECT, OWNER, OWNER)
    PROJECT.chmod(0o700)
    emit('external', aggregate.provision_external(available_after_reservations_bytes=aggregate.TOTAL_BYTES))
    emit('work', quota.provision(available_after_reservations_bytes=aggregate.BUILD_BYTES,
                                mounted_writable_roots=[str(quota.MOUNT)]))
    for p in (quota.MOUNT/'state', PROJECT/'state'):
        p.mkdir(mode=0o700); os.chown(p, OWNER, OWNER)
    (quota.MOUNT/'controller-build-resources').mkdir(mode=0o700)
    command('mount', '--bind', str(quota.MOUNT/'state'), str(PROJECT/'state'))
    for p in journal.targets():
        assert not p.exists(); p.mkdir(parents=True, mode=0o700)
    emit('journals', journal.install_binds_before_activation())
    # A harmless holder activates the exact parent; it is explicitly outside
    # the worker census and not represented as a production sidecar.
    command('systemd-run', '--unit=zog-native-parent-holder.service',
            '--property=Slice=zogfreshcrossbootstrapoct25.slice',
            '--property=RuntimeMaxSec=180', '/usr/bin/sleep', '180')
    try:
        subprocess.run(['unshare', '--mount', '--propagation', 'private', sys.executable,
                        '-B', __file__, 'worker'], check=True, timeout=150)
    finally:
        command('systemctl', 'stop', 'zogfreshcrossbootstrapoct25.slice')


def worker():
    from zog.root_control.build import BuildBackend, FRESH_COMPILER_PARENT_SLICE
    from zog.root_control.systemd import BusctlSystemdBackend
    assert os.geteuid() == 0
    directory = Path('/var/lib/zog/build-resources')
    assert not directory.exists()
    directory.mkdir(parents=True, mode=0o700)
    command('mount', '--bind', str(quota.MOUNT/'controller-build-resources'), str(directory))
    emit('registration-alias', [ident(directory), ident(quota.MOUNT/'controller-build-resources')])
    attempt = PROJECT/'state/image-build/attempts/native'
    root, source, output = [attempt/x for x in ('root', 'source', 'output')]
    for p in (root/'bin', source, output): p.mkdir(parents=True)
    c = source/'canary.c'
    c.write_text(r'''
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
int main(void) {
  const char *paths[]={"/tmp/probe","/var/tmp/probe","/run/probe","/image-build/source/probe","/image-build/output/probe"};
  FILE *f=fopen("/image-build/output/canary.json","w"); if(!f)return 2;
  int ok=1;
  for(int i=0;i<5;i++){int d=open(paths[i],O_CREAT|O_WRONLY,0600);if(d<0)ok=0;else{write(d,"probe",5);close(d);}}
  errno=0; int u=unshare(CLONE_NEWNS);int e=errno;
  int d=open("/root-write",O_CREAT|O_WRONLY,0600);int ro=(d<0);if(d>=0)close(d);
  pid_t child=fork(); if(child==0){sleep(80);_exit(0);} if(child<0)return 3;
  fprintf(f,"{\"pid\":%d,\"child\":%d,\"uid\":%d,\"gid\":%d,\"writes\":%d,\"unshare_result\":%d,\"unshare_errno\":%d,\"root_write_denied\":%d}\n",getpid(),child,getuid(),getgid(),ok,u,e,ro);
  fflush(f);fsync(fileno(f));fclose(f);sleep(80);wait(NULL);return 0;
}
''')
    command('gcc', '-static', '-O2', '-o', str(root/'bin/canary'), str(c))
    emit('canary-sha256', hashlib.sha256((root/'bin/canary').read_bytes()).hexdigest())
    b = BuildBackend(BusctlSystemdBackend(), parent_slice=FRESH_COMPILER_PARENT_SLICE,
                     authorized_project_root=str(PROJECT))
    emit('register', b.register(project_root=str(PROJECT), resource_id=RESOURCE,
         prepared_root=root, source_directory=source, output_directory=output,
         input_manifest_id='disposable-native-canary-only', execution_user_id=UID, execution_group_id=UID)['state'])
    request=dict(build_root_id=RESOURCE,source_workspace_id=RESOURCE+'-source',output_workspace_id=RESOURCE+'-output',
                 command=['/bin/canary'],environment={'PATH':'/bin'},working_directory='/image-build/source',
                 execution_user_id=UID,execution_group_id=UID,startup_timeout_seconds=10,
                 execution_timeout_seconds=90,termination_grace_seconds=3,
                 resource_limits={'thread-count-maximum':16,'memory-maximum-bytes':67108864},
                 read_only_root=True,network_access=False)
    try:
        emit('start', b.start(project_root=str(PROJECT),job_id=JOB,request=request))
        for _ in range(100):
            if (output/'canary.json').exists(): break
            time.sleep(.1)
        data=json.loads((output/'canary.json').read_text())
        emit('canary',data)
        assert data['writes']==1 and data['unshare_result']==-1 and data['root_write_denied']==1
        observed=b.observe(project_root=str(PROJECT),job_id=JOB,build_root_id=RESOURCE)
        emit('pid1',observed)
        failures=[]
        for pid in (data['pid'],data['child']):
            emit('kernel-process', {'pid':pid,'root':os.readlink(f'/proc/{pid}/root'),
                 'mount_namespace':os.readlink(f'/proc/{pid}/ns/mnt'),
                 'cgroup':Path(f'/proc/{pid}/cgroup').read_text(),
                 'mountinfo':Path(f'/proc/{pid}/mountinfo').read_text()})
            try:
                emit('host-worker-witness',witness._verify_worker(pid,build_uid=UID,build_gid=UID,
                                                               build_device=quota.MOUNT.stat().st_dev))
            except Exception as e:
                failures.append(type(e).__name__+': '+str(e));emit('host-worker-witness-error',failures[-1])
        try:
            emit('root-worker-witness',b.inspect_fresh_worker_native(project_root=str(PROJECT),job_id=JOB,build_root_id=RESOURCE))
        except Exception as e:
            failures.append(type(e).__name__+': '+str(e));emit('root-worker-witness-error',failures[-1])
        b.cancel(project_root=str(PROJECT),job_id=JOB,build_root_id=RESOURCE,
                 expected_invocation_id=observed['invocation_id'])
        after=b.observe(project_root=str(PROJECT),job_id=JOB,build_root_id=RESOURCE)
        emit('cancelled',after)
        assert after.get('cgroup_empty') is True
        assert not failures, failures
    finally:
        # Disposable parent only. Independent 90s runtime remains if client dies.
        command('systemctl','stop',FRESH_COMPILER_PARENT_SLICE)


if __name__=='__main__':
    worker() if sys.argv[1:]==['worker'] else setup()
