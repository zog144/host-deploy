"""Disposable finite BuildBackend component probe, never compiler admission.

Directly exercises the exact restricted backend with native PID1 and a static
90-second canary. No daemon/socket authorization or six-hour acceptance claim.
The private registration bind exists only in this harness mount namespace.
"""
import array
import socket
import stat
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


def fd_inventory(pid):
    result=[]
    for path in sorted(Path(f'/proc/{pid}/fd').iterdir(),key=lambda p:int(p.name)):
        meta=path.stat()
        info=Path(f'/proc/{pid}/fdinfo/{path.name}').read_text()
        flags=next(x.split(':',1)[1].strip() for x in info.splitlines() if x.startswith('flags:'))
        result.append({'fd':int(path.name),'target':os.readlink(path),'flags':flags,
                       'writable':bool(int(flags,8)&os.O_ACCMODE),
                       'device':f'{os.major(meta.st_dev)}:{os.minor(meta.st_dev)}',
                       'inode':meta.st_ino,'kind':stat.S_IFMT(meta.st_mode)})
    return {'pid':pid,'fds':result}


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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
int main(void) {
  const char *paths[]={"/tmp/probe","/var/tmp/probe","/run/probe","/image-build/source/probe","/image-build/output/probe"};
  FILE *f=fopen("/image-build/output/canary.json","w"); if(!f)return 2;
  int ok=1;
  for(int i=0;i<5;i++){int d=open(paths[i],O_CREAT|O_WRONLY,0600);if(d<0)ok=0;else{write(d,"probe",5);close(d);}}
  errno=0; int u=unshare(CLONE_NEWNS);int e=errno;
  int d=open("/root-write",O_CREAT|O_WRONLY,0600);int ro=(d<0);if(d>=0)close(d);
  int held=open("/image-build/output/held-fd",O_CREAT|O_RDWR,0600);
  int mem=memfd_create("zog-canary",0);
  int nul=open("/dev/null",O_WRONLY);
  int huge=open("/dev/hugepages/zog-native-probe",O_CREAT|O_EXCL|O_RDWR,0600); int huge_errno=errno;
  if(huge>=0){close(huge);unlink("/dev/hugepages/zog-native-probe");}
  FILE *hf=fopen("/image-build/output/huge.json","w");
  fprintf(hf,"{\"open_result\":%d,\"errno\":%d}\n",huge,huge_errno);fclose(hf);
  int sock=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un address={.sun_family=AF_UNIX};
  strcpy(address.sun_path,"/image-build/output/fd.sock");
  if(bind(sock,(struct sockaddr*)&address,sizeof(address))<0 || listen(sock,1)<0)return 4;
  pid_t child=fork(); if(child==0){sleep(80);_exit(0);} if(child<0)return 3;
  fprintf(f,"{\"pid\":%d,\"child\":%d,\"uid\":%d,\"gid\":%d,\"writes\":%d,\"unshare_result\":%d,\"unshare_errno\":%d,\"root_write_denied\":%d}\n",getpid(),child,getuid(),getgid(),ok,u,e,ro);
  fflush(f);fsync(fileno(f));fclose(f);
  int peer=accept(sock,NULL,NULL); if(peer<0)return 5;
  char payload; struct iovec io={.iov_base=&payload,.iov_len=1};
  char control[CMSG_SPACE(sizeof(int))]; memset(control,0,sizeof(control));
  struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
  if(recvmsg(peer,&msg,0)<0)return 6;
  struct cmsghdr *cm=CMSG_FIRSTHDR(&msg);
  if(!cm || cm->cmsg_level!=SOL_SOCKET || cm->cmsg_type!=SCM_RIGHTS)return 7;
  int foreign; memcpy(&foreign,CMSG_DATA(cm),sizeof(int));
  ssize_t wrote=write(foreign,"X",1);
  FILE *ack=fopen("/image-build/output/fd-ack.json","w");
  fprintf(ack,"{\"foreign_fd\":%d,\"write_result\":%ld}\n",foreign,(long)wrote);fclose(ack);
  sleep(80);wait(NULL);return 0;
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
        imported=b.resource_path(str(PROJECT), RESOURCE)/'root'
        host_import=b._pid1_resource_path(imported, fresh=True)
        emit('imported-root-identities',[ident(imported),ident(host_import),ident(f"/proc/{data['pid']}/root")])
        cg=Path('/sys/fs/cgroup')/observed['control_group'].lstrip('/')
        emit('native-limits',{name:(cg/name).read_text().strip() for name in
                              ('memory.max','memory.swap.max','cgroup.procs')})
        emit('boot-id',Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        for dest,src in [(x[1],x[0]) for key,xs in observed['properties'] if key=='BindPaths' for x in xs]:
            emit('worker-bind-identities',[ident(src),ident(Path(f"/proc/{data['pid']}/root")/dest.lstrip('/'))])
        emit('hugetlb-open', json.loads((output/'huge.json').read_text()))
        census=witness._processes()
        emit('parent-descendant-census',census)
        assert data['pid'] in census and data['child'] in census
        failures=[]
        for pid in (data['pid'],data['child']):
            emit('kernel-process', {'pid':pid,'root':os.readlink(f'/proc/{pid}/root'),
                 'mount_namespace':os.readlink(f'/proc/{pid}/ns/mnt'),
                 'cgroup':Path(f'/proc/{pid}/cgroup').read_text(),
                 'mountinfo':Path(f'/proc/{pid}/mountinfo').read_text()})
            emit('native-fds-before',fd_inventory(pid))
            try:
                emit('host-worker-witness',witness._verify_worker(pid,build_uid=UID,build_gid=UID,
                                                               build_device=quota.MOUNT.stat().st_dev))
            except Exception as e:
                failures.append(type(e).__name__+': '+str(e));emit('host-worker-witness-error',failures[-1])
        try:
            emit('root-worker-witness',b.inspect_fresh_worker_native(project_root=str(PROJECT),job_id=JOB,build_root_id=RESOURCE))
        except Exception as e:
            failures.append(type(e).__name__+': '+str(e));emit('root-worker-witness-error',failures[-1])
        # A same-filesystem wrong expected inode must be rejected even before
        # mount parsing. Direct helper negative only, not an admission receipt.
        from zog.root_control import fresh_native_worker_witness as root_witness
        wrong=b.resource_path(str(PROJECT),'d'*32)
        (wrong/'root').mkdir(parents=True)
        info=json.loads((b.resource_path(str(PROJECT),RESOURCE)/'jobs'/(JOB+'.json')).read_text())
        try:
            root_witness.inspect(backend=b,project_root=str(PROJECT),path=wrong,info=info,observed=observed)
        except RuntimeError as error:
            emit('wrong-root-inode-negative',str(error))
            assert 'inode' in str(error)
        else:
            failures.append('wrong root inode accepted')
        # Deliberate privileged fault injection, confined to this disposable
        # runner and a one-byte temporary file. Do not modify production policy.
        foreign=Path('/var/tmp/zog-native-foreign-fd')
        assert not foreign.exists()
        fd=os.open(foreign,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.connect(str(output/'fd.sock'))
                connection.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            for _ in range(100):
                if (output/'fd-ack.json').exists() and (output/'fd-ack.json').stat().st_size: break
                time.sleep(.05)
            emit('foreign-fd-injection',json.loads((output/'fd-ack.json').read_text()))
            emit('foreign-file-identity',ident(foreign))
            emit('native-fds-after',fd_inventory(data['pid']))
            try:
                witness._verify_worker(data['pid'],build_uid=UID,build_gid=UID,build_device=quota.MOUNT.stat().st_dev)
            except RuntimeError as error:
                emit('foreign-fd-witness-rejection',{'error':str(error),'fd_check_reached':'file descriptor' in str(error)})
            else:
                failures.append('foreign writable FD accepted')
        finally:
            os.close(fd)
            foreign.unlink()
        b.cancel(project_root=str(PROJECT),job_id=JOB,build_root_id=RESOURCE,
                 expected_invocation_id=observed['invocation_id'])
        after=b.observe(project_root=str(PROJECT),job_id=JOB,build_root_id=RESOURCE)
        emit('cancelled',after)
        assert after.get('cgroup_empty') is True
        # Actual durable job record remains start_attempted / cleanup false;
        # test the new idle veto against the real two-level registry layout.
        current=json.loads((b.resource_path(str(PROJECT),RESOURCE)/'jobs'/(JOB+'.json')).read_text())
        emit('retained-job-cleanup-flags',{k:current.get(k) for k in ('start_attempted','process_cleanup_complete')})
        try:
            witness._assert_no_unclean_starts(quota.MOUNT.stat().st_dev)
        except RuntimeError as error:
            emit('idle-cleanup-veto',{'rejected':True,'error':str(error)})
        else:
            emit('idle-cleanup-veto',{'rejected':False})
            failures.append('idle cleanup veto missed actual retained job')
        assert not failures, failures
    finally:
        # Disposable parent only. Independent 90s runtime remains if client dies.
        command('systemctl','stop',FRESH_COMPILER_PARENT_SLICE)


if __name__=='__main__':
    worker() if sys.argv[1:]==['worker'] else setup()
