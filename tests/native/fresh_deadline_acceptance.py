"""Disposable PID1 admission probe for the unchanged fixed deadline message.

Does not arm the compiler budget, create a worker, or claim elapsed deadline
acceptance. Always removes the test timer before returning.
"""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

from dbus_next import BusType, MessageType
from dbus_next.aio import MessageBus
from zog.host_deploy.gateway import fresh_deadline_timer as deadline


def command(*args):
    return subprocess.run(args, text=True, capture_output=True, timeout=30)


def emit(name, evidence):
    print(json.dumps({'probe': name, 'evidence': evidence}), flush=True)


async def probe():
    assert os.geteuid() == 0
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    emit('environment', command('systemctl', '--version').stdout.splitlines()[0])
    for unit in (deadline.UNIT, deadline.STOP_UNIT):
        before = command('systemctl', 'show', unit, '-p', 'LoadState', '--value')
        assert before.stdout.strip() == 'not-found', 'refuse pre-existing deadline'
    plan = {'schema': 'host-deploy-fresh-sidecar-install-v1',
            'unit': 'zog-fresh-cross-bootstrap-oct25-controller.service',
            'installed': {'python_executable': sys.executable,
                          'host_deploy_python_root': str(Path('src').resolve())}}
    message = deadline.message(plan)
    emit('fixed-deadline', {'seconds': deadline.TRIGGER_SECONDS,
                           'overall_seconds': deadline.DEADLINE_SECONDS,
                           'shortened': False})
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        reply = await bus.call(message)
        emit('native-pid1-reply', {'type': reply.message_type.name,
                                 'error': reply.error_name, 'body': reply.body})
        assert reply.message_type != MessageType.ERROR, 'native PID1 rejected unchanged deadline message'
        assert reply.signature == 'o'
        observed = command('systemctl', 'show', deadline.UNIT,
                           '-p', 'ActiveState,TimersMonotonic,NextElapseUSecMonotonic,Unit')
        emit('native-timer', observed.stdout)
        assert 'ActiveState=active' in observed.stdout
        emit('result', {'timer_admission': 'PASS', 'elapsed_six_hour': 'NOT_TESTED',
                        'compiler_admission': False})
    finally:
        bus.disconnect()
        result = command('systemctl', 'stop', deadline.UNIT)
        emit('timer-cleanup', {'returncode': result.returncode})


if __name__ == '__main__':
    asyncio.run(probe())
