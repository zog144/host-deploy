import json
from pathlib import Path
import pytest
from zog.host_deploy.gateway.github_configuration import configuration, prepare_configured
from zog.host_deploy.gateway.github_dispatch import GitHubDispatchError, ISSUE_MARKER


def settings():
    return {
        'ZOG_GATEWAY_DISPATCH_REVISION': 'a' * 40,
        'ZOG_GATEWAY_AWS_REGION': 'us-east-1',
        'ZOG_GATEWAY_QUEUE_URL': 'https://sqs.us-east-1.amazonaws.com/123456789012/zog-build-requests.fifo',
        'ZOG_GATEWAY_ROLE_ARN': 'arn:aws:iam::123456789012:role/test-dispatch',
        'ZOG_GATEWAY_AUTHORIZED_ACTORS': '["operator"]',
        'ZOG_GATEWAY_ALLOWED_OPERATIONS': '["build.status"]',
        'GITHUB_EVENT_NAME': 'issues', 'GITHUB_RUN_ATTEMPT': '1',
        'GITHUB_ACTOR': 'operator', 'GITHUB_TRIGGERING_ACTOR': 'operator',
        'GITHUB_REPOSITORY': 'zog144/host-deploy', 'GITHUB_REPOSITORY_ID': '123',
    }


def event():
    intent = dict(schema=1, request_id='1'*32, workspace_id='2'*32,
                  operation='build.status', parameters={'lane':'readonly', 'pipeline_id':'3'*32})
    return {'action':'opened', 'repository':{'full_name':'zog144/host-deploy', 'id':123},
            'sender':{'login':'operator'}, 'issue':{'number':1, 'state':'open',
            'user':{'login':'operator'}, 'body':ISSUE_MARKER+'\n```json\n'+json.dumps(intent)+'\n```'}}


def invoke(tmp_path, env, value=None):
    p=tmp_path/'event.json';p.write_text(json.dumps(value or event()))
    return prepare_configured(p,tmp_path/'request.json',env)


def test_configured_readonly_request_binds_actor(tmp_path):
    result=invoke(tmp_path,settings())
    assert result['operation']=='build.status'
    assert json.loads((tmp_path/'request.json').read_text())['origin']['trigger_actor']=='operator'
    assert (tmp_path/'request.json').stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('key,value',[
 ('ZOG_GATEWAY_DISPATCH_REVISION','main'), ('ZOG_GATEWAY_AWS_REGION','us-west-2'),
 ('ZOG_GATEWAY_ROLE_ARN','arn:aws:iam::999999999999:role/test'),
 ('ZOG_GATEWAY_QUEUE_URL','https://attacker.invalid/123456789012/zog-build-requests.fifo'),
 ('ZOG_GATEWAY_AUTHORIZED_ACTORS','[]'), ('ZOG_GATEWAY_AUTHORIZED_ACTORS','["other"]'),
 ('ZOG_GATEWAY_ALLOWED_OPERATIONS','["build.submit"]'),
 ('ZOG_GATEWAY_ALLOWED_OPERATIONS','["shell.execute"]'),
 ('GITHUB_RUN_ATTEMPT','2'), ('GITHUB_EVENT_NAME','pull_request'),
 ('GITHUB_TRIGGERING_ACTOR','other'), ('GITHUB_REPOSITORY_ID','999'),
])
def test_invalid_configuration_never_writes_request(tmp_path,key,value):
    env=settings();env[key]=value
    with pytest.raises(GitHubDispatchError):invoke(tmp_path,env)
    assert not (tmp_path/'request.json').exists()


@pytest.mark.parametrize('key',[k for k in settings() if k.startswith('ZOG_GATEWAY_')])
def test_missing_setting_fails_closed(tmp_path,key):
    env=settings();del env[key]
    with pytest.raises(GitHubDispatchError):invoke(tmp_path,env)
    assert not (tmp_path/'request.json').exists()


def test_edited_event_and_origin_injection_rejected(tmp_path):
    v=event();v['action']='edited'
    with pytest.raises(GitHubDispatchError):invoke(tmp_path,settings(),v)


def test_request_file_cannot_be_overwritten(tmp_path):
    invoke(tmp_path,settings());before=(tmp_path/'request.json').read_bytes()
    with pytest.raises(FileExistsError):invoke(tmp_path,settings())
    assert (tmp_path/'request.json').read_bytes()==before


# These are the reviewed protocol task and lane *selections*. Their root-owned
# task catalogue, precise producer/pin and protected lane are independently
# verified after SQS admission; GitHub does not provide that authority.
REVIEWED_TOOLCHAIN_TASK = 'self-hosted-c-cxx-toolchain-v1'
REVIEWED_TOOLCHAIN_LANE = 'compiler-reviewed'


def toolchain_event(operation='toolchain.submit'):
    value = event()
    intent = dict(
        schema=1, request_id='1'*32, workspace_id='2'*32,
        operation=operation,
        parameters=(
            {'lane': REVIEWED_TOOLCHAIN_LANE, 'task': REVIEWED_TOOLCHAIN_TASK}
            if operation == 'toolchain.submit' else
            {'lane': REVIEWED_TOOLCHAIN_LANE, 'operation_id': '3'*32}
        ),
    )
    if operation == 'toolchain.submit':
        intent['source'] = {
            'repository': 'zog144/image-build',
            'commit': '31e6121cdf9fd05336286529666e2c35cdbe0831',
        }
    value['issue']['body'] = (
        ISSUE_MARKER + '\\n```json\\n' + json.dumps(intent) + '\\n```'
    )
    return value


@pytest.mark.parametrize('operation', [
    'toolchain.submit', 'toolchain.inspect', 'toolchain.resume',
])
def test_reviewed_toolchain_operation_is_valid_but_requires_explicit_opt_in(
        tmp_path, operation):
    evt = toolchain_event(operation)
    disabled = settings()
    with pytest.raises(GitHubDispatchError, match='operation not enabled'):
        invoke(tmp_path, disabled, evt)
    assert not (tmp_path/'request.json').exists()
    enabled = settings()
    enabled['ZOG_GATEWAY_ALLOWED_OPERATIONS'] = json.dumps(['build.status', operation])
    assert operation in configuration(enabled)['operations']
    summary = invoke(tmp_path, enabled, evt)
    saved = json.loads((tmp_path/'request.json').read_text())
    assert summary['operation'] == saved['operation'] == operation
    assert saved['parameters']['lane'] == REVIEWED_TOOLCHAIN_LANE
    assert saved['origin'] == {
        'repository': 'zog144/host-deploy', 'issue_number': 1,
        'trigger_actor': 'operator',
    }
    assert (tmp_path/'request.json').stat().st_mode & 0o777 == 0o600
    if operation == 'toolchain.submit':
        assert saved['parameters']['task'] == REVIEWED_TOOLCHAIN_TASK
        assert saved['source']['commit'] == (
            '31e6121cdf9fd05336286529666e2c35cdbe0831')


@pytest.mark.parametrize('operations', [
    ['toolchain.submit', 'toolchain.submit'],
    ['toolchain.submit', 'shell.execute'],
    ['toolchain.submit', 'diagnostic.submit'],
    [],
    ['*'],
])
def test_toolchain_dispatch_configuration_is_not_a_wildcard(tmp_path, operations):
    env = settings()
    env['ZOG_GATEWAY_ALLOWED_OPERATIONS'] = json.dumps(operations)
    with pytest.raises(GitHubDispatchError, match='operation allowlist'):
        invoke(tmp_path, env, toolchain_event())
    assert not (tmp_path/'request.json').exists()


@pytest.mark.parametrize('mutate', [
    lambda value: value.update(action='edited'),
    lambda value: value['issue'].update(state='closed'),
    lambda value: value['issue']['user'].update(login='unapproved'),
    lambda value: value['sender'].update(login='unapproved'),
    lambda value: value['repository'].update(full_name='zog144/image-build'),
    lambda value: value['issue'].update(
        body=value['issue']['body'].replace(
            REVIEWED_TOOLCHAIN_TASK, 'arbitrary-shell-tool')),
    lambda value: value['issue'].update(
        body=value['issue']['body'].replace(
            REVIEWED_TOOLCHAIN_LANE, 'bad lane with spaces')),
])
def test_toolchain_dispatch_retains_actor_event_and_task_validation(
        tmp_path, mutate):
    env = settings()
    env['ZOG_GATEWAY_ALLOWED_OPERATIONS'] = '["toolchain.submit"]'
    value = toolchain_event()
    mutate(value)
    with pytest.raises(GitHubDispatchError):
        invoke(tmp_path, env, value)
    assert not (tmp_path/'request.json').exists()


@pytest.mark.parametrize('key,value', [
    ('GITHUB_RUN_ATTEMPT', '2'),
    ('GITHUB_EVENT_NAME', 'workflow_dispatch'),
    ('GITHUB_ACTOR', 'unapproved'),
    ('GITHUB_TRIGGERING_ACTOR', 'unapproved'),
    ('GITHUB_REPOSITORY_ID', '999'),
    ('ZOG_GATEWAY_AUTHORIZED_ACTORS', '["somebody-else"]'),
])
def test_toolchain_submit_requires_original_reviewed_issue_actor_and_run(
        tmp_path, key, value):
    env = settings()
    env['ZOG_GATEWAY_ALLOWED_OPERATIONS'] = '["toolchain.submit"]'
    env[key] = value
    with pytest.raises(GitHubDispatchError):
        invoke(tmp_path, env, toolchain_event())
    assert not (tmp_path/'request.json').exists()
