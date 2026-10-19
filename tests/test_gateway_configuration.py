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
