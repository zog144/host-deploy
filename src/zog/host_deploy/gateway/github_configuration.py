"""Fail-closed deployment configuration for the public issue dispatcher."""
import argparse
import json
import os
from pathlib import Path
import re

from .github_dispatch import (
    AWS_REGION, GitHubDispatchError, load_authorized_actors, prepare_event,
    summary, validate_queue_url, write_prepared_request,
)
from .queues import queue_account_id


def configuration(env):
    """Only repository-admin settings select AWS targets and trusted source."""
    def required(name):
        value = env.get('ZOG_GATEWAY_' + name, '')
        if not isinstance(value, str) or not value:
            raise GitHubDispatchError('missing deployment setting: ' + name)
        return value

    revision = required('DISPATCH_REVISION')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise GitHubDispatchError('dispatcher revision must be an exact commit')
    if required('AWS_REGION') != AWS_REGION:
        raise GitHubDispatchError('region differs from supported gateway contract')
    queue = validate_queue_url(required('QUEUE_URL'))
    role = required('ROLE_ARN')
    match = re.fullmatch(r'arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}', role)
    if not match or match.group(1) != queue_account_id(queue):
        raise GitHubDispatchError('dispatch role and queue account must match')
    try:
        actors = json.loads(required('AUTHORIZED_ACTORS'))
        operations = json.loads(required('ALLOWED_OPERATIONS'))
    except (ValueError, TypeError):
        raise GitHubDispatchError('deployment lists must be JSON') from None
    allowed = {'host.status', 'build.status', 'build.submit', 'build.cancel', 'build.resume'}
    if (not isinstance(operations, list) or not operations
            or any(not isinstance(x, str) or x not in allowed for x in operations)
            or len(set(operations)) != len(operations)):
        raise GitHubDispatchError('invalid deployment operation allowlist')
    return dict(revision=revision, queue=queue, role=role, actors=actors,
                operations=operations)


def prepare_configured(event_path, output, env):
    settings = configuration(env)
    if (env.get('GITHUB_EVENT_NAME') != 'issues'
            or env.get('GITHUB_RUN_ATTEMPT') != '1'):
        raise GitHubDispatchError('only original issue-opened executions may submit')
    if env.get('GITHUB_ACTOR') != env.get('GITHUB_TRIGGERING_ACTOR'):
        raise GitHubDispatchError('triggering actor differs from original actor')
    event = json.loads(Path(event_path).read_text())
    if (event.get('repository', {}).get('full_name') != env.get('GITHUB_REPOSITORY')
            or str(event.get('repository', {}).get('id')) != env.get('GITHUB_REPOSITORY_ID')
            or event.get('sender', {}).get('login') != env.get('GITHUB_ACTOR')):
        raise GitHubDispatchError('event differs from GitHub execution identity')
    # Reuse the protocol's strict actor-file validator; never execute event text.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='zog-gateway-actors-') as temporary:
        actors = Path(temporary) / 'actors.json'
        actors.write_text(json.dumps({'schema': 1, 'actors': settings['actors']}))
        request = prepare_event(event, load_authorized_actors(actors))
    if request['operation'] not in settings['operations']:
        raise GitHubDispatchError('operation not enabled by deployment')
    write_prepared_request(output, request)
    return summary(request)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--event', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_configured(args.event, args.output, os.environ), sort_keys=True))


if __name__ == '__main__':
    main()
