import json

import pytest

from zog.host_deploy.gateway.task_catalogue import (
    TaskCatalogueError,
    load,
    select,
    validate,
)


REVISION = "a" * 40
GENERATION = "b" * 64


def catalogue(arguments=None):
    return {
        "schema": 1,
        "tasks": {
            "final-compiler": {
                "source_repository": "zog144/image-build",
                "source_revision": REVISION,
                "arguments": arguments
                or {
                    "mode": "image",
                    "selection": GENERATION,
                    "targets": ["gcc", "binutils"],
                },
            }
        },
    }


def test_catalogue_is_server_owned_finite_pipeline_input(tmp_path):
    path = tmp_path / "tasks.json"
    path.write_text(json.dumps(catalogue()))
    value, identity = load(path)

    selected = select(
        value,
        "final-compiler",
        repository="zog144/image-build",
        revision=REVISION,
    )
    assert identity.startswith("sha256:")
    assert selected["arguments"] == {
        "mode": "image",
        "selection": GENERATION,
        "targets": ["gcc", "binutils"],
    }


def test_catalogue_digest_changes_with_generation(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(json.dumps(catalogue()))
    changed = catalogue()
    changed["tasks"]["final-compiler"]["arguments"]["selection"] = "c" * 64
    second.write_text(json.dumps(changed))

    assert load(first)[1] != load(second)[1]


@pytest.mark.parametrize(
    "value",
    [
        {"schema": 1, "tasks": {"unknown": {}}},
        {
            "schema": 1,
            "tasks": {
                "final-compiler": {
                    "source_repository": "other/image-build",
                    "source_revision": REVISION,
                    "arguments": {
                        "mode": "image",
                        "selection": GENERATION,
                        "targets": ["gcc"],
                    },
                }
            },
        },
        {
            "schema": 1,
            "tasks": {
                "final-compiler": {
                    "source_repository": "zog144/image-build",
                    "source_revision": "unstable",
                    "arguments": {
                        "mode": "image",
                        "selection": GENERATION,
                        "targets": ["gcc"],
                    },
                }
            },
        },
        {
            "schema": 1,
            "tasks": {
                "final-compiler": {
                    "source_repository": "zog144/image-build",
                    "source_revision": REVISION,
                    "arguments": {
                        "mode": "image",
                        "selection": "latest",
                        "targets": ["gcc"],
                    },
                }
            },
        },
        {
            "schema": 1,
            "tasks": {
                "final-compiler": {
                    "source_repository": "zog144/image-build",
                    "source_revision": REVISION,
                    "arguments": {
                        "mode": "image",
                        "selection": GENERATION,
                        "targets": [],
                    },
                }
            },
        },
    ],
)
def test_catalogue_rejects_mutable_or_unbounded_inputs(value):
    with pytest.raises(TaskCatalogueError):
        validate(value)


def test_catalogue_select_requires_exact_admitted_source():
    value = validate(catalogue())
    with pytest.raises(TaskCatalogueError, match="admitted source revision"):
        select(
            value,
            "final-compiler",
            repository="zog144/image-build",
            revision="c" * 40,
        )


def test_bootstrap_task_stages_are_bound_by_catalogue():
    value = catalogue(
        {
            "mode": "bootstrap",
            "selection": GENERATION,
            "stages": [["binutils"], ["gcc", "glibc"]],
        }
    )
    assert validate(value)["tasks"]["final-compiler"]["arguments"]["stages"] == [
        ["binutils"],
        ["gcc", "glibc"],
    ]


def test_catalogue_symlink_is_rejected(tmp_path):
    target = tmp_path / "target.json"
    target.write_text(json.dumps(catalogue()))
    link = tmp_path / "tasks.json"
    link.symlink_to(target)
    with pytest.raises(TaskCatalogueError, match="regular file"):
        load(link)
