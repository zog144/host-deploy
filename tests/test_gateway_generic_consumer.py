"""Opt-in queue coordinator cannot execute arbitrary or unreviewed build jobs."""
from pathlib import Path
from types import SimpleNamespace
import pytest
from zog.host_deploy.gateway import consumer

RID="a"*32

def setup(tmp_path):
    self=object.__new__(consumer.GatewayConsumer)
    self.state_directory=tmp_path
    self.approved_generic_catalogue=None
    self.approved_catalogue_identity=None
    (tmp_path/"requests"/RID).mkdir(parents=True)
    return self

def test_default_queue_owner_is_admission_only(tmp_path,monkeypatch):
    obj=setup(tmp_path)
    monkeypatch.setattr(consumer,"load_request",
                        lambda *args:pytest.fail("not enabled"))
    assert obj._advance_one_reviewed() is None

def test_reviewed_queue_advances_only_one_frozen_stage(tmp_path,monkeypatch):
    obj=setup(tmp_path)
    obj.approved_generic_catalogue={"schema":2,"tasks":{"xcb-support-image-v1":{}}}
    obj.approved_catalogue_identity="sha256:"+"f"*64
    monkeypatch.setattr(consumer,"load_request",
        lambda root,rid:{"request":{"operation":"build.submit"},
                         "states":{"admission":"admitted"}})
    monkeypatch.setattr(consumer,"load_dispatch",lambda *args:None)
    seen=[]
    monkeypatch.setattr(consumer,"prepare_image_build_dispatch",
                        lambda root,rid,**kwargs:seen.append((rid,kwargs)))
    assert obj._advance_one_reviewed()=={"request_id":RID,"action":"prepared"}
    assert seen==[(RID,{
        "task_catalogue":obj.approved_generic_catalogue,
        "task_catalogue_identity":obj.approved_catalogue_identity,
    })]

def test_existing_blocked_or_uncertain_stage_is_not_reissued(tmp_path,monkeypatch):
    obj=setup(tmp_path)
    obj.approved_generic_catalogue={"schema":2,"tasks":{}}
    obj.approved_catalogue_identity="sha256:"+"f"*64
    monkeypatch.setattr(consumer,"load_request",
        lambda root,rid:{"request":{"operation":"build.submit"},
                         "states":{"admission":"admitted"}})
    monkeypatch.setattr(consumer,"load_dispatch",
                        lambda *args:{"phase":"prepared"})
    monkeypatch.setattr(consumer,"generic_status",
                        lambda *args:{"phase":"uncertain"})
    monkeypatch.setattr(consumer,"advance_generic",
                        lambda *args:pytest.fail("uncertain must not replay"))
    assert obj._advance_one_reviewed() is None
