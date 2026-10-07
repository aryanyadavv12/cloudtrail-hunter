import sys
import types
from src.cloudtrail import lookup_recent_events

def test_cloudtrail_lookup_with_fake_boto3(monkeypatch):
    class Paginator:
        def paginate(self, **kwargs):
            assert kwargs["MaxResults"] == 2
            return [{"Events": [{"EventId": "1"}, {"EventId": "2"}]}]
    class Client:
        def get_paginator(self, name):
            assert name == "lookup_events"
            return Paginator()
    class Session:
        def __init__(self, profile_name=None, region_name=None):
            assert region_name == "us-east-1"
        def client(self, name):
            assert name == "cloudtrail"
            return Client()
    fake = types.SimpleNamespace(Session=Session)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    assert len(lookup_recent_events(region="us-east-1", max_results=2)) == 2
