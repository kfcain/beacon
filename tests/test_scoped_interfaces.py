import json

import pytest
from fastapi.testclient import TestClient
from click.testing import CliRunner

from beacon.cli import main
from beacon.config import load_settings
from beacon.errors import BeaconError
from beacon.gui.app import create_app
from beacon.mcp.server import call_tool
from beacon.scope.store import init_scope
from beacon.workspace import seed_workspace


def test_web_rejects_cross_site_mutations_and_remote_host(initialized):
    client=TestClient(create_app())
    assert client.post('/api/push').status_code==403
    assert client.post('/api/push',headers={'X-Beacon-Request':'1','Origin':'https://attacker.invalid'}).status_code==403
    assert client.get('/api/system',headers={'Host':'attacker.invalid'}).status_code==400
    assert client.get('/').headers['content-security-policy'].startswith("default-src 'self'")


def test_configured_api_token_protects_reads_and_writes(initialized, monkeypatch):
    monkeypatch.setenv('BEACON_API_TOKEN','operator-test-secret')
    client=TestClient(create_app())
    assert client.get('/api/system').status_code==401
    assert client.get('/api/system',headers={'Authorization':'Bearer operator-test-secret'}).status_code==200
    assert client.post('/api/push',headers={'X-Beacon-Request':'1'}).status_code==401


def test_remote_allowed_host_requires_a_token(initialized, monkeypatch):
    monkeypatch.setenv('BEACON_ALLOWED_HOSTS','beacon.example.com')
    monkeypatch.delenv('BEACON_API_TOKEN',raising=False)
    with pytest.raises(BeaconError, match='BEACON_API_TOKEN'):
        create_app()
    monkeypatch.setenv('BEACON_API_TOKEN','operator-test-secret')
    client=TestClient(create_app(),base_url='http://beacon.example.com')
    assert client.get('/api/system').status_code==401


def test_non_ascii_authorization_is_rejected_not_an_error(initialized, monkeypatch):
    monkeypatch.setenv('BEACON_API_TOKEN','operator-test-secret')
    client=TestClient(create_app())
    assert client.get('/api/system',headers={'Authorization':'Bearer caf\u00e9'.encode('latin-1')}).status_code==401


def test_cli_web_and_mcp_share_scopes_and_objectives(initialized):
    settings=load_settings();init_scope(settings,'assessment');seed_workspace(settings)
    client=TestClient(create_app(),headers={'X-Beacon-Request':'1'})
    assert client.get('/api/scopes').json()['scopes'][0]['scope_id']=='assessment'
    cli=CliRunner().invoke(main,['objectives','--control','CRY-07'])
    assert cli.exit_code==0,cli.output
    mcp=call_tool('beacon_objectives',{'control_ref':'CRY-07'})
    web=client.get('/api/objectives?control=CRY-07').json()
    assert json.loads(cli.output)['objectives']==mcp['objectives']==web['objectives']
    for tool in ['beacon_collect','beacon_evaluate']:
        result=call_tool(tool,{'scope_id':'missing','live':'yes'})
        assert result['ok'] is False
    collection=client.post('/api/collect',json={'plugin':'aws.ebs.encryption','scope_id':'assessment','live':False})
    assert collection.status_code==200
    evaluated=call_tool('beacon_evaluate',{'scope_id':'assessment','control_ref':'CRY-07'})
    assert evaluated['control_satisfied'] is False
    assert len(evaluated['results'])==10
    assert client.get('/api/receipts?scope_id=assessment').json()['receipts']
