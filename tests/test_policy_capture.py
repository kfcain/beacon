import json
import subprocess

import pytest

from beacon.assurance.evaluation import evaluate_control, rules_for
from beacon.assurance.policy_capture import capture_policy
from beacon.canonical import dumps, sha256_bytes
from beacon.config import load_settings
from beacon.crypto.witness import load_records
from beacon.errors import BeaconError
from beacon.scope.store import import_scope, new_scope_document


def test_policy_capture_reads_approved_commit_not_working_tree(initialized,tmp_path):
    settings=load_settings();root=tmp_path/'policy-repo';root.mkdir()
    subprocess.run(['git','init',str(root)],check=True,capture_output=True)
    policy={'schema_version':1,'policy_id':'access-policy','title':'Access policy',
        'people':[{'role':'security lead','name':'Security team'}],
        'process':[{'id':'review','summary':'The security lead reviews access quarterly.'}],
        'control_refs':['IAC-02'],'scope_refs':['policy-assessment']}
    raw=dumps(policy);(root/'policy.json').write_bytes(raw)
    subprocess.run(['git','-C',str(root),'add','policy.json'],check=True)
    subprocess.run(['git','-C',str(root),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-m','policy'],check=True,capture_output=True)
    commit=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    body=new_scope_document('policy-assessment').canonical_body()
    body.update(schema_version=2,allowed_evidence_kinds=['policy'],boundary={'systems':['access-service']},parameters={
        'approved_rule_sha256':[row['rule_sha256'] for row in rules_for('IAC-02')],
        'policy_sources':[{'path':'policy.json','commit':commit,'file_sha256':sha256_bytes(raw),'system_id':'access-service'}]})
    scope=import_scope(settings,json.dumps(body))
    (root/'policy.json').write_text('{"unreviewed":"working tree"}')
    result=capture_policy(settings,scope_id=scope.scope_id,root=root,path='policy.json',commit=commit)
    stored=json.loads((settings.evidence_dir/f"{result['evidence_id']}.json").read_bytes())
    assert stored['content'].encode()==raw
    assert stored['git_commit']==commit
    receipt=evaluate_control(settings,scope_id=scope.scope_id,control_ref='IAC-02')
    assert receipt['summary']['needs_review']==2
    assert receipt['control_satisfied'] is False
    with pytest.raises(BeaconError):capture_policy(settings,scope_id=scope.scope_id,root=root,path='../policy.json',commit=commit)
