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
    assert all(row['status']!='supporting_pass' for row in receipt['results'])
    with pytest.raises(BeaconError):capture_policy(settings,scope_id=scope.scope_id,root=root,path='../policy.json',commit=commit)


def _commit_policy(root,name,control_ref,scope_id):
    policy={'schema_version':1,'policy_id':name,'title':name,
        'people':[{'role':'security lead','name':'Security team'}],
        'process':[{'id':'review','summary':'The security lead reviews the activity quarterly.'}],
        'control_refs':[control_ref],'scope_refs':[scope_id]}
    raw=dumps(policy);(root/f'{name}.json').write_bytes(raw)
    subprocess.run(['git','-C',str(root),'add',f'{name}.json'],check=True)
    subprocess.run(['git','-C',str(root),'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-m',name],check=True,capture_output=True)
    commit=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    return {'path':f'{name}.json','commit':commit,'file_sha256':sha256_bytes(raw),'system_id':'access-service'}


def _two_policy_scope(settings,tmp_path,**params):
    root=tmp_path/'policy-repo';root.mkdir()
    subprocess.run(['git','init',str(root)],check=True,capture_output=True)
    access=_commit_policy(root,'access','IAC-02','two-policies')
    governance=_commit_policy(root,'governance','GOV-02','two-policies')
    body=new_scope_document('two-policies').canonical_body()
    body.update(schema_version=2,allowed_evidence_kinds=['policy'],boundary={'systems':['access-service']},parameters={
        'approved_rule_sha256':[row['rule_sha256'] for control in ('IAC-02','GOV-02') for row in rules_for(control)],
        'policy_sources':[access,governance],**params})
    return import_scope(settings,json.dumps(body)),root,access,governance


def test_newer_policy_for_another_control_does_not_mask_this_one(initialized,tmp_path):
    settings=load_settings();scope,root,access,governance=_two_policy_scope(settings,tmp_path)
    capture_policy(settings,scope_id=scope.scope_id,root=root,path=access['path'],commit=access['commit'])
    capture_policy(settings,scope_id=scope.scope_id,root=root,path=governance['path'],commit=governance['commit'])
    receipt=evaluate_control(settings,scope_id=scope.scope_id,control_ref='IAC-02')
    judged=[row for row in receipt['results'] if row['rule_sha256']]
    assert judged and all(row['status']=='needs_review' for row in judged), judged


class PerfectJudge:
    """Returns every probability at the code minimum. The result must stay advisory."""
    def judge(self,*,objective,rule,candidate):
        return {'status':'judged','choice':candidate['candidate_sha256'],'score':1.0,'noul':1.0,
                'choice_confidence':1.0,'score_confidence':1.0,'model':'test'}


def test_model_judgment_never_sets_a_supporting_result(initialized,tmp_path):
    settings=load_settings()
    scope,root,access,_=_two_policy_scope(settings,tmp_path,allow_external_judgment=True)
    capture_policy(settings,scope_id=scope.scope_id,root=root,path=access['path'],commit=access['commit'])
    receipt=evaluate_control(settings,scope_id=scope.scope_id,control_ref='IAC-02',judge=PerfectJudge())
    judged=[row for row in receipt['results'] if row['judgment']]
    assert judged
    for row in judged:
        assert row['status']=='needs_review'
        assert row['reasons']==['advisory_meets_thresholds','human_review_required']
    assert 'supporting_pass' not in receipt['summary']
    assert receipt['control_satisfied'] is False and receipt['assurance_claim'] is False
