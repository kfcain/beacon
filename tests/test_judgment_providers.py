"""Transport contract tests: no model credentials, charges, or live AWS calls."""
import json
from types import SimpleNamespace

import boto3
from botocore.stub import Stubber, ANY
import pytest

from beacon.assurance.bedrock import BedrockJudge, SYSTEM
from beacon.assurance.jev import JevJudge, judgment_supports
from beacon.errors import BeaconError

CANDIDATE = {"candidate_sha256":"a"*64, "content":"The security lead owns the access review."}
RULE = {"assertion":"The policy assigns access review ownership.", "score_min":1.0,"noul_min":1.0,"confidence_min":1.0}
OBJECTIVE = {"ao_id":"IAC-02_A05", "statement":"Responsibility is assigned."}


def test_jev_actual_sdk_request_and_probabilities(monkeypatch):
    sdk = pytest.importorskip("typesafe_sdk")
    http = pytest.importorskip("httpx2")
    monkeypatch.setenv("BEACON_JEV_ENABLED", "1")
    sent = []
    def handler(request):
        data = json.loads(request.content); sent.append(data)
        assert all(not key.endswith('_min') for key in data["state"]["rule"])
        assert data["questions"]["noul"]["type"] == "noul"
        rubric = data["questions"]["score"]["criteria"]
        assert len(rubric) == 2
        return http.Response(200, json={"model":"jev-pinned-test", "usage":{"input_tokens":100,"output_tokens":20}, "answers":{
            "choice":{"type":"choice","choice":"a"*64,"confidence":1.0,"probabilities":{"a"*64:1.0,"no_match":0.0}},
            "score":{"type":"score","score":1.0,"confidence":1.0,"legend":{str(i):v for i,v in enumerate(rubric)},"probabilities":{"0":0.0,"1":1.0}},
            "noul":{"type":"noul","noul":1.0}}})
    with sdk.TypeSafeClient(api_key="test-key",model="jev-pinned-test",transport=http.MockTransport(handler)) as client:
        judge = JevJudge(model="jev-pinned-test", client=client)
        result=judge.judge(objective=OBJECTIVE,rule=RULE,candidate=CANDIDATE)
    assert len(sent)==1
    assert result["status"]=="judged", result
    assert judgment_supports(result,CANDIDATE["candidate_sha256"],RULE)
    assert result["model"]=="jev-pinned-test" and result["request_sha256"]


@pytest.mark.parametrize("value", [float('nan'),float('inf'),-1,2,True,"1",None])
def test_untrusted_score_never_crosses_code_gate(value):
    result={"status":"judged","choice":"a"*64,"score":value,"noul":1.0,"choice_confidence":1.0,"score_confidence":1.0}
    assert not judgment_supports(result,"a"*64,RULE)


def test_judges_require_explicit_enablement(monkeypatch):
    monkeypatch.delenv("BEACON_JEV_ENABLED",raising=False)
    monkeypatch.delenv("BEACON_BEDROCK_ENABLED",raising=False)
    with pytest.raises(BeaconError): JevJudge(model="test")
    with pytest.raises(BeaconError): BedrockJudge(scope=SimpleNamespace(parameters={}))


@pytest.mark.parametrize("failure", ["valid", "fabricated_quote", "truncated", "timeout", "invalid_json"])
def test_bedrock_converse_is_bounded_and_advisory(monkeypatch, failure):
    monkeypatch.setenv("BEACON_BEDROCK_ENABLED","1")
    scope=SimpleNamespace(parameters={"allow_external_judgment":True,"bedrock_model_id":"test-model","bedrock_region":"us-east-1"})
    client=boto3.client("bedrock-runtime",region_name="us-east-1",aws_access_key_id="testing",aws_secret_access_key="testing")
    review={"disposition":"supported","rationale":"An owner is documented.","quotes":[CANDIDATE["content"]]}
    if failure=="fabricated_quote":review["quotes"]=["The audit committee approved it."]
    text=json.dumps(review) if failure!="invalid_json" else 'not json'
    expected={"modelId":"test-model","system":[{"text":SYSTEM}],"messages":ANY,"inferenceConfig":{"maxTokens":1200}}
    with Stubber(client) as stub:
        if failure=="timeout":stub.add_client_error("converse",service_error_code="ModelTimeoutException",expected_params=expected)
        else:stub.add_response("converse", {"output":{"message":{"role":"assistant","content":[{"text":text}]}},
            "stopReason":"max_tokens" if failure=="truncated" else "end_turn",
            "usage":{"inputTokens":40,"outputTokens":20,"totalTokens":60},"metrics":{"latencyMs":1}}, expected)
        result=BedrockJudge(scope=scope,client=client).judge(objective=OBJECTIVE,rule=RULE,candidate=CANDIDATE)
        stub.assert_no_pending_responses()
    assert result["status"] == ("advisory" if failure=="valid" else "abstain")
    assert not judgment_supports(result,CANDIDATE["candidate_sha256"],RULE)
