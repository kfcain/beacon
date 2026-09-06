#!/usr/bin/env node
// A configuration gate. A passing result is not source authentication or release approval.
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const [binary,approvedBinaryHash,policyPath,inputPath]=process.argv.slice(2);
let output={schema:'beacon.opa-result.v1',status:'ERROR',provenance:'UNVERIFIED_INPUT',publicationEligible:false};
try{
 if(!/^[a-f0-9]{64}$/.test(approvedBinaryHash||''))throw new Error('Usage: opa-gate.mjs OPA_BINARY APPROVED_BINARY_SHA256 POLICY.rego INPUT.json');
 if(sha(readFileSync(binary))!==approvedBinaryHash)throw new Error('OPA binary digest mismatch');
 const input=readFileSync(inputPath);if(input.length>1000000)throw new Error('Gate input exceeds 1 MB');
 const parsed=JSON.parse(input);if(parsed.schema!=='beacon.inventory.gate.v1')throw new Error('Unexpected gate input');
 const policy=readFileSync(policyPath);output={...output,inputSha256:sha(input),policySha256:sha(policy),binarySha256:approvedBinaryHash,stage:parsed.context?.stage||'unspecified',manifestHash:parsed.context?.manifestHash||null,observationHash:parsed.context?.observationHash||null};
 const raw=execFileSync(binary,['eval','--format=json','--strict-builtin-errors','--data',policyPath,'--stdin-input','data.beacon.inventory'],{input,timeout:10000,maxBuffer:1000000,stdio:['pipe','pipe','pipe']});
 const evaluation=JSON.parse(raw).result?.[0]?.expressions?.[0]?.value;if(!evaluation||typeof evaluation.allow!=='boolean')throw new Error('OPA did not return a complete decision');
 output={...output,status:evaluation.allow?'PASS':'FAIL',denials:evaluation.deny||[],evaluatedAt:new Date().toISOString(),limitation:'Technical configuration assertion only; signed source provenance and release authority are separate gates.'};
}catch(error){output.error=error.message;}
console.log(JSON.stringify(output,null,2));process.exitCode=output.status==='PASS'?0:2;
