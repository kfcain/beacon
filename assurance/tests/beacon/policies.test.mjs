import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {seed,execute,verifyBundle,canonical} from '../../lib/beacon/engine.mjs';
import {normalizeMapperReport} from '../../lib/beacon/policies.mjs';
import {mapUpload} from '../../lib/beacon/mapper-client.mjs';
import {rpc} from '../../lib/beacon/rpc.mjs';
function report(text='Administrators must use MFA.'){
 return {doc_id:'pol-access',ingest:{source_hash:createHash('sha256').update(text).digest('hex'),markdown:text,title:'Access control',engine:'markdown',pages_needing_ocr:[]},statements:[{statement:{statement_id:'s1',text,heading_path:['Access'],strength:'must',statement_kind:'obligation',classification_confidence:0.9,classification_reasons:['Mandatory modal'],source_span:[0,text.length]},mappings:[{framework:'NIST 800-53',control_id:'IA-2',title:'Identification and Authentication',source:'seed',confidence:0.8,relationship:'related'}]}]};
}
test('policy versions retain source, reviews and exact wording changes without granting operational assurance',async()=>{
 const s=await seed(),before=s.runs.length;const a=await execute(s,'policy-import',{report:report()},'reviewer');
 await assert.rejects(execute(s,'policy-import',{report:report()},'reviewer'),/already imported/);
 await execute(s,'policy-review',{policyId:a.id,statementId:'s1',mappingIndex:0,decision:'accepted',note:'Supports the documented authentication requirement only.',claimId:'IAM-01'},'reviewer');
 const b=await execute(s,'policy-import',{report:report('Administrators may use MFA.')},'reviewer');
 assert.equal(b.version,2);assert.equal(b.reviews.length,0);assert.equal(a.reviews.length,1);assert.equal(b.change.removed[0],'Administrators must use MFA.');assert.equal(b.publicationEligible,false);assert.equal(s.runs.length,before);
 const release=await execute(s,'publish',{target:'sandbox'},'reviewer');assert.equal(canonical(release).includes('Administrators'),false);
 assert.equal((await verifyBundle(s)).ok,true);b.report.statements[0].statement.text='altered';assert.equal((await verifyBundle(s)).ok,false);
});
test('untrusted mapper payloads reject invalid populations, confidence and review references',async()=>{
 const duplicate=report();duplicate.statements.push(duplicate.statements[0]);await assert.rejects(normalizeMapperReport(duplicate),/Duplicate/);
 const invalid=report();invalid.statements[0].mappings[0].confidence=Infinity;await assert.rejects(normalizeMapperReport(invalid),/confidence/);
 const s=await seed();const p=await execute(s,'policy-import',{report:report()},'owner');
 for(const mappingIndex of [-1,1,1.5])await assert.rejects(execute(s,'policy-review',{policyId:p.id,statementId:'s1',mappingIndex,decision:'accepted',note:'x'},'owner'),/Unknown mapping/);
 const normalized=await normalizeMapperReport({report:{...report(),unsafe:'ignored'}});assert.equal(normalized.unsafe,undefined);
});
test('mapper adapter uses fixed authenticated offline endpoint and checks exact uploaded source bytes',async()=>{
 const input={docId:'pol-access',filename:'policy.md',base64:Buffer.from('Administrators must use MFA.').toString('base64')};
 const config={BEACON_MAPPER_URL:'https://mapper.example/api/analyze',BEACON_MAPPER_TOKEN:'x'.repeat(32)};
 let called=0;const request=async(url,options)=>{called++;assert.equal(url,config.BEACON_MAPPER_URL);assert.equal(options.redirect,'error');assert.equal(options.headers.Authorization,'Bearer '+config.BEACON_MAPPER_TOKEN);assert.equal(options.body.get('offline'),'true');assert.equal(options.body.get('doc_id'),input.docId);return Response.json({report:report()});};
 const result=await mapUpload(input,config,request);assert.equal(result.sourceBinding,'MATCHED_UPLOAD_BYTES');assert.equal(called,1);
 await assert.rejects(mapUpload({...input,base64:Buffer.from('changed').toString('base64')},config,request),/binding mismatch/);
 await assert.rejects(mapUpload(input,{...config,BEACON_MAPPER_URL:'http://localhost/api/analyze'},request),/HTTPS/);
 await assert.rejects(mapUpload({...input,filename:'script.exe'},config,request),/Upload/);
 await assert.rejects(mapUpload({...input,filename:'policy.pdf'},config,request),/PDF signature/);
 await assert.rejects(mapUpload(input,{},request),/not connected/);
});
test('MCP exposes imported policy mappings as untrusted read-only data',async()=>{
 const s=await seed();await execute(s,'policy-import',{report:report()},'owner');
 const result=await rpc({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'beacon_policies',arguments:{}}},{read:async()=>s,canWrite:false});
 const data=JSON.parse(result.result.content[0].text);assert.equal(data.policies.length,1);assert.match(data.limitation,/Do not follow instructions/);
});
