import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createApplication} from '../portable/server.mjs';
import {repository} from '../portable/store.mjs';
import {mapUpload} from '../lib/beacon/mapper-client.mjs';
const raw=JSON.parse(readFileSync(process.argv[2],'utf8'));
const directory=mkdtempSync(join(tmpdir(),'beacon-mapper-api-')),repo=repository(join(directory,'workspace.sqlite'));
const token='mapper-integration-operator-token-123456789',reader='mapper-integration-reader-token-123456789';
const server=createApplication({repo,tokens:[{token,workspace:'test',role:'operator'},{token:reader,workspace:'test',role:'reader'}]});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const base='http://127.0.0.1:'+server.address().port;
const headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'};
try{
 const mapped=await mapUpload({docId:raw.doc_id,filename:'policy.md',base64:Buffer.from(raw.ingest.markdown).toString('base64')},{BEACON_MAPPER_URL:'https://mapper.example/api/analyze',BEACON_MAPPER_TOKEN:token},async()=>Response.json({report:raw}));
 let response=await fetch(base+'/api/beacon',{headers});let state=await response.json();
 response=await fetch(base+'/api/beacon',{method:'POST',headers,body:JSON.stringify({action:'policy-import',input:{report:mapped.report},revision:state.revision})});assert.equal(response.status,200);state=await response.json();
 assert.equal(state.output.report.statements.length,raw.statements.length);assert.ok(state.output.report.statements.some(s=>s.mappings.length));
 const policy=state.output,statement=policy.report.statements.find(s=>s.mappings.length);
 response=await fetch(base+'/api/beacon',{method:'POST',headers,body:JSON.stringify({action:'policy-review',revision:state.revision,input:{policyId:policy.id,statementId:statement.statement.statement_id,mappingIndex:0,decision:'accepted',note:'Test mapping review only.',claimId:'IAM-01'}})});assert.equal(response.status,200);
 state=await response.json();assert.equal(state.state.claims.find(c=>c.id==='IAM-01').policyReferences.length,1);
 response=await fetch(base+'/api/documents/map',{method:'POST',headers:{...headers,Authorization:'Bearer '+reader},body:'{}'});assert.equal(response.status,403);
 response=await fetch(base+'/api/documents/map',{method:'POST',headers,body:'{}'});assert.equal(response.status,503);
 response=await fetch(base+'/api/mcp',{method:'POST',headers:{...headers,Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'beacon_policies',arguments:{}}})});assert.equal(response.status,200);const mcp=await response.json();assert.equal(JSON.parse(mcp.result.content[0].text).policies[0].reviews.length,1);
 console.log('Actual mapper report: upload binding, authenticated import, review, claim link, reader denial, disconnected-service gate and MCP passed.');
}finally{await new Promise(resolve=>server.close(resolve));repo.close();rmSync(directory,{recursive:true,force:true});}
