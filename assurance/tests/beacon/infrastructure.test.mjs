import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {seed,execute,snapshot,verifyBundle} from '../../lib/beacon/engine.mjs';
import {infrastructureView} from '../../lib/beacon/infrastructure.mjs';
import {projectPlan} from '../../portable/terraform-project.mjs';
const now=Date.parse('2026-09-06T12:00:00Z');
test('declared inventory separates planned, runtime, missing and recovered states',async()=>{
 const s=await seed();await execute(s,'infra-demo',{scenario:'drift'},'operator',now);
 let b=infrastructureView(s,now).boundaries[0];assert.equal(b.plan.passing,5);assert.equal(b.runtime.passing,4);assert.equal(b.rows[0].drift,true);assert.equal(b.observed.provenance,'SIMULATED');
 await execute(s,'infra-demo',{scenario:'missing'},'operator',now+1000);b=infrastructureView(s,now+1000).boundaries[0];assert.equal(b.runtime.observed,4);assert.equal(b.rows[4].status,'UNKNOWN');
 await execute(s,'infra-demo',{scenario:'recovery'},'operator',now+2000);b=infrastructureView(s,now+2000).boundaries[0];assert.equal(b.runtime.passing,5);assert.equal(s.infrastructure.runs.length,6);
 assert.equal(infrastructureView(s,now+49*3600000).boundaries[0].rows[0].status,'STALE');
 assert.equal((await verifyBundle(s)).ok,true);s.infrastructure.runs[0].observation.resources[0].facts.encryptionAlgorithm='tampered';assert.equal((await verifyBundle(s)).ok,false);
});
test('unknown values and unsupported checks never become passing',async()=>{
 const s=await seed();await execute(s,'infra-demo',{scenario:'unknown'},'operator',now);let b=infrastructureView(s,now).boundaries[0];assert.equal(b.rows[0].status,'UNKNOWN');
 const m=structuredClone(b.manifest);m.id='unassessed';m.resources=[{id:'device-1',type:'corporate_endpoint',owner:'IT',checks:[]}];await execute(s,'infra-register',{manifest:m},'operator',now);b=infrastructureView(s,now).boundaries.find(b=>b.manifest.id==='unassessed');assert.equal(b.rows[0].status,'UNKNOWN');
});
test('imports enforce manifest binding, reject duplicate resources and keep provenance unverified',async()=>{
 const s=await seed();await execute(s,'infra-demo',{scenario:'healthy'},'operator',now);const base=s.infrastructure.runs[1].observation;
 await assert.rejects(execute(s,'infra-import',{observation:{...base,manifestHash:'a'.repeat(64)}},'operator',now),/manifest binding/);
 const duplicate=structuredClone(base);duplicate.resources.push(duplicate.resources[0]);await assert.rejects(execute(s,'infra-import',{observation:duplicate},'operator',now),/Duplicate/);
 const replay=structuredClone(base);replay.collectedAt=new Date(now-1000).toISOString();const r=await execute(s,'infra-import',{observation:replay,simulation:true},'operator',now);assert.equal(r.provenance,'UNVERIFIED_IMPORT');assert.notEqual(infrastructureView(s,now).boundaries[0].observed.id,r.id);
});
test('Terraform projection visits nested modules and strips unknown and sensitive values',()=>{
 const plan={format_version:'1.2',planned_values:{root_module:{resources:[{address:'aws_secretsmanager_secret.example',type:'aws_secretsmanager_secret',mode:'managed',values:{password:'DO_NOT_EXPORT'}}],child_modules:[{resources:[{address:'module.security.aws_kms_key.data',type:'aws_kms_key',mode:'managed',values:{enable_key_rotation:true,password:'DO_NOT_EXPORT'}}]}]}},resource_changes:[{address:'module.security.aws_kms_key.data',change:{after_unknown:{enable_key_rotation:true}}}]};
 let out=projectPlan(plan);assert.equal(out.length,2);assert.equal(out[1].facts.keyRotation,null);assert.equal(JSON.stringify(out).includes('DO_NOT_EXPORT'),false);
 plan.resource_changes[0].change={after_unknown:{},after_sensitive:{enable_key_rotation:true}};out=projectPlan(plan);assert.equal(out[1].facts.keyRotation,null);
 assert.throws(()=>projectPlan({...plan,errored:true}),/successful/);assert.throws(()=>projectPlan({...plan,format_version:'2.0'}),/format major/);
});
test('TUI reads the same snapshot and emits an inspectable read-only posture',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'beacon-tui-'));try{const s=await seed();await execute(s,'infra-demo',{scenario:'drift'},'operator',Date.now());const file=join(dir,'snapshot.json');writeFileSync(file,JSON.stringify(await snapshot(s)));const result=spawnSync('python3',['portable/tui.py','--snapshot',file,'--once'],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);const view=JSON.parse(result.stdout);assert.equal(view.infrastructure.length,5);assert.equal(view.infrastructure[0].status,'FAIL');assert.equal(view.claims.length,6);}finally{rmSync(dir,{recursive:true,force:true});}
});
