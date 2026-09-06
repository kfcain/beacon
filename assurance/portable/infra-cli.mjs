#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {repository} from './store.mjs';
import {infrastructureView} from '../lib/beacon/infrastructure.mjs';
const [command,value,stage='observed']=process.argv.slice(2);
let repo;
try{
 repo=repository();const owner=process.env.BEACON_WORKSPACE||'local-owner';
 if(command==='demo'){const result=await repo.mutate(owner,'infra-demo',{scenario:value||'drift'});console.log(JSON.stringify(result.output,null,2));}
 else if(command==='register'){const result=await repo.mutate(owner,'infra-register',{manifest:JSON.parse(readFileSync(value,'utf8'))});console.log(JSON.stringify(result.output,null,2));}
 else if(command==='import'){const result=await repo.mutate(owner,'infra-import',{observation:JSON.parse(readFileSync(value,'utf8'))});console.log(JSON.stringify(result.output,null,2));}
 else if(command==='status')console.log(JSON.stringify(infrastructureView((await repo.read(owner)).state),null,2));
 else if(command==='gate'){
  if(!['planned','observed'].includes(stage))throw new Error('Stage must be planned or observed');
  const boundary=infrastructureView((await repo.read(owner)).state).boundaries.find(b=>b.manifest.id===value);if(!boundary)throw new Error('Unknown boundary');const run=boundary[stage==='planned'?'planned':'observed'];if(!run)throw new Error('No observation for the requested stage');
  console.log(JSON.stringify({schema:'beacon.inventory.gate.v1',expected:boundary.manifest.resources,resources:run.observation.resources,ageSeconds:(Date.now()-Date.parse(run.observation.collectedAt))/1000,maxAgeSeconds:boundary.manifest.maxAgeHours*3600,context:{manifestHash:boundary.hash,observationHash:run.hash,stage,provenance:run.provenance}},null,2));
 }else throw new Error('Usage: infra-cli.mjs demo SCENARIO | register MANIFEST.json | import OBSERVATION.json | status | gate BOUNDARY_ID planned|observed');
}catch(e){console.error(e.message);process.exitCode=2;}finally{repo?.close();}
