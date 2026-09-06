#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {catalog,evaluate,snapshot,verifyBundle,fixture} from '../lib/beacon/engine.mjs';
import {repository} from './store.mjs';
import {verifySignature} from './verify-signature.mjs';
import {admitEvidence, initializeAdmissionLedger, readAdmissionReceipt} from './admission.mjs';
const [command,...args]=process.argv.slice(2);const option=k=>{const i=args.indexOf(k);if(i<0||!args[i+1]||args[i+1].startsWith('--'))throw new Error('Missing '+k);return args[i+1];};
try{
 if(command==='ledger-init'){
  initializeAdmissionLedger(option('--ledger'));console.log(JSON.stringify({initialized:true}));
 }else if(command==='receipt'){
  console.log(JSON.stringify(readAdmissionReceipt(option('--ledger'),option('--job-id')),null,2));
 }else if(command==='admit'){
  const read=k=>JSON.parse(readFileSync(option(k),'utf8'));
  const receipt=await admitEvidence({ledgerPath:option('--ledger'),envelope:read('--envelope'),registry:read('--registry'),evidence:read('--evidence'),scope:read('--scope'),job:read('--job'),claimId:option('--claim')});
  console.log(JSON.stringify(receipt,null,2));
 }else if(command==='evaluate'){
  const raw=JSON.parse(readFileSync(option('--evidence'),'utf8')),approved=JSON.parse(readFileSync(option('--scope'),'utf8'));const c=catalog.find(c=>c.id===option('--claim'));if(!c)throw new Error('Unknown claim');
  const result=await evaluate(c,raw,approved);
  if(args.includes('--require-live')){
   if(raw.mode!=='live'){result.status='ERROR';result.reasons.push('Live collection required');}
   try{const read=k=>JSON.parse(readFileSync(option(k),'utf8'));result.signatureVerification=await verifySignature(read('--envelope'),read('--registry'),raw,approved,read('--job'));}
   catch(e){result.status='ERROR';result.reasons.push('Production gate: '+e.message);}
  }
  result.assurance='Source provenance requires independent verification; a live label alone is not authority.';console.log(JSON.stringify(result,null,2));process.exitCode=result.status==='PASS'?0:2;
 }else if(command==='verify'){
  const result=await verifyBundle(JSON.parse(readFileSync(option('--bundle'),'utf8')));console.log(JSON.stringify(result,null,2));process.exitCode=result.ok?0:2;
 }else if(command==='status'||command==='reconcile'||command==='export'){
  const repo=repository(),owner=process.env.BEACON_WORKSPACE||'local-owner';try{const s=command==='reconcile'?(await repo.mutate(owner,'reconcile',{})).output:command==='export'?(await repo.read(owner)).state:await snapshot((await repo.read(owner)).state);console.log(JSON.stringify(s,null,2));}finally{repo.close();}
 }else throw new Error('Usage: cli.mjs evaluate --evidence FILE --scope FILE --claim ID [--require-live] | admit --ledger FILE --evidence FILE --scope FILE --claim ID --envelope FILE --registry FILE --job FILE | ledger-init --ledger FILE | receipt --ledger FILE --job-id ID | verify --bundle FILE | status | reconcile | export');
}catch(e){console.error(e.message);process.exitCode=2;}
