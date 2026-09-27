import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign, constants} from 'node:crypto';
import {mkdtempSync, rmSync, writeFileSync, existsSync, chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {canonical, digest, seed, fixture} from '../../lib/beacon/engine.mjs';
import {verifySignature} from '../../portable/verify-signature.mjs';
import {admitEvidence, initializeAdmissionLedger, readAdmissionReceipt} from '../../portable/admission.mjs';
const exec = promisify(execFile);
const keys = generateKeyPairSync('rsa', {modulusLength:2048});
const registry = {trusted:{role:'evidence-signer',publicKeyPem:keys.publicKey.export({type:'spki',format:'pem'})}};
async function input(scenario='healthy', jobId='job-one') {
 const claim=(await seed()).claims[0], evidence=await fixture(claim,scenario); evidence.mode='live';
 const job={jobId,imageSha256:'a'.repeat(64),maxAgeSeconds:3600};
 const manifest={jobId,imageSha256:job.imageSha256,evidenceSha256:await digest(evidence),scopeSha256:await digest(claim.scope),collectedAt:new Date().toISOString()};
 const envelope={schema:'beacon.signature.v1',keyId:'trusted',algorithm:'RSASSA_PSS_SHA_256',manifest,signature:sign('sha256',Buffer.from(canonical(manifest)),{key:keys.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64')};
 return {envelope,registry:structuredClone(registry),evidence,scope:claim.scope,job,claimId:claim.id};
}
const verify = i => verifySignature(i.envelope,i.registry,i.evidence,i.scope,i.job);
function directory(t) { const dir=mkdtempSync(join(tmpdir(),'beacon-admission-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir; }

test('verification rejects malformed approval, revoked signer, weak key and noncanonical signature',async()=>{
 const valid=await input();
 for(const job of [{}, {...valid.job,jobId:''}, {...valid.job,imageSha256:'bad'}, ...[null,0,-1,Infinity,NaN,'3600',86401].map(maxAgeSeconds=>({...valid.job,maxAgeSeconds}))]) {
  await assert.rejects(verify({...valid,job}),/Invalid/);
 }
 for(const revoked of [true,'false',0]) {const i=structuredClone(valid);i.registry.trusted.revoked=revoked;await assert.rejects(verify(i),/not authorized/);}
 const inherited={...valid,registry:Object.create(valid.registry)};await assert.rejects(verify(inherited),/not authorized/);
 const weak=generateKeyPairSync('rsa',{modulusLength:1024});const i=structuredClone(valid);i.registry.trusted.publicKeyPem=weak.publicKey.export({type:'spki',format:'pem'});await assert.rejects(verify(i),/2048/);
 for(const suffix of ['\n','!'])await assert.rejects(verify({...valid,envelope:{...valid.envelope,signature:valid.envelope.signature+suffix}}),/encoding/);
 for(const collectedAt of ['2026-02-30T00:00:00Z','2026-01-01','2999-01-01T00:00:00Z'])await assert.rejects(verify({...valid,envelope:{...valid.envelope,manifest:{...valid.envelope.manifest,collectedAt}}}),/timestamp|future-dated/);
 assert.equal((await verify(valid)).ok,true);assert.equal((await verify(valid)).ok,true);
});

test('admission persists exact receipt and rejects replay after reopening',async t=>{
 const ledgerPath=join(directory(t),'admission.sqlite');initializeAdmissionLedger(ledgerPath);
 const i=await input();const first=await admitEvidence({...i,ledgerPath});
 assert.equal(first.evaluation.status,'PASS');assert.equal(first.publicationEligible,false);
 assert.deepEqual(readAdmissionReceipt(ledgerPath,i.job.jobId),first);
 await assert.rejects(admitEvidence({...i,ledgerPath}),/replay rejected/);
 assert.throws(()=>initializeAdmissionLedger(ledgerPath),/EEXIST/);
});

test('invalid or incomplete evidence does not consume a job',async t=>{
 const ledgerPath=join(directory(t),'admission.sqlite');initializeAdmissionLedger(ledgerPath);
 for(const scenario of ['drift','missing-region','access-denied','stale','tampered'])await assert.rejects(admitEvidence({...await input(scenario),ledgerPath}),/Admission rejected/);
 const simulation=await input();simulation.evidence.mode='simulation';await assert.rejects(admitEvidence({...simulation,ledgerPath}),/live collection/);
 const forged=await input();forged.envelope.signature='AAAA';await assert.rejects(admitEvidence({...forged,ledgerPath}),/encoding/);
 assert.equal((await admitEvidence({...await input(),ledgerPath})).evaluation.status,'PASS');
});

test('missing, uninitialized or publicly readable ledger fails closed',async t=>{
 const ledgerPath=join(directory(t),'admission.sqlite');const i=await input();
 await assert.rejects(admitEvidence({...i,ledgerPath}),/ENOENT/);assert.equal(existsSync(ledgerPath),false);
 writeFileSync(ledgerPath,'',{mode:0o600});await assert.rejects(admitEvidence({...i,ledgerPath}),/not initialized/);
 rmSync(ledgerPath);initializeAdmissionLedger(ledgerPath);chmodSync(ledgerPath,0o644);await assert.rejects(admitEvidence({...i,ledgerPath}),/private regular file/);
});

test('two CLI processes race for one job: one receipt, one rejection',async t=>{
 const dir=directory(t),ledgerPath=join(dir,'admission.sqlite');initializeAdmissionLedger(ledgerPath);const i=await input();
 const args=['portable/cli.mjs','admit','--ledger',ledgerPath,'--claim',i.claimId];
 for(const field of ['evidence','scope','envelope','registry','job']) {const path=join(dir,field+'.json');writeFileSync(path,JSON.stringify(i[field]));args.push('--'+field,path);}
 const results=await Promise.allSettled([exec(process.execPath,args),exec(process.execPath,args)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
 const failure=results.find(r=>r.status==='rejected');assert.equal(failure.reason.code,2);assert.match(failure.reason.stderr,/replay rejected/);
 const success=JSON.parse(results.find(r=>r.status==='fulfilled').value.stdout);
 const receipt=await exec(process.execPath,['portable/cli.mjs','receipt','--ledger',ledgerPath,'--job-id',i.job.jobId]);assert.deepEqual(JSON.parse(receipt.stdout),success);
});
