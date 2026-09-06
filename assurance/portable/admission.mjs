import {DatabaseSync} from 'node:sqlite';
import {openSync, closeSync, lstatSync, constants as fsConstants} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {catalog, evaluate, digest} from '../lib/beacon/engine.mjs';
import {verifySignature} from './verify-signature.mjs';

// The ledger directory and database belong to the admission service, not collectors.
// Initialization is explicit so a missing ledger cannot silently reset replay state.
export function initializeAdmissionLedger(path) {
 const fd = openSync(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
 closeSync(fd);
 const db = new DatabaseSync(path);
 try {
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
   CREATE TABLE admissions (
    job_id TEXT PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE,
    accepted_at TEXT NOT NULL, receipt TEXT NOT NULL
   ); PRAGMA user_version=1;`);
 } finally { db.close(); }
}

function openLedger(path) {
 const stat = lstatSync(path);
 if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error('Admission ledger must be a private regular file');
 const db = new DatabaseSync(path);
 try {
  db.exec('PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL;');
  if (db.prepare('PRAGMA user_version').get().user_version !== 1) throw new Error('Admission ledger is not initialized');
  return db;
 } catch (error) { db.close(); throw error; }
}

export async function admitEvidence({ledgerPath, envelope, registry, evidence, scope, job, claimId}) {
 // Copy once before asynchronous hashing to keep evaluated and recorded inputs identical.
 const input = structuredClone({envelope, registry, evidence, scope, job, claimId});
 if (input.evidence?.mode !== 'live') throw new Error('Admission requires live collection');
 const claim = catalog.find(item => item.id === input.claimId);
 if (!claim || claim.kind !== 'automated') throw new Error('Unknown automated claim');
 const signature = await verifySignature(input.envelope, input.registry, input.evidence, input.scope, input.job);
 const evaluation = await evaluate(claim, input.evidence, input.scope);
 if (evaluation.status !== 'PASS') throw new Error('Admission rejected: ' + evaluation.status + ': ' + evaluation.reasons.join('; '));
 const receipt = {
  schema:'beacon.admission.v1', id:randomUUID(), jobId:input.job.jobId,
  acceptedAt:new Date().toISOString(), claimId:input.claimId, keyId:signature.keyId,
  evidenceSha256:await digest(input.evidence), scopeSha256:await digest(input.scope),
  imageSha256:input.job.imageSha256, envelopeSha256:await digest(input.envelope),
  policySha256:await digest({job:input.job, scope:input.scope, claimId:input.claimId, registry:input.registry}),
  evaluation, publicationEligible:false,
  limitation:'Local admission receipt, not a signed external witness or certification decision.'
 };
 const db = openLedger(ledgerPath);
 try {
  // One atomic INSERT enforces a single winner across independent processes.
  const result = db.prepare('INSERT INTO admissions VALUES (?,?,?,?) ON CONFLICT(job_id) DO NOTHING')
   .run(receipt.jobId, receipt.id, receipt.acceptedAt, JSON.stringify(receipt));
  if (result.changes !== 1) throw new Error('Job has already been admitted; replay rejected');
  return receipt;
 } finally { db.close(); }
}

export function readAdmissionReceipt(ledgerPath, jobId) {
 const db = openLedger(ledgerPath);
 try {
  const row = db.prepare('SELECT receipt FROM admissions WHERE job_id=?').get(jobId);
  if (!row) throw new Error('No admission receipt for this job');
  return JSON.parse(row.receipt);
 } finally { db.close(); }
}
