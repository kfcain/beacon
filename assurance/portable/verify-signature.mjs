import {verify,constants,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {canonical,digest} from '../lib/beacon/engine.mjs';
export async function verifySignature(envelope,registry,evidence,approvedScope,expectedJob){
 const key=registry[envelope.keyId];if(!key||key.revoked||key.role!=='evidence-signer')throw new Error('Signer is not authorized by the independent registry');
 if(envelope.schema!=='beacon.signature.v1'||envelope.algorithm!=='RSASSA_PSS_SHA_256')throw new Error('Unsupported envelope');
 if(envelope.manifest.jobId!==expectedJob.jobId||envelope.manifest.imageSha256!==expectedJob.imageSha256)throw new Error('Job identity or approved image mismatch');
 if(envelope.manifest.evidenceSha256!==await digest(evidence)||envelope.manifest.scopeSha256!==await digest(approvedScope))throw new Error('Artifact or scope binding mismatch');
 const t=Date.parse(envelope.manifest.collectedAt);if(!Number.isFinite(t)||t>Date.now()+120000||Date.now()-t>(expectedJob.maxAgeSeconds||86400)*1000)throw new Error('Signature manifest is stale or future-dated');
 if(!verify('sha256',Buffer.from(canonical(envelope.manifest)),{key:key.publicKeyPem,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(envelope.signature,'base64')))throw new Error('Invalid signature');
 return {ok:true,jobId:expectedJob.jobId,keyId:envelope.keyId,limitation:'Trusted signer and job binding verified. The signer must independently authenticate collection execution.'};
}
