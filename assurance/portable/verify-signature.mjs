import {verify, constants, createPublicKey} from 'node:crypto';
import {canonical, digest} from '../lib/beacon/engine.mjs';

const requireValue = (value, message) => { if (!value) throw new Error(message); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const identifier = value => typeof value === 'string' && /^[\x21-\x7e]{1,512}$/.test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const timestamp = value => {
 requireValue(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value), 'Invalid UTC timestamp');
 const time = Date.parse(value);
 requireValue(Number.isFinite(time) && new Date(time).toISOString() === value.replace(/Z$/, value.includes('.') ? 'Z' : '.000Z'), 'Invalid UTC timestamp');
 return time;
};

// These inputs must come from protected policy, never from an evidence uploader.
export function validateJob(job) {
 requireValue(object(job) && identifier(job.jobId) && hash(job.imageSha256), 'Invalid approved job identity or image digest');
 const maxAgeSeconds = job.maxAgeSeconds === undefined ? 86400 : job.maxAgeSeconds;
 requireValue(Number.isSafeInteger(maxAgeSeconds) && maxAgeSeconds > 0 && maxAgeSeconds <= 86400, 'Invalid maximum signature age (1–86400 seconds)');
 return {maxAgeSeconds};
}

export async function verifySignature(envelope, registry, evidence, approvedScope, expectedJob) {
 const {maxAgeSeconds} = validateJob(expectedJob);
 requireValue(object(envelope) && envelope.schema === 'beacon.signature.v1' && envelope.algorithm === 'RSASSA_PSS_SHA_256', 'Unsupported envelope');
 requireValue(identifier(envelope.keyId) && object(registry) && Object.hasOwn(registry, envelope.keyId), 'Signer is not authorized by the independent registry');
 const key = registry[envelope.keyId];
 requireValue(object(key) && (key.revoked === undefined || key.revoked === false) && key.role === 'evidence-signer', 'Signer is not authorized by the independent registry');
 const manifest = envelope.manifest;
 requireValue(object(manifest) && identifier(manifest.jobId) && ['imageSha256', 'evidenceSha256', 'scopeSha256'].every(field => hash(manifest[field])), 'Invalid signature manifest');
 requireValue(manifest.jobId === expectedJob.jobId && manifest.imageSha256 === expectedJob.imageSha256, 'Job identity or approved image mismatch');
 requireValue(Array.isArray(approvedScope) && approvedScope.length > 0, 'Invalid approved scope');
 requireValue(manifest.evidenceSha256 === await digest(evidence) && manifest.scopeSha256 === await digest(approvedScope), 'Artifact or scope binding mismatch');
 const time = timestamp(manifest.collectedAt), now = Date.now();
 requireValue(time <= now + 120000 && now - time <= maxAgeSeconds * 1000, 'Signature manifest is stale or future-dated');
 requireValue(typeof key.publicKeyPem === 'string' && key.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'), 'Registry must contain an SPKI public key');
 const publicKey = createPublicKey(key.publicKeyPem);
 requireValue(publicKey.asymmetricKeyType === 'rsa' && publicKey.asymmetricKeyDetails.modulusLength >= 2048, 'Signer must use RSA with at least 2048 bits');
 requireValue(typeof envelope.signature === 'string' && envelope.signature.length <= 16384, 'Invalid signature encoding');
 const signature = Buffer.from(envelope.signature, 'base64');
 requireValue(signature.toString('base64') === envelope.signature && signature.length === Math.ceil(publicKey.asymmetricKeyDetails.modulusLength / 8), 'Invalid signature encoding');
 requireValue(verify('sha256', Buffer.from(canonical(manifest)), {key:publicKey, padding:constants.RSA_PKCS1_PSS_PADDING, saltLength:32}, signature), 'Invalid signature');
 return {ok:true, jobId:expectedJob.jobId, keyId:envelope.keyId, limitation:'Signature and protected job binding verified. This repeatable check does not consume the job or independently authenticate collection execution.'};
}
