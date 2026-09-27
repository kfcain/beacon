import {canonical,digest} from './engine.mjs';
export const INFRA_CHECKS=[
 {id:'S3-KMS',type:'aws_s3_bucket_server_side_encryption_configuration',title:'Bucket defaults use an identified KMS key',fields:['encryptionAlgorithm','kmsKeyArn'],mappings:[['NIST 800-53 Rev5','SC-28'],['CMMC L2 Rev2','3.13.11']],limitation:'Configuration only; key ownership, approved cryptographic modules and existing object encryption need additional tests.'},
 {id:'S3-VERSION',type:'aws_s3_bucket_versioning',title:'Bucket versioning is enabled',fields:['versioning'],mappings:[['NIST 800-53 Rev5','CP-9']],limitation:'Does not establish successful recovery or retention sufficiency.'},
 {id:'KMS-ROTATE',type:'aws_kms_key',title:'Key rotation is enabled',fields:['keyRotation'],mappings:[['NIST 800-53 Rev5','SC-12']],limitation:'Key rotation is one supporting configuration fact.'},
 {id:'LAMBDA-TRACE',type:'aws_lambda_function',title:'Lambda tracing is active',fields:['tracing'],mappings:[['NIST 800-53 Rev5','SI-4']],limitation:'Does not demonstrate detection coverage or incident response effectiveness.'},
 {id:'API-LOG',type:'aws_api_gateway_stage',title:'API stage has an access-log destination',fields:['logging'],mappings:[['NIST 800-53 Rev5','AU-12'],['CMMC L2 Rev2','3.3.1']],limitation:'A configured destination does not prove events arrive or remain complete.'}
];
const check=(v,m)=>{if(!v)throw new Error(m);};
const text=(v,n=200)=>{check(typeof v==='string'&&v.trim()&&v.length<=n,'Invalid infrastructure text');return v;};
const identifier=v=>{text(v);check(/^[a-zA-Z0-9_.:-]+$/.test(v),'Invalid identifier');return v;};
const iso=v=>{check(typeof v==='string'&&/(Z|[+-]\d{2}:\d{2})$/.test(v)&&Number.isFinite(Date.parse(v)),'Invalid timestamp');return v;};
export async function registerManifest(s,input,actor,now){
 const m=input.manifest;check(m?.schema==='beacon.infrastructure.manifest.v1','Unsupported manifest');
 check(Array.isArray(m.resources)&&m.resources.length>0&&m.resources.length<=300,'Declare 1–300 expected resources');
 const seen=new Set(),resources=m.resources.map(r=>{const id=text(r.id,500);check(!seen.has(id),'Duplicate expected resource');seen.add(id);text(r.type);check(Array.isArray(r.checks)&&r.checks.length<=10&&new Set(r.checks).size===r.checks.length,'Declare checks explicitly (empty means unassessed)');for(const id of r.checks)check(INFRA_CHECKS.some(c=>c.id===id&&c.type===r.type),'Check is not supported for this resource type');return {id,type:r.type,owner:text(r.owner),checks:r.checks};});
 check(Number.isInteger(m.maxAgeHours)&&m.maxAgeHours>=1&&m.maxAgeHours<=168,'Freshness must be 1–168 hours');
 const manifest={schema:m.schema,id:identifier(m.id),name:text(m.name),provider:text(m.provider),account:text(m.account),region:text(m.region),environment:text(m.environment),repository:text(m.repository),maxAgeHours:m.maxAgeHours,resources};
 const hash=await digest(manifest);s.infrastructure||={manifests:[],runs:[]};check(s.infrastructure.manifests.length<100,'Manifest history limit reached');
 const prior=s.infrastructure.manifests.filter(x=>x.manifest.id===manifest.id).at(-1);check(prior?.hash!==hash,'Manifest already registered');
 const out={id:crypto.randomUUID(),manifest,hash,version:(prior?.version||0)+1,actor,at:new Date(now).toISOString()};s.infrastructure.manifests.push(out);return out;
}
export async function importInventory(s,input,actor,now){
 const x=input.observation;check(x?.schema==='beacon.infrastructure.observation.v1','Unsupported inventory schema');
 const m=s.infrastructure?.manifests.filter(m=>m.manifest.id===x.manifestId).at(-1);check(m&&x.manifestHash===m.hash,'Current approved manifest binding required');
 check(['planned','observed'].includes(x.stage),'Stage must be planned or observed');const at=iso(x.collectedAt);check(Date.parse(at)<=now+120000,'Future observation rejected');
 check(Array.isArray(x.resources)&&x.resources.length<=500,'Invalid resource population');
 const seen=new Set(),fields=new Set(INFRA_CHECKS.flatMap(c=>c.fields));
 const resources=x.resources.map(r=>{const id=text(r.id,500);check(!seen.has(id),'Duplicate observed resource');seen.add(id);text(r.type);check(['complete','error'].includes(r.collectionStatus),'Collection status required');const facts={};check(r.facts&&typeof r.facts==='object'&&!Array.isArray(r.facts),'Facts required');for(const [key,value] of Object.entries(r.facts)){check(fields.has(key),'Unsupported fact; do not upload raw Terraform values');check(value===null||typeof value==='boolean'||(typeof value==='string'&&value.length<=500),'Invalid fact type');facts[key]=value;}return {id,type:r.type,collectionStatus:r.collectionStatus,facts};});
 check(typeof x.sourceSha256==='string'&&/^[a-f0-9]{64}$/.test(x.sourceSha256),'Source SHA-256 required');
 if(x.stage==='planned')check(typeof x.sourceRevision==='string'&&/^[a-f0-9]{40}$/.test(x.sourceRevision),'Full source commit required');
 const normalized={schema:x.schema,manifestId:x.manifestId,manifestHash:x.manifestHash,stage:x.stage,collectedAt:at,sourceSha256:x.sourceSha256,sourceRevision:x.sourceRevision||null,resources};
 const hash=await digest(normalized);check(!s.infrastructure.runs.some(r=>r.hash===hash),'Observation already imported');check(s.infrastructure.runs.length<200,'Inventory history limit reached');
 const out={id:crypto.randomUUID(),observation:normalized,hash,actor,at:new Date(now).toISOString(),provenance:input.simulation===true?'SIMULATED':'UNVERIFIED_IMPORT'};
 // The caller cannot promote an imported observation to trusted evidence.
 s.infrastructure.runs.push(out);return out;
}
function assertion(id,f){
 if(id==='S3-KMS')return f.encryptionAlgorithm==='aws:kms'&&typeof f.kmsKeyArn==='string'&&/^arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:\d{12}:key\/[a-zA-Z0-9-]+$/.test(f.kmsKeyArn);
 if(id==='S3-VERSION')return f.versioning==='Enabled';
 if(id==='KMS-ROTATE')return f.keyRotation===true;
 if(id==='LAMBDA-TRACE')return f.tracing==='Active';
 if(id==='API-LOG')return typeof f.logging==='string'&&f.logging.startsWith('arn:')&&f.logging.includes(':logs:');
 return false;
}
export function evaluateInventory(manifest,observation,now=Date.now()){
 const expected=manifest.resources;const actual=new Map((observation?.resources||[]).map(r=>[r.id,r]));
 const stale=!!observation&&now-Date.parse(observation.collectedAt)>manifest.maxAgeHours*3600000;
 const rows=expected.map(r=>{const got=actual.get(r.id);const results=r.checks.map(id=>{const c=INFRA_CHECKS.find(c=>c.id===id);let status='UNKNOWN',reason='No observation for expected resource';if(got){if(got.type!==r.type){status='ERROR';reason='Resource type mismatch';}else if(got.collectionStatus!=='complete'){reason='Collector reported an error';}else if(c.fields.some(k=>got.facts[k]===null||got.facts[k]===undefined)){reason='Required fact is unknown or omitted';}else if(stale){status='STALE';reason='Evidence freshness window expired';}else{status=assertion(id,got.facts)?'PASS':'FAIL';reason=status==='PASS'?'Observed facts satisfy this assertion':'Observed facts do not satisfy this assertion';}}return {id,title:c.title,status,reason,mappings:c.mappings,limitation:c.limitation};});const order=['ERROR','FAIL','UNKNOWN','STALE','PASS'];return {...r,checks:results,status:order.find(s=>results.some(r=>r.status===s))||'UNKNOWN'};});
 const unmanaged=[...actual.values()].filter(r=>!expected.some(e=>e.id===r.id)).map(r=>({id:r.id,type:r.type}));
 return {rows,unmanaged,expected:expected.length,observed:rows.filter(r=>actual.has(r.id)).length,passing:rows.filter(r=>r.status==='PASS').length,coverage:Math.round(rows.filter(r=>actual.has(r.id)).length/expected.length*100),complete:rows.every(r=>r.status==='PASS')&&!unmanaged.length,limitation:'Passing assertions do not establish a framework requirement or authenticated source provenance.'};
}
export function infrastructureView(s,now=Date.now()){
 const i=s.infrastructure||{manifests:[],runs:[]},latest=new Map();for(const m of i.manifests)latest.set(m.manifest.id,m);
 const boundaries=[...latest.values()].map(m=>{const runs=i.runs.filter(r=>r.observation.manifestHash===m.hash).sort((a,b)=>Date.parse(a.observation.collectedAt)-Date.parse(b.observation.collectedAt));const planned=runs.filter(r=>r.observation.stage==='planned').at(-1),observed=runs.filter(r=>r.observation.stage==='observed').at(-1);const plan=evaluateInventory(m.manifest,planned?.observation,now),runtime=evaluateInventory(m.manifest,observed?.observation,now);return {...m,planned,observed,plan,runtime,rows:runtime.rows.map(r=>({...r,plannedStatus:plan.rows.find(p=>p.id===r.id).status,drift:plan.rows.find(p=>p.id===r.id).status==='PASS'&&r.status==='FAIL'}))};});
 return {boundaries,runCount:i.runs.length,expected:boundaries.reduce((n,b)=>n+b.runtime.expected,0),observed:boundaries.reduce((n,b)=>n+b.runtime.observed,0),passing:boundaries.reduce((n,b)=>n+b.runtime.passing,0),unmanaged:boundaries.reduce((n,b)=>n+b.runtime.unmanaged.length,0),scope:'Declared boundaries only; undiscovered accounts and systems are not counted.'};
}
export async function infrastructureDemo(s,scenario,actor,now){
 check(['healthy','drift','missing','unknown','stale','recovery'].includes(scenario),'Unknown infrastructure scenario');
 const resources=INFRA_CHECKS.map((c,i)=>({id:(i===0?'module.storage.':'')+c.type+'.capstone',type:c.type,owner:i<3?'Platform engineering':'Application engineering',checks:[c.id]}));
 const manifest={schema:'beacon.infrastructure.manifest.v1',id:scenario==='stale'?'capstone-demo-stale':'capstone-demo',name:scenario==='stale'?'Acme Health · expired evidence simulation':'Acme Health · capstone simulation',provider:'AWS',account:'111111111111',region:'us-east-1',environment:'Training',repository:'kfcain/cgep-capstone',maxAgeHours:24,resources};
 let m=s.infrastructure?.manifests.filter(m=>m.manifest.id===manifest.id).at(-1);if(!m)m=await registerManifest(s,{manifest},actor,now);
 const facts=[{encryptionAlgorithm:'aws:kms',kmsKeyArn:'arn:aws:kms:us-east-1:111111111111:key/demo-key'},{versioning:'Enabled'},{keyRotation:true},{tracing:'Active'},{logging:'arn:aws:logs:us-east-1:111111111111:log-group:demo'}];
 const base={schema:'beacon.infrastructure.observation.v1',manifestId:manifest.id,manifestHash:m.hash,sourceSha256:await digest({scenario,now}),sourceRevision:'ae185730f85b20dc456a2d0e8915133015a47dc2',resources:resources.map((r,i)=>({id:r.id,type:r.type,collectionStatus:'complete',facts:facts[i]}))};
 await importInventory(s,{observation:{...base,stage:'planned',collectedAt:new Date(now).toISOString()},simulation:true},actor,now);
 const runtime=structuredClone(base);if(scenario==='drift')runtime.resources[0].facts.encryptionAlgorithm='AES256';if(scenario==='missing')runtime.resources.pop();if(scenario==='unknown')runtime.resources[0].facts.kmsKeyArn=null;
 // A separate boundary demonstrates stale observations without replacing newer history.
 const at=now-(scenario==='stale'?48*3600000:0);
 const run=await importInventory(s,{observation:{...runtime,stage:'observed',collectedAt:new Date(at).toISOString()},simulation:true},actor,now);
 return {id:run.id,manifestId:manifest.id,scenario,result:evaluateInventory(manifest,run.observation,now)};
}
