import {registerContract,submitEvidence,registerTemplate,generateReport,reconcileVerification,verificationView,verifyVerification} from './verification.mjs';
import {importPolicy,reviewPolicy,policyLinks} from './policies.mjs';
import {registerManifest,importInventory,infrastructureDemo,infrastructureView} from './infrastructure.mjs';
import CR26 from './cr26.json' with {type:'json'};
// One credential-free domain engine for the GUI, API, CLI and MCP.
export const VERSION='0.2.0';
export const FRAMEWORKS=['FedRAMP 20x','FedRAMP Rev5','CMMC L2','ISO 27001','SOC 2','ISO 42001'];
export const SCENARIOS=['healthy','drift','missing-region','access-denied','stale','tampered'];
export const scope=['us-gov-west-1','us-gov-east-1'].map(region=>({partition:'aws-us-gov',account:'111111111111',region}));
export const catalog=[
 {id:'ENC-01',title:'New block storage defaults to encryption',domain:'Data protection',owner:'Infrastructure',source:'AWS EC2',operation:'GetEbsEncryptionByDefault',field:'EbsEncryptionByDefault',kind:'automated',summary:'Evaluate EBS encryption defaults across the approved account and Region population.',limitation:'Defaults only. Existing volumes, snapshots, data classification and key governance need separate evidence.',mappings:[['FedRAMP 20x','KSI-SVC-SIN'],['FedRAMP Rev5','SC-28'],['CMMC L2','3.13.16'],['ISO 27001','A.8.24'],['SOC 2','CC6.1']]},
 {id:'LOG-01',title:'Audit trails are actively logging',domain:'Detection & response',owner:'Security operations',source:'AWS CloudTrail',operation:'GetTrailStatus',field:'IsLogging',kind:'automated',summary:'Evaluate logging status for an explicitly selected trail in each approved Region.',limitation:'Does not establish organization-wide event coverage, selectors, retention, integrity or monitoring effectiveness.',mappings:[['FedRAMP Rev5','AU-12'],['CMMC L2','3.3.1'],['ISO 27001','A.8.15'],['SOC 2','CC7.2']]},
 {id:'IAM-01',title:'Root account MFA is enabled',domain:'Identity & access',owner:'Identity engineering',source:'AWS IAM',operation:'GetAccountSummary',field:'AccountMFAEnabled',kind:'automated',summary:'Evaluate the account-level root MFA indicator.',limitation:'Does not establish workforce MFA coverage, phishing resistance, break-glass controls or absence of root keys.',mappings:[['FedRAMP Rev5','IA-2'],['CMMC L2','3.5.3'],['ISO 27001','A.8.5'],['SOC 2','CC6.1']]},
 {id:'REC-01',title:'Recovery procedures work in practice',domain:'Resilience',owner:'Platform engineering',source:'Recovery exercise',kind:'manual',summary:'Review witnessed restoration results against approved recovery objectives.',limitation:'Requires an exercise record, measured outcomes, scope and reviewer conclusions. Configuration alone is insufficient.',mappings:[['FedRAMP Rev5','CP-4'],['ISO 27001','A.8.13'],['SOC 2','A1.3']]},
 {id:'CHG-01',title:'Production changes have accountable approval',domain:'Change management',owner:'Engineering delivery',source:'CI/CD evidence',kind:'manual',summary:'Review release decisions, change scope, test results and deployment identity.',limitation:'Build evidence requires provenance verification and population reconciliation before operating-effectiveness conclusions.',mappings:[['FedRAMP Rev5','CM-3'],['CMMC L2','3.4.3'],['ISO 27001','A.8.32'],['SOC 2','CC8.1']]},
 {id:'ACC-01',title:'Access reviews resolve inappropriate access',domain:'Identity & access',owner:'GRC engineering',source:'Access review',kind:'manual',summary:'Review the approved population, reviewer decisions and completed revocations.',limitation:'Requires accountable decisions and closure evidence, not only an identity export.',mappings:[['FedRAMP Rev5','AC-2'],['CMMC L2','3.1.1'],['ISO 27001','A.5.18'],['SOC 2','CC6.2']]}
];
export function canonical(x){
 if(x===null||['boolean','string'].includes(typeof x))return JSON.stringify(x);
 if(typeof x==='number'&&Number.isFinite(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(x&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 throw new Error('Unsupported JSON value');
}
export async function digest(x){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(x)));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');}
const sk=s=>[s.partition,s.account,s.region].join('/');
const assert=(v,m)=>{if(!v)throw new Error(m);};
const iso=v=>{assert(typeof v==='string'&&/(Z|[+-]\d{2}:\d{2})$/.test(v),'Timezone required');const t=Date.parse(v);assert(Number.isFinite(t),'Invalid timestamp');return t;};
export async function evaluate(claim,run,approvedScope,now=Date.now()){
 const r={status:'ERROR',expected:approvedScope.length,pass:0,fail:0,unknown:0,stale:0,coverage:0,reasons:[],evaluatedAt:new Date(now).toISOString(),validator:'beacon-validator/0.2.0',publicationEligible:false};
 try{
  assert(claim?.kind==='automated','Manual review required');assert(approvedScope.length>0&&new Set(approvedScope.map(sk)).size===approvedScope.length,'Invalid approved scope');
  assert(run.schema==='beacon.observation.v1'&&run.claimId===claim.id,'Unsupported schema or claim');assert(run.operation===claim.operation,'Unexpected source operation');assert(['simulation','live'].includes(run.mode),'Invalid mode');
  const start=iso(run.startedAt),end=iso(run.completedAt);assert(end>=start&&end<=now+120000,'Invalid collection interval');assert(Array.isArray(run.observations)&&run.observations.length<=1000,'Invalid population');
  const expected=new Set(approvedScope.map(sk)),seen=new Set();
  for(const row of run.observations){
   const k=sk(row.scope);assert(expected.has(k)&&!seen.has(k),'Unexpected or duplicate scope');seen.add(k);const t=iso(row.observedAt);assert(t>=start&&t<=end,'Observation outside collection interval');
   if(row.collectionStatus!=='complete'){r.unknown++;r.reasons.push(`${row.scope.region}: collection incomplete`);continue;}
   assert(row.sourceIdentity?.Account===row.scope.account&&row.sourceIdentity?.Arn?.startsWith(`arn:${row.scope.partition}:`)&&row.sourceIdentity?.Arn?.split(':')[4]===row.scope.account,'Source identity mismatch');assert(await digest(row.raw)===row.rawSha256,'Artifact hash mismatch');
   const v=claim.id==='IAM-01'?row.raw?.SummaryMap?.AccountMFAEnabled:row.raw?.[claim.field];assert(claim.id==='IAM-01'?(v===0||v===1):typeof v==='boolean','Unexpected source field type');
   if(now-t>(claim.maxAgeHours||24)*3600000){r.stale++;r.reasons.push(`${row.scope.region}: evidence expired`);continue;}
   if(v===true||v===1)r.pass++;else{r.fail++;r.reasons.push(`${row.scope.region}: assertion failed`);}
  }
  r.unknown+=expected.size-seen.size;if(expected.size!==seen.size)r.reasons.push('Approved population is incomplete');r.coverage=Math.round((r.pass+r.fail)/r.expected*100);
  r.status=r.fail?'FAIL':r.unknown?'UNKNOWN':r.stale?'STALE':'PASS';r.inputSha256=await digest(run);
 }catch(e){r.status='ERROR';r.reasons.push(e.message);}
 return r;
}
export async function fixture(claim,scenario='healthy',now=Date.now()){
 assert(SCENARIOS.includes(scenario),'Unknown scenario');const t=now-(scenario==='stale'?48*3600000:10000);
 const run={schema:'beacon.observation.v1',claimId:claim.id,mode:'simulation',operation:claim.operation,startedAt:new Date(t-2000).toISOString(),completedAt:new Date(t+2000).toISOString(),collector:'beacon-fixture/0.2.0',observations:[]};
 for(const s of claim.scope){const value=!(scenario==='drift'&&s.region===claim.scope.at(-1).region);const raw=claim.id==='IAM-01'?{SummaryMap:{AccountMFAEnabled:value?1:0}}:{[claim.field]:value};run.observations.push({scope:s,observedAt:new Date(t).toISOString(),collectionStatus:'complete',sourceIdentity:{Account:s.account,Arn:`arn:${s.partition}:sts::${s.account}:assumed-role/beacon-demo/session`},raw,rawSha256:await digest(raw)});}
 if(scenario==='missing-region')run.observations.pop();if(scenario==='access-denied')run.observations[0].collectionStatus='error';if(scenario==='tampered')run.observations[0].raw.injected=true;return run;
}
export async function appendEvent(s,actor,action,detail){const e={id:crypto.randomUUID(),at:new Date().toISOString(),actor,action,detail,previous:s.audit.at(-1)?.sha256||null};e.sha256=await digest(e);s.audit.push(e);}
export async function seed(actor='local-owner'){
 const s={schema:'beacon.workspace.v1',name:'Beacon reference organization',mode:'demonstration',claims:catalog.map(c=>({...c,scope:c.id==='IAM-01'?[scope[0]]:scope,maxAgeHours:24,implementation:'Partially Implemented',narrative:c.summary,parameters:'Approved reference account and Regions; daily freshness window.',inheritance:'Provider-operated demonstration. No inheritance asserted.',reviews:[]})),runs:[],documents:[],releases:[],audit:[],relays:[],settings:{cadenceHours:24,frameworks:FRAMEWORKS},lastReconciled:null};
 for(const [i,c] of s.claims.filter(c=>c.kind==='automated').entries()){const raw=await fixture(c,i===1?'drift':'healthy');s.runs.push({id:crypto.randomUUID(),claimId:c.id,at:raw.completedAt,raw,evaluation:await evaluate(c,raw,c.scope),provenance:'SIMULATED',review:null});}
 await appendEvent(s,actor,'workspace.created','Demonstration initialized. No certification asserted.');return s;
}
export function latest(s,id){return s.runs.filter(r=>r.claimId===id).at(-1);}
function earliestObservation(r){const times=[r.raw.completedAt,...(r.raw.observations||[]).map(x=>x.observedAt)].map(Date.parse).filter(Number.isFinite);return times.length?new Date(Math.min(...times)).toISOString():null;}
export async function snapshot(state,now=Date.now()){
 const s=structuredClone(state);s.infrastructureView=infrastructureView(state,now);s.verificationView=await verificationView(s,now);for(const c of s.claims){c.policyReferences=policyLinks(s,c.id);const r=latest(s,c.id);if(r)r.evaluation=await evaluate(c,r.raw,c.scope,now);c.current=r?{...r.evaluation,runId:r.id,at:earliestObservation(r),provenance:r.provenance,review:r.review}:{status:'UNKNOWN',coverage:0,expected:c.scope.length,reasons:['Evidence and review required']};}return s;
}
const text=(v,max=12000)=>{assert(typeof v==='string'&&v.trim().length>0&&v.length<=max,'Invalid text');return v.trim();};
export const ACTIONS=['run','import','review','document','publish','reconcile','configure','relay','requirement','policy-import','policy-review','infra-register','infra-import','infra-demo','verification-contract','verification-evidence','verification-template','verification-report','verification-reconcile'];
export async function execute(s,action,input,actor,now=Date.now()){
 assert(ACTIONS.includes(action),'Unknown action');assert(s.audit.length<5000&&s.runs.length<500,'Archive and rotate workspace before continuing');const c=input.claimId?s.claims.find(c=>c.id===input.claimId):null;
 if(['run','import','review','document','configure'].includes(action))assert(c,'Unknown claim');let out;
 if(action==='verification-contract')out=await registerContract(s,input,actor,now);
 if(action==='verification-evidence')out=await submitEvidence(s,input,actor,now);
 if(action==='verification-template')out=await registerTemplate(s,input,actor,now);
 if(action==='verification-report')out=await generateReport(s,input,actor,now);
 if(['verification-contract','verification-evidence','verification-reconcile'].includes(action)){const reconciliation=await reconcileVerification(s,actor,now);if(action==='verification-reconcile')out=reconciliation;}
 if(action==='infra-register')out=await registerManifest(s,input,actor,now);
 if(action==='infra-import')out=await importInventory(s,{observation:input.observation},actor,now);
 if(action==='infra-demo')out=await infrastructureDemo(s,input.scenario,actor,now);
 if(action==='policy-import')out=await importPolicy(s,input,actor,now);
 if(action==='policy-review')out=reviewPolicy(s,input,actor,now);
 if(action==='requirement'){
  assert(CR26.rows.some(r=>r.id===input.id),'Unknown requirement');
  out={id:input.id,implementation:text(input.implementation),verification:text(input.verification,8000),validation:text(input.validation,8000),owner:text(input.owner,200),at:new Date(now).toISOString(),actor,status:'DRAFT',independentVerification:'Pending',independentValidation:'Pending',sourceVersion:CR26.version};
  s.requirements ||= {};const versions=s.requirements[input.id]||[];out.version=versions.length+1;versions.push(out);s.requirements[input.id]=versions;
 }
 if(action==='run'||action==='import'){
  assert(c.kind==='automated','Manual evidence and review required');const raw=action==='run'?await fixture(c,input.scenario||'healthy',now):input.evidence;assert(raw&&canonical(raw).length<=250000,'Evidence missing or too large');
  out={id:crypto.randomUUID(),claimId:c.id,at:new Date(now).toISOString(),raw,evaluation:await evaluate(c,raw,c.scope,now),provenance:action==='run'?'SIMULATED':'UNVERIFIED_IMPORT',review:null};s.runs.push(out);
 }
 if(action==='review'){const r=latest(s,c.id);assert(r,'Collect before reviewing');out={id:crypto.randomUUID(),actor,at:new Date(now).toISOString(),conclusion:text(input.conclusion,4000),type:'provider',runId:r.id};r.review=out;c.reviews.push(out);}
 if(action==='configure'){
  assert(['Implemented','Partially Implemented','Planned','Alternative Implementation','Not Applicable'].includes(input.implementation),'Invalid implementation status');assert(Number.isInteger(input.maxAgeHours)&&input.maxAgeHours>=1&&input.maxAgeHours<=720,'Freshness must be 1–720 hours');
  c.narrative=text(input.narrative);c.parameters=text(input.parameters,4000);c.implementation=input.implementation;c.maxAgeHours=input.maxAgeHours;out=c;
 }
 if(action==='document'){
  const r=latest(s,c.id),current=(await snapshot(s,now)).claims.find(x=>x.id===c.id).current;
  out={id:crypto.randomUUID(),claimId:c.id,version:s.documents.filter(x=>x.claimId===c.id).length+1,at:new Date(now).toISOString(),title:`${c.id} · Implementation and evidence record`,status:'DRAFT',runId:r?.id||null,body:`# ${c.id}: ${c.title}\n\nDRAFT — provider review required.\n\n## Implementation\n${c.narrative}\n\nImplementation status: ${c.implementation}\n\n## Parameters\n${c.parameters}\n\n## Responsibility\n${c.inheritance}\n\n## Verification and validation\nTest: ${c.operation||'Manual assessment'}\nResult: ${current.status}\nProvenance: ${r?.provenance||'MISSING'}\nCoverage: ${current.coverage}% of approved population\nInput hash: ${r?.evaluation.inputSha256||'Unavailable'}\n\n## Limitations\n${c.limitation}\n\n## Provider review\n${r?.review?.conclusion||'Pending'}\n\n## Independent verification and validation\nPending. No independent conclusion asserted.\n\n## Supporting framework mappings\n${c.mappings.map(m=>'- '+m.join(': ')+' (supporting; mapping review required)').join('\n')}\n\nThis Beacon working record is not a complete FedRAMP package or certification determination.\n`};out.policyReferences=policyLinks(s,c.id);out.body+='\n## Reviewed policy references\n'+(out.policyReferences.length?out.policyReferences.map(p=>'- '+p.docId+' v'+p.version+' · source SHA-256 '+p.sourceHash+' · '+p.mapping.framework+' '+p.mapping.control_id+' · provider mapping review only').join('\n'):'No current reviewed policy references.');out.sha256=await digest(out.body);s.documents.push(out);
 }
 if(action==='publish'){
  assert(input.target==='sandbox','Production release requires verified provenance and organizational assessment controls. This build permits sandbox releases only.');const view=await snapshot(s,now);
  out={id:crypto.randomUUID(),version:s.releases.length+1,at:new Date(now).toISOString(),target:'sandbox',certification:'NOT_ASSERTED',claims:view.claims.map(c=>({id:c.id,title:c.title,status:c.current.status,coverage:c.current.coverage,provenance:c.current.provenance||'MISSING',at:c.current.at||null,freshUntil:c.current.at?new Date(Date.parse(c.current.at)+c.maxAgeHours*3600000).toISOString():null,limitation:c.limitation,mappings:c.mappings,reviewStatus:c.current.review?'Provider review recorded':'Pending',documentVersion:s.documents.filter(d=>d.claimId===c.id).at(-1)?.version||null}))};out.sha256=await digest(out);s.releases.push(out);
 }
 if(action==='reconcile'){s.lastReconciled=new Date(now).toISOString();const v=await snapshot(s,now);out={at:s.lastReconciled,results:v.claims.map(c=>({id:c.id,status:c.current.status,reasons:c.current.reasons})),documentsNeedingRevision:s.documents.filter(d=>d.runId!==latest(s,d.claimId)?.id).map(d=>d.id)};}
 if(action==='relay'){const r=s.releases.at(-1);assert(r,'Create a sandbox release first');out={id:crypto.randomUUID(),releaseId:r.id,releaseSha256:r.sha256,destination:'Beacon sandbox trust center',at:new Date(now).toISOString(),status:'DELIVERED',external:false};s.relays.push(out);}
 if(action==='reconcile'&&s.verification)out.verification=await reconcileVerification(s,actor,now);
 if(['policy-import','policy-review','verification-report'].includes(action)&&s.verification)await reconcileVerification(s,actor,now);
 await appendEvent(s,actor,action,`${c?.id||'workspace'} · ${out.id||out.at||'updated'}`);assert(canonical(s).length<3500000,'Workspace size limit reached');return out;
}
export async function verifyBundle(s){const errors=await verifyVerification(s);let prev=null;for(const e of s.audit||[]){const {sha256,...body}=e;if(body.previous!==prev||await digest(body)!==sha256)errors.push('Audit integrity failure');prev=sha256;}for(const r of s.runs||[]){const c=s.claims.find(c=>c.id===r.claimId);const v=await evaluate(c,r.raw,c.scope);if(v.status==='ERROR')errors.push(...v.reasons);if(r.evaluation.inputSha256&&await digest(r.raw)!==r.evaluation.inputSha256)errors.push('Run manifest mismatch');}for(const p of s.policies||[]){if(await digest(p.report)!==p.reportHash||p.sourceHash!==p.report.ingest.source_hash)errors.push('Policy report integrity failure');}for(const r of s.infrastructure?.runs||[]){if(await digest(r.observation)!==r.hash)errors.push('Infrastructure observation integrity failure');}for(const m of s.infrastructure?.manifests||[]){if(await digest(m.manifest)!==m.hash)errors.push('Infrastructure manifest integrity failure');}return {ok:!errors.length,errors,checkpoint:prev,assurance:'Hash integrity only. Signer trust and an external checkpoint are separate requirements.'};}
