import {canonical,digest} from './engine.mjs';
import {REPORT_TEMPLATES} from './report-catalog.mjs';
const check=(condition,message)=>{if(!condition)throw new Error(message);};
const str=(v,max=300)=>{check(typeof v==='string'&&v.trim()&&v.length<=max,'Invalid or missing text');return v.trim();};
const list=(v,max=100)=>{check(Array.isArray(v)&&v.length>0&&v.length<=max,'Invalid or empty population');return v;};
const iso=v=>{check(typeof v==='string'&&/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(v)&&Number.isFinite(Date.parse(v)),'Invalid timestamp');return new Date(v).toISOString();};
const primitive=v=>v===null||typeof v==='string'||typeof v==='boolean'||typeof v==='number'&&Number.isFinite(v);
const unique=v=>{check(new Set(v).size===v.length,'Duplicate identifiers');return v;};
const state=s=>s.verification ||= {contracts:[],evidence:[],evaluations:[],reports:[],templates:[],alerts:[]};
const current=rows=>[...new Map(rows.map(r=>[r.key,r])).values()];
async function save(rows,key,body,actor,now){check(rows.length<500,'Verification history capacity reached; archive before continuing');const record={key,version:rows.filter(r=>r.key===key).length+1,body,actor:str(actor),at:new Date(now).toISOString()};record.id=crypto.randomUUID();record.hash=await digest(record);rows.push(record);return record;}
export async function registerContract(s,input,actor,now){
 const c=input.contract;check(c&&canonical(c).length<50000,'Invalid contract');
 const key=str(c.id),objectives=list(c.objectives,30).map(o=>{
  const assertions=(o.assertions||[]).map(a=>{check(['eq','gte','lte','present'].includes(a.op),'Unsupported assertion');check(a.op==='present'||primitive(a.value)&&a.value!==null,'Expected primitive assertion value');if(['gte','lte'].includes(a.op))check(typeof a.value==='number','Numeric threshold required');return {field:str(a.field),op:a.op,...(a.op==='present'?{}:{value:a.value})};});check(assertions.length<=20,'Too many assertions');
  return {id:str(o.id),title:str(o.title,1000),kind:str(o.kind),policyReference:o.policyReference?{documentId:str(o.policyReference.documentId),version:str(o.policyReference.version),locator:str(o.policyReference.locator,1000),sourceHash:str(o.policyReference.sourceHash,64),review:'UNVERIFIED_REFERENCE'}:null,subjects:unique(list(o.subjects,100).map(x=>str(x))),assertions,manualReviewRequired:true,mappings:list(o.mappings,20).map(m=>({framework:str(m.framework),edition:str(m.edition),reference:str(m.reference),relationship:'supporting-candidate'}))};
 });for(const o of objectives)if(o.policyReference)check(/^[a-f0-9]{64}$/.test(o.policyReference.sourceHash),'Invalid policy source hash');unique(objectives.map(o=>o.id));check(objectives.reduce((n,o)=>n+o.subjects.length,0)<=300,'Population exceeds 300 checks');check(Number.isInteger(c.maxAgeHours)&&c.maxAgeHours>0&&c.maxAgeHours<=8760,'Invalid freshness window');
 const existing=current(state(s).contracts).filter(r=>r.key!==key);check(existing.length<50&&existing.reduce((n,r)=>n+r.body.objectives.reduce((n,o)=>n+o.subjects.length,0),0)+objectives.reduce((n,o)=>n+o.subjects.length,0)<=1000,'Workspace contract population capacity reached');
 return save(state(s).contracts,key,{id:key,title:str(c.title),scopeId:str(c.scopeId),owner:str(c.owner),maxAgeHours:c.maxAgeHours,objectives,status:'DRAFT_CONTRACT',limitation:'Declared objectives only; mappings and sufficiency require review.'},actor,now);
}
export async function submitEvidence(s,input,actor,now){
 const e=input.evidence;check(e&&canonical(e).length<=150000,'Evidence envelope missing or too large');check(e.facts&&typeof e.facts==='object'&&!Array.isArray(e.facts),'Facts must be a flat object');
 check(Object.keys(e.facts).length<=100&&Object.entries(e.facts).every(([k,v])=>!['__proto__','constructor','prototype'].includes(k)&&k.length<=300&&primitive(v)&&(typeof v!=='string'||v.length<=12000)),'Invalid facts');
 const previous=current(state(s).evidence).find(r=>r.key===e.id);if(previous)check(['scopeId','subjectId','kind'].every(k=>previous.body[k]===e[k]),'Evidence identity cannot change scope, subject or kind');const observedAt=iso(e.observedAt);if(previous)check(observedAt>=previous.body.observedAt,'Evidence replay predates current version');check(Date.parse(observedAt)<=now,'Future evidence is not accepted');
 const collectionStatus=e.collectionStatus||'OK';check(['OK','ERROR','DENIED','INVALID'].includes(collectionStatus),'Invalid collection status');const sourceType=e.source?.type;check(['collector','document','human','llm','test','external-engine'].includes(sourceType),'Unknown source type');
 const content=e.content??null;check(content===null||typeof content==='string'||typeof content==='object','Invalid content');
 const contentHash=await digest(content);if(e.contentHash!==undefined)check(e.contentHash===contentHash,'Content digest mismatch');
 const body={id:str(e.id),scopeId:str(e.scopeId),subjectId:str(e.subjectId),kind:str(e.kind),collectionStatus,mediaType:str(e.mediaType||'application/json'),observedAt,source:{type:sourceType,name:str(e.source.name),version:str(e.source.version||'unspecified')},facts:structuredClone(e.facts),content,contentHash,provenance:'UNVERIFIED_IMPORT',assertionAuthority:'NONE',citations:(e.citations||[]).map(c=>({locator:str(c.locator,1000),sourceHash:str(c.sourceHash,64)}))};
 check(body.citations.length<=30&&body.citations.every(c=>/^[a-f0-9]{64}$/.test(c.sourceHash)),'Invalid source citations');
 if(e.period){body.period={start:iso(e.period.start),end:iso(e.period.end)};check(body.period.start<=body.period.end&&Date.parse(body.period.end)<=now,'Invalid evidence period');}
 return save(state(s).evidence,body.id,body,actor,now);
}
async function intact(record){const {hash,...body}=record;return await digest(body)===hash;}
export async function evaluateContract(s,key,now=Date.now()){
 const v=state(s),contract=current(v.contracts).find(c=>c.key===key);check(contract,'Unknown contract');const c=contract.body,contractValid=await intact(contract);const checks=[];
 for(const o of c.objectives)for(const subject of o.subjects){
  const matches=current(v.evidence).filter(e=>e.body.scopeId===c.scopeId&&e.body.subjectId===subject&&e.body.kind===o.kind).sort((a,b)=>Date.parse(b.body.observedAt)-Date.parse(a.body.observedAt)||Date.parse(b.at)-Date.parse(a.at));
  const policy=o.policyReference?(s.policies||[]).filter(p=>p.docId===o.policyReference.documentId).at(-1):null;const policyBinding=!o.policyReference?'NOT_LINKED':!policy?'MISSING':policy.sourceHash!==o.policyReference.sourceHash||String(policy.version)!==o.policyReference.version?'REVISED':'CURRENT_UNVERIFIED';
  const e=matches[0];let status='UNKNOWN',reasons=[];
  if(!contractValid){status='ERROR';reasons=['Contract integrity failure'];}
  else if(!e)reasons=['Expected evidence is missing'];
  else if(!await intact(e)){status='ERROR';reasons=['Evidence record integrity failure'];}
  else if(Date.parse(e.body.observedAt)>now){status='ERROR';reasons=['Evidence timestamp is in the future'];}
  else if(e.body.collectionStatus&&e.body.collectionStatus!=='OK'){status='ERROR';reasons=['Collection '+e.body.collectionStatus+'; operating state unknown'];}
  else if(now-Date.parse(e.body.observedAt)>c.maxAgeHours*3600000){status='STALE';reasons=['Evidence freshness expired'];}
  else if(!o.assertions.length)reasons=['No automated assertion; manual assessment required'];
  else {let missing=false,failed=false;for(const a of o.assertions){const value=Object.hasOwn(e.body.facts,a.field)?e.body.facts[a.field]:null;if(value===null){missing=true;reasons.push(`${a.field}: unresolved`);continue;}const pass=a.op==='present'||a.op==='eq'&&value===a.value||a.op==='gte'&&typeof value==='number'&&value>=a.value||a.op==='lte'&&typeof value==='number'&&value<=a.value;if(!pass){failed=true;reasons.push(`${a.field}: ${a.op} assertion failed`);}}status=failed?'FAIL':missing?'UNKNOWN':'PASS';}
  checks.push({objectiveId:o.id,title:o.title,subjectId:subject,kind:o.kind,status,reasons,evidenceId:e?.id||null,evidenceHash:e?.hash||null,sourceType:e?.body.source.type||null,provenance:e?.body.provenance||'MISSING',assessment:'REVIEW_REQUIRED',policyBinding,collectionStatus:e?.body.collectionStatus||null,policyReference:o.policyReference,mappings:o.mappings});
 }
 const status=checks.some(x=>x.status==='ERROR')?'ERROR':checks.some(x=>x.status==='FAIL')?'FAIL':checks.some(x=>x.status==='STALE')?'STALE':checks.some(x=>x.status==='UNKNOWN')?'UNKNOWN':'PASS';
 return {contractId:key,contractHash:contract.hash,scopeId:c.scopeId,evaluatedAt:new Date(now).toISOString(),configurationStatus:status,determination:'NOT_ASSESSED',publicationEligible:false,checks,expected:checks.length,passing:checks.filter(x=>x.status==='PASS').length,limitation:'Assertions test submitted facts. Source authenticity, semantics, period coverage and independent conclusions are not established.'};
}
export async function reconcileVerification(s,actor,now){const v=state(s),results=[];for(const c of current(v.contracts)){const result=await evaluateContract(s,c.key,now);const prior=current(v.evaluations).find(r=>r.key===c.key);const withoutTime=({evaluatedAt,...body})=>body;if(prior&&canonical(withoutTime(prior.body))===canonical(withoutTime(result)))results.push(prior);else results.push(await save(v.evaluations,c.key,result,actor,now));}v.lastReconciled=new Date(now).toISOString();const alerts=await correlate(s,results.map(r=>r.body),actor,now);return {id:crypto.randomUUID(),at:new Date(now).toISOString(),results,alerts};}
export function reportTemplates(s){return [...REPORT_TEMPLATES,...current(state(s).templates).map(t=>({...t.body,templateHash:t.hash}))];}
export async function registerTemplate(s,input,actor,now){const t=input.template;check(t&&canonical(t).length<30000,'Invalid template');const id=str(t.id);check(!REPORT_TEMPLATES.some(t=>t.id===id),'Built-in template IDs are reserved');const sections=unique(list(t.sections,40).map(x=>str(x)));check(sections.every(k=>!['__proto__','constructor','prototype'].includes(k)),'Reserved section name');return save(state(s).templates,id,{id,title:str(t.title),framework:str(t.framework),edition:str(t.edition),sections,source:'Customer-defined',status:'DRAFT_BLUEPRINT',schemaValidated:false},actor,now);}
export async function generateReport(s,input,actor,now){
 const template=reportTemplates(s).find(t=>t.id===input.templateId);check(template,'Unknown report template');const ids=unique(list(input.contractIds,30).map(x=>str(x)));const sections=input.sections||{};check(sections&&typeof sections==='object'&&!Array.isArray(sections)&&Object.keys(sections).every(k=>template.sections.includes(k)),'Unknown report section');check(canonical(sections).length<=60000,'Report text too large');for(const value of Object.values(sections))str(value,12000);
 const evaluations=[];for(const id of ids)evaluations.push(await evaluateContract(s,id,now));const scopes=unique([...new Set(evaluations.map(x=>x.scopeId))]);check(scopes.length===1,'Reports must use one explicit scope');
 const missing=template.sections.filter(k=>!sections[k]?.trim());const body={templateId:template.id,templateHash:await digest(template),title:template.title,framework:template.framework,edition:template.edition,scopeId:scopes[0],status:'DRAFT_NOT_FOR_SUBMISSION',schemaValidated:false,publicationEligible:false,sections,missingSections:missing,evaluations,source:template.source,reportingPeriod:input.reportingPeriod?{start:iso(input.reportingPeriod.start),end:iso(input.reportingPeriod.end)}:null,limitations:['Template coverage is a starting blueprint, not a completeness determination.','Narrative sections are user or model supplied and have not been verified.','No independent opinion, signature, certification or regulatory notification is generated.','Evidence timestamps do not establish continuous operation or sample completeness.']};
 if(body.reportingPeriod)check(body.reportingPeriod.start<=body.reportingPeriod.end&&Date.parse(body.reportingPeriod.end)<=now,'Invalid reporting period');
 body.markdown=`# ${body.title}\n\nDRAFT — NOT FOR SUBMISSION\n\nFramework: ${body.framework} · ${body.edition}\nScope: ${body.scopeId}\n\n`+template.sections.map(k=>`## ${k}\n\n${sections[k]||'[MISSING — owner input required]'}`).join('\n\n')+'\n\n## Evidence evaluation snapshot\n\n'+evaluations.map(e=>`${e.contractId}: ${e.configurationStatus}, ${e.passing}/${e.expected} assertions. Determination: ${e.determination}.\nContract hash: ${e.contractHash}\n`+e.checks.map(c=>`- ${c.objectiveId} / ${c.subjectId}: ${c.status}; evidence ${c.evidenceHash||'MISSING'}; provenance ${c.provenance}; review required.`).join('\n')).join('\n\n')+'\n\n## Limitations\n\n'+body.limitations.map(x=>'- '+x).join('\n');
 return save(state(s).reports,`${template.id}:${scopes[0]}`,body,actor,now);
}
export async function verificationView(s,now=Date.now()){
 const v=state(s),evaluations=[];for(const c of current(v.contracts))evaluations.push(await evaluateContract(s,c.key,now));
 const templates=reportTemplates(s),hashes=new Map();for(const t of templates)hashes.set(t.id,await digest(t));
 const reports=[];for(const r of v.reports){const integrityValid=await intact(r);reports.push({...r,integrityValid,needsRefresh:!integrityValid||hashes.get(r.body.templateId)!==r.body.templateHash||r.body.evaluations.some(old=>{const cur=evaluations.find(e=>e.contractId===old.contractId);return !cur||cur.contractHash!==old.contractHash||canonical(cur.checks)!==canonical(old.checks);})});}
 return {contracts:current(v.contracts),evidence:current(v.evidence),evaluations,reports,templates,historyCount:v.evaluations.length,alerts:current(v.alerts||[]),lastReconciled:v.lastReconciled||null,mode:'UNVERIFIED_DIAGNOSTICS'};
}
export async function verifyVerification(s){const v=s.verification;if(!v)return [];const errors=[];for(const k of ['contracts','evidence','evaluations','reports','templates','alerts'])for(const r of v[k]||[])if(!await intact(r))errors.push(`Verification ${k} integrity failure`);return errors;}

// Correlation is diagnostic. Recovery is observed, never an automatic compliance closure.
async function correlate(s,evaluations,actor,now){
 const v=state(s);v.alerts ||= [];const groups=new Map();
 for(const evaluation of evaluations)for(const c of evaluation.checks){
  const key=await digest({scope:evaluation.scopeId,subject:c.subjectId,kind:c.kind});
  const group=groups.get(key)||{scopeId:evaluation.scopeId,subjectId:c.subjectId,kind:c.kind,checks:[],affectedReports:[]};
  group.checks.push({...c,contractId:evaluation.contractId,contractHash:evaluation.contractHash});groups.set(key,group);
 }
 const changed=[];
 for(const [key,g] of groups){
  const prior=current(v.alerts).find(a=>a.key===key);const abnormal=g.checks.filter(c=>c.status!=='PASS'||['MISSING','REVISED'].includes(c.policyBinding));
  if(!abnormal.length&&!prior)continue;
  const categories=[...new Set(abnormal.flatMap(c=>[...(c.policyBinding==='REVISED'?['POLICY_REFERENCE_CHANGED']:c.policyBinding==='MISSING'?['POLICY_REFERENCE_MISSING']:[]),...(c.status==='PASS'?[]:[c.status==='FAIL'?'ASSERTION_MISMATCH':c.status==='STALE'?'EVIDENCE_STALE':c.status==='UNKNOWN'?'EVIDENCE_GAP':c.collectionStatus&&c.collectionStatus!=='OK'?'COLLECTION_ERROR':'VALIDATOR_ERROR'])]))];
  g.affectedReports=v.reports.filter(r=>r.body.scopeId===g.scopeId&&r.body.evaluations.some(e=>g.checks.some(c=>c.contractId===e.contractId))).map(r=>r.id);
  const body={...g,categories,state:abnormal.length?'OPEN':'OBSERVED_RECOVERY',assessment:'REVIEW_REQUIRED',externalDelivery:'NOT_CONFIGURED',limitation:'Shared scope, subject and evidence kind establish correlation, not causal proof. Imported facts and policy references require verification.'};
  if(!prior||canonical(prior.body)!==canonical(body))changed.push(await save(v.alerts,key,body,actor,now));
 }
 return changed;
}
