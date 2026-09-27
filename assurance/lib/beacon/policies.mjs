import {digest, canonical} from './engine.mjs';
export const MAPPER_SOURCE = 'https://github.com/kfcain/grc-pdf-mapper';
export const MAPPER_REVISION = 'c340144b3b4071bd569b5fd15669300ee666dc88';
const check=(v,m)=>{if(!v)throw new Error(m);};
const str=(v,n=4000)=>{check(typeof v==='string'&&v.length<=n,'Invalid mapper text');return v;};
const list=(v,n)=>{check(Array.isArray(v)&&v.length<=n,'Invalid mapper population');return v;};
const score=v=>{check(typeof v==='number'&&Number.isFinite(v)&&v>=0&&v<=1,'Invalid mapping confidence');return v;};
const hash=v=>{check(typeof v==='string'&&/^[a-f0-9]{64}$/.test(v),'Invalid source hash');return v;};
export async function normalizeMapperReport(payload){
 const r=payload?.report||payload;
 check(r&&typeof r==='object','Mapper report required');
 const docId=str(r.doc_id,160);check(/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(docId),'Use a stable document ID containing letters, numbers, dots, hyphens or underscores');
 const ingest=r.ingest;check(ingest&&typeof ingest==='object','Mapper ingest metadata required');
 const markdown=str(ingest.markdown,180000),sourceHash=hash(ingest.source_hash);
 const seen=new Set();
 const statements=list(r.statements,500).map(row=>{
  const s=row.statement;check(s&&typeof s==='object','Invalid statement');
  const id=str(s.statement_id,200);check(id&&!seen.has(id),'Duplicate or empty statement ID');seen.add(id);
  const span=s.source_span;check(span==null||(Array.isArray(span)&&span.length===2&&span.every(Number.isSafeInteger)&&span[0]>=0&&span[1]>=span[0]),'Invalid source span');
  check(s.page==null||(Number.isInteger(s.page)&&s.page>0),'Invalid page');
  return {statement:{statement_id:id,text:str(s.text,16000),heading_path:list(s.heading_path||[],30).map(v=>str(v,500)),page:s.page??null,source_span:span??null,strength:str(s.strength||'descriptive',40),statement_kind:str(s.statement_kind||'control_description',80),classification_confidence:score(s.classification_confidence??0),classification_reasons:list(s.classification_reasons||[],40).map(v=>str(v,1000))},mappings:list(row.mappings,500).map(m=>({framework:str(m.framework,160),control_id:str(m.control_id,160),title:str(m.title||'',2000),source:str(m.source,160),relationship:str(m.relationship||'related',100),confidence:score(m.confidence),url:typeof m.url==='string'&&/^https:\/\//.test(m.url)?str(m.url,2000):null}))};
 });
 const out={doc_id:docId,ingest:{source_hash:sourceHash,markdown,title:str(ingest.title||docId,500),engine:str(ingest.engine||'unknown',100),detected_format:str(ingest.detected_format||'unknown',100),pages_needing_ocr:list(ingest.pages_needing_ocr||[],10000).map(p=>{check(Number.isInteger(p)&&p>0,'Invalid OCR page');return p;})},statements};
 check(canonical(out).length<=240000,'Mapping report exceeds workspace limit; split the document into sections');return out;
}
export async function importPolicy(state,input,actor,now){
 const report=await normalizeMapperReport(input.report),reportHash=await digest(report);
 const policies=state.policies||[];check(policies.length<30,'Policy version limit reached');
 const previous=policies.filter(p=>p.docId===report.doc_id).at(-1);
 check(previous?.reportHash!==reportHash,'This document mapping version is already imported');
 const texts=r=>new Set((r?.statements||[]).map(s=>s.statement.text));
 const old=texts(previous?.report),current=texts(report);
 const out={id:crypto.randomUUID(),docId:report.doc_id,version:(previous?.version||0)+1,previousId:previous?.id||null,at:new Date(now).toISOString(),actor,report,reportHash,sourceHash:report.ingest.source_hash,reviews:[],provenance:'UNVERIFIED_DOCUMENT_REPORT',publicationEligible:false,change:{added:[...current].filter(t=>!old.has(t)),removed:[...old].filter(t=>!current.has(t)),reviewReset:!!previous},limitation:'Proposed documentation mappings. Neither policy text nor mapping approval establishes operating effectiveness or certification.'};
 state.policies=[...policies,out];return out;
}
export function reviewPolicy(state,input,actor,now){
 const policy=state.policies?.find(p=>p.id===input.policyId);check(policy,'Unknown policy version');
 const statement=policy.report.statements.find(s=>s.statement.statement_id===input.statementId);check(statement,'Unknown statement');
 check(Number.isInteger(input.mappingIndex)&&input.mappingIndex>=0&&input.mappingIndex<statement.mappings.length,'Unknown mapping');
 check(['accepted','rejected'].includes(input.decision),'Invalid mapping decision');
 const note=str(input.note,2000).trim();check(note.length>0,'Explain the mapping decision');
 if(input.claimId)check(state.claims.some(c=>c.id===input.claimId),'Unknown supporting claim');
 const out={id:crypto.randomUUID(),policyId:policy.id,statementId:input.statementId,mappingIndex:input.mappingIndex,decision:input.decision,note,claimId:input.claimId||null,actor,at:new Date(now).toISOString(),type:'provider_mapping_review'};
 policy.reviews.push(out);return out;
}

export function policyLinks(state,claimId){
 const latest=new Map();for(const p of state.policies||[])latest.set(p.docId,p);
 const links=[];
 for(const p of latest.values()){
  const decisions=new Map();for(const r of p.reviews)decisions.set(r.statementId+'\u0000'+r.mappingIndex,r);
  for(const r of decisions.values())if(r.decision==='accepted'&&r.claimId===claimId){
   const statement=p.report.statements.find(s=>s.statement.statement_id===r.statementId);
   links.push({policyId:p.id,docId:p.docId,version:p.version,sourceHash:p.sourceHash,statement:statement.statement.text,mapping:statement.mappings[r.mappingIndex],review:r});
  }
 }
 return links;
}
