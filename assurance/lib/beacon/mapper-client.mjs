import {normalizeMapperReport} from './policies.mjs';
export const MAX_DOCUMENT_BYTES=6*1024*1024;
export function mapperConfigured(config){return typeof config.BEACON_MAPPER_URL==='string'&&typeof config.BEACON_MAPPER_TOKEN==='string'&&config.BEACON_MAPPER_TOKEN.length>=32;}
export async function mapUpload(input,config,fetcher=fetch){
 if(!mapperConfigured(config))throw new Error('Document mapper is not connected. Import a GRC PDF Mapper JSON report or configure the private mapper service.');
 const url=new URL(config.BEACON_MAPPER_URL);
 if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search)throw new Error('Mapper requires a fixed HTTPS endpoint');
 if(typeof input.docId!=='string'||!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}$/.test(input.docId))throw new Error('A stable document ID is required');
 const suffix=typeof input.filename==='string'?input.filename.toLowerCase().match(/\.(md|markdown|txt|pdf|docx)$/)?.[0]:null;
 if(!suffix)throw new Error('Upload Markdown, text, PDF or DOCX');
 if(typeof input.base64!=='string'||input.base64.length>Math.ceil(MAX_DOCUMENT_BYTES/3)*4)throw new Error('Document exceeds 6 MiB');
 let decoded;try{decoded=atob(input.base64);}catch{throw new Error('Invalid document encoding');}
 if(!decoded.length||decoded.length>MAX_DOCUMENT_BYTES||btoa(decoded)!==input.base64)throw new Error('Invalid document encoding');
 const bytes=Uint8Array.from(decoded,c=>c.charCodeAt(0));
 if(suffix==='.pdf'&&!decoded.startsWith('%PDF-'))throw new Error('Invalid PDF signature');
 if(suffix==='.docx'&&!decoded.startsWith('PK\x03\x04'))throw new Error('Invalid DOCX signature');
 const form=new FormData();form.set('file',new Blob([bytes]),'document'+suffix);form.set('doc_id',input.docId);form.set('offline','true');form.set('format','json');
 const response=await fetcher(url.href,{method:'POST',headers:{Authorization:'Bearer '+config.BEACON_MAPPER_TOKEN},body:form,redirect:'error',signal:AbortSignal.timeout(60000)});
 if(!response.ok)throw new Error('Mapper extraction failed; check service health and converter availability');
 if(!response.body)throw new Error('Empty mapper response');
 const reader=response.body.getReader(),decoder=new TextDecoder();let body='',size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>4*1024*1024)throw new Error('Mapper report is too large');body+=decoder.decode(value,{stream:true});}body+=decoder.decode();}finally{await reader.cancel();}
 const report=await normalizeMapperReport(JSON.parse(body));
 const hash=await crypto.subtle.digest('SHA-256',bytes);const sourceHash=[...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,'0')).join('');
 if(report.doc_id!==input.docId||report.ingest.source_hash!==sourceHash)throw new Error('Mapper source binding mismatch');
 return {report,sourceBinding:'MATCHED_UPLOAD_BYTES',limitation:'Source hash binds the upload. Mapping conclusions still require review.'};
}
