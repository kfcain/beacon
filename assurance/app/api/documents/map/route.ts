import {env} from 'cloudflare:workers';
import {mapUpload,mapperConfigured} from '@/lib/beacon/mapper-client.mjs';
export const dynamic='force-dynamic';
const reply=(body:any,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
let active=0;
export async function GET(req:Request){if(!req.headers.get('oai-authenticated-user-id'))return reply({error:'Authentication required'},401);return reply({configured:mapperConfigured(env),maxBytes:6291456,formats:['.md','.markdown','.txt','.pdf','.docx']});}
export async function POST(req:Request){
 if(!req.headers.get('oai-authenticated-user-id'))return reply({error:'Authentication required'},401);
 if(req.headers.get('Origin')&&req.headers.get('Origin')!==new URL(req.url).origin)return reply({error:'Origin rejected'},403);
 if(!req.headers.get('content-type')?.includes('application/json'))return reply({error:'JSON required'},415);
 if(!mapperConfigured(env))return reply({error:'Document mapper is not connected. Import a GRC PDF Mapper JSON report.'},503);
 if(active>=1)return reply({error:'Mapper busy. Retry shortly.'},429);
 active++;
 try{
  if(!req.body)return reply({error:'Upload required'},400);
  const reader=req.body.getReader(),decoder=new TextDecoder();let body='',size=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>8500000)return reply({error:'Upload exceeds 6 MiB'},413);body+=decoder.decode(value,{stream:true});}body+=decoder.decode();}finally{await reader.cancel();}
  return reply(await mapUpload(JSON.parse(body),env));
 }catch(e:any){return reply({error:e.message},400);}finally{active--;}
}
