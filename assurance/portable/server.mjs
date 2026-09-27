#!/usr/bin/env node
import {createServer} from 'node:http';
import {timingSafeEqual,randomBytes,createHash} from 'node:crypto';
import {readFileSync,existsSync} from 'node:fs';
import {resolve,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {repository} from './store.mjs';
import {snapshot,verifyBundle} from '../lib/beacon/engine.mjs';
import {mapUpload,mapperConfigured} from '../lib/beacon/mapper-client.mjs';
import {rpc} from '../lib/beacon/rpc.mjs';
const hash=x=>createHash('sha256').update(x).digest();
export function createApplication({repo,tokens,publicOrigin='http://127.0.0.1:8787',assets=resolve('portable/dist'),trustConsumer=null,mapperConfig=process.env}){
 if(!Array.isArray(tokens)||!tokens.length||tokens.some(t=>typeof t.token!=='string'||t.token.length<32||!t.workspace||!['reader','operator'].includes(t.role)))throw new Error('Configure BEACON_TOKENS_JSON with strong tokens, workspace IDs and reader/operator roles');
 const sessions=new Map();let activeMappings=0;
 function identity(req){const auth=req.headers.authorization?.replace(/^Bearer /,'');const cookie=req.headers.cookie?.match(/(?:^|; )beacon_session=([a-f0-9]+)/)?.[1];const session=cookie?sessions.get(cookie):null;if(session&&session.expires>Date.now())return session.identity;if(auth)return tokens.find(t=>timingSafeEqual(hash(auth),hash(t.token)));return null;}
 const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin'};
 const send=(res,status,body,extra={})=>{res.writeHead(status,{...headers,'Content-Type':'application/json',...extra});res.end(typeof body==='string'?body:JSON.stringify(body));};
 async function readBody(req,limit=270000){let text='';for await(const chunk of req){text+=chunk;if(Buffer.byteLength(text)>limit)throw new Error('Request too large');}return text;}
 const server=createServer(async(req,res)=>{
  try{
   const url=new URL(req.url,publicOrigin),origin=req.headers.origin;
   if(origin&&origin!==publicOrigin)return send(res,403,{error:'Origin rejected'});
   if(req.method==='GET'&&url.pathname==='/healthz')return send(res,200,{ok:true,service:'beacon'});
   if(req.method==='POST'&&url.pathname==='/session'){
    if(!req.headers['content-type']?.includes('application/json'))return send(res,415,{error:'JSON required'});
    const {token}=JSON.parse(await readBody(req));if(typeof token!=='string')return send(res,401,{error:'Invalid token'});const user=tokens.find(t=>timingSafeEqual(hash(token),hash(t.token)));if(!user)return send(res,401,{error:'Invalid token'});
    if(sessions.size>1000)for(const [k,v] of sessions)if(v.expires<Date.now())sessions.delete(k);
    if(sessions.size>1000)return send(res,429,{error:'Session limit reached'});
    const key=randomBytes(32).toString('hex');sessions.set(key,{identity:user,expires:Date.now()+3600000});return send(res,200,{ok:true},{'Set-Cookie':`beacon_session=${key}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600${publicOrigin.startsWith('https:')?'; Secure':''}`});
   }
   if(req.method==='GET'&&url.pathname==='/login'){const body=readFileSync(new URL('./login.html',import.meta.url));return send(res,200,body.toString(),{'Content-Type':'text/html'});}
   const user=identity(req);if(!user){if(!url.pathname.startsWith('/api/')){res.writeHead(302,{Location:'/login'});return res.end();}return send(res,401,{error:'Authentication required'});}
   const actor=user.actor||user.workspace;const canWrite=user.role==='operator';
   if(url.pathname==='/api/documents/map'){
    if(req.method==='GET')return send(res,200,{configured:mapperConfigured(mapperConfig),maxBytes:6291456,formats:['.md','.markdown','.txt','.pdf','.docx']});
    if(req.method!=='POST')return send(res,405,{error:'Method not allowed'});
    if(!canWrite)return send(res,403,{error:'Operator role required'});
    if(!req.headers['content-type']?.includes('application/json'))return send(res,415,{error:'JSON required'});
    if(!mapperConfigured(mapperConfig))return send(res,503,{error:'Document mapper is not connected. Import a GRC PDF Mapper JSON report.'});
    if(activeMappings>=2)return send(res,429,{error:'Mapper busy. Retry shortly.'});
    activeMappings++;try{return send(res,200,await mapUpload(JSON.parse(await readBody(req,8500000)),mapperConfig));}finally{activeMappings--;}
   }
   if(req.method==='GET'&&url.pathname==='/api/beacon'){
    const {state,revision}=await repo.read(user.workspace);return send(res,200,url.searchParams.get('view')==='bundle'?state:url.searchParams.get('view')==='verify'?await verifyBundle(state):{state:await snapshot(state),revision});
   }
   if(req.method==='GET'&&url.pathname==='/api/trust'){const {state}=await repo.read(user.workspace);return send(res,200,{release:state.releases.at(-1)||null});}
   if(req.method==='POST'&&url.pathname==='/api/beacon'){
    if(!canWrite)return send(res,403,{error:'Operator role required'});if(!req.headers['content-type']?.includes('application/json'))return send(res,415,{error:'JSON required'});
    const {action,input={},revision}=JSON.parse(await readBody(req));const r=await repo.mutate(user.workspace,action,input,revision,actor);return send(res,200,{...r,state:await snapshot(r.state)});
   }
   if(req.method==='POST'&&url.pathname==='/api/mcp'){
    const accept=req.headers.accept||'';if(!accept.includes('application/json')||!accept.includes('text/event-stream'))return send(res,406,{error:'MCP Accept header required'});
    if(req.headers['mcp-protocol-version']&&req.headers['mcp-protocol-version']!=='2025-11-25')return send(res,400,{error:'Unsupported protocol version'});
    const out=await rpc(JSON.parse(await readBody(req)),{read:async()=>(await repo.read(user.workspace)).state,canWrite,mutate:async(a,i)=>(await repo.mutate(user.workspace,a,i,undefined,actor)).output});return out?send(res,200,out):send(res,202,'');
   }
   if(url.pathname.startsWith('/api/'))return send(res,405,{error:'Method not allowed'},{Allow:'GET, POST'});
   if(req.method!=='GET')return send(res,405,{error:'Method not allowed'});
   const file=resolve(assets,'.'+decodeURIComponent(url.pathname));if(!file.startsWith(assets+'/')&&file!==assets)return send(res,403,{error:'Invalid path'});
   const target=extname(file)&&existsSync(file)?file:resolve(assets,'index.html');if(!existsSync(target))return send(res,503,{error:'Build the portable web client first'});
   const types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.woff2':'font/woff2'};res.writeHead(200,{...headers,'Content-Type':types[extname(target)]||'application/octet-stream','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"});res.end(readFileSync(target));
  }catch(e){send(res,e.message.includes('changed')?409:400,{error:e.message});}
 });
 server.requestTimeout=15000;server.headersTimeout=10000;return server;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const repo=repository(),tokens=JSON.parse(process.env.BEACON_TOKENS_JSON||'[]');const server=createApplication({repo,tokens,publicOrigin:process.env.BEACON_ORIGIN||'http://127.0.0.1:8787'});
 server.listen(Number(process.env.PORT||8787),process.env.BEACON_BIND||'127.0.0.1',()=>console.error('Beacon API and GUI are listening. Configure TLS before remote access.'));
 for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>{repo.close();process.exit(0);}));
}
