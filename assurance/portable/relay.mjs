#!/usr/bin/env node
// Explicit, fixed destination; redirects prohibited. No arbitrary URL from evidence.
import {readFileSync} from 'node:fs';
import {createHmac} from 'node:crypto';
const [file]=process.argv.slice(2);
try{
 const url=new URL(process.env.BEACON_RELAY_URL||'');if(url.protocol!=='https:'||url.username||url.password)throw new Error('Configure an explicit HTTPS relay destination');
 const allow=(process.env.BEACON_RELAY_HOSTS||'').split(',');if(!allow.includes(url.hostname))throw new Error('Destination is not approved');
 if(!process.env.BEACON_RELAY_SECRET||process.env.BEACON_RELAY_SECRET.length<32)throw new Error('Strong relay signing secret required');
 const release=JSON.parse(readFileSync(file,'utf8'));if(release.target!=='sandbox')throw new Error('Only sandbox relay is enabled in this release');
 const body=JSON.stringify(release),timestamp=new Date().toISOString(),signature=createHmac('sha256',process.env.BEACON_RELAY_SECRET).update(timestamp+'.'+body).digest('hex');
 const r=await fetch(url,{method:'POST',redirect:'error',signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json','Idempotency-Key':release.id,'X-Beacon-Timestamp':timestamp,'X-Beacon-Signature':signature,...(process.env.BEACON_RELAY_TOKEN?{Authorization:'Bearer '+process.env.BEACON_RELAY_TOKEN}:{})},body});
 if(!r.ok)throw new Error('Relay returned HTTP '+r.status);console.log(JSON.stringify({releaseId:release.id,status:'DELIVERED',destination:url.origin,at:timestamp}));
}catch(e){console.error(e.message);process.exitCode=2;}
