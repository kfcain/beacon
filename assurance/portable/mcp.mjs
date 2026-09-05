#!/usr/bin/env node
import {createInterface} from 'node:readline';
import {repository} from './store.mjs';
import {rpc} from '../lib/beacon/rpc.mjs';
const repo=repository(),owner=process.env.BEACON_WORKSPACE||'local-owner';
const ctx={read:async()=>(await repo.read(owner)).state,canWrite:process.env.BEACON_MCP_WRITES==='true',mutate:async(action,input)=>(await repo.mutate(owner,action,input)).output};
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
for await(const line of lines){
 if(!line.trim())continue;let response;
 try{if(Buffer.byteLength(line)>50000)throw new Error('Too large');response=await rpc(JSON.parse(line),ctx);}catch{response={jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}};}
 if(response)process.stdout.write(JSON.stringify(response)+'\n');
}
repo.close();
