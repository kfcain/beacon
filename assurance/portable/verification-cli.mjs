#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {setTimeout as delay} from 'node:timers/promises';
import {repository} from './store.mjs';
import {verificationView} from '../lib/beacon/verification.mjs';
const [command,file]=process.argv.slice(2),owner=process.env.BEACON_WORKSPACE||'local-owner';
let repo,stopped=false;
process.on('SIGINT',()=>{stopped=true;});process.on('SIGTERM',()=>{stopped=true;});
try{
 repo=repository();
 const actions={contract:'verification-contract',evidence:'verification-evidence',template:'verification-template',report:'verification-report',reconcile:'verification-reconcile'};
 if(command==='status')console.log(JSON.stringify(await verificationView((await repo.read(owner)).state),null,2));
 else if(command==='watch'){
  const seconds=Number(file||60);if(!Number.isInteger(seconds)||seconds<10||seconds>86400)throw new Error('Interval must be 10–86400 seconds');
  while(!stopped){const result=await repo.mutate(owner,'verification-reconcile',{});console.log(JSON.stringify(result.output));for(let i=0;i<seconds&&!stopped;i++)await delay(1000);}
 }else if(Object.hasOwn(actions,command)){
  const input=command==='reconcile'?{}:JSON.parse(readFileSync(file,'utf8'));console.log(JSON.stringify((await repo.mutate(owner,actions[command],input)).output,null,2));
 }else throw new Error('Usage: verification-cli.mjs contract|evidence|template|report INPUT.json | status | reconcile | watch [SECONDS]');
}catch(e){console.error(e.message);process.exitCode=2;}finally{repo?.close();}
