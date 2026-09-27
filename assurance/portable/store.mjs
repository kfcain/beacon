import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {seed,execute} from '../lib/beacon/engine.mjs';
export function repository(path=process.env.BEACON_DATABASE||'./.beacon-v2/workspace.sqlite'){
 const file=resolve(path);mkdirSync(dirname(file),{recursive:true,mode:0o700});const db=new DatabaseSync(file);chmodSync(file,0o600);
 db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS workspaces (owner TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL);');
 async function read(owner='local-owner'){
  let row=db.prepare('SELECT revision,body FROM workspaces WHERE owner=?').get(owner);
  if(!row){const s=await seed(owner);db.prepare('INSERT OR IGNORE INTO workspaces VALUES (?,0,?)').run(owner,JSON.stringify(s));row=db.prepare('SELECT revision,body FROM workspaces WHERE owner=?').get(owner);}
  return {revision:row.revision,state:JSON.parse(row.body)};
 }
 async function mutate(owner,action,input,expectedRevision,actor=owner){
  const {state,revision}=await read(owner);if(expectedRevision!==undefined&&expectedRevision!==revision)throw new Error('Workspace changed. Refresh and retry.');
  const output=await execute(state,action,input,actor);const r=db.prepare('UPDATE workspaces SET revision=revision+1,body=? WHERE owner=? AND revision=?').run(JSON.stringify(state),owner,revision);
  if(r.changes!==1)throw new Error('Workspace changed. Refresh and retry.');return {state,revision:revision+1,output};
 }
 return {read,mutate,close:()=>db.close()};
}
