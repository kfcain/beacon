#!/usr/bin/env node
// Minimize a Terraform show -json PLAN before it leaves the trusted runner.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {digest} from '../lib/beacon/engine.mjs';
import {fileURLToPath} from 'node:url';
const PATHS={
 aws_s3_bucket_server_side_encryption_configuration:{encryptionAlgorithm:['rule',0,'apply_server_side_encryption_by_default',0,'sse_algorithm'],kmsKeyArn:['rule',0,'apply_server_side_encryption_by_default',0,'kms_master_key_id']},
 aws_s3_bucket_versioning:{versioning:['versioning_configuration',0,'status']},
 aws_kms_key:{keyRotation:['enable_key_rotation']},
 aws_lambda_function:{tracing:['tracing_config',0,'mode']},
 aws_api_gateway_stage:{logging:['access_log_settings',0,'destination_arn']}
};
function valueAt(object,path){let value=object;for(const key of path){if(value===true)return true;if(value==null)return undefined;value=value[key];}return value;}
function fact(values,unknown,sensitive,plannedSensitive,path){if(valueAt(unknown,path)===true||valueAt(sensitive,path)===true||valueAt(plannedSensitive,path)===true)return null;let value=values;for(const key of path){if(value==null)return null;value=value[key];}return typeof value==='string'||typeof value==='boolean'?value:null;}
export function projectPlan(plan){
 if(typeof plan.format_version!=='string'||!/^1\./.test(plan.format_version)||!plan.planned_values?.root_module||plan.errored===true)throw new Error('A successful Terraform JSON plan with format major 1 is required');
 const changes=new Map((plan.resource_changes||[]).map(r=>[r.address,r.change]));const resources=[];const seen=new Set();
 function visit(module,depth=0){if(depth>30)throw new Error('Module nesting limit');for(const r of module.resources||[]){if(r.mode!=='managed')continue;if(typeof r.address!=='string'||typeof r.type!=='string'||seen.has(r.address))throw new Error('Invalid resource identity');seen.add(r.address);if(seen.size>500)throw new Error('Split plans with over 500 resources');const change=changes.get(r.address),facts={};for(const [name,path] of Object.entries(PATHS[r.type]||{}))facts[name]=fact(r.values,change?.after_unknown,change?.after_sensitive,r.sensitive_values,path);resources.push({id:r.address,type:r.type,collectionStatus:'complete',facts});}for(const child of module.child_modules||[])visit(child,depth+1);}
 visit(plan.planned_values.root_module);return resources;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const [planPath,manifestPath,revision]=process.argv.slice(2);if(!/^[a-f0-9]{40}$/.test(revision||''))throw new Error('Usage: terraform-project.mjs PLAN.json MANIFEST.json FULL_COMMIT_SHA');const bytes=readFileSync(planPath);if(bytes.length>20*1024*1024)throw new Error('Plan exceeds 20 MiB');const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));const observation={schema:'beacon.infrastructure.observation.v1',manifestId:manifest.id,manifestHash:await digest(manifest),stage:'planned',collectedAt:new Date().toISOString(),sourceSha256:createHash('sha256').update(bytes).digest('hex'),sourceRevision:revision,resources:projectPlan(JSON.parse(bytes))};console.log(JSON.stringify(observation,null,2));}catch(e){console.error(e.message);process.exitCode=2;}
}
