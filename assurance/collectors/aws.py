"""Read-only AWS collector. One account per job; errors never become fixtures."""
import argparse, datetime, hashlib, json, os, re
from pathlib import Path

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
def sha(value): return hashlib.sha256(canonical(value)).hexdigest()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def safe_json(value):
    return json.loads(json.dumps(value, default=lambda x: x.isoformat() if isinstance(x, datetime.datetime) else str(x)))

def collect(session, approved, claim, trails=None, config=None):
    if not approved or len(approved)>100: raise ValueError('Provide 1–100 approved account/Region pairs')
    accounts={s['account'] for s in approved}; partitions={s['partition'] for s in approved}
    if len(accounts)!=1 or len(partitions)!=1: raise ValueError('One account and partition per job')
    account=next(iter(accounts)); partition=next(iter(partitions))
    if not re.fullmatch(r'\d{12}',account) or partition not in ('aws','aws-us-gov'): raise ValueError('Invalid scope')
    if len({s['region'] for s in approved})!=len(approved): raise ValueError('Duplicate Region')
    if claim=='IAM-01' and len(approved)!=1: raise ValueError('IAM account summary requires one account-level scope entry')
    for s in approved:
        if session.get_partition_for_region(s['region'])!=partition: raise ValueError('Region/partition mismatch')
    operations={'ENC-01':'GetEbsEncryptionByDefault','LOG-01':'GetTrailStatus','IAM-01':'GetAccountSummary'}
    run={'schema':'beacon.observation.v1','claimId':claim,'mode':'live','operation':operations[claim], 'startedAt':now(),'collector':'beacon-aws/0.2.0','observations':[]}
    for s in approved:
        row={'scope':s,'observedAt':now(),'collectionStatus':'error'}
        try:
            identity=session.client('sts',region_name=s['region'],config=config).get_caller_identity()
            if identity['Account']!=account or not identity['Arn'].startswith('arn:'+partition+':'): raise ValueError('Caller identity outside approved scope')
            row['sourceIdentity']=safe_json(identity)
            if claim=='ENC-01': raw=session.client('ec2',region_name=s['region'],config=config).get_ebs_encryption_by_default()
            elif claim=='IAM-01': raw=session.client('iam',region_name=s['region'],config=config).get_account_summary()
            else:
                arn=(trails or {}).get(s['region'],'')
                if not arn.startswith(f"arn:{partition}:cloudtrail:{s['region']}:{account}:trail/"): raise ValueError('Explicit trail ARN required for approved account/Region')
                raw=session.client('cloudtrail',region_name=s['region'],config=config).get_trail_status(Name=arn)
                row['query']={'Name':arn}
            row.update(collectionStatus='complete',raw=safe_json(raw),observedAt=now())
            row['rawSha256']=sha(row['raw'])
        except Exception as exc:
            row['error']={'type':type(exc).__name__,'code':getattr(exc,'response',{}).get('Error',{}).get('Code','COLLECTION_FAILED')}
            row['observedAt']=now()
        run['observations'].append(row)
    run['completedAt']=now();return run

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--scope',required=True);parser.add_argument('--claim',choices=['ENC-01','LOG-01','IAM-01'],required=True);parser.add_argument('--output',required=True);parser.add_argument('--trails');args=parser.parse_args()
    if any(k.startswith('AWS_ENDPOINT_URL') for k in os.environ): raise ValueError('Custom AWS endpoint overrides are not permitted')
    import boto3
    from botocore.config import Config
    config=Config(connect_timeout=5,read_timeout=20,retries={'max_attempts':3,'mode':'standard'},use_fips_endpoint=os.environ.get('BEACON_FIPS_ENDPOINTS')=='true')
    result=collect(boto3.Session(),json.loads(Path(args.scope).read_text()),args.claim,json.loads(Path(args.trails).read_text()) if args.trails else None,config)
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as out: json.dump(result,out,ensure_ascii=False,allow_nan=False,indent=2)
    return 0 if all(r['collectionStatus']=='complete' for r in result['observations']) else 2
if __name__=='__main__': raise SystemExit(main())
