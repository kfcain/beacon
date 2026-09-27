"""Run under a separate signing role after authorization of the job manifest.
This script signs an envelope; deployment must enforce the signer request policy.
"""
import argparse, base64, hashlib, json, re
from pathlib import Path
from aws import canonical

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',required=True);p.add_argument('--key-arn',required=True);p.add_argument('--region',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    import boto3
    manifest=json.loads(Path(a.manifest).read_text())
    for field in ('evidenceSha256','scopeSha256','imageSha256'):
        if not re.fullmatch('[a-f0-9]{64}',manifest.get(field,'')): raise ValueError('Missing digest: '+field)
    if not manifest.get('jobId') or not manifest.get('collectedAt'): raise ValueError('Missing job identity or time')
    hashed=hashlib.sha256(canonical(manifest)).digest()
    response=boto3.client('kms',region_name=a.region).sign(KeyId=a.key_arn,Message=hashed,MessageType='DIGEST',SigningAlgorithm='RSASSA_PSS_SHA_256')
    envelope={'schema':'beacon.signature.v1','manifest':manifest,'keyId':response['KeyId'],'algorithm':'RSASSA_PSS_SHA_256','signature':base64.b64encode(response['Signature']).decode()}
    with open(a.output,'x') as out: json.dump(envelope,out,indent=2)
if __name__=='__main__': main()
