"""Read-only, explicitly scoped and paginated EBS encryption observation.

No resource changes. The result supports one storage assertion, not a complete
SCF objective or control. API: boto3 EC2 DescribeVolumes and STS GetCallerIdentity.
"""
from __future__ import annotations

import datetime as dt
import json

import boto3
from botocore.config import Config

from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec
from beacon.scope.enforce import boundary_reasons
from beacon.scope.v2 import parse_scope


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class EbsEncryptionPlugin:
    spec = FetcherSpec(name="aws.ebs.encryption", version="1.0.0", category="aws",
        description="Inventory EBS volumes across an explicit account and region boundary; preserve partial failures.",
        scf_targets=("CRY-07",), tools=())

    def collect(self, ctx: CollectContext) -> CollectResult:
        if ctx.live is not True:
            return CollectResult(ok=True, mode="fixture", scf_targets=self.spec.scf_targets, payload={
                "source": self.spec.name, "mode": "fixture", "ok": True, "cloud": "aws",
                "collection_complete": False, "fixture_reason": "explicit_live_required",
                "volumes": [{"VolumeId": "vol-fixture", "Encrypted": True, "region": "us-east-1"}],
            })
        payload = {"format": "beacon.aws-ebs/v1", "source": self.spec.name, "collector_version": self.spec.version,
                   "mode": "live", "cloud": "aws", "ok": False, "collection_complete": False,
                   "observed_at": utcnow(), "identity": {}, "regions": [], "volumes": [],
                   "pages": [], "errors": [], "region_runs": [], "tags": ["evidence:cloud_inspector",
                   "automation:automated", "control:CRY-07"]}
        # KSI linkage is deliberately absent: no invented framework crosswalk.
        try:
            scope = parse_scope(json.dumps(ctx.extra.get("scope")))
            if len(scope.boundary.accounts) != 1 or not scope.boundary.regions:
                raise ValueError("EBS collection requires one explicit account and at least one region")
            if ctx.target is not None and ctx.target.upper() != "CRY-07":
                raise ValueError("EBS collector supports CRY-07 only")
            regions = list(scope.boundary.regions)
            if len(regions) > 40:
                raise ValueError("collection region bound exceeded")
            payload["regions"] = regions
            config = Config(retries={"mode": "standard", "max_attempts": 3}, connect_timeout=5, read_timeout=20)
            session = boto3.Session()
            identity = session.client("sts", region_name=regions[0], config=config).get_caller_identity()
            payload["identity"] = {"account_id": identity["Account"], "arn": identity["Arn"],
                                   "partition": identity["Arn"].split(":")[1]}
            reasons = boundary_reasons(scope, payload)
            if reasons:
                raise ValueError(",".join(reasons))
            partition = payload["identity"]["partition"]
            if partition not in {"aws", "aws-us-gov"}:
                raise ValueError("collector partition is unsupported")
            for region in regions:
                expected_partition = "aws-us-gov" if region.startswith("us-gov-") else "aws"
                if expected_partition != partition:
                    raise ValueError("account and region partition differ")
            for region in regions:
                run = {"region": region, "complete": False, "pages": 0, "volume_count": 0}
                try:
                    client = session.client("ec2", region_name=region, config=config)
                    seen = set()
                    for page in client.get_paginator("describe_volumes").paginate(PaginationConfig={"PageSize": 500}):
                        if run["pages"] >= 200:
                            raise ValueError("page bound exceeded")
                        rows = page.get("Volumes")
                        if not isinstance(rows, list):
                            raise ValueError("malformed DescribeVolumes response")
                        # Preserve original API pages, normalizing only JSON-incompatible datetimes.
                        raw = json.loads(json.dumps(page, default=lambda value: value.isoformat()))
                        payload["pages"].append({"region": region, "api": "ec2:DescribeVolumes", "response": raw})
                        run["pages"] += 1
                        for volume in rows:
                            vid = volume.get("VolumeId")
                            if not isinstance(vid, str) or vid in seen or type(volume.get("Encrypted")) is not bool:
                                raise ValueError("missing, duplicate, or malformed volume")
                            seen.add(vid)
                            payload["volumes"].append({"VolumeId": vid, "Encrypted": volume["Encrypted"],
                                "KmsKeyId": volume.get("KmsKeyId"), "AvailabilityZone": volume.get("AvailabilityZone"),
                                "region": region})
                        run["volume_count"] = len(seen)
                    run["complete"] = True
                except Exception as exc:
                    payload["errors"].append({"region": region, "code": type(exc).__name__, "detail": str(exc)[:1000]})
                payload["region_runs"].append(run)
            payload["collection_complete"] = all(run["complete"] for run in payload["region_runs"])
            payload["ok"] = payload["collection_complete"]
        except Exception as exc:
            payload["errors"].append({"code": type(exc).__name__, "detail": str(exc)[:1000]})
        payload["completed_at"] = utcnow()
        if not payload["ok"]:
            payload["mode"] = "live_failed"
        return CollectResult(ok=payload["ok"], mode=payload["mode"], payload=payload,
                             error=None if payload["ok"] else "collection incomplete", scf_targets=self.spec.scf_targets)


PLUGIN = EbsEncryptionPlugin()
