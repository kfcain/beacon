"""Remote evidence lake (S3 + DynamoDB index). Offline collect does not need AWS."""

from beacon.storage.s3 import (
    ArtifactLake,
    checkpoint_id,
    evidence_object_key,
    pack_object_key,
    publish_collect_run,
    publish_pack,
    pull_workspace,
    record_object_key,
    sync_workspace,
)

__all__ = [
    "ArtifactLake",
    "checkpoint_id",
    "evidence_object_key",
    "pack_object_key",
    "publish_collect_run",
    "publish_pack",
    "pull_workspace",
    "record_object_key",
    "sync_workspace",
]
