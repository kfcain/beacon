#!/usr/bin/env bash
set -euo pipefail
: "${NODE_RUNTIME:?Approved Chainguard Node runtime digest required}"
: "${PYTHON_RUNTIME:?Approved Python runtime digest required}"
: "${PYTHON_BUILDER:?Approved compatible Python builder digest required}"
: "${COSIGN_IDENTITY:?Exact approved signing identity required}"
: "${COSIGN_ISSUER:?Approved OIDC issuer required}"
for image in "$NODE_RUNTIME" "$PYTHON_RUNTIME" "$PYTHON_BUILDER"; do
  [[ "$image" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'Immutable digest required' >&2; exit 2; }
  cosign verify --certificate-identity "$COSIGN_IDENTITY" --certificate-oidc-issuer "$COSIGN_ISSUER" "$image" >/dev/null
done
node node_modules/vite/bin/vite.js build --config portable/vite.config.ts
docker build --build-arg NODE_RUNTIME="$NODE_RUNTIME" -f deploy/Dockerfile.api -t beacon-api:review .
docker build --build-arg PYTHON_RUNTIME="$PYTHON_RUNTIME" --build-arg PYTHON_BUILDER="$PYTHON_BUILDER" -f deploy/Dockerfile.collector -t beacon-collector:review .
syft beacon-api:review -o spdx-json > api.sbom.json
syft beacon-collector:review -o spdx-json > collector.sbom.json
grype beacon-api:review --fail-on high
grype beacon-collector:review --fail-on high
# Publish to an approved registry, record final digests, sign final images and
# attach build provenance using the organization's pinned CI release workflow.
