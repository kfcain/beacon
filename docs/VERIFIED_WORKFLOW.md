# Verified evidence and objective evaluation

Beacon now verifies custody before ledger reads, method summaries, pack compilation,
exports, verified remote publication, and evaluation. The evaluation engine runs
only versioned, operator-approved supporting rules. It never declares a complete
SCF objective, control, or framework satisfied.

## Run the AWS storage example

Use Python 3.11 or later. `uv sync --frozen --all-extras` installs the reviewed
lockfile; `pip install -e '.[dev,jev]'` is an alternative development install.
The SDK and model calls are optional. No AWS resource is created by these commands.

```bash
beacon init
beacon rules --control CRY-07
# Copy examples/scopes/aws-ebs.example.json to a working file.
# Review the rule, replace the account, regions, and expected volume inventory.
beacon scope import --file approved-scope.json
beacon collect --plugin aws.ebs.encryption --scope aws-ebs-review --live
beacon evaluate --scope aws-ebs-review --control CRY-07
beacon ledger show --scope aws-ebs-review
beacon receipts --scope aws-ebs-review
beacon push
```

The collection principal needs `sts:GetCallerIdentity` and `ec2:DescribeVolumes`.
Use an already assumed, read-only role for the target account. This collector
uses boto3, validates the STS account/ARN/partition against the scope, paginates
every selected region, retains raw API pages, and preserves partial failures.
It supports commercial AWS and GovCloud partitions; model availability is a
separate deployment question. Credential discovery does not enable this collector:
`--live` must be explicit. An empty inventory does not produce a passing result.

`expected_ebs_volumes` is an operator-approved list of `region/volume-id` values,
ideally reconciled against an independent inventory. A missing, extra, duplicate,
or unencrypted volume prevents supporting success. An approved inventory can
itself be incomplete; Beacon does not claim to independently establish all assets.
Use a new scope id and recollect when scope, inventory, or rules change. Existing
scope ids cannot be overwritten through the enrollment command.

The bundled EBS rule tests only `Encrypted=true` for that inventory. It supports
`CRY-07_A02`; it does not assess every storage service, algorithm strength, KMS
permissions, data classification, transport protection, or the other nine CRY-07
objectives. Its explicitly approved freshness limit is 24 hours, not a claimed
SCF conformity cadence.

## Admission and outcomes

1. Verify pinned recorder/witness identities, signatures, payload digests, scope
   hashes, complete Merkle/TSA checkpoint coverage, and retained history.
2. Require live, successful, complete, timely evidence with a matching source,
   allowed evidence kind, principal, account/project/subscription, and regions.
3. Require the exact rule hash in version-2 scope parameters and the exact
   objective from the reviewed SCF source. Require the rule's population and
   schema checks. The latest attempt for the same control and scope supersedes
   older attempts, including a newer failed collection. A record for another
   control does not compete.
4. Run a deterministic predicate or an explicitly enabled policy reviewer.
5. Seal a receipt and checkpoint it. Bind the scope, SCF workbook and objective
   file digests, objective row, rule, input payloads, preceding chain head,
   evaluation time, expiry, and provider request/response digests where used.

Results include `supporting_pass`, `supporting_fail`, `no_rule`, `no_evidence`,
`unapproved_rule`, `ineligible`, `insufficient`, and `needs_review`. Every objective
is present. `objective_satisfied`, `control_satisfied`, and `assurance_claim` remain
false because the bundled rules cover supporting assertions only. Historical
receipts are explicitly marked historical; run `evaluate` for a current result.
The version-1 `decide_claim` helper never authorizes a claim: those receipts lack
objective, rule, candidate, freshness, and trusted-chain bindings.

Fixtures, failed attempts, stale observations, unbound evidence, catalog references,
and evaluation receipts remain available for custody inspection but cannot count
as eligible automated methods. Method totals do not certify a KSI; the current
Class C/D draft compilers are not official FedRAMP schemas. No KSI relationship is
invented for the EBS collector. Pack imports must be a verified prefix of the
local workspace's already trusted history; self-contained third-party trust
onboarding is deliberately not implied by a pack's embedded public keys.

## Policy capture and model providers

`beacon policy seal --scope ID --root REPO --path policy.json --commit FULL_SHA`
reads the Git object at the approved commit, not the working tree. Scope
`policy_sources` must approve its path, commit, byte digest, and `system_id`.
The JSON policy must name the scope and relevant control. This proves which
policy bytes were captured; it does not prove that people follow the policy.
Mapper/inbox imports remain candidates. They are not promoted automatically.

Evaluation defaults to `--judge none`. To enable Jev, install the `jev` extra,
configure the SDK credential through its normal environment, set
`BEACON_JEV_ENABLED=1` and `BEACON_JEV_MODEL` to an explicit model, and approve
`allow_external_judgment: true` in the scope. The pinned SDK is `typesafe-sdk==0.7.1`.
The adapter uses Choice, a **two-level** Score rubric (0..1), and numeric Noul.
Python applies the 1.0 coverage, sufficiency, and confidence minima. Minima are
not sent to the model. A Jev judgment is advisory: the row stays `needs_review`
with `advisory_meets_thresholds` or `judgment_abstained_or_below_threshold`, and
always `human_review_required`. No model output sets `supporting_pass`. Missing,
malformed, uncertain, oversized, or failed responses never meet the minima. These
probabilities are model judgments, not measured control effectiveness or a
calibrated audit confidence.

For Bedrock, set `BEACON_BEDROCK_ENABLED=1`, approve model processing in scope,
and supply `bedrock_model_id` and `bedrock_region` in scope parameters. Use
`beacon evaluate --scope ID --control IAC-02 --judge bedrock`. Optional
`bedrock_guardrail` takes `guardrailIdentifier` and `guardrailVersion`. The
operator must verify inference-profile routing against the permitted residency
boundary; a client region alone does not constrain cross-region inference.

Bedrock Converse responses are structured **advisory** reviews with exact source
quotations. Beacon validates response shape, quotation membership, completion,
size, and request time limits. It does not translate model-written confidence
into Jev probabilities or promote an advisory result to a passing assessment.
No execution tools are supplied to either policy reviewer. The model, region,
prompt version, usage, request id, and input/output hashes are recorded when
available. SDK failures record error classes, not credentials or request headers.

## Interfaces

CLI, GUI, TUI, and MCP call the same verification/evaluation functions. The web
Assessment tab selects scope, collector mode, control, and optional reviewer;
it shows objective rows, evidence exclusions, and historical receipts. The TUI
accepts a scope and plugin and evaluates a selected target without model calls.
MCP exposes `beacon_scopes`, `beacon_objectives`, `beacon_ledger`,
`beacon_evaluate`, and `beacon_receipts`, with typed arguments and no arbitrary
file-reading or shell tool.

The web console binds to loopback by default. A non-loopback CLI bind requires
`BEACON_API_TOKEN`; use TLS termination and explicit `BEACON_ALLOWED_HOSTS` for
remote use. API reads and writes require that bearer token when configured.
Mutation requests need `X-Beacon-Request: 1`; cross-origin requests and unapproved
Host headers are rejected. The UI keeps a supplied token only in memory and
escapes evidence-derived HTML. This is an operator console, not multitenant
identity management or an OIDC deployment.

## Trust migration and recovery

New workspaces pin recorder/witness public keys and the TSA certificate digest at
initialization. Verification never enrolls whatever keys happen to appear in a
record. Keep `trust.json` under separate administration and optionally point
`BEACON_TRUST_FILE` at that independently managed copy.

A local `retained-head.json` catches rollback of the chain alone. To detect full
workspace restoration, configure a directory outside the workspace and run:

```bash
export BEACON_ANCHOR_DIR=/separately-retained/beacon-heads
beacon custody anchor
export BEACON_REQUIRE_EXTERNAL_ANCHOR=1
beacon check
```

The directory must actually be independently retained and protected in the
operator's deployment. A different pathname with identical write privileges is
not independent administration. Beacon serializes local and shared-directory
writers, flushes evidence/chain/head writes, and fails on a missing or conflicting
head. It does not deploy a managed signer, independent witness service, or an
append-only external transparency service. Local private keys remain accessible
to the workspace owner. A privileged owner can fabricate observations or replace
all locally controlled trust state. A valid seal authenticates local custody,
not truth at the cloud source. Drop-ins execute trusted Python in-process and
must be reviewed as code with access to the workspace and credentials.

For a legacy workspace, obtain known-good public pins and a previously retained
sequence/head from an independent record, then explicitly enroll them:

```bash
beacon custody enroll --recorder RECORDER_PUBLIC_HEX --witness WITNESS_PUBLIC_HEX \
  --tsa-sha256 CERT_SHA256 --workspace-id EXISTING_ID \
  --expected-seq RETAINED_SEQUENCE --expected-head RETAINED_HEAD_SHA256
```

Enrollment checks the whole history in a staging workspace before installing
trust state and refuses to reset existing pins or heads. If no prior trusted
head exists, enrollment establishes trust only from that point forward; it
cannot prove the absence of earlier truncation. Preserve scopes, trust registry,
TSA certificate, and the externally retained head when recovering from S3.
Private signing keys are not needed for read-only verification.

Remote observation and finding pointers retain S3 `VersionId` when versioning is
available. Pull reads those versions and still verifies hashes, signatures,
checkpoints, and retained history before promotion. Unversioned legacy pointers
use digest checks. Conditional evidence/checkpoint index updates refuse changing
their existing digests. S3 objects dual-written before a checkpoint retain
`verified=false`; verified index state is set only after the shared check passes.
Cumulative chain/checkpoint objects and the DynamoDB index are not an independent
anti-rollback authority. Protect the retained head separately.
