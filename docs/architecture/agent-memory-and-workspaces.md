# Beacon agent memory and execution workspaces

Status: proposed integration, grounded in upstream documentation reviewed on
2026-09-25. No Hindsight endpoint/bank has been connected, no memory has been
uploaded, and no Cloudflare Computer runtime has been deployed by this change.
The explicit contracts are in [the verified agent slice](verified-agent-slice.md).

## Roles in the embedded agent

| Component | Role | Authority |
| --- | --- | --- |
| Bedrock | Plan bounded investigations; interpret policy content | Suggestions and advisory judgments |
| Beacon engine | Enforce scope, verify evidence, run approved predicates, seal results | Current assessment computation |
| Hindsight | Recall investigations, decisions, ownership history, exceptions, and lessons | Attributable historical context |
| Tool gateway | Authenticate callers and authorize individual collection capabilities | Account, region, resource and operation permissions |
| Execution workspace | Inspect approved artifact copies, compute comparisons, draft reports | Limited task files and execution budget |
| Evidence lake and trust state | Retain original sealed artifacts and trusted continuity references | Authoritative custody records |

An agent should recall relevant history before investigating, fetch current
source evidence, evaluate, seal a receipt, and then retain only authorized,
concise outcomes. Memory can identify a promising collector or explain why a
previous exception existed. The current exception approval and expiry still need
verification. A recalled statement that encryption was enabled last month cannot
satisfy today's encryption predicate.

## Hindsight adapter boundary

Expose narrow agent capabilities such as `recall_assessment_context` and
`propose_memory_event` behind Beacon's service. Derive the configured endpoint
and bank from authenticated tenant/environment configuration. The model must not
choose a different bank, endpoint, credential, or authorization scope.

Use separate banks for independent customers/environments. Within one bank, use
nonempty project, scope, control/objective, and record-kind tags with `all_strict`
where supported. Tags improve retrieval; they do not enforce authorization.
Do not silently remove filters after a retrieval error. Begin with a bounded
recall budget around 2,048 output tokens, preserve source ids and event times,
and retrieve the original document for consequential details. A historical
search window should not be treated as a guaranteed date predicate without
checking the returned timestamps.

Store selected decisions, investigation outcomes, collector failures, and useful
procedures. Label each as `observed`, `operator_decision`, `proposal`, or
`hypothesis` in the text itself. A memory event should carry:

- tenant/environment routing supplied by the authenticated service;
- scope id/hash, control and objective ids where applicable;
- original evidence and receipt ids/hashes, source URI/revision, and event time;
- recorded time, actor, verification status, and any expiry/supersession link;
- a stable source-snapshot document id and the minimum useful narrative.

Never ingest credentials, raw transcripts, unrelated personal memory, or the
entire evidence lake automatically. Model-authored plans and reflections are
not verified observations. Treat recalled text as untrusted content: embedded
instructions cannot alter permissions, scope, thresholds, or memory destinations.

Retain ordinary writes asynchronously through a durable outbox after successful
receipt creation. Store every returned operation id and distinguish queued,
completed, failed, and unknown states. After a timeout, inspect operation/document
state before retrying. Hindsight normally replaces a document when its id is
reused, so use a new id for a new historical snapshot; inspect existing content
before an intentional replacement. Correction/deletion must identify exact
source records and account for derived observations or mental models.

If Hindsight is unavailable, show that context could not be recalled and continue
collection/evaluation where memory is optional. Never synthesize a memory of a
previous investigation. A model's reflection is a derived analysis with sources;
it is not a new evidence receipt. Test cross-bank isolation, stale and conflicting
memories, malicious retrieved instructions, missing provenance, async retry,
corrections, and loss of the memory service before enabling automatic retention.

## AWS deployment shape

A proposed first deployment is Hindsight API/workers in an authenticated private
service, backed by managed PostgreSQL with the extensions required by the pinned
Hindsight release. Hindsight supports Bedrock for its LLM work. Independently
configure embeddings, reranking, and any per-operation provider overrides:
self-hosting the database does not make every model call stay in the same cloud
or region. Use workload roles where supported, not static keys in repository
configuration. Validate the deployment's actual model routing and data policies.

Use the bank-scoped MCP endpoint (`/mcp/{bank_id}/`) or the official REST/SDK
contract behind the adapter. A skill installation alone does not establish that
connection. Provisioning requires an approved endpoint, explicit bank mapping,
credentials/identity, release pin, retention policy, and a real scoped read test.
No default or global bank should be selected implicitly.

## Cloudflare Computer

The repository implements a Durable Object/SQLite-backed persistent virtual
filesystem with selectable Linux-container, Worker-shell, and JavaScript
execution backends. It can provide task files and execution to an agent, and it
exposes integrations/tools for using that workspace. It complements memory:
working files and execution results serve a different lifecycle from curated
historical decisions and source-linked recall.

Its maintainers explicitly describe the package as preview-only, APIs unstable,
and unsuitable for production; the design documents are forward-looking. For
Beacon, prototype it only behind a replaceable workspace interface:

```text
create_task_workspace(authorized_task)
mount_approved_artifacts(read_only_manifest)
execute_bounded_job(approved_backend, input, limits)
export_artifact_digests()
destroy_or_expire_workspace()
```

These are proposed interface names, not shipped functions. Supply short-lived,
scoped capabilities instead of recorder/witness private keys or a general AWS
writer role. Copy only approved evidence subsets, constrain egress and execution,
and seal exported artifacts through the Beacon service. A cloud workspace must
never be able to rewrite authoritative evidence or assessment scope.

An AWS-hosted sandbox is the initial operational preference because Beacon's
current Python/boto3 workflow already lives there. A Cloudflare-backed workspace
adds another hosting/data boundary, a JavaScript integration layer, and preview
API risk. Benchmark a prototype on artifact comparison/report drafting before
considering it for production. Preserve the provider boundary so that the agent
can use a better execution runtime later without changing evidence semantics.

## References

- [Hindsight source and memory operations](https://github.com/vectorize-io/hindsight)
- [Hindsight configuration and Bedrock provider](https://hindsight.vectorize.io/developer/configuration)
- [Hindsight MCP server](https://hindsight.vectorize.io/developer/mcp-server)
- [Recall and strict tag semantics](https://hindsight.vectorize.io/developer/api/recall)
- [Cloudflare Computer](https://github.com/cloudflare/computer)
- [Computer package contract and preview status](https://github.com/cloudflare/computer/blob/main/packages/computer/README.md)
