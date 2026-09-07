# Persistent verification and correlated assurance

Beacon now has a provider-neutral diagnostic contract engine alongside its AWS and infrastructure validators. The GUI, API, portable CLI, TUI and MCP share persistent evidence, evaluations, correlated findings and report drafts. A connector is an observation source; a versioned contract defines the question, expected population, scope, freshness and typed assertions. Candidate framework relationships reuse a test without equating entire requirements.

## What is implemented

- Versioned contracts, evidence envelopes and custom report section blueprints, with record hashes and application audit events.
- Explicit scope and subject matching; missing population, expired evidence, collection errors, record corruption and failed assertions remain distinct. Replayed older versions and identity changes are rejected.
- Flat typed assertions (`eq`, `gte`, `lte`, `present`). Heterogeneous artifacts can carry text or JSON, a media type, normalized facts and citation references. These are envelope support, not universal file decoding or semantic validation.
- Policy references pin a mapper document ID, version, location and source hash. A missing document or changed imported version opens a reassessment finding even if technical assertions pass. Matching hashes do not approve the interpretation or authenticate the document.
- Automatic reconciliation on contract/evidence import, policy changes and report generation. The existing reconcile action also includes these contracts. A local watcher can detect expiration without another upstream event.
- Correlation by workspace, scope, subject and evidence kind. Findings include affected objectives, framework mappings, policy references and report versions. Unchanged findings/evaluations are deduplicated; changed records retain history.
- A local alert inbox. Recovery becomes `OBSERVED_RECOVERY`, requiring review; it is not an automatically closed compliance finding. Shared evidence is correlation, not proof of root cause.
- 32 built-in section blueprints across FedRAMP, SOC 2, CMMC, ISO 27001 and ISO 42001; customer-defined blueprints are supported. Generated JSON/Markdown drafts pin contract and evidence hashes, retain missing sections, preserve old versions and identify changed evidence.
- Sixteen total MCP tools, including seven generic verification/report tools. The new tools cannot approve policy, publish production claims, execute document instructions or notify external parties.

## A policy-to-reality example

A proposed access policy interpretation requires production access removal within four hours. The contract identifies the approved organization boundary and the termination events expected in that test population. An identity/HR adapter must correlate termination time, account identities, downstream application entitlements and actual revocation time. The adapter submits `elapsedHours: 6` and `allProductionAccessRemoved: true`; the four-hour assertion fails. SOC 2 and ISO relationships share that observation, and reports using the affected contract become outdated when the observation changes.

If the identity API returns access denied, the adapter must submit `collectionStatus: "DENIED"`; apparently healthy facts cannot override the error. If it produces no envelope, expected evidence remains missing or eventually expires. A later healthy import records observed recovery; authenticity, population completeness and operating effectiveness remain review obligations.

Policy extraction is not policy approval. The GRC PDF Mapper can identify candidate obligations and source spans. A reviewer must establish the exact threshold, exceptions, applicability, evidence sources and test semantics. This build stores draft contracts only; a production approval and separation-of-duties workflow is still required before enforcement.

## Local walkthrough

Run from the `assurance` directory in the GitHub repository, or the root of the standalone Site source:

```sh
node portable/verification-cli.mjs contract examples/verification/offboarding-contract.json
node portable/verification-cli.mjs status
node portable/verification-cli.mjs evidence observation-envelope.json
node portable/verification-cli.mjs report report-request.json
node portable/verification-cli.mjs reconcile
node portable/verification-cli.mjs watch 60
```

The example contract is synthetic. `observation-envelope.json` has an `evidence` object containing stable `id`, `scopeId`, `subjectId`, `kind`, `observedAt`, `source`, `collectionStatus`, `facts` and optional content/citations. The GUI's Verification engine provides a synthetic six-hour observation that can be edited/imported. A report request looks like:

```json
{"templateId":"soc2-workpaper","contractIds":["demo-offboarding"],"sections":{"Control and criteria":"Draft candidate mapping; owner review pending."}}
```

The watcher is a foreground process against the same SQLite repository, not a hosted background service. Run it under a supervised deployment with an independent missed-heartbeat monitor. It has no cloud discovery or notification credentials. Conflicting writes or capacity errors stop the process with a nonzero exit rather than pretending the checks ran. The hosted GUI reevaluates displayed evidence during refresh; durable alert transitions require reconciliation. A scheduler must be connected to the hosted deployment separately.

The TUI adds Verification, Alerts and Reports views. `portable/cli.mjs status` produces a full workspace snapshot for the existing TUI `--snapshot` mode. A generic verification-only status export is not a full TUI workspace snapshot.

## LLM and connector boundary

Codex, Cursor, Claude and other MCP clients can use the packaged stdio server. Client-specific configuration differs; point the client's MCP process command at `node portable/mcp.mjs`, using an absolute path and the intended `BEACON_DATABASE`. The server is read-only by default. `BEACON_MCP_WRITES=true` explicitly permits the bounded draft/import operations in that local workspace. Use a dedicated service identity/database for automation; this flag is not enterprise RBAC.

Useful sequence: `beacon_report_templates`, `beacon_register_contract`, `beacon_submit_evidence`, `beacon_reconcile_verification`, `beacon_verification`, `beacon_generate_report`. Report generation takes a `request` object containing the same CLI report request. The existing MCP transport has a 50 KB request limit; larger envelopes should use the bounded API/import path.

All generic imports receive `UNVERIFIED_IMPORT` and assertion authority `NONE`, including source labels supplied by models or external evidence engines. A hash detects changes; it does not prove that a model's extraction, a screenshot, a collector identity or an upstream timestamp is truthful. Citation locations/hashes are retained, not independently resolved or authenticated. No URI is fetched and no uploaded text or template is executed by this module.

Adapters for external GRC engines, SIEMs, identity providers and cloud inventories still need explicit authentication, field/identity mapping, scope registration, source-byte binding and error translation. Supporting the envelope is not a claim that every vendor connector is already implemented. Existing AWS and Terraform/Rego paths remain distinct; this change does not authenticate their results or automatically ingest them into the generic model.

## Report coverage and limits

| Family | Draft blueprints included | Release qualification still required |
| --- | --- | --- |
| FedRAMP CR26 / 20x | OCR, SDR, SCG, VDR, VER history/evaluation, PAIN worksheet, significant change and incident drafts | Exact applicable rule edition, pinned official JSON schemas and schema tests, full field coverage, PAIN methodology validation, access-controlled delivery and authorized submission |
| FedRAMP Rev5 | SSP, SAP, SAR, POA&M | Baseline-specific control/parameter inventory, official package contracts, assessor work and signatures |
| SOC 2 | Workpapers, system description, management assertion, evidence requests, findings | Licensed criteria, actual populations/sampling, period coverage, management approval and independent CPA opinion |
| CMMC L2 | SSP, POA&M, module-validation register, CUI flow specification, assessment workbook | Objective-level completeness, POA&M eligibility, actual CMVP certificate/deployment checks, validated rendered diagrams and authorized assessment |
| ISO 27001 | Scope, ISMS core, SoA, policy/procedure, internal audit, management review | Organization-specific risk treatment, licensed standard coverage, approved SoA, implemented processes and audit evidence |
| ISO 42001 | AIMS, AI system documentation, impact/risk assessment, SoA | AI inventory and lifecycle integration, reviewed dataset/model lineage, evaluation thresholds, impact assessment and management-system audit |

These are author-authored section blueprints, **not validated regulator submission schemas**. Optional reporting periods are recorded; the engine does not establish continuous operation, sample completeness or evidentiary sufficiency across that period. A populated narrative is still unverified. There are no DOCX/XLSX/PDF renderers, complete diagram generation, digital approval signatures, CPA opinions or certification issuance in this layer. A generated report remains `DRAFT_NOT_FOR_SUBMISSION` and `schemaValidated: false`. All requested families have an extension point; full framework readiness is not asserted.

The supplied ISMS, policy, SOC 2 and AI documentation examples informed the separation of scope, owners, populations, procedures, findings, approvals and reporting periods. Their raw member-use contents are not redistributed in this repository. No supplied crosswalk or suggested sample size is treated as an authoritative framework requirement.

## Production completion requirements

1. **Source admission:** workload identities, source-specific permissions, signed job manifests, replay protection, immutable raw evidence and independently retained checkpoints. Extend the existing portable admission design to this generic schema before any production gate consumes it.
2. **Approved policy contracts:** reviewer identity and separation of duties, policy interpretation approval, exceptions with expiry, framework/edition applicability and regression-tested extraction/assertions. Models propose changes; approval is a separate capability.
3. **Collection orchestration:** declared expected populations, event plus periodic collection, bounded retries, connector health and independent scheduler heartbeats. Losing monitoring cannot resolve a finding.
4. **Alert delivery:** a durable transactional outbox, destination allowlists, redacted payloads, idempotency, signed requests, bounded retry/dead-letter handling, delivery receipts and explicit acknowledgement/escalation. Slack, Teams, Jira, email and PagerDuty are destinations to implement/configure; this build sends none. A notification failure must not erase the finding.
5. **Scale and retention:** migrate prototype workspace JSON/history into separately indexed records, encrypted object storage, backup/restore tests, retention and legal hold. Current limits are 50 active contracts, 1,000 total checks, 500 records per history collection and 3.5 MB per workspace; the application audit also has a 5,000-event limit. These are bounded prototype storage, not a production retention policy.
6. **Controlled reporting and trust publication:** versioned normative schemas, field-level evidence citations, automated schema checks, human conclusions/signatures and approved audience-specific projections. Generic findings do not auto-publish to the trust center. Sensitive raw evidence and CUI should not enter an unapproved hosted workspace.

## Primary references checked September 7, 2026

- [FedRAMP schemas](https://www.fedramp.gov/schemas/): published OCR, SDR, significant-change and vulnerability schemas require dedicated schema-valid exporters; an internal JSON draft is insufficient.
- [Vulnerability detection and response](https://fedramp.gov/2026/reference/vulnerability-detection-and-response/) and [evaluation and reporting](https://www.fedramp.gov/2026/reference/vulnerability-evaluation-and-reporting/).
- [Secure Configuration Guide](https://fedramp.gov/2026/reference/secure-configuration-guide/) and [significant change notification](https://fedramp.gov/2026/reference/20x/c/significant-change-notification/).
- [AICPA SOC resources](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services).
- [DoD CMMC resources](https://dodcio.defense.gov/cmmc/Resources-Documentation/) and [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program).
- [ISO/IEC 27001](https://www.iso.org/standard/27001) and [ISO/IEC 42001](https://www.iso.org/standard/42001).
