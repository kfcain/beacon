# Beacon: organization-wide assurance blueprint

Beacon should be the operational record connecting an organization's assets, security requirements, implementations, policies, evidence, decisions and public claims. Its advantage should be the precision and inspectability of those relationships. A large connector count or a convincing green dashboard alone is insufficient.

This document distinguishes the working implementation from the product we should build. No discovery of the user's real organization, cloud account, corporate tenant or production system occurred in this session.

## What the CGE-P capstone contributes

Reviewed source: [kfcain/cgep-capstone](https://github.com/kfcain/cgep-capstone/tree/ae185730f85b20dc456a2d0e8915133015a47dc2), commit `ae185730f85b20dc456a2d0e8915133015a47dc2`.

The capstone connects Terraform hardening, five Rego policy families, a GitHub Actions plan/gate/apply/sign/upload sequence, CloudTrail and an Object Lock evidence vault, and a selected CMMC Rev2 OSCAL component. Its write-up explicitly separates the synthetic training deployment from certification or permission to process CUI. Preserve that honesty in Beacon.

### Findings that change the production design

| Finding in the reviewed code | Consequence | Production change |
|---|---|---|
| Policies read only `planned_values.root_module.resources` and match fixed addresses | Child-module resources and other workloads do not receive equivalent coverage | Walk nested modules; retain repository, workspace, account, Region and full resource address; use reviewed resource selectors and expected populations |
| Some deny bodies bind a missing resource before evaluating the condition | A missing resource can produce no denial | Make absence, unknown values, failed collection, unsupported checks and an empty evaluation explicit non-passing outcomes |
| TLS content is checked only when the policy value is known | An unknown policy can avoid that denial during planning | Block unresolved security-critical facts or require a separately controlled post-apply verification before acceptance |
| S3 check tests `aws:kms` but not key identity; DynamoDB tests `enabled` | The rule title promises more than the test establishes | Check the exact key and its provenance/ownership; do not equate an algorithm name with approved cryptographic operation |
| IAM policy parsing assumes particular Action/Resource shapes and excludes KMS wildcard suffixes | Broader policy semantics need additional tests | Normalize scalar/list forms; evaluate Allow/Deny, resource scope, conditions, service-specific wildcard implications and policy population |
| Workflow has PR/push/manual triggers but no periodic reconciliation | Out-of-band runtime drift and missed collections are not continuously detected by this workflow | Combine scheduled reconciliation with event triggers and independent expected-run monitoring |
| Signing/upload steps run only on success | Failed gates and partial execution are absent from that vault path | Preserve sanitized failure, timeout, denial and cancellation records; do not let evidence publication imply success |
| Signing follows apply but the archived files are plan JSON and Conftest results | A signature does not prove applied configuration or runtime behavior | Bind apply receipt, post-apply readbacks, behavioral probes, collector identity and exact object versions |
| Vault uses GOVERNANCE retention for one day and `force_destroy=true` | This is a short-lived training posture, not a production retention design | Independently administer retention and bypass permissions; choose approved retention/legal-hold behavior and protect against deletion or rollback |
| No remote Terraform backend is declared in the shown configuration | The default local-state workflow on ephemeral runners does not itself provide durable locked state | Configure protected remote state, encryption, locking, backups, narrow access and controlled plan/apply handoff |
| Workflow roles and permissions are broad at the job level; actions use tags; downloaded Conftest archive has no digest check | Plan evaluation, deployment and evidence publication need stronger separation | Pin action/binary digests; separate plan, apply, collect, sign and publish identities; protect policy inputs and OIDC subjects |
| OSCAL evidence links use a configured-at-runtime placeholder and `LATEST/receipt.json`, but the workflow does not create that receipt | The component is not yet a durable, resolvable evidence index | Generate a manifest/receipt and bind immutable artifact version IDs and hashes; validate references and schemas |

**Reproduced with OPA 1.8.0, checked against its published SHA-256:** the capstone access namespace returned an empty deny set with the expected IAM policy absent. The storage namespace also returned an empty deny set for a constructed input with unknown TLS policy content, no S3 key identifier and no DynamoDB key identifier. These are targeted counterexamples, not a statement that every capstone gate fails open. We did not alter the capstone repo or revalidate its historical deployment claims.

## Operating model

An organization contains business units and service boundaries. Each boundary declares accounts, subscriptions, tenants, sites, networks, workloads and data classifications. Resources belong to those boundaries and owners. Requirements are versioned and include applicability, assessment objectives, parameters, inheritance and expected evidence. Policy documents describe intent; IaC describes planned configuration; runtime observations describe sampled reality; behavioral tests describe observed outcomes; review records explain sufficiency and decisions.

Maintain separate timelines for planned, applied, observed and independently assessed state. A clean plan cannot substitute for a readback. A readback cannot substitute for a restore exercise. A fresh object hash cannot establish that a collector saw the real system. A mapping relationship cannot establish that all objectives of a framework requirement are covered.

The user should be able to start from an asset, requirement, document, finding or release and reach the same supporting evidence graph. Every screen must show the denominator: declared scope, discovered scope, expected evidence population, observation age, unassessed resources and exclusions. Never collapse all of that into an unexplained overall compliance percentage.

## Capability map

Status: **working** means implemented in the current Beacon reference; **partial** means a narrow implementation exists; **next** means proposed engineering, not shipped functionality.

| Area | Capabilities | Status |
|---|---|---|
| Organization model | Business units, legal entities, subsidiaries, service boundaries, sites, owner directories, environments, classifications | Partial: declared boundary/provider/account/Region/environment/owner model |
| Asset inventory | AWS Organizations, Azure management groups, M365/GCC High, Entra, Google Workspace, on-prem AD, endpoints, VDI, networks, Kubernetes, SaaS, databases, backup systems | Partial: explicit inventory imports, Terraform projection and unassessed resource records; no complete live discovery |
| Identity reconciliation | Stable resource IDs, aliases, rename/move/deletion history, repository/workspace namespaces, tenant/account boundaries, duplicate resolution | Next; current manifest IDs and full Terraform addresses preserve basic identity |
| Asset relationships | Network paths, service dependencies, trust relationships, identities, data flows, shared-service inheritance | Next |
| Scope completeness | Expected accounts/Regions/resources; discovered-but-unregistered assets; missing sources; connector coverage; last-seen/decommission review | Partial: expected resource population, missing/unregistered observations |
| Requirement library | FedRAMP CR26 rules/KSIs, NIST objectives, CMMC assessment basis, SOC 2, ISO 27001/42001, contractual requirements and internal standards | Partial: pinned CR26 catalog and selected mappings; broader objective catalogs and licensing remain |
| Bespoke requirements | Organization parameters, customer overlays, control variants, geographic restrictions, alternative implementations and applicability decisions | Partial: draft parameters/narratives; versioned executable requirement contracts are next |
| Documentation | Policy/procedure import, clause locations, statement classification, mapping rationale, version comparison, owner review, approvals, renewal | Partial: GRC PDF Mapper report integration and mapping review; direct parser deployment/retention still required |
| IaC and PaC | Terraform plan projection, nested modules, unknown/sensitive handling, Rego testing, runtime adapters, Git change linkage | Partial: working projection, sample Rego gate and declared inventory model |
| Runtime evidence | Read-only source APIs, controlled command collectors, sampling, temporal windows, pagination, denied/partial collection, exact source identities | Partial: three AWS collectors and minimized observation contracts; broad fleet adapters are next |
| Behavioral evidence | MFA bypass attempts, TLS denial, restore tests, alert-delivery tests, access revocation, backup recovery, log arrival | Next; must run in approved test scope with explicit authorization |
| Continuous assurance | Event-driven checks, scheduled full sweeps, queue/DLQ, retry/backoff, expected-run ledger, stale transitions, alert escalation and recovery | Partial: on-read freshness and replayable scenario histories; orchestration and alerts are next |
| Evidence trust | Approved collectors/policy bundles, workload identity, signatures, immutable objects, independent checkpoints, replay prevention, revocation | Partial: separate signature verifier and local admission ledger; cloud trust operations remain |
| Findings | Asset/objective linkage, severity, exploitability/business impact, owner, due date, remediation evidence, re-test and closure | Next |
| Exceptions | Narrow scope, rationale, compensating controls, risk owner, expiration, reassessment, no silent conversion of FAIL to PASS | Next |
| Change management | PR checks, approved plan/apply binding, production deployment verification, emergency change review, policy-change blast radius | Partial: CLI gates and metadata; enforced production workflow remains |
| Risk management | Risk register, business impact, treatment, acceptance, dependencies, board reporting and loss scenarios | Next |
| Vulnerability operations | Tenable/EDR/cloud findings, exploitability, patch SLAs, asset ownership, rescans and exception linkage | Next |
| Identity assurance | Entra/AD/IAM population, privileged roles, service identities, MFA enforcement, access-review closures, orphaned accounts | Next beyond the narrow AWS root-MFA assertion |
| Data assurance | Classification, data stores/flows, CUI/PHI/ITAR scope, key custody, retention, backups, residency and DLP relationships | Next; do not infer classification from a tag alone |
| Third-party assurance | Supplier dependencies, inherited controls, dated assurances, evidence rights, vendor changes and expiring attestations | Next |
| Audit workbench | Examine/interview/test evidence, samples, independent verifier roles, challenge/replay, assessor notes and signed conclusions | Partial: provider records; independent-role workflow is next |
| Package generation | Human-readable and schema-valid CPO/SDR/SCG or applicable artifacts, OSCAL, objective evidence indexes and immutable references | Partial: versioned drafts, not complete official packages |
| Trust center | Audience-specific facts, field minimization, approvals, NDA/access, agency access, expiration, revocation, delivery history | Partial: sandbox release/relay only; production publishing remains blocked |
| GUI | Organization/boundary/resource navigation, intended-vs-observed table, evidence details, policy mapping, scenario exploration | Working reference; user acceptance/accessibility QA remains |
| TUI | Keyboard navigation, filtering, resource/claim/policy inspection, refresh, offline snapshots and structured output | Working read-only Python terminal client |
| API and MCP | Shared domain model, scoped identity, read-only inspection, bounded writes, tool permissions, audit history | Working reference; enterprise OAuth/SSO and fine-grained authorization remain |
| Search | Asset/control/document/owner search, saved queries, saved views, event timeline and cross-link exploration | Partial filters; unified indexed search is next |
| AI assistance | Proposed mappings, draft narratives, investigation summaries, missing-evidence suggestions, cited reasoning | Partial deterministic mapper; autonomous production changes are not enabled |
| Platform operations | Tenant isolation, normalized storage, queues, immutable object versions, retention, backups, restore, HA, quotas, observability | Partial local SQLite/hosted D1; enterprise operation is next |
| Product administration | SSO/SCIM, RBAC/ABAC, customer-managed keys, connector grants, billing, support access, regional deployments | Next |

## Local security design

Offer three explicit modes: an offline assessment workstation, a local team appliance and a distributed enterprise deployment. They should use the same contracts while making their trust boundaries visible.

| Boundary | Required protection | Local reference today |
|---|---|---|
| Laptop/host | Full-disk encryption, supported patched OS, Secure Boot where applicable, EDR, separate admin account, private filesystem ownership | Deployment responsibility |
| Local API | Loopback binding, strong scoped tokens, reader/operator separation, HttpOnly sessions, Origin checks, bounded payloads, no permissive CORS | Implemented reference; enterprise session revocation and SSO remain |
| TUI | Read-only token in a private file, HTTPS remotely, no redirects or insecure TLS option, no commands from evidence text, clean terminal output | Implemented; snapshot mode is explicitly not live |
| Collector | Rootless nonroot task, read-only root filesystem, dropped capabilities, seccomp/MAC, resource and timeout limits, ephemeral identity, allowlisted egress | Templates exist; enforcement needs deployed host/orchestrator verification |
| Document parser | Separate unprivileged process/container/VM, no cloud/signing credentials, quarantine, malware screening, zip/OCR limits, outbound denial | Mapper adapter exists; production parser isolation is not provisioned |
| Terraform/OPA | Run untrusted plans and policy tests without production write credentials; pin approved binaries, modules/providers and policy bundle; explicit unknown handling | Projection and gate runner exist; controlled production runner remains |
| Signer | Separate administration and identity, KMS/HSM or suitable hardware-backed key, authenticated job source, allowlisted digests and nonce binding | Separate signing utility; service authorization and key lifecycle still needed |
| Evidence store | Private permissions, volume encryption, immutable backups/object versions, independent retention and checkpoint continuity | SQLite permissions/WAL and hashes exist; local admins can still roll back history |
| Network | No public database, local socket/loopback where possible, TLS/mTLS or approved private tunnel, no Docker socket mount, no unrestricted parser egress | Must be enforced by the deployment |
| Supply chain | Exact image digest, verified signature/provenance, SBOM for final image, vulnerability policy, controlled promotion and signed update channel | Build templates; no image build/scan performed here |
| Recovery | Encrypted consistent backups, isolated restore test, independently retained receipt heads, documented recovery and admission halt on mismatch | Not yet exercised |

Chainguard/minimal images reduce attack surface, but are not evidence that all CIS controls are satisfied. Document exactly which image, host and orchestrator settings were checked and where evidence is retained. FIPS conformance depends on the actual validated module and operating environment, not merely an algorithm name or image label.

Do not grant Beacon a single organization administrator credential. Use separate read-only grants per source and boundary. Separate configuration of collectors, review of requirements, management of signer keys, and authority to release trust-center claims. A local single-admin appliance cannot provide genuine administrative independence merely by creating four processes.

## Continuous operation and the evidence contract

Each expected collection has a job identity, approved scope/version, source system, expected population, approved collector/image and policy digests, trigger, deadline and retention target. Preserve start, finish, missing, denied, partial, cancelled and timeout states. Source events accelerate detection; periodic reconciliation catches missed events and discovery drift. Use source-specific budgets, pagination, backoff and concurrency controls.

A concrete operating loop:

1. A PR changes Terraform. Inspect the exact commit using a read-only planning identity. Preserve unknowns and sensitive markers; run unit/negative tests for the policy bundle.
2. Project only approved configuration facts from the plan. Retain the raw plan in a restricted evidence location, because Terraform JSON can contain secrets even when normal terminal output hides them.
3. Evaluate the protected expected manifest and projected facts. Unknown facts, missing resources, unsupported checks and unexpected resources prevent an all-pass gate.
4. Bind approved plan, policy, scope and commit to the release. Apply through a separate identity and preserve the apply receipt. A merge into main is not by itself evidence that the PR-reviewed plan was what ran.
5. Read back real configuration using a collector identity. Compare actual resources with the independent expected population. Run behavioral tests where configuration alone cannot establish the objective.
6. Validate source identity, input integrity, job nonce, collector and test versions, scope, freshness and rule semantics. Preserve the result and all limitations even when a test fails.
7. Alert the owner on meaningful drift; use a reviewed expiring exception if needed. Close a finding only after new evidence and an appropriate review. Do not erase failed history.
8. Reevaluate on relevant changes and at the scheduled interval. Expire evidence when the interval is exceeded; do not leave the last passing result indefinitely green.
9. Reconcile full objective coverage and obtain required provider/independent conclusions. Release only approved, minimized claims to the trust center with fresh-enough evidence and explicit limitations.

Suggested starting cadences are design inputs, not compliance mandates: event-trigger critical identity/network changes plus a daily full inventory; frequent high-risk configuration checks; daily policy/repository drift reconciliation; source-appropriate vulnerability scans; scheduled access reviews and restore exercises. Define the actual cadence from requirement language, risk, source behavior and business operations.

## Requirement-level determination

A production requirement contract needs framework/edition/control/objective IDs, organizational parameters, applicability and boundary, acceptable evidence types, expected population, automated assertions, manual steps, independence needs, freshness, exception rules, aggregation logic and publication constraints. Mapping several frameworks to a single test does not remove their distinct objectives.

Maintain separate states for source authenticity, technical result, evidence completeness, design appropriateness, operating effectiveness, provider conclusion and independent conclusion. A requirement remains unresolved if any necessary component is missing, even when available tests pass. No opaque weighted average should turn an untested critical objective into green status.

Example: an approved policy calls for quarterly privileged-access review. Entra/AD/IAM exports show the population; approved reviewer records show decisions; revocation events and subsequent access tests show closure; the review period and completeness checks establish coverage. An MFA setting, a policy paragraph or a generic AC-2 mapping alone cannot prove that process happened.

## Demonstrate the working slice

In the GUI, open **Infrastructure**, choose **drift**, and run the capstone simulation. Inspect the S3 resource: planned configuration passes while observed configuration fails. Run **missing**, **unknown**, **stale**, and **recovery**. The stale scenario creates a separate training boundary so an old observation cannot replace newer current evidence. Resource history remains available. Other providers and corporate resource types can be registered with an empty checks list; they remain UNKNOWN until checks and observations exist.

For a local portable workspace, the following uses the same database as the API when `BEACON_DATABASE` and `BEACON_WORKSPACE` match:

```sh
node portable/infra-cli.mjs demo drift
node portable/infra-cli.mjs status
node portable/cli.mjs status > /tmp/beacon-demo-snapshot.json
python3 portable/tui.py --snapshot /tmp/beacon-demo-snapshot.json
```

TUI keys: Tab switches Infrastructure/Claims/Policies; j/k or arrows select and scroll; Enter opens details; / filters; r refreshes; q backs out or exits. Snapshot mode is offline. API mode continuously refreshes the portable application:

```sh
python3 portable/tui.py --url https://YOUR-BEACON-API --token-file /protected/beacon-reader.token
```

The token file must be private (0600 or stricter). Provision a dedicated reader token through the portable server's protected configuration. The hosted private Site's platform login is not automatically interchangeable with this bearer-token client; external OAuth/gateway integration is still needed for that endpoint.

For a Terraform plan, first register an independently approved manifest and export its normalized `manifest` object. Do not auto-approve the resource denominator from the same collector being assessed.

```sh
node portable/infra-cli.mjs register approved-manifest.json
terraform show -json reviewed.tfplan > /protected/plan.json
node portable/terraform-project.mjs /protected/plan.json approved-manifest.json FULL_COMMIT_SHA > observation.json
node portable/infra-cli.mjs import observation.json
node portable/infra-cli.mjs evaluate BOUNDARY_ID planned > gate-input.json
opa test policies/beacon -v
node portable/opa-gate.mjs /approved/opa APPROVED_OPA_SHA256 policies/beacon/inventory.rego gate-input.json > gate-result.json
```

The last command always exits 2 and writes its structured result: configuration PASS is reported as overall BLOCKED; failed assertions produce FAIL. The production `infra-cli gate` command also rejects every observation until trusted infrastructure admission is implemented. `evaluate` exports diagnostics only. Rego exposes `configuration_pass` for diagnostics and keeps `allow` false even for self-labeled VERIFIED inputs. Preserve that file on unsuccessful CI runs too. The OPA digest is an independently approved release input, not a checksum accepted from the submitted evidence. The result is a technical configuration diagnostic; it does not authenticate collection or authorize production publication. The current infrastructure path is not yet connected to the separate signed-admission service.

## Implementation limits and next releases

Working now: a shared declared inventory model, versioned manifests and observation history, five narrow configuration checks, nested Terraform projection with sensitive/unknown minimization, expected/missing/unregistered resources, planned-versus-observed UI, scenario execution, read-only TUI, MCP and OPA test/gate examples.

Reference limits: 300 expected resources per manifest, 500 imported observations per run, 100 manifest versions, 200 inventory runs, plus existing overall workspace limits. This JSON storage model is not sufficient for a large enterprise. Split into normalized resource/event tables, queues and immutable object storage before an enterprise pilot. Expected resource identities and source facts are not independently authenticated by the current import path. There is no live organization discovery, scheduler deployment, automatic alert delivery, remediation, enterprise assessor separation or production release authority in this slice.

Prioritize in this order: (1) normalized inventory and evidence storage plus OIDC/authorization; (2) protected job registry and authenticated collectors; (3) readback/reconciliation with failure retention and alerts; (4) complete requirement/objective contracts and independent review; (5) secure parser/source archive; (6) approved trust-center releases; (7) broader hybrid-enterprise connectors. Each release should be accepted using a known-good, known-bad, missing, denied, stale, replayed and restored scenario against its real deployment boundary.

## Primary references

- [Capstone workflow](https://github.com/kfcain/cgep-capstone/blob/ae185730f85b20dc456a2d0e8915133015a47dc2/.github/workflows/grc-gate.yml)
- [Capstone policies](https://github.com/kfcain/cgep-capstone/tree/ae185730f85b20dc456a2d0e8915133015a47dc2/policies)
- [Terraform JSON format, unknown values and nested modules](https://developer.hashicorp.com/terraform/internals/json-format)
- [OPA policy testing](https://www.openpolicyagent.org/docs/policy-testing)
- [S3 Object Lock retention and governance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [FedRAMP Rev5 SDR expectations](https://www.fedramp.gov/2026/providers/rev5/rules/security-decision-record/)
