# Beacon production engineering and milestone status

This is an executable assurance application and reference deployment package. It is not a completed enterprise deployment, a certified product, or a claim that all previously identified legacy defects have been repaired.

## What is implemented

| Milestone | Implemented and locally verified | Remaining deployment or product work |
|---|---|---|
| Interactive SaaS workspace | Nine working views, claim drawers, scenario execution, filters, evidence downloads, implementation editing, provider review, document generation, requirement drafts, trust releases and actual MCP workbench | Browser visual/accessibility QA and user acceptance testing |
| Portable application | Same React GUI and domain engine with Node HTTP API, SQLite persistence, scoped bearer tokens, HttpOnly sessions and separate workspaces | Enterprise OIDC/SAML, organizational membership, fine-grained assessor/publisher roles, session revocation and managed secret delivery |
| MCP | Stdio and stateless Streamable HTTP, initialization, 7 tools, resources, argument validation, read-only defaults on stdio | External OAuth authorization-server integration and broader client interoperability testing |
| Collection | Read-only AWS EC2, IAM and CloudTrail collector; explicit scope; retained partial failures; hashed SDK dependency lock | Live account/Region/trail selection, workload identity, approved network routes, image build and deployment |
| Validation | Strict fields, account/partition checks, operation checks, expected population, timestamps, hashes and fail-closed results | Broader collector/test catalog, witnessed live drift exercises and independent validation of test sufficiency |
| Persistent evaluation | Freshness recalculated on API reads; explicit reconciliation; portable systemd service/timer | Install the scheduler and collection orchestration, queue/DLQ, alerts and run-population reconciliation in the target environment |
| Frameworks | Full pinned source catalog of 246 CR26 rules and 46 KSIs, type/class filters, provider draft records, selected supporting mappings across five programs | Full non-FedRAMP catalogs, licensed content, objective-level mapping review, path/boundary applicability, official package schemas and assessment completeness |
| Documentation | Versioned Markdown implementation records and JSON working records; evidence lineage and pending independent conclusions | Complete CPO/SDR/SCG and process-specific packages, diagram automation, formal document approval and signature workflows |
| Trust center | Built-in sandbox portal, allowlisted releases, versioned JSON, sandbox delivery receipts, external HTTPS/HMAC relay utility | Real external endpoint and receipt reconciliation, production release authority, agency access inventory/log retention, uninterrupted sharing and availability-history service |
| Signing and proof | Separate KMS signing utility; offline verification against a supplied trusted-key registry; job/image/scope/evidence binding; strict policy/key/encoding checks; one-time admission ledger with concurrent replay rejection | KMS key, key policy, authorized-job registry, source authentication in signer, external monotonic checkpoint and key rotation/revocation operations |
| Container baseline | Separate API and collector Dockerfiles, digest/signature checks, hashed Python dependencies, SBOM/scan commands, nonroot/read-only/runtime restrictions | Docker runtime was unavailable here: images were not built or scanned. Select entitled Chainguard digests, verify applicable CIS controls, crypto modules and deployed host/orchestrator |
| CI/CD | Executable fail-closed CLI; repeatable verification and one-time admission; sample production gate; code-validation workflow | Trusted runner/artifact path, protected policy inputs, OIDC roles, approved action/image digests, registry admission and deployment verification |
| Legacy migration | New application isolated from legacy plugins and private keys; immutable reference to reviewed repository | Legacy witness/TSA code remains a prototype. Do not use its signatures as production assurance; replace or formally retire before claiming migration complete |

## Trust boundaries

Collector, validator, signer and publisher are separate identities. Do not put a signer sidecar in the same credential-bearing task as an untrusted collector. Production should use ephemeral collector tasks, an ingestion service, immutable object versions, a deterministic validator, and an authorized signing/publishing service. This portable reference uses a local database and a separate signing utility; it does not impersonate that entire production topology.

Only deployed policy can enforce network egress, task identity and separation of administration. A Dockerfile cannot establish those properties. The Kubernetes template intentionally denies all network access until approved DNS, STS, source APIs and ingestion routes are configured. It also requires explicit workload-identity token projection and result retrieval. Do not run benchmark scanners with host privileges inside the evidence collector.

Node/Chainguard runtime must support Node 24 and node:sqlite. Python builder and runtime must share an ABI and compatible library stack. The FIPS variant must actually route required cryptography through validated modules in an approved operating environment. Inspect TLS and all application crypto paths; an image brand or an approved algorithm does not establish FIPS conformance.

Use organization-approved mutable-input controls. Base images, action versions, collector digests, tests, framework versions and signer registries are independently reviewed release inputs. The final application image needs its own SBOM, scan, signature and provenance; base-image evidence does not automatically cover added software.

## Data and scale

The hosted demonstration is owner-private. Every request uses the platform-authenticated user ID as its workspace key. The portable server maps configured tokens to a workspace and reader/operator role; browser sessions are one hour and process-local. Put remote portable deployments behind TLS, a rate-limited identity gateway, and an organization-approved secret delivery system. Do not reuse demonstration tokens in production.

Workspace writes use revision comparison to prevent lost updates. SQLite uses WAL and a busy timeout; hosted storage uses conditional D1 updates. JSON workspaces are intentionally bounded (500 runs, 5,000 audit entries and approximately 3.5 MB). Archive and migrate to normalized records and object storage before those limits. Historical documents and runs are retained; raw JSON evidence is limited to 250 KB per import. Backup/restore, disaster recovery, high availability and six-month access-summary retention must be designed and exercised in the target environment.

The admission ledger persists one receipt per job ID and rejects reuse across process restarts. Its explicit initialization avoids silently resetting replay state when a database is missing. It is a local service primitive: durable protected storage, an independent checkpoint, authenticated job issuance, and an external admission endpoint still require deployment. See [Admission](ADMISSION.md).

The audit chain detects alteration against available history. Without an independently retained head, it cannot detect a complete valid-prefix rollback. Exports are forensic working data, not signed certification packages. Incomplete or tampered test fixtures can be exported for examination and correctly fail the bundle verifier.

## Production release gates

1. Register the exact service boundary, account/Region/resource population, classifications, customers and shared responsibilities.
2. Establish scoped federation, secret handling, egress and admission enforcement; deploy a verified image.
3. Collect the approved population and preserve every error, expected run and immutable input version.
4. Verify source execution, job nonce, approved image, scope, signer authorization, retention and external checkpoint continuity.
5. Run deterministic validators and independently replay sampled evidence; execute known-good, known-bad, denied, stale, partial and restored live configurations in a dedicated account.
6. Review the full applicable requirements, parameters, documentation and coverage. Resolve findings and obtain genuine independent conclusions.
7. Authorize publication, verify public-field minimization and test downstream synchronization, agency access and failure availability.
8. Exercise incident response, revocation, restore, key rotation, scheduler failure, missed-event reconciliation and evidence retention.

Production publication is deliberately rejected by the current application. Completing a simulated flow or adding a live label cannot override that gate.

## Source grounding

- [CR26 structured source, pinned commit](https://github.com/FedRAMP/rules/blob/58efbf3d898496dd4a3a419eba78e458bbad5cb6/fedramp-consolidated-rules.json): version 2026.07.14.01. This is a pinned reference, not an automatic assertion that newer rules do not exist.
- [Rev5 Security Decision Record](https://www.fedramp.gov/2026/providers/rev5/rules/security-decision-record/)
- [20x Security Decision Record](https://www.fedramp.gov/2026/providers/20x/rules/security-decision-record/)
- [Certification Data Sharing](https://fedramp.gov/2026/reference/certification-data-sharing/)
- [Chainguard signature verification](https://edu.chainguard.dev/chainguard/containers/how-to-use/verifying-chainguard-images-and-metadata-signatures-with-cosign/)
- [Chainguard FIPS verification](https://edu.chainguard.dev/platform/fips/verify-fips/)
- [Docker CIS scope](https://docs.docker.com/dhi/explore/security-concepts/cis/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [MCP 2025-11-25 transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

Framework mappings are selected, supporting candidates. NIST Rev5, CMMC L2/SP 800-171 Rev2, ISO 27001:2022 and SOC 2 criteria are not interchangeable. Framework editions, assessment objectives, organization-defined parameters, exceptions and independent determinations must remain separate.
