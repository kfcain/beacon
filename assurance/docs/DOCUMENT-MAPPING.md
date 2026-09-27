# Policy and procedure mapping with GRC PDF Mapper

Beacon integrates with [kfcain/grc-pdf-mapper](https://github.com/kfcain/grc-pdf-mapper), reviewed and tested at commit `c340144b3b4071bd569b5fd15669300ee666dc88`. It uses that repository's `MappingReport` contract and `/api/analyze` API. The Python extraction/classification/crosswalk engine is reused through a private service; it is not rewritten as a competing JavaScript classifier.

## What works

In Beacon → Documents, import a mapper CLI JSON report or the mapper GUI's full JSON payload. The upload panel also accepts PDF, DOCX, Markdown and text when a private mapper service is configured. For direct document uploads enter a stable ID such as `pol-access-control`; reuse it for subsequent versions. Report imports use their embedded `doc_id`.

The workspace shows source statements, heading/page metadata when the mapper supplies it, obligation kinds, classification reasons and scores, and proposed framework mappings with their original source and relationship. Filter by framework or search statement text. Inspect the original extracted text as escaped text; embedded HTML and instructions are not executed.

Click an individual mapping, record a rationale, accept or reject it, and optionally link it to a Beacon claim. Accepted mappings from the latest document version appear in that claim's evidence drawer and generated implementation record. They do not change its operational test result. Exported review records contain the retained report, source hash and decision history. Reimporting an exported record imports its report only; it does not trust or reinstate supplied review decisions.

Versions preserve previous reports and reviews. Added/removed statement text is shown as an exact-text comparison, not a semantic drift determination. A new version starts without approvals even if some wording is identical, because mappings or extraction may have changed. Previous accepted mappings no longer count as current claim references. Nothing uploads policy text to the trust center; public release fields remain explicitly allowlisted.

MCP's read-only `beacon_policies` tool exposes the same imported versions, mappings and review history. Its instructions label document text as untrusted data. It cannot execute document instructions or publish a policy.

## Use without a hosted mapper service

Install the reviewed mapper release in an isolated Python environment using its repository instructions and organization-approved dependency locks. Markdown works with the core dependencies; PDF and Office conversion require the mapper's optional converter packages.

```sh
grc-pdf analyze policies/access-control.md \
  --doc-id pol-access-control --version v1 \
  --offline --no-commit --json access-control-report.json
```

Upload `access-control-report.json` in Beacon → Documents. No mapper credentials are needed for report import. The original document hash is a claim made by the imported report, so its provenance remains `UNVERIFIED_DOCUMENT_REPORT`. Beacon calculates its own normalized report hash for later integrity checks.

## Direct uploads through the mapper API

Run the mapper's existing GUI/API service in a separate parser environment. Its upstream local GUI has no application authentication; do not expose it directly. Place `/api/analyze` behind your organization's HTTPS identity gateway, requiring the service bearer token, and allow only Beacon to reach it. Keep its other endpoints private. Put the parser on an identity with no collector, signer, publisher or production infrastructure credentials. Enforce outbound denial and resource/time limits at the container/host layer. An `offline=true` parameter controls the crosswalk engine's behavior; it is not a network sandbox.

Configure server-side runtime values (portable process environment or hosted Site secrets):

```text
BEACON_MAPPER_URL=https://YOUR-PRIVATE-MAPPER/api/analyze
BEACON_MAPPER_TOKEN=<dedicated service token of at least 32 characters>
```

No endpoint or token is taken from a document, browser field or MCP argument. The shared adapter sends multipart `file`, `doc_id`, `offline=true`, `format=json`; it requires HTTPS, rejects redirects, limits upload and response sizes, times out, and checks the returned document ID and source SHA-256 against the uploaded bytes. The service token stays server-side. Gateway authorization and parser isolation must be enforced by the deployment, not assumed from the presence of an Authorization header.

The authenticated Beacon upload endpoint is `/api/documents/map`. Portable deployments require an operator role to submit documents. A missing service returns an explicit disconnected state; it does not fabricate a mapping result. The hosted Python mapper service has **not** been provisioned or connected as part of this change.

## Limits and evidence meaning

- Direct uploads: 6 MiB; initial allowlist is PDF, DOCX, Markdown and text. Macro-enabled Office formats are excluded. File signatures catch basic mismatches; they are not malware scanning or a full archive validation mechanism.
- Imported JSON: the UI accepts up to 4 MiB and normalizes before persistence. Normalized report limit: 240,000 characters, 500 statements, 500 candidates per statement, 180,000 characters of extracted text. Oversized reports are rejected, not silently truncated; split large documents into sections for this reference runtime.
- Thirty stored policy versions maximum, subject to the existing overall workspace/storage limits. Original binary files are sent to the parser but not retained in Beacon. Before production, add quarantined object storage, immutable source versions, malware scanning, parser job isolation, OCR review and retention controls. A hash without the retained original is not a complete evidence archive.
- A mapper score is its reported heuristic score, not a calibrated probability or assessor conclusion. SCF and seed crosswalks are candidate relationships, not proof that every mapped requirement is met. Framework editions, assessment objectives, ODPs, applicability and inheritance still need review.
- Mapper CR26 results reflect the mapper's catalog. Beacon's pinned CR26 browser has its own source version. This integration does not silently equate editions or declare official package coverage. Record and reconcile catalog versions before relying on either for an assessment.
- OCR gaps are visible. A scanned/empty document or zero extracted statements must not be treated as a clean bill of health.
- Reports are minimized to source statements and candidate mapping fields. Upstream raw catalog objects and local source paths are not retained. Catalog licensing and source attribution remain applicable; see the mapper repository's SCF attribution.

## Verification performed

29 Node tests pass, including policy versioning, review references, source binding, mapper URL/format rejection, hash tampering and the read-only MCP path. A separate integration run used the actual pinned Python mapper to generate a report, then exercised Beacon's authenticated HTTP import, mapping review, claim linkage, reader-role denial, disconnected-service response and MCP retrieval. A larger upstream access-control fixture also normalized successfully: 25 statements and 902 candidate mappings, reduced from a 412 KB raw report to a 193 KB retained report.

Reproduce the actual-engine integration with the reviewed mapper installed in your Python environment:

```sh
python tests/mapper_integration.py
```

The mapping HTTP transport test supplies an actual-engine report through a controlled response; a live HTTPS mapper deployment was not exercised. PDF/DOCX conversion and OCR were not tested in this session. Browser visual testing was not performed. Worker and portable client builds and TypeScript checking are separate release checks.
