# Northstar Casework: a fictional 20x walkthrough

Open **20x walkthrough** in Beacon. The seven steps persist their progress in your private workspace. No vendor credentials, real agency information or network collection are involved. The backend imports synthetic responses through the same verification and document paths used by other evidence. Existing workspace records are preserved; reserved sample IDs cannot replace an existing sample population.

Northstar is a 42-person case-management SaaS with three fictional agency tenants. Its offering includes containerized API/workers, a PostgreSQL database, attachment storage, identity integration and a restricted log archive. Customer endpoints and agency identity providers are external dependencies. Four representative assets and six assertions illustrate only part of this boundary.

| Step | What happens | What to inspect |
|---|---|---|
| Load | Four policy/procedure records and four contracts are registered | Six checks start UNKNOWN; policies have no approval |
| Collect | Canned source responses become typed facts | Terraform encryption intent passes while deployed encryption fails; enabled logging passes while a 35-minute canary misses the 15-minute target; access removal takes 6 hours against 4; restore fails at 95 minutes against 60 |
| Draft | SDR, SCG and OCR blueprints receive pinned evidence | All three baseline versions preserve failures and pending assessment |
| Remediate | New synthetic observations show encryption on, 2-minute delivery, 3-hour removal and successful 42-minute restore | Configuration assertions pass; earlier drafts need refresh; recovery remains subject to review |
| Revise | Access policy v2 reduces the deadline to 2 hours | Old assertion still passes; changed policy reference opens reassessment |
| Rebind | Contract explicitly adopts v2 and its 2-hour threshold | Existing 3-hour evidence now fails |
| Finish | New 1-hour access observation and refreshed observations are evaluated; three new drafts are generated | Baseline versions remain unchanged; current drafts reflect new facts |

All numeric targets are Northstar's fictional policy choices, not universal FedRAMP deadlines. Candidate KSI links are selective: KSI-SVC-SIN, KSI-MLA-ALA, KSI-IAM-ELP and KSI-RPL-TRC. The offboarding example only supports one aspect of least privilege; it does not establish workforce-wide least-privilege operation. SOC 2 links likewise remain supporting candidates.

The Evidence tab exposes synthetic raw responses, normalization, assertion results, policy binding and downloadable hashed records. The Documentation tab exposes every policy revision and draft Markdown/JSON report. These remain visible in the main Verification engine and Documents views. The demo action is sequential and revision-checked through the existing authenticated API. It does not approve findings, create trusted evidence or enable production publication.

The current Class C rules call for at least two automated verification and validation methods per KSI. This narrow exercise does not demonstrate full KSI coverage, authenticated or independent methods, period completeness, full inventory, formal approval, vulnerability/incident coverage or official package-schema validation. Reports are instructional drafts, not submission-ready artifacts.

Primary references checked September 8, 2026:
- https://www.fedramp.gov/2026/providers/20x/key-security-indicators/
- https://fedramp.gov/2026/reference/20x/c/fedramp-certification/
- https://fedramp.gov/2026/providers/20x/rules/independent-verification-and-validation/
- https://fedramp.gov/2026/agencies/use/packages/20x/
