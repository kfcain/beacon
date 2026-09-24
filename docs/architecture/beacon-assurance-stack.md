# Beacon assurance stack

Status: design accepted. This change adds the architecture and thin sketches. It does not submit a package.
Date: 2026-09-24.

The assessment-scope phases 0–6 stay in [assessment-scope-and-jev.md](assessment-scope-and-jev.md). This document starts at phase 7. Main already pins SCF 2026.3. This document does not change `beacon/scf/catalog/PIN.json` and does not vendor `controls.json`. It does not invent SCF control ids. Example ids follow the 2026.3 workbook Legacy SCF # map: IAC-01 (IAM) is IAC-02, CRY-05 (Encrypting Data At Rest) is CRY-07, and GOV-01 (SCRP) is GOV-02. The blocked framework id `usa-federal-gsa-fedramp-20x-ksi` stays in `not_a_framework_id`. It is not a framework id and it is not an SCF control id.

The package shape below follows the attached CR26 Class C submission guide, version `v2026.09.13.02`. Rule ids in this document are citations of that guide. A citation is not a statement that Beacon has met the rule.

## Problem

Beacon seals bytes. Operators also need a path from an assessment boundary to a machine-readable authorization package. The path has to keep people, process, and technology as data. Word files, PDF files, and screenshots are not the source of truth. A human can read Markdown rendered from the same objects.

A seal still does not mean a control is met. The words compliant, evidenced, and proven still require `decide_claim` plus a linked receipt. A KSI method count is a package rule. It is not that gate.

## Decision

Beacon remains the custody engine. It collects, seals, witnesses, stores the lake, answers ledger queries, compiles pack drafts, and exports trust-center copies. Two siblings stay outside this repository:

| System | Role |
| --- | --- |
| Beacon | Custody engine: collect, seal, witness, lake, ledger queries, pack compilers, trust-center export |
| Nomos / program-as-code (external sibling) | Git source of truth for policies, roles, debt and POA&M, and significant change. Beacon points at git SHAs as evidence |
| grc-pdf-mapper (https://github.com/kfcain/grc-pdf-mapper) | Optional ingest of legacy PDF or Word into git-native policy statements and KSI maps. It is not the long-term store |

```
interactive scope workshop (solutions, risks, components/services + context)
  → tags (platform/evidence/owner/automation/framework) + multi-framework context
  → commit hashed ScopeDocument
  → fetcher plan (agent proposes; registry + catalog fail-closed)
  → collect/seal (custody) + optional lake
  → evidence ledger (by control/KSI/AO, freshness, method counts)
  → package compilers (20x CPO/SDR/OCR/SCG; CMMC AO views; Rev5 SSP/POA&M/CVMP/BoE as structured objects)
  → trust center publish (packs/reports only) + SCN + security-inbox ops
```

An agent may propose a draft. An agent must not commit a scope, a policy, or a significant-change notice. A human commits. Beacon then hashes and seals.

## A. Interactive scope workshop

Draft files belong under `.beacon/scopes/drafts/`. A human commit writes `.beacon/scopes/{scope_id}.json` and the writer recomputes the canonical SHA-256. `beacon scope init` already writes schema version 1 at the commit path. This change does not add a draft writer and does not add a workshop UI.

A component or service row has `kind`, `id`, `role`, `platform`, `context`, `solutions_refs`, `risk_refs`, and `status`. `kind` is `component` or `service`. `status` is a workshop state: `proposed`, `in_scope`, or `excluded`. Those words are not SDR status words and they are not claim words.

`beacon/scope/draft_v2.py` defines `ScopeDraftV2`. Schema version is `2`. The draft wraps a version 1 `ScopeDocument` and adds `components`, `tags`, and `framework_context`. `ScopeDocument` stays `schema_version` 1 with `extra=forbid`. A version 1 file still round-trips. `load_scope` rejects a version 2 file. The draft module does not write a file.

## B. Tags

A tag is `namespace:value`. It is custody metadata. It is not a claim.

| Namespace | Closed set in this change |
| --- | --- |
| `platform:` | `aws`, `azure`, `gcp` (builtin collectors) |
| `evidence:` | `cloud_inspector`, `lake_log_extract`, `catalog_pin`, `drop_in`, and `policy` |
| `owner:` | Empty unless the caller passes an allow-list |
| `automation:` | `automated`, `manual` |
| `framework:` | Framework ids on the vendored 2026.3 pin summary |
| `control:` | Seeded ids `IAC-02`, `CRY-07`, `GOV-02` |
| `risk:` | Empty. The pin summary counts risks and does not list risk ids |

`evidence:policy` names a later seal of a git tip SHA. It is not an `allowed_evidence_kinds` value on `ScopeDocument` v1. An unknown namespace or an unregistered value fails closed. `framework:usa-federal-gsa-fedramp-20x-ksi` fails closed. `control:IAC-01` fails closed because 2026.3 IAC-01 is a different control than the seeded IAM id.

Parser: `beacon.assurance.tags.parse_tag`.

## C. Multi-framework context

SCF stays the hub. Each selected framework keeps its own `required_components`, `rules`, and `tags` on `FrameworkContext`. A crosswalk is a lens. The draft does not merge two frameworks into one control row.

`framework_id` must be on the vendored pin summary (270 crosswalk ids). The blocked id `usa-federal-gsa-fedramp-20x-ksi` fails closed. A framework context must name a framework that is already on the wrapped version 1 document. A `required_components` id must name a component on the draft. Rule labels are operator tokens. This change does not ship a CR26 rule catalog and does not invent rule ids inside the model.

Version 1 `ScopeDocument.frameworks` still accepts a non-blank label. The stricter pin check applies when that document is wrapped in `ScopeDraftV2`.

## D. Evidence ledger and KSI counters

A later index will group sealed evidence by scope, control, KSI, assessment objective, tags, and freshness. This change adds a pure function, `ksi_method_report`, over fixture records. Each record carries `scope_id`, `ksi_id`, `method_id`, `automated`, and `evidence_sha256`. Optional fields are `s3_uri`, `git_sha`, `ao_id`, `control_ref`, and `sealed_at`. The record does not carry observation bytes.

The same `method_id` counts once. A manual method is listed and does not count. The caller may pass `not_before`. A record older than that instant is excluded. A record with no `sealed_at` is excluded when `not_before` is set. This function does not choose the window. The lake's 24-hour freshness field stays a separate rule.

| Package class | Automated methods per KSI | Source |
| --- | --- | --- |
| `c` | at least 2 | CR26 Class C guide, rule FRC-CSX-VVK |
| `d` | at least 4 | Assurance-stack brief. The attached guide is Class C only. This document does not invent a Class D rule id |

The report returns `automated_method_count`, `minimum`, and `shortfall` per KSI label. `shortfall` is a package gap. It is not a met flag. The guide says the package covers all 46 KSIs. This repository does not list those 46 ids. When the caller omits `required_ksi_ids`, `required_list_supplied` is false and only labels present on counted records appear. Fixture KSI labels in tests use the prefix `fixture-ksi-`. They are not FedRAMP KSI ids.

The guide also cites KSI history (FRC-CSX-MOT), including the assessor note for a new service in the first 6 months. That note is an assessor position. It is not implemented here.

## E. Package compilers

CR26 Class C names three JSON parts plus the secure configuration guide:

| Guide name | Guide ids cited | Beacon `pack_type` today | Sketch kind |
| --- | --- | --- | --- |
| Certification Package Overview (CPO) | CPO-CSO-OVR, CPO-CSO-OSA | none | `cpo` |
| Security Decision Record (SDR) | SDR-CSO-FRR; the guide prints SDR-CSX-KMT on page 1 and SDR-CSX-KSI plus SDR-CSO-MTD on page 4 | `security-decision-record` | `sdr` |
| Ongoing Certification Report (OCR) | CCM-OCR-AVL | `ongoing-certification-report` | `ocr` |
| Secure Configuration Guide (SCG) | SCG-CSO-AUP | `secure-configuration-guide` | `scg` |

`bundle` stays the evidence bundle. It is not a CR26 document. This change does not add `cpo` to `BEACON_PACK_TYPE` and does not change `beacon push`.

`compile_pack_draft` returns a draft object. Evidence is a pointer: `sha256`, optional `s3_uri`, optional `git_sha`. An `s3_uri` that points at an `observations/` prefix fails closed. Human fields from the guide stay in `unset_fields`. The sketch does not fetch the schema URLs on page 4 of the guide. Those URLs are the later validator target:

- `https://fedramp.gov/schemas/fedramp-certification-package-overview-schema-2026-06-24.json`
- `https://fedramp.gov/schemas/fedramp-security-decision-record-schema-2026-06-24.json`
- `https://fedramp.gov/schemas/fedramp-ongoing-certification-report-schema-2026-06-24.json`

CPO field names cited by the guide, and left unset here, include `serviceIdentification`, `contactInformation`, `serviceProperties.trustCenter.url`, `serviceProperties.secureConfigurationGuidance`, `serviceProperties.assessor`, and `nextOngoingCertificationReportDate`.

SDR field names left unset include `certificationPackageOverviewUri`, `fedRampRequirements`, `keySecurityIndicators`, and `metadata`. The guide says the schema marks `keySecurityIndicators` and `metadata` optional, and that SDR-CSX-KSI and SDR-CSO-MTD require them for 20x. This sketch does not fill them. It does not emit the schema status words Implemented, Partially Implemented, or Not Implemented.

OCR field names left unset include `reportPeriod` (`from` and `to`), change lists, `acceptedVulnerabilities`, and `reportableIncidents`. The guide says an empty incidents array attests that no reportable incident occurred. The sketch does not emit that array.

SCG leaves `instructions_to_get_and_use` unset. The guide requires those instructions (SCG-CSO-AUP).

Other guide facts that later compilers must keep, and that this change does not automate:

- Open items use the first matching row. A MUST failure (the guide's example is fewer than 2 automated methods for a KSI) is closed before submission (FRD-MST). A SHOULD or MAY failure can be submitted with an SDR explanation (FRD-SHD). A real weakness is tracked as a vulnerability in the SDR (VDR-CSO-RES). 20x has no POA&M.
- An item with no fix, or open past 192 days, is an accepted vulnerability on the OCR (VER-TFR-MAV).
- Assessment age at submission is 3 months (FRC-APP-FIA), with a changes-only review up to 9 months (FRC-APP-USA). Package refresh is 7 days (FRC-APP-FCP). After certification, the maximum interval between package updates is 2 weeks (CPO-CSX-CPM).
- The FedRAMP ID goes on every file and message (CDS-CSO-FID). The sketch copies `fedramp_id` only when the caller supplies it.

### CMMC assessment objectives

The pin already contains the framework id `usa-federal-dow-cmmc-2-level-2`. A later compiler joins 800-171A assessment-objective labels to evidence pointers, including a git policy tip SHA tagged `evidence:policy`. This repository does not vendor assessment-objective ids. An unknown objective id fails closed. This change does not emit a CMMC view.

### Rev5 and CUI structured objects

The pin already contains `general-nist-800-53-r5-2` and `usa-federal-gsa-fedramp-5-high`. A later compiler emits these as structured objects, with people, process, and technology fields:

| Object | Role |
| --- | --- |
| SSP | System security plan |
| POA&M | Plan of action and milestones. This is a Rev5 object. It is not a 20x POA&M. 20x has no POA&M |
| CVMP | Configuration and vulnerability management plan |
| Body of evidence | Evidence pointers for a FedRAMP-certified service, plus responsibility matrices, baselines, and techniques and tools |

Beacon does not generate those documents in this change. LIMITS still says Beacon does not generate OSCAL, SSPs, or POA&M documents.

## F. Git policy and the mapper bridge

Prefer git Markdown or YAML policies mapped to scope systems and processes. Nomos holds that git source of truth. The mapper path is:

1. Analyze a legacy PDF or Word file in grc-pdf-mapper.
2. Propose policy commits.
3. A human commits.
4. Beacon seals the tip SHA as `evidence:policy`.

Policy-as-code lockstep between policy and Terraform stays a mapper and Nomos concern. Beacon seals the artifacts that those systems produce. This change does not call the mapper and does not read a PDF.

## G. Trust center, SCN, and the FedRAMP security inbox

`public/trust-center/` already accepts pack and report copies and refuses raw observations. Scope documents and judgment receipts stay off that prefix. This change does not host a trust center and does not upload a new object class.

Later trust-center work, cited from the guide and not built here:

| Guide point | Rule ids | Later Beacon behavior |
| --- | --- | --- |
| The package lives in a FedRAMP-compatible trust center | CDS-CSO-UTC | Publish packs and reports only |
| CPO `serviceProperties.trustCenter` names the URL, `authenticationRequired`, and access steps | field names on guide page 3 | Fill those fields from operator config when the CPO compiler is real |
| Just-in-time access for `@fedramp.gov` and `@gsa.gov` | CDS-TRC-USH, AFC-CSO-TFG | Confirm the address. Grant named, least-privilege, time-limited access. Do not use a shared link |
| Access logs | CDS-TRC-ACL | Keep access summaries at least 6 months |
| Programmatic access | CDS-TRC-PAC | Publish API docs for the package |
| FedRAMP ID on artifacts | CDS-CSO-FID | Stamp the id the operator supplies |
| Quarterly OCR in the trust center, snapshot retained, review invite | CCM-OCR-AVL, CDS-CSO-HAD, CCM-QTR-MTG, CCM-QTR-SAR, CCM-OCR-NRD | Human publish. No separate PMO notice (FRD-ANP) |

Significant-change notification (SCN) is a draft built from significant-change objects whose source of truth is Nomos git. A human sends it. This change does not send mail.

The FedRAMP security inbox is an operations runbook: watch the inbox and reply (AFC-CSO-INB). It is not a collector. Beacon does not poll that inbox in this change.

## H. Phased build plan

Phases 0–6 remain the assessment-scope plan. Do them as that document says. This stack adds phases 7–11. The sequence Kyle asked to proceed through is the five slices below. Existing phase 2 (scope bind) sits between slice 1 and slice 2. Bind is not renumbered.

| Order | Phase | Slice | Done in this change |
| --- | --- | --- | --- |
| 1 | 7 | Interactive workshop, tags, and multi-framework context. Draft path `.beacon/scopes/drafts/`. Agents propose. A human commits. Version 1 files stay valid. | Design, `ScopeDraftV2`, and the tag registry. No workshop UI. No draft writer. No auto-commit. |
| 2 | 2 | Scope bind from the assessment-scope ADR. `collect` and `push` copy `scope_id` and `scope_sha256` when `--scope` is set. `check` recomputes the hash. | No. Ledger counts are not bound to seals until this phase exists. |
| 3 | 8 | Evidence ledger and KSI counters. Class C at least 2 automated methods. Class D at least 4. Gap view. Index by scope, control, KSI, assessment objective, tags, and freshness. | Pure `ksi_method_report` and fixture tests. No lake index. No list of 46 KSI ids. |
| 4 | 9 | Pack compilers. Schema-valid CPO, SDR, OCR, and SCG, plus Markdown from the same objects. Then CMMC assessment-objective views and Rev5 SSP, POA&M, CVMP, and body-of-evidence objects. | `compile_pack_draft` emits pointer drafts and `unset_fields`. No schema fetch. No `beacon push` change. No CMMC or Rev5 emitter. |
| 5 | 10 | Git policy ingest bridge. Mapper proposes commits. A human commits. Beacon seals the tip SHA as `evidence:policy`. | Design only. |
| 6 | 11 | Trust-center publish of packs and reports, SCN draft from significant-change objects, security-inbox runbook. Just-in-time access, access logs, programmatic API docs, FedRAMP ID on artifacts. | Design only. The current trust-center refusal of raw observations stays as it is. No mail send. |

Phase 2 scope bind is implemented. `collect` and `push` copy `scope_id` and `scope_sha256` when `--scope` is set. `check` recomputes the hash. Ledger counts are still not bound to seals.

Phase 7 is the review surface for phases 8–11. Phases 3–6 of the assessment-scope ADR (candidate builder, Jev, lake index, claim-word display) stay in force. A KSI shortfall of 0 does not permit a claim word. `decide_claim` still does.

## Non-goals

This change leaves the following work out:

- A workshop UI, a draft file writer, and any auto-commit
- A live FedRAMP schema fetch or a live submission
- A live Jev client and a witness `Record` version change
- New SCF control ids, a fabricated 20x crosswalk id, or a vendored list of 46 KSI ids
- A change to the SCF catalog pin
- Trust-center hosting, SCN email, and security-inbox collection
- Private keys in the repository, or raw observations on `public/trust-center/`
- Edits to draft pull requests #5 and #2
