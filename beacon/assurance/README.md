# 20x pack drafts

`beacon pack compile` writes Certification Package Overview (CPO), Security Decision Record (SDR), Ongoing Certification Report (OCR), and Secure Configuration Guide (SCG) drafts from sealed observations.

The JSON file is the source. The Markdown file is rendered from that same object. This command does not write a Word file or a PDF file.

```bash
beacon pack compile --scope prod-commercial --class c --out .beacon/export/20x
```

`--class c` requires at least 2 distinct automated evidence methods per KSI label. `--class d` requires at least 4. A shortfall is a `package_gaps` row. The draft does not set a schema status word.

`--scope` is optional. When every selected seal shares one scope pair, the draft stamps `scope_id` and `scope_sha256`. `--fedramp-id` is copied only when you pass it.

An unknown tag namespace or an unregistered tag value fails closed. `Record.v` stays 1.

The official CR26 Class C schemas are not vendored here. `official_schema` is `not-fetched`. The field map below is a Beacon map. It is not a statement that a guide rule is met.

## Field map

| Beacon field | Guide field | Filled |
| --- | --- | --- |
| `evidence.sha256` | evidence pointer | seal digest only |
| `scope_id`, `scope_sha256` | Beacon scope stamp | when one scope pair is present |
| `fedramp_id` | FedRAMP identifier (guide citation CDS-CSO-FID) | only when the operator passes it |
| `package_gaps` | method minimum (Class C cites FRC-CSX-VVK) | shortfall rows |
| `method_counts` | automated method count | distinct method ids |
| `unset_fields` | CPO, SDR, OCR, and SCG human fields from the assurance-stack ADR | left unset |

CPO leaves `serviceIdentification`, `contactInformation`, trust-center URL, secure-configuration guidance, assessor, and the next OCR date unset.

SDR leaves `certificationPackageOverviewUri`, `fedRampRequirements`, `keySecurityIndicators`, and `metadata` unset. Beacon writes `package_gaps` in place of a schema status on `keySecurityIndicators`.

OCR leaves `reportableIncidents` unset. An empty array is not written.

SCG leaves `instructions_to_get_and_use` unset (guide citation SCG-CSO-AUP).

See [docs/architecture/beacon-assurance-stack.md](../../docs/architecture/beacon-assurance-stack.md).

## Git policy

A policy file is JSON. The file names people, process, and technology. `beacon policy show` prints the relative path, the canonical content hash, and the raw file hash. `beacon policy hash` prints the content hash only.

```bash
beacon policy show --path policies/access-control.json
beacon policy hash --path policies/access-control.json
```

`--expect-sha256` fails closed when the canonical hash differs. A Word file or a PDF file fails closed. `control_refs` accepts IAC-02, CRY-07, and GOV-02. The custody tag is `evidence:policy`. The role is `candidate`. This command does not append a witness record.

## Mapper ingest

`beacon ingest mapper` reads one JSON file from grc-pdf-mapper. The known shapes are a mapping report (`doc_id`, `snapshot_id`, `ingest`), a KSI catalog (`source`, `classes`, `domains`), and policy-code links (`links`). Any other shape fails closed.

```bash
beacon ingest mapper --file maps/report.json
```

The candidate file is `.beacon/ingest/mapper/{shape}-{hash}.json`. Pass `--out` to choose another directory. The candidate stores digests, statement ids, and mapper labels. It does not store statement prose. `legacy_bytes_are_source_of_truth` is false. `claim` is null. `Record.v` stays 1.

## Trust center

`beacon trust publish` writes the local tree `.beacon/export/trust-center/`. Set `BEACON_TRUST_CENTER_EXPORT=1`. The command fails closed when the flag is unset. The same flag copies pack and report objects to `public/trust-center/` when `BEACON_S3_BUCKET` is set. No public host is required for the local tree.

Allowlisted relative keys:

- `packs/{folder}/{id}/beacon-pack.json`
- `packs/{folder}/{id}/report.md`
- `activity-log/{id}.jsonl`
- `ledger/{id}/summary.json`

`{folder}` is `bundle`, `ongoing-certification-report`, `secure-configuration-guide`, `security-decision-record`, or the local draft folder `cpo`. `cpo` is not a `BEACON_PACK_TYPE`. An observations path, a scope file, or any other relative key fails closed.

```bash
BEACON_TRUST_CENTER_EXPORT=1 beacon trust publish --ledger
BEACON_TRUST_CENTER_EXPORT=1 beacon trust publish --file cpo.json --relative packs/cpo/v1/beacon-pack.json
```

## SCN draft

`beacon scn draft` builds `beacon-scn-draft/v1` from sealed observation pointers and package gaps. `--changes` reads a local JSON file of operator rows. `--dry-run` prints the object and does not write a file. `mailed` is false. `delivery` is `not-sent`. The command does not send mail.

```bash
beacon scn draft --dry-run
beacon scn draft --class c --changes changes.json
```

## Security inbox

`beacon inbox intake` reads one local JSON file. Known shapes are `evidence_candidate` and `ticket_candidate`. Each message becomes a digest and a candidate under `.beacon/ingest/inbox/`. An unknown shape or a credential field fails closed. The command does not open a mailbox.

```bash
beacon inbox intake --file inbox.json
```
