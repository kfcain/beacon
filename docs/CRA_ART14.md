# CRA Article 14 early-warning packer

Beacon can pack **early-warning evidence** for EU Cyber Resilience Act (Regulation (EU) 2024/2847) Article 14. Article 14 is the manufacturer duty to report **actively exploited vulnerabilities** (and related severe incidents) to the coordinating CSIRT and ENISA, and to inform users. Early-warning timing in the Act is measured in hours after the manufacturer becomes aware of active exploitation **in the product with digital elements**.

This plugin records signals and product identity. It does **not** decide that a notification is required. It is not legal advice. It does not send mail or file an ENISA / CSIRT report.

## Signal vs exploitation

| Input | What Beacon records | What Beacon does not record |
| --- | --- | --- |
| CISA KEV row that matches configured product / component / watch CVE | `matched_signals[]`, `signal_present=true`, raw KEV row under `observations.kev` | Product exploitation, "became aware", or "must notify" |
| High / critical severity, ransomware campaign flag | Copied onto the signal as attributes | A finding that exploitation is confirmed |
| Human or separate policy flag (`confirmed_exploitation` or `exploitation_status`) | `exploitation_status` (`undetermined` / `confirmed` / `not_applicable`) | Automatic flip of `notification_status` |
| Absent or failed live KEV fetch | Empty matches; `live_failed` when `--live` fails | A fixture catalog rewritten as a live success |

KEV means a vulnerability is in CISA's Known Exploited Vulnerabilities catalog. That catalog is **one optional signal**. It does not prove:

- the CVE is in *this* product;
- *this* product is being exploited;
- the manufacturer has become aware of active exploitation in that product;
- Article 14 early-warning or vulnerability notification is due.

`exploitation_status` defaults to `undetermined`. `notification_status` defaults to `not_evaluated`. Findings set `kev_is_not_exploitation` and `does_not_assert_notification_duty` to `true`. A KEV hit never sets `confirmed` and never records a notification duty. Live KEV URLs must be HTTPS on port 443 without credentials, loopback, or link-local/private IP literals. Redirects are followed only when the next URL meets the same rules.

## Observations vs sealed findings

The collect payload keeps two layers, same split as the evidence lake (`observations/` vs `evidence/`):

- **observations.kev** — catalog metadata plus the matched raw KEV/CVE rows (or an error if live fetch failed). Live mode does not store the full public catalog; it stores envelope fields (`catalog_version`, `date_released`, `catalog_count`) and matched rows only.
- **findings** — sealed early-warning pack summary (`signals_recorded`). The witness chain hashes the whole payload. Remote dual-write still stores the payload bytes as an observation object and the signed record as a finding.

A live failure returns `mode=live_failed` and `ok=false`. Beacon does not substitute the offline fixture for that run.

## How to collect

The packer is a drop-in plugin (same loader as `echo`).

```bash
export BEACON_PLUGIN_PATH=./examples/cra_art14_early_warning.py
beacon plugins
beacon collect --plugin cra.art14.early_warning --fixture
beacon check
```

Offline / fixture is the default. Pytest and `BEACON_FORCE_FIXTURE=1` also force the synthetic catalog.

Optional live KEV fetch (HTTPS only). On failure the result is `live_failed`, never a silent fixture:

```bash
export BEACON_PLUGIN_PATH=./examples/cra_art14_early_warning.py
# optional: BEACON_CRA_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
beacon collect --plugin cra.art14.early_warning --live
```

Override the fixture path with `BEACON_CRA_FIXTURE_PATH` or `CollectContext.extra["fixture_path"]`. Product identity comes from the fixture `product_scope` or `extra["product_scope"]` (manufacturer, product, version, components, `watch_cves`).

Explicit policy inputs (never inferred from KEV or severity):

- `extra["exploitation_status"]`: `undetermined` | `confirmed` | `not_applicable`
- `extra["notification_status"]`: `not_evaluated` | `notified` | `not_required` | `deferred`
- `extra["confirmed_exploitation"]=True` sets exploitation to `confirmed` only

SCF binding uses documented drop-in id `GOV-02` so the loader can select the plugin. Workbook Legacy SCF # maps prior GOV-01 (SCRP) to GOV-02. 2026.3 GOV-01 is a new policy control. That id is **not** a CRA mapping and is not an invented overlay control. Do not treat it as full SCF 2026.3 coverage. HackIDLE remains 2026.1.x.

## Offline fixture

[examples/fixtures/cra.art14.early_warning.json](../examples/fixtures/cra.art14.early_warning.json) is a three-row **synthetic** KEV-shaped slice (`CVE-2099-*`). It is not a CISA dump. Two rows match the fixture product; one does not. Matched rows stay `exploitation_status=undetermined`.

## Witness chain

`beacon collect` still seals through recorder/witness keys and writes a Merkle/TSA checkpoint. `beacon check` fails closed (`E_NO_CHECKPOINT`) when coverage is missing. This plugin does not change those crypto invariants.
