# Evidence admission and replay protection

Beacon now separates repeatable verification from one-time admission. Both use the same deterministic validator and independently supplied signer registry. Admission records exactly one acceptance per approved job ID, including across concurrent CLI processes and process restarts. Each job covers one claim and one approved scope. Mint a new job ID for a new authorized collection; never reuse a job ID for several claims.

## Trusted inputs and deployment boundary

The admission service administrator controls the code, signer registry, claim choice, approved scope, job policy and ledger path. The collector submits only evidence and its signature envelope through an authenticated ingestion channel. Do not accept registry, job policy or ledger path from an evidence upload. File arguments in this reference are a deployment interface, not an authorization protocol. A signed `mode: live` field cannot prove where evidence originated; the signing service must independently authenticate the collection execution before signing.

The approved job JSON requires `jobId` and a lowercase 64-character `imageSha256`. `maxAgeSeconds` is optional (default 86400), and if supplied must be an integer from 1 through 86400. This limit concerns the signed manifest; the validator separately checks observation freshness, scope population, source operation and raw hashes. Signature checks require an independently registered, non-revoked RSA public key of at least 2048 bits, RSA-PSS/SHA-256 with a 32-byte salt, canonical base64 and a valid UTC timestamp. These algorithm checks do not assert a FIPS-validated runtime.

The ledger belongs on a protected persistent local volume on the admission host. Collectors and build jobs must have no filesystem access to that host. SQLite WAL is used for concurrency; do not place this database on a shared network filesystem. Multiple hosts need a centralized admission service or transactional database with the same unique-job constraint. A local ledger does not provide that service automatically.

## Initialize once, then admit

Provision `/var/lib/beacon-admission` as a private directory owned by the service identity. Initialize once during controlled installation, never on each process start or CI run:

```sh
node portable/cli.mjs ledger-init --ledger /var/lib/beacon-admission/admission.sqlite
```

Initialization refuses to overwrite an existing file. Admission refuses a missing, uninitialized, symlinked or group/world-accessible ledger file. Keep the entire directory private, including SQLite sidecar files. The host administrator and filesystem are part of the trusted boundary.

Run admission after the trusted service has obtained the approved job and signer policy:

```sh
node portable/cli.mjs admit \
  --ledger /var/lib/beacon-admission/admission.sqlite \
  --claim ENC-01 \
  --evidence /run/beacon/observation.json \
  --envelope /run/beacon/signature.json \
  --scope /etc/beacon/approved-scope.json \
  --registry /etc/beacon/trusted-signers.json \
  --job /run/beacon-policy/approved-job.json
```

The command prints a JSON receipt and exits zero only after the database insert commits. It exits 2 for invalid provenance, non-PASS evaluation, replay or a storage failure. Failed validation does not consume the job. Two competing submissions for the same job produce one successful insert and one replay rejection. The receipt binds evidence, scope, image, envelope and policy hashes to the validator result, job ID, signer key ID and acceptance time. It remains `publicationEligible: false`; admission is not a certification or publication decision.

If the process commits and then loses its output, retrieve the existing receipt instead of submitting the job again:

```sh
node portable/cli.mjs receipt \
  --ledger /var/lib/beacon-admission/admission.sqlite \
  --job-id APPROVED_JOB_ID
```

This is at-most-once admission. It does not promise exactly-once downstream delivery. A future ingestion service needs a transactional outbox and destination acknowledgment reconciliation before promising reliable automatic relay.

## CI and assessment workflows

Ephemeral CI runners can use `evaluate --require-live` to repeat verification against protected policy inputs. They must submit to the retained admission service for one-time acceptance; creating a new SQLite file in every runner defeats replay protection. The example workflow explicitly labels itself repeatable verification and pins Node 24.

Assessors can independently run verification multiple times. Admission receipts describe what the local service accepted; they are not signed external witnesses. UI/API/MCP observation imports still remain unverified, and this update does not automatically promote them using a receipt. An authenticated ingestion integration is a remaining milestone.

## Rollback, backup and recovery

The unique-job constraint prevents duplicate admission while its history is retained. It cannot detect an administrator restoring an older valid database, deleting rows or replacing the policy. Do not claim rollback resistance from SQLite or a local hash chain. Before production, retain an independently administered monotonic checkpoint/receipt history, verify continuity at startup and after restore, and halt admission on mismatch. Protect and test coordinated SQLite backups including active WAL data. Keep admission disabled during restore until independent history reconciliation completes; never automatically create a replacement ledger when one is missing.

## Validation

Tests exercise malformed policies, revoked/inherited signer entries, weak keys, noncanonical signatures, bad timestamps, repeatable verification, receipt persistence, duplicate admission, non-PASS rejection without consumption, missing/uninitialized/open-permission ledgers, and two real CLI processes racing for the same job. Test observations use controlled fixtures with a test key; they do not represent a live AWS execution.

Implementation references: [Node 24 cryptography](https://nodejs.org/docs/latest-v24.x/api/crypto.html), [Node 24 SQLite](https://nodejs.org/docs/latest-v24.x/api/sqlite.html), and [SQLite WAL deployment constraints](https://sqlite.org/wal.html).
