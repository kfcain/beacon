# Guided setup

Open **Connect & verify** from Overview or the sidebar. Name the application, environment, owner and assets. Choose a manual-import, existing-collector or AI-workspace recipe. Start with encryption, audit logging, timely access removal, or a custom typed comparison. Set the maximum evidence age, test a sample, then save.

The test uses the same verification engine as persisted evaluations, in an ephemeral workspace. It evaluates one sample asset; remaining assets are missing. Saving registers a real versioned contract through the existing authorized, revision-checked API. The preview observation is never stored. A failed preview may still be saved: it demonstrates how a failing observation will be reported.

Download the collection recipe after saving. Populate its actual timestamp, source identity, stable observation ID and observed fact; then submit through `beacon_submit_evidence` on an authorized writable MCP connection or the Verification engine's evidence importer. Submit a separate observation for each asset. Imported facts have no source-authentication or publication authority. The wizard does not provision accounts, store credentials, install vendor adapters or schedule recurring collection. The selected route is used to export the recipe, not persisted as a connected integration.

Saved checks show **Waiting for evidence** or **Imports received · review required** based on actual matching observations. The verification engine retains failures, stale observations, missing assets and correlated local findings. Framework applicability starts with an organization-defined expectation; reviewed framework mappings can be added in the advanced contract editor. No framework control is inferred from a starter's name.

The Verification engine also includes a form-based manual observation flow. Select a saved contract, objective and asset; enter actual source, observation time and typed facts. Saving evaluates and reconciles through the same server API. Use advanced imports for original source content and collection error envelopes.

Next usability increments: reconnectable setup recipes; an authenticated first-party collector enrollment flow; field discovery from bounded source samples; reviewed framework suggestions; connection troubleshooting and collector health. These are not represented as completed connections in this release.
