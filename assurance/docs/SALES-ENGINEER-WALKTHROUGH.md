# Beacon — evidence you can stand behind

Beacon connects the work your security tools do to the claims your organization makes. It gives engineering, GRC, assessors and customers a common record: what you intended, what you observed, how you tested it, what remains uncertain, and what you decided.

The product direction is an assurance backend that stands alone or supplies an existing trust center. The current release demonstrates that lifecycle with real application persistence and deterministic sample evaluations. Enterprise scale, the full connector catalog and certification outcomes are not claimed.

## The five-minute demonstration

“Let's open the workspace. These numbers come from stored claims and test runs. The population is small and explicitly simulated. A failing CloudTrail assertion and three claims needing human evidence are visible alongside passing tests.”

“Open the encryption claim. Here is the exact claim: new EBS storage defaults to encryption in the approved account and Regions. Here are the observations, the test result, and the limits. Existing volumes and key governance still require evidence. We haven't turned one API call into a blanket compliance claim.”

“Now run the missing-Region scenario. The expected population stays fixed. The result becomes unknown because the evidence is incomplete. A denied API call, an expired observation and a changed artifact are also first-class outcomes.”

“Switch to frameworks. We reuse the observation across selected supporting mappings and preserve each framework's identity. Below that is the pinned CR26 library: 246 rules and 46 KSIs. Open an SDR rule, inspect the source and dates, record the implementation, verification and validation, and save a new draft version. Independent conclusions remain pending.”

“Update the implementation and generate a document. The draft carries its evidence reference and limitations. If the underlying evidence changes, the old document stays available and is flagged as needing a new input revision.”

“Create a sandbox trust release. The portal receives the publishable fields, the coverage and the caveats. Raw cloud identities stay in the restricted workspace. Download the same structured release for another system.”

“Finally, open the MCP workbench. This is a real call to the same engine. An agent can inspect a claim, reevaluate evidence and prepare a draft without gaining arbitrary shell execution, production publication or remediation authority.”

## How it fits existing workflows

**Engineering:** A read-only collector runs under an approved temporary workload identity. Its output is validated in a delivery job. The production CLI gate requires a live observation plus a signed envelope, trusted signer registry and approved job description. A failure returns a nonzero exit code. The signer and its authorization policy are deployed separately.

**GRC:** Control owners maintain implementation narratives and parameters alongside evidence. The system preserves distinctions between a passing assertion, a reviewed control and a certification decision. Requirement records can be exported for further package generation and review.

**Assessment:** Evidence packages preserve inputs and test identifiers. A recipient can independently rerun validation and verify configured signer/job bindings. The product currently records provider reviews and pending independent conclusions; a production assessor workspace and its access governance still need implementation.

**Customer assurance:** Use the built-in sandbox trust center or a configured HTTPS relay. A real production connection needs authenticated recipients, idempotent delivery, replay protection, receipt reconciliation and a publication policy. The packaged relay demonstrates a timestamped HMAC contract against an explicitly allowlisted destination.

**AI workspaces:** Configure the stdio MCP server with the same database path as the portable API. Read-only access is the default; enable write tools deliberately. The hosted workbench uses the private application's authentication. External OAuth authorization on the hosted endpoint is not configured.

## Homepage copy

**Your trust. Backed by proof.**

Turn security evidence into clear decisions. Collect it, challenge it, connect it to your obligations, and give every claim a source.

**Evidence with context.** Preserve source observations, scope, collection failures and the input behind every result.

**Validation you can examine.** Exercise known failures, reevaluate freshness and keep uncertainty visible.

**Reuse without losing meaning.** Connect observations to multiple requirements while preserving scope and assessment limitations.

**Documentation with a lineage.** Generate versioned implementation drafts from the records your team reviews.

**A trust center with substance.** Deliver controlled records with evidence coverage, caveats and review status.

**An interface for your agents.** Expose structured claim and validation operations through MCP.

## Competitive take

Anecdotes already positions around evidence-backed, agentic GRC, and RegScale already positions around continuous controls monitoring, OSCAL and CI/CD. “We automate evidence” does not distinguish Beacon. Their published capabilities are not evidence that Beacon outperforms them.

The product hypothesis worth testing is that explicit claim scope, deterministic replay, visible uncertainty, independently trusted provenance and a usable engineering workflow can make assurance easier to defend. Win a bounded pilot on those outcomes before claiming a broader competitive advantage.

Pilot measures: time to resolve an evidence challenge; false-pass and false-fail rates; missing-population detection; time between drift and stale-claim publication; reproducibility of independent replay; reviewer effort; and complete deployment/operational cost.

Sources: [Anecdotes](https://www.anecdotes.ai/), [RegScale DevSecOps](https://regscale.com/continuous-compliance-for-devsecops/). Checked September 5, 2026.
