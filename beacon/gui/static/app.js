const pages = ["dashboard", "assessment", "freshness", "validation", "push", "system"];

const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;", "'":"&#39;"}[char]));
let apiToken = "";

function $(id) { return document.getElementById(id); }

function pill(ok) {
  return ok
    ? '<span class="badge ok">OK</span>'
    : '<span class="badge fail">FAIL</span>';
}

async function getJSON(url, opts) {
  opts = opts || {};
  opts.headers = {"X-Beacon-Request":"1", ...(opts.headers || {})};
  if (apiToken) opts.headers.Authorization = `Bearer ${apiToken}`;
  const res = await fetch(url, opts);
  if (res.status === 401) throw new Error("Enter your API token above, then connect.");
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || data.code || `Request failed (${res.status})`);
  return data;
}

function renderDashboard(data) {
  const s = data.status || {};
  const chain = s.chain || {};
  $("dashboard").innerHTML = `
    <div class="grid">
      <div class="card"><div class="k">Records</div><div class="v">${escapeHTML(s.records ?? 0)}</div></div>
      <div class="card"><div class="k">Checkpoints</div><div class="v">${escapeHTML(s.checkpoints ?? 0)}</div></div>
      <div class="card"><div class="k">Covered through</div><div class="v">${escapeHTML(chain.covered_through ?? 0)}</div></div>
      <div class="card"><div class="k">SCF</div><div class="v">${escapeHTML(s.scf_version || "—")}</div></div>
    </div>
    <div class="card" >
      <h3>Plugins</h3>
      <table><thead><tr><th>Name</th><th>SCF</th><th>Tools</th></tr></thead>
      <tbody>${(s.plugins || []).map(p => `<tr><td>${escapeHTML(p.name)}</td><td>${escapeHTML((p.scf_targets||[]).join(", "))}</td><td>${escapeHTML((p.tools||[]).join(", "))}</td></tr>`).join("")}</tbody></table>
    </div>`;
}

function renderFreshness(items) {
  $("freshness").innerHTML = `
    <div class="card">
      <h3>Latest sealed evidence</h3>
      <table><thead><tr><th>Plugin</th><th>Mode</th><th>Time</th><th>Seq</th></tr></thead>
      <tbody>${(items || []).map(i => `<tr><td>${escapeHTML(i.plugin)}</td><td>${escapeHTML(i.mode)}</td><td>${escapeHTML(i.ts)}</td><td>${escapeHTML(i.seq)}</td></tr>`).join("") || '<tr><td colspan="4">No evidence yet. Run beacon seed.</td></tr>'}</tbody>
    </table>
    </div>`;
}

function renderValidation(v) {
  $("validation").innerHTML = `
    <div class="card">
      <h3>Chain validation</h3>
      <p>${pill(!!v.ok)} <span class="mono">${escapeHTML(v.code || "")}</span></p>
      <pre>${escapeHTML(JSON.stringify(v, null, 2))}</pre>
    </div>`;
}

function renderPush() {
  $("push").innerHTML = `
    <div class="card">
      <h3>Push sealed pack</h3>
      <p>Export records, checkpoints, and public keys. Private keys stay in .beacon/keys.</p>
      <button class="act" id="pushBtn">Export pack</button>
      <pre id="pushOut"></pre>
    </div>`;
  $("pushBtn").onclick = async () => {
    const out = await getJSON("/api/push", { method: "POST" });
    $("pushOut").textContent = JSON.stringify(out, null, 2);
  };
}

function renderSystem(s) {
  $("system").innerHTML = `
    <div class="card">
      <h3>System</h3>
      <p class="k">Data dir</p><p class="mono">${escapeHTML(s.home || "")}</p>
      <p class="k">Recorder</p><p class="mono">${escapeHTML(s.recorder_fingerprint || "")}</p>
      <p class="k">Witness</p><p class="mono">${escapeHTML(s.witness_fingerprint || "")}</p>
      <p class="k">Keys distinct</p><p>${s.keys_distinct ? pill(true) : pill(false)}</p>
      <p class="k">SCF API</p><p class="mono">${escapeHTML(s.scf_api_base || "")} ${escapeHTML(s.scf_offline ? "(offline)" : "")}</p>
    </div>`;
}

async function load() {
  const dash = await getJSON("/api/dashboard");
  const fresh = await getJSON("/api/freshness");
  const valid = await getJSON("/api/validation");
  const sys = await getJSON("/api/system");
  const failClosed = sys.chain && sys.chain.fail_closed;
  $("badge").className = "badge " + (valid.ok && !failClosed ? "ok" : "fail");
  $("badge").textContent = valid.ok ? "CHAIN OK" : (valid.code || "CHECK");
  renderDashboard(dash);
  renderFreshness(fresh.items);
  renderValidation(valid);
  renderPush();
  renderSystem(sys);
  await loadScopes();
}

document.querySelectorAll(".tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const page = btn.dataset.page;
    pages.forEach((id) => $(id).classList.toggle("active", id === page));
  });
});

load().catch((err) => {
  $("badge").className = "badge fail";
  $("badge").textContent = "ERROR";
  $("dashboard").innerHTML = `<div class="card"><pre>${escapeHTML(err)}</pre></div>`;
  $("dashboard").classList.add("active");
});

async function loadScopes() {
  const data = await getJSON("/api/scopes");
  const selected = $("scopeSelect").value;
  $("scopeSelect").replaceChildren();
  for (const scope of data.scopes || []) {
    const option = document.createElement("option");
    option.value = scope.scope_id; option.textContent = scope.scope_id;
    $("scopeSelect").append(option);
  }
  if ([...$("scopeSelect").options].some(option => option.value === selected)) $("scopeSelect").value = selected;
  await loadAssessmentWorkspace();
}
function assessmentBody() { return {scope_id:$("scopeSelect").value, control_ref:$("controlSelect").value}; }
function showAssessment(data) { $("assessmentOut").textContent = JSON.stringify(data, null, 2); }
async function assessmentAction(action) {
  try {
    const body = assessmentBody();
    if (!body.scope_id) throw new Error("Import an approved scope with beacon scope import first.");
    if (action === "collect") showAssessment(await getJSON("/api/collect", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scope_id:body.scope_id,plugin:"aws.ebs.encryption",live:$("liveCheck").checked})}));
    if (action === "evaluate") showAssessment(await getJSON("/api/evaluate", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...body,judge:$("judgeSelect").value})}));
    if (action === "objectives") showAssessment(await getJSON("/api/objectives?control="+encodeURIComponent(body.control_ref)));
    if (action === "ledger") showAssessment(await getJSON("/api/ledger?scope_id="+encodeURIComponent(body.scope_id)));
    if (action === "receipts") showAssessment(await getJSON("/api/receipts?scope_id="+encodeURIComponent(body.scope_id)));
  } catch (error) { showAssessment({error:String(error)}); }
}
for (const button of document.querySelectorAll("[data-assessment]")) button.onclick = () => assessmentAction(button.dataset.assessment);
$("connectBtn").onclick = () => {
  apiToken=$("apiToken").value; $("apiToken").value="";
  load().catch(error => {
    $("badge").className = "badge fail";
    $("badge").textContent = "ERROR";
    assessmentMessage(String(error), true);
  });
};

let assessmentRows = [];
let assessmentSpecs = [];
let assessmentView = "all";
let assessmentGeneration = 0;

const readableLabel = value => String(value ?? "").replaceAll("_", " ");
function readableValue(value) {
  if (value === null || value === undefined) return '<span class="muted-text">Not supplied</span>';
  if (Array.isArray(value)) return value.length ? `<ul>${value.map(item => `<li>${readableValue(item)}</li>`).join("")}</ul>` : '<span class="muted-text">None recorded</span>';
  if (typeof value === "object") return `<dl class="facts">${Object.entries(value).map(([key, item]) => `<dt>${escapeHTML(readableLabel(key))}</dt><dd>${readableValue(item)}</dd>`).join("")}</dl>`;
  return escapeHTML(value);
}

function assessmentMessage(message, error = false) {
  $("assessmentMessage").textContent = message;
  $("assessmentMessage").className = error ? "error-text" : "muted-text";
}

function assessmentStatus(row) {
  if (row.current === false) return '<span class="badge warn">Reevaluation required</span>';
  const status = row.receipt?.status || "not assessed";
  const color = status === "supporting_pass" ? "supporting" : (status.includes("fail") ? "fail" : "warn");
  return `<span class="badge ${color}">${escapeHTML(status === "supporting_pass" ? "Checks passed (supporting)" : readableLabel(status))}</span>`;
}

function showSpecification() {
  const selected = assessmentSpecs.find(item => item.spec_sha256 === $("specSelect").value);
  $("assessBtn").disabled = !selected;
  if (!selected) {
    $("specSummary").textContent = "No approved specification for this scope. Import a specification and approve its hash in the local scope configuration before assessing.";
    return;
  }
  const spec = selected.spec || {};
  $("specSummary").textContent = `${spec.title || spec.spec_id || "Assessment specification"} · ${spec.control_ref || ""} / ${spec.ao_id || ""} · ${readableLabel(spec.time_basis)} · SHA-256 ${selected.spec_sha256}`;
}

function renderAssessmentList() {
  const title = assessmentView === "queue" ? "Review queue" : "Latest assessments";
  $("assessmentList").innerHTML = `<h3>${title}</h3>${assessmentRows.length ? `
    <div class="table-scroll"><table><thead><tr><th>Specification</th><th>Scope</th><th>Result</th><th>Evaluated</th><th>Review</th><th></th></tr></thead><tbody>
    ${assessmentRows.map((row, index) => `<tr><td>${escapeHTML(row.receipt?.spec_id || "Unknown specification")}</td><td>${escapeHTML(row.receipt?.scope_id)}</td><td>${assessmentStatus(row)}</td><td>${escapeHTML(row.receipt?.evaluated_at)}</td><td>${escapeHTML(row.review?.decision || "Not recorded")}</td><td><button data-receipt-index="${index}">Inspect</button></td></tr>`).join("")}
    </tbody></table></div>` : `<p>${assessmentView === "queue" ? "No queued receipts. This does not indicate that every requirement has been assessed." : "No assessment receipts. Select an approved specification to run an assessment."}</p>`}`;
  for (const button of $("assessmentList").querySelectorAll("[data-receipt-index]")) {
    button.onclick = () => renderAssessmentDetail(assessmentRows[Number(button.dataset.receiptIndex)]);
  }
}

function renderAssessmentDetail(row) {
  const receipt = row.receipt || {};
  const results = receipt.results || [];
  $("assessmentDetail").innerHTML = `
    <h3>${escapeHTML(receipt.spec_id || "Assessment receipt")}</h3>
    <p>${assessmentStatus(row)} <span class="muted-text">Scope: ${escapeHTML(receipt.scope_id)} · ${escapeHTML(receipt.evaluated_at)}</span></p>
    <p>${escapeHTML(receipt.title || "")} · Control ${escapeHTML(receipt.control_ref || "unspecified")} / objective ${escapeHTML(receipt.ao_id || "unspecified")} · ${escapeHTML(readableLabel(receipt.time_basis || "unspecified time basis"))}</p>
    ${row.current === false ? `<div class="notice"><strong>Historical result — reevaluation required</strong>${readableValue(row.invalidation_reasons || [])}</div>` : ""}
    <p>Objective and control satisfaction remain unset. A supporting result applies only to this specification and captured evidence.</p>
    <h4>Criteria</h4>
    ${results.length ? `<div class="table-scroll"><table><thead><tr><th>Criterion</th><th>Result</th><th>Explanation and evidence</th></tr></thead><tbody>${results.map(result => {
      const detail = Object.fromEntries(Object.entries(result).filter(([key]) => !["criterion_id", "assertion", "status"].includes(key)));
      return `<tr><td><strong>${escapeHTML(result.criterion_id || "Criterion")}</strong><p>${escapeHTML(result.assertion || "")}</p></td><td>${escapeHTML(readableLabel(result.status || "not assessed"))}</td><td>${readableValue(detail)}</td></tr>`;
    }).join("")}</tbody></table></div>` : "<p>No criterion results recorded.</p>"}
    <h4>Gaps and next steps</h4>${readableValue(receipt.gaps || [])}
    <h4>Findings</h4>${readableValue(receipt.findings || [])}
    <h4>Operator review (local OS account)</h4>${row.review ? readableValue(row.review) : "<p>No review recorded. An approved reviewer account can record one in the local TUI or an interactive CLI session.</p>"}
    <details><summary>Receipt provenance</summary><dl class="facts">
    <dt>Evidence ID</dt><dd class="mono">${escapeHTML(row.evidence_id || receipt.receipt_evidence_id)}</dd>
    <dt>Specification SHA-256</dt><dd class="mono">${escapeHTML(receipt.spec_sha256)}</dd>
    <dt>Objective SHA-256</dt><dd class="mono">${escapeHTML(receipt.objective_sha256)}</dd>
    <dt>Catalog SHA-256</dt><dd class="mono">${escapeHTML(receipt.catalog_sha256)}</dd>
    <dt>Input SHA-256</dt><dd class="mono">${escapeHTML(receipt.input_sha256)}</dd>
    <dt>Expires</dt><dd>${escapeHTML(receipt.expires_at || "See criterion freshness limits")}</dd>
    </dl></details>`;
}

async function loadAssessmentWorkspace(preferredId) {
  const generation = ++assessmentGeneration;
  const scope = $("scopeSelect").value;
  const previousSpec = $("specSelect").value;
  $("assessBtn").disabled = true;
  $("refreshAssessmentsBtn").disabled = !scope;
  $("specSelect").replaceChildren();
  $("assessmentDetail").innerHTML = "<p>Select a receipt to inspect criteria, evidence references, and gaps.</p>";
  assessmentMessage("");
  if (!scope) {
    assessmentRows = []; assessmentSpecs = [];
    renderAssessmentList(); showSpecification();
    assessmentMessage("Import an approved scope with beacon scope import before assessing.");
    return true;
  }
  try {
    const query = "?scope_id=" + encodeURIComponent(scope);
    const [specs, results] = await Promise.all([
      getJSON("/api/assessment-specs" + query),
      getJSON((assessmentView === "queue" ? "/api/review-queue" : "/api/assessments") + query)
    ]);
    if (generation !== assessmentGeneration) return;
    assessmentSpecs = (specs.specs || []).filter(item => item.approved === true);
    for (const item of assessmentSpecs) {
      const option = document.createElement("option");
      option.value = item.spec_sha256;
      option.textContent = `${item.spec?.spec_id || "Specification"} · ${item.spec_sha256.slice(0, 12)}`;
      $("specSelect").append(option);
    }
    if (assessmentSpecs.some(item => item.spec_sha256 === previousSpec)) $("specSelect").value = previousSpec;
    assessmentRows = results.assessments || [];
    showSpecification(); renderAssessmentList();
    const selected = assessmentRows.find(row => row.evidence_id === preferredId);
    if (selected) renderAssessmentDetail(selected);
    return true;
  } catch (error) {
    if (generation !== assessmentGeneration) return;
    assessmentRows = []; assessmentSpecs = [];
    $("assessmentList").innerHTML = "<p>Assessment results unavailable. Resolve the error and refresh.</p>";
    $("specSummary").textContent = "Specification approval state unavailable.";
    $("refreshAssessmentsBtn").disabled = true;
    assessmentMessage(String(error), true);
    return false;
  }
}

async function runAssessmentAction(refresh) {
  const scope_id = $("scopeSelect").value;
  const spec_sha256 = $("specSelect").value;
  if (!scope_id || (!refresh && !spec_sha256)) return;
  const controls = ["scopeSelect", "specSelect", "assessBtn", "refreshAssessmentsBtn", "allAssessmentsBtn", "reviewQueueBtn"];
  controls.forEach(id => $(id).disabled = true);
  assessmentMessage(refresh ? "Checking for changed or expired assessment inputs…" : "Evaluating approved criteria and sealing a receipt…");
  try {
    const result = await getJSON(refresh ? "/api/assessments/refresh" : "/api/assess", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(refresh ? {scope_id} : {scope_id, spec_sha256})
    });
    assessmentView = "all";
    const loaded = await loadAssessmentWorkspace(result.receipt_evidence_id);
    if (loaded) assessmentMessage(refresh ? `Reevaluation completed: ${(result.evaluations || []).length} new receipts; ${result.unchanged || 0} unchanged. No live collection was requested.` : "Assessment receipt sealed. Inspect criteria and gaps below.");
  } catch (error) {
    assessmentMessage(String(error), true);
  } finally {
    controls.forEach(id => $(id).disabled = false);
    $("assessBtn").disabled = !assessmentSpecs.length;
    $("refreshAssessmentsBtn").disabled = !$("scopeSelect").value;
  }
}

$("scopeSelect").onchange = () => loadAssessmentWorkspace();
$("specSelect").onchange = showSpecification;
$("assessBtn").onclick = () => runAssessmentAction(false);
$("refreshAssessmentsBtn").onclick = () => runAssessmentAction(true);
$("allAssessmentsBtn").onclick = () => { assessmentView = "all"; loadAssessmentWorkspace(); };
$("reviewQueueBtn").onclick = () => { assessmentView = "queue"; loadAssessmentWorkspace(); };
