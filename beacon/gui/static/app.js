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
  return res.json();
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
  $("scopeSelect").replaceChildren();
  for (const scope of data.scopes || []) {
    const option = document.createElement("option");
    option.value = scope.scope_id; option.textContent = scope.scope_id;
    $("scopeSelect").append(option);
  }
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
$("connectBtn").onclick = () => { apiToken=$("apiToken").value; $("apiToken").value=""; load().catch(showAssessment); };
