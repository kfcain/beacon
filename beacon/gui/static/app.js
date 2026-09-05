const pages = ["dashboard", "freshness", "validation", "push", "system"];

function $(id) { return document.getElementById(id); }

function pill(ok) {
  return ok
    ? '<span class="badge ok">OK</span>'
    : '<span class="badge fail">FAIL</span>';
}

async function getJSON(url, opts) {
  const res = await fetch(url, opts);
  return res.json();
}

function renderDashboard(data) {
  const s = data.status || {};
  const chain = s.chain || {};
  $("dashboard").innerHTML = `
    <div class="grid">
      <div class="card"><div class="k">Records</div><div class="v">${s.records ?? 0}</div></div>
      <div class="card"><div class="k">Checkpoints</div><div class="v">${s.checkpoints ?? 0}</div></div>
      <div class="card"><div class="k">Covered through</div><div class="v">${chain.covered_through ?? 0}</div></div>
      <div class="card"><div class="k">SCF</div><div class="v">${s.scf_version || "—"}</div></div>
    </div>
    <div class="card" style="margin-top:1rem">
      <h3>Plugins</h3>
      <table><thead><tr><th>Name</th><th>SCF</th><th>Tools</th></tr></thead>
      <tbody>${(s.plugins || []).map(p => `<tr><td>${p.name}</td><td>${(p.scf_targets||[]).join(", ")}</td><td>${(p.tools||[]).join(", ")}</td></tr>`).join("")}</tbody></table>
    </div>`;
}

function renderFreshness(items) {
  $("freshness").innerHTML = `
    <div class="card">
      <h3>Latest sealed evidence</h3>
      <table><thead><tr><th>Plugin</th><th>Mode</th><th>Time</th><th>Seq</th></tr></thead>
      <tbody>${(items || []).map(i => `<tr><td>${i.plugin}</td><td>${i.mode}</td><td>${i.ts}</td><td>${i.seq}</td></tr>`).join("") || '<tr><td colspan="4">No evidence yet. Run beacon seed.</td></tr>'}</tbody>
    </table>
    </div>`;
}

function renderValidation(v) {
  $("validation").innerHTML = `
    <div class="card">
      <h3>Chain validation</h3>
      <p>${pill(!!v.ok)} <span class="mono">${v.code || ""}</span></p>
      <pre>${JSON.stringify(v, null, 2)}</pre>
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
      <p class="k">Data dir</p><p class="mono">${s.home || ""}</p>
      <p class="k">Recorder</p><p class="mono">${s.recorder_fingerprint || ""}</p>
      <p class="k">Witness</p><p class="mono">${s.witness_fingerprint || ""}</p>
      <p class="k">Keys distinct</p><p>${s.keys_distinct ? pill(true) : pill(false)}</p>
      <p class="k">SCF API</p><p class="mono">${s.scf_api_base || ""} ${s.scf_offline ? "(offline)" : ""}</p>
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
  $("dashboard").innerHTML = `<div class="card"><pre>${err}</pre></div>`;
  $("dashboard").classList.add("active");
});
