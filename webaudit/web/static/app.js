"use strict";

// The session token arrives in the URL webaudit opened. Keep it in memory and strip
// it from the address bar so it isn't left in history or copied by accident.
const PARAMS = new URLSearchParams(location.search);
const TOKEN = PARAMS.get("token") || "";
const VIEW_RUN = PARAMS.get("view") || ""; // optional: open a past run directly
history.replaceState(null, "", location.pathname);

const SEVERITIES = ["critical", "high", "medium", "low"];
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
};

async function api(path, options = {}) {
  const headers = { "X-Auth-Token": TOKEN, ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

let currentSource = null; // the open EventSource, so we can close it

// ---------- tabs ----------
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const view = tab.dataset.view;
    $("view-scan").hidden = view !== "scan";
    $("view-history").hidden = view !== "history";
    if (view === "history") loadHistory();
  });
});

// ---------- startup: load checks ----------
async function init() {
  try {
    const meta = await api("/api/meta");
    $("version").textContent = "v" + meta.version;
    const box = $("checks");
    for (const check of meta.checks) {
      const label = el("label");
      label.title = check.description;
      const input = el("input");
      input.type = "checkbox";
      input.value = check.name;
      input.checked = check.default;
      input.dataset.name = check.name;
      input.addEventListener("change", updateExposureNote);
      const name = el("span", "cname", check.name);
      label.append(input, name);
      box.append(label);
    }
    updateExposureNote();
    if (VIEW_RUN) viewPastRun(VIEW_RUN);
  } catch (err) {
    showFormError("Could not reach the dashboard server: " + err.message);
  }
}

function selectedChecks() {
  return [...document.querySelectorAll("#checks input:checked")].map((i) => i.value);
}
function updateExposureNote() {
  $("exposure-note").hidden = !selectedChecks().includes("exposure");
}

function readOptions() {
  const n = (id) => Number($(id).value);
  return {
    concurrency: n("concurrency"), timeout: n("timeout"), site_timeout: n("site_timeout"),
    per_site_requests: n("per_site_requests"), delay: n("delay"),
    max_pages: n("max_pages"), max_links: n("max_links"),
  };
}

function showFormError(msg) {
  const box = $("form-error");
  box.textContent = msg;
  box.hidden = !msg;
}

// ---------- run a scan ----------
$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showFormError("");
  const targets = $("targets").value;
  const checks = selectedChecks();
  if (!targets.trim()) return showFormError("Enter at least one target.");
  if (!checks.length) return showFormError("Select at least one check.");

  setRunning(true);
  resetResults();
  try {
    const res = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify({ targets, checks, options: readOptions() }),
    });
    if (res.rejected && res.rejected.length) showRejected(res.rejected);
    follow(res.id);
  } catch (err) {
    setRunning(false);
    showFormError(err.message);
  }
});

$("cancel-btn").addEventListener("click", async () => {
  if (activeId) {
    $("cancel-btn").disabled = true;
    await api(`/api/scans/${activeId}/cancel`, { method: "POST" }).catch(() => {});
  }
});

let activeId = null;
const rowsById = new Map();

function setRunning(on) {
  $("run-btn").disabled = on;
  $("cancel-btn").hidden = !on;
  $("cancel-btn").disabled = false;
  $("progress-wrap").hidden = !on;
}
function resetResults() {
  activeId = null;
  rowsById.clear();
  $("results").innerHTML = "";
  $("empty").hidden = true;
  $("summary-bar").hidden = true;
  $("rejected").hidden = true;
  $("open-report").hidden = true;
  $("results-title").textContent = "Results";
  setProgress(0, 0);
}
function setProgress(done, total) {
  const pct = total ? Math.round((done / total) * 100) : 0;
  $("progress-bar").style.width = pct + "%";
  $("progress-text").textContent = total ? `${done} / ${total} sites` : "Starting…";
}
function showRejected(list) {
  const box = $("rejected");
  box.innerHTML = "";
  box.append(el("b", null, `${list.length} line(s) skipped:`));
  const ul = el("ul", "fev");
  list.forEach((line) => ul.append(el("li", null, line)));
  box.append(ul);
  box.hidden = false;
}

// Stream progress over Server-Sent Events, with a polling fallback.
function follow(id) {
  activeId = id;
  if (currentSource) currentSource.close();
  const source = new EventSource(`/api/scans/${id}/events?token=${encodeURIComponent(TOKEN)}`);
  currentSource = source;

  source.onmessage = (msg) => {
    const ev = JSON.parse(msg.data);
    if (ev.type === "init") {
      setProgress(ev.completed, ev.total);
      (ev.rows || []).forEach(upsertRow);
      if (ev.status !== "running") { source.close(); finish(id); }
    } else if (ev.type === "start") {
      $("progress-text").textContent = `Scanning ${ev.url} …`;
    } else if (ev.type === "site") {
      upsertRow(ev.row);
      setProgress(ev.completed, ev.total);
    } else if (ev.type === "done") {
      source.close();
      finish(id);
    } else if (ev.type === "error") {
      source.close();
      setRunning(false);
      showFormError(ev.error || "Scan failed.");
    }
  };
  source.onerror = () => { source.close(); pollUntilDone(id); };
}

async function pollUntilDone(id) {
  try {
    const state = await api(`/api/scans/${id}`);
    (state.rows || []).forEach(upsertRow);
    setProgress(state.completed || 0, state.total || 0);
    if (state.status === "running") return setTimeout(() => pollUntilDone(id), 1000);
    finish(id);
  } catch (err) {
    setRunning(false);
    showFormError(err.message);
  }
}

function gradeClass(g) { return "g-" + (g || "-"); }

function upsertRow(row) {
  rowsById.set(row.url, row);
  renderRows([...rowsById.values()]);
}

// A row may be the live compact shape or the finished summary shape (with findings).
function renderRows(rows) {
  $("empty").hidden = true;
  const container = $("results");
  container.innerHTML = "";
  rows.sort((a, b) => (scoreVal(a) - scoreVal(b)) || a.url.localeCompare(b.url));
  for (const row of rows) container.append(renderSite(row));
}
function scoreVal(row) { return row.score == null ? 999 : row.score; }

function renderSite(row) {
  const counts = row.severity_counts || {};
  const details = el("details", "site");
  const summary = el("summary");

  const badge = el("div", "badge " + gradeClass(row.grade), row.grade || "-");
  const mid = el("div", "url");
  mid.append(document.createTextNode(row.url));
  const st = el("div", "st", row.status + (row.error ? " — " + row.error : ""));
  mid.append(st);

  const countWrap = el("div", "counts");
  for (const sev of SEVERITIES) {
    const n = counts[sev] || 0;
    countWrap.append(el("span", `cbox ${n ? "on-" + sev : "off"}`, `${sev[0].toUpperCase()}:${n}`));
  }
  const score = el("div", "score", row.score == null ? "–" : String(row.score));
  summary.append(badge, mid, countWrap, score);
  details.append(summary);

  const findings = row.findings;
  if (findings) {
    const box = el("div", "findings");
    if (!findings.length) box.append(el("div", "clean", "No findings — clean."));
    for (const f of findings) box.append(renderFinding(f));
    details.append(box);
  }
  return details;
}

function renderFinding(f) {
  const node = el("div", "finding");
  const top = el("div", "ftop");
  top.append(el("span", "sev sev-" + f.severity, f.severity));
  top.append(el("span", "ftitle", f.title));
  top.append(el("span", "fcheck", "(" + f.check + ")"));
  node.append(top);
  if (f.detail) node.append(el("p", "fdetail", f.detail));
  if (f.recommendation) node.append(el("p", "frec", "→ " + f.recommendation));
  if (f.evidence && f.evidence.length) {
    const ul = el("ul", "fev");
    f.evidence.forEach((e) => ul.append(el("li", null, e)));
    node.append(ul);
  }
  return node;
}

async function finish(id) {
  setRunning(false);
  try {
    const state = await api(`/api/scans/${id}`);
    const summary = state.summary;
    if (summary) {
      rowsById.clear();
      summary.sites.forEach((s) => rowsById.set(s.url, s));
      renderRows(summary.sites);
      renderSummaryBar(summary);
      $("results-title").textContent =
        state.status === "interrupted" ? "Results (stopped early)" : "Results";
      const link = $("open-report");
      link.href = `/api/scans/${id}/report?token=${encodeURIComponent(TOKEN)}`;
      link.hidden = false;
    }
  } catch (err) {
    showFormError(err.message);
  }
}

function renderSummaryBar(summary) {
  const bar = $("summary-bar");
  bar.innerHTML = "";
  const avg = summary.average_score;
  bar.append(chip(`Average ${avg == null ? "–" : avg}`, ""));
  const totals = summary.severity_totals || {};
  for (const sev of SEVERITIES) {
    bar.append(chip(`${sev}: ${totals[sev] || 0}`, "sev-" + sev));
  }
  bar.hidden = false;
}
function chip(text, cls) {
  const c = el("span", "chip " + cls);
  c.innerHTML = `<b>${text}</b>`;
  return c;
}

// ---------- history ----------
async function loadHistory() {
  const list = $("history-list");
  list.innerHTML = '<p class="muted">Loading…</p>';
  try {
    const { runs } = await api("/api/scans");
    if (!runs.length) { list.innerHTML = '<p class="muted">No scans yet.</p>'; return; }
    list.innerHTML = "";
    for (const run of runs) {
      const item = el("div", "hrun");
      const score = el("div", "hscore " + scoreColor(run.average_score), run.average_score == null ? "–" : run.average_score);
      const meta = el("div", "hmeta");
      meta.append(el("div", "hid", run.id));
      const totals = run.severity_totals || {};
      const detail = `${run.sites} site(s) · ${totals.critical || 0} critical, ${totals.high || 0} high` +
        (run.interrupted ? " · stopped early" : "");
      meta.append(el("div", "muted", detail));
      const open = el("button", "ghost", "View");
      item.append(score, meta, open);
      item.addEventListener("click", () => viewPastRun(run.id));
      list.append(item);
    }
  } catch (err) {
    list.innerHTML = `<p class="note error">${err.message}</p>`;
  }
}
function scoreColor() { return ""; }

async function viewPastRun(id) {
  document.querySelector('.tab[data-view="scan"]').click();
  resetResults();
  $("progress-wrap").hidden = true;
  await finish(id);
}

init();
