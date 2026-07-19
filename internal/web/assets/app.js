"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
let me = null;

// mutate guards a destructive/async action against double-submit: a second call
// while one is in flight is ignored, so rage-clicking Forget/Merge/bulk fires once.
let mutating = false;
async function mutate(fn) {
  if (mutating) return;
  mutating = true;
  try { await fn(); } finally { mutating = false; }
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  if (r.status === 401) { showLogin(); throw new Error("unauthorized"); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json().catch(() => null);
}
const getJSON = (p) => api("GET", p);
const post = (p, b) => api("POST", p, b ?? {});

function fmtTime(t) { if (!t || t.startsWith("0001")) return "—"; return new Date(t).toLocaleString(); }
// fmtExpiry describes a suppression's expiry for display: indefinite, or a date
// with a days-remaining hint.
function fmtExpiry(iso) {
  if (!iso) return "no expiry";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "no expiry";
  const days = Math.ceil((d.getTime() - Date.now()) / 86400000);
  return `expires ${d.toLocaleDateString()}${days >= 0 ? ` (${days}d)` : ""}`;
}
// uptimePct formats an availability ratio (0–1, or -1/null = unknown) as a %.
function uptimePct(r) {
  if (r == null || r < 0) return "—";
  return (r * 100).toFixed(r >= 0.999 ? 0 : 1) + "%";
}

let iconCache = null;
async function loadIcons(force) { if (force || !iconCache) iconCache = await getJSON("/api/icons"); return iconCache; }

// ── auth ─────────────────────────────────────────────────────────────────────

async function showAuth() {
  $("login").classList.remove("hidden");
  let st = { first_run: false, token_required: false };
  try { st = await fetch("/api/setup/status").then((r) => r.json()); } catch {}
  $("setup-form").classList.toggle("hidden", !st.first_run);
  $("login-form").classList.toggle("hidden", st.first_run);
  $("su-token-row").classList.toggle("hidden", !st.token_required);
  (st.first_run ? (st.token_required ? $("su-token") : $("su-user")) : $("login-user")).focus();
}
function showLogin() { showAuth(); }
function hideLogin() { $("login").classList.add("hidden"); }

$("login-form").onsubmit = async (e) => {
  e.preventDefault();
  $("login-error").textContent = "";
  try {
    await fetch("/api/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("login-user").value, password: $("login-pass").value }),
    }).then((r) => { if (!r.ok) throw 0; });
    location.reload();
  } catch { $("login-error").textContent = "Invalid username or password"; }
};

$("setup-form").onsubmit = async (e) => {
  e.preventDefault();
  $("setup-error").textContent = "";
  try {
    const r = await fetch("/api/setup", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: $("su-token").value.trim(), username: $("su-user").value.trim(), password: $("su-pass").value }),
    });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "setup failed");
    location.reload();
  } catch (err) { $("setup-error").textContent = err.message; }
};

function renderUserbar() {
  const link = (v, label) => `<a class="nav-link" data-view="${v}">${label}</a>`;
  const settings = me.is_admin ? link("system", "System") + link("settings", "Settings") : "";
  $("userbar").innerHTML =
    `<nav class="nav">${link("dashboard", "Dashboard")}${link("activity", "Activity")}${link("topology", "Topology")}${link("ports", "Ports")}${link("observations", "Observations")}${link("security", "Security")}${settings}</nav>` +
    `<button id="nav-search" class="nav-search" title="Search devices, subnets, services (⌘K or /)">🔍 <kbd>⌘K</kbd></button>` +
    `<b>${esc(me.username)}</b><span class="role">${esc(me.role)}</span><a id="nav-logout">Logout</a>`;
  for (const a of document.querySelectorAll("#userbar .nav-link")) a.onclick = () => showView(a.dataset.view);
  $("nav-search").onclick = () => openPalette();
  $("nav-logout").onclick = async () => { await post("/api/logout"); location.reload(); };
}

// ── inventory (unchanged behavior, admin-gated annotation) ───────────────────

async function refresh() {
  let summary, hosts;
  try {
    [summary, hosts] = await Promise.all([getJSON("/api/summary"), getJSON("/api/hosts")]);
  } catch (e) {
    toast("Couldn't load inventory: " + e.message);
    return; // keep whatever's on screen rather than blanking it
  }
  renderSummary(summary); renderHosts(hosts); renderDevices(hosts, summary.open_conflicts);
  renderTrends();
  paletteSubnets = null; // re-fetch subnets/services on next palette open
}

// ── trend charts (hand-rolled SVG, no deps) ──────────────────────────────────
// sparkLine draws a filled line chart from [{t,v}] points into a viewBox.
function sparkLine(points, opts) {
  const o = Object.assign({ w: 300, h: 90, pad: 6, color: "var(--accent)", fmt: (v) => v }, opts || {});
  if (!points || points.length === 0) return `<div class="chart-empty">no data yet</div>`;
  const xs = points.map((p) => new Date(p.t).getTime());
  const ys = points.map((p) => p.v);
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y1 = Math.max(...ys, 1);
  const W = o.w, H = o.h, P = o.pad;
  const sx = (x) => x1 === x0 ? W / 2 : P + (x - x0) / (x1 - x0) * (W - 2 * P);
  const sy = (y) => H - P - (y / y1) * (H - 2 * P);
  // A single point: render a flat line.
  const pts = points.length === 1 ? [{ x: P, y: sy(ys[0]) }, { x: W - P, y: sy(ys[0]) }] : points.map((p, i) => ({ x: sx(xs[i]), y: sy(ys[i]) }));
  const line = pts.map((p, i) => `${i ? "L" : "M"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
  const area = `${line} L${pts[pts.length - 1].x.toFixed(1)},${H - P} L${pts[0].x.toFixed(1)},${H - P} Z`;
  const last = ys[ys.length - 1];
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <path d="${area}" fill="${o.color}" opacity="0.12"/>
    <path d="${line}" fill="none" stroke="${o.color}" stroke-width="2"/>
    <circle cx="${pts[pts.length - 1].x.toFixed(1)}" cy="${pts[pts.length - 1].y.toFixed(1)}" r="3" fill="${o.color}"/>
  </svg><div class="chart-foot"><span>${o.fmt(ys[0])}</span><b>${o.fmt(last)}</b></div>`;
}

// utilBars draws horizontal utilization bars for subnets.
function utilBars(subnets) {
  if (!subnets || !subnets.length) return `<div class="chart-empty">no subnets</div>`;
  return `<div class="ubars">${subnets.slice(0, 8).map((s) => {
    const pct = Math.round((s.utilization || 0) * 100);
    const col = pct >= 90 ? "var(--absent)" : pct >= 75 ? "#e0a23c" : "var(--accent)";
    return `<div class="ubar"><span class="ubar-l mono">${esc(s.name || s.cidr)}</span>
      <span class="ubar-track"><span class="ubar-fill" style="width:${s.total ? pct : 0}%;background:${col}"></span></span>
      <span class="ubar-v">${s.total ? pct + "%" : "—"} <span class="muted-note">(${s.used}${s.total ? "/" + s.total : ""})</span></span></div>`;
  }).join("")}</div>`;
}

// ── activity feed (the "what changed" history) ───────────────────────────────
const EVENT_KINDS = {
  new_device:     { icon: "🆕", label: "New device" },
  device_offline: { icon: "🔴", label: "Went offline" },
  device_online:  { icon: "🟢", label: "Back online" },
  ip_changed:     { icon: "🔀", label: "IP changed" },
  conflict:       { icon: "⚠️", label: "Conflict" },
  risky_service:  { icon: "🛡️", label: "Risky service" },
};
let activityKind = "";

async function renderActivity() {
  const body = $("activity-body");
  const path = "/api/events?limit=300" + (activityKind ? "&kind=" + encodeURIComponent(activityKind) : "");
  let data;
  try { data = await getJSON(path); } catch (e) { body.innerHTML = `<p class="muted-note">Couldn't load activity: ${esc(e.message)}</p>`; return; }
  const events = data.events || [];

  const chip = (k, label) => `<button class="act-chip ${activityKind === k ? "on" : ""}" data-kind="${k}">${label}</button>`;
  const filters = `<div class="act-filters">${chip("", "All")}${Object.entries(EVENT_KINDS).map(([k, m]) => chip(k, m.icon + " " + m.label)).join("")}</div>`;

  const rows = events.length ? events.map((ev) => {
    const m = EVENT_KINDS[ev.kind] || { icon: "•", label: ev.kind };
    const delta = ev.old && ev.new ? ` <span class="mono">${esc(ev.old)}</span> → <span class="mono">${esc(ev.new)}</span>` : "";
    return `<div class="act-row" data-host="${esc(ev.stable_id)}">
      <span class="act-ico" title="${esc(m.label)}">${m.icon}</span>
      <span class="act-msg">${esc(ev.message || m.label)}${delta}</span>
      <span class="act-time" title="${esc(ev.at)}">${fmtTime(ev.at)}</span>
    </div>`;
  }).join("") : `<p class="muted-note">No changes recorded yet${activityKind ? " for this filter" : ""}. Tessera logs devices appearing, going offline, changing IP, and new conflicts/risky services as they happen.</p>`;

  body.innerHTML = `<h2>Activity</h2>
    <p class="muted-note">Everything that's changed on your network, newest first. This is also available over the API (<span class="mono">/api/events?since=&lt;cursor&gt;</span>) for incremental sync.</p>
    ${filters}<div class="act-feed">${rows}</div>`;

  for (const c of body.querySelectorAll(".act-chip")) c.onclick = () => { activityKind = c.dataset.kind; renderActivity(); };
  for (const r of body.querySelectorAll(".act-row")) {
    const id = r.dataset.host;
    if (id) r.onclick = () => openHost(id);
  }
}

// ── system health ────────────────────────────────────────────────────────────
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + " " + u[i];
}
function fmtUptime(s) {
  s = Math.max(0, s | 0);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}
async function renderSystem() {
  const body = $("system-body");
  let d;
  try { d = await getJSON("/api/system"); } catch (e) { body.innerHTML = `<h2>System</h2><p class="muted-note">Couldn't load system info: ${esc(e.message)}</p>`; return; }
  const tile = (label, val, warn) => `<div class="sys-tile ${warn ? "warn" : ""}"><div class="sys-val">${esc(String(val))}</div><div class="sys-lbl">${esc(label)}</div></div>`;

  const badge = (st) => {
    const cls = st.state === "ok" ? "ok" : st.state === "error" ? "err" : "idle";
    const dot = st.state === "idle" ? "○" : "●";
    return `<span class="status-badge ${cls}">${dot} ${esc(st.state)}</span>`;
  };
  const cols = (d.collectors || []).map((c) => `<tr>
    <td class="mono">${esc(c.name)}</td><td>${badge(c)}</td>
    <td>${c.last_run && !String(c.last_run).startsWith("0001") ? fmtTime(c.last_run) : "—"}</td>
    <td class="muted-note">${esc(c.state === "error" ? (c.err || "error") : (c.detail || ""))}</td></tr>`).join("");

  body.innerHTML = `<h2>System</h2>
    <p class="muted-note">Is Tessera working? Collector health, data volume, and build — at a glance.</p>
    <div class="sys-tiles">
      ${tile("Uptime", fmtUptime(d.uptime_seconds))}
      ${tile("Database", fmtBytes(d.db_size_bytes))}
      ${tile("Observations", (d.observations_total || 0).toLocaleString())}
      ${tile("Changes logged", (d.events_total || 0).toLocaleString())}
      ${tile("Dropped (backpressure)", (d.dropped || 0).toLocaleString(), d.dropped > 0)}
      ${tile("Hosts", d.hosts || 0)}
      ${tile("Addresses", d.addresses || 0)}
      ${tile("Services", d.services || 0)}
      ${tile("Subnets", d.subnets || 0)}
      ${tile("Conflicts", d.conflicts || 0, d.conflicts > 0)}
    </div>
    <h3>Collectors <span class="badge">${(d.collectors || []).length}</span></h3>
    ${d.collectors && d.collectors.length
      ? `<table class="obs"><thead><tr><th>Collector</th><th>State</th><th>Last run</th><th>Detail</th></tr></thead><tbody>${cols}</tbody></table>`
      : `<p class="muted-note">No collectors enabled yet. Turn one on in <a href="#settings" class="link-in">Settings</a> — the UniFi poller, Proxmox, or the active prober are good first choices.</p>`}
    ${d.dropped > 0 ? `<p class="muted-note warn-note">⚠ ${d.dropped.toLocaleString()} observation(s) were dropped under load — the passive sensor's SPAN feed is best-effort. If this keeps climbing, the host can't keep up with the mirror-port volume.</p>` : ""}
    <p class="muted-note" style="margin-top:14px">Tessera ${esc(d.version)} · build ${esc(d.build)}</p>`;
}

async function renderTrends() {
  const sec = $("trends-section");
  if (!sec) return;
  let d;
  try { d = await getJSON("/api/trends"); } catch { sec.classList.add("hidden"); return; }
  const growth = d.device_growth || [], avail = d.availability || [], subnets = d.subnets || [];
  // Only surface the panel once there's something to show.
  if (growth.length === 0 && avail.length === 0 && subnets.length === 0) { sec.classList.add("hidden"); return; }
  sec.classList.remove("hidden");
  $("trends-body").innerHTML = `<div class="charts">
    <div class="chart-card"><h3>Devices over time</h3>${sparkLine(growth, { color: "var(--accent)" })}</div>
    <div class="chart-card"><h3>Online devices</h3>${sparkLine(avail, { color: "#4aa3ff" })}</div>
    <div class="chart-card"><h3>Subnet utilization</h3>${utilBars(subnets)}</div>
  </div>`;
}
function renderSummary(s) {
  const stat = (n, l, d) => `<div class="stat" data-drill="${d}"><b>${n}</b><span>${l}</span></div>`;
  $("summary").innerHTML = stat(s.hosts, "hosts", "inventory") + stat(s.addresses, "addresses", "inventory") +
    stat(s.subnets, "subnets", "subnets") + stat(s.services, "services", "services") +
    stat(s.open_conflicts, "conflicts", "conflicts") + stat(s.observations, "observations", "observations");
  for (const t of $("summary").querySelectorAll(".stat")) t.onclick = () => openDrill(t.dataset.drill);
}

async function openDrill(kind) {
  try {
    if (kind === "observations") {
      showView("observations");
    } else if (kind === "subnets") {
      renderSubnets(await getJSON("/api/subnets"));
    } else if (kind === "conflicts") {
      await openConflicts();
    } else if (kind === "services") {
      await openServices();
    } else {
      showView("dashboard");
      document.getElementById("hosts").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (e) { toast(e.message); }
}

// ── observations page (server-side search/filter/paginate) ───────────────────
let obsState = { q: "", source: "", attr: "", offset: 0, total: 0 };
let obsTimer = null;

async function renderObservations(reset) {
  if (reset) {
    obsState.q = $("obs-q").value.trim();
    obsState.source = $("obs-source").value;
    obsState.attr = $("obs-attr").value;
    obsState.offset = 0;
    $("obs-body").innerHTML = "";
  }
  const p = new URLSearchParams({ limit: "200", offset: String(obsState.offset), q: obsState.q, source: obsState.source, attribute: obsState.attr });
  const page = await getJSON("/api/observations?" + p.toString());
  obsState.total = page.total;
  // Populate facet dropdowns on the first page (preserving the current choice).
  if (page.sources) fillFacet("obs-source", page.sources, obsState.source, "All sources");
  if (page.attributes) fillFacet("obs-attr", page.attributes, obsState.attr, "All attributes");
  const rows = (page.rows || []).map((o) =>
    `<tr><td class="mono">${fmtTime(o.observed_at)}</td><td class="src">${esc(o.source)}</td><td class="mono">${esc(o.subject)}</td><td>${esc(o.attribute)}</td><td>${esc(o.value)}</td><td class="conf">${o.confidence}</td></tr>`).join("");
  $("obs-body").insertAdjacentHTML("beforeend", rows);
  obsState.offset += (page.rows || []).length;
  $("obs-total").textContent = obsState.total;
  $("obs-shown").textContent = `showing ${obsState.offset} of ${obsState.total}`;
  $("obs-more").classList.toggle("hidden", obsState.offset >= obsState.total);
}

function fillFacet(id, values, selected, allLabel) {
  const el = $(id);
  el.innerHTML = `<option value="">${allLabel}</option>` + values.map((v) => `<option value="${esc(v)}" ${v === selected ? "selected" : ""}>${esc(v)}</option>`).join("");
}

function setupObservations() {
  $("obs-q").oninput = () => { clearTimeout(obsTimer); obsTimer = setTimeout(() => renderObservations(true), 250); };
  $("obs-source").onchange = () => renderObservations(true);
  $("obs-attr").onchange = () => renderObservations(true);
  $("obs-more").onclick = () => renderObservations(false);
}

// openServices lists discovered services grouped by friendly name (alphabetical),
// with unnamed numeric ports last. The API already returns them in that order.
async function openServices() {
  const rows = await getJSON("/api/services");
  let body;
  if (!rows.length) {
    body = `<p class="muted-note">No services discovered yet. The active prober populates these as it finds open TCP/UDP ports — set ports under Settings → Active prober, then rescan a host or subnet.</p>`;
  } else {
    let html = "", group = null;
    for (const r of rows) {
      const label = r.service || `Port ${r.port}`;
      if (label !== group) {
        group = label;
        html += `<h3 class="svc-group">${esc(label)}</h3>`;
      }
      html += `<div class="svc-row" data-id="${esc(r.stable_id || "")}">
        <span class="mono">${esc(r.proto)}/${r.port}</span>
        <span class="svc-host">${esc(r.host || "(unknown host)")}</span>
        ${r.banner ? `<span class="src">${esc(r.banner)}</span>` : ""}</div>`;
    }
    body = html;
  }
  $("detail-body").innerHTML = `<h2>Services <span class="badge">${rows.length}</span></h2>
    <p class="muted-note">Grouped by service, named services first (alphabetical), then bare ports by number.</p>${body}`;
  for (const row of $("detail-body").querySelectorAll(".svc-row[data-id]:not([data-id=''])")) {
    row.style.cursor = "pointer";
    row.onclick = () => openHost(row.dataset.id);
  }
  openPanel("detail");
}

function renderSubnets(rows) {
  const cols = ["CIDR", "VLAN", "Name", "Gateway", "Source"];
  if (me.can_edit) cols.push("");
  $("detail-body").innerHTML = `<h2>Subnets <span class="badge">${rows.length}</span></h2>
    <p class="muted-note">Click a subnet to see its address map and utilization.</p>
    ${me.can_edit ? `<div class="detail-actions"><button class="ghost" id="add-subnet-btn">+ Add subnet</button></div>` : ""}
    <table class="obs"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((s) => `<tr class="subnet-row" data-id="${s.id}">
      <td class="mono">${esc(s.cidr)}</td><td>${s.vlan_id ?? "—"}</td><td>${esc(s.name || "—")}</td>
      <td class="mono">${esc(s.gateway || "—")}</td><td>${esc(s.source)}</td>
      ${me.can_edit ? `<td><button class="ghost rescan-subnet" data-id="${s.id}" data-cidr="${esc(s.cidr)}" title="Actively probe every address in this subnet">↻ Rescan</button></td>` : ""}
    </tr>`).join("")}</tbody></table>`;
  if ($("add-subnet-btn")) $("add-subnet-btn").onclick = openCreateSubnet;
  for (const tr of $("detail-body").querySelectorAll(".subnet-row")) {
    tr.style.cursor = "pointer";
    tr.onclick = (e) => { if (!e.target.closest(".rescan-subnet")) openSubnet(tr.dataset.id); };
  }
  for (const b of $("detail-body").querySelectorAll(".rescan-subnet")) {
    b.onclick = async () => {
      b.disabled = true; b.textContent = "Scanning…";
      try {
        const res = await post("/api/subnet/rescan", { subnet_id: Number(b.dataset.id) });
        toast(`Scanning ${b.dataset.cidr} — ${res.targets} hosts; results will appear shortly`);
        // Background scan: refresh the inventory once it has had time to land.
        setTimeout(refresh, 20000);
      } catch (e) { toast(e.message); b.disabled = false; b.textContent = "↻ Rescan"; }
    };
  }
  openPanel("detail");
}

// openSubnet shows a subnet's address map: every IP colored by state, with
// utilization and the next free address.
async function openSubnet(id) {
  const d = await getJSON("/api/subnet?id=" + encodeURIComponent(id));
  const sn = d.subnet;
  const title = (sn.name ? esc(sn.name) + " · " : "") + esc(sn.cidr);
  const cells = (d.addresses || []).map((a) =>
    `<span class="ipcell ${esc(a.state)}${a.dhcp === "reserved" ? " dhcp-res" : ""}" data-id="${esc(a.stable_id || "")}" title="${esc(a.ip)}${a.host ? " · " + esc(a.host) : ""} (${esc(a.state)}${a.dhcp ? " · DHCP " + esc(a.dhcp) : ""})"></span>`).join("");
  const map = d.full_map
    ? `<div class="ipgrid">${cells}</div>`
    : `<p class="muted-note">Range too large to map every address — showing the ${d.used} observed addresses.</p><div class="ipgrid">${cells}</div>`;
  const nextFree = d.next_free ? `<span class="mono">${esc(d.next_free)}</span>` : "—";

  $("detail-body").innerHTML = `
    <h2>${title}</h2>
    <dl class="kv">
      ${sn.vlan_id != null ? `<dt>VLAN</dt><dd>${sn.vlan_id}</dd>` : ""}
      ${sn.gateway ? `<dt>Gateway</dt><dd class="mono">${esc(sn.gateway)}</dd>` : ""}
      <dt>Utilization</dt><dd>${d.used} / ${d.total}${d.full_map ? ` (${d.utilization}%)` : ""}</dd>
      <dt>Free</dt><dd>${d.full_map ? d.free : "—"}</dd>
      <dt>Next free</dt><dd>${nextFree}</dd>
    </dl>
    ${d.full_map ? `<div class="util"><div class="util-fill" style="width:${d.utilization}%"></div></div>` : ""}
    <div class="ip-legend">
      <span><i class="ipcell active"></i> active</span>
      <span><i class="ipcell stale"></i> stale</span>
      <span><i class="ipcell reserved"></i> reserved</span>
      <span><i class="ipcell free"></i> free</span>
      <span><i class="ipcell active dhcp-res"></i> DHCP reservation</span>
    </div>
    <h3>Addresses</h3>${map}`;
  for (const c of $("detail-body").querySelectorAll(".ipcell[data-id]:not([data-id=''])")) {
    c.style.cursor = "pointer";
    c.onclick = () => openHost(c.dataset.id);
  }
  openPanel("detail");
}

// Topology graph state: collapsed nodes (by stable_id) + the pan/zoom transform.
const topoCollapsed = new Set();
let topoView = { tx: 0, ty: 0, scale: 1 };
let topoDrag = null;
let topoPanInit = false;
let topoSeeded = false; // collapse big subtrees once, on the first load
function topoApply() {
  const g = document.getElementById("topo-g");
  if (g) g.setAttribute("transform", `translate(${topoView.tx},${topoView.ty}) scale(${topoView.scale})`);
}
function initTopoPan() {
  if (topoPanInit) return;
  topoPanInit = true;
  document.addEventListener("mousemove", (e) => {
    if (!topoDrag) return;
    topoView.tx = topoDrag.tx + (e.clientX - topoDrag.x);
    topoView.ty = topoDrag.ty + (e.clientY - topoDrag.y);
    topoApply();
  });
  document.addEventListener("mouseup", () => { topoDrag = null; });
}

// renderTopology draws the network as an interactive SVG node-link graph: gateway
// → switches → APs → clients. Hierarchical layout, pan (drag), zoom (wheel),
// collapsible subtrees, click-to-open. preserveView keeps the current pan/zoom
// (used when toggling a node); a fresh load fits the graph to the canvas.
async function renderTopology(preserveView) {
  const d = await getJSON("/api/topology");
  const roots = d.roots || [], unplaced = d.unplaced || [];
  if (!roots.length) {
    $("topology-body").innerHTML = `<h2>Network topology</h2><p class="muted-note">No topology yet — connect the UniFi controller (uplink + switch-port data builds the map).</p>`;
    return;
  }

  // First load: collapse switches/APs that fan out to many clients so the default
  // view is the readable gateway → switch backbone, not a 100-wide wall of leaves.
  if (!topoSeeded) {
    const seed = (n, depth) => {
      if (depth >= 1 && n.stable_id && (n.children || []).length > 6) topoCollapsed.add(n.stable_id);
      (n.children || []).forEach((k) => seed(k, depth + 1));
    };
    roots.forEach((r) => seed(r, 0));
    topoSeeded = true;
  }

  const NODE_W = 172, NODE_H = 48, H_GAP = 26, V_GAP = 86, ROOT_GAP = 64;
  let cursorX = 0;
  const edges = [];
  const layout = (n, depth, parent) => {
    n._y = depth * (NODE_H + V_GAP);
    if (parent) edges.push({ from: parent, to: n });
    n._hasKids = (n.children || []).length > 0;
    n._collapsed = topoCollapsed.has(n.stable_id);
    const kids = n._collapsed ? [] : (n.children || []);
    if (!kids.length) {
      n._x = cursorX;
      cursorX += NODE_W + H_GAP;
    } else {
      kids.forEach((k) => layout(k, depth + 1, n));
      n._x = (kids[0]._x + kids[kids.length - 1]._x) / 2;
    }
  };
  roots.forEach((r, i) => { if (i) cursorX += ROOT_GAP; layout(r, 0, null); });

  const nodes = [];
  const collect = (n) => { nodes.push(n); if (!n._collapsed) (n.children || []).forEach(collect); };
  roots.forEach(collect);
  const maxX = Math.max(...nodes.map((n) => n._x)) + NODE_W;
  const maxY = Math.max(...nodes.map((n) => n._y)) + NODE_H;

  const edgeSVG = edges.map((e) => {
    const x1 = e.from._x + NODE_W / 2, y1 = e.from._y + NODE_H;
    const x2 = e.to._x + NODE_W / 2, y2 = e.to._y;
    const my = (y1 + y2) / 2;
    const lbl = [e.to.port ? "port " + e.to.port : "", e.to.speed || ""].filter(Boolean).join(" · ");
    return `<path class="topo-edge" d="M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}"/>` +
      (lbl ? `<text class="topo-elabel" x="${x2 + 6}" y="${y2 - 6}">${esc(lbl)}</text>` : "");
  }).join("");

  const nodeSVG = nodes.map((n) => {
    const tog = n._hasKids ? `<button class="tnode-tog" data-tid="${esc(n.stable_id)}" title="${n._collapsed ? "Expand" : "Collapse"}">${n._collapsed ? "+" : "–"}</button>` : "";
    return `<foreignObject x="${n._x}" y="${n._y}" width="${NODE_W}" height="${NODE_H}">
      <div class="tnode" data-id="${esc(n.stable_id)}" xmlns="http://www.w3.org/1999/xhtml">
        <span class="dev-icon" style="${iconStyle(n.icon_url, "var(--accent)")}"></span>
        <span class="tnode-text"><span class="tnode-name">${esc(n.name)}</span>${n.sub ? `<span class="tnode-sub">${esc(n.sub)}</span>` : ""}</span>
        ${tog}
      </div></foreignObject>`;
  }).join("");

  $("topology-body").innerHTML = `<h2>Network topology</h2>
    <div class="topo-toolbar">
      <button class="ghost topo-zbtn" id="topo-zout" title="Zoom out">−</button>
      <button class="ghost topo-zbtn" id="topo-zin" title="Zoom in">+</button>
      <button class="ghost" id="topo-fit" title="Fit the whole map in view">Fit</button>
      <span class="muted-note">Drag to pan · scroll or +/− to zoom · click a device to open · the ± on a node expands/collapses its branch</span>
    </div>
    <div class="topo-canvas" id="topo-canvas"><svg id="topo-svg"><g id="topo-g"><g class="topo-edges">${edgeSVG}</g>${nodeSVG}</g></svg></div>
    ${unplaced.length ? `<details class="topo-unplaced"><summary>Unplaced devices <span class="badge">${unplaced.length}</span></summary>${unplaced.map((u) => `<div class="topo-row" data-id="${esc(u.stable_id)}"><span class="dev-icon" style="${iconStyle(u.icon_url, "var(--accent)")}"></span>${esc(u.name)}${u.sub ? ` <span class="topo-sub">${esc(u.sub)}</span>` : ""}</div>`).join("")}</details>` : ""}`;

  initTopoPan();
  const canvas = $("topo-canvas"), svg = $("topo-svg");
  const clampZ = (s) => Math.max(0.25, Math.min(3, s));
  // Fit: the whole map in view (overview, can be small for a big tree).
  const fitAll = () => {
    const cw = canvas.clientWidth || 800, ch = canvas.clientHeight || 500;
    let s = clampZ(Math.min((cw - 48) / maxX, (ch - 48) / maxY, 1.3));
    if (!isFinite(s) || s <= 0) s = 1;
    topoView = { scale: s, tx: Math.max(24, (cw - maxX * s) / 2), ty: 24 };
    topoApply();
  };
  // Default: readable node size. Show everything only if it fits comfortably;
  // otherwise keep nodes legible and let the user pan a wide tree.
  const defaultView = () => {
    const cw = canvas.clientWidth || 800, ch = canvas.clientHeight || 500;
    const fitS = Math.min((cw - 48) / maxX, (ch - 48) / maxY, 1.3);
    const s = clampZ(fitS >= 0.85 ? fitS : 0.95);
    topoView = { scale: s, tx: maxX * s <= cw ? (cw - maxX * s) / 2 : 24, ty: 24 };
    topoApply();
  };
  const zoomBy = (f) => {
    const cw = canvas.clientWidth, ch = canvas.clientHeight, cx = cw / 2, cy = ch / 2;
    const ns = clampZ(topoView.scale * f), k = ns / topoView.scale;
    topoView = { scale: ns, tx: cx - (cx - topoView.tx) * k, ty: cy - (cy - topoView.ty) * k };
    topoApply();
  };
  if (preserveView) topoApply(); else defaultView();
  $("topo-fit").onclick = fitAll;
  $("topo-zin").onclick = () => zoomBy(1.25);
  $("topo-zout").onclick = () => zoomBy(0.8);
  svg.onmousedown = (e) => { if (!e.target.closest(".tnode")) topoDrag = { x: e.clientX, y: e.clientY, tx: topoView.tx, ty: topoView.ty }; };
  canvas.onwheel = (e) => {
    e.preventDefault();
    const f = e.deltaY < 0 ? 1.12 : 0.89;
    const r = canvas.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
    const ns = clampZ(topoView.scale * f), k = ns / topoView.scale;
    topoView = { scale: ns, tx: mx - (mx - topoView.tx) * k, ty: my - (my - topoView.ty) * k };
    topoApply();
  };
  for (const el of canvas.querySelectorAll(".tnode[data-id]:not([data-id=''])")) {
    el.onclick = (e) => { if (!e.target.closest(".tnode-tog")) openHost(el.dataset.id); };
  }
  for (const b of canvas.querySelectorAll(".tnode-tog")) {
    b.onclick = (e) => {
      e.stopPropagation();
      const id = b.dataset.tid;
      topoCollapsed.has(id) ? topoCollapsed.delete(id) : topoCollapsed.add(id);
      renderTopology(true);
    };
  }
  for (const row of $("topology-body").querySelectorAll(".topo-unplaced .topo-row[data-id]:not([data-id=''])")) {
    row.style.cursor = "pointer";
    row.onclick = () => openHost(row.dataset.id);
  }
}

// renderSecurity renders the exposed-services / posture findings (full page),
// grouped by severity. Each finding links to its host; admins can suppress
// (accept-risk) a finding with a note, which moves it to the suppressed list and
// stops it firing alerts.
async function renderSecurity() {
  const d = await getJSON("/api/security");
  const findings = d.findings || [];
  const suppressed = d.suppressed || [];
  const isAdmin = me && me.can_edit;
  const counts = `<div class="sec-counts">
    <span class="sev-pill high">${d.high} high</span>
    <span class="sev-pill medium">${d.medium} medium</span>
    <span class="sev-pill low">${d.low} low</span></div>`;
  const row = (f, supp) => `
    <div class="sec-row${supp ? " supp" : ""}" data-id="${esc(f.stable_id)}" data-proto="${esc(f.proto || "")}" data-port="${f.port || 0}">
      <span class="sev-pill ${esc(f.severity)}">${esc(f.severity)}</span>
      <div class="sec-main">
        <div><b>${esc(f.title)}</b>${f.port ? ` <span class="mono">${esc(f.proto)}/${f.port}</span>` : ""}</div>
        <div class="sec-detail">${esc(f.detail)}</div>
        ${supp && f.note ? `<div class="sec-note">📝 ${esc(f.note)}</div>` : ""}
        ${supp ? `<div class="sec-note muted-note">acknowledged${f.suppressed_by ? ` by ${esc(f.suppressed_by)}` : ""} · ${fmtExpiry(f.expires_at)}</div>` : ""}
      </div>
      <div class="sec-host">
        <div><span class="topo-name">${esc(f.host)}</span>${f.ip ? ` <span class="mono">${esc(f.ip)}</span>` : ""}</div>
        ${isAdmin ? `<div class="sec-actions">${supp
          ? `<button class="ghost sec-restore">↩ Restore</button>`
          : `<button class="ghost sec-suppress">⊘ Suppress</button>`}</div>` : ""}
      </div>
    </div>`;
  const body = findings.length
    ? findings.map((f) => row(f, false)).join("")
    : `<p class="muted-note">No active exposed-service findings. (Findings come from the active prober's discovered open ports — set ports under Settings → Active prober and rescan.)</p>`;
  const suppBlock = suppressed.length
    ? `<details class="sec-suppressed"><summary>Suppressed / acknowledged (${suppressed.length})</summary>${suppressed.map((f) => row(f, true)).join("")}</details>`
    : "";
  $("security-body").innerHTML = `<h2>Security posture <span class="badge">${findings.length}</span></h2>
    <p class="muted-note">Reachable services worth reviewing — plaintext, remote-access, exposed databases, file sharing. These are things to confirm are intentional, not confirmed vulnerabilities.</p>
    ${counts}${body}${suppBlock}`;
  for (const r of $("security-body").querySelectorAll(".sec-row[data-id]:not([data-id=''])")) {
    r.style.cursor = "pointer";
    r.onclick = (e) => { if (!e.target.closest("button")) openHost(r.dataset.id); };
  }
  const fkey = (r) => ({ stable_id: r.dataset.id, proto: r.dataset.proto, port: +r.dataset.port });
  for (const b of $("security-body").querySelectorAll(".sec-suppress")) {
    b.onclick = async () => {
      const dur = prompt("Suppress for how long?\n• blank = indefinitely\n• a number = that many days (e.g. 30)\n• a date = until then (YYYY-MM-DD or YYYY-MM-DDTHH:MM)");
      if (dur === null) return; // cancelled
      const body = fkey(b.closest(".sec-row"));
      const s = dur.trim();
      if (s) {
        if (/^\d+$/.test(s)) {
          body.expires_in_days = +s;
        } else {
          const d = new Date(s);
          if (isNaN(d.getTime())) { toast("Unrecognized duration — use days or a date"); return; }
          if (d.getTime() <= Date.now()) { toast("Date must be in the future"); return; }
          body.expires_at = d.toISOString();
        }
      }
      const note = prompt("Note (optional, e.g. “intentional, firewalled off”):");
      if (note === null) return; // cancelled
      body.note = note;
      await post("/api/security/suppress", body);
      toast("Finding suppressed"); renderSecurity();
    };
  }
  for (const b of $("security-body").querySelectorAll(".sec-restore")) {
    b.onclick = async () => {
      await post("/api/security/unsuppress", fkey(b.closest(".sec-row")));
      toast("Finding restored"); renderSecurity();
    };
  }
}

// renderPortmap draws each switch as a faceplate: a row of numbered port cells,
// occupied ones labeled with the connected device + speed (click → host).
async function renderPortmap() {
  const d = await getJSON("/api/portmap");
  const switches = d.switches || [];
  const faceplate = (sw) => {
    const cells = sw.ports.map((p) => {
      const occ = p.device ? "occ" : "free";
      const title = p.device ? `${p.device}${p.speed ? " · " + p.speed : ""}${p.vlan != null ? " · VLAN " + p.vlan : ""}` : "empty";
      return `<div class="port ${occ}" data-id="${esc(p.stable_id || "")}" title="Port ${p.port} — ${esc(title)}">
        <span class="port-num">${p.port}</span>${p.device ? `<span class="port-dev">${esc(p.device)}</span>` : ""}</div>`;
    }).join("");
    return `<div class="faceplate">
      <div class="faceplate-head"><span class="dev-icon" style="${iconStyle(sw.icon_url, "var(--accent)")}"></span>
        <b>${esc(sw.name)}</b>${sw.model ? ` <span class="topo-sub">${esc(sw.model)}</span>` : ""}
        <span class="topo-link">${sw.used}/${sw.total} ports</span></div>
      <div class="ports">${cells}</div></div>`;
  };
  const body = switches.length ? switches.map(faceplate).join("")
    : `<p class="muted-note">No switch port data yet — connect the UniFi controller (uplinks + switch-port assignments build this).</p>`;
  $("ports-body").innerHTML = `<h2>Switch ports</h2>
    <p class="muted-note">Patch-panel view — each switch's ports and what's connected, from UniFi topology. Click an occupied port to open the device.</p>${body}`;
  for (const c of $("ports-body").querySelectorAll(".port.occ[data-id]:not([data-id=''])")) {
    c.style.cursor = "pointer";
    c.onclick = () => openHost(c.dataset.id);
  }
}

function renderDrill(title, cols, rows) {
  $("detail-body").innerHTML = `<h2>${esc(title)} <span class="badge">${rows.length}</span></h2>
    <table class="obs"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r) => `<tr>${r.map((c, i) => `<td class="${i === cols.length - 1 ? "conf" : i === 2 || i === 0 ? "mono" : ""}">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  openPanel("detail");
}
const expectedPill = (v) => v ? `<span class="pill yes">expected</span>` : `<span class="pill no">new</span>`;

// Brand/OS logo colors — each glyph painted in its official brand color (values
// tuned for legibility on the dark surface). Generic device-type icons aren't
// listed and fall back to the theme color passed by the caller.
const BRAND_COLORS = {
  amazon: "#ff9900", apple: "#e6ebed", google: "#4285f4", intel: "#1c91e6",
  microsoft: "#00a4ef", samsung: "#4263eb", synology: "#c7c8ca", ubiquiti: "#2596ff",
  android: "#3ddc84", ubuntu: "#e95420", debian: "#e0457b", raspberrypi: "#e5447a", linux: "#f6c915",
  fortinet: "#ee3124", opnsense: "#f0703a", pfsense: "#d0d3d6",
  // Networking vendors / homelab / smart-home brands (official Simple Icons hues,
  // dark ones lightened for legibility on the surface).
  tplink: "#4acbd6", netgear: "#c7c8ca", asus: "#cfd3d6", mikrotik: "#8aa0ad", cisco: "#1ba0d7",
  huawei: "#ff2d2d", openwrt: "#00b5e2", ring: "#1c9ad6", philipshue: "#2e90ff", sonos: "#e6ebed",
  homeassistant: "#18bcf2", shelly: "#4495d1", wyze: "#1df0bb", lifx: "#d8d8d8", smartthings: "#15bfff",
  wemo: "#72d44c", roku: "#8b5cc7", plex: "#ebaf00", jellyfin: "#00a4dc", kodi: "#17b2e7",
  nvidia: "#76b900", lg: "#e3486f", sony: "#e6ebed", panasonic: "#2f6fd6", xiaomi: "#ff6900", dell: "#0096d6",
  hp: "#0096d6", lenovo: "#e2231a", qnap: "#3a6fd6", acer: "#83b81a", framework: "#cfd3d6",
  supermicro: "#5566cc", truenas: "#0095d5", openmediavault: "#5dacdf", proxmox: "#e57000",
  docker: "#2496ed", unraid: "#f15a2c", oneplus: "#f5010c", oppo: "#3fa65f", motorola: "#4a90e2",
  nokia: "#3a7fff", epson: "#3a6fd6",
};
// iconId pulls the icon id from its URL (…/icons/lib/<id> or …/icons/custom/<id>).
const iconId = (url) => String(url || "").split("/").pop();
// iconStyle builds the mask + fill style: a brand color when the icon is a known
// logo, otherwise the caller's theme fallback (e.g. accent).
const iconStyle = (url, fallback) => `--i:url('${esc(url)}');background-color:${BRAND_COLORS[iconId(url)] || fallback}`;
// confBadge maps a 0–100 confidence to a high/medium/low badge (IP Recon model:
// a strong signal is high, ≥2 agreeing weak signals are medium, a lone hint is low).
function confLevel(conf) { return conf >= 70 ? "high" : conf >= 40 ? "medium" : "low"; }
function confBadge(conf) {
  if (!conf) return "";
  const lvl = confLevel(conf);
  return `<span class="conf-badge ${lvl}" title="confidence ${conf}/100">${lvl}</span>`;
}
// Inventory sort state (client-side; null key = server order until a header is clicked).
let hostsData = [];
let hostSort = { key: null, dir: 1 };
let hostQuery = "";
let tagFilter = ""; // exact-tag inventory filter (set by clicking a tag chip)

// tagColor derives a stable, legible-on-dark color from a tag name.
function tagColor(tag) {
  let h = 0;
  for (let i = 0; i < tag.length; i++) h = (h * 31 + tag.charCodeAt(i)) >>> 0;
  return `hsl(${h % 360} 55% 62%)`;
}
const tagChips = (tags, clickable) => (tags || []).map((t) =>
  `<span class="tag-chip${clickable ? " click" : ""}" data-tag="${esc(t)}" style="--tc:${tagColor(t)}">${esc(t)}</span>`).join("");

// sortKeyFns map each sortable column to a comparable value for a host row.
const sortKeyFns = {
  name: (h) => (h.display_name || "").toLowerCase(),
  device: (h) => (h.model || h.device_class || "").toLowerCase(),
  conf: (h) => ((h.device_class || h.os_guess) ? h.confidence : 0) || 0,
  addr: (h) => ipSortKey((h.ips || [])[0]),
  vendor: (h) => (h.vendor || "").toLowerCase(),
  expected: (h) => (h.is_expected ? 1 : 0),
  seen: (h) => Date.parse(h.last_seen) || 0,
};

// ipSortKey returns a string that sorts IPv4 addresses correctly (octets
// zero-padded); non-IPv4 (or missing) fall back to a plain string so the
// comparator stays type-consistent.
function ipSortKey(ip) {
  if (!ip) return "";
  const p = ip.split(".");
  if (p.length === 4 && p.every((o) => /^\d+$/.test(o))) return p.map((o) => o.padStart(3, "0")).join(".");
  return ip;
}

// hostMatches tests a host against the free-text inventory search (name, IPs,
// MACs, vendor, model, device class, OS).
function hostMatches(h, q) {
  if (!q) return true;
  const hay = [h.display_name, h.vendor, h.model, h.device_class, h.os_guess,
    (h.ips || []).join(" "), (h.macs || []).join(" "), (h.tags || []).join(" ")].join(" ").toLowerCase();
  return q.split(/\s+/).every((term) => hay.includes(term));
}

let lastFilterSig = "";
function renderHosts(hosts) {
  if (hosts) hostsData = hosts;
  // Changing the filter changes which rows you can see — drop any selection so a
  // bulk action can't hit invisible, no-longer-shown devices.
  const filterSig = tagFilter + "\x1f" + hostQuery;
  if (filterSig !== lastFilterSig) { selectedHosts.clear(); lastFilterSig = filterSig; }
  let rows = hostsData;
  if (tagFilter) rows = rows.filter((h) => (h.tags || []).includes(tagFilter));
  if (hostQuery) rows = rows.filter((h) => hostMatches(h, hostQuery));
  if (hostSort.key && sortKeyFns[hostSort.key]) {
    const f = sortKeyFns[hostSort.key], d = hostSort.dir;
    rows = [...rows].sort((a, b) => {
      const av = f(a), bv = f(b);
      return av < bv ? -d : av > bv ? d : 0;
    });
  }
  const isAdmin = me && me.can_edit;
  const visibleIDs = rows.map((h) => h.stable_id);
  $("hosts-body").innerHTML = rows.length ? rows.map((h) => `
    <tr data-id="${esc(h.stable_id)}">
      <td class="sel-col">${isAdmin ? `<input type="checkbox" class="row-sel" data-id="${esc(h.stable_id)}" ${selectedHosts.has(h.stable_id) ? "checked" : ""}>` : ""}</td>
      <td><span class="online-dot ${h.online ? "on" : "off"}" title="${h.online ? "online — has an active address" : "offline — no active address"}"></span><span class="dev-icon" style="${iconStyle(h.icon_url, "var(--accent)")}"></span>${esc(h.display_name || "(unnamed)")}${(h.tags || []).length ? `<div class="tags">${tagChips(h.tags, true)}</div>` : ""}</td>
      <td>${esc(h.model || h.device_class || "—")}</td>
      <td class="mono">${(h.ips || []).map(esc).join(", ") || "—"}</td>
      <td>${esc(h.vendor || "")}</td>
      <td>${expectedPill(h.is_expected)}</td>
      <td>${fmtTime(h.last_seen)}</td>
    </tr>`).join("")
    : `<tr><td colspan="7" class="muted-note" style="padding:18px;text-align:center">${hostsData.length ? "No devices match the current filter." : (me.is_admin ? `No devices discovered yet. Enable a collector in <a href="#settings" class="link-in">Settings</a> — the UniFi poller or Proxmox pull inventory instantly; the active prober sweeps a subnet you scope.` : "No devices discovered yet — once a collector sees traffic, devices land here.")}</td></tr>`;
  for (const tr of $("hosts-body").querySelectorAll("tr")) {
    tr.onclick = (e) => { if (!e.target.closest(".tag-chip") && !e.target.closest(".row-sel")) openHost(tr.dataset.id); };
  }
  for (const chip of $("hosts-body").querySelectorAll(".tag-chip.click")) {
    chip.onclick = () => { tagFilter = chip.dataset.tag; renderHosts(); renderTagFilterBar(); };
  }
  // Multi-select (admin): row checkboxes + select-all over the visible rows.
  if ($("sel-th")) $("sel-th").innerHTML = isAdmin ? `<input type="checkbox" id="sel-all" title="Select all shown">` : "";
  for (const cb of $("hosts-body").querySelectorAll(".row-sel")) {
    cb.onclick = (e) => { e.stopPropagation(); cb.checked ? selectedHosts.add(cb.dataset.id) : selectedHosts.delete(cb.dataset.id); renderBulkBar(); syncSelectAll(visibleIDs); };
  }
  if ($("sel-all")) {
    syncSelectAll(visibleIDs);
    $("sel-all").onclick = () => {
      const on = $("sel-all").checked;
      for (const id of visibleIDs) on ? selectedHosts.add(id) : selectedHosts.delete(id);
      for (const cb of $("hosts-body").querySelectorAll(".row-sel")) cb.checked = on;
      renderBulkBar();
    };
  }
  renderBulkBar();
  for (const th of document.querySelectorAll("#hosts thead th[data-sort]")) {
    th.setAttribute("aria-sort", th.dataset.sort === hostSort.key ? (hostSort.dir === 1 ? "ascending" : "descending") : "none");
  }
  renderTagFilterBar();
}

// ── bulk selection / actions (admin) ─────────────────────────────────────────
const selectedHosts = new Set();

function syncSelectAll(visibleIDs) {
  const all = $("sel-all");
  if (!all) return;
  const shown = visibleIDs.filter((id) => selectedHosts.has(id)).length;
  all.checked = visibleIDs.length > 0 && shown === visibleIDs.length;
  all.indeterminate = shown > 0 && shown < visibleIDs.length;
}

function renderBulkBar() {
  const bar = $("bulk-bar");
  if (!bar) return;
  const n = selectedHosts.size;
  if (n === 0) { bar.classList.add("hidden"); bar.innerHTML = ""; return; }
  bar.classList.remove("hidden");
  bar.innerHTML = `<span class="bulk-count"><b>${n}</b> selected</span>
    <button class="ghost" data-bulk="expected">✓ Expected</button>
    <button class="ghost" data-bulk="ignored">⊘ Ignore</button>
    <button class="ghost" data-bulk="new">↩ New</button>
    <button class="ghost" data-bulk="add_tags">+ Tag…</button>
    ${me.is_admin ? `<button class="ghost danger" data-bulk="forget">⌫ Forget</button>` : ""}
    <button class="ghost bulk-clear" id="bulk-clear">Clear</button>`;
  for (const b of bar.querySelectorAll("[data-bulk]")) b.onclick = () => bulkAction(b.dataset.bulk);
  $("bulk-clear").onclick = () => { selectedHosts.clear(); renderHosts(); };
}

async function bulkAction(action) {
  const ids = [...selectedHosts];
  if (!ids.length) return;
  const body = { stable_ids: ids, action };
  if (action === "add_tags") {
    const tags = prompt(`Add tags to ${ids.length} device(s) (comma-separated):`);
    if (tags === null) return;
    body.tags = splitList(tags);
    if (!body.tags.length) return;
  }
  if (action === "forget" && !confirm(`Forget ${ids.length} device(s)?\n\nThis permanently deletes their stored history and annotations. Devices still on the network are rediscovered as new on the next scan.`)) return;
  await mutate(async () => {
    try {
      const r = await post("/api/hosts/bulk", body);
      toast(`${action === "forget" ? "Forgot" : "Updated"} ${r.affected} device(s)`);
      selectedHosts.clear();
      refresh();
    } catch (e) { toast(e.message); }
  });
}

// renderTagFilterBar shows the active tag filter (with a clear button) + saved views.
function renderTagFilterBar() {
  const bar = $("inv-filterbar");
  if (!bar) return;
  const pill = tagFilter ? `<span class="tag-chip" style="--tc:${tagColor(tagFilter)}">tag: ${esc(tagFilter)} <a class="clear" id="clear-tag">✕</a></span>` : "";
  const views = savedViews();
  const opts = `<option value="">Saved views…</option>` + views.map((v, i) => `<option value="${i}">${esc(v.name)}</option>`).join("");
  bar.innerHTML = `${pill}<span class="grow"></span>
    <select id="view-select" class="view-select" title="Saved views are stored in this browser only">${opts}</select>
    <button class="ghost" id="view-save" title="Saves to this browser only">Save view</button>${views.length ? `<button class="ghost" id="view-del">Delete</button>` : ""}`;
  if ($("clear-tag")) $("clear-tag").onclick = () => { tagFilter = ""; renderHosts(); };
  $("view-select").onchange = (e) => { if (e.target.value !== "") applyView(views[+e.target.value]); };
  $("view-save").onclick = saveCurrentView;
  if ($("view-del")) $("view-del").onclick = () => { const s = $("view-select"); if (s.value !== "") deleteView(+s.value); };
}

// ── saved views (per-browser) ────────────────────────────────────────────────
function savedViews() { try { return JSON.parse(localStorage.getItem("tessera.views") || "[]"); } catch { return []; } }
function setViews(v) { localStorage.setItem("tessera.views", JSON.stringify(v)); }
function saveCurrentView() {
  const name = prompt("Save current filter as view — name:");
  if (!name) return;
  const v = savedViews();
  v.push({ name: name.trim(), q: hostQuery, tag: tagFilter, sortKey: hostSort.key, sortDir: hostSort.dir });
  setViews(v); renderTagFilterBar(); toast("View saved");
}
function applyView(v) {
  hostQuery = v.q || ""; tagFilter = v.tag || "";
  hostSort = { key: v.sortKey || null, dir: v.sortDir || 1 };
  if ($("host-search")) $("host-search").value = hostQuery;
  renderHosts();
}
function deleteView(i) { const v = savedViews(); v.splice(i, 1); setViews(v); renderTagFilterBar(); }

// setupSortHeaders wires the inventory headers once: click toggles direction on
// the active column, or switches to a new column (ascending first).
function setupSortHeaders() {
  for (const th of document.querySelectorAll("#hosts thead th[data-sort]")) {
    th.onclick = () => {
      const k = th.dataset.sort;
      if (hostSort.key === k) hostSort.dir = -hostSort.dir;
      else hostSort = { key: k, dir: 1 };
      renderHosts();
    };
  }
  const search = $("host-search");
  if (search) search.oninput = () => { hostQuery = search.value.trim().toLowerCase(); renderHosts(); };
}
// Device review workflow: every host is New (unreviewed), Expected (known), or
// Ignored (suppressed). Conflicts is a cross-cutting tab that opens the conflict
// page. Tiles move between categories via the per-tile actions (which annotate
// is_expected / ignored).
let deviceTab = "new";
const deviceStatus = (h) => h.ignored ? "ignored" : (h.is_expected ? "expected" : "new");
const DEVICE_HINTS = {
  new: "Discovered but not yet reviewed. Mark known devices Expected, or Ignore ones you don't care about.",
  expected: "Reviewed and known. These are your baseline.",
  ignored: "Suppressed from the review queue (guests, transient, or noise).",
};

function renderDevices(hosts, openCount) {
  hostsData = hosts || hostsData;
  const groups = { new: [], expected: [], ignored: [] };
  for (const h of hostsData) groups[deviceStatus(h)].push(h);

  const tab = (key, label, n) => `<button class="tab ${deviceTab === key ? "active" : ""}" data-tab="${key}">${label} <span class="badge">${n}</span></button>`;
  $("device-tabs").innerHTML =
    tab("new", "New / Unexpected", groups.new.length) +
    tab("expected", "Expected", groups.expected.length) +
    tab("ignored", "Ignored", groups.ignored.length) +
    `<button class="tab" data-tab="conflicts">Conflicts <span class="badge">${openCount ?? ""}</span></button>`;
  for (const b of $("device-tabs").querySelectorAll(".tab")) {
    b.onclick = () => {
      if (b.dataset.tab === "conflicts") { openConflicts(); return; }
      deviceTab = b.dataset.tab; renderDevices();
    };
  }

  if (me.can_edit && $("device-tabs") && !$("add-device-btn")) {
    const b = document.createElement("button");
    b.id = "add-device-btn"; b.className = "ghost add-btn"; b.textContent = "+ Add device";
    b.onclick = openCreateHost;
    $("device-tabs").appendChild(b);
  }
  $("device-hint").textContent = DEVICE_HINTS[deviceTab];
  const list = groups[deviceTab] || [];
  const admin = me.can_edit;
  // Per-category quick actions (move the tile to another category).
  const actions = (h) => {
    if (!admin) return "";
    const titles = { expected: "Mark reviewed — keep and track it", ignored: "Hide from review — keeps history", new: "Move back to unreviewed" };
    const b = (act, label) => `<button class="ghost dev-act" data-act="${act}" data-id="${esc(h.stable_id)}" title="${titles[act]}">${label}</button>`;
    const fgt = `<button class="ghost dev-forget danger" data-id="${esc(h.stable_id)}" data-name="${esc(h.display_name || "")}" title="Delete all stored history (rediscovered as new if it returns)">⌫ Forget</button>`;
    let acts;
    if (deviceTab === "new") acts = b("expected", "✓ Expected") + b("ignored", "⊘ Ignore");
    else if (deviceTab === "expected") acts = b("ignored", "⊘ Ignore") + b("new", "↩ New");
    else acts = b("expected", "✓ Expected") + b("new", "↩ New"); // ignored
    return `<div class="card-actions">${acts}${fgt}</div>`;
  };
  $("device-list").innerHTML = list.length ? list.map((h) => `
    <div class="card" data-id="${esc(h.stable_id)}">
      <div class="name"><span class="dev-icon" style="${iconStyle(h.icon_url, "var(--accent)")}"></span>${esc(h.display_name || "(unnamed)")}</div>
      <div class="meta mono">${(h.ips || []).map(esc).join(", ") || (h.macs || []).map(esc).join(", ")}</div>
      <div class="meta">${esc(h.model || h.device_class || "unclassified")} · first seen ${fmtTime(h.first_seen)}</div>
      ${actions(h)}
    </div>`).join("") : `<p class="muted-note">Nothing here.</p>`;

  for (const c of $("device-list").querySelectorAll(".card")) {
    c.onclick = (e) => { if (!e.target.closest("button")) openHost(c.dataset.id); };
  }
  for (const b of $("device-list").querySelectorAll(".dev-act")) {
    b.onclick = async () => {
      const body = { stable_id: b.dataset.id };
      const act = b.dataset.act;
      body.is_expected = act === "expected";
      body.ignored = act === "ignored";
      b.disabled = true;
      try { await post("/api/host/annotate", body); toast("Moved to " + act); refresh(); }
      catch (e) { toast(e.message); b.disabled = false; }
    };
  }
  for (const b of $("device-list").querySelectorAll(".dev-forget")) {
    b.onclick = () => forgetDevice(b.dataset.id, b.dataset.name);
  }
}

// forgetDevice permanently deletes a device's stored history + annotations so it
// can be rediscovered fresh. Destructive → always confirmed.
async function forgetDevice(stableId, name) {
  if (!confirm(`Forget “${name || stableId}”?\n\nThis permanently deletes all stored history and annotations for this device. If it's still on the network, it will be rediscovered as a new device on the next scan.`)) return;
  await mutate(async () => {
    try {
      const r = await post("/api/host/forget", { stable_id: stableId });
      toast(`Forgotten — ${r.observations_removed} records removed`);
      closePanels();
      refresh();
    } catch (e) { toast(e.message); }
  });
}

// openCreateHost documents a device by hand (offline gear / planned kit). MAC required.
function openCreateHost() {
  $("detail-body").innerHTML = `
    <h2>Add device</h2>
    <p class="muted-note">Document a device you know exists but haven't discovered yet (offline gear, planned kit). A MAC address is required — it's the stable identity. The device is marked Expected.</p>
    <form class="annotate" id="create-host-form">
      <label>MAC address *</label><input type="text" id="ch-mac" placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off">
      <label>IP address</label><input type="text" id="ch-ip" placeholder="10.0.0.5" autocomplete="off">
      <label>Display name</label><input type="text" id="ch-name">
      <label>Device / Hardware</label><input type="text" id="ch-class">
      <label>Model</label><input type="text" id="ch-model">
      <label>Notes</label><input type="text" id="ch-notes">
      <button type="submit" class="primary">Add device</button>
    </form>`;
  openPanel("detail");
  $("create-host-form").onsubmit = async (e) => {
    e.preventDefault();
    await mutate(async () => {
      try {
        const r = await post("/api/host/create", { mac: $("ch-mac").value, ip: $("ch-ip").value, display_name: $("ch-name").value, device_class: $("ch-class").value, model: $("ch-model").value, notes: $("ch-notes").value });
        toast(r.warning ? "Device added — " + r.warning : "Device added");
        openHost(r.stable_id); refresh();
      } catch (err) { toast(err.message); }
    });
  };
}

// openCreateSubnet documents a network by hand.
function openCreateSubnet() {
  $("detail-body").innerHTML = `
    <h2>Add subnet</h2>
    <p class="muted-note">Document a network Tessera hasn't seeded from UniFi or traffic.</p>
    <form class="annotate" id="create-subnet-form">
      <label>CIDR *</label><input type="text" id="cs-cidr" placeholder="10.0.0.0/24" autocomplete="off">
      <label>Name</label><input type="text" id="cs-name" placeholder="e.g. IoT VLAN">
      <label>VLAN id</label><input type="number" id="cs-vlan" min="0">
      <button type="submit" class="primary">Add subnet</button>
    </form>`;
  openPanel("detail");
  $("create-subnet-form").onsubmit = async (e) => {
    e.preventDefault();
    const vlan = $("cs-vlan").value ? Number($("cs-vlan").value) : undefined;
    await mutate(async () => {
      try {
        await post("/api/subnet/create", { cidr: $("cs-cidr").value, name: $("cs-name").value, vlan });
        toast("Subnet added"); closePanels(); refresh();
      } catch (err) { toast(err.message); }
    });
  };
}

// openConflicts is the dedicated conflict workflow: open disagreements (with a
// "keep this one" decision + note) and the log of resolved ones (with reopen).
async function openConflicts() {
  const data = await getJSON("/api/conflicts");
  const open = data.open || [], resolved = data.resolved || [];
  const admin = me.can_edit;

  const side = (c, which) => {
    const val = which === "a" ? c.value_a : c.value_b;
    const src = which === "a" ? c.source_a : c.source_b;
    const cnt = which === "a" ? c.count_a : c.count_b;
    const last = which === "a" ? c.last_seen_a : c.last_seen_b;
    const prov = `${cnt || 1} observation${(cnt || 1) === 1 ? "" : "s"}${last && !String(last).startsWith("0001") ? " · last " + fmtTime(last) : ""}`;
    const btn = admin
      ? `<button class="ghost keep" data-subject="${esc(c.subject)}" data-attr="${esc(c.attribute)}" data-value="${esc(val)}" data-source="${esc(src)}">Keep this</button>
         <button class="ghost prefer" data-attr="${esc(c.attribute)}" data-source="${esc(src)}" title="Across ALL devices, always use ${esc(src)} for ${esc(c.attribute)} — resolves this whole class of conflicts">Always prefer ${esc(src)} (all devices)</button>`
      : "";
    return `<div class="cf-side"><div><b>${esc(val)}</b> <span class="src">(${esc(src)})</span></div><div class="muted-note">${esc(prov)}</div>${btn}</div>`;
  };
  const precedence = data.precedence || [];
  const precAttrs = [["hostname", "Hostname"], ["model", "Model"], ["device_class", "Device / Hardware"], ["os_guess", "Operating System"]];
  const precSources = ["dns", "unifi", "active_rdns", "passive_mdns", "dhcp_leases", "proxmox", "active_snmp", "fingerbank", "inferred"];
  const addForm = admin ? `
    <div class="cf-card prec-add">
      <div class="prec-add-row">
        Always prefer
        <input list="prec-src-list" id="prec-src" value="dns" placeholder="source" class="prec-src-input">
        <datalist id="prec-src-list">${precSources.map((s) => `<option value="${esc(s)}">`).join("")}</datalist>
        for
        <select id="prec-attr">${precAttrs.map(([v, l]) => `<option value="${v}"${v === "hostname" ? " selected" : ""}>${l}</option>`).join("")}</select>
        <button class="ghost" id="prec-add-btn">Add rule</button>
      </div>
      <div class="muted-note">e.g. prefer <b>dns</b> for <b>hostname</b> so authoritative DNS names win over rDNS/UniFi guesses across every device.</div>
    </div>` : "";
  const precHTML = `
    <h3>Source-precedence policy <span class="badge">${precedence.length}</span></h3>
    <p class="muted-note">For these attributes, the chosen source's value always wins (manual annotations still override). Conflicts they cover are auto-resolved.</p>
    ${precedence.map((p) => `<div class="cf-card"><span class="mono">${esc(p.attribute)}</span> → always prefer <b>${esc(p.source)}</b>${admin ? ` <button class="ghost prec-clear" data-attr="${esc(p.attribute)}">Clear</button>` : ""}</div>`).join("")}
    ${addForm}`;

  const openHTML = open.length ? open.map((c) => `
    <div class="cf-card" data-subject="${esc(c.subject)}" data-attr="${esc(c.attribute)}">
      <div class="cf-head"><span class="mono">${esc(c.subject)}</span> · <b>${esc(c.attribute)}</b></div>
      <div class="cf-sides">${side(c, "a")}<span class="vs">vs</span>${side(c, "b")}</div>
      ${admin ? `<input type="text" class="cf-note" placeholder="note (optional) — why this is the source of truth">` : ""}
    </div>`).join("") : `<p class="muted-note">No open conflicts. 🎉</p>`;

  const resolvedHTML = resolved.length ? resolved.map((rr) => `
    <div class="cf-card resolved">
      <div class="cf-head"><span class="mono">${esc(rr.subject)}</span> · <b>${esc(rr.attribute)}</b>
        ${admin ? `<button class="ghost reopen" data-subject="${esc(rr.subject)}" data-attr="${esc(rr.attribute)}">Reopen</button>` : ""}</div>
      <div>source of truth: <b>${esc(rr.chosen_value || "—")}</b> ${rr.chosen_source ? `<span class="src">(${esc(rr.chosen_source)})</span>` : ""}</div>
      ${rr.note ? `<div class="cf-note-text">“${esc(rr.note)}”</div>` : ""}
      <div class="muted-note">resolved ${fmtTime(rr.resolved_at)}${rr.resolved_by ? " by " + esc(rr.resolved_by) : ""}</div>
    </div>`).join("") : `<p class="muted-note">Nothing resolved yet.</p>`;

  $("detail-body").innerHTML = `
    <h2>Conflicts</h2>
    <p class="muted-note">Sources disagree on a high-value attribute. Keep one value as the source of truth — it's written as an authoritative manual annotation, and the conflict moves to Resolved (the disagreement is recorded, not hidden).</p>
    <h3>Open <span class="badge">${open.length}</span></h3>
    ${openHTML}
    <h3>Resolved <span class="badge">${resolved.length}</span></h3>
    ${resolvedHTML}
    ${precHTML}`;

  if (admin) {
    for (const b of $("detail-body").querySelectorAll(".keep")) {
      b.onclick = async () => {
        const note = b.closest(".cf-card").querySelector(".cf-note");
        b.disabled = true;
        try {
          await post("/api/conflict/resolve", {
            subject: b.dataset.subject, attribute: b.dataset.attr,
            value: b.dataset.value, source: b.dataset.source, note: note ? note.value : "",
          });
          toast("Resolved"); openConflicts(); refresh();
        } catch (e) { toast(e.message); b.disabled = false; }
      };
    }
    for (const b of $("detail-body").querySelectorAll(".reopen")) {
      b.onclick = async () => {
        b.disabled = true;
        try { await post("/api/conflict/reopen", { subject: b.dataset.subject, attribute: b.dataset.attr }); toast("Reopened"); openConflicts(); refresh(); }
        catch (e) { toast(e.message); b.disabled = false; }
      };
    }
    for (const b of $("detail-body").querySelectorAll(".prefer")) {
      b.onclick = async () => {
        if (!confirm(`Always prefer “${b.dataset.source}” for ${b.dataset.attr}? This resolves every current and future conflict on that attribute where ${b.dataset.source} is a side.`)) return;
        try { await post("/api/conflict/precedence", { attribute: b.dataset.attr, source: b.dataset.source }); toast("Policy set"); openConflicts(); refresh(); }
        catch (e) { toast(e.message); }
      };
    }
    for (const b of $("detail-body").querySelectorAll(".prec-clear")) {
      b.onclick = async () => {
        try { await post("/api/conflict/precedence", { attribute: b.dataset.attr, source: "" }); toast("Policy cleared"); openConflicts(); refresh(); }
        catch (e) { toast(e.message); }
      };
    }
    const addBtn = $("prec-add-btn");
    if (addBtn) addBtn.onclick = async () => {
      const attribute = $("prec-attr").value;
      const source = $("prec-src").value.trim();
      if (!source) { toast("Enter a source"); return; }
      try { await post("/api/conflict/precedence", { attribute, source }); toast("Policy set"); openConflicts(); refresh(); }
      catch (e) { toast(e.message); }
    };
  }
  openPanel("detail");
}

async function openHost(id) {
  let d;
  try { d = await getJSON("/api/host?id=" + encodeURIComponent(id)); }
  catch { toast("That device is no longer here — it may have been forgotten or merged."); return; }
  const h = d.host;
  const isAdmin = me.can_edit;
  const xbtn = (attrs) => isAdmin ? `<button class="art-del" ${attrs} title="Delete this artifact (removes its stored observations)">✕</button>` : "";
  const ipById = {};
  (d.addresses || []).forEach((a) => { ipById[a.id] = a.ip; });
  const primaryIP = (d.addresses || [])[0] ? d.addresses[0].ip : "";
  const rows = (d.observations || []).map((o) => `<tr><td>${fmtTime(o.observed_at)}</td><td class="src">${esc(o.source)}</td><td>${esc(o.attribute)}</td><td>${esc(o.value)}</td><td class="conf">${o.confidence}</td>${isAdmin ? `<td>${xbtn(`data-kind="observation" data-id="${o.id}"`)}</td>` : ""}</tr>`).join("");
  const ifaces = (d.interfaces || []).map((i) => `<div class="mono art-row">${esc(i.mac)} ${i.is_randomized ? "· randomized" : ""} ${i.oui_vendor ? "· " + esc(i.oui_vendor) : ""}${xbtn(`data-kind="interface" data-mac="${esc(i.mac)}"`)}</div>`).join("") || "—";
  const addrs = (d.addresses || []).map((a) => `<div class="mono art-row">${esc(a.ip)} <span class="conf">[${esc(a.state)}]</span>${a.dhcp ? ` <span class="conf">DHCP ${esc(a.dhcp)}</span>` : ""}${xbtn(`data-kind="address" data-ip="${esc(a.ip)}"`)}</div>`).join("") || "—";
  const svcs = (d.services || []).map((s) => `<div class="mono art-row">${esc(s.proto)}/${s.port} ${s.banner ? "· " + esc(s.banner) : ""}${xbtn(`data-kind="service" data-ip="${esc(ipById[s.address_id] || primaryIP)}" data-proto="${esc(s.proto)}" data-port="${s.port}"`)}</div>`).join("") || "—";
  const topo = (d.topology || []).map((t) => `<div class="mono">${esc(t.switch)} port ${esc(t.switch_port)}</div>`).join("") || "—";
  const changeLabel = { ip: "IP", firmware: "Firmware", model: "Model", os: "OS", device: "Device", hostname: "Hostname", service: "Service" };
  const changes = (d.changes || []).map((c) => {
    const lbl = changeLabel[c.kind] || c.kind;
    const what = c.kind === "service" ? `New service <b>${esc(c.to)}</b>`
      : `${lbl}: ${c.from ? esc(c.from) + " → " : ""}<b>${esc(c.to)}</b>`;
    return `<div class="change"><span class="change-time mono">${fmtTime(c.at)}</span> ${what}</div>`;
  }).join("");
  const iconPicker = me.can_edit ? `
    <h3>Icon</h3>
    <div class="icon-picker" id="icon-picker">
      <button class="icon-tile ${h.icon ? "" : "sel"}" data-icon="" title="Auto">A</button>
      ${(await loadIcons()).map((i) => `<button class="icon-tile ${h.icon === i.id ? "sel" : ""}" data-icon="${esc(i.id)}" title="${esc(i.id)}"><span class="ic" style="${iconStyle(i.url, "var(--text)")}"></span></button>`).join("")}
    </div>` : "";
  const annotate = me.can_edit ? `
    <h3>Annotate</h3>
    <form class="annotate" id="annotate-form">
      <label>Display name</label><input type="text" id="an-name" value="${esc(h.display_name || "")}">
      <label>Device / Hardware</label><input type="text" id="an-class" value="${esc(h.device_class || "")}">
      <label>Model</label><input type="text" id="an-model" value="${esc(h.model || "")}" placeholder="e.g. UDM Pro, MacBook Pro 16&quot; M4">
      <label>Tags (comma-separated)</label><input type="text" id="an-tags" value="${esc((h.tags || []).join(", "))}" placeholder="e.g. iot, cameras, kids">
      <label>Notes</label><input type="text" id="an-notes" value="${esc(h.notes || "")}">
      <div class="row"><input type="checkbox" id="an-expected" ${h.is_expected ? "checked" : ""}><label for="an-expected" style="margin:0">Mark as expected</label></div>
      <div class="row"><input type="checkbox" id="an-ignored" ${h.ignored ? "checked" : ""}><label for="an-ignored" style="margin:0">Ignore (suppress from review)</label></div>
      <button type="submit" class="primary">Save annotation</button>
    </form>` : "";

  const av = d.availability;
  const avBlock = av ? `
    <h3>Availability</h3>
    <div class="avail">
      <div class="avail-now"><span class="pill ${av.online ? "yes" : "no"}">${av.online ? "online" : "offline"}</span> <span class="muted-note">since ${fmtTime(av.since)}</span></div>
      <div class="uptime-row">
        <span class="uptime">24h <b>${uptimePct(av.uptime_24h)}</b></span>
        <span class="uptime">7d <b>${uptimePct(av.uptime_7d)}</b></span>
        <span class="uptime">30d <b>${uptimePct(av.uptime_30d)}</b></span>
      </div>
      ${(av.events || []).length ? `<div class="avail-events">${av.events.map((e) => `<div class="change"><span class="change-time mono">${fmtTime(e.at)}</span> <span class="pill ${e.online ? "yes" : "no"}">${e.online ? "online" : "offline"}</span></div>`).join("")}</div>` : ""}
    </div>` : "";

  const actions = me.can_edit ? `<div class="detail-actions"><button id="rescan-host" class="ghost" title="Actively probe this host's addresses now">↻ Rescan host</button><button id="forget-host" class="ghost danger" title="Delete all history and let it be rediscovered">⌫ Forget</button></div>` : "";

  const otherHosts = (hostsData || []).filter((x) => x.stable_id !== h.stable_id)
    .map((x) => `<option value="${esc(x.stable_id)}">${esc(x.display_name || x.stable_id)}${(x.ips || [])[0] ? " · " + esc(x.ips[0]) : ""}</option>`).join("");
  const mergeUI = isAdmin ? `
    <h3>Merge</h3>
    ${(d.merged_from || []).length ? `<div class="merged-list">${d.merged_from.map((s) => `<div class="mono art-row">absorbed ${esc(s)} <button class="ghost unmerge" data-sec="${esc(s)}">↩ Split</button></div>`).join("")}</div>` : ""}
    <div class="merge-ctl"><select id="merge-target"><option value="">Merge another device into this one…</option>${otherHosts}</select><button class="ghost" id="merge-btn">Merge</button></div>
    <p class="muted-note">Use when two records are really the same physical device (dual-stack, randomized MAC, or an IP seen before its MAC). The selected device folds into this one; Split undoes it.</p>` : "";

  const online = d.availability ? d.availability.online : (d.addresses || []).some((a) => a.state === "active");
  const issues = [];
  if (d.sec_findings) issues.push(`<a class="issue-badge ${d.sec_high ? "high" : "med"}" data-go="security">⚠ ${d.sec_findings} security finding${d.sec_findings > 1 ? "s" : ""}</a>`);
  if (d.open_conflicts) issues.push(`<a class="issue-badge conflict" data-go="conflicts">⚠ ${d.open_conflicts} conflict${d.open_conflicts > 1 ? "s" : ""}</a>`);
  // Hardware: lead with the specific model; show the coarse class as a quiet aside.
  const hardware = esc(h.model || h.device_class || "—") +
    ((h.device_class || h.os_guess) ? " " + confBadge(h.confidence) : "") +
    (h.model && h.device_class && h.model !== h.device_class ? ` <span class="topo-sub">${esc(h.device_class)}</span>` : "");

  $("detail-body").innerHTML = `
    <h2><span class="dev-icon-lg" style="${iconStyle(d.icon_url, "var(--accent)")}"></span>${esc(h.display_name || "(unnamed)")}</h2>
    <div class="detail-sub">
      <span class="pill ${online ? "yes" : "no"}">${online ? "online" : "offline"}</span>
      ${primaryIP ? `<span class="mono">${esc(primaryIP)}</span>` : ""}
      ${issues.join("")}
    </div>
    ${actions}
    <dl class="kv">
      <dt>Hardware</dt><dd>${hardware}</dd>
      <dt>Operating System</dt><dd>${esc(h.os_guess || "—")} ${h.os_guess ? confBadge(h.confidence) : ""}</dd>
      ${h.firmware ? `<dt>Firmware</dt><dd class="mono">${esc(h.firmware)}</dd>` : ""}
      ${(h.tags || []).length ? `<dt>Tags</dt><dd><div class="tags">${tagChips(h.tags, false)}</div></dd>` : ""}
      <dt>Expected</dt><dd>${expectedPill(h.is_expected)}</dd>
      <dt>First seen</dt><dd>${fmtTime(h.first_seen)}</dd>
      <dt>Last seen</dt><dd>${fmtTime(h.last_seen)}</dd>
      <dt>Notes</dt><dd>${esc(h.notes || "—")}</dd>
      <dt class="muted-note">Identity</dt><dd class="mono muted-note">${esc(h.stable_id)}</dd>
    </dl>
    ${avBlock}
    <h3>Interfaces</h3>${ifaces}<h3>Addresses</h3>${addrs}<h3>Services</h3>${svcs}<h3>Topology</h3>${topo}
    ${iconPicker}
    ${annotate}
    ${mergeUI}
    ${(d.changes || []).length ? `<h3>Changes <span class="badge">${d.changes.length}</span></h3><div class="changes">${changes}</div>` : ""}
    <h3>Observation history <span class="badge">${(d.observations || []).length}</span></h3>
    <table class="obs"><tbody>${rows}</tbody></table>`;

  for (const b of $("detail-body").querySelectorAll(".issue-badge[data-go]")) {
    b.onclick = () => { closePanels(); if (b.dataset.go === "conflicts") openConflicts(); else showView("security"); };
  }

  if (me.can_edit) {
    $("annotate-form").onsubmit = async (e) => {
      e.preventDefault();
      await post("/api/host/annotate", { stable_id: h.stable_id, display_name: $("an-name").value, device_class: $("an-class").value, model: $("an-model").value, notes: $("an-notes").value, is_expected: $("an-expected").checked, ignored: $("an-ignored").checked, tags: splitList($("an-tags").value) });
      toast("Saved"); closePanels(); refresh();
    };
    for (const tile of $("icon-picker").querySelectorAll(".icon-tile")) {
      tile.onclick = async () => { await post("/api/host/annotate", { stable_id: h.stable_id, icon: tile.dataset.icon }); toast("Icon set"); openHost(id); refresh(); };
    }
    const rb = $("rescan-host");
    if (rb) rb.onclick = async () => {
      rb.disabled = true; rb.textContent = "Rescanning…";
      try {
        const res = await post("/api/host/rescan", { stable_id: h.stable_id });
        toast(`Rescanned ${res.probed} address(es)`); openHost(id); refresh();
      } catch (e) { toast(e.message); rb.disabled = false; rb.textContent = "↻ Rescan host"; }
    };
    const fb = $("forget-host");
    if (fb) fb.onclick = () => forgetDevice(h.stable_id, h.display_name);
    for (const b of $("detail-body").querySelectorAll(".art-del")) {
      b.onclick = async (e) => {
        e.stopPropagation();
        const k = b.dataset.kind;
        if (!confirm(`Delete this ${k}?\n\nThis removes its stored observations. If it's still live on the network it will be re-observed on the next scan.`)) return;
        const body = { stable_id: h.stable_id, kind: k };
        if (k === "observation") body.id = +b.dataset.id;
        else if (k === "address") body.ip = b.dataset.ip;
        else if (k === "interface") body.mac = b.dataset.mac;
        else if (k === "service") { body.ip = b.dataset.ip; body.proto = b.dataset.proto; body.port = +b.dataset.port; }
        await mutate(async () => {
          try {
            const r = await post("/api/host/delete-artifact", body);
            toast(`Removed ${r.observations_removed} record(s)`);
            openHost(id); refresh();
          } catch (err) { toast(err.message); }
        });
      };
    }
    const mb = $("merge-btn");
    if (mb) mb.onclick = async () => {
      const sec = $("merge-target").value;
      if (!sec) return;
      if (!confirm(`Merge that device into “${h.display_name || h.stable_id}”? They'll be treated as one device.`)) return;
      await mutate(async () => {
        try { await post("/api/host/merge", { primary: h.stable_id, secondary: sec }); toast("Merged"); openHost(id); refresh(); }
        catch (err) { toast(err.message); }
      });
    };
    for (const b of $("detail-body").querySelectorAll(".unmerge")) {
      b.onclick = async () => {
        try { await post("/api/host/unmerge", { secondary: b.dataset.sec }); toast("Split"); openHost(id); refresh(); }
        catch (err) { toast(err.message); }
      };
    }
  }
  openPanel("detail");
}

// ── settings ─────────────────────────────────────────────────────────────────

async function openSettings() {
  const [s, users, allIcons, statuses, auditResp, tokens] = await Promise.all([
    getJSON("/api/settings"), getJSON("/api/users"), loadIcons(true), getJSON("/api/status").catch(() => []),
    getJSON("/api/audit").catch(() => ({ entries: [] })), getJSON("/api/tokens").catch(() => []),
  ]);
  const audit = auditResp.entries || [];
  const customIcons = allIcons.filter((i) => i.source === "custom");
  const e = s.editable, flags = s.secrets_set, canSec = s.can_store_secrets;
  const statusByName = {};
  for (const st of statuses || []) statusByName[st.name] = st;
  const statusBadge = (name) => {
    const st = statusByName[name];
    if (!st) return "";
    const cls = st.state === "ok" ? "ok" : st.state === "error" ? "err" : "idle";
    const dot = st.state === "idle" ? "○" : "●";
    const when = st.last_run && !st.last_run.startsWith("0001") ? " · " + fmtTime(st.last_run) : "";
    const detail = (st.state === "error" ? (st.err || "error") : (st.detail || st.state)) + when;
    return `<span class="status-badge ${cls}" title="${esc(detail)}">${dot} ${esc(st.state)}</span>`;
  };
  const secField = (id, label, isSet) => `
    <div class="field"><label>${label} ${isSet ? '<span class="conf">(set — leave blank to keep)</span>' : ""}</label>
      <input type="password" id="${id}" placeholder="${isSet ? "••••••••" : "not set"}" ${canSec ? "" : "disabled"}></div>`;
  const txt = (id, label, val) => `<div class="field"><label>${label}</label><input type="text" id="${id}" value="${esc(val ?? "")}"></div>`;
  const chk = (id, label, on) => `<div class="field row"><input type="checkbox" id="${id}" ${on ? "checked" : ""}><label>${label}</label></div>`;

  // Proxmox VE: up to 5 instances, each with its own URL + auth (token OR user/pass).
  const pxInstances = e.proxmox_instances || [];
  const pxTokFlags = flags.proxmox_tokens_set || [];
  const pxPassFlags = flags.proxmox_passwords_set || [];
  // Mirror app.go's index-based collector naming (unique regardless of label) so
  // the status badge resolves and duplicate labels never collapse to one badge.
  const pxName = (i) => (i === 0 ? "proxmox" : "proxmox:" + (i + 1));
  const pxSlot = (i) => {
    const inst = pxInstances[i] || {};
    const mode = inst.auth_mode || "token";
    const hidden = i > 0 && !inst.base_url; // slot 0 always shown; extras revealed via "Add"
    const heading = `Instance ${i + 1}${i === 0 ? " · primary" : ""}${inst.name ? " — " + esc(inst.name) : ""}`;
    return `<div class="px-inst" data-px="${i}" ${hidden ? 'style="display:none"' : ""}>
      <div class="px-inst-head">${heading} ${statusBadge(pxName(i))}</div>
      ${txt(`set-px-name-${i}`, "Label (optional)", inst.name)}
      ${txt(`set-px-url-${i}`, "Base URL (https://proxmox.lan:8006)", inst.base_url)}
      ${chk(`set-px-verify-${i}`, "Verify TLS", inst.verify_tls)}
      <div class="field"><label>Authentication</label><select id="set-px-auth-${i}" class="px-auth" data-px="${i}">
        <option value="token" ${mode === "token" ? "selected" : ""}>API token</option>
        <option value="password" ${mode === "password" ? "selected" : ""}>Username + password</option></select></div>
      <div class="px-tok-${i}" ${mode === "password" ? 'style="display:none"' : ""}>
        ${secField(`set-px-token-${i}`, "API token (user@realm!tokenid=secret)", pxTokFlags[i])}</div>
      <div class="px-pass-${i}" ${mode === "token" ? 'style="display:none"' : ""}>
        ${txt(`set-px-user-${i}`, "Username (user@realm, e.g. root@pam)", inst.username)}
        ${secField(`set-px-pass-${i}`, "Password", pxPassFlags[i])}</div>
      <button class="btn" id="btn-test-px-${i}">Test</button><span class="test-result" id="tr-px-${i}"></span>
    </div>`;
  };
  const pxSlots = [0, 1, 2, 3, 4].map(pxSlot).join("");

  $("settings-body").innerHTML = `
    <h2>Settings</h2>
    ${s.restart_pending ? `<div class="restart-banner"><span>A change needs a restart to apply.</span><button class="btn" id="btn-restart">Restart now</button></div>` : ""}
    ${s.secret_decrypt_failures ? `<div class="restart-banner warn"><span>⚠ ${s.secret_decrypt_failures} stored secret(s) could not be decrypted — usually a backup restored onto a server with a different <code>secret.key</code>. Re-enter the affected credentials, or restore <code>secret.key</code> from the original server.</span></div>` : ""}

    <div class="settings-section"><h3>Server</h3>
      ${txt("set-listen", "Listen address (host:port)", e.api_listen_addr)}
      ${chk("set-tls", "Serve over HTTPS (self-signed)", e.tls_enabled)}
      <p class="muted-note">Changing the bind/port needs a restart.</p>
    </div>

    <div class="settings-section"><h3>UniFi controller ${statusBadge("unifi")}</h3>
      ${chk("set-unifi-en", "Enabled", e.unifi_enabled)}
      ${txt("set-unifi-url", "Base URL (e.g. https://192.168.1.1)", e.unifi_base_url)}
      <p class="muted-note">UniFi OS console (UDM/UDR/Cloud Key): keep path prefix <code>/proxy/network</code>. Software controller on :8443: blank prefix. Use a <b>local</b> admin account, not a UI.com cloud login (MFA breaks it).</p>
      ${txt("set-unifi-prefix", "Path prefix", e.unifi_path_prefix)}
      ${txt("set-unifi-site", "Site", e.unifi_site)}
      ${chk("set-unifi-verify", "Verify TLS", e.unifi_verify_tls)}
      ${secField("set-unifi-user", "Username", flags.unifi_username_set)}
      ${secField("set-unifi-pass", "Password", flags.unifi_password_set)}
      ${secField("set-unifi-key", "API key (alternative to user/pass)", flags.unifi_api_key_set)}
      <button class="btn" id="btn-test-unifi">Test connection</button><span class="test-result" id="tr-unifi"></span>
    </div>

    <div class="settings-section"><h3>Proxmox VE</h3>
      ${chk("set-px-en", "Enabled", e.proxmox_enabled)}
      <p class="muted-note">Pulls VM/CT inventory so guests get named + classified from the hypervisor. Up to 5 clusters/nodes, each with its own auth. Read-only either way — an API token (Datacenter → API Tokens, grant <code>PVEAuditor</code> on <code>/</code>) or a username+password (<code>user@realm</code>, e.g. <code>root@pam</code>).</p>
      ${pxSlots}
      <button class="ghost" id="btn-px-add">+ Add Proxmox instance</button>
    </div>

    <div class="settings-section"><h3>SNMP</h3>
      ${txt("set-snmp-comms", "Community strings (comma-separated, tried in order)", (e.snmp_communities || []).join(", "))}
      <div class="field"><label>Test against device IP</label><input type="text" id="set-snmp-ip" placeholder="10.0.0.1"></div>
      <button class="btn" id="btn-test-snmp">Test SNMP</button><span class="test-result" id="tr-snmp"></span>
      <p class="muted-note">Visible by design — SNMP community strings are low-sensitivity. The active prober tries each in order; the first a device answers wins. A legacy <code>TESSERA_SNMP_COMMUNITY</code> env value still works and is merged in.</p>
    </div>

    <div class="settings-section"><h3>Fingerbank ${statusBadge("fingerbank")}</h3>
      ${chk("set-fb-en", "Enabled (sends DHCP fingerprints to a third party)", e.fingerbank_enabled)}
      <div class="field"><label>Mode</label><select id="set-fb-mode">
        <option value="api" ${e.fingerbank_mode === "api" ? "selected" : ""}>api</option>
        <option value="local_db" ${e.fingerbank_mode === "local_db" ? "selected" : ""}>local_db</option>
        <option value="off" ${e.fingerbank_mode === "off" ? "selected" : ""}>off</option></select></div>
      ${secField("set-fb-key", "API key", flags.fingerbank_key_set)}
      <button class="btn" id="btn-test-fb">Test API key</button><span class="test-result" id="tr-fb"></span>
    </div>

    <div class="settings-section"><h3>Alerts</h3>
      ${chk("set-al-en", "Enabled — notify on network changes", e.alerts_enabled)}
      <div class="field"><label>Destination</label><select id="set-al-kind">
        ${["webhook", "slack", "discord", "ntfy"].map((k) => `<option value="${k}" ${e.alerts_kind === k ? "selected" : ""}>${k}</option>`).join("")}
      </select></div>
      ${secField("set-al-url", "Webhook / ntfy URL", flags.alert_url_set)}
      <p class="muted-note">Slack/Discord: paste the channel's incoming-webhook URL. ntfy: the topic URL (e.g. https://ntfy.sh/my-topic). webhook: any endpoint that accepts a JSON POST.</p>
      <div class="tech-grid">
        ${chk("set-al-new", "New device", e.alert_new_device)}
        ${chk("set-al-off", "Device offline", e.alert_offline)}
        ${chk("set-al-on", "Device back online", e.alert_online)}
        ${chk("set-al-ip", "IP changed", e.alert_ip_changed)}
        ${chk("set-al-cf", "New conflict", e.alert_conflict)}
        ${chk("set-al-risk", "Risky service appeared", e.alert_risky_service)}
      </div>
      <button class="btn" id="btn-test-alert">Send test alert</button><span class="test-result" id="tr-alert"></span>
      <p class="muted-note">Changes apply after a restart. The first run after enabling learns the current devices silently (no flood).</p>
    </div>

    <div class="settings-section"><h3>Active prober</h3>
      ${chk("set-ap-en", "Enabled", e.active_probe_enabled)}
      ${txt("set-ap-subnets", "Subnets (comma-separated CIDRs)", (e.active_probe_subnets || []).join(", "))}
      ${txt("set-ap-ports", "TCP ports to scan (comma-separated)", (e.active_probe_tcp_ports || []).join(", "))}
      ${txt("set-ap-uports", "UDP ports to scan (comma-separated)", (e.active_probe_udp_ports || []).join(", "))}
      <p class="muted-note">Only the ports you list here are probed. Leave UDP blank to skip UDP scanning. Common UDP services: 53 (DNS), 123 (NTP), 161 (SNMP), 500 (IKE), 1900 (SSDP), 5353 (mDNS).</p>
      ${txt("set-ap-iface", "Egress interface (blank = default route)", e.active_probe_interface)}
    </div>

    <div class="settings-section"><h3>DHCP lease ingestion</h3>
      ${chk("set-dhcp-en", "Read DHCP server lease files", e.dhcp_enabled)}
      ${txt("set-dhcp-files", "Lease file paths (comma-separated)", (e.dhcp_lease_files || []).join(", "))}
      <p class="muted-note">dnsmasq-family lease files (dnsmasq, Pi-hole, OpenWrt) readable on this host — e.g. <code>/var/lib/misc/dnsmasq.leases</code> or <code>/etc/pihole/dhcp.leases</code>. Leases sharpen IP↔MAC↔hostname and mark addresses reserved vs dynamic. UniFi reservations are ingested automatically by the UniFi poller. Applies after a restart.</p>
    </div>

    <div class="settings-section"><h3>DNS records ${statusBadge("dns")}</h3>
      ${chk("set-dns-en", "Ingest authoritative name↔IP records", e.dns_enabled)}
      <p class="muted-note">Names devices from your local DNS. Two source kinds — files and/or one DNS-server API. DNS names help name devices; if they disagree with UniFi/rDNS, add a "prefer dns for hostname" rule in Conflicts.</p>
      ${txt("set-dns-files", "Local DNS file paths (comma-separated)", (e.dns_hosts_files || []).join(", "))}
      <p class="muted-note">Hosts-format or Unbound files readable on this host — Pi-hole <code>/etc/pihole/custom.list</code>, dnsmasq addn-hosts, Unbound <code>local-data</code> configs, <code>/etc/hosts</code>. Covers dnsmasq, Unbound, and Pi-hole with no API.</p>
      <div class="field"><label>DNS server API (optional)</label><select id="set-dns-type">
        <option value="" ${!e.dns_server_type ? "selected" : ""}>— none (files only) —</option>
        <option value="adguard" ${e.dns_server_type === "adguard" ? "selected" : ""}>AdGuard Home</option>
        <option value="pihole" ${e.dns_server_type === "pihole" ? "selected" : ""}>Pi-hole (v6)</option>
        <option value="technitium" ${e.dns_server_type === "technitium" ? "selected" : ""}>Technitium</option></select></div>
      ${txt("set-dns-url", "Server URL", e.dns_server_url)}
      ${txt("set-dns-user", "AdGuard user (AdGuard only)", e.dns_server_user)}
      ${secField("set-dns-token", "Password / API token", flags.dns_server_token_set)}
      <p class="muted-note">AdGuard: base URL + admin user/password (pulls DNS rewrites). Pi-hole v6: URL + app password (Settings → Web interface / API → app password). Technitium: URL (e.g. <code>http://dns.lan:5380</code>) + API token (pulls zone A/AAAA records).</p>
      <button class="btn" id="btn-test-dns">Test server</button><span class="test-result" id="tr-dns"></span>
    </div>

    <div class="settings-section"><h3>Discovery &amp; scanning techniques</h3>
      <p class="muted-note">Every technique is on by default — uncheck any you don't want. Passive techniques run only when the sensor is enabled; active techniques only when the active prober is. All scanning is read-only toward the network.</p>
      <h4 class="sub">Passive (capture)</h4>
      <div class="tech-grid">
        ${chk("disc-p-arp", "ARP / NDP <span class='th'>L2 bindings</span>", e.disc_passive_arp)}
        ${chk("disc-p-dhcp", "DHCP <span class='th'>hostnames, fingerprints</span>", e.disc_passive_dhcp)}
        ${chk("disc-p-mdns", "mDNS / Bonjour <span class='th'>names, services</span>", e.disc_passive_mdns)}
        ${chk("disc-p-ssdp", "SSDP / UPnP <span class='th'>device class, OS</span>", e.disc_passive_ssdp)}
        ${chk("disc-p-nb", "NetBIOS <span class='th'>Windows names</span>", e.disc_passive_netbios)}
      </div>
      <h4 class="sub">Active (prober)</h4>
      <div class="tech-grid">
        ${chk("disc-a-icmp", "ICMP echo <span class='th'>liveness</span>", e.disc_active_icmp)}
        ${chk("disc-a-tcp", "TCP connect scan <span class='th'>listed TCP ports</span>", e.disc_active_tcp)}
        ${chk("disc-a-udp", "UDP service scan <span class='th'>listed UDP ports</span>", e.disc_active_udp)}
        ${chk("disc-a-ban", "Service banners <span class='th'>on open ports</span>", e.disc_active_banners)}
        ${chk("disc-a-rdns", "Reverse DNS <span class='th'>PTR names</span>", e.disc_active_reverse_dns)}
        ${chk("disc-a-arp", "ARP-table harvest <span class='th'>MAC↔IP</span>", e.disc_active_arp_table)}
        ${chk("disc-a-snmp", "SNMP <span class='th'>sysName/sysDescr</span>", e.disc_active_snmp)}
        ${chk("disc-a-mdns", "mDNS query <span class='th'>Fire TV · Apple TV · Cast · Ring — service types + model</span>", e.disc_active_mdns)}
        ${chk("disc-a-media", "Media probes <span class='th'>AirPlay :49152 · Cast :8008 — exact model · needs mDNS query on</span>", e.disc_active_media)}
        ${chk("disc-a-tcpbeh", "TCP behavioral scan <span class='th'>OS / firewall fingerprint</span>", e.disc_tcp_behavioral)}
        ${chk("disc-a-wake", "Thorough Wake <span class='th'>extra pass for sleepy devices · slower</span>", e.disc_thorough_wake)}
      </div>
    </div>

    <div class="settings-section"><h3>Maintenance</h3>
      ${chk("set-prune-en", "Auto-forget dormant devices", e.forget_dormant_enabled)}
      <div class="field"><label>Forget after (days not seen on the network)</label><input type="number" id="set-prune-days" min="1" value="${e.forget_dormant_days || 30}" style="width:100px"></div>
      <p class="muted-note">When enabled, a device not seen for this many days is automatically forgotten — its history and annotations are deleted, and it returns as a new device only if it reappears. Off by default; applies after a restart. Manual “Forget” is always available per device (card + detail page). Devices that were only ever entered by hand are never auto-pruned.</p>
    </div>

    <div class="settings-section"><h3>Backup &amp; restore</h3>
      <p class="muted-note">A backup is a full snapshot of the database — inventory, settings, users, and history. Secrets stay encrypted with this server's key, so restore to the same server (or copy <code>secret.key</code> from the data dir too).</p>
      <div class="field row">
        <a class="btn" href="/api/backup" download>⤓ Download backup</a>
      </div>
      <div class="field row" style="margin-top:10px">
        <input type="file" id="restore-file" accept=".db,.sqlite,application/octet-stream" style="flex:1">
        <button class="btn danger" id="btn-restore">Restore…</button>
      </div>
      <p class="muted-note">Restoring replaces ALL current data and restarts the server. The replaced database is kept as <code>&lt;db&gt;.prev</code> for one generation.</p>
    </div>

    <div class="settings-section"><h3>API tokens</h3>
      <p class="muted-note">Named tokens for API consumers (dashboards, CableMap, the runbook generator, scripts). Send as <code>Authorization: Bearer &lt;token&gt;</code> or <code>X-API-Token</code>. Viewer = read-only (recommended). Pin the stable <code>/api/v1</code> base for integrations; the contract is at <a href="/api/openapi.json" target="_blank">/api/openapi.json</a>. Poll <code>/api/v1/events?since=&lt;cursor&gt;</code> to sync just what changed.</p>
      <div id="token-new"></div>
      <div id="token-list">${(tokens || []).map(tokenRow).join("") || `<p class="muted-note">No tokens yet.</p>`}</div>
      <div class="field row" style="margin-top:10px">
        <input type="text" id="tok-name" placeholder="token name (e.g. cablemap)" style="flex:1">
        <select id="tok-role"><option value="viewer">viewer (read-only — reporting)</option><option value="operator">operator (curate inventory)</option><option value="admin">admin</option></select>
        <button class="btn" id="btn-add-token">Create token</button>
      </div>
    </div>

    <div class="settings-section"><h3>Audit log</h3>
      ${audit.length ? `<table class="obs"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr></thead>
        <tbody>${audit.map((a) => `<tr><td>${fmtTime(a.at)}</td><td>${esc(a.username)}</td><td class="mono">${esc(a.action)}</td><td>${esc(a.detail || "")}</td></tr>`).join("")}</tbody></table>`
        : `<p class="muted-note">No audit entries yet. Settings changes, user management, and restores are recorded here.</p>`}
    </div>

    <div class="settings-section"><h3>Users</h3>
      <p class="muted-note"><b>admin</b> — everything, including this Settings page (which holds your UniFi/Proxmox/DNS credentials), users, API tokens, backup &amp; restore. <b>operator</b> — curates the inventory (rename, tag, merge, resolve conflicts, suppress findings, rescan, forget a device) but never sees Settings or credentials. <b>viewer</b> — read-only, for dashboards and reporting tokens. Bulk Forget is admin-only.</p>
      <div id="user-list">${users.map(userRow).join("")}</div>
      <div class="field row" style="margin-top:10px">
        <input type="text" id="nu-name" placeholder="username" style="flex:1">
        <input type="password" id="nu-pass" placeholder="password (8+)" style="flex:1">
        <select id="nu-role"><option value="viewer">viewer (read-only)</option><option value="operator">operator (no settings/credentials)</option><option value="admin">admin</option></select>
        <button class="btn" id="btn-add-user">Add</button>
      </div>
    </div>

    <div class="settings-section"><h3>Device icons</h3>
      <p class="muted-note">${allIcons.length} icons available (${customIcons.length} custom). Icons auto-assign by vendor/OS/type; override per device on its detail page.</p>
      <div class="icon-grid">${allIcons.map((i) => `<div class="icon-cell" title="${esc(i.id)} (${i.source})"><span class="ic" style="${iconStyle(i.url, "var(--text)")}"></span>${i.source === "custom" ? `<button class="icon-del" data-icon="${esc(i.id)}">×</button>` : ""}<span class="lbl">${esc(i.id)}</span></div>`).join("")}</div>
      <div class="field row" style="margin-top:10px">
        <input type="text" id="ic-id" placeholder="icon id (e.g. plex)" style="width:160px">
        <input type="text" id="ic-svg" placeholder="paste SVG markup" style="flex:1">
        <button class="btn" id="btn-add-icon">Add icon</button>
      </div>
      <p class="muted-note">SVGs using <code>currentColor</code> match the theme. Sources: simpleicons.org (CC0), tabler.io (MIT).</p>
    </div>

    <div class="settings-section"><h3>Change my password</h3>
      ${secFieldless("pw-cur", "Current password")}${secFieldless("pw-new", "New password (8+)")}
      <button class="btn" id="btn-change-pw">Update password</button><span class="test-result" id="tr-pw"></span>
    </div>

    <button class="primary" id="btn-save-settings">Save settings</button>`;

  wireSettings(canSec);
}

function secFieldless(id, label) {
  return `<div class="field"><label>${label}</label><input type="password" id="${id}"></div>`;
}
function userRow(u) {
  return `<div class="user-row" data-id="${u.id}">
    <span class="grow"><b>${esc(u.username)}</b> <span class="role">${esc(u.role)}</span></span>
    <button class="btn" data-act="pw">Reset pw</button>
    <button class="btn danger" data-act="del">Delete</button></div>`;
}

function tokenRow(t) {
  const used = t.last_used_at && !String(t.last_used_at).startsWith("0001") ? "last used " + fmtTime(t.last_used_at) : "never used";
  return `<div class="token-row" data-id="${t.id}">
    <span class="grow"><b>${esc(t.name)}</b> <span class="role">${esc(t.role)}</span> <span class="muted-note">· ${esc(used)}</span></span>
    <button class="btn danger tok-revoke" data-id="${t.id}">Revoke</button></div>`;
}

function wireTokenRows() {
  for (const b of document.querySelectorAll(".tok-revoke")) {
    b.onclick = async () => {
      if (!confirm("Revoke this token? Anything using it stops working immediately.")) return;
      try { await api("DELETE", "/api/tokens/" + b.dataset.id); b.closest(".token-row").remove(); toast("Revoked"); }
      catch (e) { toast(e.message); }
    };
  }
}

function val(id) { return $(id).value.trim(); }
function checked(id) { return $(id).checked; }
function secInput(id) { const v = $(id).value; return v ? v : undefined; }

function wireSettings(canSec) {
  if ($("btn-restart")) $("btn-restart").onclick = async () => { await post("/api/restart"); toast("Restarting…"); setTimeout(() => location.reload(), 4000); };

  if ($("btn-restore")) $("btn-restore").onclick = async () => {
    const f = $("restore-file").files[0];
    if (!f) { toast("Choose a backup file first"); return; }
    if (!confirm("Restore the database from this file?\n\nThis REPLACES all current data and restarts the server. The current database is kept as <db>.prev for one generation.")) return;
    try {
      const res = await fetch("/api/restore", { method: "POST", body: f, credentials: "same-origin" });
      if (!res.ok) { let m = res.statusText; try { m = (await res.json()).error || m; } catch {} throw new Error(m); }
      toast("Restore staged — server restarting…");
      setTimeout(() => location.reload(), 5000);
    } catch (e) { toast(e.message); }
  };

  $("btn-test-unifi").onclick = () => runTest("/api/test/unifi", "tr-unifi", {
    base_url: val("set-unifi-url"), path_prefix: val("set-unifi-prefix"), site: val("set-unifi-site"),
    verify_tls: checked("set-unifi-verify"), username: $("set-unifi-user").value, password: $("set-unifi-pass").value, api_key: $("set-unifi-key").value,
  });
  for (let i = 0; i < 5; i++) {
    const tb = $(`btn-test-px-${i}`);
    if (tb) tb.onclick = () => runTest("/api/test/proxmox", `tr-px-${i}`, {
      index: i, base_url: val(`set-px-url-${i}`), verify_tls: checked(`set-px-verify-${i}`),
      auth_mode: val(`set-px-auth-${i}`), username: val(`set-px-user-${i}`),
      token: $(`set-px-token-${i}`).value, password: $(`set-px-pass-${i}`).value,
    });
    const as = $(`set-px-auth-${i}`);
    if (as) as.onchange = () => {
      const pw = as.value === "password";
      const tok = document.querySelector(`.px-tok-${i}`), pass = document.querySelector(`.px-pass-${i}`);
      if (tok) tok.style.display = pw ? "none" : "";
      if (pass) pass.style.display = pw ? "" : "none";
    };
  }
  if ($("btn-px-add")) $("btn-px-add").onclick = () => {
    for (const slot of document.querySelectorAll(".px-inst")) {
      if (slot.style.display === "none") { slot.style.display = ""; return; }
    }
    toast("Up to 5 Proxmox instances");
  };
  if ($("btn-test-dns")) $("btn-test-dns").onclick = () => runTest("/api/test/dns", "tr-dns", {
    type: val("set-dns-type"), url: val("set-dns-url"), user: val("set-dns-user"), token: $("set-dns-token").value,
  });
  $("btn-test-snmp").onclick = () => runTest("/api/test/snmp", "tr-snmp", { ip: val("set-snmp-ip"), community: splitList(val("set-snmp-comms"))[0] || "" });
  $("btn-test-fb").onclick = () => runTest("/api/test/fingerbank", "tr-fb", { key: $("set-fb-key").value });
  $("btn-test-alert").onclick = () => runTest("/api/test/alert", "tr-alert", { kind: $("set-al-kind").value, url: $("set-al-url").value });

  $("btn-add-user").onclick = async () => {
    try { await post("/api/users", { username: val("nu-name"), password: $("nu-pass").value, role: $("nu-role").value }); toast("User added"); openSettings(); }
    catch (e) { toast(e.message); }
  };
  for (const row of document.querySelectorAll(".user-row")) {
    const id = row.dataset.id;
    row.querySelector('[data-act=del]').onclick = async () => {
      if (!confirm("Delete this user?")) return;
      try { await api("DELETE", "/api/users/" + id); openSettings(); } catch (e) { toast(e.message); }
    };
    row.querySelector('[data-act=pw]').onclick = async () => {
      const pw = prompt("New password (8+ chars):"); if (!pw) return;
      const name = row.querySelector("b").textContent, role = row.querySelector(".role").textContent;
      try { await api("PUT", "/api/users/" + id, { username: name, role, password: pw }); toast("Password reset"); } catch (e) { toast(e.message); }
    };
  }

  if ($("btn-add-token")) $("btn-add-token").onclick = async () => {
    const name = val("tok-name");
    if (!name) { toast("Name the token first"); return; }
    try {
      const r = await post("/api/tokens", { name, role: $("tok-role").value });
      $("token-new").innerHTML = `<div class="restart-banner warn"><span>New token <b>${esc(r.name)}</b> — copy it now, it won't be shown again:</span>
        <code class="tok-secret">${esc(r.token)}</code><button class="btn" id="tok-copy">Copy</button></div>`;
      $("tok-copy").onclick = () => { navigator.clipboard?.writeText(r.token); toast("Copied"); };
      const list = $("token-list");
      // re-fetch the list without wiping the just-shown secret
      const toks = await getJSON("/api/tokens").catch(() => []);
      list.innerHTML = (toks || []).map(tokenRow).join("") || `<p class="muted-note">No tokens yet.</p>`;
      wireTokenRows();
      $("tok-name").value = "";
    } catch (e) { toast(e.message); }
  };
  wireTokenRows();

  $("btn-add-icon").onclick = async () => {
    try { await post("/api/icons", { id: val("ic-id"), svg: $("ic-svg").value }); toast("Icon added"); openSettings(); }
    catch (e) { toast(e.message); }
  };
  for (const b of document.querySelectorAll(".icon-del")) {
    b.onclick = async () => { try { await api("DELETE", "/api/icons/" + b.dataset.icon); openSettings(); } catch (e) { toast(e.message); } };
  }

  $("btn-change-pw").onclick = async () => {
    try { await post("/api/me/password", { current: $("pw-cur").value, new: $("pw-new").value }); setText("tr-pw", "updated", true); }
    catch (e) { setText("tr-pw", e.message, false); }
  };

  $("btn-save-settings").onclick = async () => {
    const editable = {
      api_listen_addr: val("set-listen"), tls_enabled: checked("set-tls"),
      unifi_enabled: checked("set-unifi-en"), unifi_base_url: val("set-unifi-url"), unifi_path_prefix: val("set-unifi-prefix"),
      unifi_site: val("set-unifi-site"), unifi_verify_tls: checked("set-unifi-verify"),
      proxmox_enabled: checked("set-px-en"),
      // Positional: per-instance secrets are stored by SLOT index, and app.go
      // reads Secrets[i] by instance index — so instance[i] MUST stay aligned to
      // slot i. Never compact interior gaps (that would shift a later instance
      // onto an earlier instance's stored token). Trim only trailing empties.
      proxmox_instances: (() => {
        const a = [0, 1, 2, 3, 4].map((i) => ({
          name: val(`set-px-name-${i}`), base_url: val(`set-px-url-${i}`), verify_tls: checked(`set-px-verify-${i}`),
          auth_mode: val(`set-px-auth-${i}`) || "token", username: val(`set-px-user-${i}`),
        }));
        let n = a.length;
        while (n > 0 && !a[n - 1].base_url) n--;
        return a.slice(0, n);
      })(),
      fingerbank_enabled: checked("set-fb-en"), fingerbank_mode: $("set-fb-mode").value,
      active_probe_enabled: checked("set-ap-en"),
      active_probe_subnets: splitList(val("set-ap-subnets")),
      active_probe_tcp_ports: splitList(val("set-ap-ports")).map(Number).filter((n) => n > 0),
      active_probe_udp_ports: splitList(val("set-ap-uports")).map(Number).filter((n) => n > 0),
      active_probe_icmp: checked("disc-a-icmp"), active_probe_interface: val("set-ap-iface"),
      snmp_communities: splitList(val("set-snmp-comms")),
      disc_passive_arp: checked("disc-p-arp"), disc_passive_dhcp: checked("disc-p-dhcp"),
      disc_passive_mdns: checked("disc-p-mdns"), disc_passive_ssdp: checked("disc-p-ssdp"),
      disc_passive_netbios: checked("disc-p-nb"),
      disc_active_icmp: checked("disc-a-icmp"), disc_active_tcp: checked("disc-a-tcp"),
      disc_active_udp: checked("disc-a-udp"),
      disc_active_banners: checked("disc-a-ban"), disc_active_reverse_dns: checked("disc-a-rdns"),
      disc_active_arp_table: checked("disc-a-arp"), disc_active_snmp: checked("disc-a-snmp"),
      disc_active_mdns: checked("disc-a-mdns"), disc_active_media: checked("disc-a-media"),
      disc_tcp_behavioral: checked("disc-a-tcpbeh"), disc_thorough_wake: checked("disc-a-wake"),
      alerts_enabled: checked("set-al-en"), alerts_kind: $("set-al-kind").value,
      alert_new_device: checked("set-al-new"), alert_offline: checked("set-al-off"),
      alert_online: checked("set-al-on"), alert_ip_changed: checked("set-al-ip"), alert_conflict: checked("set-al-cf"),
      alert_risky_service: checked("set-al-risk"),
      forget_dormant_enabled: checked("set-prune-en"), forget_dormant_days: +val("set-prune-days") || 30,
      dhcp_enabled: checked("set-dhcp-en"), dhcp_lease_files: splitList(val("set-dhcp-files")),
      dns_enabled: checked("set-dns-en"), dns_hosts_files: splitList(val("set-dns-files")),
      dns_server_type: val("set-dns-type"), dns_server_url: val("set-dns-url"), dns_server_user: val("set-dns-user"),
    };
    const secrets = {};
    if (canSec) {
      const add = (k, id) => { const v = secInput(id); if (v !== undefined) secrets[k] = v; };
      add("unifi_username", "set-unifi-user"); add("unifi_password", "set-unifi-pass"); add("unifi_api_key", "set-unifi-key");
      const pxTokens = [], pxPasswords = [];
      let anyTok = false, anyPass = false;
      for (let i = 0; i < 5; i++) {
        const t = secInput(`set-px-token-${i}`); pxTokens[i] = t === undefined ? null : t; if (t !== undefined) anyTok = true;
        const p = secInput(`set-px-pass-${i}`); pxPasswords[i] = p === undefined ? null : p; if (p !== undefined) anyPass = true;
      }
      if (anyTok) secrets.proxmox_tokens = pxTokens;
      if (anyPass) secrets.proxmox_passwords = pxPasswords;
      add("dns_server_token", "set-dns-token");
      add("fingerbank_key", "set-fb-key"); add("alert_url", "set-al-url");
    }
    try { await api("PUT", "/api/settings", { editable, secrets }); toast("Saved — restart to apply"); openSettings(); }
    catch (e) { toast(e.message); }
  };
}

async function runTest(path, resultId, body) {
  setText(resultId, "testing…", null);
  try { const r = await post(path, body); setText(resultId, r.ok ? r.detail : r.error, r.ok); }
  catch (e) { setText(resultId, e.message, false); }
}
function setText(id, text, ok) {
  const el = $(id); el.textContent = text;
  el.className = "test-result" + (ok === true ? " ok" : ok === false ? " err" : "");
}
const splitList = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);

// ── panels / chrome ──────────────────────────────────────────────────────────

function openPanel(id) { $(id).classList.remove("hidden"); $("overlay").classList.remove("hidden"); }
function closePanels() { $("detail").classList.add("hidden"); $("overlay").classList.add("hidden"); }
function toast(msg) { const t = document.createElement("div"); t.className = "toast"; t.textContent = msg; document.body.appendChild(t); setTimeout(() => t.remove(), 2200); }

$("detail-close").onclick = closePanels;
$("overlay").onclick = closePanels;

// ── full-page views (router) ─────────────────────────────────────────────────
const VIEWS = ["dashboard", "activity", "topology", "ports", "observations", "security", "system", "settings"];
function showView(name) {
  if (!VIEWS.includes(name)) name = "dashboard";
  closePanels();
  for (const v of VIEWS) $("view-" + v).classList.toggle("hidden", v !== name);
  for (const a of document.querySelectorAll("#userbar .nav-link")) a.classList.toggle("active", a.dataset.view === name);
  if (location.hash !== "#" + name) location.hash = name;
  window.scrollTo(0, 0);
  if (name === "topology") renderTopology();
  else if (name === "settings") openSettings();
  else if (name === "observations") renderObservations(true);
  else if (name === "security") renderSecurity();
  else if (name === "ports") renderPortmap();
  else if (name === "activity") renderActivity();
  else if (name === "system") renderSystem();
}

// ── global search palette (Cmd/Ctrl-K, or "/") ───────────────────────────────
let paletteSubnets = null, paletteServices = null, paletteMatches = [], paletteSel = 0;

async function openPalette() {
  if (typeof me === "undefined" || !me) return;
  // Show immediately — hosts are searchable at once from the live hostsData cache.
  $("palette").classList.remove("hidden");
  const inp = $("palette-input");
  inp.value = ""; paletteMatches = []; paletteSel = 0;
  renderPaletteResults("");
  inp.focus();
  // Fill in subnets + services in the background, then re-render with the query.
  if (paletteSubnets === null) {
    paletteSubnets = await getJSON("/api/subnets").catch(() => []);
    paletteServices = await getJSON("/api/services").catch(() => []);
    if (!$("palette").classList.contains("hidden")) renderPaletteResults(inp.value);
  }
}
function closePalette() { $("palette").classList.add("hidden"); }

function paletteSearch(q) {
  q = q.trim().toLowerCase();
  const terms = q ? q.split(/\s+/) : [];
  const hit = (hay) => terms.every((t) => hay.includes(t));
  const out = [];
  // Hosts (from the already-loaded inventory).
  for (const h of hostsData) {
    const hay = [h.display_name, h.vendor, h.model, h.device_class, h.os_guess,
      (h.ips || []).join(" "), (h.macs || []).join(" "), (h.tags || []).join(" ")].join(" ").toLowerCase();
    if (hit(hay)) out.push({ kind: "device", icon: "🖥", title: h.display_name || (h.ips || [])[0] || (h.macs || [])[0] || h.stable_id,
      sub: [(h.ips || [])[0], h.model || h.device_class].filter(Boolean).join(" · "), act: () => openHost(h.stable_id) });
  }
  for (const s of (paletteSubnets || [])) {
    const hay = [s.cidr, s.name, s.gateway].join(" ").toLowerCase();
    if (hit(hay)) out.push({ kind: "subnet", icon: "🧮", title: s.cidr, sub: s.name || s.source || "", act: () => { showView("dashboard"); openSubnet(s.id); } });
  }
  for (const sv of (paletteServices || [])) {
    const hay = [sv.service, sv.proto, String(sv.port), sv.host].join(" ").toLowerCase();
    if (hit(hay) && sv.stable_id) out.push({ kind: "service", icon: "🔌", title: `${sv.proto}/${sv.port}${sv.service ? " " + sv.service : ""}`,
      sub: [sv.host, sv.banner].filter(Boolean).join(" · "), act: () => openHost(sv.stable_id) });
  }
  return out.slice(0, 40);
}

function renderPaletteResults(q) {
  paletteMatches = paletteSearch(q);
  if (paletteSel >= paletteMatches.length) paletteSel = Math.max(0, paletteMatches.length - 1);
  const box = $("palette-results");
  if (!paletteMatches.length) {
    box.innerHTML = q.trim() ? `<div class="pal-empty">No matches.</div>` : `<div class="pal-empty">Search across devices, subnets, and services. ↑↓ to move, Enter to open.</div>`;
    return;
  }
  box.innerHTML = paletteMatches.map((m, i) => `<div class="pal-row ${i === paletteSel ? "sel" : ""}" data-i="${i}">
    <span class="pal-ico">${m.icon}</span><span class="pal-title">${esc(m.title)}</span>
    <span class="pal-kind">${m.kind}</span>${m.sub ? `<span class="pal-sub">${esc(m.sub)}</span>` : ""}</div>`).join("");
  for (const r of box.querySelectorAll(".pal-row")) r.onclick = () => choosePalette(Number(r.dataset.i));
}
function choosePalette(i) {
  const m = paletteMatches[i];
  if (!m) return;
  closePalette();
  m.act();
}
function movePaletteSel(d) {
  if (!paletteMatches.length) return;
  paletteSel = (paletteSel + d + paletteMatches.length) % paletteMatches.length;
  const box = $("palette-results");
  box.querySelectorAll(".pal-row").forEach((r, i) => r.classList.toggle("sel", i === paletteSel));
  const sel = box.querySelector(".pal-row.sel");
  if (sel) sel.scrollIntoView({ block: "nearest" });
}

document.addEventListener("keydown", (e) => {
  const paletteOpen = !$("palette").classList.contains("hidden");
  const typing = /^(input|textarea|select)$/i.test((e.target.tagName || "")) || e.target.isContentEditable;
  if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) { e.preventDefault(); paletteOpen ? closePalette() : openPalette(); return; }
  if (e.key === "/" && !typing && !paletteOpen) { e.preventDefault(); openPalette(); return; }
  if (!paletteOpen) return;
  if (e.key === "Escape") { e.preventDefault(); closePalette(); }
  else if (e.key === "ArrowDown") { e.preventDefault(); movePaletteSel(1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); movePaletteSel(-1); }
  else if (e.key === "Enter") { e.preventDefault(); choosePalette(paletteSel); }
});

async function init() {
  try { me = await fetch("/api/me").then((r) => (r.ok ? r.json() : Promise.reject())); }
  catch { showLogin(); return; }
  hideLogin(); renderUserbar(); setupSortHeaders(); setupObservations(); renderFooter();
  $("palette-input").oninput = (e) => { paletteSel = 0; renderPaletteResults(e.target.value); };
  $("palette").onclick = (e) => { if (e.target.id === "palette") closePalette(); };
  await refresh().catch((e) => $("summary").textContent = "error: " + e.message);
  // Restore the view from the URL hash (deep-link / back-button), default dashboard.
  showView((location.hash || "").replace("#", "") || "dashboard");
  window.onhashchange = () => showView((location.hash || "").replace("#", "") || "dashboard");
}
async function renderFooter() {
  try {
    const v = await getJSON("/api/version");
    $("footer").textContent = `Tessera v${v.version}` + (v.build && v.build !== "dev" ? ` · build ${v.build}` : "");
  } catch { /* footer is best-effort */ }
}
init();
setInterval(() => { if (me && $("login").classList.contains("hidden")) refresh().catch(() => {}); }, 15000);
