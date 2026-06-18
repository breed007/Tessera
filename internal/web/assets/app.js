"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
let me = null;

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
  const settings = me.is_admin ? link("settings", "Settings") : "";
  $("userbar").innerHTML =
    `<nav class="nav">${link("dashboard", "Dashboard")}${link("topology", "Topology")}${link("observations", "Observations")}${link("security", "Security")}${settings}</nav>` +
    `<b>${esc(me.username)}</b><span class="role">${esc(me.role)}</span><a id="nav-logout">Logout</a>`;
  for (const a of document.querySelectorAll("#userbar .nav-link")) a.onclick = () => showView(a.dataset.view);
  $("nav-logout").onclick = async () => { await post("/api/logout"); location.reload(); };
}

// ── inventory (unchanged behavior, admin-gated annotation) ───────────────────

async function refresh() {
  const [summary, hosts] = await Promise.all([
    getJSON("/api/summary"), getJSON("/api/hosts"),
  ]);
  renderSummary(summary); renderHosts(hosts); renderDevices(hosts, summary.open_conflicts);
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
  if (me.is_admin) cols.push("");
  $("detail-body").innerHTML = `<h2>Subnets <span class="badge">${rows.length}</span></h2>
    <p class="muted-note">Click a subnet to see its address map and utilization.</p>
    <table class="obs"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((s) => `<tr class="subnet-row" data-id="${s.id}">
      <td class="mono">${esc(s.cidr)}</td><td>${s.vlan_id ?? "—"}</td><td>${esc(s.name || "—")}</td>
      <td class="mono">${esc(s.gateway || "—")}</td><td>${esc(s.source)}</td>
      ${me.is_admin ? `<td><button class="ghost rescan-subnet" data-id="${s.id}" data-cidr="${esc(s.cidr)}" title="Actively probe every address in this subnet">↻ Rescan</button></td>` : ""}
    </tr>`).join("")}</tbody></table>`;
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
    `<span class="ipcell ${esc(a.state)}" data-id="${esc(a.stable_id || "")}" title="${esc(a.ip)}${a.host ? " · " + esc(a.host) : ""} (${esc(a.state)})"></span>`).join("");
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
    </div>
    <h3>Addresses</h3>${map}`;
  for (const c of $("detail-body").querySelectorAll(".ipcell[data-id]:not([data-id=''])")) {
    c.style.cursor = "pointer";
    c.onclick = () => openHost(c.dataset.id);
  }
  openPanel("detail");
}

// renderTopology renders the educated network tree (full page): gateway →
// switches → APs → clients, with the port + link speed each device connects via.
async function renderTopology() {
  const d = await getJSON("/api/topology");
  const nodeHTML = (n) => {
    const link = (n.port || n.speed)
      ? `<span class="topo-link">${n.port ? "port " + esc(n.port) : ""}${n.speed ? " · " + esc(n.speed) : ""}</span>` : "";
    const kids = (n.children || []).length ? `<div class="topo-children">${n.children.map(nodeHTML).join("")}</div>` : "";
    return `<div class="topo-node">
      <div class="topo-row" data-id="${esc(n.stable_id)}">
        <span class="dev-icon" style="${iconStyle(n.icon_url, "var(--accent)")}"></span>
        <span class="topo-name">${esc(n.name)}</span>
        ${n.sub ? `<span class="topo-sub">${esc(n.sub)}</span>` : ""}
        ${link}
      </div>${kids}</div>`;
  };
  const roots = (d.roots || []).map(nodeHTML).join("") || `<p class="muted-note">No topology yet — connect the UniFi controller (uplink + switch-port data builds the map).</p>`;
  const unplaced = (d.unplaced || []).length
    ? `<details class="topo-unplaced"><summary>Unplaced devices <span class="badge">${d.unplaced.length}</span></summary>${d.unplaced.map(nodeHTML).join("")}</details>`
    : "";
  $("topology-body").innerHTML = `<h2>Network topology</h2>
    <p class="muted-note">Built from UniFi uplinks and switch-port data. Click a device to open it.</p>
    <div class="topo">${roots}</div>${unplaced}`;
  for (const row of $("topology-body").querySelectorAll(".topo-row[data-id]:not([data-id=''])")) {
    row.style.cursor = "pointer";
    row.onclick = () => openHost(row.dataset.id);
  }
}

// renderSecurity renders the exposed-services / posture findings (full page),
// grouped by severity. Each finding links to its host.
async function renderSecurity() {
  const d = await getJSON("/api/security");
  const findings = d.findings || [];
  const counts = `<div class="sec-counts">
    <span class="sev-pill high">${d.high} high</span>
    <span class="sev-pill medium">${d.medium} medium</span>
    <span class="sev-pill low">${d.low} low</span></div>`;
  let body;
  if (!findings.length) {
    body = `<p class="muted-note">No exposed-service findings. (Findings come from the active prober's discovered open ports — set ports under Settings → Active prober and rescan.)</p>`;
  } else {
    body = findings.map((f) => `
      <div class="sec-row" data-id="${esc(f.stable_id)}">
        <span class="sev-pill ${esc(f.severity)}">${esc(f.severity)}</span>
        <div class="sec-main">
          <div><b>${esc(f.title)}</b>${f.port ? ` <span class="mono">${esc(f.proto)}/${f.port}</span>` : ""}</div>
          <div class="sec-detail">${esc(f.detail)}</div>
        </div>
        <div class="sec-host"><span class="topo-name">${esc(f.host)}</span>${f.ip ? ` <span class="mono">${esc(f.ip)}</span>` : ""}</div>
      </div>`).join("");
  }
  $("security-body").innerHTML = `<h2>Security posture <span class="badge">${findings.length}</span></h2>
    <p class="muted-note">Reachable services worth reviewing — plaintext, remote-access, exposed databases, file sharing. These are things to confirm are intentional, not confirmed vulnerabilities.</p>
    ${counts}${body}`;
  for (const row of $("security-body").querySelectorAll(".sec-row[data-id]:not([data-id=''])")) {
    row.style.cursor = "pointer";
    row.onclick = () => openHost(row.dataset.id);
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
    (h.ips || []).join(" "), (h.macs || []).join(" ")].join(" ").toLowerCase();
  return q.split(/\s+/).every((term) => hay.includes(term));
}

function renderHosts(hosts) {
  if (hosts) hostsData = hosts;
  let rows = hostQuery ? hostsData.filter((h) => hostMatches(h, hostQuery)) : hostsData;
  if (hostSort.key && sortKeyFns[hostSort.key]) {
    const f = sortKeyFns[hostSort.key], d = hostSort.dir;
    rows = [...rows].sort((a, b) => {
      const av = f(a), bv = f(b);
      return av < bv ? -d : av > bv ? d : 0;
    });
  }
  $("hosts-body").innerHTML = rows.map((h) => `
    <tr data-id="${esc(h.stable_id)}">
      <td><span class="dev-icon" style="${iconStyle(h.icon_url, "var(--accent)")}"></span>${esc(h.display_name || "(unnamed)")}</td>
      <td>${esc(h.model || h.device_class || "—")}</td>
      <td class="conf">${confBadge(h.device_class || h.os_guess ? h.confidence : 0)}</td>
      <td class="mono">${(h.ips || []).map(esc).join(", ") || "—"}</td>
      <td>${esc(h.vendor || "")}</td>
      <td>${expectedPill(h.is_expected)}</td>
      <td>${fmtTime(h.last_seen)}</td>
    </tr>`).join("");
  for (const tr of $("hosts-body").querySelectorAll("tr")) tr.onclick = () => openHost(tr.dataset.id);
  for (const th of document.querySelectorAll("#hosts thead th[data-sort]")) {
    th.setAttribute("aria-sort", th.dataset.sort === hostSort.key ? (hostSort.dir === 1 ? "ascending" : "descending") : "none");
  }
}

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

  $("device-hint").textContent = DEVICE_HINTS[deviceTab];
  const list = groups[deviceTab] || [];
  const admin = me.is_admin;
  // Per-category quick actions (move the tile to another category).
  const actions = (h) => {
    if (!admin) return "";
    const b = (act, label) => `<button class="ghost dev-act" data-act="${act}" data-id="${esc(h.stable_id)}">${label}</button>`;
    if (deviceTab === "new") return `<div class="card-actions">${b("expected", "✓ Expected")}${b("ignored", "⊘ Ignore")}</div>`;
    if (deviceTab === "expected") return `<div class="card-actions">${b("ignored", "⊘ Ignore")}${b("new", "↩ New")}</div>`;
    return `<div class="card-actions">${b("expected", "✓ Expected")}${b("new", "↩ New")}</div>`; // ignored
  };
  $("device-list").innerHTML = list.length ? list.map((h) => `
    <div class="card" data-id="${esc(h.stable_id)}">
      <div class="name"><span class="dev-icon" style="${iconStyle(h.icon_url, "var(--accent)")}"></span>${esc(h.display_name || "(unnamed)")}</div>
      <div class="meta mono">${(h.ips || []).map(esc).join(", ") || (h.macs || []).map(esc).join(", ")}</div>
      <div class="meta">${esc(h.model || h.device_class || "unclassified")} · first seen ${fmtTime(h.first_seen)}</div>
      ${actions(h)}
    </div>`).join("") : `<p class="muted-note">Nothing here.</p>`;

  for (const c of $("device-list").querySelectorAll(".card")) {
    c.onclick = (e) => { if (!e.target.closest(".dev-act")) openHost(c.dataset.id); };
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
}
// openConflicts is the dedicated conflict workflow: open disagreements (with a
// "keep this one" decision + note) and the log of resolved ones (with reopen).
async function openConflicts() {
  const data = await getJSON("/api/conflicts");
  const open = data.open || [], resolved = data.resolved || [];
  const admin = me.is_admin;

  const side = (c, which) => {
    const val = which === "a" ? c.value_a : c.value_b;
    const src = which === "a" ? c.source_a : c.source_b;
    const btn = admin
      ? `<button class="ghost keep" data-subject="${esc(c.subject)}" data-attr="${esc(c.attribute)}" data-value="${esc(val)}" data-source="${esc(src)}">Keep this</button>`
      : "";
    return `<div class="cf-side"><div><b>${esc(val)}</b> <span class="src">(${esc(src)})</span></div>${btn}</div>`;
  };

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
    ${resolvedHTML}`;

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
  }
  openPanel("detail");
}

async function openHost(id) {
  const d = await getJSON("/api/host?id=" + encodeURIComponent(id));
  const h = d.host;
  const rows = (d.observations || []).map((o) => `<tr><td>${fmtTime(o.observed_at)}</td><td class="src">${esc(o.source)}</td><td>${esc(o.attribute)}</td><td>${esc(o.value)}</td><td class="conf">${o.confidence}</td></tr>`).join("");
  const ifaces = (d.interfaces || []).map((i) => `<div class="mono">${esc(i.mac)} ${i.is_randomized ? "· randomized" : ""} ${i.oui_vendor ? "· " + esc(i.oui_vendor) : ""}</div>`).join("") || "—";
  const addrs = (d.addresses || []).map((a) => `<div class="mono">${esc(a.ip)} <span class="conf">[${esc(a.state)}]</span></div>`).join("") || "—";
  const svcs = (d.services || []).map((s) => `<div class="mono">${esc(s.proto)}/${s.port} ${s.banner ? "· " + esc(s.banner) : ""}</div>`).join("") || "—";
  const topo = (d.topology || []).map((t) => `<div class="mono">${esc(t.switch)} port ${esc(t.switch_port)}</div>`).join("") || "—";
  const changeLabel = { ip: "IP", firmware: "Firmware", model: "Model", os: "OS", device: "Device", hostname: "Hostname", service: "Service" };
  const changes = (d.changes || []).map((c) => {
    const lbl = changeLabel[c.kind] || c.kind;
    const what = c.kind === "service" ? `New service <b>${esc(c.to)}</b>`
      : `${lbl}: ${c.from ? esc(c.from) + " → " : ""}<b>${esc(c.to)}</b>`;
    return `<div class="change"><span class="change-time mono">${fmtTime(c.at)}</span> ${what}</div>`;
  }).join("");
  const iconPicker = me.is_admin ? `
    <h3>Icon</h3>
    <div class="icon-picker" id="icon-picker">
      <button class="icon-tile ${h.icon ? "" : "sel"}" data-icon="" title="Auto">A</button>
      ${(await loadIcons()).map((i) => `<button class="icon-tile ${h.icon === i.id ? "sel" : ""}" data-icon="${esc(i.id)}" title="${esc(i.id)}"><span class="ic" style="${iconStyle(i.url, "var(--text)")}"></span></button>`).join("")}
    </div>` : "";
  const annotate = me.is_admin ? `
    <h3>Annotate</h3>
    <form class="annotate" id="annotate-form">
      <label>Display name</label><input type="text" id="an-name" value="${esc(h.display_name || "")}">
      <label>Device / Hardware</label><input type="text" id="an-class" value="${esc(h.device_class || "")}">
      <label>Notes</label><input type="text" id="an-notes" value="${esc(h.notes || "")}">
      <div class="row"><input type="checkbox" id="an-expected" ${h.is_expected ? "checked" : ""}><label for="an-expected" style="margin:0">Mark as expected</label></div>
      <div class="row"><input type="checkbox" id="an-ignored" ${h.ignored ? "checked" : ""}><label for="an-ignored" style="margin:0">Ignore (suppress from review)</label></div>
      <button type="submit" class="primary">Save annotation</button>
    </form>` : "";

  const actions = me.is_admin ? `<div class="detail-actions"><button id="rescan-host" class="ghost" title="Actively probe this host's addresses now">↻ Rescan host</button></div>` : "";

  $("detail-body").innerHTML = `
    <h2><span class="dev-icon-lg" style="${iconStyle(d.icon_url, "var(--accent)")}"></span>${esc(h.display_name || "(unnamed)")}</h2>
    ${actions}
    <dl class="kv">
      <dt>Stable ID</dt><dd class="mono">${esc(h.stable_id)}</dd>
      <dt>Device / Hardware</dt><dd>${esc(h.device_class || "—")} ${h.device_class ? confBadge(h.confidence) : ""}</dd>
      ${h.model ? `<dt>Model</dt><dd>${esc(h.model)}</dd>` : ""}
      <dt>Operating System</dt><dd>${esc(h.os_guess || "—")} ${h.os_guess ? confBadge(h.confidence) : ""}</dd>
      ${h.firmware ? `<dt>Firmware</dt><dd class="mono">${esc(h.firmware)}</dd>` : ""}
      <dt>Expected</dt><dd>${expectedPill(h.is_expected)}</dd>
      <dt>First seen</dt><dd>${fmtTime(h.first_seen)}</dd>
      <dt>Last seen</dt><dd>${fmtTime(h.last_seen)}</dd>
      <dt>Notes</dt><dd>${esc(h.notes || "—")}</dd>
    </dl>
    <h3>Interfaces</h3>${ifaces}<h3>Addresses</h3>${addrs}<h3>Services</h3>${svcs}<h3>Topology</h3>${topo}
    ${iconPicker}
    ${annotate}
    ${(d.changes || []).length ? `<h3>Changes <span class="badge">${d.changes.length}</span></h3><div class="changes">${changes}</div>` : ""}
    <h3>Observation history <span class="badge">${(d.observations || []).length}</span></h3>
    <table class="obs"><tbody>${rows}</tbody></table>`;

  if (me.is_admin) {
    $("annotate-form").onsubmit = async (e) => {
      e.preventDefault();
      await post("/api/host/annotate", { stable_id: h.stable_id, display_name: $("an-name").value, device_class: $("an-class").value, notes: $("an-notes").value, is_expected: $("an-expected").checked, ignored: $("an-ignored").checked });
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
  }
  openPanel("detail");
}

// ── settings ─────────────────────────────────────────────────────────────────

async function openSettings() {
  const [s, users, allIcons, statuses] = await Promise.all([
    getJSON("/api/settings"), getJSON("/api/users"), loadIcons(true), getJSON("/api/status").catch(() => []),
  ]);
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

  $("settings-body").innerHTML = `
    <h2>Settings</h2>
    ${s.restart_pending ? `<div class="restart-banner"><span>A change needs a restart to apply.</span><button class="btn" id="btn-restart">Restart now</button></div>` : ""}

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
        ${chk("disc-a-tcpbeh", "TCP behavioral scan <span class='th'>OS / firewall fingerprint</span>", e.disc_tcp_behavioral)}
        ${chk("disc-a-wake", "Thorough Wake <span class='th'>extra pass for sleepy devices · slower</span>", e.disc_thorough_wake)}
      </div>
    </div>

    <div class="settings-section"><h3>Users</h3>
      <div id="user-list">${users.map(userRow).join("")}</div>
      <div class="field row" style="margin-top:10px">
        <input type="text" id="nu-name" placeholder="username" style="flex:1">
        <input type="password" id="nu-pass" placeholder="password (8+)" style="flex:1">
        <select id="nu-role"><option value="viewer">viewer</option><option value="admin">admin</option></select>
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

function val(id) { return $(id).value.trim(); }
function checked(id) { return $(id).checked; }
function secInput(id) { const v = $(id).value; return v ? v : undefined; }

function wireSettings(canSec) {
  if ($("btn-restart")) $("btn-restart").onclick = async () => { await post("/api/restart"); toast("Restarting…"); setTimeout(() => location.reload(), 4000); };

  $("btn-test-unifi").onclick = () => runTest("/api/test/unifi", "tr-unifi", {
    base_url: val("set-unifi-url"), path_prefix: val("set-unifi-prefix"), site: val("set-unifi-site"),
    verify_tls: checked("set-unifi-verify"), username: $("set-unifi-user").value, password: $("set-unifi-pass").value, api_key: $("set-unifi-key").value,
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
      disc_tcp_behavioral: checked("disc-a-tcpbeh"), disc_thorough_wake: checked("disc-a-wake"),
      alerts_enabled: checked("set-al-en"), alerts_kind: $("set-al-kind").value,
      alert_new_device: checked("set-al-new"), alert_offline: checked("set-al-off"),
      alert_online: checked("set-al-on"), alert_ip_changed: checked("set-al-ip"), alert_conflict: checked("set-al-cf"),
    };
    const secrets = {};
    if (canSec) {
      const add = (k, id) => { const v = secInput(id); if (v !== undefined) secrets[k] = v; };
      add("unifi_username", "set-unifi-user"); add("unifi_password", "set-unifi-pass"); add("unifi_api_key", "set-unifi-key");
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
const VIEWS = ["dashboard", "topology", "observations", "security", "settings"];
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
}

async function init() {
  try { me = await fetch("/api/me").then((r) => (r.ok ? r.json() : Promise.reject())); }
  catch { showLogin(); return; }
  hideLogin(); renderUserbar(); setupSortHeaders(); setupObservations(); renderFooter();
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
