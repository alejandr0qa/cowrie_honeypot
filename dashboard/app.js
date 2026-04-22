/* =============================================================================
   Cowrie Honeypot Dashboard — app.js v2.1
   Nuevas funciones RAG:
     - loadRagStats()     → tarjeta "Memoria RAG" con eventos indexados
     - showIPHistory(ip)  → drawer lateral con historial completo de la IP
     - closeIPDrawer()    → cierra el drawer
     - renderTable() actualizado → IPs son clickeables (llaman a showIPHistory)
     - runAnalysis() actualizado → envía use_rag toggle al API
   ============================================================================= */

"use strict";

// ─── Config ──────────────────────────────────────────────────────────────────
const API_BASE = "";   // Mismo origen (ajustar si API está en otro host)

// ─── Estado Global ────────────────────────────────────────────────────────────
let state = {
  allEvents:      [],
  filteredEvents: [],
  refreshTimer:   null,
  charts:         { hourly: null, events: null },
  lastFetchKey:   null,
  drawerOpen:     false,
};

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const el = {
  status:        $("honeypot-status"),
  sourceLabel:   $("data-source-badge"),
  refreshSel:    $("refresh-interval-select"),
  refreshBtn:    $("refresh-btn"),
  analyzeBtn:    $("analyze-btn"),
  aiModelSel:    $("ai-model-select"),
  useRagToggle:  $("use-rag-toggle"),
  aiOutput:      $("ai-output"),
  filterIp:      $("filter-ip"),
  filterEvent:   $("filter-event"),
  eventsBadge:   $("event-count-badge"),
  eventsBody:    $("events-tbody"),
  topIpsList:    $("top-ips-list"),
  topCmdsList:   $("top-cmds-list"),
  footerTs:      $("footer-timestamp"),
  // Stats
  valTotal:      $("val-total"),
  valIps:        $("val-ips"),
  valLogins:     $("val-logins"),
  valCmds:       $("val-cmds"),
  valSessions:   $("val-sessions"),
  valFailed:     $("val-failed"),
  valRag:        $("val-rag"),
  ragStatusLbl:  $("rag-status-label"),
  // Drawer
  drawerOverlay: $("ip-drawer-overlay"),
  ipDrawer:      $("ip-drawer"),
  drawerTitle:   $("drawer-ip-title"),
  drawerContent: $("drawer-content"),
};

// ─── Fetch Helper ─────────────────────────────────────────────────────────────
async function fetchJSON(path) {
  const res = await fetch(API_BASE + path);
  if (!res.ok) throw new Error(`HTTP ${res.status} — ${path}`);
  return res.json();
}

// ─── Status ───────────────────────────────────────────────────────────────────
async function loadStatus() {
  try {
    const data = await fetchJSON("/api/status");
    const running = data.container?.running;
    const sample  = data.log_source === "sample_data";

    el.status.className = "status-badge " + (running ? "online" : "offline");
    el.status.querySelector(".status-text").textContent =
      running ? "Honeypot Activo" : "Contenedor Detenido";

    el.sourceLabel.className = "data-source-badge " + (sample ? "sample" : "live");
    el.sourceLabel.textContent = sample ? "📦 Datos de Demo" : "⚡ Live";

    // RAG status desde el /api/status
    if (data.rag) {
      updateRagCard(data.rag.indexed_count, data.rag.available);
    }
  } catch {
    el.status.className = "status-badge offline";
    el.status.querySelector(".status-text").textContent = "API No Disponible";
  }
}

// ─── RAG Stats ────────────────────────────────────────────────────────────────
async function loadRagStats() {
  try {
    const data = await fetchJSON("/api/rag/stats");
    if (data.available) {
      updateRagCard(data.total_indexed, true, data.unique_ips);
    } else {
      updateRagCard(0, false);
    }
  } catch {
    updateRagCard(0, false);
  }
}

function updateRagCard(count, available, uniqueIps = null) {
  if (!el.valRag) return;

  if (!available) {
    el.valRag.textContent = "—";
    if (el.ragStatusLbl) el.ragStatusLbl.textContent = "pip install chromadb";
    return;
  }

  animateValue(el.valRag, count);

  if (el.ragStatusLbl) {
    el.ragStatusLbl.textContent = uniqueIps != null
      ? `${uniqueIps} IPs en memoria`
      : "indexados";
  }
}

// ─── Stats Cards ──────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const d = await fetchJSON("/api/stats");
    animateValue(el.valTotal,    d.total_events    ?? 0);
    animateValue(el.valIps,      d.unique_ips      ?? 0);
    animateValue(el.valLogins,   d.logins_success  ?? 0);
    animateValue(el.valCmds,     d.total_commands  ?? 0);
    animateValue(el.valSessions, d.unique_sessions ?? 0);
    animateValue(el.valFailed,   d.logins_failed   ?? 0);

    if (d.rag_indexed !== undefined) {
      updateRagCard(d.rag_indexed, d.rag_available);
    }

    renderTopIPs(d.top_ips    || []);
    renderTopCmds(d.top_commands || []);
    renderHourlyChart(d.hourly_activity || {});
    renderEventsChart(d.event_breakdown || {});
  } catch (e) {
    console.error("Stats error:", e);
  }
}

// Animación numérica suave
function animateValue(el, target) {
  const current = parseInt(el.textContent.replace(/\D/g,"")) || 0;
  if (current === target) return;
  const duration = 400;
  const start = performance.now();
  const animate = (now) => {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(current + (target - current) * eased).toLocaleString();
    if (progress < 1) requestAnimationFrame(animate);
  };
  requestAnimationFrame(animate);
}

// ─── Top IPs (con clic → historial) ──────────────────────────────────────────
function renderTopIPs(ips) {
  if (!ips.length) {
    el.topIpsList.innerHTML = '<p style="padding:16px;color:var(--text-muted);font-size:.82rem;">Sin datos</p>';
    return;
  }
  const max = ips[0]?.count || 1;
  el.topIpsList.innerHTML = ips.slice(0, 8).map((item, i) => `
    <div class="ip-rank-item">
      <span class="ip-rank-num">${i + 1}</span>
      <span class="ip-rank-ip ip-link" onclick="showIPHistory('${escHtml(item.ip)}')"
            title="Ver historial RAG de ${escHtml(item.ip)}">${escHtml(item.ip)}</span>
      <div class="ip-rank-bar-wrap">
        <div class="ip-rank-bar-bg">
          <div class="ip-rank-bar" style="width:${Math.round((item.count / max) * 100)}%"></div>
        </div>
        <span class="ip-rank-count">${item.count}</span>
      </div>
    </div>
  `).join("");
}

// ─── Top Commands ─────────────────────────────────────────────────────────────
function renderTopCmds(cmds) {
  if (!cmds.length) {
    el.topCmdsList.innerHTML = '<p style="padding:16px;color:var(--text-muted);font-size:.82rem;">Sin comandos capturados</p>';
    return;
  }
  el.topCmdsList.innerHTML = cmds.slice(0, 8).map((item) => `
    <div class="cmd-item">
      <span class="cmd-text">${escHtml(item.command)}</span>
      <span class="cmd-count">×${item.count}</span>
    </div>
  `).join("");
}

// ─── Charts ───────────────────────────────────────────────────────────────────
const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 600 },
  plugins: {
    legend: {
      labels: { color: "#8892a4", font: { family: "Outfit" }, boxWidth: 12, padding: 14 }
    },
    tooltip: {
      backgroundColor: "rgba(13,18,32,0.95)",
      borderColor: "rgba(255,255,255,0.1)",
      borderWidth: 1,
      titleColor: "#e8edf5",
      bodyColor: "#8892a4",
      titleFont: { family: "Outfit", weight: "600" },
      bodyFont:  { family: "JetBrains Mono" },
      padding: 10,
    }
  }
};

function renderHourlyChart(hourly) {
  const labels = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, "0") + ":00");
  const data   = labels.map((_, i) => hourly[String(i).padStart(2, "0")] || 0);
  const ctx    = document.getElementById("chart-hourly").getContext("2d");

  if (state.charts.hourly) {
    state.charts.hourly.data.datasets[0].data = data;
    state.charts.hourly.update("active");
    return;
  }
  state.charts.hourly = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Eventos",
        data,
        backgroundColor: "rgba(0, 255, 136, 0.15)",
        borderColor: "rgba(0, 255, 136, 0.7)",
        borderWidth: 1.5,
        borderRadius: 4,
        hoverBackgroundColor: "rgba(0, 255, 136, 0.28)",
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: { ticks: { color: "#4a5568", font: { family: "JetBrains Mono", size: 10 }, maxRotation: 0 }, grid: { color: "rgba(255,255,255,0.04)" } },
        y: { ticks: { color: "#4a5568", font: { family: "Outfit", size: 11 } }, grid: { color: "rgba(255,255,255,0.05)" }, beginAtZero: true }
      }
    }
  });
}

const EVENT_COLORS = {
  "cowrie.session.connect": { bg: "rgba(59,130,246,0.7)",  border: "#3b82f6" },
  "cowrie.login.success":   { bg: "rgba(255,51,102,0.7)",  border: "#ff3366" },
  "cowrie.login.failed":    { bg: "rgba(234,179,8,0.7)",   border: "#eab308" },
  "cowrie.command.input":   { bg: "rgba(0,255,136,0.7)",   border: "#00ff88" },
  "cowrie.session.closed":  { bg: "rgba(168,85,247,0.7)",  border: "#a855f7" },
};
const DEFAULT_COLOR = { bg: "rgba(74,85,104,0.7)", border: "#4a5568" };

function renderEventsChart(breakdown) {
  const rawKeys = Object.keys(breakdown);
  const labels  = rawKeys.map(k => k.replace("cowrie.", ""));
  const data    = Object.values(breakdown);
  const colors  = rawKeys.map(k => (EVENT_COLORS[k] || DEFAULT_COLOR).bg);
  const borders = rawKeys.map(k => (EVENT_COLORS[k] || DEFAULT_COLOR).border);
  const ctx     = document.getElementById("chart-events").getContext("2d");

  if (state.charts.events) {
    state.charts.events.data.datasets[0].data = data;
    state.charts.events.update("active");
    return;
  }
  state.charts.events = new Chart(ctx, {
    type: "doughnut",
    data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: borders, borderWidth: 1.5 }] },
    options: {
      ...CHART_DEFAULTS,
      cutout: "65%",
      plugins: {
        ...CHART_DEFAULTS.plugins,
        legend: { position: "bottom", labels: { color: "#8892a4", font: { family: "Outfit", size: 11 }, boxWidth: 10, padding: 10 } }
      }
    }
  });
}

// ─── Events Table ─────────────────────────────────────────────────────────────
async function loadEvents() {
  try {
    const data = await fetchJSON("/api/logs?limit=300");
    const key  = JSON.stringify(data.events.slice(0, 5).map(e => e.timestamp));
    const isNew = key !== state.lastFetchKey;
    state.lastFetchKey   = key;
    state.allEvents      = data.events || [];
    state.filteredEvents = applyFilters(state.allEvents);
    renderTable(state.filteredEvents, isNew);
    el.footerTs.textContent = "Última actualización: " + new Date().toLocaleTimeString("es", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    el.eventsBody.innerHTML = `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--red);">
      ⚠ No se pudo cargar el log. ¿Está corriendo la API?</td></tr>`;
  }
}

function applyFilters(events) {
  const ip  = el.filterIp.value.trim().toLowerCase();
  const evt = el.filterEvent.value;
  return events.filter(e => {
    if (ip  && !(e.src_ip || "").toLowerCase().includes(ip)) return false;
    if (evt && e.eventid !== evt) return false;
    return true;
  });
}

function renderTable(events, highlightNew = false) {
  el.eventsBadge.textContent = `${events.length.toLocaleString()} evento${events.length !== 1 ? "s" : ""}`;

  if (!events.length) {
    el.eventsBody.innerHTML = `<tr><td colspan="5" style="padding:24px;text-align:center;color:var(--text-muted);">
      Sin eventos que coincidan con los filtros.</td></tr>`;
    return;
  }

  el.eventsBody.innerHTML = events.map((e, i) => {
    const pill      = eventPill(e.eventid);
    const detail    = getDetail(e);
    const tsShort   = (e.timestamp || "").replace("T", " ").replace("Z", "").substring(0, 19);
    const rowClass  = getRowClass(e.eventid) + (i < 3 && highlightNew ? " row-new" : "");
    const ip        = e.src_ip || "—";

    return `<tr class="${rowClass}">
      <td class="td-ts">${escHtml(tsShort)}</td>
      <td class="td-ip">
        <span class="ip-link" onclick="showIPHistory('${escHtml(ip)}')"
              title="Ver historial RAG de ${escHtml(ip)}">${escHtml(ip)}</span>
      </td>
      <td>${pill}</td>
      <td class="td-detail">${escHtml(detail)}</td>
      <td class="td-session">${escHtml((e.session || "").substring(0, 12))}</td>
    </tr>`;
  }).join("");
}

function getRowClass(eventid) {
  const m = { "cowrie.login.success": "row-success", "cowrie.login.failed": "row-failed", "cowrie.command.input": "row-command" };
  return m[eventid] || "";
}

function eventPill(eventid) {
  const map = {
    "cowrie.session.connect": ['pill-connect', '🔌', 'Conexión'],
    "cowrie.login.success":   ['pill-success', '🔴', 'Login OK'],
    "cowrie.login.failed":    ['pill-failed',  '⚠',  'Login Fail'],
    "cowrie.command.input":   ['pill-command', '>_', 'Comando'],
    "cowrie.session.closed":  ['pill-closed',  '✕',  'Cerrada'],
    "cowrie.client.version":  ['pill-default', '📋', 'SSH Ver'],
    "cowrie.client.kex":      ['pill-default', '🔑', 'KEX'],
    "cowrie.client.size":     ['pill-default', '↔',  'Term Size'],
    "cowrie.session.params":  ['pill-default', '⚙',  'Params'],
  };
  const [cls, icon, label] = map[eventid] || ['pill-default', '·', eventid.replace("cowrie.", "")];
  return `<span class="event-pill ${cls}">${escHtml(icon)} ${escHtml(label)}</span>`;
}

function getDetail(e) {
  switch (e.eventid) {
    case "cowrie.login.success":
    case "cowrie.login.failed": return `${e.username || ""} / ${e.password || ""}`;
    case "cowrie.command.input": return e.input || "";
    case "cowrie.session.connect": return `Puerto ${e.src_port || "?"} → ${e.dst_port || "?"}`;
    case "cowrie.session.closed": return `Duración: ${e.duration || "?"}s`;
    case "cowrie.client.version": return e.version || "";
    default: return e.message || "";
  }
}

// ─── IP History Drawer ────────────────────────────────────────────────────────
window.showIPHistory = async function(ip) {
  if (!ip || ip === "—") return;

  // Abrir drawer inmediatamente con spinner
  el.drawerTitle.textContent   = ip;
  el.drawerContent.innerHTML   = `<div class="drawer-loading"><div class="loading-spinner"></div><span>Consultando memoria RAG...</span></div>`;
  el.drawerOverlay.classList.add("open");
  el.ipDrawer.classList.add("open");
  document.body.style.overflow = "hidden";
  state.drawerOpen = true;

  try {
    const data = await fetchJSON(`/api/history/${encodeURIComponent(ip)}`);
    renderIPHistory(data);
  } catch (err) {
    const msg = err.message.includes("503")
      ? "ChromaDB no disponible.\nInstala: pip install chromadb"
      : err.message;
    el.drawerContent.innerHTML = `<div class="drawer-no-data">⚠ ${escHtml(msg)}</div>`;
  }
};

window.closeIPDrawer = function() {
  el.drawerOverlay.classList.remove("open");
  el.ipDrawer.classList.remove("open");
  document.body.style.overflow = "";
  state.drawerOpen = false;
};

function renderIPHistory(d) {
  if (!d.available) {
    el.drawerContent.innerHTML = `<div class="drawer-no-data">
      ⚗ RAG no disponible.<br>Instala: <code>pip install chromadb</code>
    </div>`;
    return;
  }

  if (!d.total_events) {
    el.drawerContent.innerHTML = `<div class="drawer-no-data">
      📍 Esta IP no tiene historial en la memoria RAG.<br>
      <small>Puede ser que sea la primera vez que aparece, o que los datos aún no se hayan indexado.</small>
    </div>`;
    return;
  }

  const fmt  = (ts) => (ts || "").replace("T", " ").replace("Z", "").substring(0, 16);
  const creds = d.credentials_tried || [];
  const cmds  = d.commands || [];
  const events = d.events || [];

  const credsHtml = creds.length
    ? `<div class="drawer-section">
        <div class="drawer-section-title">🔑 Credenciales probadas</div>
        <div class="tag-list">${creds.map(c => `<span class="tag tag-cred">${escHtml(c)}</span>`).join("")}</div>
       </div>`
    : "";

  const cmdsHtml = cmds.length
    ? `<div class="drawer-section">
        <div class="drawer-section-title">>_ Comandos ejecutados</div>
        <div class="tag-list">${cmds.map(c => `<span class="tag tag-cmd">${escHtml(c)}</span>`).join("")}</div>
       </div>`
    : "";

  const dotClass = (eid) => {
    const m = {
      "cowrie.session.connect": "dot-connect", "cowrie.login.success": "dot-success",
      "cowrie.login.failed": "dot-failed", "cowrie.command.input": "dot-command",
      "cowrie.session.closed": "dot-closed",
    };
    return m[eid] || "dot-default";
  };

  const timelineHtml = events.length
    ? `<div class="drawer-section">
        <div class="drawer-section-title">📅 Timeline (${events.length} eventos)</div>
        <div class="drawer-timeline">
          ${events.slice(-20).reverse().map(ev => {
            const meta = ev.metadata || {};
            const eid  = meta.eventid || "";
            const ts   = fmt(meta.timestamp);
            let txt    = ev.text || eid.replace("cowrie.", "");
            return `<div class="timeline-item">
              <div class="timeline-dot ${dotClass(eid)}"></div>
              <div class="timeline-body">
                <span class="timeline-ts">${escHtml(ts)}</span>
                <span class="timeline-text">${escHtml(txt)}</span>
              </div>
            </div>`;
          }).join("")}
        </div>
       </div>`
    : "";

  el.drawerContent.innerHTML = `
    <!-- Stat Grid -->
    <div class="drawer-stats">
      <div class="drawer-stat">
        <span class="drawer-stat-label">Primera vez</span>
        <span class="drawer-stat-value dv-cyan" style="font-size:0.85rem">${escHtml(fmt(d.first_seen))}</span>
      </div>
      <div class="drawer-stat">
        <span class="drawer-stat-label">Última vez</span>
        <span class="drawer-stat-value dv-cyan" style="font-size:0.85rem">${escHtml(fmt(d.last_seen))}</span>
      </div>
      <div class="drawer-stat">
        <span class="drawer-stat-label">Total eventos</span>
        <span class="drawer-stat-value dv-default">${d.total_events ?? 0}</span>
      </div>
      <div class="drawer-stat">
        <span class="drawer-stat-label">Sesiones</span>
        <span class="drawer-stat-value dv-default">${d.unique_sessions ?? 0}</span>
      </div>
      <div class="drawer-stat">
        <span class="drawer-stat-label">Logins OK</span>
        <span class="drawer-stat-value dv-red">${d.logins_success ?? 0}</span>
      </div>
      <div class="drawer-stat">
        <span class="drawer-stat-label">Login Fail</span>
        <span class="drawer-stat-value dv-yellow">${d.logins_failed ?? 0}</span>
      </div>
    </div>

    ${credsHtml}
    ${cmdsHtml}
    ${timelineHtml}
  `;
}

// ─── AI Analysis (con RAG toggle) ─────────────────────────────────────────────
async function runAnalysis() {
  el.analyzeBtn.disabled = true;
  const useRag  = el.useRagToggle ? el.useRagToggle.checked : true;
  const model   = el.aiModelSel.value;
  const ragNote = useRag ? ' + <span class="rag-badge">🗄 RAG</span>' : '';

  el.aiOutput.innerHTML = `<div class="ai-loading">
    <div class="loading-spinner"></div>
    <span>Analizando con ${escHtml(model)}${useRag ? " + memoria histórica" : ""}…</span>
  </div>`;

  try {
    const res = await fetch(API_BASE + "/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model, max_events: 50, use_rag: useRag }),
      signal: AbortSignal.timeout(180_000),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    const text      = data.analysis || "(Sin respuesta)";
    const evts      = data.events_analyzed || 0;
    const ragUsed   = data.rag_context_used;
    const ragIndexed = data.rag_indexed ?? 0;
    const src       = data.source === "sample_data" ? "📦 Demo" : "⚡ Live";

    el.aiOutput.innerHTML = `
      <div class="ai-result">
        <div class="ai-meta">
          <span>🤖 ${escHtml(model)}</span>
          <span>📋 ${evts} eventos</span>
          <span>${src}</span>
          ${ragUsed ? `<span class="rag-badge">🗄 RAG (${ragIndexed} indexados)</span>` : '<span style="color:var(--text-muted);font-size:0.72rem">RAG off</span>'}
        </div>
        <pre style="white-space:pre-wrap;font-family:inherit;line-height:1.75;">${escHtml(text)}</pre>
      </div>`;
  } catch (err) {
    const msg = err.name === "TimeoutError" || err.message.includes("504")
      ? "El modelo tardó demasiado. Prueba con TinyLlama."
      : err.message;
    el.aiOutput.innerHTML = `<div class="ai-error">⚠ ${escHtml(msg)}</div>`;
  } finally {
    el.analyzeBtn.disabled = false;
  }
}

// ─── Auto-refresh ─────────────────────────────────────────────────────────────
function setupAutoRefresh(intervalSec) {
  clearInterval(state.refreshTimer);
  if (!intervalSec || intervalSec === "0") return;
  state.refreshTimer = setInterval(refreshAll, parseInt(intervalSec) * 1000);
}

async function refreshAll() {
  await Promise.allSettled([loadStatus(), loadStats(), loadEvents(), loadRagStats()]);
}

// ─── Filters ──────────────────────────────────────────────────────────────────
function onFilterChange() {
  state.filteredEvents = applyFilters(state.allEvents);
  renderTable(state.filteredEvents, false);
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Teclado: Escape cierra el drawer
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && state.drawerOpen) closeIPDrawer();
});

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  el.refreshBtn.addEventListener("click", refreshAll);
  el.refreshSel.addEventListener("change", () => setupAutoRefresh(el.refreshSel.value));
  el.analyzeBtn.addEventListener("click", runAnalysis);
  el.filterIp.addEventListener("input",    onFilterChange);
  el.filterEvent.addEventListener("change", onFilterChange);

  await refreshAll();
  setupAutoRefresh(30);
}

document.addEventListener("DOMContentLoaded", init);
