/* =============================================================================
   Cowrie Honeypot Dashboard — app.js
   Lógica principal: fetch, render, charts, filtros, análisis IA
   ============================================================================= */

"use strict";

// ─── Config ──────────────────────────────────────────────────────────────────
const API_BASE = window.location.origin.includes("localhost")
  ? ""          // Mismo origen cuando corre via Python
  : "";         // Ajustar si el API está en otro host

const REFRESH_INTERVALS = { 10: 10_000, 30: 30_000, 60: 60_000 };

// ─── Estado Global ────────────────────────────────────────────────────────────
let state = {
  allEvents: [],
  filteredEvents: [],
  refreshTimer: null,
  charts: { hourly: null, events: null },
  lastFetchKey: null, // Para detectar datos nuevos
};

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const el = {
  status:       $("honeypot-status"),
  sourceLabel:  $("data-source-badge"),
  refreshSel:   $("refresh-interval-select"),
  refreshBtn:   $("refresh-btn"),
  analyzeBtn:   $("analyze-btn"),
  aiModelSel:   $("ai-model-select"),
  aiOutput:     $("ai-output"),
  filterIp:     $("filter-ip"),
  filterEvent:  $("filter-event"),
  eventsBadge:  $("event-count-badge"),
  eventsBody:   $("events-tbody"),
  topIpsList:   $("top-ips-list"),
  topCmdsList:  $("top-cmds-list"),
  footerTs:     $("footer-timestamp"),
  // Stats values
  valTotal:    $("val-total"),
  valIps:      $("val-ips"),
  valLogins:   $("val-logins"),
  valCmds:     $("val-cmds"),
  valSessions: $("val-sessions"),
  valFailed:   $("val-failed"),
};

// ─── Fetch Helpers ────────────────────────────────────────────────────────────
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
  } catch {
    el.status.className = "status-badge offline";
    el.status.querySelector(".status-text").textContent = "API No Disponible";
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

    renderTopIPs(d.top_ips   || []);
    renderTopCmds(d.top_commands || []);
    renderHourlyChart(d.hourly_activity || {});
    renderEventsChart(d.event_breakdown || {});
  } catch (e) {
    console.error("Stats error:", e);
  }
}

// Animación numérica suave
function animateValue(el, target) {
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;
  const step = Math.ceil(Math.abs(target - current) / 20);
  let val = current;
  const tick = setInterval(() => {
    val += val < target ? step : -step;
    if ((step > 0 && val >= target) || (step < 0 && val <= target)) {
      val = target;
      clearInterval(tick);
    }
    el.textContent = val.toLocaleString();
  }, 30);
}

// ─── Top IPs ──────────────────────────────────────────────────────────────────
function renderTopIPs(ips) {
  if (!ips.length) {
    el.topIpsList.innerHTML = '<p style="padding:16px;color:var(--text-muted);font-size:.82rem;">Sin datos</p>';
    return;
  }
  const max = ips[0]?.count || 1;
  el.topIpsList.innerHTML = ips.slice(0, 8).map((item, i) => `
    <div class="ip-rank-item">
      <span class="ip-rank-num">${i + 1}</span>
      <span class="ip-rank-ip">${escHtml(item.ip)}</span>
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
      bodyFont: { family: "JetBrains Mono" },
      padding: 10,
    }
  }
};

function renderHourlyChart(hourly) {
  const labels = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, "0") + ":00");
  const data   = labels.map((_, i) => hourly[String(i).padStart(2, "0")] || 0);

  const ctx = document.getElementById("chart-hourly").getContext("2d");

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
        x: {
          ticks: { color: "#4a5568", font: { family: "JetBrains Mono", size: 10 }, maxRotation: 0 },
          grid: { color: "rgba(255,255,255,0.04)" }
        },
        y: {
          ticks: { color: "#4a5568", font: { family: "Outfit", size: 11 } },
          grid: { color: "rgba(255,255,255,0.05)" },
          beginAtZero: true,
        }
      }
    }
  });
}

const EVENT_COLORS = {
  "cowrie.session.connect":  { bg: "rgba(59,130,246,0.7)",   border: "#3b82f6" },
  "cowrie.login.success":    { bg: "rgba(255,51,102,0.7)",   border: "#ff3366" },
  "cowrie.login.failed":     { bg: "rgba(234,179,8,0.7)",    border: "#eab308" },
  "cowrie.command.input":    { bg: "rgba(0,255,136,0.7)",    border: "#00ff88" },
  "cowrie.session.closed":   { bg: "rgba(168,85,247,0.7)",   border: "#a855f7" },
};
const DEFAULT_COLOR = { bg: "rgba(74,85,104,0.7)", border: "#4a5568" };

function renderEventsChart(breakdown) {
  const labels = Object.keys(breakdown).map(k => k.replace("cowrie.", ""));
  const rawKeys = Object.keys(breakdown);
  const data    = Object.values(breakdown);
  const colors  = rawKeys.map(k => (EVENT_COLORS[k] || DEFAULT_COLOR).bg);
  const borders = rawKeys.map(k => (EVENT_COLORS[k] || DEFAULT_COLOR).border);

  const ctx = document.getElementById("chart-events").getContext("2d");

  if (state.charts.events) {
    state.charts.events.data.datasets[0].data = data;
    state.charts.events.update("active");
    return;
  }

  state.charts.events = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data, backgroundColor: colors, borderColor: borders, borderWidth: 1.5 }]
    },
    options: {
      ...CHART_DEFAULTS,
      cutout: "65%",
      plugins: {
        ...CHART_DEFAULTS.plugins,
        legend: {
          position: "bottom",
          labels: { color: "#8892a4", font: { family: "Outfit", size: 11 }, boxWidth: 10, padding: 10 }
        }
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
    state.lastFetchKey  = key;
    state.allEvents     = data.events || [];
    state.filteredEvents = applyFilters(state.allEvents);

    renderTable(state.filteredEvents, isNew);
    el.footerTs.textContent = "Última actualización: " + new Date().toLocaleTimeString("es", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch (e) {
    el.eventsBody.innerHTML = `
      <tr><td colspan="5" style="padding:24px;text-align:center;color:var(--red);">
        ⚠ No se pudo cargar el log. Asegúrate de que la API esté corriendo.
      </td></tr>`;
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
    el.eventsBody.innerHTML = `
      <tr><td colspan="5" style="padding:24px;text-align:center;color:var(--text-muted);">
        Sin eventos que coincidan con los filtros.
      </td></tr>`;
    return;
  }

  el.eventsBody.innerHTML = events.map((e, i) => {
    const pill    = eventPill(e.eventid);
    const detail  = getDetail(e);
    const tsShort = (e.timestamp || "").replace("T", " ").replace("Z", "").substring(0, 19);
    const rowClass = getRowClass(e.eventid) + (i < 3 && highlightNew ? " row-new" : "");

    return `<tr class="${rowClass}">
      <td class="td-ts">${escHtml(tsShort)}</td>
      <td class="td-ip">${escHtml(e.src_ip || "—")}</td>
      <td>${pill}</td>
      <td class="td-detail">${escHtml(detail)}</td>
      <td class="td-session">${escHtml((e.session || "").substring(0, 12))}</td>
    </tr>`;
  }).join("");
}

function getRowClass(eventid) {
  const map = {
    "cowrie.login.success": "row-success",
    "cowrie.login.failed":  "row-failed",
    "cowrie.command.input": "row-command",
  };
  return map[eventid] || "";
}

function eventPill(eventid) {
  const map = {
    "cowrie.session.connect":  ['pill-connect',  '🔌', 'Conexión'],
    "cowrie.login.success":    ['pill-success',  '🔴', 'Login OK'],
    "cowrie.login.failed":     ['pill-failed',   '⚠',  'Login Fail'],
    "cowrie.command.input":    ['pill-command',  '>_', 'Comando'],
    "cowrie.session.closed":   ['pill-closed',   '✕',  'Cerrada'],
    "cowrie.client.version":   ['pill-default',  '📋', 'SSH Version'],
    "cowrie.client.kex":       ['pill-default',  '🔑', 'KEX'],
    "cowrie.client.size":      ['pill-default',  '↔',  'Term Size'],
    "cowrie.session.params":   ['pill-default',  '⚙',  'Params'],
  };
  const [cls, icon, label] = map[eventid] || ['pill-default', '·', eventid.replace("cowrie.", "")];
  return `<span class="event-pill ${cls}">${escHtml(icon)} ${escHtml(label)}</span>`;
}

function getDetail(e) {
  switch (e.eventid) {
    case "cowrie.login.success":
    case "cowrie.login.failed":
      return `${e.username || ""} / ${e.password || ""}`;
    case "cowrie.command.input":
      return e.input || "";
    case "cowrie.session.connect":
      return `Puerto ${e.src_port || "?"} → ${e.dst_port || "?"}`;
    case "cowrie.session.closed":
      return `Duración: ${e.duration || "?"}s`;
    case "cowrie.client.version":
      return e.version || "";
    default:
      return e.message || "";
  }
}

// ─── AI Analysis ─────────────────────────────────────────────────────────────
async function runAnalysis() {
  el.analyzeBtn.disabled = true;
  el.aiOutput.innerHTML = `
    <div class="ai-loading">
      <div class="loading-spinner"></div>
      <span>Analizando con ${escHtml(el.aiModelSel.value)}... Esto puede tomar hasta 2 minutos.</span>
    </div>`;

  try {
    const res = await fetch(API_BASE + "/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: el.aiModelSel.value, max_events: 50 }),
      signal: AbortSignal.timeout(180_000),
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || `HTTP ${res.status}`);
    }

    const text  = data.analysis || "(Sin respuesta)";
    const evts  = data.events_analyzed || 0;
    const model = data.model || "?";
    const src   = data.source === "sample_data" ? "📦 Demo" : "⚡ Live";

    el.aiOutput.innerHTML = `
      <div class="ai-result">
        <div class="ai-meta">
          <span>🤖 Modelo: <strong>${escHtml(model)}</strong></span>
          <span>📋 Eventos analizados: <strong>${evts}</strong></span>
          <span>Fuente: <strong>${src}</strong></span>
        </div>
        <pre style="white-space:pre-wrap;font-family:inherit;line-height:1.75;">${escHtml(text)}</pre>
      </div>`;
  } catch (err) {
    const msg = err.message.includes("504") || err.name === "TimeoutError"
      ? "El modelo tardó demasiado en responder. Intenta con TinyLlama que es más rápido."
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
  const ms = parseInt(intervalSec) * 1000;
  state.refreshTimer = setInterval(refreshAll, ms);
}

async function refreshAll() {
  await Promise.allSettled([loadStatus(), loadStats(), loadEvents()]);
}

// ─── Filters ──────────────────────────────────────────────────────────────────
function onFilterChange() {
  state.filteredEvents = applyFilters(state.allEvents);
  renderTable(state.filteredEvents, false);
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── Init ─────────────────────────────────────────────────────────────────────
async function init() {
  // Event listeners
  el.refreshBtn.addEventListener("click", refreshAll);
  el.refreshSel.addEventListener("change", () => setupAutoRefresh(el.refreshSel.value));
  el.analyzeBtn.addEventListener("click", runAnalysis);
  el.filterIp.addEventListener("input",   onFilterChange);
  el.filterEvent.addEventListener("change", onFilterChange);

  // Primera carga
  await refreshAll();

  // Auto-refresh por defecto (30s)
  setupAutoRefresh(30);
}

document.addEventListener("DOMContentLoaded", init);
