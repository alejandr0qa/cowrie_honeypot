"use strict";

(function () {
  const esc = (v) => String(v ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/\"/g, "&quot;");

  const priority = (value) => ({
    critical: ["Crítico", "def-priority-critical"],
    high: ["Alto", "def-priority-high"],
    medium: ["Medio", "def-priority-medium"],
    low: ["Bajo", "def-priority-low"],
  }[value] || [value || "Medio", "def-priority-medium"]);

  const attackUrl = (id) => `https://attack.mitre.org/techniques/${String(id).replace(".", "/")}`;

  function ensurePanel() {
    let panel = document.getElementById("defense-panel");
    if (panel) return panel;

    panel = document.createElement("section");
    panel.id = "defense-panel";
    panel.className = "glass-panel panel--full defense-panel";
    panel.innerHTML = `
      <div class="panel-header defense-header">
        <div class="panel-title">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-5"/></svg>
          Cobertura MITRE D3FEND
          <span class="badge" id="defense-count-badge">—</span>
        </div>
        <div class="defense-actions-head">
          <span class="panel-hint">ATT&amp;CK → D3FEND</span>
          <button id="defense-refresh-btn" class="btn btn-icon" title="Actualizar D3FEND" aria-label="Actualizar D3FEND">↻</button>
        </div>
      </div>
      <div id="defense-content" class="defense-content">
        <div class="defense-loading"><div class="spinner"></div><span>Cargando recomendaciones defensivas…</span></div>
      </div>`;

    const anchor = document.querySelector(".charts-row") || document.querySelector(".content-row");
    if (anchor) anchor.insertAdjacentElement("afterend", panel);
    else document.querySelector("main")?.appendChild(panel);

    panel.querySelector("#defense-refresh-btn")?.addEventListener("click", loadDefenseRecommendations);
    return panel;
  }

  function renderError(message) {
    ensurePanel();
    const badge = document.getElementById("defense-count-badge");
    const content = document.getElementById("defense-content");
    if (badge) badge.textContent = "sin datos";
    if (content) content.innerHTML = `<div class="defense-empty">⚠ ${esc(message)}</div>`;
  }

  function renderDefense(data) {
    ensurePanel();
    const defense = data.defense || {};
    const recs = defense.recommendations || [];
    const controls = defense.top_controls || [];
    const actions = defense.top_actions || [];
    const counts = defense.priority_counts || {};
    const pre = data.pre_analysis || {};

    const badge = document.getElementById("defense-count-badge");
    if (badge) badge.textContent = `${recs.length} técnica${recs.length === 1 ? "" : "s"}`;
    if (!recs.length) return renderError("No se detectaron técnicas ATT&CK suficientes para mapear defensas.");

    const priorityHtml = ["critical", "high", "medium", "low"]
      .filter((key) => counts[key])
      .map((key) => {
        const [label, cls] = priority(key);
        return `<span class="def-priority ${cls}">${label}: ${counts[key]}</span>`;
      }).join("");

    const recsHtml = recs.slice(0, 6).map((rec) => {
      const [label, cls] = priority(rec.priority);
      const tags = (rec.d3fend_controls || []).slice(0, 4)
        .map((control) => `<span class="def-tag def-tag-control">${esc(control)}</span>`).join("");
      const firstAction = (rec.recommended_actions || [])[0] || "Registrar y revisar evidencia.";
      return `<article class="def-rec-card">
        <div class="def-rec-head">
          <a class="def-attack-id" href="${attackUrl(rec.attack_id)}" target="_blank" rel="noopener">${esc(rec.attack_id)}</a>
          <span class="def-rec-title">${esc(rec.attack_name)}</span>
          <span class="def-priority ${cls}">${label}</span>
        </div>
        <p class="def-evidence">Evidencia: ${esc(rec.evidence || "detectada en logs")}</p>
        <div class="def-tag-list">${tags}</div>
        <p class="def-action-main">${esc(firstAction)}</p>
      </article>`;
    }).join("");

    const controlsHtml = controls.length ? controls.map((item) => `
      <div class="def-control-row"><span>${esc(item.control)}</span><strong>${esc(item.count)}</strong></div>`).join("")
      : `<div class="def-muted">Sin controles agregados.</div>`;

    const actionsHtml = actions.length ? actions.map((action, i) => `
      <li><span class="def-action-num">${i + 1}</span>${esc(action)}</li>`).join("")
      : `<li>No hay acciones sugeridas.</li>`;

    document.getElementById("defense-content").innerHTML = `
      <div class="defense-summary">
        <div class="defense-metric"><span class="defense-metric-label">Eventos analizados</span><span class="defense-metric-value">${esc(data.events_analyzed)}</span></div>
        <div class="defense-metric"><span class="defense-metric-label">ATT&amp;CK detectadas</span><span class="defense-metric-value">${esc(defense.total_attack_techniques)}</span></div>
        <div class="defense-metric"><span class="defense-metric-label">Controles sugeridos</span><span class="defense-metric-value">${esc(controls.length)}</span></div>
        <div class="defense-metric"><span class="defense-metric-label">Prioridad</span><div class="def-priority-row">${priorityHtml || "—"}</div></div>
      </div>
      <div class="defense-grid">
        <div class="defense-main"><div class="def-section-title">Técnicas ATT&amp;CK mapeadas a D3FEND</div><div class="def-rec-grid">${recsHtml}</div></div>
        <aside class="defense-side">
          <div class="def-side-box"><div class="def-section-title">Top controles</div><div class="def-control-list">${controlsHtml}</div></div>
          <div class="def-side-box"><div class="def-section-title">Acciones priorizadas</div><ol class="def-action-list">${actionsHtml}</ol></div>
          <div class="def-side-box def-context-box"><div class="def-section-title">Contexto automático</div><p>${esc(pre.credential_type || "Credenciales no clasificadas")}</p><p>${esc(pre.timing?.classification || "Timing insuficiente")}</p></div>
        </aside>
      </div>`;
  }

  async function loadDefenseRecommendations() {
    ensurePanel();
    const content = document.getElementById("defense-content");
    if (content) content.innerHTML = `<div class="defense-loading"><div class="spinner"></div><span>Actualizando recomendaciones D3FEND…</span></div>`;
    try {
      const res = await fetch("/api/defense/recommendations?limit=300");
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
      renderDefense(data);
    } catch (err) {
      renderError(err.message || "No se pudo cargar D3FEND.");
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    ensurePanel();
    loadDefenseRecommendations();
    window.setInterval(loadDefenseRecommendations, 60000);
  });
})();
