/**
 * dashboard.js — ObserveX dashboard frontend.
 *
 * Improvements over the original monolith inline JS:
 *  - Fully external (removes 'unsafe-inline' from CSP).
 *  - Chart.js bar chart replaces CSS flex bars (tooltips, axis labels, responsive).
 *  - Health donut is data-driven from recomputeAggregate() — not hardcoded 70/15/15.
 *  - KPI countUp animation on every data load/refresh.
 *  - Staggered bar chart entry animation.
 *  - Topology edge flow animation (stroke-dashoffset on error edges).
 *  - Alert strip pulse animation on critical alerts.
 *  - Lazy section rendering — sections initialised on first showSection() call.
 *  - Chip toggle smooth transition.
 *  - prefers-reduced-motion respected globally.
 *
 * Dependencies (CDN, already in dashboard.html):
 *   <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
 */

/* ── Global reduced-motion guard ─────────────────────────────────────────── */
const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ── State ────────────────────────────────────────────────────────────────── */
const state = {
  sessions: {},          // session_id → result object
  activeSessions: [],    // session_ids to aggregate
  aggregate: {},         // computed aggregate result
  currentSection: null,
  initialisedSections: new Set(),
  charts: {},            // named Chart.js instances
};

/* ── KPI countUp animation ───────────────────────────────────────────────── */
function countUp(el, target, duration = 600, prefix = "", suffix = "") {
  if (!el) return;
  if (REDUCED_MOTION) { el.textContent = prefix + target + suffix; return; }
  const start     = performance.now();
  const startVal  = 0;
  const isFloat   = String(target).includes(".");
  function step(now) {
    const elapsed  = Math.min(now - start, duration);
    const progress = elapsed / duration;
    // ease-out cubic
    const eased    = 1 - Math.pow(1 - progress, 3);
    const current  = startVal + (target - startVal) * eased;
    el.textContent = prefix + (isFloat ? current.toFixed(1) : Math.round(current)) + suffix;
    if (elapsed < duration) requestAnimationFrame(step);
    else el.textContent = prefix + target + suffix;
  }
  requestAnimationFrame(step);
}

function animateKPIs(agg) {
  const kpiMap = {
    "kpi-total":   agg.total   || 0,
    "kpi-errors":  agg.errors  || 0,
    "kpi-warns":   agg.warns   || 0,
    "kpi-latency": agg.latency || 0,
    "kpi-health":  agg.health  !== undefined ? agg.health : 100,
  };
  for (const [id, val] of Object.entries(kpiMap)) {
    const el = document.getElementById(id);
    if (el) countUp(el, val, 700);
  }
}

/* ── Health donut (data-driven SVG) ─────────────────────────────────────── */
function updateHealthDonut(good = 0, warn = 0, error = 0) {
  const total = good + warn + error || 1;
  const gPct  = good  / total;
  const wPct  = warn  / total;
  const ePct  = error / total;

  // SVG conic-gradient via stroke-dasharray on three overlapping circles
  const C   = 2 * Math.PI * 44;  // circumference for r=44
  const gEl = document.getElementById("donut-good");
  const wEl = document.getElementById("donut-warn");
  const eEl = document.getElementById("donut-error");
  if (!gEl) return;

  const gLen = gPct * C;
  const wLen = wPct * C;
  const eLen = ePct * C;

  function setArc(el, len, offset) {
    el.style.strokeDasharray  = `${len} ${C - len}`;
    el.style.strokeDashoffset = -offset;
    if (!REDUCED_MOTION) el.style.transition = "stroke-dasharray 0.6s ease, stroke-dashoffset 0.6s ease";
  }
  setArc(gEl, gLen, 0);
  setArc(wEl, wLen, gLen);
  setArc(eEl, eLen, gLen + wLen);

  // Centre label
  const pct  = Math.round(gPct * 100);
  const lbl  = document.getElementById("donut-label");
  if (lbl) countUp(lbl, pct, 700, "", "%");
}

/* ── Trend chart (Chart.js) ──────────────────────────────────────────────── */
function renderTrendChart(buckets) {
  const canvas = document.getElementById("dash-trend-canvas");
  if (!canvas) return;
  const ctx    = canvas.getContext("2d");
  const labels = buckets.map(b => b.label || b.time || "");
  const errors  = buckets.map(b => b.errors || 0);
  const infos   = buckets.map(b => (b.total || 0) - (b.errors || 0) - (b.warns || 0));
  const warns   = buckets.map(b => b.warns || 0);

  if (state.charts.trend) state.charts.trend.destroy();

  state.charts.trend = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label:           "Errors",
          data:            errors,
          backgroundColor: "rgba(239,68,68,0.75)",
          borderRadius:    3,
        },
        {
          label:           "Warnings",
          data:            warns,
          backgroundColor: "rgba(251,146,60,0.75)",
          borderRadius:    3,
        },
        {
          label:           "Info",
          data:            infos,
          backgroundColor: "rgba(99,102,241,0.4)",
          borderRadius:    3,
        },
      ],
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      animation: REDUCED_MOTION ? false : {
        duration: 500,
        easing:   "easeOutQuart",
        delay:    (ctx) => ctx.dataIndex * 20,
      },
      plugins: {
        legend: { display: true, position: "top", labels: { boxWidth: 10, font: { size: 11 } } },
        tooltip: { mode: "index", intersect: false },
      },
      scales: {
        x: {
          stacked: true,
          grid:    { display: false },
          ticks:   { font: { size: 10 }, maxRotation: 0 },
        },
        y: {
          stacked:   true,
          beginAtZero: true,
          grid:      { color: "rgba(127,127,127,0.1)" },
          ticks:     { font: { size: 10 } },
        },
      },
    },
  });
}

/* ── Build time buckets for trend chart ──────────────────────────────────── */
function buildTimeBuckets(rows, numBuckets = 12) {
  if (!rows || rows.length === 0) return [];
  const times = rows
    .map(r => new Date(r.time || r.timestamp || "").getTime())
    .filter(t => !isNaN(t));
  if (times.length === 0) return [];
  const minT  = Math.min(...times);
  const maxT  = Math.max(...times);
  const range = maxT - minT || 1;
  const size  = range / numBuckets;
  const buckets = Array.from({ length: numBuckets }, (_, i) => ({
    label:  new Date(minT + i * size).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    total:  0, errors: 0, warns: 0,
  }));
  for (const r of rows) {
    const t = new Date(r.time || r.timestamp || "").getTime();
    if (isNaN(t)) continue;
    const idx = Math.min(Math.floor((t - minT) / size), numBuckets - 1);
    buckets[idx].total++;
    if ((r.level || "").toUpperCase() === "ERROR") buckets[idx].errors++;
    if ((r.level || "").toUpperCase() === "WARN")  buckets[idx].warns++;
  }
  return buckets;
}

/* ── Topology edge flow animation ────────────────────────────────────────── */
function animateTopologyEdges() {
  if (REDUCED_MOTION) return;
  document.querySelectorAll(".arch-edge").forEach(edge => {
    const isError = edge.classList.contains("edge-error");
    const len     = edge.getTotalLength ? edge.getTotalLength() : 100;
    edge.style.strokeDasharray  = `${len}`;
    edge.style.strokeDashoffset = `${len}`;

    if (isError) {
      // Pulsing red flow on error edges
      edge.animate(
        [{ strokeDashoffset: len }, { strokeDashoffset: 0 }],
        { duration: 1200, iterations: Infinity, easing: "linear" }
      );
    } else {
      // Single draw-in on load for healthy edges
      edge.animate(
        [{ strokeDashoffset: len }, { strokeDashoffset: 0 }],
        { duration: 800, fill: "forwards", easing: "ease-out" }
      );
    }
  });
}

/* ── Alert strip pulse ───────────────────────────────────────────────────── */
function startAlertPulse() {
  if (REDUCED_MOTION) return;
  document.querySelectorAll(".enterprise-alert.critical, .live-alert-critical").forEach(el => {
    el.animate(
      [
        { borderColor: "rgba(239,68,68,0.6)" },
        { borderColor: "rgba(239,68,68,1.0)" },
        { borderColor: "rgba(239,68,68,0.6)" },
      ],
      { duration: 2000, iterations: Infinity, easing: "ease-in-out" }
    );
  });
}

/* ── Chip active transition ──────────────────────────────────────────────── */
function initChipTransitions() {
  document.querySelectorAll(".chip").forEach(chip => {
    chip.style.transition = "background 0.15s, border-color 0.15s, color 0.15s";
  });
}

/* ── Skeleton loader ──────────────────────────────────────────────────────── */
function showSkeleton(containerId) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `
    <div class="skeleton-wrap">
      ${Array(4).fill('<div class="skeleton-bar"></div>').join("")}
    </div>`;
}

function hideSkeleton(containerId) {
  const el = document.getElementById(containerId);
  if (el) el.querySelector(".skeleton-wrap")?.remove();
}

/* ── Section lazy-rendering ─────────────────────────────────────────────── */
function showSection(name) {
  // Hide all panels
  document.querySelectorAll(".section-panel").forEach(p => {
    p.style.display = "none";
    p.classList.remove("panel-active");
  });
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  const panel = document.getElementById("section-" + name);
  if (!panel) return;
  panel.style.display = "block";
  panel.classList.add("panel-active");

  // Mark nav item active
  const navItem = document.querySelector(`.nav-item[data-section="${name}"]`);
  if (navItem) navItem.classList.add("active");

  state.currentSection = name;

  // Lazy init on first visit
  if (!state.initialisedSections.has(name)) {
    state.initialisedSections.add(name);
    initSection(name);
  }

  // Panel entry animation
  if (!REDUCED_MOTION) {
    panel.animate(
      [{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "translateY(0)" }],
      { duration: 280, fill: "forwards", easing: "ease" }
    );
  }
}

function initSection(name) {
  switch (name) {
    case "dashboard":
      refreshDashboard();
      break;
    case "flow":
      loadSystemMap();
      break;
    case "logs":
      break; // log table already rendered from upload result
    case "incidents":
      loadIncidents();
      break;
    default:
      break;
  }
}

/* ── Main aggregate computation ─────────────────────────────────────────── */
function recomputeAggregate() {
  const ids = state.activeSessions;
  if (ids.length === 0) {
    state.aggregate = {};
    return;
  }

  let total = 0, errors = 0, warns = 0, latencies = [], apps = new Set();
  let goodRows = 0, warnRows = 0, errorRows = 0, allRows = [];

  for (const id of ids) {
    const s = state.sessions[id];
    if (!s) continue;
    total   += s.total   || 0;
    errors  += s.errors  || 0;
    warns   += s.warns   || 0;
    if (s.latency && s.latency > 0) latencies.push(s.latency);
    (s.apps || []).forEach(a => apps.add(a));
    (s.log_rows || []).forEach(r => {
      allRows.push(r);
      const lvl = (r.level || "").toUpperCase();
      if (lvl === "ERROR" || lvl === "FAILURE") errorRows++;
      else if (lvl === "WARN")  warnRows++;
      else                      goodRows++;
    });
  }

  const avgLat = latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;
  const health = errors === 0 ? 100 : Math.max(0, Math.round(100 - (errors / Math.max(total, 1)) * 100));

  state.aggregate = {
    total, errors, warns, latency: avgLat,
    health, apps: [...apps], log_rows: allRows,
    goodRows, warnRows, errorRows,
    p95:  computeP95(allRows),
    p99:  computeP99(allRows),
  };

  return state.aggregate;
}

function computeP95(rows) {
  const lats = rows.map(r => Number(r.latency) || 0).filter(v => v > 0).sort((a, b) => a - b);
  if (!lats.length) return 0;
  return lats[Math.floor(lats.length * 0.95)];
}

function computeP99(rows) {
  const lats = rows.map(r => Number(r.latency) || 0).filter(v => v > 0).sort((a, b) => a - b);
  if (!lats.length) return 0;
  return lats[Math.floor(lats.length * 0.99)];
}

/* ── Dashboard refresh ───────────────────────────────────────────────────── */
function refreshDashboard() {
  const agg = recomputeAggregate();
  if (!agg || !agg.total) return;

  // KPI tiles with countUp
  animateKPIs(agg);

  // Data-driven health donut
  updateHealthDonut(agg.goodRows || 0, agg.warnRows || 0, agg.errorRows || 0);

  // Trend chart
  const buckets = buildTimeBuckets(agg.log_rows || []);
  if (buckets.length > 0) renderTrendChart(buckets);

  // Alert pulse
  startAlertPulse();
}

/* ── Upload handler (called from upload form callback) ───────────────────── */
function onUploadSuccess(result, sessionId) {
  state.sessions[sessionId] = result;
  state.activeSessions      = [...new Set([...state.activeSessions, sessionId])];
  refreshDashboard();
  showSection("dashboard");
}

/* ── System map ──────────────────────────────────────────────────────────── */
async function loadSystemMap() {
  const container = document.getElementById("section-flow");
  if (!container) return;

  const env = document.getElementById("env-select")?.value || "PROD";
  showSkeleton("system-map-content");

  try {
    const res  = await fetch(`/api/v1/system-map?env=${encodeURIComponent(env)}`);
    const data = await res.json();
    hideSkeleton("system-map-content");
    renderSystemMap(data.apis || []);
    // Animate edges after render
    setTimeout(animateTopologyEdges, 100);
  } catch (err) {
    hideSkeleton("system-map-content");
    console.error("System map load failed", err);
  }
}

function renderSystemMap(apis) {
  const el = document.getElementById("system-map-content");
  if (!el) return;
  if (!apis.length) {
    el.innerHTML = '<p class="empty-state">Upload logs to see your system map.</p>';
    return;
  }
  // Rendering delegated to existing renderArchitectureGraph() in dashboard.html
  // This function triggers the topology SVG builder
  if (typeof window.renderArchitectureGraph === "function") {
    window.renderArchitectureGraph(apis);
  }
}

/* ── Incidents ────────────────────────────────────────────────────────────── */
async function loadIncidents() {
  // Incidents are computed from current aggregate — no extra fetch needed
  const agg = state.aggregate;
  const el  = document.getElementById("incidents-list");
  if (!el || !agg.errors) return;

  el.innerHTML = `<div class="incident-auto">
    <span class="badge-error">Auto-detected</span>
    ${agg.errors} error(s) across ${(agg.apps || []).length} app(s).
    Avg latency ${agg.latency}ms — P95 ${agg.p95}ms.
  </div>`;
}

/* ── Log table filtering ─────────────────────────────────────────────────── */
function quickLevel(level) {
  const input = document.getElementById("log-search-input");
  if (input) {
    input.value = level ? `level:${level}` : "";
    filterLogTable(input.value);
  }
  showSection("logs");
}

function filterLogTable(query) {
  const rows = document.querySelectorAll("#log-table-body tr");
  const term = (query || "").toLowerCase();
  rows.forEach(row => {
    row.style.display = (!term || row.textContent.toLowerCase().includes(term)) ? "" : "none";
  });
}

/* ── Session history reload ──────────────────────────────────────────────── */
async function reloadSession(sessionId) {
  try {
    const res    = await fetch(`/api/v1/sessions/${sessionId}/rows`);
    const result = await res.json();
    state.sessions[sessionId] = result;
    if (!state.activeSessions.includes(sessionId)) {
      state.activeSessions.push(sessionId);
    }
    refreshDashboard();
  } catch (err) {
    console.error("Session reload failed", err);
  }
}

/* ── Init ─────────────────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  initChipTransitions();

  // Restore sidebar collapse state
  const collapsed = localStorage.getItem("sidebar-collapsed") === "true";
  if (collapsed) document.body.classList.add("sidebar-collapsed");

  // Default section
  const hash = window.location.hash.replace("#", "") || "dashboard";
  showSection(hash);

  // Log search input
  const searchInput = document.getElementById("log-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", e => filterLogTable(e.target.value));
  }

  // Sidebar toggle
  const sidebarToggle = document.getElementById("sidebar-toggle");
  if (sidebarToggle) {
    sidebarToggle.addEventListener("click", () => {
      const collapsed = document.body.classList.toggle("sidebar-collapsed");
      localStorage.setItem("sidebar-collapsed", collapsed);
    });
  }

  // Nav items
  document.querySelectorAll(".nav-item[data-section]").forEach(item => {
    item.addEventListener("click", () => showSection(item.dataset.section));
  });
});

/* ── Expose globals for dashboard.html interop ───────────────────────────── */
window.ObserveX = {
  showSection,
  onUploadSuccess,
  reloadSession,
  quickLevel,
  refreshDashboard,
  loadSystemMap,
  state,
};
