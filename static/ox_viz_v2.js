/**
 * ObserveX Dashboard — Advanced Visualizations v2
 * Adds: Latency Percentile Chart · Status Code Distribution
 *       Per-App Error Heatmap · SLO Burn Rate · Error Rate Trend
 *
 * Injects itself after the existing signal-grid via monkey-patching renderVisualDashboard.
 * No external chart library required — pure SVG rendered inline.
 */

(function () {
  'use strict';

  /* ── Colour palette (matches ObserveX CSS vars) ────────────────────────── */
  const C = {
    ok:    '#22c55e',
    warn:  '#f59e0b',
    err:   '#ef4444',
    info:  '#818cf8',
    bg:    'rgba(31,31,53,0.92)',
    bd:    'rgba(148,163,184,0.12)',
    tx:    'rgba(226,232,240,1)',
    tx2:   'rgba(148,163,184,0.8)',
    tx3:   'rgba(100,116,139,0.9)',
    grad1: '#5a5ef7',
    grad2: '#ec4899',
  };

  /* ── Inject CSS once ────────────────────────────────────────────────────── */
  if (!document.getElementById('ox-viz-v2-css')) {
    const s = document.createElement('style');
    s.id = 'ox-viz-v2-css';
    s.textContent = `
      .ox-adv-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:18px 0}
      .ox-adv-grid .viz-panel{min-height:220px}
      .ox-wide{grid-column:1/-1}
      .ox-lat-bars{display:flex;flex-direction:column;gap:10px;margin-top:10px}
      .ox-lat-row{display:grid;grid-template-columns:52px 1fr 70px;gap:10px;align-items:center;font-size:13px}
      .ox-lat-track{height:12px;background:rgba(255,255,255,.04);border-radius:999px;overflow:hidden;border:1px solid ${C.bd}}
      .ox-lat-fill{height:100%;border-radius:999px;transition:width .4s ease}
      .ox-status-bars{display:flex;flex-direction:column;gap:10px;margin-top:10px}
      .ox-st-row{display:grid;grid-template-columns:52px 1fr 58px;gap:10px;align-items:center;font-size:13px}
      .ox-st-track{height:12px;background:rgba(255,255,255,.04);border-radius:999px;overflow:hidden;border:1px solid ${C.bd}}
      .ox-st-fill{height:100%;border-radius:999px}
      .ox-heatmap-wrap{overflow-x:auto;margin-top:10px}
      .ox-heatmap{border-collapse:collapse;width:100%;font-size:11px}
      .ox-heatmap th{padding:6px 10px;color:${C.tx3};font-weight:900;text-transform:uppercase;letter-spacing:.06em;text-align:left;border-bottom:1px solid ${C.bd}}
      .ox-heatmap td{padding:7px 10px;border-bottom:1px solid rgba(255,255,255,.04)}
      .ox-heatmap td.heat-ok {background:rgba(34,197,94,.14);color:${C.ok};font-weight:700}
      .ox-heatmap td.heat-warn{background:rgba(245,158,11,.14);color:${C.warn};font-weight:700}
      .ox-heatmap td.heat-err {background:rgba(239,68,68,.18);color:${C.err};font-weight:700}
      .ox-burn-wrap{display:flex;flex-direction:column;gap:10px;margin-top:10px}
      .ox-burn-row{display:grid;grid-template-columns:110px 1fr 62px;gap:10px;align-items:center;font-size:13px}
      .ox-burn-track{height:14px;background:rgba(255,255,255,.04);border-radius:999px;overflow:hidden;border:1px solid ${C.bd}}
      .ox-burn-fill{height:100%;border-radius:999px;transition:width .4s ease}
      .ox-err-trend{display:flex;align-items:flex-end;gap:4px;padding:10px 8px 2px;height:140px;
        border-radius:14px;background:linear-gradient(180deg,rgba(255,255,255,.02),transparent);
        border:1px solid ${C.bd};margin-top:10px}
      .ox-err-bar{flex:1;min-width:6px;border-radius:6px 6px 3px 3px;position:relative;cursor:pointer}
      .ox-err-bar:hover::after{content:attr(title);position:absolute;bottom:calc(100%+4px);left:50%;
        transform:translateX(-50%);background:#0f1020;border:1px solid rgba(168,85,247,.45);
        border-radius:8px;padding:4px 8px;white-space:nowrap;font-size:11px;color:${C.tx};z-index:999;pointer-events:none}
      .ox-sampled-badge{display:inline-block;background:rgba(245,158,11,.18);color:${C.warn};
        border:1px solid rgba(245,158,11,.4);border-radius:8px;font-size:11px;font-weight:900;
        letter-spacing:.06em;padding:3px 10px;margin-bottom:8px;text-transform:uppercase}
      @media(max-width:900px){.ox-adv-grid{grid-template-columns:1fr}}
    `;
    document.head.appendChild(s);
  }

  /* ── Mount panel container after signal-grid ───────────────────────────── */
  function ensurePanels() {
    if (document.getElementById('ox-adv-panels')) return;
    const anchor = document.querySelector('.signal-grid');
    if (!anchor) return;
    const wrap = document.createElement('div');
    wrap.id = 'ox-adv-panels';
    wrap.className = 'ox-adv-grid';
    wrap.innerHTML = `
      <div class="viz-panel" id="ox-lat-panel">
        <h3>Latency Percentile Distribution</h3>
        <div class="viz-sub">P50 · P75 · P90 · P95 · P99 across all ingested rows</div>
        <div id="ox-lat-body" class="ox-lat-bars"><div style="color:var(--tx3)">Upload logs to populate.</div></div>
      </div>
      <div class="viz-panel" id="ox-status-panel">
        <h3>HTTP Status Distribution</h3>
        <div class="viz-sub">Share of 2xx success, 4xx client errors, 5xx server faults</div>
        <div id="ox-status-body" class="ox-status-bars"><div style="color:var(--tx3)">Upload logs to populate.</div></div>
      </div>
      <div class="viz-panel ox-wide" id="ox-heatmap-panel">
        <h3>Per-Service Error Heatmap</h3>
        <div class="viz-sub">Rows · Errors · Warnings · Avg Latency · Error % — colour-coded by severity</div>
        <div id="ox-heatmap-body" class="ox-heatmap-wrap"><div style="color:var(--tx3)">Upload logs to populate.</div></div>
      </div>
      <div class="viz-panel" id="ox-slo-panel">
        <h3>SLO Error-Budget Burn</h3>
        <div class="viz-sub">Budget consumed based on 99.9% / 99.5% / 99% SLO targets</div>
        <div id="ox-slo-body" class="ox-burn-wrap"><div style="color:var(--tx3)">Upload logs to populate.</div></div>
      </div>
      <div class="viz-panel" id="ox-errtrend-panel">
        <h3>Error Rate Over Time</h3>
        <div class="viz-sub">Error % per time bucket — spike detection at a glance</div>
        <div id="ox-errtrend-body" class="ox-err-trend"><div style="color:var(--tx3);align-self:center">Upload logs to populate.</div></div>
      </div>
    `;
    anchor.after(wrap);
  }

  /* ── Percentile helper ─────────────────────────────────────────────────── */
  function pct(sorted, p) {
    if (!sorted.length) return 0;
    const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p / 100));
    return sorted[idx];
  }

  /* ── Render latency percentile bars ────────────────────────────────────── */
  function renderLatency(rows) {
    const el = document.getElementById('ox-lat-body');
    if (!el) return;
    const lats = rows.map(r => Number(r.latency || 0)).filter(Boolean).sort((a, b) => a - b);
    if (!lats.length) { el.innerHTML = '<div style="color:var(--tx3)">No latency data.</div>'; return; }
    const points = [[50,'P50'],[75,'P75'],[90,'P90'],[95,'P95'],[99,'P99']];
    const maxVal = pct(lats, 99) || 1;
    const colFor = v => v > 5000 ? C.err : v > 2000 ? C.warn : C.ok;
    el.innerHTML = points.map(([p, label]) => {
      const v = pct(lats, p);
      const pct_w = Math.max(3, Math.round(v / maxVal * 100));
      return `<div class="ox-lat-row">
        <span style="color:${C.tx3};font-weight:900">${label}</span>
        <div class="ox-lat-track"><div class="ox-lat-fill" style="width:${pct_w}%;background:${colFor(v)}"></div></div>
        <span style="color:${colFor(v)};font-weight:700">${v}ms</span>
      </div>`;
    }).join('');
  }

  /* ── Render status code distribution ───────────────────────────────────── */
  function renderStatusCodes(rows) {
    const el = document.getElementById('ox-status-body');
    if (!el) return;
    const buckets = { '2xx': 0, '4xx': 0, '5xx': 0, 'Other': 0 };
    rows.forEach(r => {
      const s = String(r.status || '');
      if (/^2/.test(s)) buckets['2xx']++;
      else if (/^4/.test(s)) buckets['4xx']++;
      else if (/^5/.test(s)) buckets['5xx']++;
      else if (s) buckets['Other']++;
    });
    const total = Object.values(buckets).reduce((a, b) => a + b, 0);
    if (!total) { el.innerHTML = '<div style="color:var(--tx3)">No HTTP status codes found.</div>'; return; }
    const cfg = [['2xx', C.ok], ['4xx', C.warn], ['5xx', C.err], ['Other', C.info]];
    el.innerHTML = cfg.map(([key, col]) => {
      const v = buckets[key];
      if (!v) return '';
      const pct_w = Math.max(2, Math.round(v / total * 100));
      return `<div class="ox-st-row">
        <span style="color:${col};font-weight:900">${key}</span>
        <div class="ox-st-track"><div class="ox-st-fill" style="width:${pct_w}%;background:${col}"></div></div>
        <span style="color:${C.tx2}">${v} <small style="color:${C.tx3}">(${pct_w}%)</small></span>
      </div>`;
    }).join('');
  }

  /* ── Render per-service heatmap ─────────────────────────────────────────── */
  function renderHeatmap(rows) {
    const el = document.getElementById('ox-heatmap-body');
    if (!el) return;
    const appMap = {};
    rows.forEach(r => {
      const a = r.app || 'unknown';
      if (!appMap[a]) appMap[a] = { rows: 0, errors: 0, warns: 0, lats: [] };
      appMap[a].rows++;
      if (r.level === 'ERROR' || r.level === 'FAILURE') appMap[a].errors++;
      if (r.level === 'WARN') appMap[a].warns++;
      if (r.latency) appMap[a].lats.push(Number(r.latency));
    });
    const apps = Object.entries(appMap).sort((a, b) => b[1].errors - a[1].errors).slice(0, 20);
    if (!apps.length) { el.innerHTML = '<div style="color:var(--tx3)">No app data.</div>'; return; }
    const heatClass = (errPct, avgLat) => {
      if (errPct > 5 || avgLat > 5000) return 'heat-err';
      if (errPct > 1 || avgLat > 2000) return 'heat-warn';
      return 'heat-ok';
    };
    el.innerHTML = `<table class="ox-heatmap">
      <thead><tr>
        <th>Service</th><th>Rows</th><th>Errors</th><th>Warnings</th><th>Avg Latency</th><th>Error %</th>
      </tr></thead>
      <tbody>
        ${apps.map(([name, v]) => {
          const avg = v.lats.length ? Math.round(v.lats.reduce((a, b) => a + b, 0) / v.lats.length) : 0;
          const errPct = v.rows ? Math.round(v.errors / v.rows * 1000) / 10 : 0;
          const cls = heatClass(errPct, avg);
          return `<tr>
            <td style="color:${C.tx};font-weight:700">${name}</td>
            <td>${v.rows.toLocaleString()}</td>
            <td class="${cls}">${v.errors}</td>
            <td class="${v.warns > 0 ? 'heat-warn' : ''}">${v.warns}</td>
            <td class="${avg > 5000 ? 'heat-err' : avg > 2000 ? 'heat-warn' : ''}">${avg ? avg + 'ms' : '—'}</td>
            <td class="${cls}">${errPct}%</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>`;
  }

  /* ── Render SLO burn-rate ───────────────────────────────────────────────── */
  function renderSloBurn(totalRows, errorRows) {
    const el = document.getElementById('ox-slo-body');
    if (!el) return;
    if (!totalRows) { el.innerHTML = '<div style="color:var(--tx3)">Upload logs to calculate.</div>'; return; }
    const errRate = errorRows / totalRows;
    // SLO targets: allowed error budget = 1 - SLO
    const slos = [
      { label: 'SLO 99.9%', budget: 0.001 },
      { label: 'SLO 99.5%', budget: 0.005 },
      { label: 'SLO 99.0%', budget: 0.010 },
    ];
    el.innerHTML = slos.map(({ label, budget }) => {
      const burn = Math.min(200, Math.round(errRate / budget * 100)); // % of budget consumed
      const col = burn >= 100 ? C.err : burn >= 50 ? C.warn : C.ok;
      return `<div class="ox-burn-row">
        <span style="color:${C.tx3};font-weight:900">${label}</span>
        <div class="ox-burn-track"><div class="ox-burn-fill" style="width:${Math.min(100, burn)}%;background:${col}"></div></div>
        <span style="color:${col};font-weight:700">${burn > 200 ? '>200' : burn}%</span>
      </div>
      <div style="font-size:11px;color:${C.tx3};margin-top:-6px;margin-bottom:2px;padding-left:2px">
        ${burn >= 100 ? '🔴 Budget exhausted' : burn >= 50 ? '🟡 Budget at risk' : '🟢 Within budget'}
        — error rate ${(errRate * 100).toFixed(2)}%
      </div>`;
    }).join('');
  }

  /* ── Render error-rate trend ────────────────────────────────────────────── */
  function renderErrTrend(timeline) {
    const el = document.getElementById('ox-errtrend-body');
    if (!el) return;
    const buckets = (timeline || []).slice(-32);
    if (!buckets.length) { el.innerHTML = '<div style="color:var(--tx3);align-self:center">No timeline data.</div>'; return; }
    const maxErrPct = Math.max(1, ...buckets.map(b => b.total ? (b.errors / b.total * 100) : 0));
    el.innerHTML = buckets.map(b => {
      const errPct = b.total ? (b.errors / b.total * 100) : 0;
      const h = Math.max(6, Math.round(errPct / maxErrPct * 100));
      const col = errPct > 5 ? C.err : errPct > 1 ? C.warn : C.info;
      return `<div class="ox-err-bar" style="height:${h}%;background:${col};opacity:0.85"
        title="${b.time ? b.time.slice(11, 16) : ''} · ${errPct.toFixed(1)}% error rate (${b.errors||0}/${b.total||0})"></div>`;
    }).join('');
  }

  /* ── Render sampled-file warning banner ─────────────────────────────────── */
  function renderSampledBanner(d) {
    let banner = document.getElementById('ox-sampled-banner');
    const wasSampled = d.was_sampled || d.sampled_rows || false;
    if (!wasSampled) { if (banner) banner.remove(); return; }
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'ox-sampled-banner';
      banner.style.cssText = 'margin:0 0 12px;';
      const hero = document.querySelector('#sec-dashboard .hero');
      if (hero) hero.after(banner);
    }
    const limit = d.sampled_rows || 80000;
    banner.innerHTML = `<span class="ox-sampled-badge">⚡ Large file sampled</span>
      <span style="color:var(--tx2);font-size:13px;margin-left:10px">
        File exceeds ${limit.toLocaleString()}-row analysis limit. First ${limit.toLocaleString()} rows parsed in full;
        remaining rows are counted but not individually analysed.
        Set <code>OBSERVEX_MAX_ROWS</code> env var to increase.
      </span>`;
  }

  /* ── Main hook — patch renderVisualDashboard ────────────────────────────── */
  const _orig = window.renderVisualDashboard;
  window.renderVisualDashboard = function (d) {
    if (_orig) _orig.call(this, d);
    ensurePanels();
    const rows = (typeof _allRows !== 'undefined' ? _allRows : []) || [];
    renderLatency(rows);
    renderStatusCodes(rows);
    renderHeatmap(rows);
    renderSloBurn(d.total || 0, d.errors || 0);
    renderErrTrend(d.timeline_buckets || []);
    renderSampledBanner(d);
  };

  console.info('[ObserveX viz-v2] Advanced dashboard panels registered ✓');
})();
