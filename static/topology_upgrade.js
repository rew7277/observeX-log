// ═══════════════════════════════════════════════════════════════════════════
//  ObserveX Topology Engine v2 — Drop-in upgrade for dashboard.js
//  Replace renderArchitectureSvg, renderTraceWaterfall, renderCallMatrix
//  and add new interactive features on top.
//  Include this file AFTER dashboard.js to override the old functions.
// ═══════════════════════════════════════════════════════════════════════════

// ─── Tier colour config ───────────────────────────────────────────────────
const TIER_CFG = {
  Client:   { fill:'rgba(16,185,129,.20)',  stroke:'rgba(16,185,129,.60)',  glow:'rgba(16,185,129,.35)',  icon:'◎' },
  Gateway:  { fill:'rgba(99,102,241,.24)',  stroke:'rgba(99,102,241,.65)',  glow:'rgba(99,102,241,.35)',  icon:'⬡' },
  API:      { fill:'rgba(90,94,247,.26)',   stroke:'rgba(90,94,247,.70)',   glow:'rgba(90,94,247,.40)',   icon:'⬡' },
  Service:  { fill:'rgba(139,92,246,.22)',  stroke:'rgba(139,92,246,.60)',  glow:'rgba(139,92,246,.35)',  icon:'⬡' },
  External: { fill:'rgba(245,158,11,.20)',  stroke:'rgba(245,158,11,.60)',  glow:'rgba(245,158,11,.35)',  icon:'⬡' },
  Data:     { fill:'rgba(59,130,246,.20)',  stroke:'rgba(59,130,246,.60)',  glow:'rgba(59,130,246,.35)',  icon:'⬡' },
};
const HEALTH_CFG = {
  critical: { fill:'rgba(239,68,68,.28)',  stroke:'rgba(239,68,68,.75)',  pulse:true  },
  warn:     { fill:'rgba(245,158,11,.22)', stroke:'rgba(245,158,11,.65)', pulse:false },
  ok:       { fill:null, stroke:null, pulse:false },
};

// ─── Layout constants ─────────────────────────────────────────────────────
const NW=160, NH=66, COL_PAD=96, COL_GAP=200, ROW_GAP=96;

// ─── Helper ───────────────────────────────────────────────────────────────
function _esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function _trunc(s,n){ s=String(s||''); return s.length>n?s.slice(0,n-1)+'…':s; }

// ─── Node position calculator ─────────────────────────────────────────────
function _layoutNodes(nodes){
  const ALL=['Client','Gateway','API','Service','External','Data'];
  const activeTiers=ALL.filter(t=>nodes.some(n=>n.tier===t));
  const groups={};
  activeTiers.forEach(t=>{ groups[t]=nodes.filter(n=>n.tier===t); });
  const maxPer=Math.max(1,...activeTiers.map(t=>groups[t].length));
  const W=Math.max(980, COL_PAD*2+activeTiers.length*COL_GAP);
  const H=Math.max(520, maxPer*ROW_GAP+160);
  const pos={};
  activeTiers.forEach((t,ti)=>{
    const g=groups[t]||[];
    const colX=COL_PAD+ti*(W-COL_PAD*2)/(activeTiers.length-1||1);
    g.forEach((n,i)=>{
      const totalH=(g.length-1)*ROW_GAP;
      const startY=(H-totalH)/2;
      const cx=colX, cy=startY+i*ROW_GAP+NH/2;
      pos[n.id||n.name]={ x:cx-NW/2, y:cy-NH/2, cx, cy, w:NW, h:NH };
    });
  });
  return { pos, W, H, activeTiers, groups };
}

// ─── SVG defs ─────────────────────────────────────────────────────────────
function _buildDefs(hasError){
  return `<defs>
    <filter id="glow-ok"  x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-err" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="160%">
      <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="rgba(0,0,0,.4)"/>
    </filter>
    <marker id="arr"     markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="rgba(167,139,250,.80)"/></marker>
    <marker id="arr-err" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="rgba(239,68,68,.90)"/></marker>
    <marker id="arr-ok"  markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="rgba(16,185,129,.80)"/></marker>
    <style>
      @keyframes topo-pulse{0%,100%{opacity:.85}50%{opacity:1}}
      @keyframes dash-flow{to{stroke-dashoffset:-16}}
      .topo-edge-animated{stroke-dasharray:5 4;animation:dash-flow 1.4s linear infinite}
      .topo-node-critical rect{animation:topo-pulse .9s ease-in-out infinite}
      .topo-node:hover rect{filter:brightness(1.35) drop-shadow(0 0 10px currentColor)}
      .topo-node{cursor:pointer;transition:opacity .15s}
      .topo-edge{fill:none;stroke-width:2;transition:stroke-width .15s,opacity .15s}
      .topo-edge:hover{stroke-width:3.5;opacity:1!important}
      .topo-edge.faded{opacity:.18}
    </style>
  </defs>`;
}

// ─── Tier swimlane background ─────────────────────────────────────────────
function _buildSwimlanes(activeTiers, W, H){
  return activeTiers.map((t,ti)=>{
    const colX=COL_PAD+ti*(W-COL_PAD*2)/(activeTiers.length-1||1);
    const cfg=TIER_CFG[t]||TIER_CFG.API;
    const laneW=Math.round((W-COL_PAD*2)/(activeTiers.length||1));
    const lx=colX-laneW/2;
    return `<rect x="${lx}" y="34" width="${laneW}" height="${H-38}"
      fill="${cfg.fill.replace('.20)','.06)').replace('.24)','.08)').replace('.26)','.08)').replace('.22)','.06)')}"
      rx="0" stroke="none"/>
      <text x="${colX}" y="22" text-anchor="middle"
        style="font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.12em;fill:${cfg.stroke.replace('.60)','.55)').replace('.70)','.55)').replace('.65)','.55)')};font-family:inherit">${_esc(t)}</text>`;
  }).join('');
}

// ─── Dividers ─────────────────────────────────────────────────────────────
function _buildDividers(activeTiers, W, H){
  return activeTiers.slice(1).map((t,ti)=>{
    const x=COL_PAD+(ti+0.5)*(W-COL_PAD*2)/(activeTiers.length-1||1);
    return `<line x1="${x}" y1="30" x2="${x}" y2="${H}" stroke="rgba(255,255,255,.05)" stroke-width="1"/>`;
  }).join('');
}

// ─── Edge paths ───────────────────────────────────────────────────────────
function _buildEdge(e, pos, maxCount){
  const a=pos[e.from], b=pos[e.to]; if(!a||!b) return '';
  const isErr=e.errors>0, isMain=e.count>=maxCount*.6;
  const markerId=isErr?'arr-err':isMain?'arr-ok':'arr';
  const strokeCol=isErr?'rgba(239,68,68,.85)':isMain?'rgba(16,185,129,.70)':'rgba(167,139,250,.65)';
  const sw=isErr?2.6:isMain?2.4:1.8;
  const x1=a.cx+NW/2, y1=a.cy;
  const x2=b.cx-NW/2, y2=b.cy;
  const tip=`${_esc(e.from)} → ${_esc(e.to)}\n${e.count||0} calls · ${e.errors||0} errors · ${e.avg_latency_ms||0}ms`;
  let path;
  if(x1>=x2-12){
    const arcY=Math.min(y1,y2)-60;
    path=`M${x1},${y1} C${x1+48},${arcY} ${x2-48},${arcY} ${x2},${y2}`;
  } else {
    const cx=(x1+x2)/2;
    path=`M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}`;
  }
  const animClass=isMain?' topo-edge-animated':'';
  return `<path class="topo-edge${animClass}" d="${path}"
    stroke="${strokeCol}" stroke-width="${sw}" fill="none"
    marker-end="url(#${markerId})"
    data-from="${_esc(e.from)}" data-to="${_esc(e.to)}"
    data-tip="${_esc(tip)}"/>`;
}

// ─── Edge label (latency badge on midpoint) ────────────────────────────────
function _buildEdgeLabel(e, pos){
  const a=pos[e.from], b=pos[e.to]; if(!a||!b) return '';
  if(!e.avg_latency_ms) return '';
  const mx=(a.cx+b.cx)/2, my=(a.cy+b.cy)/2-16;
  const lat=e.avg_latency_ms>=1000?(e.avg_latency_ms/1000).toFixed(1)+'s':e.avg_latency_ms+'ms';
  const col=e.avg_latency_ms>3000?'rgba(239,68,68,.75)':e.avg_latency_ms>800?'rgba(245,158,11,.75)':'rgba(100,220,130,.60)';
  return `<g>
    <rect x="${mx-22}" y="${my-9}" width="44" height="16" rx="8" fill="${col}" opacity=".85"/>
    <text x="${mx}" y="${my+3}" text-anchor="middle" style="font-size:9px;font-weight:900;fill:#fff;font-family:monospace">${_esc(lat)}</text>
  </g>`;
}

// ─── Node card ────────────────────────────────────────────────────────────
function _buildNode(n, p){
  if(!p) return '';
  const tier=n.tier||'API';
  const cfg=TIER_CFG[tier]||TIER_CFG.API;
  const hcfg=HEALTH_CFG[n.health||'ok'];
  const fill=hcfg.fill||cfg.fill;
  const stroke=hcfg.stroke||cfg.stroke;
  const pulseClass=hcfg.pulse?' topo-node-critical':'';
  const filterAttr=n.health==='critical'?'filter="url(#glow-err)"':n.health==='warn'?'filter="url(#glow-ok)"':'filter="url(#shadow)"';
  const label=_trunc(n.name,24);
  const errLabel=n.errors?`⚠ ${n.errors} err`:'';
  const latLabel=n.avg_latency_ms?`${n.avg_latency_ms}ms`:'';
  const statsText=[errLabel,latLabel].filter(Boolean).join(' · ')||tier;
  const tip=`${_esc(n.name)}\nTier: ${_esc(tier)}\nRequests: ${n.count||0}\nErrors: ${n.errors||0}\nAvg latency: ${n.avg_latency_ms||0}ms\nHealth: ${n.health||'ok'}`;
  const onClick=`topologyNodeClick(${JSON.stringify(n.name)})`;
  return `<g class="topo-node${pulseClass}" data-node="${_esc(n.name)}" data-tip="${_esc(tip)}" onclick="${onClick}">
    <rect x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="16"
      fill="${fill}" stroke="${stroke}" stroke-width="1.5" ${filterAttr}/>
    <text x="${p.cx}" y="${p.y+22}" text-anchor="middle"
      style="font-size:12px;font-weight:800;fill:#f1f5f9;font-family:inherit">${_esc(label)}</text>
    <text x="${p.cx}" y="${p.y+40}" text-anchor="middle"
      style="font-size:10px;fill:rgba(203,213,225,.65);font-family:inherit">${_esc(statsText)}</text>
    ${n.health==='critical'?`<circle cx="${p.x+NW-14}" cy="${p.y+14}" r="5" fill="rgba(239,68,68,.9)"/>`:n.health==='warn'?`<circle cx="${p.x+NW-14}" cy="${p.y+14}" r="5" fill="rgba(245,158,11,.9)"/>`:''}
  </g>`;
}

// ─── Flow direction normalization (global) ────────────────────────────────
// Ensures Response Exit is ALWAYS the last node — never accidentally first.
// Call this on any flow array before rendering or building edges.
function _normalizeFlowOrder(nodes){
  const cleaned = (nodes||[]).filter(Boolean);
  const responseIdx = cleaned.findIndex(n =>
    /response\s*exit|response\s*out|exit/i.test(String(n||''))
  );
  if(responseIdx !== -1 && responseIdx !== cleaned.length - 1){
    const responseNode = cleaned.splice(responseIdx, 1)[0];
    cleaned.push(responseNode);
  }
  return cleaned;
}

// ─── Client-side topology synthesis from active uploaded rows ───────────────
function _topoLabelFromToken(s){
  s = String(s || '').split('?')[0]
    .replace(/^https?:\/\//i, '')
    .replace(/\..*$/, '')
    .replace(/\/.*$/, '');
  s = s.replace(/[-_]+/g, ' ').replace(/\b(api|svc|service)\b/ig, '').trim();
  return s.split(/\s+/).filter(Boolean).map(w => /^(kyc|cbs|lms|upi|bbps)$/i.test(w) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ').slice(0, 80);
}
function _topoRowSignals(rows, ep){
  const text = (rows || []).slice(0, 1200).map(r => [r.message, r.flow, r.app, r.endpoint].filter(Boolean).join(' ')).join('\n');
  const found = [];
  const add = x => { if (x && !found.some(y => y.toLowerCase() === String(x).toLowerCase())) found.push(x); };
  const checks = [
    [/\bkyc\b|aadhaar|aadhar|pan.?verify|ckyc/i, 'KYC Provider'],
    [/credit.?bureau|cibil|experian|equifax|crif/i, 'Credit Bureau'],
    [/\bcbs\b|core.?banking|finacle|flexcube|fcubs/i, 'CBS / Core Banking'],
    [/\blms\b|loan.?management|loan.?details/i, 'LMS'],
    [/\bbbps\b|bill.?payment/i, 'BBPS'], [/\bsetu\b/i, 'Setu'], [/\bupi\b|vpa/i, 'UPI Gateway'],
    [/salesforce|sfdc/i, 'Salesforce'], [/kafka|event.?bus|message.?broker/i, 'Message Broker'],
    [/redis/i, 'Redis Cache'], [/oracle|mysql|postgres|mongodb|dynamodb/i, 'Database']
  ];
  checks.forEach(([re, label]) => { if (re.test(text)) add(label); });
  const urlRe = /https?:\/\/([^\/\s"'?,;]+)|(?:target|service|downstream|dependency|host|baseUrl|url|uri)\s*[:=]\s*["']?([^\s"',;{}]+)/ig;
  let m;
  while ((m = urlRe.exec(text))) {
    const label = _topoLabelFromToken(m[1] || m[2] || '');
    if (label && !/^(Http|Https|Localhost|Request|Response|Api|Www)$/i.test(label)) add(label);
  }
  if (found.includes('Credit Bureau')) ['Credit Score', 'CRIF SMS'].forEach(x => { const i = found.indexOf(x); if (i >= 0) found.splice(i, 1); });
  return found.slice(0, 8);
}
function _buildClientTopologyFromRows(ep, arch){
  const rows = (window._allRows || []); if (!rows.length) return null;
  const epText = String(ep?.endpoint || arch?.endpoint || '').toLowerCase().replace(/^\//, '');
  let scoped = rows.filter(r => !epText || [r.endpoint, r.flow, r.api, r.app, r.message].some(v => String(v || '').toLowerCase().includes(epText)));
  if (scoped.length < 3) scoped = rows;
  const first = (arch?.simple_flow && arch.simple_flow[0]) || ep?.api || ep?.app || scoped.find(r => r.app)?.app || 'Application';
  let flow = [first];
  const method = (arch?.method || ep?.method || '').toUpperCase();
  const endpoint = arch?.endpoint || ep?.endpoint || '';
  if (method && endpoint && endpoint !== '/') flow.push(method + ' ' + endpoint);
  _topoRowSignals(scoped, ep).forEach(x => flow.push(x));
  flow.push('Response');
  flow = _normalizeFlowOrder(flow.filter((x, i, a) => x && a.findIndex(y => String(y).toLowerCase() === String(x).toLowerCase()) === i));
  if (flow.length < 3) return null;
  const errors = scoped.filter(r => ['ERROR', 'FAILURE'].includes(String(r.level || '').toUpperCase())).length;
  const lats = scoped.map(r => Number(r.latency || 0)).filter(Boolean);
  const avg = lats.length ? Math.round(lats.reduce((a, b) => a + b, 0) / lats.length) : 0;
  const tierOf = s => { const low = String(s).toLowerCase(); if (low === 'response') return 'Client'; if (/^(get|post|put|delete|patch) /.test(low)) return 'Gateway'; if (/database|redis|oracle|mysql|postgres|mongo|dynamo/.test(low)) return 'Data'; if (/salesforce|bureau|cbs|core|lms|provider|gateway|bbps|setu|upi|message broker/.test(low)) return 'External'; return flow.indexOf(s) === 0 ? 'API' : 'Service'; };
  const nodes = flow.map((name, i) => ({ id: name, name, tier: tierOf(name), count: scoped.length, errors: (i === flow.length - 2 ? errors : 0), warns: 0, avg_latency_ms: (i > 0 && i < flow.length - 1 ? avg : 0), health: errors && i === flow.length - 2 ? 'critical' : 'ok' }));
  const edges = flow.slice(0, -1).map((from, i) => ({ from, to: flow[i + 1], count: Math.max(1, scoped.length), errors: (i === flow.length - 3 ? errors : 0), avg_latency_ms: i ? avg : 0, label: 'calls', error_rate: Math.round(errors / Math.max(1, scoped.length) * 1000) / 10 }));
  return { nodes, edges, simple_flow: flow, endpoint: endpoint || '/', method, hints: ['Client-side topology synthesis used active uploaded rows to enrich sparse backend flow.'] };
}

// ─── MAIN: renderArchitectureSvg (replaces old version) ───────────────────
function renderArchitectureSvg(ep){
  let arch=ep.architecture||{};
  const sparse=!(arch.nodes||[]).length || ((arch.simple_flow||[]).length<=3);
  const clientArch=sparse ? _buildClientTopologyFromRows(ep, arch) : null;
  if(clientArch){ arch=Object.assign({}, arch, clientArch); ep.architecture=arch; }
  let nodes=arch.nodes||[], edges=arch.edges||[];

  // Fallback: render clean pill-chain if no graph nodes
  if(!nodes.length){
    let flow=arch.simple_flow||ep.flow_steps||[];
    if(!flow.length){
      setHTML('flow-diagram','<div style="color:var(--tx3);padding:20px">No topology detected for this endpoint. Re-upload logs to rebuild.</div>');
      return;
    }
    // Normalize: Response Exit must be last, never first
    flow = _normalizeFlowOrder(flow);
    _renderCleanFlowV2(flow, ep);
    return;
  }

  const { pos, W, H, activeTiers } = _layoutNodes(nodes);
  const maxCount=Math.max(1,...edges.map(e=>e.count||1));

  const defs=_buildDefs(edges.some(e=>e.errors>0));
  const swimlanes=_buildSwimlanes(activeTiers,W,H);
  const dividers=_buildDividers(activeTiers,W,H);
  const edgeSvg=edges.map(e=>_buildEdge(e,pos,maxCount)).join('');
  const edgeLabels=edges.map(e=>_buildEdgeLabel(e,pos)).join('');
  const nodeSvg=nodes.map(n=>_buildNode(n,pos[n.id||n.name])).join('');

  // Mini legend
  const legendItems=['ok','warn','critical'].map(h=>{
    const c=HEALTH_CFG[h]; const labels={ok:'Healthy',warn:'Warning',critical:'Critical'};
    return `<g><rect width="10" height="10" rx="2" fill="${c.fill||'rgba(90,94,247,.26)'}" stroke="${c.stroke||'rgba(90,94,247,.70)'}"/><text x="14" y="9" style="font-size:9px;fill:rgba(203,213,225,.7);font-family:inherit">${labels[h]}</text></g>`;
  });
  const legend=`<g transform="translate(${W-160},${H-30})" style="cursor:default">
    ${legendItems.map((l,i)=>`<g transform="translate(${i*52},0)">${l}</g>`).join('')}
  </g>`;

  const svg=`<svg class="arch-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMin meet"
    style="height:${H}px;cursor:crosshair" id="topo-svg">
    ${defs}
    ${swimlanes}
    ${dividers}
    ${edgeSvg}
    ${edgeLabels}
    ${nodeSvg}
    ${legend}
  </svg>`;

  setHTML('flow-diagram', svg + _buildTopoControls());
  _bindTopoInteractions();
}

// ─── Clean flow V2 (rich pills with tier colour + stats) ──────────────────
function _renderCleanFlowV2(flow, ep){
  const arch=ep.architecture||{};
  const tierOf=(step)=>{
    const low=(step||'').toLowerCase();
    if(low==='client'||low==='response') return 'Client';
    if(low.startsWith('get ')||low.startsWith('post ')||low.startsWith('put ')||low.startsWith('delete ')||low.startsWith('patch ')) return 'Gateway';
    if(low.includes('salesforce')||low.includes('gupshup')||low.includes('kotak')||low.includes('lms')||low.includes('core')||low.includes('html/pdf')||low.includes('external')) return 'External';
    if(low.includes('db')||low.includes('database')||low.includes('cache')||low.includes('redis')) return 'Data';
    return 'API';
  };
  const cards=flow.map((step,i)=>{
    const tier=tierOf(step);
    const cfg=TIER_CFG[tier]||TIER_CFG.API;
    const border=`border:1.5px solid ${cfg.stroke}`;
    const bg=`background:${cfg.fill}`;
    return `<div class="clean-flow-step ${tier.toLowerCase()}"
      style="${bg};${border};border-radius:18px;padding:13px 16px;min-width:148px;max-width:210px;position:relative"
      title="${_esc(step)}">
      <div class="clean-flow-index" style="background:${cfg.stroke.replace('.60)',',.22)').replace('.70)','.22)').replace('.80)','.22)')};color:${cfg.stroke};border:1px solid ${cfg.stroke}">${i+1}</div>
      <b style="font-size:12px;color:#f1f5f9;display:block;word-break:break-word;line-height:1.3;margin-top:6px">${_esc(step)}</b>
      <span style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:rgba(203,213,225,.55);display:block;margin-top:6px">${tier}</span>
    </div>`;
  }).join('<div class="clean-flow-arrow" style="font-size:22px;color:rgba(167,139,250,.75);font-weight:900;flex-shrink:0">→</div>');

  const hints=(arch.hints||[]);
  const hintHTML=hints.length?`<div style="margin-top:16px;color:var(--tx3);font-size:12px;line-height:1.6">${hints.map(h=>'• '+_esc(h)).join('<br>')}</div>`:'';

  setHTML('flow-diagram',`<div class="clean-flow-wrap">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <div style="font-weight:900;font-size:13px;color:var(--tx)">Execution topology</div>
      <span style="font-size:11px;color:var(--tx3);background:var(--sf2);border:1px solid var(--bd2);border-radius:999px;padding:4px 10px">${flow.length} stages</span>
    </div>
    <div class="clean-flow-lane" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">${cards}</div>
    ${hintHTML}
  </div>`);
}

// ─── Topology toolbar controls ─────────────────────────────────────────────
function _buildTopoControls(){
  return `<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px;padding:0 4px">
    <button class="btn btn-ghost btn-sm" onclick="topoFilterHealth('all')" id="topo-btn-all" style="font-size:11px;border-color:rgba(167,139,250,.5)">All nodes</button>
    <button class="btn btn-ghost btn-sm" onclick="topoFilterHealth('critical')" id="topo-btn-critical" style="font-size:11px">⚠ Critical only</button>
    <button class="btn btn-ghost btn-sm" onclick="topoFilterHealth('warn')" id="topo-btn-warn" style="font-size:11px">⚡ Warnings</button>
    <button class="btn btn-ghost btn-sm" onclick="topoZoom('in')" style="font-size:11px">＋ Zoom</button>
    <button class="btn btn-ghost btn-sm" onclick="topoZoom('out')" style="font-size:11px">－ Zoom</button>
    <button class="btn btn-ghost btn-sm" onclick="topoZoom('reset')" style="font-size:11px">⟳ Reset</button>
    <span id="topo-node-info" style="font-size:11px;color:var(--tx3);margin-left:4px">Click a node to inspect</span>
  </div>`;
}

// ─── Topology interactivity ────────────────────────────────────────────────
let _topoZoom=1, _topoFilter='all';

function _bindTopoInteractions(){
  // Tooltip
  const tip=document.getElementById('arch-tooltip');
  document.querySelectorAll('[data-tip]').forEach(el=>{
    el.onmousemove=e=>{
      if(!tip)return;
      tip.style.display='block';
      tip.style.left=(e.clientX+14)+'px';
      tip.style.top=(e.clientY+14)+'px';
      tip.innerHTML=el.getAttribute('data-tip').replace(/\n/g,'<br>');
    };
    el.onmouseleave=()=>{ if(tip)tip.style.display='none'; };
  });

  // Edge hover: highlight connected nodes, fade others
  document.querySelectorAll('.topo-edge').forEach(edge=>{
    edge.addEventListener('mouseenter',()=>{
      const from=edge.dataset.from, to=edge.dataset.to;
      document.querySelectorAll('.topo-node').forEach(n=>{
        const name=n.dataset.node;
        n.style.opacity=(name===from||name===to)?'1':'0.35';
      });
      document.querySelectorAll('.topo-edge').forEach(e=>{
        e.classList.toggle('faded', e!==edge);
      });
    });
    edge.addEventListener('mouseleave',()=>{
      document.querySelectorAll('.topo-node').forEach(n=>n.style.opacity='');
      document.querySelectorAll('.topo-edge').forEach(e=>e.classList.remove('faded'));
    });
  });
}

function topologyNodeClick(name){
  const info=document.getElementById('topo-node-info');
  const ep=typeof _selectedEndpoint!=='undefined'?_selectedEndpoint:{};
  const arch=ep.architecture||{};
  const node=(arch.nodes||[]).find(n=>(n.id||n.name)===name);
  if(!node||!info) return;
  const connectedEdges=(arch.edges||[]).filter(e=>e.from===name||e.to===name);
  info.innerHTML=`<b style="color:var(--tx)">${_esc(name)}</b>
    &nbsp;·&nbsp;Tier: ${_esc(node.tier)}
    &nbsp;·&nbsp;${node.count||0} reqs
    &nbsp;·&nbsp;<span style="color:${node.errors?'var(--rd)':'var(--gn)'}">${node.errors||0} err</span>
    &nbsp;·&nbsp;${node.avg_latency_ms||0}ms
    &nbsp;·&nbsp;${connectedEdges.length} edge(s)`;
  // Highlight node in SVG
  document.querySelectorAll('.topo-node').forEach(el=>{
    el.style.opacity=el.dataset.node===name?'1':'0.30';
  });
  document.querySelectorAll('.topo-edge').forEach(e=>{
    const active=(e.dataset.from===name||e.dataset.to===name);
    e.classList.toggle('faded',!active);
  });
}

function topoFilterHealth(mode){
  _topoFilter=mode;
  ['all','critical','warn'].forEach(m=>{
    const btn=document.getElementById('topo-btn-'+m);
    if(btn) btn.style.borderColor=m===mode?'rgba(167,139,250,.75)':'';
  });
  document.querySelectorAll('.topo-node').forEach(el=>{
    const ep=typeof _selectedEndpoint!=='undefined'?_selectedEndpoint:{};
    const node=((ep.architecture||{}).nodes||[]).find(n=>(n.id||n.name)===el.dataset.node);
    const health=(node||{}).health||'ok';
    if(mode==='all') el.style.opacity='';
    else if(mode==='critical') el.style.opacity=health==='critical'?'1':'0.18';
    else if(mode==='warn')     el.style.opacity=(health==='critical'||health==='warn')?'1':'0.18';
  });
}

function topoZoom(dir){
  const svg=document.getElementById('topo-svg'); if(!svg)return;
  if(dir==='in')        _topoZoom=Math.min(_topoZoom*1.2,3);
  else if(dir==='out')  _topoZoom=Math.max(_topoZoom/1.2,0.4);
  else                  _topoZoom=1;
  svg.style.transform=`scale(${_topoZoom})`;
  svg.style.transformOrigin='top left';
}

// ─── Enhanced Trace Waterfall ─────────────────────────────────────────────
function renderTraceWaterfall(ep){
  const traces=(ep.architecture?.traces)||[];
  const panel=document.getElementById('arch-waterfall'); if(!panel)return;

  if(!traces.length){
    panel.innerHTML='<div style="color:var(--tx3);padding:24px;text-align:center">No trace waterfall detected for this endpoint.<br><span style="font-size:12px">Upload logs with trace/event IDs to generate hop-by-hop reconstruction.</span></div>';
    return;
  }

  // Sort: errors first, then by hop count
  const sorted=[...traces].sort((a,b)=>b.errors-a.errors||b.rows.length-a.rows.length);
  const maxLat=Math.max(1,...sorted.flatMap(t=>(t.rows||[]).map(r=>r.latency||0)));

  panel.innerHTML=sorted.map((t,idx)=>{
    const hops=t.rows||[];
    const errCount=t.errors||0;
    const totalLat=hops.reduce((s,r)=>s+(r.latency||0),0)||t.latency||0;
    const health=errCount?'critical':totalLat>3000?'warn':'ok';
    const borderCol=health==='critical'?'rgba(239,68,68,.55)':health==='warn'?'rgba(245,158,11,.45)':'rgba(167,139,250,.25)';
    const hopPills=hops.slice(0,8).map((r,ri)=>{
      const isErr=/ERROR|FAILURE/i.test(r.level);
      const latW=totalLat>0?Math.max(4,Math.round((r.latency||0)/totalLat*100)):4;
      return `<div style="display:flex;flex-direction:column;align-items:center;gap:3px">
        <span style="font-size:10px;background:${isErr?'rgba(239,68,68,.18)':'rgba(90,94,247,.14)'};border:1px solid ${isErr?'rgba(239,68,68,.4)':'rgba(167,139,250,.28)'};border-radius:999px;padding:3px 8px;color:var(--tx2);white-space:nowrap">${_esc(r.service||'—')}</span>
        ${r.latency?`<div style="width:${latW}px;height:3px;background:${isErr?'rgba(239,68,68,.6)':'rgba(167,139,250,.5)'};border-radius:2px;max-width:60px"></div>`:''}
      </div>`;
    }).join('<span style="color:var(--tx3);align-self:center;font-size:12px">→</span>');

    return `<div class="trace-card" style="border-color:${borderCol};padding:14px;margin-bottom:10px"
      onclick="openWaterfallModal(${idx})" title="Click to open full waterfall">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px">
        <div style="display:flex;align-items:center;gap:8px">
          ${health==='critical'?'<span style="color:rgba(239,68,68,.9);font-size:13px;font-weight:900">⚠</span>':''}
          <b class="mono" style="font-size:12px;color:var(--tx)">${_esc(_trunc(t.trace,32))}</b>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <span style="color:${errCount?'#fda4af':'#86efac'};font-size:12px;font-weight:700">${errCount} errors</span>
          <span style="font-size:11px;color:var(--tx3)">${totalLat}ms total</span>
          <span style="font-size:11px;color:var(--tx3)">${hops.length} hops</span>
          <span class="btn btn-ghost btn-sm" style="padding:4px 10px;font-size:11px">Open ↗</span>
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">${hopPills}</div>
      ${hops.length>8?`<div style="font-size:10px;color:var(--tx3);margin-top:6px">+${hops.length-8} more hops in full view</div>`:''}
    </div>`;
  }).join('');

  _currentWaterfallTraces=sorted;
  _currentWaterfallEndpoint=ep;
}

// ─── Enhanced Call Matrix ─────────────────────────────────────────────────
function renderCallMatrix(ep){
  const rows=(ep.architecture?.matrix)||[];
  const el=document.getElementById('arch-matrix'); if(!el)return;

  if(!rows.length){ el.innerHTML='<div style="color:var(--tx3);padding:24px;text-align:center">No service call matrix detected for this endpoint.</div>'; return; }

  const maxCalls=Math.max(1,...rows.map(r=>r.calls||0));
  const maxLat=Math.max(1,...rows.map(r=>r.avg_latency_ms||0));

  el.innerHTML=`<div class="table-wrap">
    <table class="call-matrix" style="border-collapse:collapse;width:100%">
      <thead><tr>
        <th style="padding:10px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--tx3)">From</th>
        <th style="padding:10px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--tx3)">To</th>
        <th style="padding:10px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--tx3)">Volume</th>
        <th style="padding:10px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--tx3)">Errors</th>
        <th style="padding:10px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--tx3)">Error %</th>
        <th style="padding:10px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--tx3)">Avg Latency</th>
        <th style="padding:10px;border-bottom:1px solid var(--bd);font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--tx3)">Traffic</th>
      </tr></thead>
      <tbody>${rows.sort((a,b)=>(b.errors||0)-(a.errors||0)||(b.calls||0)-(a.calls||0)).map(r=>{
        const errRate=r.error_rate||0;
        const callW=Math.round((r.calls||0)/maxCalls*100);
        const latW=Math.round((r.avg_latency_ms||0)/maxLat*100);
        const errCol=errRate>20?'var(--rd)':errRate>5?'#fbbf24':'var(--gn)';
        const latCol=r.avg_latency_ms>3000?'var(--rd)':r.avg_latency_ms>800?'#fbbf24':'rgba(167,139,250,.8)';
        return `<tr style="border-bottom:1px solid var(--bd)">
          <td style="padding:10px;font-size:12px;font-weight:700;color:var(--tx)">${_esc(r.from)}</td>
          <td style="padding:10px;font-size:12px;color:var(--tx2)">${_esc(r.to)}</td>
          <td style="padding:10px;font-size:12px">
            <div style="display:flex;align-items:center;gap:6px">
              <div style="width:${callW}px;max-width:80px;height:6px;background:rgba(167,139,250,.5);border-radius:3px;min-width:4px"></div>
              <span style="color:var(--tx)">${r.calls||0}</span>
            </div>
          </td>
          <td style="padding:10px;font-size:12px;color:${r.errors?'var(--rd)':'var(--tx3)'};font-weight:${r.errors?700:400}">${r.errors||0}</td>
          <td style="padding:10px;font-size:12px;color:${errCol};font-weight:700">${errRate}%</td>
          <td style="padding:10px;font-size:12px;color:${latCol};font-weight:700">${r.avg_latency_ms||0}ms</td>
          <td style="padding:10px;min-width:90px">
            <div style="height:4px;background:rgba(255,255,255,.06);border-radius:2px">
              <div style="width:${callW}%;height:100%;background:${errRate>10?'rgba(239,68,68,.6)':'rgba(167,139,250,.55)'};border-radius:2px"></div>
            </div>
          </td>
        </tr>`;
      }).join('')}</tbody>
    </table>
  </div>`;
}

// ─── Mini topology health summary (injected into flow-hints area) ──────────
function _buildTopologyHealthBadges(ep){
  const arch=ep.architecture||{};
  const nodes=arch.nodes||[];
  if(!nodes.length) return '';
  const critical=nodes.filter(n=>n.health==='critical').length;
  const warn=nodes.filter(n=>n.health==='warn').length;
  const ok=nodes.length-critical-warn;
  const badges=[
    critical?`<span style="background:rgba(239,68,68,.18);border:1px solid rgba(239,68,68,.45);color:#fda4af;border-radius:999px;padding:3px 10px;font-size:11px;font-weight:700">⚠ ${critical} critical</span>`:'',
    warn?`<span style="background:rgba(245,158,11,.14);border:1px solid rgba(245,158,11,.4);color:#fbbf24;border-radius:999px;padding:3px 10px;font-size:11px;font-weight:700">⚡ ${warn} warn</span>`:'',
    `<span style="background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.38);color:#86efac;border-radius:999px;padding:3px 10px;font-size:11px;font-weight:700">✓ ${ok} ok</span>`,
  ].filter(Boolean).join(' ');
  return `<div style="margin:8px 0 4px;display:flex;gap:6px;flex-wrap:wrap">${badges}</div>`;
}

// ─── Override renderArchitecture to inject health badges ──────────────────
const _origRenderArchitecture=window.renderArchitecture||function(){};
window.renderArchitecture=function renderArchitecture(ep){
  if(!ep) return;
  renderArchitectureSvg(ep);
  renderTraceWaterfall(ep);
  renderCallMatrix(ep);
  const sm=document.getElementById('sm-trace-path');
  if(sm) sm.innerHTML=`<b>Trace example:</b> <code class="mono">${_esc(ep.sample_trace||'—')}</code>`;
  const lat=document.getElementById('sm-kpi-lat');
  if(lat) lat.textContent=(ep.avg_latency_ms||0)+'ms';
  const tr=document.getElementById('sm-kpi-trace');
  if(tr&&ep.sample_trace) tr.textContent=ep.sample_trace.slice(0,24)+(ep.sample_trace.length>24?'…':'');
  // Hints panel
  const arch=ep.architecture||{};
  const flow=_normalizeFlowOrder(arch.simple_flow&&arch.simple_flow.length?arch.simple_flow:(ep.flow_steps||[]));
  const hints=(arch.hints||[]);
  const healthBadges=_buildTopologyHealthBadges(ep);
  const fhEl=document.getElementById('flow-hints');
  if(fhEl) fhEl.innerHTML=healthBadges
    +(flow.length?'<b>High-level flow</b><br>'+flow.map(x=>`<span class="flow-node">${_esc(x)}</span>`).join('<span class="flow-arrow">→</span>')+'<br><br>':'')
    +(hints.length?hints.map(h=>'• '+_esc(h)).join('<br>'):'• Start with Guided Debugging: inspect the top failed trace and compare the 10 preceding log lines.');
  if(typeof renderEndpointIntelligence==='function') renderEndpointIntelligence(ep);
};

// ─── CSS injection (topology-specific styles not already in dashboard.html) ─
(function(){
  const s=document.createElement('style');
  s.textContent=`
    .topo-node rect{transition:filter .18s,opacity .18s}
    .topo-edge{cursor:pointer}
    .arch-canvas{overflow:auto;position:relative}
    #topo-svg{transition:transform .2s;display:block}
    .topo-node:hover{filter:drop-shadow(0 0 12px rgba(167,139,250,.5))}
    .clean-flow-step.external{border-color:rgba(245,158,11,.45)!important;background:rgba(245,158,11,.12)!important}
    .clean-flow-step.client,.clean-flow-step.response{border-color:rgba(16,185,129,.45)!important;background:rgba(16,185,129,.10)!important}
    .clean-flow-step.gateway{border-color:rgba(99,102,241,.50)!important;background:rgba(99,102,241,.14)!important}
    .clean-flow-step.data{border-color:rgba(59,130,246,.50)!important;background:rgba(59,130,246,.14)!important}
  `;
  document.head.appendChild(s);
})();

console.log('[ObserveX] Topology Engine v2 + Flow Normalizer loaded ✓');


async function pushTopologyToRegistry(){
  const apiName = document.getElementById('reg-api-name')?.value?.trim();
  const env = document.getElementById('reg-env')?.value || 'PROD';
  const nodesText = document.getElementById('curated-flow-nodes')?.value || '';
  const endpoint = document.getElementById('reg-endpoints')?.value?.split('\n')?.[0]?.trim() || '/';
  const nodes = nodesText.split('\n').map(x=>x.trim()).filter(Boolean);
  if(!apiName || !nodes.length){ alert('Enter API name and flow nodes first'); return; }
  const res = await safeJson(await fetch('/api/v1/topology/push',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({api_name:apiName, environment:env, endpoint, flow_nodes:nodes})
  }));
  if(res.error){ alert(res.error); return; }
  const status = document.getElementById('push-topo-status');
  if(status){ status.textContent = '✅ ' + (res.message || 'Topology saved'); status.style.color = '#86efac'; }
  await loadApiRegistry?.();
  await loadSystemMap?.();
}
function previewCuratedFlow(){
  const nodesText = document.getElementById('curated-flow-nodes')?.value || '';
  const nodes = nodesText.split('\n').map(x=>x.trim()).filter(Boolean);
  if(!nodes.length){ alert('Enter flow nodes first'); return; }
  if(typeof _renderCleanFlowV2 === 'function') _renderCleanFlowV2(nodes,{architecture:{}});
  else if(typeof renderArchitectureSvg === 'function') renderArchitectureSvg({architecture:{simple_flow:nodes}});
}
function useSelectedTopology(){
  const nodesText = document.getElementById('curated-flow-nodes')?.value || '';
  const nodes = nodesText.split('\n').map(x=>x.trim()).filter(Boolean);
  if(!nodes.length){ alert('Enter flow nodes first'); return; }
  if(typeof _selectedEndpoint !== 'undefined' && _selectedEndpoint){
    _selectedEndpoint.architecture = _selectedEndpoint.architecture || {};
    _selectedEndpoint.architecture.simple_flow = nodes;
    renderArchitectureSvg(_selectedEndpoint);
  } else {
    previewCuratedFlow();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ObserveX V6.1 — Non-blocking upload + editable curated topology chain
// ═══════════════════════════════════════════════════════════════════════════
(function(){
  function $id(id){ return document.getElementById(id); }
  function _htmlEsc(s){ return String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }

  // ── normalizeFlow: ensures Response Exit is always the last node ──────────
  // This prevents the "Response showing first" bug caused by any upstream
  // sort, group, or reverse that accidentally reorders flow nodes.
  function normalizeFlow(nodes){
    const cleaned = nodes.filter(Boolean);
    // Find and extract any response/exit node
    const responseIdx = cleaned.findIndex(n =>
      /response\s*exit|response\s*out|exit/i.test(String(n||''))
    );
    if(responseIdx !== -1 && responseIdx !== cleaned.length - 1){
      const responseNode = cleaned.splice(responseIdx, 1)[0];
      cleaned.push(responseNode);
    }
    return cleaned;
  }

  window.parseCuratedFlowNodes = function parseCuratedFlowNodes(text){
    const raw = String(text||'')
      .split(/\s*(?:→|->|=>|\n|\r|,)\s*/g)
      .map(x=>x.trim())
      .filter(Boolean)
      .filter((x,i,a)=>i===0 || x.toLowerCase()!==a[i-1].toLowerCase());
    // Always normalize so Response Exit is last — never first
    return normalizeFlow(raw);
  };

  function titleFromEndpoint(ep){
    const raw=String(ep||'/').split('?')[0].replace(/^\/+|\/+$/g,'');
    const last=(raw.split('/').filter(Boolean).pop()||'Request').replace(/[-_]+/g,' ');
    return last.replace(/\b\w/g,m=>m.toUpperCase());
  }

  function findCurrentApi(){
    const name=$id('sm-api-select')?.value || $id('reg-api-name')?.value || '';
    return ((_smData&&_smData.apis)||[]).find(a=>a.api_name===name) || null;
  }

  function findCurrentEndpoint(){
    if(typeof _selectedEndpoint!=='undefined' && _selectedEndpoint) return _selectedEndpoint;
    const api=findCurrentApi();
    const epVal=$id('sm-endpoint-select')?.value || '';
    if(!api) return null;
    return epVal ? (api.endpoints||[]).find(e=>(e.endpoint||'/')===epVal) : (api.endpoints||[])[0];
  }

  window.buildSuggestedCuratedFlow = function buildSuggestedCuratedFlow(ep, api){
    api = api || findCurrentApi() || {};
    ep = ep || findCurrentEndpoint() || {};
    const apiName = api.api_name || $id('sm-api-select')?.value || $id('reg-api-name')?.value || ep.api || 'API';
    const method = String(ep.method || 'GET').toUpperCase();
    const endpoint = ep.endpoint || '/';
    const routeNode = `${method} ${endpoint}:${apiName}-config.CPU-LITE`;
    const operation = titleFromEndpoint(endpoint);
    const arch = ep.architecture || {};
    const existing = (arch.simple_flow || ep.flow_steps || []).filter(Boolean);
    const names = (arch.nodes || []).map(n=>n.name||n.id).filter(Boolean);
    const all = [...existing, ...names];
    const lowApi = apiName.toLowerCase();
    const external = all.find(n=>{
      const low=String(n).toLowerCase();
      if(!low || low===lowApi) return false;
      if(/client|response|entry|exit|request|cpu|config|verify|validate/.test(low)) return false;
      return /gupshup|bbps|setu|upi|flexcube|lms|cbs|bank|gateway|vendor|external|payment-engine|loan-details/.test(low);
    }) || (lowApi.includes('gupshup') ? 'Gupshup' : 'External System');
    const chain=[apiName,'Request Entry',routeNode,operation,external,'Response Exit'];
    return chain.filter((x,i,a)=>x && (i===0 || String(x).toLowerCase()!==String(a[i-1]).toLowerCase()));
  };

  function tierForCuratedNode(name, idx, total){
    const low=String(name||'').toLowerCase();
    if(idx===0 || /-api\b|api$|mule/.test(low)) return 'API';
    // Request Entry → Gateway (entry point)
    if(/request entry/.test(low)) return 'Gateway';
    // Response Exit → Client (end of chain — rendered last/rightmost)
    if(/response exit|response out/.test(low)) return 'Client';
    if(/client|response/.test(low)) return 'Client';
    if(/^\s*(get|post|put|patch|delete)\s+/.test(low) || /config\.cpu/.test(low)) return 'Gateway';
    if(/db|database|redis|cache|oracle|postgres|mysql|mongo/.test(low)) return 'Data';
    if(/gupshup|bbps|setu|upi|flexcube|lms|cbs|bank|gateway|vendor|external|salesforce|s3|kafka/.test(low)) return 'External';
    return 'Service';
  }

  window.curatedFlowToArchitecture = function curatedFlowToArchitecture(nodes, baseEp){
    // CRITICAL: normalize first — Response Exit must always be last
    // Never sort, reverse, or reorder after this point
    nodes = normalizeFlow((nodes||[]).filter(Boolean));
    const req = Number(baseEp?.request_count || 1), err = Number(baseEp?.error_count || 0), lat = Number(baseEp?.avg_latency_ms || 0);
    const graphNodes = nodes.map((n,i)=>({
      id:n, name:n, tier:tierForCuratedNode(n,i,nodes.length),
      count:i===0?req:1, errors:(err && i===nodes.length-2)?err:0, warns:0,
      avg_latency_ms:(i===nodes.length-2)?lat:0,
      health:(err && i===nodes.length-2)?'critical':'ok'
    }));
    const edges=[];
    for(let i=0;i<nodes.length-1;i++){
      edges.push({from:nodes[i], to:nodes[i+1], count:req||1, errors:(err && i===nodes.length-2)?err:0, avg_latency_ms:(i===nodes.length-2)?lat:0, error_rate:req?Math.round(err/req*1000)/10:0, label:'curated'});
    }
    const traces=[{trace:baseEp?.sample_trace||'curated-flow', api:nodes[0], endpoint:baseEp?.endpoint||'/', errors:err, latency:lat, rows:nodes.map((n,i)=>({service:n, level:(err&&i===nodes.length-2)?'ERROR':'INFO', message:i===0?'API entry':'Curated topology hop', latency:i===nodes.length-2?lat:0, start_ms:i*20, duration_ms:i===nodes.length-2?lat:20}))}];
    return {simple_flow:nodes, nodes:graphNodes, edges, traces, matrix:edges.map(e=>({from:e.from,to:e.to,calls:e.count,errors:e.errors,avg_latency_ms:e.avg_latency_ms,error_rate:e.error_rate})), hints:['Curated topology is editable. Changes here update this topology preview instantly and can be pushed to Registry.']};
  };

  window.renderCuratedTopologyLive = function renderCuratedTopologyLive(){
    const txt=$id('curated-flow-nodes')?.value || '';
    const nodes=parseCuratedFlowNodes(txt);
    if(!nodes.length) return;
    const ep=findCurrentEndpoint() || {};
    const preview=Object.assign({}, ep, {architecture:curatedFlowToArchitecture(nodes, ep), flow_steps:nodes});
    if(typeof renderArchitectureSvg==='function') renderArchitectureSvg(preview);
    if(typeof renderTraceWaterfall==='function') renderTraceWaterfall(preview);
    if(typeof renderCallMatrix==='function') renderCallMatrix(preview);
    const hints=$id('flow-hints');
    if(hints) hints.innerHTML='<b>Editable curated flow</b><br>'+nodes.map(x=>`<span class="flow-node">${_htmlEsc(x)}</span>`).join('<span class="flow-arrow">→</span>')+'<br><br>Click <b>Push → Registry</b> to make this source-of-truth after refresh.';
  };

  window.fillCuratedTopologyFromSelectedEndpoint = function fillCuratedTopologyFromSelectedEndpoint(force){
    const box=$id('curated-flow-nodes');
    if(!box) return;
    const api=findCurrentApi(); const ep=findCurrentEndpoint();
    if(!api || !ep) return;
    const arch=ep.architecture||{};
    const manual=(arch.simple_flow||ep.flow_steps||[]).filter(Boolean);
    const suggested=buildSuggestedCuratedFlow(ep, api);
    const finalNodes=(force || !box.value.trim()) ? suggested : parseCuratedFlowNodes(box.value);
    box.value=finalNodes.join(' → ');
    $id('reg-api-name') && ($id('reg-api-name').value=api.api_name||'');
    $id('reg-env') && ($id('reg-env').value=ep.environment||api.environments?.[0]||'PROD');
    renderCuratedTopologyLive();
  };

  // Override existing buttons to support arrow-separated chains and live graph render.
  window.previewCuratedFlow=function previewCuratedFlow(){
    const nodes=parseCuratedFlowNodes($id('curated-flow-nodes')?.value||'');
    if(!nodes.length){ alert('Enter flow nodes first'); return; }
    renderCuratedTopologyLive();
  };

  window.useSelectedTopology=function useSelectedTopology(){
    const nodes=parseCuratedFlowNodes($id('curated-flow-nodes')?.value||'');
    if(!nodes.length){ alert('Enter flow nodes first'); return; }
    const ep=findCurrentEndpoint() || {};
    const arch=curatedFlowToArchitecture(nodes, ep);
    if(typeof _selectedEndpoint!=='undefined' && _selectedEndpoint){
      _selectedEndpoint.architecture=arch;
      _selectedEndpoint.flow_steps=nodes;
    }
    renderCuratedTopologyLive();
  };

  window.pushTopologyToRegistry=async function pushTopologyToRegistry(){
    const api=findCurrentApi(); const ep=findCurrentEndpoint() || {};
    const apiName=($id('reg-api-name')?.value || api?.api_name || '').trim();
    const env=$id('reg-env')?.value || ep.environment || api?.environments?.[0] || 'PROD';
    const nodes=parseCuratedFlowNodes($id('curated-flow-nodes')?.value||'');
    if(!apiName || !nodes.length){ alert('Select API and enter topology flow first'); return; }
    const res=await safeJson(await fetch('/api/v1/topology/push',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_name:apiName, environment:env, endpoint:ep.endpoint||'/', method:ep.method||'', flow_nodes:nodes})}));
    if(res.error){ alert(res.error); return; }
    const st=$id('push-topo-status'); if(st){ st.textContent='✅ Saved. Topology will stay after refresh.'; st.style.color='#86efac'; }
    if(typeof _selectedEndpoint!=='undefined' && _selectedEndpoint){ _selectedEndpoint.architecture=curatedFlowToArchitecture(nodes,_selectedEndpoint); _selectedEndpoint.flow_steps=nodes; }
    renderCuratedTopologyLive();
    if(typeof loadApiRegistry==='function') loadApiRegistry().catch(()=>{});
  };

  // Wrap System Map selection handlers so the curated box follows API/endpoint clicks.
  const oldApiChange=window.onSmApiChange;
  if(typeof oldApiChange==='function'){
    window.onSmApiChange=function(){ oldApiChange.apply(this,arguments); setTimeout(()=>fillCuratedTopologyFromSelectedEndpoint(true),80); };
  }
  const oldEpChange=window.onSmEndpointChange;
  if(typeof oldEpChange==='function'){
    window.onSmEndpointChange=function(){ oldEpChange.apply(this,arguments); setTimeout(()=>fillCuratedTopologyFromSelectedEndpoint(true),80); };
  }

  document.addEventListener('input', function(e){
    if(e.target && e.target.id==='curated-flow-nodes') renderCuratedTopologyLive();
  });

  // ═══════════════════════════════════════════════════════════════════════
  // SUPER-FAST UPLOAD ENGINE — V6.2
  // Parallel processing, streaming, non-blocking UI, real progress
  // ═══════════════════════════════════════════════════════════════════════

  // Inline Web Worker source for log pre-filtering (runs off main thread)
  const WORKER_SRC = `
    self.onmessage = function(e){
      const { text, fileName } = e.data;
      const lines = text.split('\\n');
      const relevant = [];
      const keywords = /error|warn|info|debug|trace|exception|failure|latency|status|payload|request|response/i;
      let lineNo = 0;
      for(const line of lines){
        lineNo++;
        if(line.trim() && keywords.test(line)){
          relevant.push({ line, lineNo });
        }
      }
      self.postMessage({ fileName, relevant, total: lines.length });
    };
  `;

  function makeWorker(){
    try{
      const blob = new Blob([WORKER_SRC], { type:'application/javascript' });
      return new Worker(URL.createObjectURL(blob));
    }catch(e){
      return null; // Fallback: no worker, process on main thread
    }
  }

  // Stream a small file through a worker for pre-filtering
  async function preFilterWithWorker(file){
    return new Promise((resolve)=>{
      const worker = makeWorker();
      if(!worker){ resolve(null); return; }
      const reader = new FileReader();
      reader.onload = (e)=>{
        worker.onmessage = (msg)=>{ worker.terminate(); resolve(msg.data); };
        worker.postMessage({ text: e.target.result, fileName: file.name });
      };
      reader.onerror = ()=>{ worker.terminate(); resolve(null); };
      reader.readAsText(file);
    });
  }

  // Upload one file — returns a promise, enables parallel execution
  async function uploadOneFile(file, env, onProgress, onStatus){
    const LARGE = 5*1024*1024;
    const fd = new FormData();
    fd.append('env', env);
    fd.append('logfile', file);

    if(file.size >= LARGE){
      onStatus(`⚡ Queuing ${file.name} (${Math.round(file.size/1024/1024)}MB) in background…`);
      const queued = await safeJson(await fetch('/analyse/async',{method:'POST',body:fd}));
      if(!queued.job_id) throw new Error(queued.error||'Queue failed');
      onStatus(`✅ ${file.name} queued. Analysis running in background.`);
      onProgress(file.size);
      // Fire-and-forget background poll
      (async()=>{
        for(let i=0;i<240;i++){
          await new Promise(r=>setTimeout(r,2000));
          let job;
          try{ job=await safeJson(await fetch('/ingestion-jobs/'+queued.job_id)); }catch(e){ continue; }
          if(job.status==='success'){
            const hist=await safeJson(await fetch('/history')).catch(()=>[]);
            const latest=(hist||[]).find(x=>String(x.file||'').includes(file.name))||(hist||[])[0];
            if(latest && typeof reloadSession==='function') await reloadSession(latest.id, latest.file||file.name).catch(()=>{});
            if(typeof loadSystemMap==='function') loadSystemMap().catch(()=>{});
            return;
          }
          if(job.status==='failed') return;
        }
      })();
    }else{
      onStatus(`📤 Uploading ${file.name} (${Math.round(file.size/1024)}KB)…`);
      // Try worker pre-filter for instant feedback, then upload
      preFilterWithWorker(file); // Non-blocking — just warms up parsing
      const d = await safeJson(await fetch('/analyse',{method:'POST',body:fd}));
      if(typeof addSession==='function') addSession(d, file.name, file.size);
      if(typeof loadSystemMap==='function') loadSystemMap().catch(()=>{});
      onProgress(file.size);
    }
  }

  window.uploadFiles = async function uploadFiles(files){
    if(!files || !files.length) return;
    const fileArr = [...files];
    const status  = $id('upload-status');
    const bar     = $id('upload-progress');
    const total   = fileArr.reduce((a,f)=>a+f.size, 0);
    let   done    = 0;

    const env = $id('env')?.value || 'PROD';

    // Reset progress bar
    if(bar){ bar.style.width='0%'; bar.style.transition='width .3s ease'; }
    if(status) status.textContent = `⚡ Starting parallel upload of ${fileArr.length} file(s)…`;

    const onProgress = (bytes)=>{
      done += bytes;
      const pct = Math.min(100, Math.round(done/Math.max(1,total)*100));
      if(bar) bar.style.width = pct+'%';
    };

    const completedNames = [];
    const failedNames    = [];

    // PARALLEL: all files upload simultaneously
    const statusLines = {};
    const updateStatus = ()=>{
      if(!status) return;
      const lines = Object.values(statusLines);
      if(lines.length <= 3){
        status.textContent = lines.join(' | ');
      } else {
        status.textContent = `⚡ Uploading ${fileArr.length} files in parallel… (${completedNames.length} done)`;
      }
    };

    await Promise.all(fileArr.map(file =>
      uploadOneFile(
        file, env,
        (bytes)=>{ onProgress(bytes); },
        (msg)=>{ statusLines[file.name]=msg; updateStatus(); }
      ).then(()=>{ completedNames.push(file.name); })
       .catch(e=>{ failedNames.push(file.name+': '+e.message); alert(file.name+': '+e.message); })
    ));

    if(bar) bar.style.width='100%';
    const totalRows = (_allRows||[]).length;
    const summary = failedNames.length
      ? `⚠ ${completedNames.length}/${fileArr.length} uploaded. Failures: ${failedNames.join(', ')}`
      : `✅ ${fileArr.length} file(s) uploaded in parallel. Dataset: ${totalRows} log record(s).`;
    if(status) status.textContent = summary;
    console.log('[ObserveX] Parallel upload complete:', completedNames);
  };

  // Improve placeholder/help text without requiring HTML changes.
  setTimeout(()=>{
    const box=$id('curated-flow-nodes');
    if(box){
      box.placeholder='Example:\ns-gupshup-api → Request Entry → GET /verify-otp:s-gupshup-api-config.CPU-LITE → Verify OTP → Gupshup → Response Exit';
      box.title='Use arrows or one node per line. The topology graphic updates while you edit.';
    }
  },500);

  console.log('[ObserveX] V6.2 parallel upload + topology flow-fix loaded ✓');
})();
