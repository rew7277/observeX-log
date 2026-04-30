/* ObserveX Pro Topology UI v44
   Purpose: replace text/pill topology with a clean animated architecture graph.
   No external libraries required. Uses backend topology when available and falls back to clean flow steps. */
(function(){
  const $ = (id)=>document.getElementById(id);
  const esc = (s)=>String(s ?? '').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const norm = (s)=>String(s||'').trim().replace(/\s+/g,' ');
  const bad = /^(common|default|logger|logging|processor|mule-subflow|request|response|entry|exit)$/i;
  const noise = /(\/processors?\/\d+|CPU_LITE|\.xml:\d+|event-\d+|0x[0-9a-f]+)/i;
  function cleanLabel(s){
    s = norm(s).replace(/^processor[:=\-\s]+/i,'')
      .replace(/\/processors?\/\d+.*/i,'')
      .replace(/-event-\d+-[0-9a-f].*/i,'')
      .replace(/--+/g,'-')
      .replace(/_/g,' ');
    s = s.replace(/\b(GET|POST|PUT|DELETE|PATCH)\s+(.{1,70})/i,(m,a,b)=>a.toUpperCase()+' '+b.replace(/[?#].*$/,''));
    return norm(s);
  }
  function titleType(name){
    const n = String(name||'').toLowerCase();
    if(/client|consumer|request entry|entry/.test(n)) return 'Client';
    if(/gateway|proxy|ingress|router/.test(n)) return 'Gateway';
    if(/api|paymentengine|kyc|service/.test(n)) return 'API / Service';
    if(/lms|loan|cbs|core|db|database|postgres|oracle|mysql|redis|mongo/.test(n)) return 'Data / Core';
    if(/bureau|upi|setu|bbps|gupshup|external|third|partner|http/.test(n)) return 'External';
    if(/response|exit/.test(n)) return 'Response';
    return 'Service';
  }
  function stableId(label, i){ return 'n'+i+'_'+String(label).toLowerCase().replace(/[^a-z0-9]+/g,'_').slice(0,32); }
  function buildGraph(ep){
    const arch = ep?.architecture || {};
    let srcNodes = Array.isArray(arch.nodes) ? arch.nodes.slice() : [];
    let srcEdges = Array.isArray(arch.edges) ? arch.edges.slice() : [];
    let nodes = [];
    let idByOld = new Map();

    if(srcNodes.length){
      srcNodes.forEach((n,i)=>{
        const label = cleanLabel(n.name || n.label || n.id || ('Step '+(i+1)));
        if(!label || bad.test(label) || noise.test(label)) return;
        const id = String(n.id || stableId(label,i));
        idByOld.set(String(n.id||n.name||label), id);
        nodes.push({
          id, label, tier:n.tier || titleType(label),
          errors:+(n.errors||0), count:+(n.count||n.records||0), latency:+(n.avg_latency_ms||n.latency||0), health:n.health||''
        });
      });
    }

    if(nodes.length < 2){
      const flow = (arch.simple_flow && arch.simple_flow.length ? arch.simple_flow : (ep?.flow_steps||[]))
        .map(cleanLabel).filter(x=>x && !bad.test(x) && !noise.test(x))
        .filter((x,i,a)=>a.findIndex(y=>y.toLowerCase()===x.toLowerCase())===i);
      nodes = flow.map((label,i)=>({id:stableId(label,i), label, tier:titleType(label), errors:0, count:0, latency:0, health:''}));
      srcEdges = nodes.slice(1).map((n,i)=>({from:nodes[i].id, to:n.id, count:ep?.request_count||0, errors:ep?.error_count||0, avg_latency_ms:ep?.avg_latency_ms||0}));
      idByOld = new Map(nodes.map(n=>[n.id,n.id]));
    }

    const nodeIds = new Set(nodes.map(n=>n.id));
    let edges = srcEdges.map(e=>{
      const from = idByOld.get(String(e.from||e.source||'')) || String(e.from||e.source||'');
      const to = idByOld.get(String(e.to||e.target||'')) || String(e.to||e.target||'');
      return {from,to,count:+(e.count||0),errors:+(e.errors||0),latency:+(e.avg_latency_ms||e.latency||0)};
    }).filter(e=>nodeIds.has(e.from)&&nodeIds.has(e.to)&&e.from!==e.to);

    if(!edges.length && nodes.length>1) edges = nodes.slice(1).map((n,i)=>({from:nodes[i].id,to:n.id,count:ep?.request_count||0,errors:ep?.error_count||0,latency:ep?.avg_latency_ms||0}));
    const seen = new Set();
    edges = edges.filter(e=>{ const k=e.from+'>'+e.to; if(seen.has(k)) return false; seen.add(k); return true; });
    return {nodes, edges};
  }
  function layout(nodes, edges){
    const order = ['Client','Gateway','API / Service','Service','Data / Core','External','Response'];
    const groups = {};
    nodes.forEach(n=>{ const t=order.includes(n.tier)?n.tier:titleType(n.label); (groups[t]||(groups[t]=[])).push(n); });
    const active = order.filter(t=>groups[t]?.length);
    const W = Math.max(1120, active.length*230 + 120), H = Math.max(520, Math.max(1,...active.map(t=>groups[t].length))*120 + 160);
    const pos = {};
    active.forEach((tier,ti)=>{
      const list = groups[tier];
      const x = 80 + ti*((W-160)/Math.max(1,active.length-1));
      const total = (list.length-1)*112;
      list.forEach((n,i)=>{ const y = 92 + (H-170-total)/2 + i*112; pos[n.id]={x,y,w:174,h:68,cx:x,cy:y+34}; });
    });
    return {W,H,pos,active};
  }
  function iconFor(t){
    if(t==='Client') return '👤'; if(t==='Gateway') return '🛡️'; if(t==='External') return '🌐'; if(t==='Data / Core') return '🗄️'; if(t==='Response') return '✅'; return '⚙️';
  }
  function renderPro(ep){
    const host = $('flow-diagram'); if(!host) return;
    const graph = buildGraph(ep);
    if(!graph.nodes.length){ host.innerHTML='<div class="pro-empty">No topology detected yet. Upload logs or add API Registry flow.</div>'; return; }
    const {W,H,pos,active} = layout(graph.nodes, graph.edges);
    const totalErr = +(ep?.error_count||graph.nodes.reduce((a,n)=>a+n.errors,0)||0);
    const totalReq = +(ep?.request_count||0);
    const errRate = totalReq ? ((totalErr/totalReq)*100).toFixed(2)+'%' : (ep?.error_rate||'0%');
    const lanes = active.map((t,i)=>{ const x = 80+i*((W-160)/Math.max(1,active.length-1)); return `<g><rect x="${x-98}" y="44" width="196" height="${H-72}" rx="24" class="pro-lane"/><text x="${x}" y="72" text-anchor="middle" class="pro-lane-title">${esc(t)}</text></g>`; }).join('');
    const defs = `<defs><marker id="proArrow" markerWidth="11" markerHeight="11" refX="9" refY="5.5" orient="auto"><path d="M0,0 L0,11 L11,5.5 z" fill="#73f5ff"/></marker><marker id="proArrowErr" markerWidth="11" markerHeight="11" refX="9" refY="5.5" orient="auto"><path d="M0,0 L0,11 L11,5.5 z" fill="#ff4d6d"/></marker><filter id="glow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
    const edges = graph.edges.map((e,i)=>{ const a=pos[e.from], b=pos[e.to]; if(!a||!b)return ''; const err=e.errors>0||totalErr>0&&i===graph.edges.length-1; const x1=a.cx+a.w/2, y1=a.cy, x2=b.cx-b.w/2, y2=b.cy; const m=(x1+x2)/2; const d = x2>x1 ? `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}` : `M${a.cx},${a.y} C${a.cx},${a.y-70} ${b.cx},${b.y-70} ${b.cx},${b.y}`; return `<g class="pro-edge-group"><path class="pro-edge-bg" d="${d}"/><path class="pro-edge ${err?'is-error':''}" d="${d}" marker-end="url(#${err?'proArrowErr':'proArrow'})"/><circle class="pro-packet ${err?'is-error':''}" r="4"><animateMotion dur="${2.2+i*.25}s" repeatCount="indefinite" path="${d}"/></circle><title>${esc((e.count||0)+' calls, '+(e.errors||0)+' errors, '+(e.latency||0)+'ms avg')}</title></g>`; }).join('');
    const nodes = graph.nodes.map((n,i)=>{ const p=pos[n.id]; if(!p)return ''; const err=n.errors>0||/critical/i.test(n.health); const warn=!err && (+n.latency>1000||/warn/i.test(n.health)); const cls=err?'is-error':(warn?'is-warn':'is-ok'); const label=esc(n.label.length>28?n.label.slice(0,27)+'…':n.label); return `<g class="pro-node ${cls}" tabindex="0" data-node="${esc(n.label)}" transform="translate(${p.x},${p.y})"><rect width="${p.w}" height="${p.h}" rx="18"/><text x="16" y="25" class="pro-node-icon">${iconFor(n.tier)}</text><text x="46" y="25" class="pro-node-label">${label}</text><text x="46" y="47" class="pro-node-meta">${esc(n.tier)} · ${n.errors||0} err · ${n.latency||0}ms</text><circle cx="${p.w-18}" cy="18" r="5"/><title>${esc(n.label+'\n'+n.tier+'\n'+(n.count||0)+' records · '+(n.errors||0)+' errors · '+(n.latency||0)+'ms avg')}</title></g>`; }).join('');
    host.innerHTML = `<div class="pro-topology-shell"><div class="pro-topology-toolbar"><div><b>Architecture Topology</b><span>${graph.nodes.length} systems · ${graph.edges.length} calls · ${esc(errRate)} error rate</span></div><div class="pro-topology-actions"><button onclick="window.proFitTopology&&window.proFitTopology()">Fit</button><button onclick="window.proToggleLabels&&window.proToggleLabels()">Toggle Labels</button></div></div><div class="pro-topology-canvas" id="proTopoCanvas"><svg class="pro-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">${defs}${lanes}${edges}${nodes}</svg></div><div class="pro-insight-strip"><div><small>Requests</small><b>${(totalReq||0).toLocaleString()}</b></div><div><small>Errors</small><b class="${totalErr?'danger':''}">${totalErr}</b></div><div><small>Avg latency</small><b>${esc(ep?.avg_latency_ms||0)}ms</b></div><div><small>Trace</small><b class="mono">${esc(ep?.sample_trace?String(ep.sample_trace).slice(0,18)+'…':'—')}</b></div></div></div>`;
  }
  function installCss(){
    if($('pro-topology-css')) return;
    const css = document.createElement('style'); css.id='pro-topology-css'; css.textContent = `
      #sec-flow{max-width:none!important}.main{overflow-x:hidden}.pro-topology-shell{width:min(100%,1240px);margin:0 auto;background:linear-gradient(145deg,rgba(18,22,45,.96),rgba(11,13,28,.98));border:1px solid rgba(124,119,255,.25);border-radius:24px;box-shadow:0 24px 70px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05);overflow:hidden}.pro-topology-toolbar{display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.035)}.pro-topology-toolbar b{display:block;color:#f8fafc;font-size:16px}.pro-topology-toolbar span{display:block;color:#98a2b3;font-size:12px;margin-top:3px}.pro-topology-actions{display:flex;gap:8px}.pro-topology-actions button{border:1px solid rgba(115,245,255,.22);background:rgba(115,245,255,.08);color:#dffcff;border-radius:999px;padding:7px 11px;font-size:12px;font-weight:800;cursor:pointer}.pro-topology-canvas{min-height:540px;padding:10px;background:radial-gradient(circle at 25% 15%,rgba(99,102,241,.16),transparent 35%),radial-gradient(circle at 80% 35%,rgba(20,184,166,.11),transparent 30%)}.pro-svg{width:100%;height:560px;display:block}.pro-lane{fill:rgba(255,255,255,.025);stroke:rgba(255,255,255,.075);stroke-dasharray:4 7}.pro-lane-title{fill:#b9c1d9;font-weight:900;font-size:12px;letter-spacing:.08em;text-transform:uppercase}.pro-edge-bg{fill:none;stroke:rgba(0,0,0,.42);stroke-width:8;stroke-linecap:round}.pro-edge{fill:none;stroke:#73f5ff;stroke-width:2.7;stroke-linecap:round;filter:url(#glow);stroke-dasharray:10 8;animation:proDash 1.2s linear infinite}.pro-edge.is-error{stroke:#ff4d6d}.pro-packet{fill:#73f5ff;filter:url(#glow)}.pro-packet.is-error{fill:#ff4d6d}.pro-node rect{fill:linear-gradient(135deg,rgba(35,43,78,.98),rgba(21,25,48,.98));stroke:#6e75ff;stroke-width:1.4;filter:drop-shadow(0 12px 22px rgba(0,0,0,.34))}.pro-node.is-ok rect{stroke:#36e4b7}.pro-node.is-warn rect{stroke:#fbbf24}.pro-node.is-error rect{stroke:#ff4d6d;fill:rgba(75,25,42,.95)}.pro-node text{pointer-events:none}.pro-node-icon{font-size:18px}.pro-node-label{fill:#f8fafc;font-size:12px;font-weight:900}.pro-node-meta{fill:#9aa4bd;font-size:10px}.pro-node circle{fill:#36e4b7}.pro-node.is-warn circle{fill:#fbbf24}.pro-node.is-error circle{fill:#ff4d6d;animation:proPulse 1s ease-in-out infinite}.pro-insight-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:rgba(255,255,255,.07);border-top:1px solid rgba(255,255,255,.08)}.pro-insight-strip div{background:rgba(15,18,38,.96);padding:14px 16px}.pro-insight-strip small{display:block;color:#8c96ad;font-size:11px;text-transform:uppercase;font-weight:900}.pro-insight-strip b{display:block;color:#f8fafc;font-size:18px;margin-top:4px}.pro-insight-strip .danger{color:#ff8aa0}.pro-empty{padding:36px;color:#aab4cc;text-align:center;border:1px dashed rgba(255,255,255,.18);border-radius:20px}.pro-hide-labels .pro-node-label,.pro-hide-labels .pro-node-meta{display:none}@keyframes proDash{to{stroke-dashoffset:-18}}@keyframes proPulse{50%{r:8;opacity:.55}}@media(max-width:900px){.pro-topology-shell{border-radius:18px}.pro-insight-strip{grid-template-columns:1fr 1fr}.pro-topology-toolbar{align-items:flex-start;gap:10px;flex-direction:column}.pro-svg{height:500px}}`;
    document.head.appendChild(css);
  }
  window.proFitTopology = function(){ const c=$('proTopoCanvas'); if(c) c.scrollIntoView({behavior:'smooth',block:'center'}); };
  window.proToggleLabels = function(){ const h=$('flow-diagram'); if(h) h.classList.toggle('pro-hide-labels'); };
  function install(){ installCss(); window.renderArchitectureSvg = renderPro; }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', install); else install();
  setTimeout(install,500);
})();
