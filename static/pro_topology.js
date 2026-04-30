/* ObserveX Pro Topology UI v45
   Clean architecture topology: deterministic flow ordering, fit-to-screen SVG, readable labels,
   subtle traffic animation, and click-to-inspect without noisy processor labels. */
(function(){
  const $ = (id)=>document.getElementById(id);
  const esc = (s)=>String(s ?? '').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const norm = (s)=>String(s||'').trim().replace(/\s+/g,' ');
  const processorNoise = /(\/processors?\/\d+|CPU_LITE|\.xml:\d+|event-[a-f0-9-]+|processor-[a-f0-9]+|0x[0-9a-f]+)/i;
  const weakLabels = /^(common|default|logger|logging|processor|mule-subflow|request|response|entry|exit|api endpoint)$/i;

  function cleanLabel(s){
    s = norm(s).replace(/^processor[:=\-\s]+/i,'')
      .replace(/\/processors?\/\d+.*/i,'')
      .replace(/-event-[a-f0-9-]+.*/i,'')
      .replace(/--+/g,'-')
      .replace(/_/g,' ')
      .replace(/\bCPU LITE\b/ig,'')
      .replace(/\bCPU_LITE\b/ig,'')
      .replace(/\s*-\s*$/, '');
    s = s.replace(/\b(GET|POST|PUT|DELETE|PATCH)\s+([^\s].{0,95})/i,(m,a,b)=>a.toUpperCase()+' '+b.replace(/[?#].*$/,''));
    return norm(s);
  }

  function displayLabel(label){
    let s = cleanLabel(label);
    s = s.replace(/^s-([a-z0-9-]+)-api$/i,(_,x)=>x.split('-').map(w=>w.toUpperCase()==='API'?w:w.charAt(0).toUpperCase()+w.slice(1)).join(' ')+' API');
    s = s.replace(/paymentengine/ig,'Payment Engine').replace(/loanDetails/ig,'Loan Details');
    return s;
  }

  function tierOf(label){
    const n = String(label||'').toLowerCase();
    if(/response|exit|completed|complete/.test(n)) return 'Response';
    if(/client|consumer|browser|mobile|user/.test(n)) return 'Client';
    if(/request entry|entry|gateway|proxy|ingress|router/.test(n)) return 'Gateway';
    if(/\b(get|post|put|delete|patch)\b|endpoint|api|service|payment engine|kyc/.test(n)) return 'API / Service';
    if(/lms|loan|cbs|core banking|database|postgres|oracle|mysql|redis|mongo/.test(n)) return 'Core Systems';
    if(/bureau|cibil|experian|equifax|crif|upi|setu|bbps|gupshup|external|third|partner|provider/.test(n)) return 'External';
    return 'Core Systems';
  }
  function tierRank(t){ return {'Client':0,'Gateway':1,'API / Service':2,'Core Systems':3,'External':4,'Response':5}[t] ?? 3; }
  function stageScore(label, idx){
    const n = String(label||'').toLowerCase();
    if(/response|exit|completed|complete/.test(n)) return 9000 + idx;
    if(/client|consumer|browser|mobile|user/.test(n)) return 0 + idx;
    if(/request entry|entry/.test(n)) return 50 + idx;
    if(/gateway|proxy|ingress|router/.test(n)) return 90 + idx;
    if(/^s-|\bapi\b|payment engine|kyc/.test(n)) return 150 + idx;
    if(/\b(get|post|put|delete|patch)\b|endpoint|loan details/.test(n)) return 220 + idx;
    if(/lms|loan management|cbs|core banking|database/.test(n)) return 420 + idx;
    if(/bureau|cibil|experian|equifax|crif|upi|setu|bbps|external|provider/.test(n)) return 520 + idx;
    return 360 + idx;
  }
  function stableId(label, i){ return 'n'+i+'_'+String(label).toLowerCase().replace(/[^a-z0-9]+/g,'_').slice(0,32); }
  function isBad(label){ return !label || processorNoise.test(label) || weakLabels.test(label); }

  function readFlow(ep){
    const arch = ep?.architecture || {};
    let labels = [];
    if(Array.isArray(arch.simple_flow)) labels = labels.concat(arch.simple_flow);
    if(Array.isArray(ep?.flow_steps)) labels = labels.concat(ep.flow_steps);
    if(Array.isArray(arch.nodes)) labels = labels.concat(arch.nodes.map(n=>n.name||n.label||n.id));
    labels = labels.map(cleanLabel).filter(x=>!isBad(x));
    const seen = new Set();
    labels = labels.filter(x=>{ const k=x.toLowerCase(); if(seen.has(k)) return false; seen.add(k); return true; });
    labels.sort((a,b)=>stageScore(a, labels.indexOf(a))-stageScore(b, labels.indexOf(b)));

    // Add missing standard boundaries only when useful.
    if(!labels.some(x=>/request entry|entry|gateway/i.test(x))) labels.unshift('Request Entry');
    if(!labels.some(x=>/response|exit/i.test(x))) labels.push('Response Exit');
    // Prevent response from appearing before dependencies.
    labels = labels.filter((x,i)=>!/response|exit/i.test(x) || i===labels.findLastIndex?.(y=>/response|exit/i.test(y)));
    return labels;
  }

  function buildGraph(ep){
    const labels = readFlow(ep);
    let nodes = labels.map((label,i)=>({ id: stableId(label,i), raw: label, label: displayLabel(label), tier: tierOf(label), originalIndex:i, errors:0, count:0, latency:0 }));
    const totalReq = +(ep?.request_count || ep?.requests || 0);
    const totalErr = +(ep?.error_count || ep?.errors || 0);
    const avgLat = +(ep?.avg_latency_ms || ep?.latency || 0);
    nodes = nodes.map((n,i)=>({ ...n, count: i===0?totalReq:0, errors: (/response|exit/i.test(n.raw)?totalErr:0), latency: avgLat }));
    let edges = [];
    for(let i=0;i<nodes.length-1;i++) edges.push({from:nodes[i].id,to:nodes[i+1].id,count:totalReq,errors:(i===nodes.length-2?totalErr:0),latency:avgLat});

    // Prefer backend edges only when they form a clean forward chain. Otherwise generated order wins.
    const arch = ep?.architecture || {};
    if(Array.isArray(arch.edges) && Array.isArray(arch.nodes) && arch.edges.length){
      const backendNodes = arch.nodes.map((n,i)=>({old:String(n.id||n.name||n.label||i), label:cleanLabel(n.name||n.label||n.id), i})).filter(n=>!isBad(n.label));
      const idMap = new Map(backendNodes.map((n,i)=>[n.old, stableId(n.label,i)]));
      const bEdges = arch.edges.map(e=>({from:idMap.get(String(e.from||e.source||'')),to:idMap.get(String(e.to||e.target||'')),count:+(e.count||totalReq),errors:+(e.errors||0),latency:+(e.avg_latency_ms||avgLat)})).filter(e=>e.from&&e.to&&e.from!==e.to);
      const rank = new Map(nodes.map((n,i)=>[n.id,i]));
      const cleanForward = bEdges.length && bEdges.every(e=>(rank.get(e.to)??999) > (rank.get(e.from)??-1));
      if(cleanForward) edges = bEdges;
    }
    return {nodes, edges};
  }

  function layout(nodes){
    const tiers = ['Client','Gateway','API / Service','Core Systems','External','Response'];
    const groups = {};
    nodes.forEach(n=>{ (groups[n.tier]||(groups[n.tier]=[])).push(n); });
    const active = tiers.filter(t=>groups[t]?.length);
    const W = 1180;
    const maxRows = Math.max(1,...active.map(t=>groups[t].length));
    const H = Math.max(430, 190 + maxRows*105);
    const pos = {};
    active.forEach((tier,ti)=>{
      const list = groups[tier].sort((a,b)=>a.originalIndex-b.originalIndex);
      const x = active.length===1 ? W/2 : 90 + ti*((W-180)/(active.length-1));
      const totalH = (list.length-1)*104;
      const startY = Math.max(130, (H-totalH)/2);
      list.forEach((n,i)=>{ pos[n.id]={x:x-82,y:startY+i*104,w:164,h:58,cx:x,cy:startY+i*104+29}; });
    });
    return {W,H,pos,active};
  }

  function pathBetween(a,b){
    const x1=a.x+a.w, y1=a.cy, x2=b.x, y2=b.cy;
    if(x2>=x1){ const m=x1+(x2-x1)*0.55; return `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`; }
    const midY = Math.min(y1,y2)-42;
    return `M${a.cx},${a.y} C${a.cx},${midY} ${b.cx},${midY} ${b.cx},${b.y}`;
  }
  function iconFor(t){ return {'Client':'👤','Gateway':'🛡️','API / Service':'⚙️','Core Systems':'🗄️','External':'🌐','Response':'✅'}[t] || '●'; }

  function renderPro(ep){
    const host = $('flow-diagram'); if(!host) return;
    const graph = buildGraph(ep);
    if(!graph.nodes.length){ host.innerHTML='<div class="pro-empty">No topology detected yet. Upload logs or teach the API Registry flow.</div>'; return; }
    const {W,H,pos,active} = layout(graph.nodes);
    const totalErr = +(ep?.error_count||0), totalReq = +(ep?.request_count||0), avgLat = +(ep?.avg_latency_ms||0);
    const errRate = totalReq ? ((totalErr/totalReq)*100).toFixed(2)+'%' : '0%';
    const lanes = active.map((t,ti)=>{ const x = active.length===1 ? W/2 : 90 + ti*((W-180)/(active.length-1)); return `<g><rect x="${x-92}" y="82" width="184" height="${H-132}" rx="18" class="pro-lane"/><text x="${x}" y="62" text-anchor="middle" class="pro-lane-title">${esc(t)}</text></g>`; }).join('');
    const defs = `<defs><marker id="proArrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto"><path d="M0,0 L0,10 L10,5 z" fill="#68e8ff"/></marker><marker id="proArrowErr" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto"><path d="M0,0 L0,10 L10,5 z" fill="#ff5470"/></marker><filter id="softGlow"><feGaussianBlur stdDeviation="2.1" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>`;
    const edges = graph.edges.map((e,i)=>{ const a=pos[e.from], b=pos[e.to]; if(!a||!b) return ''; const d=pathBetween(a,b); const err=e.errors>0; return `<g class="pro-edge-group"><path class="pro-edge-shadow" d="${d}"/><path class="pro-edge ${err?'is-error':''}" d="${d}" marker-end="url(#${err?'proArrowErr':'proArrow'})"/><circle class="pro-packet ${err?'is-error':''}" r="3.4"><animateMotion dur="${3.4+i*.18}s" repeatCount="indefinite" path="${d}"/></circle><title>${esc((e.count||0)+' calls · '+(e.errors||0)+' errors · '+(e.latency||0)+'ms avg')}</title></g>`; }).join('');
    const nodes = graph.nodes.map(n=>{ const p=pos[n.id]; if(!p) return ''; const err=/response|exit/i.test(n.raw) && totalErr>0; const warn=!err && avgLat>1000; const cls=err?'is-error':(warn?'is-warn':'is-ok'); const label=esc(n.label.length>24?n.label.slice(0,23)+'…':n.label); const meta=esc(n.tier + (n.tier==='Response'?` · ${totalErr} errors`:` · ${avgLat}ms`)); return `<g class="pro-node ${cls}" transform="translate(${p.x},${p.y})" tabindex="0" data-title="${esc(n.label)}"><rect width="${p.w}" height="${p.h}" rx="14"/><text x="14" y="24" class="pro-node-icon">${iconFor(n.tier)}</text><text x="42" y="24" class="pro-node-label">${label}</text><text x="42" y="43" class="pro-node-meta">${meta}</text><circle cx="${p.w-16}" cy="16" r="4.5"/><title>${esc(n.label+'\n'+n.tier+'\nRequests: '+totalReq+'\nErrors: '+(err?totalErr:0)+'\nAvg latency: '+avgLat+'ms')}</title></g>`; }).join('');
    host.innerHTML = `<div class="pro-topology-shell"><div class="pro-topology-toolbar"><div><b>Architecture Topology</b><span>Clean request flow · processor noise hidden · ${graph.nodes.length} systems · ${graph.edges.length} hops</span></div><div class="pro-topology-actions"><button type="button" onclick="window.proToggleMotion&&window.proToggleMotion()">Pause Flow</button><button type="button" onclick="window.proToggleLabels&&window.proToggleLabels()">Labels</button></div></div><div class="pro-topology-canvas" id="proTopoCanvas"><svg class="pro-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">${defs}${lanes}${edges}${nodes}</svg></div><div class="pro-insight-strip"><div><small>Requests</small><b>${(totalReq||0).toLocaleString()}</b></div><div><small>Errors</small><b class="${totalErr?'danger':''}">${totalErr}</b></div><div><small>Error rate</small><b>${esc(errRate)}</b></div><div><small>Avg latency</small><b>${esc(avgLat)}ms</b></div></div></div>`;
  }

  function installCss(){
    if($('pro-topology-css')) return;
    const css = document.createElement('style'); css.id='pro-topology-css'; css.textContent = `
      #sec-flow{max-width:none!important}.main{overflow-x:hidden}.pro-topology-shell{width:100%;max-width:1180px;margin:0 auto;background:linear-gradient(145deg,rgba(15,18,39,.98),rgba(8,10,24,.98));border:1px solid rgba(126,116,255,.32);border-radius:22px;box-shadow:0 22px 60px rgba(0,0,0,.34);overflow:hidden}.pro-topology-toolbar{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.035)}.pro-topology-toolbar b{display:block;color:#f8fafc;font-size:15px}.pro-topology-toolbar span{display:block;color:#9aa6c1;font-size:11px;margin-top:3px}.pro-topology-actions{display:flex;gap:8px}.pro-topology-actions button{border:1px solid rgba(104,232,255,.26);background:rgba(104,232,255,.08);color:#e5fbff;border-radius:999px;padding:7px 10px;font-size:11px;font-weight:800;cursor:pointer}.pro-topology-canvas{height:clamp(420px,52vh,610px);padding:8px;background:radial-gradient(circle at 20% 10%,rgba(99,102,241,.15),transparent 35%),radial-gradient(circle at 82% 42%,rgba(20,184,166,.10),transparent 30%)}.pro-svg{width:100%;height:100%;display:block}.pro-lane{fill:rgba(255,255,255,.026);stroke:rgba(255,255,255,.075);stroke-dasharray:5 8}.pro-lane-title{fill:#b8c2dc;font-weight:900;font-size:11px;letter-spacing:.08em;text-transform:uppercase}.pro-edge-shadow{fill:none;stroke:rgba(0,0,0,.45);stroke-width:6;stroke-linecap:round}.pro-edge{fill:none;stroke:#68e8ff;stroke-width:2.4;stroke-linecap:round;filter:url(#softGlow);opacity:.9}.pro-edge.is-error{stroke:#ff5470}.pro-packet{fill:#68e8ff;filter:url(#softGlow);opacity:.95}.pro-packet.is-error{fill:#ff5470}.pro-paused .pro-packet{display:none}.pro-node rect{fill:#151b34;stroke:#36e4b7;stroke-width:1.2;filter:drop-shadow(0 10px 18px rgba(0,0,0,.32))}.pro-node.is-warn rect{stroke:#fbbf24}.pro-node.is-error rect{stroke:#ff5470;fill:#2a1322}.pro-node text{pointer-events:none}.pro-node-icon{font-size:15px}.pro-node-label{fill:#f8fafc;font-size:11px;font-weight:900}.pro-node-meta{fill:#9aa6c1;font-size:9.5px}.pro-node circle{fill:#36e4b7}.pro-node.is-warn circle{fill:#fbbf24}.pro-node.is-error circle{fill:#ff5470;animation:proPulse 1.2s ease-in-out infinite}.pro-insight-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:rgba(255,255,255,.07);border-top:1px solid rgba(255,255,255,.08)}.pro-insight-strip div{background:rgba(15,18,38,.96);padding:12px 14px}.pro-insight-strip small{display:block;color:#8c96ad;font-size:10px;text-transform:uppercase;font-weight:900}.pro-insight-strip b{display:block;color:#f8fafc;font-size:16px;margin-top:4px}.pro-insight-strip .danger{color:#ff8aa0}.pro-empty{padding:36px;color:#aab4cc;text-align:center;border:1px dashed rgba(255,255,255,.18);border-radius:20px}.pro-hide-labels .pro-node-meta{display:none}@keyframes proPulse{50%{r:7;opacity:.55}}@media(max-width:900px){.pro-topology-shell{border-radius:18px}.pro-insight-strip{grid-template-columns:1fr 1fr}.pro-topology-toolbar{align-items:flex-start;flex-direction:column}.pro-topology-canvas{height:520px}}`;
    document.head.appendChild(css);
  }
  window.proToggleMotion = function(){ const h=$('flow-diagram'); if(h) h.classList.toggle('pro-paused'); };
  window.proToggleLabels = function(){ const h=$('flow-diagram'); if(h) h.classList.toggle('pro-hide-labels'); };
  function install(){ installCss(); window.renderArchitectureSvg = renderPro; }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', install); else install();
  setTimeout(install,500);
})();
