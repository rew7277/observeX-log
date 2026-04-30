/* ObserveX Simple Mode
   Keeps the strong parser/topology engine, but presents a clean operator UI:
   Upload -> Summary -> Log Search -> System Map -> History/Settings.
*/
(function(){
  const keepNav = new Set(['Dashboard','Log Search','System Map','Upload History','Settings']);
  const hiddenDashboardSelectors = [
    '.global-search-box','#live-alert-strip','.dashboard-extra-grid','.dashboard-viz-grid','.signal-grid','#action-cards'
  ];
  function txt(el){return (el&&el.textContent||'').replace(/\s+/g,' ').trim();}
  function hide(el){ if(el) el.style.display='none'; }
  function show(el){ if(el) el.style.display=''; }
  function hideByHeading(pattern){
    document.querySelectorAll('.card').forEach(card=>{
      const h=card.querySelector('h3,h4');
      if(h && pattern.test(txt(h))) hide(card);
    });
  }
  function simplifyNav(){
    document.querySelectorAll('.nav-link').forEach(a=>{
      const label = txt(a.querySelector('.nav-text')) || a.getAttribute('data-title') || '';
      if(!keepNav.has(label)) hide(a);
    });
    document.querySelectorAll('.nav-section').forEach(s=>{
      const label=txt(s);
      if(label && label!=='Operate' && label!=='Setup') hide(s);
    });
  }
  function simplifyDashboard(){
    hiddenDashboardSelectors.forEach(sel=>document.querySelectorAll(sel).forEach(hide));
    hideByHeading(/AI RCA|Endpoint SLA|Executive Reports|Incident Severity|Schema Detection|RCA Evidence/i);
    const hero = document.querySelector('#sec-dashboard .hero');
    if(hero){
      const h=hero.querySelector('h1'); if(h) h.textContent='ObserveX Dashboard';
      const p=hero.querySelector('p'); if(p) p.textContent='Upload logs, understand the issue, search evidence, and view the API flow in a simple workflow.';
      hero.querySelectorAll('button').forEach(btn=>{ if(!/Load Demo/i.test(txt(btn))) hide(btn); });
    }
    const root = document.getElementById('root-cause'); if(root) root.textContent='Upload logs to generate a clear issue summary.';
    const dep = document.getElementById('deploy-recommendation'); if(dep) dep.textContent='You will see what happened, impacted APIs, likely owner, and next steps.';
  }
  function simplifyLogs(){
    const ql=document.querySelector('.ql-help'); if(ql) hide(ql);
    const chips=[...document.querySelectorAll('#sec-logs .chip')];
    chips.forEach(c=>{ if(/Query language|env=|trace=|Has trace/i.test(txt(c))) hide(c); });
  }
  function simplifySystemMap(){
    const flowTitle=document.querySelector('#sec-flow .page-title'); if(flowTitle) flowTitle.textContent='🔀 System Map';
    const flowSub=document.querySelector('#sec-flow .page-sub'); if(flowSub) flowSub.textContent='Clean API flow extracted from logs. Shows request path, dependency calls, errors, and latency without internal processor noise.';
    document.querySelectorAll('.arch-tab').forEach(t=>{ if(/Call Matrix/i.test(txt(t))) hide(t); });
    hideByHeading(/API Registry|Manual Flow Builder|Curated Topology Flow|Flow Confidence|Trace Comparison|Smart RCA|Business & Security Signals|Error Timeline/i);
    const deps=document.getElementById('deps'); if(deps){ const card=deps.closest('.card'); if(card) hide(card); }
  }
  function addSimpleHelp(){
    if(document.getElementById('simple-mode-help')) return;
    const dash=document.getElementById('sec-dashboard'); if(!dash) return;
    const box=document.createElement('div');
    box.id='simple-mode-help';
    box.className='card simple-help-card';
    box.innerHTML='<h3>Recommended workflow</h3><div class="simple-steps"><div><b>1 Upload</b><span>Drop Mule/API logs</span></div><div><b>2 Review</b><span>See health, errors, RCA</span></div><div><b>3 Search</b><span>Open exact evidence</span></div><div><b>4 Map</b><span>Validate API flow</span></div></div>';
    const after=dash.querySelector('.lite-grid');
    if(after) after.insertAdjacentElement('afterend', box);
  }
  function applySimpleMode(){
    document.body.classList.add('simple-mode');
    simplifyNav(); simplifyDashboard(); simplifyLogs(); simplifySystemMap(); addSimpleHelp();
  }
  const oldRender = window.renderArchitectureSvg;
  window.renderArchitectureSvg = function(ep){
    if(!document.body.classList.contains('simple-mode')) return oldRender ? oldRender(ep) : null;
    const arch=ep?.architecture||{};
    const flow=(arch.simple_flow&&arch.simple_flow.length?arch.simple_flow:(ep?.flow_steps||[]))
      .filter(Boolean)
      .map(x=>String(x).replace(/^processor[:=\-\s]+/i,'').replace(/\/processors?\/\d+.*/i,'').replace(/-event-\d+-[0-9a-f].*/i,'').trim())
      .filter(x=>x && !/^(common|default|logger|logging|mule-subflow)$/i.test(x))
      .filter((x,i,a)=>a.findIndex(y=>y.toLowerCase()===x.toLowerCase())===i)
      .slice(0,8);
    const nodes=(arch.nodes||[]).filter(n=>n&&n.name).slice(0,8);
    const source=flow.length?flow:nodes.map(n=>n.name);
    const errorCount=Number(ep?.error_count||0);
    const errRate=Number(ep?.error_rate||0);
    const latency=Number(ep?.avg_latency_ms||0);
    const html = source.length
      ? '<div class="simple-topology">'+source.map((s,i)=>'<div class="simple-node '+(i===0?'start':i===source.length-1?'end':'')+'"><b>'+esc(s)+'</b><small>'+(i===0?'Entry':i===source.length-1?'Exit / dependency':'Step '+(i+1))+'</small></div>').join('<div class="simple-arrow">→</div>')+'</div>'
      : '<div class="simple-empty">No topology detected yet. Upload logs with API name, endpoint, trace ID, and downstream call messages.</div>';
    setHTML('flow-diagram', html + '<div class="simple-map-summary"><div><small>Errors</small><b class="'+(errorCount?'pill-error':'pill-ok')+'">'+errorCount+'</b></div><div><small>Error rate</small><b>'+errRate+'%</b></div><div><small>Avg latency</small><b>'+latency+'ms</b></div><div><small>Confidence</small><b>'+(source.length>=3?'High':source.length?'Medium':'Low')+'</b></div></div>');
  };
  window.addEventListener('DOMContentLoaded', applySimpleMode);
  window.addEventListener('load', applySimpleMode);
  window.__applySimpleMode = applySimpleMode;
})();
