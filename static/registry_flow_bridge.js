// ═══════════════════════════════════════════════════════════════════════════
// ObserveX V42 — API Registry ↔ Topology Bridge
// Adds curated Flow Builder to API Registry and Push-to-Registry from topology.
// Loaded after dashboard.js/topology_upgrade.js so it can safely override helpers.
// ═══════════════════════════════════════════════════════════════════════════
(function(){
  const $ = (id)=>document.getElementById(id);
  const htmlEsc = (s)=>String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const clip = (s,n=42)=>{s=String(s??'');return s.length>n?s.slice(0,n-1)+'…':s;};
  const sj = async (res)=>{ const d=await res.json().catch(()=>({})); if(!res.ok && !d.error) d.error='Request failed'; return d; };

  function parseEndpoints(txt){
    return String(txt||'').split(/\n+/).map(x=>x.trim()).filter(Boolean).map(line=>{
      const m=line.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$/i);
      return m ? {method:m[1].toUpperCase(), endpoint:m[2].trim()} : {endpoint:line};
    });
  }
  function parseFlow(txt){
    return String(txt||'').replace(/→|=>/g,'\n').split(/\n+/).map(x=>x.replace(/^[-*\d.\)\s]+/,'').trim()).filter(Boolean);
  }
  function flowToText(flow){ return (flow||[]).join('\n'); }

  function ensureBridgeUi(){
    const endpoints=$('reg-endpoints');
    if(!endpoints || $('reg-flow-steps')) return;
    const row=document.createElement('div');
    row.className='toolbar registry-flow-builder-row';
    row.style.cssText='margin-top:10px;align-items:flex-start;gap:12px;flex-wrap:wrap';
    row.innerHTML=`
      <div style="display:flex;flex-direction:column;gap:6px;min-width:520px;flex:1">
        <label style="font-size:11px;color:var(--tx3);font-weight:800;text-transform:uppercase;letter-spacing:.08em">Curated topology flow</label>
        <textarea id="reg-flow-steps" class="input mono" rows="5" style="width:100%;min-height:110px" placeholder="One step per line or use arrows. Example:\ns-gupshup-api\nGET /generate-otp\ngenerate-otp-subflow\nGupshup\nResponse"></textarea>
        <div class="muted-note">This is the source-of-truth flow used by System Map when auto-detection is incomplete.</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:8px;min-width:220px">
        <button class="btn btn-ghost btn-sm" onclick="previewRegistryFlow()">Preview Flow</button>
        <button class="btn btn-ghost btn-sm" onclick="useSelectedTopologyInRegistry()">Use Selected Topology</button>
        <button class="btn btn-primary btn-sm" onclick="pushSelectedTopologyToRegistry()">Push Topology → Registry</button>
        <div id="registry-flow-status" class="muted-note">Registry and topology are now bidirectionally connected.</div>
      </div>`;
    endpoints.closest('.toolbar')?.after(row);
  }

  function currentSelectedApi(){
    const sel=$('sm-api-select');
    return (sel&&sel.value) || (($('_selectedApi')||{}).value) || (($('reg-api-name')||{}).value) || '';
  }
  function selectedEndpointPayload(){
    const ep=(typeof _selectedEndpoint!=='undefined' ? _selectedEndpoint : {}) || {};
    const arch=ep.architecture || {};
    const flow=(arch.simple_flow&&arch.simple_flow.length?arch.simple_flow:(ep.flow_steps||[]));
    const apiName=currentSelectedApi();
    return {apiName, ep, arch, flow};
  }

  window.useSelectedTopologyInRegistry=function(){
    ensureBridgeUi();
    const {apiName, ep, flow}=selectedEndpointPayload();
    if(!flow || flow.length<2){ alert('No selected topology flow found. Select an API/endpoint in System Map first.'); return; }
    if($('reg-api-name')) $('reg-api-name').value=apiName || $('reg-api-name').value;
    if($('reg-env')) $('reg-env').value=ep.environment || $('sm-env-filter')?.value || $('reg-env').value || 'PROD';
    if($('reg-endpoints') && ep.endpoint){ $('reg-endpoints').value=((ep.method||'')+' '+(ep.endpoint||'/')).trim(); }
    if($('reg-flow-steps')) $('reg-flow-steps').value=flowToText(flow);
    const st=$('registry-flow-status'); if(st) st.textContent='Loaded selected System Map topology into Registry Flow Builder.';
  };

  window.previewRegistryFlow=function(){
    ensureBridgeUi();
    const api=($('reg-api-name')||{}).value||'Manual API';
    const flow=parseFlow(($('reg-flow-steps')||{}).value);
    if(flow.length<2){ alert('Add at least 2 flow steps first.'); return; }
    const steps=flow[0]===api?flow:[api,...flow];
    if(!steps.some(x=>String(x).toLowerCase()==='response')) steps.push('Response');
    const ep={
      endpoint:'/', method:'', request_count:1, error_count:0, avg_latency_ms:0, sample_trace:'registry-preview',
      flow_steps:steps,
      architecture:{
        source:'registry-preview', confidence:95, simple_flow:steps,
        nodes:steps.map((x,i)=>({id:x,name:x,tier:i===0?'API':String(x).toLowerCase()==='response'?'Client':/salesforce|gupshup|kotak|external|lms|core|html|pdf/i.test(x)?'External':/get |post |put |delete |patch /i.test(x)?'Gateway':'Service',count:1,errors:0,warns:0,avg_latency_ms:0,health:'ok'})),
        edges:steps.slice(0,-1).map((x,i)=>({from:x,to:steps[i+1],count:1,errors:0,avg_latency_ms:0,error_rate:0,label:'registry-preview'})),
        traces:[], matrix:[], hints:['Previewing curated Registry flow. Click Save Registry to make this the System Map source of truth.']
      }
    };
    try{ _selectedEndpoint=ep; }catch(e){ window._selectedEndpoint=ep; }
    if(typeof renderArchitecture==='function') renderArchitecture(ep);
    try{ showSection('flow'); }catch(e){}
  };

  window.pushSelectedTopologyToRegistry=async function(){
    ensureBridgeUi();
    const {apiName, ep, flow}=selectedEndpointPayload();
    if(!apiName){ alert('Select an API in System Map first.'); return; }
    if(!flow || flow.length<2){ alert('No topology flow available to push. Select an endpoint with detected topology first.'); return; }
    const env=ep.environment || $('sm-env-filter')?.value || $('reg-env')?.value || 'PROD';
    const payload={
      api_name:apiName, environment:env, endpoint:ep.endpoint||'/', method:ep.method||'',
      flow_steps:flow, request_count:ep.request_count||0, error_count:ep.error_count||0, avg_latency_ms:ep.avg_latency_ms||0
    };
    const res=await sj(await fetch('/api/v1/api-registry/push-flow',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}));
    if(res.error){ alert(res.error); return; }
    if($('reg-api-name')) $('reg-api-name').value=res.api_name||apiName;
    if($('reg-env')) $('reg-env').value=res.environment||env;
    if($('reg-flow-steps')) $('reg-flow-steps').value=flowToText(res.flow_steps||flow);
    const st=$('registry-flow-status'); if(st) st.textContent='Saved topology to API Registry and refreshed System Map.';
    if(typeof loadApiRegistry==='function') await loadApiRegistry();
    if(typeof loadSystemMap==='function') await loadSystemMap();
  };

  // Override Registry save/fill/load with flow support. Runs after old dashboard functions.
  window.saveApiRegistry=async function(){
    ensureBridgeUi();
    const api=($('reg-api-name')||{}).value.trim();
    if(!api){ alert('API name is required'); return; }
    const body={
      api_name:api,
      environment:($('reg-env')||{}).value||'PROD',
      base_url:($('reg-base-url')||{}).value||'',
      owner:($('reg-owner')||{}).value||'',
      downstream_systems:($('reg-downstreams')||{}).value||'',
      endpoints:parseEndpoints(($('reg-endpoints')||{}).value||''),
      flow_steps:parseFlow(($('reg-flow-steps')||{}).value||'')
    };
    const res=await sj(await fetch('/api/v1/api-registry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
    if(res.error){ alert(res.error); return; }
    const st=$('registry-flow-status'); if(st) st.textContent='Saved Registry + curated topology flow.';
    if(typeof loadApiRegistry==='function') await loadApiRegistry();
    if(typeof loadSystemMap==='function') await loadSystemMap();
  };

  window.fillRegistryForm=function(id){
    ensureBridgeUi();
    const r=(window._apiRegistryRows||[]).find(x=>Number(x.id)===Number(id)); if(!r) return;
    if($('reg-api-name')) $('reg-api-name').value=r.api_name||'';
    if($('reg-env')) $('reg-env').value=r.environment||'PROD';
    if($('reg-base-url')) $('reg-base-url').value=r.base_url||'';
    if($('reg-owner')) $('reg-owner').value=r.owner||'';
    if($('reg-downstreams')) $('reg-downstreams').value=(r.downstream_systems||[]).join(', ');
    if($('reg-endpoints')) $('reg-endpoints').value=(r.endpoints||[]).map(e=>((e.method||'')+' '+(e.endpoint||'/')).trim()).join('\n');
    if($('reg-flow-steps')) $('reg-flow-steps').value=flowToText(r.flow_steps||[]);
    const st=$('registry-flow-status'); if(st) st.textContent='Loaded Registry entry. Edit flow steps and Save Registry.';
  };

  window.loadApiRegistry=async function(){
    ensureBridgeUi();
    const env=($('sm-env-filter')||{}).value||'';
    const data=await sj(await fetch('/api/v1/api-registry'+(env?'?env='+encodeURIComponent(env):''))).catch(()=>({apis:[]}));
    const rows=(data.apis||[]); window._apiRegistryRows=rows;
    const grouped={};
    rows.forEach(r=>{
      const key=(typeof shortApiName==='function'?shortApiName(r.api_name):r.api_name);
      if(!grouped[key]) grouped[key]={name:key, rows:[], endpoints:0, errors:0, downstream:new Set(), envs:new Set(), owner:r.owner||'Unassigned', flowSteps:0};
      const g=grouped[key]; g.rows.push(r); g.endpoints+=(r.endpoints||[]).length; g.errors+=(r.endpoints||[]).reduce((a,e)=>a+Number(e.error_count||0),0); (r.downstream_systems||[]).forEach(x=>g.downstream.add(x)); g.envs.add(r.environment||'PROD'); if(r.owner)g.owner=r.owner; g.flowSteps=Math.max(g.flowSteps,(r.flow_steps||[]).length);
    });
    const list=Object.values(grouped).sort((a,b)=>b.flowSteps-a.flowSteps || b.endpoints-a.endpoints);
    const html='<div class="registry-toolbar"><div><b>'+list.length+' grouped API entries</b><div class="muted-note">Registry flow is now connected to System Map. Manual flow wins when log topology is incomplete.</div></div><button class="btn btn-primary btn-sm" onclick="pushSelectedTopologyToRegistry()">Push Selected Topology</button><button class="btn btn-ghost btn-sm" onclick="loadApiRegistry()">Refresh</button></div><table><thead><tr><th>API / Group</th><th>Env</th><th>Owner</th><th>Health</th><th>Flow</th><th>Downstream</th><th>Endpoints</th><th>Action</th></tr></thead><tbody>'+ (list.map(g=>{
      const first=g.rows[0]||{}; const ds=[...g.downstream]; const tags=ds.slice(0,3).map(x=>'<span class="chip">'+htmlEsc(clip(x,24))+'</span>').join('')+(ds.length>3?' <span class="muted-note">+'+(ds.length-3)+' more</span>':'');
      const health=g.errors?'Watch':'OK';
      const flowBadge=g.flowSteps?'<span class="badge badge-ok">'+g.flowSteps+' steps</span>':'<span class="badge badge-warn">not mapped</span>';
      const rawRows=g.rows.slice(0,12).map(r=>'• '+htmlEsc(r.api_name)+' · flow '+((r.flow_steps||[]).length)+' steps · endpoints '+((r.endpoints||[]).length)).join('\n')+(g.rows.length>12?'\n+'+(g.rows.length-12)+' more rows':'');
      return '<tr><td><div class="registry-name"><b>'+htmlEsc(g.name)+'</b></div><div class="registry-sub">'+g.rows.length+' row(s) collapsed</div></td><td>'+htmlEsc([...g.envs].join(', '))+'</td><td>'+htmlEsc(g.owner||'Unassigned')+'</td><td><span class="badge badge-'+(health==='OK'?'ok':'warn')+'">'+health+'</span></td><td>'+flowBadge+'</td><td class="registry-tags">'+(tags||'—')+'</td><td>'+g.endpoints+'</td><td><button class="btn btn-ghost btn-sm" onclick="fillRegistryForm('+first.id+')">Edit</button> <button class="btn btn-ghost btn-sm" onclick="previewRegistryRowFlow('+first.id+')">Preview</button> <button class="btn btn-ghost btn-sm danger" onclick="deleteApiRegistry('+first.id+','+JSON.stringify(g.name).replace(/\"/g,'&quot;')+')">Delete</button></td></tr><tr><td colspan="8"><details class="compact-section"><summary>Show raw rows for '+htmlEsc(g.name)+'</summary><div class="compact-body raw-preview">'+rawRows+'</div></details></td></tr>';
    }).join('') || '<tr><td colspan="8">No registry found. Add one above.</td></tr>') + '</tbody></table>';
    const listEl=$('api-registry-list'); if(listEl) listEl.innerHTML=html;
  };

  window.previewRegistryRowFlow=function(id){
    const r=(window._apiRegistryRows||[]).find(x=>Number(x.id)===Number(id));
    if(!r || !(r.flow_steps||[]).length){ alert('This Registry row has no curated flow yet. Click Edit and add flow steps.'); return; }
    if($('reg-api-name')) $('reg-api-name').value=r.api_name||'';
    if($('reg-env')) $('reg-env').value=r.environment||'PROD';
    if($('reg-flow-steps')) $('reg-flow-steps').value=flowToText(r.flow_steps||[]);
    previewRegistryFlow();
  };

  // Add an action row below topology hints whenever an endpoint renders.
  const oldRender=window.renderArchitecture;
  window.renderArchitecture=function(ep){
    if(typeof oldRender==='function') oldRender(ep);
    setTimeout(()=>{
      const hints=$('flow-hints');
      if(hints && !$('topology-registry-actions')){
        const div=document.createElement('div');
        div.id='topology-registry-actions';
        div.style.cssText='margin-top:12px;display:flex;gap:8px;flex-wrap:wrap';
        div.innerHTML='<button class="btn btn-primary btn-sm" onclick="pushSelectedTopologyToRegistry()">Push detected flow to API Registry</button><button class="btn btn-ghost btn-sm" onclick="useSelectedTopologyInRegistry()">Edit this flow manually</button>';
        hints.appendChild(div);
      }
    },50);
  };

  document.addEventListener('DOMContentLoaded',()=>{ ensureBridgeUi(); setTimeout(()=>{ try{ loadApiRegistry(); }catch(e){} },600); });
  setTimeout(ensureBridgeUi,800);
})();
