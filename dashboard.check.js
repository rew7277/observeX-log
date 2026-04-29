
let _allRows=[],_visibleRows=[],_lastResult=null,_sessions=[],_environments=[];
const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));const badge=l=>l==='ERROR'||l==='FAILURE'?'badge-error':l==='WARN'?'badge-warn':l==='SUCCESS'?'badge-ok':'badge-info';
function toggleSidebar(){let s=document.getElementById('shell');s.classList.toggle('collapsed');localStorage.setItem('observexSidebarCollapsed',s.classList.contains('collapsed')?'1':'0')}function switchTab(id,btn){document.querySelectorAll('.tab-panel').forEach(x=>x.classList.remove('active'));document.getElementById(id).classList.add('active');btn.parentElement.querySelectorAll('.tab-btn').forEach(x=>x.classList.remove('active'));btn.classList.add('active')}
async function safeJson(res){let d=await res.json().catch(()=>({error:'Invalid server response'}));if(!res.ok)throw new Error(d.error||'Request failed');return d}
const dz=document.getElementById('drop-zone');['dragenter','dragover'].forEach(e=>dz.addEventListener(e,x=>{x.preventDefault();dz.classList.add('drag')}));['dragleave','drop'].forEach(e=>dz.addEventListener(e,x=>{x.preventDefault();dz.classList.remove('drag')}));dz.addEventListener('drop',e=>uploadFiles([...e.dataTransfer.files]));document.getElementById('fileInput').addEventListener('change',e=>uploadFiles([...e.target.files]));
async function uploadFiles(files){if(!files.length)return;let total=files.reduce((a,f)=>a+f.size,0),done=0;document.getElementById('upload-status').textContent=`Uploading ${files.length} file(s)…`;for(const file of files){const fd=new FormData();fd.append('env',document.getElementById('env').value);fd.append('logfile',file);try{let d=await safeJson(await fetch('/analyse',{method:'POST',body:fd}));addSession(d,file.name,file.size)}catch(e){alert(file.name+': '+e.message)}done+=file.size;document.getElementById('upload-progress').style.width=Math.round(done/total*100)+'%'}document.getElementById('upload-status').textContent='Upload complete. Active dataset contains '+_allRows.length+' parsed log record(s).'}
async function analysePaste(){let raw=document.getElementById('paste-area').value.trim();if(!raw)return alert('Paste logs first');const fd=new FormData();fd.append('raw_paste',raw);fd.append('env',document.getElementById('env').value);let d=await safeJson(await fetch('/analyse',{method:'POST',body:fd}));addSession(d,'paste',raw.length)}
function addSession(d,name,size){let sid='u'+Date.now()+Math.random().toString(16).slice(2);(d.log_rows||[]).forEach(r=>{r.uploadId=sid;r.uploadName=name;r.serverSessionId=d.session_id||''});_sessions.push({id:sid,serverId:d.session_id,name,size,result:d});recomputeAggregate();showSection('dashboard')}
async function deleteUpload(id){let s=_sessions.find(x=>x.id===id);_sessions=_sessions.filter(x=>x.id!==id);if(s?.serverId){try{await fetch('/history?id='+encodeURIComponent(s.serverId),{method:'DELETE'})}catch(e){console.warn(e)}}recomputeAggregate();clearTrace()}function recomputeAggregate(){_allRows=_sessions.flatMap(s=>s.result.log_rows||[]);_visibleRows=[..._allRows];let results=_sessions.map(s=>s.result);let d={total:_allRows.length,errors:_allRows.filter(r=>r.level==='ERROR').length,warns:_allRows.filter(r=>r.level==='WARN').length,apps:[...new Set(_allRows.map(r=>r.app).filter(Boolean))],smart_tags:[...new Set(results.flatMap(r=>r.smart_tags||[]))],dependencies:[...new Set(results.flatMap(r=>r.dependencies||[]))],suggestions:[...new Set(results.flatMap(r=>r.suggestions||[]))],top_errors:[],findings:[],hot_traces:[],app_health:[],timeline_buckets:[],action_cards:[]};let lats=_allRows.map(r=>Number(r.latency||0)).filter(Boolean);d.latency=lats.length?Math.round(lats.reduce((a,b)=>a+b,0)/lats.length):0;d.health_score=Math.max(0,Math.min(100,100-Math.min(50,d.errors*100/Math.max(1,d.total)*5)-Math.min(25,d.warns*100/Math.max(1,d.total)*2)-(d.latency>3000?15:0)));let errMap={};_allRows.filter(r=>r.level==='ERROR'||r.level==='FAILURE').forEach(r=>{let k=(r.message.match(/(?:Exception|ERROR|failed|failure)[:\s]+([A-Za-z0-9_.:-]+)/i)||[])[1]||'General error';errMap[k]=(errMap[k]||0)+1});d.top_errors=Object.entries(errMap).sort((a,b)=>b[1]-a[1]).slice(0,10);let traceMap={};_allRows.forEach(r=>{let t=r.trace||r.event;if(t){traceMap[t]??={trace:t,count:0,errors:0,latency:0,app:r.app};traceMap[t].count++;traceMap[t].errors+=r.level==='ERROR'||r.level==='FAILURE'?1:0;traceMap[t].latency=Math.max(traceMap[t].latency,Number(r.latency||0))}});d.hot_traces=Object.values(traceMap).sort((a,b)=>(b.errors-a.errors)||(b.latency-a.latency)||(b.count-a.count)).slice(0,8);let appMap={};_allRows.forEach(r=>{let a=r.app||'unknown';appMap[a]??={app:a,lines:0,errors:0,warns:0,latencies:[]};appMap[a].lines++;appMap[a].errors+=r.level==='ERROR'||r.level==='FAILURE'?1:0;appMap[a].warns+=r.level==='WARN'?1:0;if(r.latency)appMap[a].latencies.push(r.latency)});d.app_health=Object.values(appMap).map(a=>({...a,avg_latency:a.latencies.length?Math.round(a.latencies.reduce((x,y)=>x+y,0)/a.latencies.length):0,severity:a.errors?'critical':a.warns?'warn':'ok'})).sort((a,b)=>b.errors-a.errors||b.lines-a.lines);let tb={};_allRows.forEach(r=>{let k=String(r.time||'').slice(0,16);if(k){tb[k]??={time:k,total:0,errors:0,warns:0};tb[k].total++;tb[k].errors+=r.level==='ERROR'||r.level==='FAILURE'?1:0;tb[k].warns+=r.level==='WARN'?1:0}});d.timeline_buckets=Object.values(tb).sort((a,b)=>a.time.localeCompare(b.time)).slice(-40);d.root_cause=d.top_errors[0]?`Most repeated error cluster is '${d.top_errors[0][0]}' with ${d.top_errors[0][1]} hits`:(d.total?'No strong failure pattern detected in active dataset':'Upload logs to generate an incident summary.');d.deploy_summary={recommendation:d.errors?'Block release until critical errors are explained.':'Safe to continue with monitoring.'};d.action_cards=[{title:'Investigate trace',value:d.hot_traces[0]?.trace||'No trace yet',type:d.errors?'critical':'ok'},{title:'Top app',value:d.app_health[0]?.app||'Unknown',type:d.app_health[0]?.severity||'warn'},{title:'Review dependency',value:d.dependencies[0]||'No dependency signal',type:d.dependencies.length?'warn':'ok'},{title:'Deploy readiness',value:`Health ${Math.round(d.health_score)}/100`,type:d.health_score<70?'critical':d.health_score<90?'warn':'ok'}];let successCount=_allRows.filter(r=>String(r.level||'').toUpperCase()==='SUCCESS'||/\b(success|status\":\s*\"success|httpstatus\":\s*2\d\d)\b/i.test(r.message||'')).length;let uniqueTraces=new Set(_allRows.map(r=>r.trace||r.event).filter(Boolean));let apiSet=new Set(_allRows.map(r=>r.flow||r.api||'').filter(Boolean));let times=_allRows.map(r=>Date.parse(String(r.time||'').replace(' ', 'T'))).filter(x=>!isNaN(x));let minutes=times.length?Math.max(1,Math.ceil((Math.max(...times)-Math.min(...times))/60000)):1;let sortedLat=_allRows.map(r=>Number(r.latency||0)).filter(Boolean).sort((a,b)=>a-b);let p95=sortedLat.length?sortedLat[Math.min(sortedLat.length-1,Math.floor(sortedLat.length*.95))]:0;d.derived_metrics={error_rate:d.total?Math.round((d.errors/d.total)*1000)/10:0,success_rate:d.total?Math.round((successCount/d.total)*1000)/10:0,throughput:Math.round(d.total/minutes),traces:uniqueTraces.size,apis:apiSet.size,p95:p95,sources:_sessions.length,anomaly:(d.total && (d.errors/d.total>.05||p95>5000))?'High':'Normal'};d.findings=[{label:`Active files: ${_sessions.length}`,type:'info'},{label:`${d.errors} error(s), ${d.warns} warning(s)`,type:d.errors?'error':d.warns?'warn':'ok'},{label:`Applications detected: ${d.apps.join(', ')||'none'}`,type:d.apps.length?'ok':'warn'},{label:`Avg latency ${d.latency}ms · P95 ${p95}ms`,type:d.latency>3000?'warn':'info'}];_lastResult=d;renderResult(d);renderUploads();renderRows(_visibleRows);updateFilters();renderFlow();generateReport()}

function renderVisualDashboard(d){
  let dm=d.derived_metrics||{};
  const put=(id,val)=>{let el=document.getElementById(id);if(el)el.textContent=val};
  let timeline=(d.timeline_buckets||[]).slice(-32);
  let max=Math.max(1,...timeline.map(x=>x.total||0));
  let trend=document.getElementById('dash-trend');
  if(trend){
    if(!timeline.length){timeline=Array.from({length:24},(_,i)=>({total:(i%5)+1,errors:0,warns:i%7===0?1:0,time:''}));max=6}
    trend.innerHTML=timeline.map(x=>`<div class="trend-bar ${(x.errors||0)>0?'err':(x.warns||0)>0?'warn':''}" title="${esc(x.time||'sample')} · ${x.total||0} logs · ${x.errors||0} errors" style="height:${Math.max(8,Math.round(((x.total||1)/max)*100))}%"></div>`).join('');
  }
  let score=Math.max(0,Math.min(100,Math.round(d.health_score||100))), err=Math.max(0,Math.min(100,Number(dm.error_rate||0))), warn=Math.max(0,Math.min(100,Number(d.warns||0)/Math.max(1,Number(d.total||1))*100));
  let ok=Math.max(0,100-err-warn);
  let donut=document.getElementById('health-donut');
  if(donut)donut.style.background=`conic-gradient(#22c55e 0 ${ok}%, #f59e0b ${ok}% ${ok+warn}%, #ef4444 ${ok+warn}% 100%)`;
  put('donut-score', score);
  let hb=document.getElementById('health-breakdown');
  if(hb)hb.innerHTML=[['Healthy signals',ok,'ok'],['Warning signals',warn,'warn'],['Failure signals',err,'err']].map(([n,v,t])=>`<div class="health-row"><div><b>${n}</b><div class="health-track"><span class="health-fill ${t==='warn'?'warn':t==='err'?'err':''}" style="width:${Math.max(2,Math.round(v))}%"></span></div></div><strong>${Math.round(v)}%</strong></div>`).join('');
  let mttr=(d.errors||0)>50||err>10?'High':(d.errors||0)>0||err>2?'Medium':'Low';
  put('m-mttr-risk',mttr);put('m-noise',Math.round(100-Math.min(100,err+Number(dm.success_rate||0)))+'%');
  let conf=Math.min(98,Math.round((dm.traces?35:0)+(d.top_errors?.length?25:0)+(d.rca_explain?.length?25:0)+(d.dependencies?.length?13:0)));
  put('m-rca-conf',conf+'%');
  let rows=_allRows||[];let latest=rows.map(r=>String(r.time||'')).filter(Boolean).sort().pop();put('m-freshness',latest?latest.slice(0,16):'—');
}

function renderResult(d){renderVisualDashboard(d);document.getElementById('m-total').textContent=d.total.toLocaleString();document.getElementById('m-errors').textContent=d.errors.toLocaleString();document.getElementById('m-warns').textContent=d.warns.toLocaleString();document.getElementById('m-latency').textContent=(d.latency||0)+'ms';document.getElementById('m-apps').textContent=(d.apps||[]).length;document.getElementById('m-score').textContent=Math.round(d.health_score||100);let dm=d.derived_metrics||{};const put=(id,val)=>{let el=document.getElementById(id);if(el)el.textContent=val};put('m-error-rate',(dm.error_rate||0)+'%');put('m-success-rate',(dm.success_rate||0)+'%');put('m-throughput',(dm.throughput||0)+'/min');put('m-traces',dm.traces||0);put('m-apis',dm.apis||0);put('m-p95',(dm.p95||0)+'ms');put('m-sources',dm.sources||0);put('m-anomaly',dm.anomaly||'Normal');document.getElementById('root-cause').textContent=d.root_cause;document.getElementById('deploy-recommendation').textContent=d.deploy_summary?.recommendation||'';let sv=d.severity||{};if(document.getElementById('severity-card')){document.getElementById('severity-card').innerHTML=`<b>${esc(String(sv.label||'low').toUpperCase())} · ${sv.score??0}/100</b><div style="color:var(--tx2);font-size:12px">${esc((sv.why||[]).join(' · '))}</div>`;document.getElementById('schema-card').innerHTML=`<b>${esc(d.schema_type||'Unknown')}</b><div style="color:var(--tx2);font-size:12px">Auto-detected parser strategy for this dataset.</div>`;document.getElementById('explain-card').innerHTML=(d.rca_explain||[]).map(x=>`<div class="node-card"><b>${esc(x.reason)}</b><div class="mono" style="font-size:11px;color:var(--tx2);white-space:pre-wrap">${esc(JSON.stringify(x.evidence,null,2)).slice(0,900)}</div></div>`).join('')||'—';}document.getElementById('findings').innerHTML=(d.findings||[]).map(f=>`<div class="finding-row"><span>${esc(f.label)}</span><span class="badge badge-${f.type==='error'?'error':f.type==='warn'?'warn':f.type==='ok'?'ok':'info'}">${esc(f.type).toUpperCase()}</span></div>`).join('');document.getElementById('smart-tags').innerHTML=(d.smart_tags||[]).map(x=>`<span class="chip" onclick="quickSearch('${esc(x)}')">${esc(x)}</span>`).join('')||'—';document.getElementById('top-errors').innerHTML=(d.top_errors||[]).map(([k,v])=>`<div class="finding-row"><span>${esc(k)}</span><b class="pill-error">${v}</b></div>`).join('')||'No error clusters.';document.getElementById('next-steps').innerHTML=(d.suggestions||[]).map(x=>`• ${esc(x)}`).join('<br>')||'—';document.getElementById('action-cards').innerHTML=(d.action_cards||[]).map(c=>`<div class="action-card ${esc(c.type)}"><small>${esc(c.title)}</small><b>${esc(c.value)}</b></div>`).join('');document.getElementById('guided-steps').innerHTML=[`Open trace ${esc(d.hot_traces?.[0]?.trace||'with highest signal')}`,`Check impacted app ${esc(d.app_health?.[0]?.app||'from app health')}`,`Verify dependency/config: ${esc((d.dependencies||[])[0]||'none detected')}`,`Decision: ${esc(d.deploy_summary?.recommendation||'continue monitoring')}`].map((x,i)=>`<div class="debug-step" data-step="${i+1}">${x}</div>`).join('')}
function renderUploads(){document.getElementById('upload-list').innerHTML=_sessions.map(s=>`<span class="upload-pill"><b>${esc(s.name)}</b><small>${Math.round((s.size||0)/1024)} KB</small><button title="Delete this file from active dataset" onclick="deleteUpload('${s.id}')">×</button></span>`).join('')}
function updateFilters(){let apps=[...new Set(_allRows.map(r=>r.app).filter(Boolean))].sort();document.getElementById('filter-app').innerHTML='<option value="">All Apps</option>'+apps.map(a=>`<option>${esc(a)}</option>`).join('');let files=[...new Set(_allRows.map(r=>r.uploadName||r.file).filter(Boolean))].sort();document.getElementById('filter-file').innerHTML='<option value="">All Files</option>'+files.map(f=>`<option>${esc(f)}</option>`).join('')}
function parseDateTime(v){let m=String(v||'').match(/(\d{4}-\d{2}-\d{2})[T\s](\d{2}:\d{2})(?::(\d{2}))?/);return m?new Date(`${m[1]}T${m[2]}:${m[3]||'00'}`):null}function inDateTimeRange(r,fd,td,ft,tt){let dt=parseDateTime(r.time);if(!dt)return true;let d=dt.toISOString().slice(0,10),t=dt.toTimeString().slice(0,5);return (!fd||d>=fd)&&(!td||d<=td)&&(!ft||t>=ft)&&(!tt||t<=tt)}
let _logPage=1,_logPageSize=50;
function setLogPageSize(v){_logPageSize=Number(v)||50;_logPage=1;renderRows(_visibleRows||[])}
function prevLogPage(){if(_logPage>1){_logPage--;paintLogPage()}}
function nextLogPage(){const pages=Math.max(1,Math.ceil((_visibleRows||[]).length/_logPageSize));if(_logPage<pages){_logPage++;paintLogPage()}}
function renderRows(rows){_visibleRows=Array.isArray(rows)?rows:[];_logPage=1;paintLogPage()}
function paintLogPage(){
  const body=document.getElementById('logs-tbody'); if(!body)return;
  const rows=_visibleRows||[]; const total=rows.length; const pages=Math.max(1,Math.ceil(total/_logPageSize));
  _logPage=Math.min(Math.max(1,_logPage),pages);
  const start=(_logPage-1)*_logPageSize, pageRows=rows.slice(start,start+_logPageSize);
  body.innerHTML=pageRows.map(r=>`<tr onclick="openLogModal(${_allRows.indexOf(r)})" style="cursor:pointer"><td>${esc(r.time)}</td><td>${esc(r.env)}</td><td><span class="badge ${badge(r.level)}">${r.level}</span></td><td>${esc(r.app)}</td><td class="mono">${esc(r.trace||'—')}</td><td>${esc(r.flow||'—')}</td><td class="mono" style="font-size:11px">${esc(r.message).slice(0,240)}</td></tr>`).join('')||'<tr><td colspan="7" style="text-align:center;color:var(--tx3)">No matching logs.</td></tr>';
  const info=document.getElementById('logs-page-info'); if(info)info.textContent=total?`${start+1}-${Math.min(start+_logPageSize,total)} of ${total} logs`:'0 logs';
  const label=document.getElementById('logs-page-label'); if(label)label.textContent=`Page ${_logPage} / ${pages}`;
}
function openLogModal(idx){let r=_allRows[idx];if(!r)return;_currentLogText=r.message||'';document.getElementById('log-detail').innerHTML=`<div class="log-detail-grid">${['time','env','level','app','trace','event','flow','status','latency','uploadName','line_no','is_multiline'].map(k=>`<div class="detail-box"><small>${k}</small><b>${esc(r[k]||'—')}</b></div>`).join('')}</div><h3>Message</h3><pre class="detail-message mono">${esc(r.message)}</pre>`;document.getElementById('log-modal').classList.add('active')}function closeLogModal(){document.getElementById('log-modal').classList.remove('active')}function copyCurrentLog(){navigator.clipboard.writeText(_currentLogText||'');alert('Complete log copied')}
function openTopTrace(){if(_lastResult?.hot_traces?.[0]){document.getElementById('trace-q').value=_lastResult.hot_traces[0].trace;openTrace()}}function clearTrace(){document.getElementById('trace-q').value='';document.getElementById('trace-explain').style.display='none';document.getElementById('trace-inline').innerHTML=''}function openTrace(){let id=document.getElementById('trace-q').value.trim();if(!id)return alert('Enter trace/event ID');let rows=_allRows.filter(r=>String(r.trace).includes(id)||String(r.event).includes(id)||String(r.message).includes(id));let errs=rows.filter(r=>r.level==='ERROR'||r.level==='FAILURE').length;document.getElementById('trace-explain').style.display='block';document.getElementById('trace-explain').innerHTML=`<b>Trace explanation:</b> ${errs?`This trace contains ${errs} failure signal(s). Start at the first ERROR/FAILURE and read previous INFO/DEBUG lines.`:'No failure in this trace. Use it as timing/context evidence.'}`;document.getElementById('trace-inline').innerHTML=rows.map(r=>`<div class="trace-row" onclick="openLogModal(${_allRows.indexOf(r)})" style="cursor:pointer"><span>${esc(r.time)}</span><span class="badge ${badge(r.level)}">${r.level}</span><span>${esc(r.app)}</span><span class="mono">${esc(r.message).slice(0,520)}</span></div>`).join('')||'No trace found.';showSection('logs')}

// ── System Map state ─────────────────────────────────────────────────────────
let _smData=null,_selectedEndpoint=null;
function renderFlow(){
  let d=_lastResult||{},deps=d.dependencies||[];
  const set=(id,val)=>{let el=document.getElementById(id);if(el)el.innerHTML=val;};
  set('deps',deps.map(x=>`<span class="chip">${esc(x)}</span>`).join('')||'—');
  set('flow-hints',(d.suggestions||[]).map(x=>`• ${esc(x)}`).join('<br>')||'—');
  set('app-health',(d.app_health||[]).map(a=>`<div class="node-card"><b>${esc(a.app)}</b><div style="color:var(--tx2);font-size:12px">${a.lines} lines · ${a.errors} errors · ${a.warns} warnings · avg ${a.avg_latency}ms</div></div>`).join('')||'—');
  let max=Math.max(1,...(d.timeline_buckets||[]).map(b=>b.total));
  set('error-timeline',(d.timeline_buckets||[]).map(b=>`<div title="${esc(b.time)} · ${b.errors} errors" class="mini-bar ${b.errors?'err':''}" style="height:${Math.max(8,Math.round((b.total/max)*76))}px"></div>`).join('')||'—');
  let pay=(_allRows||[]).filter(r=>/checkout|amount|upi|bbps|success|payment|loan/i.test(r.message||''));
  set('business-signals',`<div class="node-card"><b>${pay.length}</b><div style="color:var(--tx2);font-size:12px">business/payment/loan related log records detected</div></div>`);
  set('security-signals',`<div class="node-card"><b>Enabled</b><div style="color:var(--tx2);font-size:12px">JWT, tokens, Aadhaar, PAN, mobile, email, names and identifiers masked.</div></div>`);
  loadSystemMap();
}
function switchArchTab(name,btn){document.querySelectorAll('.arch-panel').forEach(x=>x.classList.remove('active'));document.getElementById('arch-panel-'+name)?.classList.add('active');document.querySelectorAll('.arch-tab').forEach(x=>x.classList.remove('active'));btn?.classList.add('active');}
async function loadSystemMap(){
  let env=document.getElementById('sm-env-filter')?.value||'';
  let url='/api/v1/system-map'+(env?'?env='+encodeURIComponent(env):'');
  let data=await safeJson(await fetch(url)).catch(()=>null);
  if(!data||!data.apis){setHTML('flow-diagram','<span style="color:var(--tx3)">Upload logs or save API Registry to render the architecture map.</span>');return;}
  loadApiRegistry().catch(()=>{});
  _smData=data;
  let apiSel=byId('sm-api-select'); if(!apiSel)return; let prev=apiSel.value;
  apiSel.innerHTML='<option value="">— Select API —</option>'+data.apis.map(a=>`<option value="${esc(a.api_name)}">${esc(a.api_name)} (${a.total_requests} reqs)</option>`).join('');
  if(prev) apiSel.value=prev;
  setHTML('sm-api-overview',`<div class="table-wrap"><table><thead><tr><th>API</th><th>Owner</th><th>Envs</th><th>Requests</th><th>Errors</th><th>Error %</th></tr></thead><tbody>${data.apis.map(a=>`<tr onclick="document.getElementById('sm-api-select').value='${esc(a.api_name)}';onSmApiChange()" style="cursor:pointer"><td><b>${esc(a.api_name)}</b></td><td>${esc(a.owner||'Unassigned')}</td><td>${(a.environments||[]).join(', ')}</td><td>${a.total_requests}</td><td class="${a.total_errors?'pill-error':''}">${a.total_errors}</td><td>${a.error_rate}%</td></tr>`).join('')}</tbody></table></div>`);
  if(prev) onSmApiChange(); else if(data.apis.length){apiSel.value=data.apis[0].api_name;onSmApiChange();}
}
function onSmApiChange(){
  let apiName=document.getElementById('sm-api-select').value;
  if(!apiName||!_smData){setHTML('sm-endpoint-select','<option value="">— select API first —</option>');return;}
  let api=_smData.apis.find(a=>a.api_name===apiName); if(!api)return;
  let epSel=byId('sm-endpoint-select'); if(!epSel)return;
  epSel.innerHTML='<option value="">— All endpoints —</option>'+(api.endpoints||[]).map(e=>`<option value="${esc(e.endpoint||'/')}">${esc(e.method||'?')} ${esc(e.endpoint||'/')} (${e.request_count} reqs, ${e.error_count} errs)</option>`).join('');
  setHTML('sm-endpoint-list',`<div class="table-wrap"><table><thead><tr><th>Method</th><th>Endpoint</th><th>Reqs</th><th>Errors</th><th>Avg Lat</th><th>Env</th></tr></thead><tbody>${(api.endpoints||[]).map(e=>`<tr onclick="document.getElementById('sm-endpoint-select').value='${esc(e.endpoint||'/')}';onSmEndpointChange()" style="cursor:pointer"><td><span class="status-pill">${esc(e.method||'?')}</span></td><td class="mono">${esc(e.endpoint||'/')}</td><td>${e.request_count}</td><td class="${e.error_count?'pill-error':''}">${e.error_count}</td><td>${e.avg_latency_ms}ms</td><td>${esc(e.environment||'')}</td></tr>`).join('')}</tbody></table></div>`);
  document.getElementById('sm-kpi-row').style.display='';document.getElementById('sm-kpi-reqs').textContent=api.total_requests;document.getElementById('sm-kpi-errs').textContent=api.total_errors;document.getElementById('sm-kpi-erate').textContent=api.error_rate+'%';document.getElementById('sm-kpi-lat').textContent='—';document.getElementById('sm-kpi-trace').textContent='—';
  if(api.endpoints&&api.endpoints.length){_selectedEndpoint=api.endpoints[0];renderArchitecture(_selectedEndpoint);} else setHTML('flow-diagram','No endpoints detected for this API. Add endpoints in API Registry.');
}
function onSmEndpointChange(){let apiName=document.getElementById('sm-api-select').value,epVal=document.getElementById('sm-endpoint-select').value;if(!apiName||!_smData)return;let api=_smData.apis.find(a=>a.api_name===apiName);if(!api)return;let ep=epVal?api.endpoints.find(e=>(e.endpoint||'/')==epVal):api.endpoints[0];if(ep){_selectedEndpoint=ep;renderArchitecture(ep);}}
function renderArchitecture(ep){
  if(!ep) return;
  renderArchitectureSvg(ep);
  renderTraceWaterfall(ep);
  renderCallMatrix(ep);
  safeSetHTML('sm-trace-path',`<b>Trace example:</b> <code class="mono">${esc(ep.sample_trace||'—')}</code>`);
  safeSetText('sm-kpi-lat',(ep.avg_latency_ms||0)+'ms');
  if(ep.sample_trace) safeSetText('sm-kpi-trace',ep.sample_trace.slice(0,24)+(ep.sample_trace.length>24?'…':''));
  const arch=ep.architecture||{};
  const flow=(arch.simple_flow&&arch.simple_flow.length?arch.simple_flow:(ep.flow_steps||[]));
  const hints=(arch.hints||[]);
  safeSetHTML('flow-hints',(flow.length?'<b>Clean high-level flow</b><br>'+flow.map(x=>`<span class="flow-node">${esc(x)}</span>`).join('<span class="flow-arrow">→</span>')+'<br><br>':'')+(hints.length?hints.map(h=>'• '+esc(h)).join('<br>'):'• Start with Guided Debugging: inspect the top failed trace and compare the 10 preceding log lines.<br>• Group similar errors and assign ownership by app/dependency instead of reading raw logs line by line.'));
  renderEndpointIntelligence(ep);
}
function renderArchitectureSvg(ep){

  let arch=ep.architecture||{},nodes=arch.nodes||[],edges=arch.edges||[];
  if(!nodes.length){
    setHTML('flow-diagram',(ep.flow_steps||[]).map((s,i,a)=>`<span class="flow-node">${esc(s)}</span>${i<a.length-1?'<span class="flow-arrow">→</span>':''}`).join('')||'No topology detected for this endpoint.');
    return;
  }
  // Only use tiers that actually have nodes — avoid blank columns
  const ALL_TIERS=['Client','Gateway','API','Service','External','Data'];
  const activeTiers=ALL_TIERS.filter(t=>nodes.some(n=>n.tier===t));
  const groups={};
  activeTiers.forEach(t=>{groups[t]=nodes.filter(n=>n.tier===t);});

  const NODE_W=148, NODE_H=54, TIER_PAD=80, TIER_GAP=190;
  const maxPerTier=Math.max(1,...activeTiers.map(t=>groups[t].length));
  const ROW_GAP=90;
  const W=Math.max(960, TIER_PAD*2 + activeTiers.length * TIER_GAP);
  const H=Math.max(480, maxPerTier * ROW_GAP + 140);

  // Assign positions: one column per active tier
  const pos={};
  activeTiers.forEach((t,ti)=>{
    const g=groups[t]||[];
    const colX=TIER_PAD + ti*(W-TIER_PAD*2)/(activeTiers.length-1||1);
    g.forEach((n,i)=>{
      const totalH=(g.length-1)*ROW_GAP;
      const startY=(H-totalH)/2;
      pos[n.id||n.name]={x:colX-NODE_W/2, y:startY+i*ROW_GAP, w:NODE_W, h:NODE_H, cx:colX, cy:startY+i*ROW_GAP+NODE_H/2};
    });
  });

  // Tier column labels
  const labels=activeTiers.map((t,ti)=>{
    const colX=TIER_PAD + ti*(W-TIER_PAD*2)/(activeTiers.length-1||1);
    return `<text class="arch-tier-label" x="${colX}" y="22" text-anchor="middle">${esc(t)}</text>`;
  }).join('');

  // Tier column dividers (faint vertical lines)
  const dividers=activeTiers.slice(1).map((t,ti)=>{
    const x=TIER_PAD + (ti+0.5)*(W-TIER_PAD*2)/(activeTiers.length-1||1);
    return `<line x1="${x}" y1="34" x2="${x}" y2="${H}" stroke="rgba(255,255,255,.04)" stroke-width="1"/>`;
  }).join('');

  // Arrow marker definition
  const defs=`<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="rgba(167,139,250,.75)"/></marker><marker id="arrow-err" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill="rgba(244,63,94,.85)"/></marker></defs>`;

  // Edge paths — cubic bezier, left-to-right only
  const edgeSvg=edges.map(e=>{
    const a=pos[e.from], b=pos[e.to];
    if(!a||!b) return '';
    const isErr=e.errors>0;
    const x1=a.cx+(a.w/2), y1=a.cy;
    const x2=b.cx-(b.w/2), y2=b.cy;
    if(x1>=x2-10){
      // Same-tier or back-edge: draw arc above
      const mid=(y1+y2)/2, arcY=Math.min(y1,y2)-55;
      return `<path class="arch-edge${isErr?' error':''}" d="M${x1},${y1} C${x1+40},${arcY} ${x2-40},${arcY} ${x2},${y2}" marker-end="url(#${isErr?'arrow-err':'arrow'})" data-tip="${esc(e.from)} → ${esc(e.to)}<br>${e.count||0} calls · ${e.errors||0} errors · ${e.avg_latency_ms||0}ms"/>`;
    }
    const cx=(x1+x2)/2;
    return `<path class="arch-edge${isErr?' error':''}" d="M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}" marker-end="url(#${isErr?'arrow-err':'arrow'})" data-tip="${esc(e.from)} → ${esc(e.to)}<br>${e.count||0} calls · ${e.errors||0} errors · ${e.avg_latency_ms||0}ms"/>`;
  }).join('');

  // Node rectangles — color by health, show full name + stats
  const TIER_COLORS={
    'Client':'rgba(16,185,129,.22)','Gateway':'rgba(99,102,241,.28)',
    'API':'rgba(90,94,247,.28)','Service':'rgba(139,92,246,.24)',
    'External':'rgba(245,158,11,.22)','Data':'rgba(59,130,246,.22)'
  };
  const nodeSvg=nodes.map(n=>{
    const p=pos[n.id||n.name]; if(!p) return '';
    const fill=n.health==='critical'?'rgba(244,63,94,.32)':n.health==='warn'?'rgba(245,158,11,.26)':TIER_COLORS[n.tier]||'rgba(90,94,247,.24)';
    const stroke=n.health==='critical'?'rgba(244,63,94,.7)':n.health==='warn'?'rgba(245,158,11,.55)':'rgba(167,139,250,.45)';
    const label=esc(n.name).slice(0,22)+(n.name.length>22?'…':'');
    const stats=`${n.errors||0}err · ${n.avg_latency_ms||0}ms`;
    const tip=`${esc(n.name)}\nTier: ${esc(n.tier)}\n${n.count||0} records · ${n.errors||0} errors · ${n.avg_latency_ms||0}ms avg`;
    return `<g class="arch-node" data-tip="${esc(tip)}">
      <rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="14" fill="${fill}" stroke="${stroke}" stroke-width="1.4"/>
      <text x="${p.cx}" y="${p.y+20}" text-anchor="middle" style="font-size:12px;font-weight:800;fill:#f1f5f9">${label}</text>
      <text x="${p.cx}" y="${p.y+38}" text-anchor="middle" style="font-size:10px;fill:rgba(203,213,225,.6)">${esc(n.tier)} · ${stats}</text>
    </g>`;
  }).join('');

  setHTML('flow-diagram',`<svg class="arch-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMin meet" style="height:${H}px">${defs}${dividers}${labels}${edgeSvg}${nodeSvg}</svg>`);
  bindArchTooltips();
}
function renderTraceWaterfall(ep){
  // Inline panel: just show clickable summary cards
  let traces=(ep.architecture?.traces)||[];
  let panel=byId('arch-waterfall'); if(!panel)return;
  if(!traces.length){panel.innerHTML='<div style="color:var(--tx3);padding:20px">No trace waterfall detected for this endpoint.</div>';return;}
  panel.innerHTML=traces.map((t,idx)=>`
    <div class="trace-card" onclick="openWaterfallModal(${idx})" title="Click to open full waterfall">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <b class="mono" style="font-size:13px">${esc(t.trace)}</b>
        <div style="display:flex;gap:8px;align-items:center">
          <span style="color:${t.errors?'#fda4af':'#86efac'};font-size:12px;font-weight:700">${t.errors||0} errors · ${t.latency||0}ms</span>
          <span style="font-size:11px;color:var(--tx3)">${(t.rows||[]).length} hops</span>
          <span class="btn btn-ghost btn-sm" style="padding:4px 10px;font-size:11px">Open ↗</span>
        </div>
      </div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
        ${(t.rows||[]).slice(0,6).map(r=>`<span style="font-size:11px;background:${/ERROR|FAILURE/.test(r.level)?'rgba(244,63,94,.18)':'rgba(90,94,247,.14)'};border:1px solid ${/ERROR|FAILURE/.test(r.level)?'rgba(244,63,94,.35)':'rgba(167,139,250,.25)'};border-radius:999px;padding:3px 9px;color:var(--tx2)">${esc(r.service||'—')}</span>`).join('<span style="color:var(--tx3);align-self:center">→</span>')}
      </div>
    </div>`).join('');
  // Store traces reference for modal
  _currentWaterfallTraces = traces;
  _currentWaterfallEndpoint = ep;
}

let _currentWaterfallTraces=[], _currentWaterfallEndpoint=null;

function openWaterfallModal(idx){
  const traces=_currentWaterfallTraces;
  const ep=_currentWaterfallEndpoint||{};
  if(!traces||!traces.length) return;

  const t = idx!=null ? traces[idx] : traces[0];
  const allTraces = traces;
  const maxLat = Math.max(1, ...(t.rows||[]).map(r=>r.latency||0));

  // Subtitle
  document.getElementById('wf-subtitle').innerHTML=
    `Endpoint: <code class="mono">${esc(ep.endpoint||ep.sample_trace||'—')}</code> · API: <b>${esc(ep.api_name||t.api||'—')}</b>`;

  // KPI strip
  const totalLat=(t.rows||[]).reduce((a,r)=>a+(r.latency||0),0);
  document.getElementById('wf-kpis').innerHTML=`
    <div class="wf-kpi-tile"><small>Trace ID</small><b class="mono" style="font-size:13px;word-break:break-all">${esc(t.trace).slice(0,28)}</b></div>
    <div class="wf-kpi-tile"><small>Total Hops</small><b>${(t.rows||[]).length}</b></div>
    <div class="wf-kpi-tile"><small>Errors</small><b class="${t.errors?'pill-error':''}">${t.errors||0}</b></div>
    <div class="wf-kpi-tile"><small>Max Latency</small><b>${t.latency||0}ms</b></div>`;

  // Trace selector tabs if multiple traces
  let selector='';
  if(allTraces.length>1){
    selector=`<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
      ${allTraces.map((tr,i)=>`<button onclick="openWaterfallModal(${i})" class="btn btn-ghost btn-sm${i===idx?' btn-primary':''}" style="font-size:11px">${esc(tr.trace).slice(0,20)}${tr.errors?` ⚠ ${tr.errors}`:''}  </button>`).join('')}
    </div>`;
  }

  // Hop rows with latency bar
  const hops=(t.rows||[]).map(r=>{
    const barW=maxLat>0?Math.round((r.latency||0)/maxLat*100):0;
    const isErr=/ERROR|FAILURE/.test(r.level||'');
    return `<div class="wf-hop">
      <span class="mono" style="color:var(--tx3)">${esc(r.time||'—')}</span>
      <div>
        <b style="font-size:12px">${esc(r.service||'—')}</b>
        <div class="wf-bar-wrap"><div class="wf-bar${isErr?' err':''}" style="width:${barW}%"></div></div>
        <span style="font-size:10px;color:var(--tx3)">${r.latency||0}ms</span>
      </div>
      <span class="badge ${badge(r.level||'')}" style="align-self:start">${esc(r.level||'—')}</span>
      <span class="mono" style="font-size:11px;color:var(--tx2);word-break:break-word">${esc(r.message||'').slice(0,320)}</span>
    </div>`;
  }).join('');

  document.getElementById('wf-body').innerHTML=selector+`
    <div style="border:1px solid var(--bd);border-radius:16px;overflow:hidden">
      <div class="wf-hop" style="border-top:0;background:rgba(255,255,255,.04);padding:10px;font-size:11px;font-weight:900;text-transform:uppercase;color:var(--tx3);letter-spacing:.06em">
        <span>Timestamp</span><span>Service</span><span>Level</span><span>Message</span>
      </div>
      ${hops||'<div style="padding:16px;color:var(--tx3)">No hop data</div>'}
    </div>`;

  document.getElementById('waterfall-modal').classList.add('active');
}

function closeWaterfallModal(){document.getElementById('waterfall-modal').classList.remove('active');}
function copyWaterfall(){
  const t=_currentWaterfallTraces[0];if(!t)return;
  const text='Trace: '+t.trace+'\nErrors: '+t.errors+'\nMax latency: '+t.latency+'ms\n\n'+
    (t.rows||[]).map(r=>`${r.time||''} [${r.level}] ${r.service} ${r.latency||0}ms\n  ${r.message||''}`).join('\n');
  navigator.clipboard.writeText(text);alert('Waterfall copied');
}
function renderCallMatrix(ep){let rows=(ep.architecture?.matrix)||[];document.getElementById('arch-matrix').innerHTML=rows.length?`<div class="table-wrap"><table class="call-matrix"><thead><tr><th>From</th><th>To</th><th>Calls</th><th>Errors</th><th>Error %</th><th>Avg Latency</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.from)}</td><td>${esc(r.to)}</td><td>${r.calls}</td><td class="${r.errors?'pill-error':''}">${r.errors}</td><td>${r.error_rate}%</td><td>${r.avg_latency_ms}ms</td></tr>`).join('')}</tbody></table></div>`:'No service call matrix detected.';}
function bindArchTooltips(){let tip=document.getElementById('arch-tooltip');document.querySelectorAll('[data-tip]').forEach(el=>{el.onmousemove=e=>{tip.style.display='block';tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY+14)+'px';tip.innerHTML=el.getAttribute('data-tip');};el.onmouseleave=()=>tip.style.display='none';});}
function generateReport(){let d=_lastResult;if(!d)return;document.getElementById('rca-report').textContent=`ObserveX RCA\nFiles: ${_sessions.map(s=>s.name).join(', ')||'N/A'}\nRoot cause: ${d.root_cause}\nApps: ${(d.apps||[]).join(', ')||'N/A'}\nLines: ${d.total}\nErrors: ${d.errors}\nWarnings: ${d.warns}\nAvg latency: ${d.latency}ms\nHealth: ${Math.round(d.health_score)}/100\nDecision: ${d.deploy_summary?.recommendation||''}\nNext steps:\n- ${(d.suggestions||[]).join('\n- ')}`}
function copyReport(){generateReport();navigator.clipboard.writeText(document.getElementById('rca-report')?.textContent||'');alert('Report copied')}
async function exportCsv(){let res=await fetch('/export/csv',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rows:_visibleRows||[]})});let blob=await res.blob();let a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='observex-log-export.csv';a.click()}
function copyKey(){navigator.clipboard.writeText(document.getElementById('api-key-display').textContent.trim());alert('Dummy API header copied')}
async function loadApiDocs(){let d=await safeJson(await fetch('/api/docs'));document.getElementById('api-docs-json').textContent=JSON.stringify(d,null,2)}

// ── showSection: guard against missing section IDs ────────────────────────
function showSection(name,ev){
  document.querySelectorAll('.section-panel').forEach(s=>s.style.display='none');
  const el=document.getElementById('sec-'+name);
  if(el) el.style.display='block';
  document.querySelectorAll('.nav-link').forEach(n=>n.classList.remove('active'));
  if(ev?.currentTarget) ev.currentTarget.classList.add('active');
  if(name==='history')   loadHistory();
  if(name==='flow')      {renderFlow();loadSystemMap();setTimeout(()=>loadApiRegistry().catch(()=>{}),250);}
  if(name==='compliance')loadCompliance();
  if(name==='connectors')loadConnectors();
  if(name==='api')       loadApiDocs();
  if(name==='onboarding')loadOnboarding();
  if(name==='health')    loadSourceHealth();
  if(name==='performance')loadPerformance();
  if(name==='customdash')loadWidgets();
  if(name==='incidents') loadIncidents();
  if(name==='metrics')   loadLogMetrics();
  if(name==='marketplace')loadMarketplace();
  if(name==='billing')   loadBilling();
  if(name==='settings')  {loadInvites();loadMembers();}
}

// ── Stub functions for sections not yet fully implemented ─────────────────
function loadOnboarding(){const el=document.getElementById('onboarding-content');if(el)el.innerHTML=`<div class="insight"><h3>Quick Start</h3><ol style="color:var(--tx2);margin-top:10px;line-height:2"><li>Upload a <code>.log</code> or <code>.txt</code> file from the Dashboard tab</li><li>Browse parsed logs in <b>Log Search</b></li><li>Explore the service topology in <b>System Map</b></li><li>Set up ingestion from CI/CD or MuleSoft via <b>API Ingestion</b></li></ol></div>`;}
function loadSourceHealth(){const el=document.getElementById('source-health-content');if(el)el.innerHTML=_sessions.length?_sessions.map(s=>`<div class="node-card"><b>${esc(s.name)}</b><div style="color:var(--tx2);font-size:12px">${Math.round((s.size||0)/1024)} KB · ${(s.result?.log_rows||[]).length} rows · ${(s.result?.log_rows||[]).filter(r=>r.level==='ERROR').length} errors</div></div>`).join(''):'<div style="color:var(--tx3)">No active sources. Upload logs on the Dashboard.</div>';}
function loadPerformance(){const el=document.getElementById('performance-content');if(!el)return;const lats=_allRows.map(r=>Number(r.latency||0)).filter(Boolean).sort((a,b)=>a-b);if(!lats.length){el.innerHTML='<div style="color:var(--tx3)">No latency data detected yet. Upload logs with duration/latency fields.</div>';return;}const p50=lats[Math.floor(lats.length*.5)]||0,p95=lats[Math.floor(lats.length*.95)]||0,p99=lats[Math.floor(lats.length*.99)]||0,avg=Math.round(lats.reduce((a,b)=>a+b,0)/lats.length);el.innerHTML=`<div class="lite-grid" style="grid-template-columns:repeat(4,1fr)"><div class="kpi"><b>${avg}ms</b><span>Avg</span></div><div class="kpi"><b>${p50}ms</b><span>P50</span></div><div class="kpi"><b class="${p95>3000?'pill-error':p95>1000?'pill-warn':''}">${p95}ms</b><span>P95</span></div><div class="kpi"><b class="${p99>5000?'pill-error':''}">${p99}ms</b><span>P99</span></div></div>`;}
function loadWidgets(){const el=document.getElementById('widgets-content');if(el)el.innerHTML='<div style="color:var(--tx3)">Custom widget builder coming soon. Use the Dashboard for built-in charts.</div>';}
function loadIncidents(){const el=document.getElementById('incidents-content');if(!el)return;const errs=_allRows.filter(r=>r.level==='ERROR'||r.level==='FAILURE');if(!errs.length){el.innerHTML='<div style="color:var(--tx3)">No incidents detected. Upload logs with ERROR or FAILURE records.</div>';return;}const groups={};errs.forEach(r=>{const k=(r.message.match(/(?:Exception|ERROR|failed)[:\s]+([A-Za-z0-9_.:-]+)/i)||[])[1]||'General error';groups[k]??={count:0,first:r.time,last:r.time,app:r.app};groups[k].count++;groups[k].last=r.time;});el.innerHTML='<div class="table-wrap"><table><thead><tr><th>Error cluster</th><th>App</th><th>Count</th><th>First seen</th><th>Last seen</th><th>Status</th></tr></thead><tbody>'+Object.entries(groups).sort((a,b)=>b[1].count-a[1].count).map(([k,v])=>`<tr><td><b>${esc(k)}</b></td><td>${esc(v.app)}</td><td class="pill-error">${v.count}</td><td class="mono" style="font-size:11px">${esc(v.first)}</td><td class="mono" style="font-size:11px">${esc(v.last)}</td><td><span class="status-pill status-open">OPEN</span></td></tr>`).join('')+'</tbody></table></div>';}
function loadLogMetrics(){const el=document.getElementById('metrics-content');if(!el)return;if(!_allRows.length){el.innerHTML='<div style="color:var(--tx3)">No data. Upload logs first.</div>';return;}const apps=[...new Set(_allRows.map(r=>r.app).filter(Boolean))];el.innerHTML='<div class="table-wrap"><table><thead><tr><th>App</th><th>Total</th><th>Errors</th><th>Warnings</th><th>Error %</th><th>Avg Latency</th></tr></thead><tbody>'+apps.map(a=>{const rows=_allRows.filter(r=>r.app===a);const errs=rows.filter(r=>r.level==='ERROR'||r.level==='FAILURE').length;const warns=rows.filter(r=>r.level==='WARN').length;const lats=rows.map(r=>Number(r.latency||0)).filter(Boolean);const avg=lats.length?Math.round(lats.reduce((x,y)=>x+y,0)/lats.length):0;return`<tr><td><b>${esc(a)}</b></td><td>${rows.length}</td><td class="${errs?'pill-error':''}">${errs}</td><td class="${warns?'pill-warn':''}">${warns}</td><td>${rows.length?Math.round(errs/rows.length*100):0}%</td><td>${avg}ms</td></tr>`;}).join('')+'</tbody></table></div>';}
async function createAlert(){let name=document.getElementById('alert-env').value+' - '+(document.getElementById('alert-name').value||'Alert'),condition=document.getElementById('alert-cond').value,threshold=Number(document.getElementById('alert-threshold').value||0);await safeJson(await fetch('/alerts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,condition,threshold})}));alert('Alert created')}async function loadHistory(){
  let rows=await safeJson(await fetch('/history'));
  if(!Array.isArray(rows)){document.getElementById('history-body').innerHTML='<tr><td colspan="10">Error loading history.</td></tr>';return;}
  document.getElementById('history-body').innerHTML=rows.map(r=>`<tr>
    <td><input type="checkbox" class="history-check" value="${r.id}"></td>
    <td>${esc(r.env)}</td>
    <td>${esc(r.file)}</td>
    <td>${r.total}</td>
    <td class="${r.errors?'pill-error':''}">${r.errors}</td>
    <td>${r.warns}</td>
    <td>${r.latency}ms</td>
    <td style="font-size:11px">${esc(r.apps)}</td>
    <td style="font-size:11px">${esc(r.at)}</td>
    <td style="white-space:nowrap">
      <span class="danger-link" style="margin-right:10px" onclick="reloadSession(${r.id},'${esc(r.file)}')" title="Reload log rows from Postgres into active dashboard">↩ Reload</span>
      <span class="danger-link" onclick="deleteHistory(${r.id})">🗑 Delete</span>
    </td>
  </tr>`).join('')||'<tr><td colspan="10" style="text-align:center;color:var(--tx3)">No saved history yet. Upload a log file to create a session.</td></tr>';
  document.getElementById('history-status').textContent=rows.length?`${rows.length} session(s) stored in Postgres`:'';
}
async function reloadSession(sessionId,filename){
  let statusEl=document.getElementById('history-status');
  statusEl.textContent='⏳ Reloading session…';
  try{
    let r=await fetch('/api/v1/sessions/'+sessionId+'/rows');
    if(!r.ok){statusEl.textContent='❌ Reload failed: '+r.status;return;}
    let d=await r.json();
    if(d.error){statusEl.textContent='❌ '+d.error;return;}
    addSession(d, filename||('session-'+sessionId), 0);
    statusEl.textContent='✅ Session reloaded successfully';
    showSection('dashboard');
  }catch(e){statusEl.textContent='❌ Network error: '+e.message;}
}
async function deleteHistory(id){
  if(!confirm('Delete this session and its log rows from Postgres?')) return;
  await safeJson(await fetch('/history?id='+id,{method:'DELETE'}));
  loadHistory();
  loadSystemMap();
}
async function clearServerHistory(){
  if(confirm('Delete ALL saved sessions, log rows and system map data from Postgres?')){
    await safeJson(await fetch('/history',{method:'DELETE'}));
    loadHistory();
    loadSystemMap();
  }
}

async function loadCompliance(){let d=await safeJson(await fetch('/settings/saas'));document.getElementById('workspace-name').value=d.workspace?.name||'';document.getElementById('workspace-plan').value=d.workspace?.plan||'starter';document.getElementById('retention-days').value=d.retention?.days||30;document.getElementById('masked-only').checked=!!d.retention?.masked_only;document.getElementById('encrypted-raw').checked=!!d.retention?.encrypted_raw_logs;document.getElementById('workspace-info').innerHTML=`<b>${esc(d.workspace?.name||'Workspace')}</b><div style="color:var(--tx2);font-size:12px">Role: ${esc(d.role||'Admin')} · Plan: ${esc(d.workspace?.plan||'starter')}</div><div style="color:var(--tx3);font-size:12px;margin-top:6px">${esc(d.recommendation||'')}</div>`;document.getElementById('retention-info').innerHTML=`<b>${d.retention?.days||30} days</b><div style="color:var(--tx2);font-size:12px">Masked only: ${d.retention?.masked_only?'Yes':'No'} · Encrypted raw logs: ${d.retention?.encrypted_raw_logs?'Yes':'No'}</div>`;document.getElementById('usage-info').innerHTML=`<div class="node-card"><b>${d.storage?.mb||0} MB</b><div style="color:var(--tx2);font-size:12px">${d.storage?.stored_files||0} stored files · ${d.storage?.sessions||0} sessions · backend: ${esc(d.storage?.backend||'railway-volume')}</div><div style="color:var(--tx3);font-size:12px">Mongo configured: ${d.storage?.mongo_configured?'Yes':'No'} · Max upload: ${d.storage?.max_upload_mb||500} MB</div></div>`;loadAudit();loadDestinations()}
async function saveSaasSettings(){let body={workspace_name:document.getElementById('workspace-name').value,plan:document.getElementById('workspace-plan').value,retention_days:Number(document.getElementById('retention-days').value||30),masked_only:document.getElementById('masked-only').checked,encrypted_raw_logs:document.getElementById('encrypted-raw').checked};await safeJson(await fetch('/settings/saas',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));loadCompliance();alert('SaaS settings saved')}
async function applyRetention(){let d=await safeJson(await fetch('/retention/apply',{method:'POST'}));alert(`Retention cleanup complete. Deleted ${d.deleted_sessions||0} old session(s).`);loadCompliance();loadHistory()}
async function loadAudit(){let rows=await safeJson(await fetch('/audit'));document.getElementById('audit-body').innerHTML=(rows||[]).map(r=>`<tr><td>${esc(r.at)}</td><td>${esc(r.action)}</td><td>${esc(r.target)}</td><td>${esc(r.ip)}</td></tr>`).join('')||'<tr><td colspan="4">No audit events yet.</td></tr>'}
async function loadDestinations(){let rows=await safeJson(await fetch('/alert-destinations'));document.getElementById('destinations-list').innerHTML=(rows||[]).map(d=>`<span class="upload-pill"><b>${esc(d.kind)}</b>${esc(d.target)}<button onclick="deleteDestination(${d.id})">×</button></span>`).join('')||'<span style="color:var(--tx3)">No destinations yet.</span>'}
async function createDestination(){let kind=document.getElementById('dest-kind').value,target=document.getElementById('dest-target').value.trim();if(!target)return alert('Enter a destination target');await safeJson(await fetch('/alert-destinations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind,target})}));document.getElementById('dest-target').value='';loadDestinations()}
async function deleteDestination(id){await safeJson(await fetch('/alert-destinations?id='+id,{method:'DELETE'}));loadDestinations()}
async function loadConnectors(){let rows=await safeJson(await fetch('/connectors'));document.getElementById('connectors-body').innerHTML=(rows||[]).map(c=>`<tr><td>${esc(c.kind)}</td><td>${esc(c.name)}</td><td class="mono">${esc(JSON.stringify(c.config||{})).slice(0,180)}</td><td>${c.active?'Active':'Disabled'}</td><td><span class="danger-link" onclick="deleteConnector(${c.id})">Delete</span></td></tr>`).join('')||'<tr><td colspan="5">No connectors configured yet.</td></tr>'}
async function createConnector(){let kind=document.getElementById('connector-kind').value,name=document.getElementById('connector-name').value.trim(),cfg=document.getElementById('connector-config').value.trim();let config={};if(cfg){try{config=JSON.parse(cfg)}catch(e){return alert('Config must be valid JSON')}}if(!name)return alert('Enter connector name');await safeJson(await fetch('/connectors',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind,name,config})}));document.getElementById('connector-name').value='';document.getElementById('connector-config').value='';loadConnectors()}
async function deleteConnector(id){await safeJson(await fetch('/connectors?id='+id,{method:'DELETE'}));loadConnectors()}

async function loadDemo(){let d=await safeJson(await fetch('/demo/load',{method:'POST'}));_sessions.push({id:'demo-'+Date.now(),name:'demo-incident.log',size:0,result:d});recomputeAggregate();alert('Demo incident loaded')}
async function shareCurrentReport(){generateReport();let content=document.getElementById('rca-report')?.textContent||'No report yet';let d=await safeJson(await fetch('/reports/share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content,title:'ObserveX RCA Report',days:7})}));if(d.url){navigator.clipboard.writeText(d.url);alert('Safe masked report link copied: '+d.url)}else alert('Unable to create share link')}
async function loadOnboarding(){let d=await safeJson(await fetch('/onboarding/status'));document.getElementById('onboarding-steps').innerHTML=(d.steps||[]).map((s,i)=>`<div class="debug-step" data-step="${i+1}"><b>${esc(s.name)}</b> <span class="badge ${s.done?'badge-ok':'badge-warn'}">${s.done?'DONE':'PENDING'}</span></div>`).join('')}
async function loadSourceHealth(){let h=await safeJson(await fetch('/data-source-health'));document.getElementById('source-health-cards').innerHTML=Object.entries(h).filter(([k])=>k!=='connectors').map(([k,v])=>`<div class="action-card ${v.status==='active'||v.status==='ready'?'ok':v.status==='not_connected'?'warn':'critical'}"><small>${esc(k.replaceAll('_',' '))}</small><b>${esc(v.status||'unknown')}</b><small>${esc(v.last_seen||v.endpoint||'')}</small></div>`).join('');let jobs=await safeJson(await fetch('/ingestion/jobs'));document.getElementById('jobs-body').innerHTML=(jobs||[]).map(j=>`<tr><td>${j.id}</td><td>${esc(j.source)}</td><td>${esc(j.file)}</td><td>${esc(j.status)}</td><td>${j.bytes}</td><td>${j.lines}</td><td>${esc(j.finished_at||'')}</td></tr>`).join('')||'<tr><td colspan="7">No jobs yet.</td></tr>'}
async function loadPerformance(){let d=await safeJson(await fetch('/performance'));document.getElementById('perf-body').innerHTML=(d.metrics||[]).map(m=>`<tr><td>${esc(m.at)}</td><td>${esc(m.action)}</td><td>${m.duration_ms}ms</td><td>${m.rows}</td><td>${m.bytes}</td></tr>`).join('')||'<tr><td colspan="5">No performance metrics yet.</td></tr>'}
async function createInvite(){let role=document.getElementById('invite-role').value;let d=await safeJson(await fetch('/workspace/invites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role})}));loadInvites();if(d.code){navigator.clipboard.writeText(d.code);alert('Invite code copied: '+d.code)}}
async function loadInvites(){let box=document.getElementById('invite-list');if(!box)return;let rows=await safeJson(await fetch('/workspace/invites'));box.innerHTML=(rows||[]).map(i=>`<span class="env-pill"><b>${esc(i.role)}</b><span class="mono">${esc(i.code)}</span><small>${i.active?'active':'disabled'}</small></span>`).join('')||'<span style="color:var(--tx3)">No invites yet.</span>'}
async function loadMembers(){let body=document.getElementById('members-body');if(!body)return;let rows=await safeJson(await fetch('/workspace/members'));body.innerHTML=(rows||[]).map(m=>`<tr><td>${esc(m.name)}</td><td>${esc(m.email)}</td><td>${esc(m.role)}</td></tr>`).join('')||'<tr><td colspan="3">No members yet.</td></tr>'}

function safeSetHTML(id,html){const el=document.getElementById(id);if(!el){console.warn("Missing element",id);return false;}el.innerHTML=html;return true;}
function safeSetText(id,text){const el=document.getElementById(id);if(!el){console.warn("Missing element",id);return false;}el.textContent=text;return true;}
async function loadOnboarding(){try{let d=await safeJson(await fetch('/onboarding/status'));safeSetHTML('onboarding-content','<div class="insight"><h3>Quick Start</h3><p style="color:var(--tx2)">Upload logs, search rows, open System Map, and set alert rules.</p></div>'+((d.steps||[]).map((s,i)=>`<div class="debug-step" data-step="${i+1}"><b>${esc(s.name)}</b> <span class="badge ${s.done?'badge-ok':'badge-warn'}">${s.done?'DONE':'PENDING'}</span></div>`).join('')))}catch(e){console.warn(e)}}
async function loadSourceHealth(){try{let h=await safeJson(await fetch('/data-source-health'));let cards=Object.entries(h).filter(([k])=>k!=='connectors').map(([k,v])=>`<div class="action-card ${v.status==='active'||v.status==='ready'?'ok':v.status==='not_connected'?'warn':'critical'}"><small>${esc(k.replaceAll('_',' '))}</small><b>${esc(v.status||'unknown')}</b><small>${esc(v.last_seen||v.endpoint||'')}</small></div>`).join('');let jobs=await safeJson(await fetch('/ingestion/jobs'));let jobTable='<div class="table-wrap" style="margin-top:14px"><table><thead><tr><th>ID</th><th>Source</th><th>File</th><th>Status</th><th>Bytes</th><th>Lines</th><th>Finished</th></tr></thead><tbody>'+((jobs||[]).map(j=>`<tr><td>${j.id}</td><td>${esc(j.source)}</td><td>${esc(j.file)}</td><td>${esc(j.status)}</td><td>${j.bytes}</td><td>${j.lines}</td><td>${esc(j.finished_at||'')}</td></tr>`).join('')||'<tr><td colspan="7">No jobs yet.</td></tr>')+'</tbody></table></div>';safeSetHTML('source-health-content','<div class="actions-grid">'+cards+'</div>'+jobTable)}catch(e){console.warn(e)}}
async function loadPerformance(){try{let d=await safeJson(await fetch('/performance'));safeSetHTML('performance-content','<div class="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Duration</th><th>Rows</th><th>Bytes</th></tr></thead><tbody>'+((d.metrics||[]).map(m=>`<tr><td>${esc(m.at)}</td><td>${esc(m.action)}</td><td>${m.duration_ms}ms</td><td>${m.rows}</td><td>${m.bytes}</td></tr>`).join('')||'<tr><td colspan="5">No performance metrics yet.</td></tr>')+'</tbody></table></div>')}catch(e){console.warn(e)}}
function toggleAllHistory(checked){document.querySelectorAll('.history-check').forEach(cb=>cb.checked=!!checked);const master=document.getElementById('history-select-all');if(master)master.checked=!!checked;}
async function deleteSelectedHistory(){const ids=[...document.querySelectorAll('.history-check:checked')].map(cb=>cb.value);if(!ids.length){alert('Select at least one history item.');return;}if(!confirm(`Delete ${ids.length} selected session(s), log rows and system map data?`))return;for(const id of ids){await safeJson(await fetch('/history?id='+encodeURIComponent(id),{method:'DELETE'}));}loadHistory();loadSystemMap();}
function renderEnvLists(){document.querySelectorAll('.env-select').forEach(sel=>{let current=sel.value,first=sel.querySelector('option[value=""]')?'<option value="">All Envs</option>':'';sel.innerHTML=first+_environments.map(e=>`<option>${esc(e)}</option>`).join('');if([...sel.options].some(o=>o.value===current))sel.value=current});document.getElementById('env-list').innerHTML=_environments.map(e=>`<span class="env-pill"><b>${esc(e)}</b>${['PROD','UAT','SIT','DEV','PREPROD','DR'].includes(e)?'<small style="color:var(--tx3)">default</small>':`<button onclick="deleteEnvironment('${esc(e)}')">×</button>`}</span>`).join('')}async function addEnvironment(){let name=document.getElementById('new-env').value.trim();if(!name)return;let d=await safeJson(await fetch('/settings/environments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})}));_environments=d.environments;document.getElementById('new-env').value='';renderEnvLists()}async function deleteEnvironment(name){let d=await safeJson(await fetch('/settings/environments?name='+encodeURIComponent(name),{method:'DELETE'}));_environments=d.environments;renderEnvLists()}document.querySelectorAll('.nav-link').forEach(a=>{if(!a.dataset.title){let t=a.querySelector('.nav-text');if(t)a.dataset.title=t.textContent.trim()}});if(localStorage.getItem('observexSidebarCollapsed')==='1')document.getElementById('shell').classList.add('collapsed');renderEnvLists();renderResult({total:0,errors:0,warns:0,latency:0,apps:[],health_score:100,root_cause:'Upload logs to generate an incident summary.',findings:[{label:'No logs analysed yet',type:'info'}],smart_tags:[],top_errors:[],suggestions:[],action_cards:[{title:'Next action',value:'Upload logs',type:'warn'},{title:'API focus',value:'Waiting',type:'warn'},{title:'Dependency',value:'Waiting',type:'ok'},{title:'Readiness',value:'No baseline',type:'warn'}],hot_traces:[],app_health:[],dependencies:[],timeline_buckets:[],deploy_summary:{recommendation:'Waiting for logs.'},derived_metrics:{error_rate:0,success_rate:0,throughput:0,traces:0,apis:0,p95:0,sources:0,anomaly:'Normal'}});


function setQueryExample(q){document.getElementById('filter-q').value=q;applyClientSearch()}
async function saveCurrentSearch(){let q=document.getElementById('filter-q').value, title=prompt('Saved search name','Production errors');if(!title)return;await safeJson(await fetch('/saved-searches',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,query:q})}));loadSavedSearches()}
async function loadSavedSearches(){let rows=await safeJson(await fetch('/saved-searches'));let box=document.getElementById('saved-searches-box');box.innerHTML=(rows||[]).map(r=>`<div class="saved-search-item"><div><b>${esc(r.title)}</b><div class="mono" style="font-size:11px;color:var(--tx3)">${esc(r.query)}</div></div><div><button class="btn btn-ghost btn-sm" onclick="document.getElementById('filter-q').value='${esc(r.query)}';applyClientSearch()">Run</button><button class="btn btn-ghost btn-sm" onclick="deleteSavedSearch(${r.id})">Delete</button></div></div>`).join('')||'<span style="color:var(--tx3)">No saved searches yet.</span>'}
async function deleteSavedSearch(id){await safeJson(await fetch('/saved-searches?id='+id,{method:'DELETE'}));loadSavedSearches()}
async function loadWidgets(){try{let rows=await safeJson(await fetch('/dashboard-widgets'));safeSetHTML('widgets-content',(rows||[]).map(w=>`<div class="widget-card"><small>${esc(w.type)}</small><h3>${esc(w.title)}</h3><b>${esc(w.value||'—')}</b><div style="margin-top:10px"><button class="btn btn-ghost btn-sm" onclick="deleteWidget(${w.id})">Remove</button></div></div>`).join('')||'<div class="card">No widgets yet. Add your first dashboard widget.</div>')}catch(e){console.warn(e)}}
async function createWidget(){let type=document.getElementById('widget-type').value,title=document.getElementById('widget-title').value||type;await safeJson(await fetch('/dashboard-widgets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,title})}));document.getElementById('widget-title').value='';loadWidgets()}
async function deleteWidget(id){await safeJson(await fetch('/dashboard-widgets?id='+id,{method:'DELETE'}));loadWidgets()}
async function loadIncidents(){try{let rows=await safeJson(await fetch('/incidents'));safeSetHTML('incidents-content','<div class="table-wrap"><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>API</th><th>Owner</th><th>Status</th><th>Action</th></tr></thead><tbody>'+((rows||[]).map(i=>`<tr><td>${i.id}</td><td>${esc(i.title)}</td><td>${esc(i.severity||'Medium')}</td><td>${esc(i.impacted_apis||'')}</td><td>${esc(i.owner||'Unassigned')}</td><td><span class="status-pill ${i.status==='Resolved'?'status-resolved':i.status==='Acknowledged'?'status-ack':'status-open'}">${esc(i.status||'Open')}</span></td><td><button class="btn btn-ghost btn-sm" onclick="updateIncident(${i.id},'Acknowledged')">Ack</button><button class="btn btn-ghost btn-sm" onclick="updateIncident(${i.id},'Resolved')">Resolve</button></td></tr>`).join('')||'<tr><td colspan="7">No incidents yet.</td></tr>')+'</tbody></table></div>')}catch(e){console.warn(e)}}
async function createIncident(){let body={title:document.getElementById('incident-title').value||'Production incident',owner:document.getElementById('incident-owner').value,status:document.getElementById('incident-status').value};await safeJson(await fetch('/incidents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));loadIncidents()}
async function updateIncident(id,status){await safeJson(await fetch('/incidents/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})}));loadIncidents()}
async function loadLogMetrics(){try{let d=await safeJson(await fetch('/log-metrics'));safeSetHTML('metrics-content',`<div class="lite-grid"><div class="kpi"><b>${d.errors||0}</b><span>Errors</span></div><div class="kpi"><b>${d.success||0}</b><span>Success</span></div><div class="kpi"><b>${d.ingested_lines||0}</b><span>Ingested Lines</span></div><div class="kpi"><b>${esc(d.anomaly?.status||'Normal')}</b><span>Anomaly</span></div></div><div class="two"><div class="card"><h3>Metrics Summary</h3>${(d.metrics||[]).map(m=>`<div class="node-card"><b>${esc(m.name)}</b><div style="color:var(--tx2)">${esc(m.value)}</div></div>`).join('')||'<p style="color:var(--tx3)">No metrics yet.</p>'}</div><div class="card"><h3>Anomaly Summary</h3><div class="node-card"><b>${esc(d.anomaly?.status||'Normal')}</b><div style="color:var(--tx2)">${esc(d.anomaly?.reason||'Not enough history yet. Baseline will improve as logs are ingested.')}</div></div></div></div>`)}catch(e){console.warn(e)}}
async function loadMarketplace(){let rows=await safeJson(await fetch('/marketplace'));document.getElementById('marketplace-grid').innerHTML=(rows||[]).map(m=>`<div class="market-card"><div class="icon">${esc(m.icon)}</div><h3>${esc(m.name)}</h3><p style="color:var(--tx2)">${esc(m.description)}</p><button class="btn btn-ghost btn-sm" onclick="showSection('connectors',event)">${m.status==='available'?'Configure':'Coming soon'}</button></div>`).join('')}
async function loadBilling(){let d=await safeJson(await fetch('/billing/usage'));document.getElementById('bill-plan').textContent=d.plan;document.getElementById('bill-storage').textContent=d.storage_mb+' MB';document.getElementById('bill-ingestion').textContent=d.ingestion_gb_month+' GB';document.getElementById('bill-users').textContent=d.users;document.getElementById('bill-retention').textContent=d.retention_days+' days';document.getElementById('bill-alerts').textContent=d.alerts;document.getElementById('billing-limits').innerHTML=`<div class="node-card"><b>${esc(d.plan)} plan</b><div style="color:var(--tx2)">${d.limits.storage_gb} GB storage · ${d.limits.ingestion_gb_month} GB/month ingestion · ${d.limits.users} users · ${d.limits.retention_days} days retention · ${d.limits.alerts} alerts</div></div>`}

// V24 helpers and advanced reliability/system-map features
function byId(id){return document.getElementById(id)}
function setHTML(id,html){const el=byId(id); if(el){el.innerHTML=html;} else {console.warn('Missing element '+id);} }
function setText(id,text){const el=byId(id); if(el){el.textContent=text;} else {console.warn('Missing element '+id);} }
function renderEndpointIntelligence(ep){
  const req=Number(ep.request_count||0), err=Number(ep.error_count||0), lat=Number(ep.avg_latency_ms||0);
  const traces=(ep.architecture&&ep.architecture.traces)||[];
  const api=((_smData&&_smData.apis)||[]).find(a=>a.api_name===(byId('sm-api-select')||{}).value)||{};
  const hasManual=(ep.flow_steps||[]).length>2 || ((ep.architecture&&ep.architecture.simple_flow)||[]).length>2 || ((api.downstream_systems||[]).length>0);
  const conf=traces.length&&req?'High Confidence':hasManual?'Medium Confidence':'Needs Manual Mapping';
  const confClass=conf==='High Confidence'?'pill-ok':conf==='Medium Confidence'?'pill-warn':'pill-error';
  setHTML('flow-confidence',`<b class="${confClass}">${conf}</b><div style="color:var(--tx2);font-size:12px;margin-top:6px">Signals: ${traces.length} trace sample(s), ${req} request(s), ${hasManual?'manual registry available':'manual registry missing'}</div>`);
  const owner=api.owner||'Unassigned';
  setHTML('error-ownership',`<b>${esc(owner)}</b><div style="color:var(--tx2);font-size:12px;margin-top:6px">${err?err+' error(s) should be triaged by API owner first, then downstream owner if dependency step fails.':'No active error owner required.'}</div>`);
  const rate=Math.round(err/Math.max(1,req)*1000)/10; const sla=rate>5||lat>3000?'Breach risk':rate>1||lat>1000?'Watch':'Healthy';
  setHTML('endpoint-sla',`<b class="${sla==='Healthy'?'pill-ok':sla==='Watch'?'pill-warn':'pill-error'}">${sla}</b><div style="color:var(--tx2);font-size:12px;margin-top:6px">${rate}% errors · avg ${lat}ms · threshold suggestion: P95 &lt; 3s, error rate &lt; 1%</div>`);
  const failed=traces.find(t=>Number(t.errors||0)>0), success=traces.find(t=>!Number(t.errors||0));
  setHTML('trace-comparison',failed||success?`<div class="node-card"><b>Failed:</b> <code class="mono">${esc((failed||{}).trace||'Not found')}</code><br><b>Success:</b> <code class="mono">${esc((success||{}).trace||'Not found')}</code><div style="color:var(--tx2);font-size:12px;margin-top:6px">Compare failed trace hops against a successful trace for the same endpoint to isolate the first diverging service.</div></div>`:'No traces available yet. Upload logs with trace/correlation IDs.');
  setHTML('smart-rca',`<ol style="color:var(--tx2);line-height:1.9;margin-left:18px"><li>Open top failed trace waterfall.</li><li>Check 10 log lines before first ERROR.</li><li>Assign owner: ${esc(owner)}.</li><li>${lat>3000?'Investigate slow downstream latency.':err?'Group same error message across traces.':'No major hotspot detected.'}</li></ol>`);
}
async function loadApiRegistry(){
  const env=(byId('sm-env-filter')||{}).value||'';
  const data=await safeJson(await fetch('/api/v1/api-registry'+(env?'?env='+encodeURIComponent(env):''))).catch(()=>({apis:[]}));
  const rows=(data.apis||[]); window._apiRegistryRows=rows;
  setHTML('api-registry-list','<table><thead><tr><th>API</th><th>Env</th><th>Owner</th><th>Base URL</th><th>Downstream</th><th>Endpoints</th><th>Action</th></tr></thead><tbody>'+ (rows.map(r=>`<tr><td><b>${esc(r.api_name)}</b></td><td>${esc(r.environment)}</td><td>${esc(r.owner||'Unassigned')}</td><td class="mono">${esc(r.base_url||'—')}</td><td>${(r.downstream_systems||[]).map(x=>`<span class="chip">${esc(x)}</span>`).join(' ')||'—'}</td><td>${(r.endpoints||[]).length}</td><td><button class="btn btn-ghost btn-sm" onclick="fillRegistryForm(${r.id})">Edit</button></td></tr>`).join('') || '<tr><td colspan="7">No registry found. Add one above.</td></tr>') + '</tbody></table>');
}
function fillRegistryForm(id){
  const r=(window._apiRegistryRows||[]).find(x=>x.id===id); if(!r)return;
  byId('reg-api-name').value=r.api_name||''; byId('reg-env').value=r.environment||'PROD'; byId('reg-base-url').value=r.base_url||''; byId('reg-owner').value=r.owner||'';
  byId('reg-downstreams').value=(r.downstream_systems||[]).join(', ');
  byId('reg-endpoints').value=(r.endpoints||[]).map(e=>`${e.method||''} ${e.endpoint||'/'}`.trim()).join('\n');
}
async function saveApiRegistry(){
  const api=(byId('reg-api-name')||{}).value?.trim(); if(!api){alert('API name is required');return;}
  const endpoints=((byId('reg-endpoints')||{}).value||'').split('\n').map(x=>x.trim()).filter(Boolean).map(line=>{const m=line.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$/i);return m?{method:m[1].toUpperCase(),endpoint:m[2].trim()}:{endpoint:line};});
  const body={api_name:api,environment:(byId('reg-env')||{}).value||'PROD',base_url:(byId('reg-base-url')||{}).value||'',owner:(byId('reg-owner')||{}).value||'',downstream_systems:(byId('reg-downstreams')||{}).value||'',endpoints};
  const res=await safeJson(await fetch('/api/v1/api-registry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
  if(res.error){alert(res.error);return;} await loadApiRegistry(); await loadSystemMap(); alert('API Registry saved');
}
function renderUploadQuality(){
  const total=_allRows.length, traces=new Set(_allRows.map(r=>r.trace).filter(Boolean)).size, apis=new Set(_allRows.map(r=>r.app).filter(Boolean)).size;
  const unknown=_allRows.filter(r=>!r.app||r.app==='unknown'||!r.level).length; const conf=total?Math.max(5,Math.round(((total-unknown)/total)*100)):0;
  setHTML('upload-quality',`<div class="lite-grid" style="grid-template-columns:repeat(4,1fr)"><div class="kpi"><b>${apis}</b><span>APIs detected</span></div><div class="kpi"><b>${traces}</b><span>Trace IDs</span></div><div class="kpi"><b>${unknown}</b><span>Unknown lines</span></div><div class="kpi"><b>${conf}%</b><span>Parsing confidence</span></div></div>`);
}
// V24 stable loaders: override older duplicate functions and never write into missing IDs.
async function loadOnboarding(){try{let d=await safeJson(await fetch('/onboarding/status')).catch(()=>({steps:[]}));setHTML('onboarding-content','<ol style="color:var(--tx2);line-height:2;margin-left:18px"><li>Register APIs in System Map → API Registry.</li><li>Upload logs by environment.</li><li>Check Upload Quality, Trace Explorer and System Map.</li><li>Create incidents or widgets for repeating issues.</li></ol>'+((d.steps||[]).map((s,i)=>`<div class="debug-step" data-step="${i+1}"><b>${esc(s.name)}</b> <span class="badge ${s.done?'badge-ok':'badge-warn'}">${s.done?'DONE':'PENDING'}</span></div>`).join('')));renderUploadQuality();}catch(e){console.warn(e)}}
async function loadSourceHealth(){try{let h=await safeJson(await fetch('/data-source-health')).catch(()=>({}));let cards=Object.entries(h).filter(([k])=>k!=='connectors').map(([k,v])=>`<div class="action-card ${v.status==='active'||v.status==='ready'?'ok':v.status==='not_connected'?'warn':'critical'}"><small>${esc(k.replaceAll('_',' '))}</small><b>${esc(v.status||'unknown')}</b><small>${esc(v.last_seen||v.endpoint||'')}</small></div>`).join('');let jobs=await safeJson(await fetch('/ingestion/jobs')).catch(()=>[]);let jobTable='<div class="table-wrap" style="margin-top:14px"><table><thead><tr><th>ID</th><th>Source</th><th>File</th><th>Status</th><th>Bytes</th><th>Lines</th><th>Finished</th></tr></thead><tbody>'+((jobs||[]).map(j=>`<tr><td>${j.id}</td><td>${esc(j.source)}</td><td>${esc(j.file)}</td><td>${esc(j.status)}</td><td>${j.bytes}</td><td>${j.lines}</td><td>${esc(j.finished_at||'')}</td></tr>`).join('')||'<tr><td colspan="7">No jobs yet.</td></tr>')+'</tbody></table></div>';setHTML('source-health-content','<div class="actions-grid">'+(cards||'<div class="node-card">No connector health yet.</div>')+'</div>'+jobTable)}catch(e){console.warn(e)}}
async function loadPerformance(){try{let d=await safeJson(await fetch('/performance')).catch(()=>({metrics:[]}));setHTML('performance-content','<div class="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Duration</th><th>Rows</th><th>Bytes</th></tr></thead><tbody>'+((d.metrics||[]).map(m=>`<tr><td>${esc(m.at)}</td><td>${esc(m.action)}</td><td>${m.duration_ms}ms</td><td>${m.rows}</td><td>${m.bytes}</td></tr>`).join('')||'<tr><td colspan="5">No performance metrics yet.</td></tr>')+'</tbody></table></div>')}catch(e){console.warn(e)}}
async function loadWidgets(){try{let rows=await safeJson(await fetch('/dashboard-widgets')).catch(()=>[]);setHTML('widgets-content',(rows||[]).map(w=>`<div class="widget-card"><small>${esc(w.type)}</small><h3>${esc(w.title)}</h3><b>${esc(w.value||'—')}</b><div style="margin-top:10px"><button class="btn btn-ghost btn-sm" onclick="deleteWidget(${w.id})">Remove</button></div></div>`).join('')||'<div class="node-card">No widgets yet. Add your first dashboard widget.</div>')}catch(e){console.warn(e)}}
async function loadIncidents(){try{let rows=await safeJson(await fetch('/incidents')).catch(()=>[]);setHTML('incidents-content','<div class="table-wrap"><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>API</th><th>Owner</th><th>Status</th><th>Action</th></tr></thead><tbody>'+((rows||[]).map(i=>`<tr><td>${i.id}</td><td>${esc(i.title)}</td><td>${esc(i.severity||'Medium')}</td><td>${esc(i.impacted_apis||'')}</td><td>${esc(i.owner||'Unassigned')}</td><td><span class="status-pill ${i.status==='Resolved'?'status-resolved':i.status==='Acknowledged'?'status-ack':'status-open'}">${esc(i.status||'Open')}</span></td><td><button class="btn btn-ghost btn-sm" onclick="updateIncident(${i.id},'Acknowledged')">Ack</button><button class="btn btn-ghost btn-sm" onclick="updateIncident(${i.id},'Resolved')">Resolve</button></td></tr>`).join('')||'<tr><td colspan="7">No incidents yet.</td></tr>')+'</tbody></table></div>')}catch(e){console.warn(e)}}
async function loadLogMetrics(){try{let d=await safeJson(await fetch('/log-metrics')).catch(()=>({}));setHTML('metrics-content',`<div class="lite-grid"><div class="kpi"><b>${d.errors||0}</b><span>Errors</span></div><div class="kpi"><b>${d.warnings||0}</b><span>Warnings</span></div><div class="kpi"><b>${d.success||0}</b><span>Success</span></div><div class="kpi"><b>${d.ingested_lines||0}</b><span>Ingested Lines</span></div><div class="kpi"><b>${esc((d.anomaly||{}).status||'Normal')}</b><span>Anomaly</span></div></div><div class="two" style="margin-top:14px"><div class="card"><h3>Metrics Summary</h3>${(d.metrics||[]).map(m=>`<div class="node-card"><b>${esc(m.name)}</b><div style="color:var(--tx2)">${esc(m.value)}</div></div>`).join('')||'<p style="color:var(--tx3)">No metrics yet.</p>'}</div><div class="card"><h3>Anomaly Summary</h3><div class="node-card"><b>${esc((d.anomaly||{}).status||'Normal')}</b><div style="color:var(--tx2)">${esc((d.anomaly||{}).reason||'Not enough history yet. Baseline will improve as logs are ingested.')}</div></div></div></div>`)}catch(e){console.warn(e)}}


// V25 fixes: robust JSON handling, working Log Search buttons, Trace Explorer, and safer history deletion UI.
async function safeJson(res){
  const text = await res.text().catch(()=>"");
  let d = {};
  try { d = text ? JSON.parse(text) : {}; } catch(e) { d = {error: text || 'Invalid server response'}; }
  if(!res.ok) throw new Error(d.error || d.detail || ('HTTP '+res.status));
  return d;
}
function parseQueryLanguage(q){
  const out={text:[], env:'', app:'', level:'', trace:''};
  String(q||'').split(/\s+/).filter(Boolean).forEach(tok=>{
    const m=tok.match(/^(env|environment|app|api|level|trace|event)[:=](.+)$/i);
    if(m){ const k=m[1].toLowerCase(), v=m[2];
      if(k==='environment'||k==='env') out.env=v;
      else if(k==='api'||k==='app') out.app=v;
      else if(k==='level') out.level=v;
      else if(k==='trace'||k==='event') out.trace=v;
    } else out.text.push(tok);
  });
  return out;
}
function rowMatchesDateTime(r, fd, td, ft, tt){
  const raw=String(r.time||r.event_time||'').trim();
  if(!raw) return true;
  const datePart=(raw.match(/\d{4}-\d{2}-\d{2}/)||[''])[0];
  const timePart=(raw.match(/\d{2}:\d{2}/)||[''])[0];
  if(fd && datePart && datePart < fd) return false;
  if(td && datePart && datePart > td) return false;
  if(ft && timePart && timePart < ft) return false;
  if(tt && timePart && timePart > tt) return false;
  return true;
}
function applyClientSearch(){
  const env=(byId('filter-env')||{}).value||'';
  const file=(byId('filter-file')||{}).value||'';
  const app=(byId('filter-app')||{}).value||'';
  const level=(byId('filter-level')||{}).value||'';
  const fd=(byId('from-date')||{}).value||'', td=(byId('to-date')||{}).value||'';
  const ft=(byId('from-time')||{}).value||'', tt=(byId('to-time')||{}).value||'';
  const qRaw=(byId('filter-q')||{}).value||'';
  const ql=parseQueryLanguage(qRaw);
  const finalEnv=ql.env||env, finalApp=ql.app||app, finalLevel=ql.level||level;
  const traceNeedle=(ql.trace||'').toLowerCase(); const needle=ql.text.join(' ').toLowerCase();
  const rows=(_allRows||[]).filter(r=>{
    if(finalEnv && String(r.env||r.environment||'').toLowerCase()!==String(finalEnv).toLowerCase()) return false;
    if(file && String(r.uploadName||r.file||r.filename||'')!==file) return false;
    if(finalApp && !String(r.app||r.api||r.api_name||'').toLowerCase().includes(String(finalApp).toLowerCase())) return false;
    if(finalLevel && String(r.level||'').toUpperCase()!==String(finalLevel).toUpperCase()) return false;
    if(!rowMatchesDateTime(r,fd,td,ft,tt)) return false;
    if(traceNeedle){ const tr=[r.trace,r.event].map(x=>String(x||'')).join(' ').toLowerCase(); if(traceNeedle==='*'){ if(!tr.trim()) return false; } else if(!tr.includes(traceNeedle)) return false; }
    if(needle){ const hay=[r.trace,r.event,r.message,r.flow,r.app,r.api,r.endpoint,r.level,r.status].map(x=>String(x||'')).join(' ').toLowerCase(); if(!hay.includes(needle)) return false; }
    return true;
  });
  renderRows(rows);
}
function clearLogFilters(){
  ['filter-env','filter-file','filter-app','filter-level','from-date','to-date','from-time','to-time','filter-q'].forEach(id=>{const el=byId(id); if(el) el.value='';});
  renderRows(_allRows||[]);
}
function quickLevel(level){const el=byId('filter-level'); if(el) el.value=level; applyClientSearch();}
function quickSearch(q){const el=byId('filter-q'); if(el) el.value=(q==='trace'?'trace:*':q||''); applyClientSearch(); showSection('logs');}
function updateFilters(){
  const fill=(id,vals,label)=>{const el=byId(id); if(!el)return; const current=el.value; el.innerHTML=`<option value="">${label}</option>`+[...vals].sort().map(v=>`<option>${esc(v)}</option>`).join(''); if(current) el.value=current;};
  fill('filter-file', new Set((_allRows||[]).map(r=>r.uploadName||r.file||r.filename).filter(Boolean)), 'All Files');
  fill('filter-app', new Set((_allRows||[]).map(r=>r.app||r.api||r.api_name).filter(Boolean)), 'All Apps');
}
function openTrace(){
  const id=(byId('trace-q')||{}).value?.trim();
  if(!id) return alert('Enter trace/event ID');
  const rows=(_allRows||[]).filter(r=>[r.trace,r.event,r.message,r.flow,r.app,r.endpoint].some(v=>String(v||'').includes(id)));
  const errs=rows.filter(r=>/ERROR|FAILURE/i.test(r.level||'')).length;
  const explain=byId('trace-explain'), inline=byId('trace-inline');
  if(explain){explain.style.display='block';explain.innerHTML=`<b>Trace explanation:</b> ${errs?`This trace contains ${errs} failure signal(s). Start at the first ERROR/FAILURE and read previous INFO/DEBUG lines.`:'No failure found in the loaded rows for this trace. Use it as timing/context evidence.'}`;}
  if(inline){inline.innerHTML=rows.map(r=>`<div class="trace-row" onclick="openLogModal(${_allRows.indexOf(r)})" style="cursor:pointer"><span>${esc(r.time||'')}</span><span class="badge ${badge(r.level||'')}">${esc(r.level||'')}</span><span>${esc(r.app||r.api||'')}</span><span class="mono">${esc(r.message||'').slice(0,520)}</span></div>`).join('')||'<div style="color:var(--tx3);padding:14px">No trace found in currently loaded logs. Reload an upload session from Upload History or upload the related log file.</div>';}
  showSection('logs');
}
function clearTrace(){const tq=byId('trace-q'); if(tq)tq.value=''; const ex=byId('trace-explain'); if(ex)ex.style.display='none'; setHTML('trace-inline','');}
async function deleteHistory(id){
  if(!confirm('Delete this session and its indexed log rows?')) return;
  try{ await safeJson(await fetch('/history?id='+encodeURIComponent(id),{method:'DELETE'})); await loadHistory(); await loadSystemMap(); }
  catch(e){ alert('Delete failed: '+e.message); }
}
async function clearServerHistory(){
  if(!confirm('Delete ALL saved sessions, indexed log rows and system map data?')) return;
  try{ await safeJson(await fetch('/history',{method:'DELETE'})); await loadHistory(); await loadSystemMap(); }
  catch(e){ alert('Clear history failed: '+e.message); }
}
async function deleteSelectedHistory(){
  const ids=[...document.querySelectorAll('.history-check:checked')].map(cb=>cb.value);
  if(!ids.length){alert('Select at least one history item.');return;}
  if(!confirm(`Delete ${ids.length} selected session(s), log rows and system map data?`))return;
  try{ for(const id of ids){ await safeJson(await fetch('/history?id='+encodeURIComponent(id),{method:'DELETE'})); } await loadHistory(); await loadSystemMap(); }
  catch(e){ alert('Delete selected failed: '+e.message); }
}

setTimeout(()=>showSection('dashboard'),0);
