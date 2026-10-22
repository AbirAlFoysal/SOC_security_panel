const HakrawlerWorkspace = (() => {
  let timer=null, activeProject=null, data=null, selectedId=null, tabName='output', polling=false, hostIndex=0;
  const esc=escapeHTML;
  async function request(path,body){
    const headers={};if(body!==undefined){const auth=await (await fetch('/api/status')).json();headers['Content-Type']='application/json';headers['X-App-Token']=auth.token;}
    const response=await fetch(path,body===undefined?{}:{method:'POST',headers,body:JSON.stringify(body)});
    const value=await response.json();if(!response.ok)throw Error(value.error||'Request failed');return value;
  }
  function selected(){return (selectedId ? [data?.current,...(data?.history||[])].find(r=>r?.id===selectedId) : data?.current||data?.history?.[0])||null;}
  const quote = value => /^[a-zA-Z0-9_.,:/=@%+{}-]+$/.test(value) ? value : "'"+value.replace(/'/g,"'\"'\"'")+"'";
  let tokens=[], previousTarget='', currentOption=null, applying=false;
  function tokenize(text) {
    const result=[];let value='',mode=null,started=false;
    for(let i=0;i<text.length;i++){
      const c=text[i];
      if(mode==="'"){if(c==="'")mode=null;else value+=c;started=true;continue;}
      if(mode==='"'){if(c==='"')mode=null;else if(c==='\\'&&['"','\\','$','`'].includes(text[i+1]))value+=text[++i];else value+=c;started=true;continue;}
      if(c==="'"||c==='"'){mode=c;started=true;}
      else if(c==='\\'){if(i+1>=text.length)throw Error('Finish the escaped character.');value+=text[++i];started=true;}
      else if(/\s/.test(c)){if(started){result.push(value);value='';started=false;}}
      else{value+=c;started=true;}
    }
    if(mode)throw Error('Close the quote in the command.');if(started)result.push(value);return result;
  }
  function commandTokens(){const parsed=tokenize($('hakrawler-command').value);if(parsed[0]!=='hakrawler')throw Error('The command must begin with hakrawler.');return parsed;}
  function syncCommand(){ $('hakrawler-command').value=tokens.map(quote).join(' ');markOptions(); }
  function presetOptions(selected){
    const select=$('hakrawler-profile');if(!select||!data)return;
    const signature=JSON.stringify([Object.keys(data.profiles),data.presets]);
    if(select.dataset.signature===signature&&!selected)return;
    const value=selected||select.value||'regular';
    select.innerHTML='<option value="custom">Custom command</option><optgroup label="Built-in presets">'+Object.entries(data.profiles).map(([id,p])=>`<option value="${id}">${esc(p.name)}</option>`).join('')+'</optgroup>'+(data.presets.length?'<optgroup label="Saved presets">'+data.presets.map(p=>`<option value="preset:${p.id}">${esc(p.name)}</option>`).join('')+'</optgroup>':'');
    select.value=value;select.dataset.signature=signature;
  }
  function applyPreset(){
    const value=$('hakrawler-profile').value;if(value==='custom')return;
    try{
      if(value.startsWith('preset:')){const p=data.presets.find(p=>'preset:'+p.id===value);tokens=tokenize(p.command);}
      else tokens=['hakrawler',...(data.profiles[value]?.args||['-d','2','-u','-json'])];
      syncCommand();
    }catch(e){$('hakrawler-notice').textContent=e.message;}
  }
  function markOptions(){
    if(!data)return;
    document.querySelectorAll('[data-hakrawler-option]').forEach(button=>{
      const option=data.options[Number(button.dataset.hakrawlerOption)];
      button.classList.toggle('chosen',tokens.some(t=>t===option.flag||t.startsWith(option.flag+'=')||(option.kind==='optional'&&t.startsWith(option.flag))));
    });
  }
  function renderParameters(){
    if(!data)return;
    const query=$('hakrawler-parameter-search').value.toLowerCase();
    const groups=new Map();
    data.options.forEach((o,i)=>{if(`${o.flag} ${o.name} ${o.description}`.toLowerCase().includes(query)){if(!groups.has(o.group))groups.set(o.group,[]);groups.get(o.group).push([o,i]);}});
    $('hakrawler-parameter-list').innerHTML=[...groups].map(([name,options])=>`<details class="parameter-group" ${query||name==='Crawler options'?'open':''}><summary>${esc(name)} <span>${options.length}</span></summary>${options.map(([o,i])=>`<button type="button" class="parameter-button" data-hakrawler-option="${i}" title="${esc(o.description)}${o.admin?' Administrator privileges required.':''}" aria-label="${esc(o.name)} (${esc(o.flag)})"><code>${esc(o.flag)}</code><span>${esc(o.name)}${o.admin?'<small title="Administrator privileges"> ◇</small>':''}${o.kind!=='flag'?'<small> …</small>':''}</span></button>`).join('')}</details>`).join('')||'<p class="muted">No parameters found.</p>';
    markOptions();
  }
  function removeOption(flag){
    const option=data.options.find(o=>o.flag===flag);
    for(let i=tokens.length-1;i>=1;i--){
      const t=tokens[i];
      if(t===flag){const takes=option&&['value','file','script','directory','output'].includes(option.kind);tokens.splice(i,takes&&i+1<tokens.length?2:1);}
      else if(t.startsWith(flag+'=')||(option?.kind==='optional'&&t.startsWith(flag)))tokens.splice(i,1);
    }
  }
  function addOption(option,value){
    tokens=commandTokens();removeOption(option.flag);
    tokens.push(option.flag);if(option.kind!=='flag')tokens.push(value);
    $('hakrawler-profile').value='custom';syncCommand();
  }
  function selectParameter(option){
    try{
      tokens=commandTokens();
      if(tokens.includes(option.flag)||tokens.some(t=>t.startsWith(option.flag+'=')||(option.kind==='optional'&&t.startsWith(option.flag)))){removeOption(option.flag);$('hakrawler-profile').value='custom';syncCommand();return;}
      if(option.kind==='flag'){addOption(option);return;}
      currentOption=option;$('parameter-title').textContent=`${option.name} · ${option.flag}`;$('parameter-description').textContent=option.description;
      $('parameter-value').value='';$('parameter-value').placeholder=option.hint;
      $('parameter-error').textContent='';$('parameter-file').value='';$('parameter-directory').value='';
      $('parameter-file-area').hidden=!['file','directory','script'].includes(option.kind);
      $('parameter-file').closest('label').hidden=option.kind==='directory';$('parameter-directory').closest('label').hidden=option.kind==='file';
      $('parameter-value').required=!['optional','file','directory','script'].includes(option.kind);
      $('parameter-dialog').showModal();
    }catch(e){$('hakrawler-notice').textContent=e.message;}
  }
  async function fileContent(file){return await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(',')[1]);reader.onerror=()=>reject(Error('Unable to read file.'));reader.readAsDataURL(file);});}
  async function submitParameter(e){
    e.preventDefault();const button=e.submitter;button.disabled=true;
    try{
      let value=$('parameter-value').value.trim();
      const directoryFiles=[...$('parameter-directory').files], regularFiles=[...$('parameter-file').files];
      const files=directoryFiles.length?directoryFiles:regularFiles;
      if(files.length){
        if(files.length>200||files.reduce((n,f)=>n+f.size,0)>4*1024*1024)throw Error('Choose up to 200 files totaling 4 MB, or enter an existing server path.');
        const uploaded=await request(`/api/projects/${activeProject.id}/hakrawler/files`,{directory:Boolean(directoryFiles.length),files:await Promise.all(files.map(async file=>({path:file.webkitRelativePath||file.name,content:await fileContent(file)})))});
        value=uploaded.path;
      }
      if(!value&&currentOption.kind!=='optional')throw Error('Enter a value or choose a file/directory.');
      if(currentOption.kind==='optional'&&value&&!/^[0-9,-]+$/.test(value))throw Error('Use a comma-separated list of numbers or ranges.');
      addOption(currentOption,value);$('parameter-dialog').close();
    }catch(error){$('parameter-error').textContent=error.message;}finally{button.disabled=false;}
  }
  function builderMarkup(project){return `<div class="hakrawler-heading"><h1>Hakrawler</h1><span id="hakrawler-run-status">CONNECTING</span></div><div class="hakrawler-workbench"><div class="hakrawler-main"><form id="hakrawler-form" class="hakrawler-controls"><div class="hakrawler-top"><label>Target URLs (one per line)<textarea id="hakrawler-target" rows="2" placeholder="https://example.com/">${esc(initialTarget(project))}</textarea></label><label>Preset<select id="hakrawler-profile" aria-label="Preset"><option value="regular">Regular crawl</option></select></label><div class="hakrawler-actions"><button type="button" id="hakrawler-load-urls" title="Load target URLs from a text file">URL list</button><input id="hakrawler-url-file" type="file" accept="text/*,.txt,.list" hidden><button id="hakrawler-scan" class="primary" disabled>Crawl</button><button id="hakrawler-stop" type="button" disabled>Stop</button></div></div><label class="command-label">Command<div class="command-field"><input id="hakrawler-command" aria-label="Hakrawler command" spellcheck="false"><button id="hakrawler-save-preset" type="button" title="Save command as a preset" aria-label="Save command as preset">+</button></div></label></form><p id="hakrawler-notice" role="status">IPs are supported. Use the web service’s protocol and port; observed Nmap web ports are prefilled.</p><div class="hakrawler-layout"><aside class="hakrawler-host-panel"><h2>Summary</h2><div id="hakrawler-hosts"><p>No hosts yet</p></div></aside><section class="hakrawler-results"><div class="hakrawler-tabs" role="tablist">${[['output','Output'],['urls','URLs'],['sources','Sources'],['scans','Crawls']].map(([id,name])=>`<button type="button" role="tab" aria-selected="${id==='output'}" data-hakrawler-tab="${id}">${name}</button>`).join('')}</div><div id="hakrawler-result" role="tabpanel"></div></section></div></div><aside class="hakrawler-parameters" aria-label="Hakrawler parameters"><div class="parameter-heading"><strong>Parameters</strong><span id="parameter-count"></span></div><input id="hakrawler-parameter-search" type="search" placeholder="Find a flag or name…" aria-label="Search Hakrawler parameters"><div id="hakrawler-parameter-list"></div><a href="https://github.com/hakluke/hakrawler" target="_blank" rel="noopener">Hakrawler reference ↗</a></aside></div><dialog id="parameter-dialog" aria-labelledby="parameter-title"><form id="parameter-form"><h2 id="parameter-title"></h2><p id="parameter-description"></p><label>Value<input id="parameter-value" maxlength="4000"></label><div id="parameter-file-area"><p>Or upload a file / directory into this project:</p><label>File<input id="parameter-file" type="file"></label><label>Directory<input id="parameter-directory" type="file" webkitdirectory multiple></label></div><p id="parameter-error" class="form-message" role="status"></p><div class="form-actions"><button type="button" id="parameter-cancel">Cancel</button><button type="submit" class="primary">Add parameter</button></div></form></dialog><dialog id="preset-dialog" aria-labelledby="preset-title"><form id="preset-form"><h2 id="preset-title">Save preset</h2><label>Preset name<input id="preset-name" maxlength="80" required placeholder="e.g. Site crawl"></label><p class="muted">Presets are global across all projects. Target URLs are supplied separately.</p><p id="preset-error" class="form-message" role="status"></p><div class="form-actions"><button type="button" id="preset-cancel">Cancel</button><button type="submit" class="primary">Save preset</button></div></form></dialog>`;}
  function initialTarget(project){
    const value=(project.host||project.ip).trim();
    if(value.includes('://'))return value;
    const candidate=value.split(':').length>2&&!value.startsWith('[')?'['+value+']':value;
    try{
      const url=new URL('http://'+candidate);
      const host=url.hostname.replace(/^\[|\]$/g,'');
      const isIP=/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)||host.includes(':');
      if(!isIP)return 'https://'+value;
      if(url.port)return (['443','8443'].includes(url.port)?'https://':'http://')+candidate+'/';
      // Prefer an observed web port from this project's Nmap results, without probing new services.
      const priority=[80,443,8080,8000,8443,3000,5000,8888];
      for(const scan of project.tool_history?.nmap||[]){
        const matching=(scan.hosts||[]).filter(h=>(h.addresses||[]).includes(host));
        const ports=matching.flatMap(h=>h.ports||[]).filter(p=>p.state==='open'&&p.protocol==='tcp');
        const port=priority.find(n=>ports.some(p=>Number(p.port)===n));
        if(port){const tls=[443,8443].includes(port);return (tls?'https://':'http://')+candidate+([80,443].includes(port)?'':':'+port)+'/';}
      }
      return 'http://'+candidate+'/';
    }catch(_){return 'https://'+value;}
  }
  function results(){
    const run=selected(), urls=run?.urls||[];
    if(run?.status==='completed')$('hakrawler-notice').textContent=run.warning||(urls.length?`Crawl completed. ${urls.length} unique URLs saved.`:'No links discovered. Check HTTP/HTTPS, the web port, path, redirects, or whether the site needs its domain name.');
    else if(run?.status==='failed')$('hakrawler-notice').textContent=run.error||'Crawl failed. See output.';
    else if(run?.status==='cancelled')$('hakrawler-notice').textContent='Crawl cancelled. Partial results saved.';
    $('hakrawler-run-status').textContent=run ? run.status.toUpperCase() : 'READY';
    $('hakrawler-scan').disabled=!data?.installed||data?.busy;
    $('hakrawler-stop').disabled=!(data?.current?.status==='running');
    $('hakrawler-hosts').innerHTML=`<p><strong>${urls.length}</strong><br>unique URLs</p><p>${run?run.target.split('\n').length:0} seed URLs</p>`;
    const pane=$('hakrawler-result');
    if(tabName==='output')pane.innerHTML=`<pre class="hakrawler-terminal">${esc(run?.output||'Enter target URLs and choose a preset, then click Crawl.')}</pre>${run?.error?`<p class="scan-error">${esc(run.error)}</p>`:''}`;
    else if(tabName==='urls')pane.innerHTML=urls.length?`<div class="port-scroll"><table><thead><tr><th>URL</th><th>Source</th><th>Found on</th></tr></thead><tbody>${urls.map(row=>`<tr><td>${esc(row.url)}</td><td>${esc(row.source||'—')}</td><td>${esc(row.where||'—')}</td></tr>`).join('')}</tbody></table></div>`:'<p class="scan-empty muted">No URLs discovered yet. JSON output gives the most detailed results.</p>';
    else if(tabName==='sources'){
      const counts={};urls.forEach(row=>{const key=row.source||'Unspecified';counts[key]=(counts[key]||0)+1;});
      pane.innerHTML=urls.length?`<table><thead><tr><th>Source</th><th>URLs</th></tr></thead><tbody>${Object.entries(counts).map(([source,count])=>`<tr><td>${esc(source)}</td><td>${count}</td></tr>`).join('')}</tbody></table>`:'<p class="scan-empty muted">No source information yet.</p>';
    }else{
      const scans=[...(data?.current&&!(data?.history||[]).some(r=>r.id===data.current.id)?[data.current]:[]),...(data?.history||[])];
      pane.innerHTML=scans.length?scans.map(r=>`<button class="saved-scan" data-hakrawler-run="${r.id}"><strong>${esc(r.title||r.command)}</strong><span>${esc(r.status)} · ${esc(new Date(r.created_at).toLocaleString())}</span></button>`).join(''):'<p class="scan-empty muted">No saved crawls in this project.</p>';
    }
  }
  async function poll(){
    if(!activeProject||polling)return;polling=true;const id=activeProject.id;
    try{const next=await request(`/api/projects/${id}/hakrawler`);if(activeProject?.id!==id)return;data=next;presetOptions();const counter=document.querySelector('[data-toggle-tool="hakrawler"]')?.closest('.tool-nav')?.querySelector('.tool-submenu span');if(counter)counter.textContent=data.history.length;results();}
    catch(e){if(activeProject?.id===id)$('hakrawler-notice').textContent=e.message;}
    finally{polling=false;}
  }
  async function mount(project,runId){
    activeProject=project;selectedId=runId||null;tabName='output';data=null;hostIndex=0;
    $('hakrawler-workspace').innerHTML=builderMarkup(project);
    previousTarget=initialTarget(project);tokens=['hakrawler','-d','2','-u','-json'];
    $('hakrawler-load-urls').onclick=()=>$('hakrawler-url-file').click();
    $('hakrawler-url-file').onchange=async()=>{const file=$('hakrawler-url-file').files[0];if(!file)return;if(file.size>262144){$('hakrawler-notice').textContent='URL lists must be 256 KB or smaller.';return;}$('hakrawler-target').value=await file.text();$('hakrawler-notice').textContent='Loaded URL list. URLs will be passed to Hakrawler through stdin.';};
    $('hakrawler-command').oninput=()=>{try{tokens=commandTokens();$('hakrawler-profile').value='custom';markOptions();}catch(_){}};
    $('hakrawler-profile').onchange=applyPreset;
    $('hakrawler-parameter-search').oninput=renderParameters;
    $('hakrawler-parameter-list').onclick=e=>{const button=e.target.closest('[data-hakrawler-option]');if(button)selectParameter(data.options[Number(button.dataset.hakrawlerOption)]);};
    $('parameter-cancel').onclick=()=>$('parameter-dialog').close();$('parameter-form').onsubmit=submitParameter;
    $('preset-cancel').onclick=()=>$('preset-dialog').close();
    $('hakrawler-save-preset').onclick=()=>{$('preset-name').value='';$('preset-error').textContent='';$('preset-dialog').showModal();};
    $('preset-form').onsubmit=async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;try{const parts=commandTokens();const saved=await request('/api/hakrawler/presets',{name:$('preset-name').value,command:parts.map(quote).join(' ')});await poll();presetOptions('preset:'+saved.id);$('preset-dialog').close();$('hakrawler-notice').textContent='Preset saved and available in the Preset dropdown.';}catch(error){$('preset-error').textContent=error.message;}finally{button.disabled=false;}};
    $('hakrawler-form').onsubmit=async e=>{e.preventDefault();$('hakrawler-scan').disabled=true;try{const run=await request(`/api/projects/${project.id}/hakrawler`,{command:$('hakrawler-command').value,target:$('hakrawler-target').value,profile:$('hakrawler-profile').value});selectedId=run.id;tabName='output';setTab();$('hakrawler-notice').textContent=run.admin?'Scan requested. Approve the system authentication dialog.':'Crawl running. Results will be saved automatically.';await poll();}catch(e){$('hakrawler-notice').textContent=e.message;$('hakrawler-scan').disabled=false;}};
    $('hakrawler-stop').onclick=async()=>{try{await request(`/api/projects/${project.id}/hakrawler/cancel`,{});$('hakrawler-notice').textContent='Stopping crawl…';await poll();}catch(e){$('hakrawler-notice').textContent=e.message;}};
    $('hakrawler-workspace').onclick=e=>{const t=e.target.closest('[data-hakrawler-tab]');if(t){tabName=t.dataset.hakrawlerTab;setTab();results();}const h=e.target.closest('[data-hakrawler-host]');if(h){hostIndex=Number(h.dataset.hakrawlerHost);results();}const run=e.target.closest('[data-hakrawler-run]');if(run){selectedId=run.dataset.hakrawlerRun;tabName='output';setTab();results();}};
    await poll();if(activeProject?.id===project.id){presetOptions('regular');applyPreset();renderParameters();$('parameter-count').textContent=data?.options?.length||'';timer=setInterval(poll,1500);}
  }
  function setTab(){document.querySelectorAll('[data-hakrawler-tab]').forEach(b=>b.setAttribute('aria-selected',b.dataset.hakrawlerTab===tabName));}
  function unmount(){if(timer)clearInterval(timer);timer=null;activeProject=null;polling=false;}
  return {mount,unmount};
})();
