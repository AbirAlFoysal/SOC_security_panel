const NmapWorkspace = (() => {
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
  function commandTokens(){const parsed=tokenize($('nmap-command').value);if(parsed[0]!=='nmap')throw Error('The command must begin with nmap.');return parsed;}
  function syncCommand(){ $('nmap-command').value=tokens.map(quote).join(' ');markOptions(); }
  function presetOptions(selected){
    const select=$('nmap-profile');if(!select||!data)return;
    const signature=JSON.stringify([Object.keys(data.profiles),data.presets]);
    if(select.dataset.signature===signature&&!selected)return;
    const value=selected||select.value||'regular';
    select.innerHTML='<option value="custom">Custom command</option><optgroup label="Built-in presets">'+Object.entries(data.profiles).map(([id,p])=>`<option value="${id}">${esc(p.name)}</option>`).join('')+'</optgroup>'+(data.presets.length?'<optgroup label="Saved presets">'+data.presets.map(p=>`<option value="preset:${p.id}">${esc(p.name)}</option>`).join('')+'</optgroup>':'');
    select.value=value;select.dataset.signature=signature;
  }
  function applyPreset(){
    const value=$('nmap-profile').value;if(value==='custom')return;
    const target=$('nmap-target').value.trim();
    try{
      if(value.startsWith('preset:')){const p=data.presets.find(p=>'preset:'+p.id===value);tokens=tokenize(p.command).map(t=>t==='{target}'?target:t);}
      else tokens=['nmap',...(data.profiles[value]?.args||['-sT']),'--reason','-v',...(target.includes(':')&&!target.includes('://')?['-6']:[]),target].filter(Boolean);
      previousTarget=target;syncCommand();
    }catch(e){$('nmap-notice').textContent=e.message;}
  }
  function markOptions(){
    if(!data)return;
    document.querySelectorAll('[data-nmap-option]').forEach(button=>{
      const option=data.options[Number(button.dataset.nmapOption)];
      button.classList.toggle('chosen',tokens.some(t=>t===option.flag||t.startsWith(option.flag+'=')||(option.kind==='optional'&&t.startsWith(option.flag))));
    });
  }
  function renderParameters(){
    if(!data)return;
    const query=$('nmap-parameter-search').value.toLowerCase();
    const groups=new Map();
    data.options.forEach((o,i)=>{if(`${o.flag} ${o.name} ${o.description}`.toLowerCase().includes(query)){if(!groups.has(o.group))groups.set(o.group,[]);groups.get(o.group).push([o,i]);}});
    $('nmap-parameter-list').innerHTML=[...groups].map(([name,options])=>`<details class="parameter-group" ${query||name==='Scan techniques'?'open':''}><summary>${esc(name)} <span>${options.length}</span></summary>${options.map(([o,i])=>`<button type="button" class="parameter-button" data-nmap-option="${i}" title="${esc(o.description)}${o.admin?' Administrator privileges required.':''}" aria-label="${esc(o.name)} (${esc(o.flag)})"><code>${esc(o.flag)}</code><span>${esc(o.name)}${o.admin?'<small title="Administrator privileges"> ◇</small>':''}${o.kind!=='flag'?'<small> …</small>':''}</span></button>`).join('')}</details>`).join('')||'<p class="muted">No parameters found.</p>';
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
    if(option.exclusive)data.options.filter(o=>o.exclusive===option.exclusive&&o.flag!==option.flag).forEach(o=>removeOption(o.flag));
    if(['-iL','-iR','--resume'].includes(option.flag)){const old=tokens.lastIndexOf($('nmap-target').value.trim());if(old>0)tokens.splice(old,1);$('nmap-target').value='';previousTarget='';}
    if(option.flag==='--resume')tokens=['nmap'];
    const parts=option.kind==='optional'?[option.flag+(value||'')]:option.kind==='flag'?[option.flag]:[option.flag,value];
    // Insert options before the current target, preserving an editable full command.
    const targetIndex=tokens.lastIndexOf($('nmap-target').value.trim());
    tokens.splice(targetIndex>0?targetIndex:tokens.length,0,...parts);
    $('nmap-profile').value='custom';syncCommand();
  }
  function selectParameter(option){
    try{
      tokens=commandTokens();
      if(tokens.includes(option.flag)||tokens.some(t=>t.startsWith(option.flag+'=')||(option.kind==='optional'&&t.startsWith(option.flag)))){removeOption(option.flag);$('nmap-profile').value='custom';syncCommand();return;}
      if(option.kind==='flag'){addOption(option);return;}
      currentOption=option;$('parameter-title').textContent=`${option.name} · ${option.flag}`;$('parameter-description').textContent=option.description;
      $('parameter-value').value='';$('parameter-value').placeholder=option.hint;
      $('parameter-error').textContent='';$('parameter-file').value='';$('parameter-directory').value='';
      $('parameter-file-area').hidden=!['file','directory','script'].includes(option.kind);
      $('parameter-file').closest('label').hidden=option.kind==='directory';$('parameter-directory').closest('label').hidden=option.kind==='file';
      $('parameter-value').required=!['optional','file','directory','script'].includes(option.kind);
      $('parameter-dialog').showModal();
    }catch(e){$('nmap-notice').textContent=e.message;}
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
        const uploaded=await request(`/api/projects/${activeProject.id}/nmap/files`,{directory:Boolean(directoryFiles.length),files:await Promise.all(files.map(async file=>({path:file.webkitRelativePath||file.name,content:await fileContent(file)})))});
        value=uploaded.path;
      }
      if(!value&&currentOption.kind!=='optional')throw Error('Enter a value or choose a file/directory.');
      if(currentOption.kind==='optional'&&value&&!/^[0-9,-]+$/.test(value))throw Error('Use a comma-separated list of numbers or ranges.');
      addOption(currentOption,value);$('parameter-dialog').close();
    }catch(error){$('parameter-error').textContent=error.message;}finally{button.disabled=false;}
  }
  function builderMarkup(project){return `<div class="nmap-heading"><h1>Nmap</h1><span id="nmap-run-status">CONNECTING</span></div><div class="nmap-workbench"><div class="nmap-main"><form id="nmap-form" class="nmap-controls"><div class="nmap-top"><label>Target<input id="nmap-target" value="${esc(project.host||project.ip)}" placeholder="IP, network, or host"></label><label>Preset<select id="nmap-profile" aria-label="Preset"><option value="regular">Regular scan</option></select></label><div class="nmap-actions"><button id="nmap-scan" class="primary" disabled>Scan</button><button id="nmap-stop" type="button" disabled>Stop</button></div></div><label class="command-label">Command<div class="command-field"><input id="nmap-command" aria-label="Nmap command" spellcheck="false"><button id="nmap-save-preset" type="button" title="Save command as a preset" aria-label="Save command as preset">+</button></div></label></form><p id="nmap-notice" role="status">Results and output files save inside this project.</p><div class="nmap-layout"><aside class="nmap-host-panel"><h2>Hosts</h2><div id="nmap-hosts"><p>No hosts yet</p></div></aside><section class="nmap-results"><div class="nmap-tabs" role="tablist">${[['output','Nmap Output'],['ports','Ports / Hosts'],['hosts','Host Details'],['scans','Scans']].map(([id,name])=>`<button type="button" role="tab" aria-selected="${id==='output'}" data-nmap-tab="${id}">${name}</button>`).join('')}</div><div id="nmap-result" role="tabpanel"></div></section></div></div><aside class="nmap-parameters" aria-label="Nmap parameters"><div class="parameter-heading"><strong>Parameters</strong><span id="parameter-count"></span></div><input id="nmap-parameter-search" type="search" placeholder="Find a flag or name…" aria-label="Search Nmap parameters"><div id="nmap-parameter-list"></div><a href="https://nmap.org/book/man.html" target="_blank" rel="noopener">Nmap reference ↗</a></aside></div><dialog id="parameter-dialog" aria-labelledby="parameter-title"><form id="parameter-form"><h2 id="parameter-title"></h2><p id="parameter-description"></p><label>Value or existing server path<input id="parameter-value" maxlength="4000"></label><div id="parameter-file-area"><p>Or upload a file / directory into this project:</p><label>File<input id="parameter-file" type="file"></label><label>Directory<input id="parameter-directory" type="file" webkitdirectory multiple></label></div><p id="parameter-error" class="form-message" role="status"></p><div class="form-actions"><button type="button" id="parameter-cancel">Cancel</button><button type="submit" class="primary">Add parameter</button></div></form></dialog><dialog id="preset-dialog" aria-labelledby="preset-title"><form id="preset-form"><h2 id="preset-title">Save preset</h2><label>Preset name<input id="preset-name" maxlength="80" required placeholder="e.g. Web service scan"></label><p class="muted">The current target is replaced when you reuse this preset in another project.</p><p id="preset-error" class="form-message" role="status"></p><div class="form-actions"><button type="button" id="preset-cancel">Cancel</button><button type="submit" class="primary">Save preset</button></div></form></dialog>`;}
  function results(){
    const run=selected(), hosts=run?.hosts||[];
    $('nmap-run-status').textContent=run ? `${run.status.toUpperCase()} · ${run.target}` : 'READY';
    $('nmap-scan').disabled=!data?.installed||data?.busy;
    $('nmap-stop').disabled=!(data?.current?.status==='running');
    $('nmap-hosts').innerHTML=hosts.length?hosts.map((h,i)=>`<button class="${hostIndex===i?'selected':''}" data-nmap-host="${i}">${esc(h.addresses[0]||h.names[0]||'Host')}<small>${esc(h.state)}</small></button>`).join(''):'<p>No hosts yet</p>';
    const pane=$('nmap-result');
    if(tabName==='output'){pane.innerHTML=`<pre class="nmap-terminal">${esc(run?.output||'Select a target and profile, then click Scan. Output will appear here.')}</pre>${run?.error?`<p class="scan-error">${esc(run.error)}</p>`:''}`;}
    else if(tabName==='ports'){
      const host=hosts[hostIndex]||hosts[0];
      pane.innerHTML=host?`<div class="port-scroll"><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>${host.ports.map(p=>`<tr><td>${esc(p.port)}/${esc(p.protocol)}</td><td class="port-${esc(p.state)}">${esc(p.state)}</td><td>${esc(p.service||'—')}</td><td>${esc(p.version||'—')}</td></tr>`).join('')}</tbody></table></div>${!host.ports.length?'<p class="muted scan-empty">No individual port results for this host.</p>':''}`:'<p class="scan-empty muted">Run a scan to see hosts and ports.</p>';
    }else if(tabName==='hosts'){
      pane.innerHTML=hosts.length?hosts.map(h=>`<article class="host-detail"><h3>${esc(h.addresses[0]||'Host')}</h3><p>State: ${esc(h.state)}</p><p>Addresses: ${esc(h.addresses.join(', '))}</p><p>Host names: ${esc(h.names.join(', ')||'—')}</p><p>Open ports: ${h.ports.filter(p=>p.state==='open').length}</p></article>`).join(''):'<p class="scan-empty muted">No host details yet.</p>';
    }else{
      const scans=[...(data?.current&&!(data?.history||[]).some(r=>r.id===data.current.id)?[data.current]:[]),...(data?.history||[])];
      pane.innerHTML=scans.length?scans.map(r=>`<button class="saved-scan" data-nmap-run="${r.id}"><strong>${esc(r.title||r.command||r.target)}</strong><span>${esc(r.status)} · ${esc(new Date(r.created_at).toLocaleString())}</span><code>${esc(r.command)}</code></button>`).join(''):'<p class="scan-empty muted">No saved scans in this project.</p>';
    }
  }
  async function poll(){
    if(!activeProject||polling)return;polling=true;const id=activeProject.id;
    try{const next=await request(`/api/projects/${id}/nmap`);if(activeProject?.id!==id)return;data=next;presetOptions();const counter=document.querySelector('[data-toggle-tool="nmap"]')?.closest('.tool-nav')?.querySelector('.tool-submenu span');if(counter)counter.textContent=data.history.length;results();}
    catch(e){if(activeProject?.id===id)$('nmap-notice').textContent=e.message;}
    finally{polling=false;}
  }
  async function mount(project,runId){
    activeProject=project;selectedId=runId||null;tabName='output';data=null;hostIndex=0;
    $('nmap-workspace').innerHTML=builderMarkup(project);
    previousTarget=project.host||project.ip;tokens=['nmap','-sT','--reason','-v',previousTarget];
    $('nmap-target').oninput=()=>{try{tokens=commandTokens();const index=tokens.lastIndexOf(previousTarget);if(index>0)tokens.splice(index,1,...($('nmap-target').value.trim()?[$('nmap-target').value.trim()]:[]));else if($('nmap-target').value.trim())tokens.push($('nmap-target').value.trim());previousTarget=$('nmap-target').value.trim();syncCommand();}catch(e){$('nmap-notice').textContent=e.message;}};
    $('nmap-command').oninput=()=>{try{tokens=commandTokens();$('nmap-profile').value='custom';markOptions();}catch(_){}};
    $('nmap-profile').onchange=applyPreset;
    $('nmap-parameter-search').oninput=renderParameters;
    $('nmap-parameter-list').onclick=e=>{const button=e.target.closest('[data-nmap-option]');if(button)selectParameter(data.options[Number(button.dataset.nmapOption)]);};
    $('parameter-cancel').onclick=()=>$('parameter-dialog').close();$('parameter-form').onsubmit=submitParameter;
    $('preset-cancel').onclick=()=>$('preset-dialog').close();
    $('nmap-save-preset').onclick=()=>{$('preset-name').value='';$('preset-error').textContent='';$('preset-dialog').showModal();};
    $('preset-form').onsubmit=async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;try{const target=$('nmap-target').value.trim();const parts=commandTokens();const index=parts.lastIndexOf(target);if(target&&index>0)parts[index]='{target}';const saved=await request('/api/nmap/presets',{name:$('preset-name').value,command:parts.map(quote).join(' ')});await poll();presetOptions('preset:'+saved.id);$('preset-dialog').close();$('nmap-notice').textContent='Preset saved and available in the Preset dropdown.';}catch(error){$('preset-error').textContent=error.message;}finally{button.disabled=false;}};
    $('nmap-form').onsubmit=async e=>{e.preventDefault();$('nmap-scan').disabled=true;try{const run=await request(`/api/projects/${project.id}/nmap`,{command:$('nmap-command').value,profile:$('nmap-profile').value});selectedId=run.id;tabName='output';setTab();$('nmap-notice').textContent=run.admin?'Scan requested. Approve the system authentication dialog.':'Scan running. Results will be saved automatically.';await poll();}catch(e){$('nmap-notice').textContent=e.message;$('nmap-scan').disabled=false;}};
    $('nmap-stop').onclick=async()=>{try{await request(`/api/projects/${project.id}/nmap/cancel`,{});$('nmap-notice').textContent='Stopping scan…';await poll();}catch(e){$('nmap-notice').textContent=e.message;}};
    $('nmap-workspace').onclick=e=>{const t=e.target.closest('[data-nmap-tab]');if(t){tabName=t.dataset.nmapTab;setTab();results();}const h=e.target.closest('[data-nmap-host]');if(h){hostIndex=Number(h.dataset.nmapHost);results();}const run=e.target.closest('[data-nmap-run]');if(run){selectedId=run.dataset.nmapRun;tabName='output';setTab();results();}};
    await poll();if(activeProject?.id===project.id){presetOptions('regular');applyPreset();renderParameters();$('parameter-count').textContent=data?.options?.length||'';timer=setInterval(poll,1500);}
  }
  function setTab(){document.querySelectorAll('[data-nmap-tab]').forEach(b=>b.setAttribute('aria-selected',b.dataset.nmapTab===tabName));}
  function unmount(){if(timer)clearInterval(timer);timer=null;activeProject=null;polling=false;}
  return {mount,unmount};
})();
