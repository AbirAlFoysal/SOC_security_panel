const WebScanWorkspace = (() => {
  const quote = value => /^[a-zA-Z0-9_.,:/=@%+{}-]+$/.test(value) ? value : "'"+value.replace(/'/g,"'\"'\"'")+"'";
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
  let project=null,tool=null,data=null,timer=null,selectedId=null,currentTab='output',generation=0,polling=false,currentOption=null,config=null,previousTarget='';
  const esc=escapeHTML, el=id=>document.getElementById('web-'+id);
  const display=()=>config?.name||(tool==='sqlmap'?'SQLmap':'Nikto');
  async function request(path,body){
    const headers={};
    if(body!==undefined){const auth=await(await fetch('/api/status')).json();headers['Content-Type']='application/json';headers['X-App-Token']=auth.token;}
    const response=await fetch(path,body===undefined?{cache:'no-store'}:{method:'POST',headers,body:JSON.stringify(body)});
    const result=await response.json();if(!response.ok)throw Error(result.error||'Request failed');return result;
  }
  const path=()=>`/api/projects/${project.id}/${tool}`;
  function webInitialTarget(project){
    if(config){
      const raw=project.host||project.ip;let host=raw;
      try{host=new URL(raw.includes('://')?raw:'http://'+(raw.includes(':')&&!raw.startsWith('[')?'['+raw+']':raw)).hostname;}catch(_){}
      if(config.target_kind==='file')return '';
      if(config.target_kind==='filter')return 'host '+host.replace(/^\[|\]$/g,'');
      if(config.target_kind==='service')return 'ssh://'+host;
    }

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
  function initialTarget(project){const value=webInitialTarget(project);return config?.target_kind==='fuzz-url'&&!value.includes('FUZZ')?value.replace(/\/$/,'')+'/FUZZ':value;}
  function commandTokens(){const tokens=tokenize(el('command').value);if(tokens[0]!==tool)throw Error('Command must begin with '+tool);return tokens;}
  const modeValue=()=>el('mode')?.value||'dir';
  function activeOptions(){return data.options.filter(o=>!o.modes?.length||o.modes.includes(modeValue()));}
  function optionFor(token){const flag=token.split('=')[0];return activeOptions().find(o=>o.aliases.some(a=>tool==='nikto'?a.toLowerCase()===flag.toLowerCase():a===flag));}
  function pieces(tokens){const rows=[];for(let i=1;i<tokens.length;i++){
    if(tool==='gobuster'&&i===1&&!tokens[i].startsWith('-')){rows.push({mode:true,tokens:[tokens[i]]});continue;}
    const o=optionFor(tokens[i]);let values=[tokens[i]];
    if(o&&o.kind!=='flag'&&!tokens[i].includes('=')&&i+1<tokens.length&&(o.kind!=='optional-value'||(tool!=='john'&&!tokens[i+1].startsWith('-'))))values.push(tokens[++i]);
    rows.push({option:o,tokens:values,positional:!o});
  }return rows;}
  function primaryPositions(tokens){return pieces(tokens).filter(r=>r.positional);}
  function targetOption(){let flag=config?.target_option||(tool==='sqlmap'?'--url':'-host');if(tool==='gobuster')flag=modeValue()==='dns'?'--domain':modeValue()==='tftp'?'--server':'--url';return activeOptions().find(o=>o.flag===flag)||{flag,kind:flag.startsWith('$')?'positional-value':'value',aliases:[flag]};}
  function removeOption(tokens,option){
    const rows=pieces(tokens);let removedPrimary=false;
    const kept=rows.filter(row=>{
      if(option.flag.startsWith('$')){if(row.positional&&(!removedPrimary||tool==='tcpdump')){removedPrimary=true;return false;}return true;}
      return row.option?.flag!==option.flag;
    });tokens.splice(1,tokens.length-1,...kept.flatMap(r=>r.tokens));
  }
  function utility(tokens){return config&&tokens.some(t=>config.utility.includes(t.split('=')[0]));}
  function alternateTarget(tokens){return tool==='sqlmap'&&tokens.some(t=>['-r','-m','-l','-d','-g','--dork','-c','--openapi'].includes(t.split('=')[0]))||tool==='ffuf'&&tokens.includes('-request')||tool==='gobuster'&&['s3','gcs'].includes(modeValue());}
  function appendTarget(tokens,value){
    if(!value||utility(tokens)||alternateTarget(tokens))return;
    const option=targetOption();
    if(tool==='gobuster'&&modeValue()==='dns'){try{value=new URL(value.includes('://')?value:'http://'+value).hostname;}catch(_){}}
    if(tool==='gobuster'&&modeValue()==='tftp'){try{value=new URL(value.includes('://')?value:'http://'+value).host;}catch(_){}}
    if(config?.target_kind==='file'){
      const rows=pieces(tokens),index=rows.findIndex(r=>r.positional),before=rows.slice(0,index<0?rows.length:index).flatMap(r=>r.tokens),after=index<0?[]:rows.slice(index).flatMap(r=>r.tokens);
      tokens.splice(1,tokens.length-1,...before,value,...after);
    }else if(option.flag.startsWith('$'))tokens.push(...(tool==='tcpdump'?tokenize(value):[value]));else tokens.push(option.flag,value);
  }
  function setCommand(tokens){el('command').value=tokens.map(quote).join(' ');markOptions();}
  function syncTarget(){try{const tokens=commandTokens();
    if(config?.target_kind==='file'){
      const rows=pieces(tokens);let removed=false;
      const kept=rows.filter(r=>{if(!removed&&previousTarget&&r.positional&&r.tokens[0]===previousTarget){removed=true;return false;}return true;});
      tokens.splice(1,tokens.length-1,...kept.flatMap(r=>r.tokens));
    }else removeOption(tokens,targetOption());if(tool==='nikto')removeOption(tokens,data.options.find(o=>o.flag==='-url'));appendTarget(tokens,el('target').value.trim());previousTarget=el('target').value;setCommand(tokens);}catch(e){el('notice').textContent=e.message;}}
  function targetFromCommand(){try{const tokens=commandTokens();if(tool==='gobuster'&&config.modes.includes(tokens[1]))el('mode').value=tokens[1];if(targetOption().flag.startsWith('$')){const rows=primaryPositions(tokens);if(rows.length)el('target').value=tool==='tcpdump'?rows.flatMap(r=>r.tokens).map(quote).join(' '):rows[0].tokens[0];}else for(let i=1;i<tokens.length;i++){const o=optionFor(tokens[i]);if(o&&(o.flag===targetOption().flag||(tool==='nikto'&&o.flag==='-url'))){el('target').value=tokens[i].includes('=')?tokens[i].slice(tokens[i].indexOf('=')+1):tokens[i+1]||'';break;}}previousTarget=el('target').value;markOptions();}catch(_){}}
  function syncInterface(){try{const tokens=commandTokens(),option=data.options.find(o=>o.flag==='-i');removeOption(tokens,option);const rows=pieces(tokens),index=rows.findIndex(r=>r.positional);const flags=rows.slice(0,index<0?rows.length:index).flatMap(r=>r.tokens),rest=index<0?[]:rows.slice(index).flatMap(r=>r.tokens);setCommand([tool,...flags,'-i',el('interface').value,...rest]);}catch(e){el('notice').textContent=e.message;}}
  function presetOptions(selected){const select=el('preset'), signature=JSON.stringify([data.profiles,data.presets]);if(select.dataset.signature===signature&&!selected)return;const previous=selected||select.value||'regular';select.innerHTML='<option value="custom">Custom command</option><optgroup label="Built-in presets">'+Object.entries(data.profiles).map(([id,p])=>`<option value="${id}">${esc(p.name)}</option>`).join('')+'</optgroup>'+(data.presets.length?'<optgroup label="Global presets">'+data.presets.map(p=>`<option value="preset:${p.id}">${esc(p.name)}</option>`).join('')+'</optgroup>':'');select.value=previous;select.dataset.signature=signature;}
  function applyPreset(){const id=el('preset').value;if(id==='custom')return;let tokens;
    if(id.startsWith('preset:'))tokens=tokenize(data.presets.find(p=>'preset:'+p.id===id).command.replaceAll('{target}',quote(el('target').value.trim())));
    else{
      tokens=[tool,...data.profiles[id].args];
      if(tool==='gobuster'&&config.modes.includes(tokens[1]))el('mode').value=tokens[1];
      if(tool==='tcpdump'&&!utility(tokens)&&!tokens.includes('-r'))tokens.push('-i',el('interface').value);
      appendTarget(tokens,el('target').value.trim());
    }
    if(tool==='gobuster'&&config.modes.includes(tokens[1]))el('mode').value=tokens[1];
    setCommand(tokens);targetFromCommand();if(tool==='gobuster')el('target').disabled=['s3','gcs'].includes(modeValue());if(config)renderParameters();
  }
  function markOptions(){let tokens;try{tokens=commandTokens();}catch(_){return;}document.querySelectorAll('[data-web-option]').forEach(b=>{const option=data.options[Number(b.dataset.webOption)];b.classList.toggle('chosen',tokens.some(t=>optionFor(t)?.flag===option.flag));});}
  function renderParameters(){const query=el('search').value.toLowerCase(),groups=new Map();data.options.forEach((o,i)=>{if(o.modes?.length&&!o.modes.includes(modeValue()))return;if(`${o.flag} ${o.aliases.join(' ')} ${o.name} ${o.description}`.toLowerCase().includes(query)){if(!groups.has(o.group))groups.set(o.group,[]);groups.get(o.group).push([o,i]);}});el('parameters').innerHTML=[...groups].map(([group,items])=>`<details class="parameter-group" ${query||['Target','Detection','Scan options','Capture options','Authentication options','Input files','Input files and masks','Options'].includes(group)?'open':''}><summary>${esc(group)} <span>${items.length}</span></summary>${items.map(([o,i])=>`<button class="parameter-button" type="button" data-web-option="${i}" title="${esc(o.description)}"><code>${esc(o.flag.startsWith('$')?'Input':o.aliases.join(', '))}</code><span>${esc(o.name)}${o.kind==='flag'?'':' …'}</span></button>`).join('')}</details>`).join('')||'<p class="muted">No parameters found.</p>';markOptions();}
  function addOption(option,value){let tokens=commandTokens();
    if(option.flag.startsWith('$')){
      if(option.flag===targetOption().flag){el('target').value=value;syncTarget();el('preset').value='custom';return;}
      if(!primaryPositions(tokens).length&&config?.target_kind==='file'&&!utility(tokens))throw Error('Choose the primary hash or capture file first.');
      tokens.push(value);
    }else{
      if(!option.repeat)removeOption(tokens,option);for(const flag of option.exclusive||[]){const peer=data.options.find(o=>o.flag===flag);if(peer)removeOption(tokens,peer);}
      if(tool==='sqlmap'&&['-r','-m','-l','-d','--dork','-c','--openapi'].includes(option.flag))removeOption(tokens,targetOption());
      if(option.flag===targetOption().flag||(tool==='nikto'&&option.flag==='-url')){removeOption(tokens,targetOption());if(tool==='nikto')removeOption(tokens,data.options.find(o=>o.flag==='-url'));el('target').value=value;}
      const rows=pieces(tokens),index=rows.findIndex(r=>r.positional);const before=rows.slice(0,index<0?rows.length:index).flatMap(r=>r.tokens),after=index<0?[]:rows.slice(index).flatMap(r=>r.tokens);
      const addition=tool==='john'&&option.kind!=='flag'&&(value||option.allow_empty)?[option.flag+'='+value]:[option.flag,...(option.kind!=='flag'&&(value||option.allow_empty)?[value]:[])];
      tokens=[tool,...before,...addition,...after];if(tool==='gobuster'&&option.flag==='--status-codes'){const blacklist=activeOptions().find(o=>o.flag==='--status-codes-blacklist');if(blacklist){removeOption(tokens,blacklist);tokens.push('--status-codes-blacklist','');}}
      if(tool==='tcpdump'&&option.flag==='-i')el('interface').value=value;
    }
    el('preset').value='custom';setCommand(tokens);
  }
  function selectParameter(option){try{const tokens=commandTokens();if(!option.flag.startsWith('$')&&!option.repeat&&tokens.some(t=>optionFor(t)?.flag===option.flag)){removeOption(tokens,option);el('preset').value='custom';setCommand(tokens);return;}if(option.kind==='flag'){addOption(option);return;}currentOption=option;el('parameter-title').textContent=option.name+' · '+option.flag;el('description').textContent=option.description+(option.kind.startsWith('output')?' Output is saved inside this project.':'');el('value').value='';el('value').placeholder=option.hint;el('value').required=!option.allow_empty&&!['file','directory','file-or-value','optional-value','positional-file','state-file'].includes(option.kind);el('file-area').hidden=!['file','directory','file-or-value','positional-file','state-file'].includes(option.kind);el('file').closest('label').hidden=option.kind==='directory';el('directory').closest('label').hidden=option.kind!=='directory';el('file').value='';el('directory').value='';el('parameter-error').textContent='';el('parameter-dialog').showModal();}catch(e){el('notice').textContent=e.message;}}
  function content(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(',')[1]);reader.onerror=()=>reject(Error('Unable to read file'));reader.readAsDataURL(file);});}
  function markup(p){return `<div class="hakrawler-heading"><h1>${display()}</h1><span id="web-status">CONNECTING</span></div><div class="hakrawler-workbench"><div class="hakrawler-main"><form id="web-form" class="hakrawler-controls"><div class="hakrawler-top"><label>${esc(config?.target_label||'Target URL')}<span class="primary-input"><input id="web-target" value="${esc(initialTarget(p))}" placeholder="${config?.target_kind==='file'?'Choose an input file':config?.target_kind==='filter'?'host 127.0.0.1 and tcp':'Target'}">${config?.target_kind==='file'?'<button type="button" id="web-choose-input">File</button><input id="web-input-file" type="file" hidden>':''}</span></label>${tool==='gobuster'?`<label>Mode<select id="web-mode">${config.modes.map(m=>`<option>${m}</option>`).join('')}</select></label>`:''}${tool==='tcpdump'?`<label>Interface<select id="web-interface">${[...new Set([...(config.default_interface?[config.default_interface]:[]),...(config.interfaces||[])])].map(n=>`<option>${esc(n)}</option>`).join('')}</select></label>`:''}<label>Preset<select id="web-preset" aria-label="Preset"></select></label><div class="hakrawler-actions"><button class="primary" id="web-scan" disabled>${esc(config?.action||'Scan')}</button><button type="button" id="web-stop" disabled>Stop</button></div></div>${tool==='tcpdump'&&config.can_elevate?'<label class="capture-admin"><input type="checkbox" id="web-elevate">Use administrator permission for live capture</label>':''}<label class="command-label">Command<div class="command-field"><input id="web-command" aria-label="${display()} command" spellcheck="false"><button type="button" id="web-save-preset" aria-label="Save command as preset" title="Save command as preset">+</button></div></label></form><p id="web-notice" role="status">${config?esc(config.help):tool==='sqlmap'?'Use the full page URL with query parameters, POST data, or an HTTP request file.':'Enter the web service URL, including its protocol and port.'}</p><section class="web-results"><div class="hakrawler-tabs" role="tablist">${[['output','Output'],['details','Scan details'],['scans','Runs'],['files','Output files']].map(([id,name])=>`<button type="button" role="tab" data-web-tab="${id}" aria-selected="${id==='output'}">${name}</button>`).join('')}</div><div id="web-result" role="tabpanel"></div></section></div><aside class="hakrawler-parameters" aria-label="${display()} parameters"><div class="parameter-heading"><strong>Parameters</strong><span id="web-count"></span></div><input id="web-search" type="search" placeholder="Find a flag or name…" aria-label="Search ${display()} parameters"><div id="web-parameters"></div><a href="${config?config.reference:tool==='sqlmap'?'https://github.com/sqlmapproject/sqlmap/wiki/Usage':'https://github.com/sullo/nikto/wiki/Annotated-Option-List'}" target="_blank" rel="noopener">${display()} reference ↗</a></aside></div><dialog id="web-parameter-dialog"><form id="web-parameter-form"><h2 id="web-parameter-title"></h2><p id="web-description"></p><label>Value<input id="web-value" maxlength="8000"></label><div id="web-file-area"><label>Upload file<input type="file" id="web-file"></label><label>Upload directory<input type="file" webkitdirectory multiple id="web-directory"></label><small>Or enter an existing local path above.</small></div><p id="web-parameter-error" role="alert"></p><div class="form-actions"><button type="button" id="web-parameter-cancel">Cancel</button><button class="primary">Add parameter</button></div></form></dialog><dialog id="web-preset-dialog"><form id="web-preset-form"><h2>Save preset</h2><label>Preset name<input id="web-preset-name" maxlength="80" required></label><p class="muted">Presets are available in all projects. The target URL is replaced with each project’s target.</p><p id="web-preset-error" role="alert"></p><div class="form-actions"><button type="button" id="web-preset-cancel">Cancel</button><button class="primary">Save preset</button></div></form></dialog>`;}
  function selected(){return (selectedId?[data?.current,...(data?.history||[])].find(r=>r?.id===selectedId):data?.current||data?.history?.[0])||null;}
  function results(){const run=selected();el('status').textContent=!data.installed?'NOT INSTALLED':run?.status.toUpperCase()||'READY';el('scan').disabled=!data.installed||data.busy;el('stop').disabled=data.current?.status!=='running';
    if(!data.installed)el('notice').textContent=display()+' is not installed. Install it from the startscreen.';
    else if(run?.error)el('notice').textContent=run.error;
    else if(run)el('notice').textContent=run.status==='running'?'Scan running. Results are saved automatically.':run.status==='cancelled'?'Scan stopped. Partial results saved.':'Run '+run.status+(run.outcome==='exhausted'?' (candidate list exhausted)':'')+'. Results saved in this project.';
    if(currentTab!=='files')delete el('result').dataset.filesKey;
    if(currentTab==='files'){const gen=generation,key=run?`${gen}/${run.id}/${run.status}/${run.status==='running'?Math.floor(Date.now()/5000):''}`:'empty';if(el('result').dataset.filesKey===key)return;el('result').dataset.filesKey=key;el('result').innerHTML='<p class="muted">Loading output files…</p>';if(!run){el('result').innerHTML='<p class="muted">No run selected.</p>';return;}request(path()+`/history/${run.id}/files`).then(value=>{if(gen!==generation||currentTab!=='files'||selected()?.id!==run.id)return;el('result').innerHTML=value.files.map(f=>`<a class="output-file" href="${path()}/history/${run.id}/files/${f.token}" download><span>${esc(f.name)}<small>${Math.ceil(f.size/1024)} KB</small></span><span>↓</span></a>`).join('')||'<p class="muted">No output files saved yet.</p>';}).catch(e=>{if(gen===generation&&currentTab==='files'&&selected()?.id===run.id){el('result').textContent=e.message;delete el('result').dataset.filesKey;}});}
    else if(currentTab==='output'){const previous=el('result').querySelector('pre');const scroll=previous?.scrollTop||0;const atBottom=!previous||previous.scrollHeight-previous.clientHeight-previous.scrollTop<40;el('result').innerHTML=`<pre class="web-terminal">${esc(run?.output||'Prepare a command and click '+(config?.action||'Scan')+' to start.')}</pre>`;const terminal=el('result').querySelector('pre');terminal.scrollTop=atBottom?terminal.scrollHeight:scroll;}
    else if(currentTab==='details')el('result').innerHTML=run?`<dl><dt>Target</dt><dd>${esc(run.target)}</dd><dt>Status</dt><dd>${esc(run.status)}</dd><dt>Started</dt><dd>${esc(new Date(run.created_at).toLocaleString())}</dd><dt>Command</dt><dd><code>${esc(run.command)}</code></dd><dt>Executed command</dt><dd><code>${esc(run.executed_command||run.command)}</code></dd></dl><p class="muted">Reports, session data, and output stay inside projects/${esc(project.id)}/scans/${tool}/.</p>`:'<p class="muted">No scan selected.</p>';
    else el('result').innerHTML=(data.history||[]).map(r=>`<button class="saved-scan" type="button" data-web-run="${r.id}"><strong>${esc(r.title||r.command)}</strong><span>${esc(r.status)} · ${esc(new Date(r.created_at).toLocaleString())}</span></button>`).join('')||'<p class="muted">No saved scans yet.</p>';
  }
  function setTab(){document.querySelectorAll('[data-web-tab]').forEach(b=>b.setAttribute('aria-selected',b.dataset.webTab===currentTab));}
  async function poll(){if(!project||polling)return;polling=true;const gen=generation;try{const next=await request(path());if(gen!==generation)return;data=next;presetOptions();const count=document.querySelector(`[data-toggle-tool="${tool}"]`)?.closest('.tool-nav')?.querySelector('.tool-submenu span');if(count)count.textContent=data.history.length;results();}catch(e){if(gen===generation)el('notice').textContent=e.message;}finally{if(gen===generation)polling=false;}}
  async function mount(p,selectedTool,runId){unmount();project=p;tool=selectedTool;selectedId=runId||null;currentTab='output';data=null;const gen=generation;document.getElementById('webscan-workspace').innerHTML='<p class="muted">Loading tool workspace…</p>';
    try{data=await request(path());if(gen!==generation)return;config=data.workspace||null;document.getElementById('webscan-workspace').innerHTML=markup(p);presetOptions('regular');const saved=selected();if(runId&&saved){el('command').value=saved.command;el('target').value=saved.target;el('preset').value='custom';targetFromCommand();}else applyPreset();renderParameters();el('count').textContent=data.options.length;results();}catch(e){if(gen===generation){document.getElementById('webscan-workspace').innerHTML=`<p class="scan-error" role="alert">${esc(e.message)}</p><button type="button" id="web-retry">Retry loading workspace</button>`;el('retry').onclick=()=>mount(p,selectedTool,runId);}return;}
    el('target').oninput=syncTarget;
    if(el('mode'))el('mode').onchange=()=>{try{const tokens=commandTokens();const old=pieces(tokens).filter(r=>r.option&&!['--url','--domain','--server'].includes(r.option.flag)).flatMap(r=>r.tokens);const next=[tool,modeValue(),...old];appendTarget(next,el('target').value);setCommand(next);el('target').disabled=['s3','gcs'].includes(modeValue());el('preset').value='custom';renderParameters();}catch(e){el('notice').textContent=e.message;}};
    if(el('interface'))el('interface').onchange=()=>{syncInterface();el('preset').value='custom';};
    if(el('choose-input')){el('choose-input').onclick=()=>el('input-file').click();el('input-file').onchange=async()=>{const file=el('input-file').files[0];if(!file)return;const uploadGeneration=generation,endpoint=path();try{if(file.size>4*1024*1024)throw Error('Uploads must be at most 4 MB. For larger files enter an existing local path.');const encoded=await content(file);if(uploadGeneration!==generation)return;const uploaded=await request(endpoint+'/files',{files:[{path:file.name,content:encoded}]});if(uploadGeneration!==generation)return;el('target').value=uploaded.path;syncTarget();el('notice').textContent='Input file uploaded into this project.';}catch(e){if(uploadGeneration===generation)el('notice').textContent=e.message;}};}
el('command').oninput=()=>{el('preset').value='custom';targetFromCommand();};el('preset').onchange=applyPreset;el('search').oninput=renderParameters;
    el('parameters').onclick=e=>{const b=e.target.closest('[data-web-option]');if(b)selectParameter(data.options[Number(b.dataset.webOption)]);};
    el('parameter-cancel').onclick=()=>el('parameter-dialog').close();
    el('parameter-form').onsubmit=async e=>{e.preventDefault();const button=e.submitter,actionGeneration=generation,endpoint=path(),option=currentOption;button.disabled=true;try{let value=el('value').value;const directories=[...el('directory').files],files=directories.length?directories:[...el('file').files];if(files.length){if(files.length>200||files.reduce((sum,f)=>sum+f.size,0)>4*1024*1024)throw Error('Choose up to 200 files totaling 4 MB.');const payload={directory:Boolean(directories.length),files:await Promise.all(files.map(async f=>({path:f.webkitRelativePath||f.name,content:await content(f)})))};if(actionGeneration!==generation)return;const uploaded=await request(endpoint+'/files',payload);if(actionGeneration!==generation)return;value=uploaded.path;}if(actionGeneration!==generation||currentOption!==option||!el('parameter-dialog').open)return;if(!value&&option.kind!=='optional-value'&&!option.allow_empty)throw Error('Enter a value or choose a file.');addOption(option,value);el('parameter-dialog').close();}catch(error){if(actionGeneration===generation)el('parameter-error').textContent=error.message;}finally{button.disabled=false;}};
    el('save-preset').onclick=()=>{el('preset-name').value='';el('preset-error').textContent='';el('preset-dialog').showModal();};el('preset-cancel').onclick=()=>el('preset-dialog').close();
    el('preset-form').onsubmit=async e=>{e.preventDefault();const button=e.submitter,actionGeneration=generation;button.disabled=true;try{const tokens=commandTokens();if(config&&targetOption().flag.startsWith('$')&&config.target_kind!=='file'){const rows=pieces(tokens);const positions=rows.filter(r=>r.positional);if(positions.length){const retained=rows.filter(r=>!r.positional).flatMap(r=>r.tokens);tokens.splice(1,tokens.length-1,...retained,'{target}');}}else if(!config||config.target_kind!=='file'){for(let i=1;i<tokens.length;i++){const o=optionFor(tokens[i]);if(o&&(o.flag===targetOption().flag||(tool==='nikto'&&o.flag==='-url'))){if(tokens[i].includes('='))tokens[i]=tokens[i].split('=')[0]+'={target}';else tokens[i+1]='{target}';}}}const preset=await request(`/api/${tool}/presets`,{name:el('preset-name').value,command:tokens.map(quote).join(' ')});if(actionGeneration!==generation)return;await poll();if(actionGeneration!==generation)return;presetOptions('preset:'+preset.id);el('preset-dialog').close();el('notice').textContent='Global preset saved.';}catch(error){if(actionGeneration===generation)el('preset-error').textContent=error.message;}finally{button.disabled=false;}};
    el('form').onsubmit=async e=>{e.preventDefault();el('scan').disabled=true;const startGeneration=generation;try{const run=await request(path(),{command:el('command').value,target:el('target').value,profile:el('preset').value,elevate:el('elevate')?.checked===true});if(startGeneration!==generation)return;selectedId=run.id;currentTab='output';setTab();await poll();}catch(error){if(startGeneration===generation){el('notice').textContent=error.message;el('scan').disabled=!data.installed||data.busy;}}};
    el('stop').onclick=async()=>{const actionGeneration=generation;try{await request(path()+'/cancel',{});if(actionGeneration===generation)await poll();}catch(error){if(actionGeneration===generation)el('notice').textContent=error.message;}};
    document.getElementById('webscan-workspace').onclick=e=>{const tab=e.target.closest('[data-web-tab]');if(tab){currentTab=tab.dataset.webTab;setTab();results();}const run=e.target.closest('[data-web-run]');if(run){selectedId=run.dataset.webRun;const saved=selected();el('command').value=saved.command;el('target').value=saved.target;el('preset').value='custom';targetFromCommand();currentTab='output';setTab();results();}};
    timer=setInterval(poll,1500);
  }
  function unmount(){generation++;if(timer)clearInterval(timer);timer=null;project=null;polling=false;}
  return {mount,unmount};
})();
