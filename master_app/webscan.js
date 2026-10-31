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
  const display=()=>config?.name||(tool==='sqlmap'?'SQLmap':tool==='nuclei'?'Nuclei':'Nikto');
  async function request(path,body){
    const headers={};
    if(body!==undefined){const auth=await(await fetch('/api/status')).json();headers['Content-Type']='application/json';headers['X-App-Token']=auth.token;}
    const response=await fetch(path,body===undefined?{cache:'no-store'}:{method:'POST',headers,body:JSON.stringify(body)});
    const result=await response.json();if(!response.ok)throw Error(result.error||'Request failed');return result;
  }
  
  let selectedHostIdx = -1, batchSearchQuery = '', activeBatchHostLog = '', activeBatchHostLogKey = '', batchUploadedTargetsText = '', batchUploadedFileName = '', batchDialogMode = 'start', savedHostsListScroll = 0, lastBatchRunId = null;

  function batchStatusBadge(status) {
    const s = String(status || 'pending').toLowerCase();
    const map = {
      findings: { cls: 'status-findings', label: '⚠ Findings' },
      findings_partial: { cls: 'status-partial', label: '⚠ Partial' },
      no_findings: { cls: 'status-clean', label: '✓ Clean' },
      clean: { cls: 'status-clean', label: '✓ Clean' },
      incomplete_waf: { cls: 'status-waf', label: '⛔ WAF' },
      waf: { cls: 'status-waf', label: '⛔ WAF' },
      timeout: { cls: 'status-timeout', label: '⏱ Timeout' },
      error: { cls: 'status-error', label: '✕ Error' },
      running: { cls: 'status-running', label: '⟳ Running' },
      pending: { cls: 'status-pending', label: '· Pending' },
      cancelled: { cls: 'status-cancelled', label: '— Cancelled' },
      completed: { cls: 'status-clean', label: '✓ Done' },
    };
    const item = map[s] || { cls: 'status-pending', label: s };
    return '<span class="batch-badge ' + item.cls + '">' + esc(item.label) + '</span>';
  }
const path=()=>`/api/projects/${project.id}/${tool}`;
  function webInitialTarget(project){
    const raw=(project.host||project.ip||'').trim();let host=raw;
    if(raw){
      try{host=new URL(raw.includes('://')?raw:'http://'+(raw.includes(':')&&!raw.startsWith('[')?'['+raw+']':raw)).hostname;}catch(_){}
    }
    if(config){
      if(config.target_kind==='file')return '';
      if(config.target_kind==='filter')return host?'host '+host.replace(/^\[|\]$/g,''):'';
      if(config.target_kind==='service')return host?'ssh://'+host:'';
    }

    if(!raw)return '';
    const value=raw;
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
  function targetOption(){let flag=config?.target_option||(tool==='sqlmap'?'--url':tool==='nuclei'?'-u':'-host');if(tool==='gobuster')flag=modeValue()==='dns'?'--domain':modeValue()==='tftp'?'--server':'--url';return activeOptions().find(o=>o.flag===flag)||{flag,kind:flag.startsWith('$')?'positional-value':'value',aliases:[flag]};}
  function removeOption(tokens,option){
    const rows=pieces(tokens);let removedPrimary=false;
    const kept=rows.filter(row=>{
      if(option.flag.startsWith('$')){if(row.positional&&(!removedPrimary||tool==='tcpdump')){removedPrimary=true;return false;}return true;}
      return row.option?.flag!==option.flag;
    });tokens.splice(1,tokens.length-1,...kept.flatMap(r=>r.tokens));
  }
  function utility(tokens){return Boolean(Array.isArray(config?.utility) && tokens.some(t=>config.utility.includes(t.split('=')[0])));}
  function alternateTarget(tokens){return tool==='sqlmap'&&tokens.some(t=>['-r','-m','-l','-d','-g','--dork','-c','--openapi'].includes(t.split('=')[0]))||tool==='nuclei'&&tokens.some(t=>['-l','-list'].includes(t.split('=')[0]))||tool==='ffuf'&&tokens.includes('-request')||tool==='gobuster'&&['s3','gcs'].includes(modeValue());}
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
  function targetFromCommand(){try{const tokens=commandTokens();if(tool==='gobuster'&&config?.modes?.includes(tokens[1]))el('mode').value=tokens[1];if(targetOption().flag.startsWith('$')){const rows=primaryPositions(tokens);if(rows.length)el('target').value=tool==='tcpdump'?rows.flatMap(r=>r.tokens).map(quote).join(' '):rows[0].tokens[0];}else for(let i=1;i<tokens.length;i++){const o=optionFor(tokens[i]);if(o&&(o.flag===targetOption().flag||(tool==='nikto'&&o.flag==='-url'))){el('target').value=tokens[i].includes('=')?tokens[i].slice(tokens[i].indexOf('=')+1):tokens[i+1]||'';break;}}previousTarget=el('target').value;markOptions();}catch(_){}}
  function syncInterface(){try{const tokens=commandTokens(),option=data.options.find(o=>o.flag==='-i');removeOption(tokens,option);const rows=pieces(tokens),index=rows.findIndex(r=>r.positional);const flags=rows.slice(0,index<0?rows.length:index).flatMap(r=>r.tokens),rest=index<0?[]:rows.slice(index).flatMap(r=>r.tokens);setCommand([tool,...flags,'-i',el('interface').value,...rest]);}catch(e){el('notice').textContent=e.message;}}
  function presetOptions(selected){const select=el('preset'), signature=JSON.stringify([data.profiles,data.presets]);if(select.dataset.signature===signature&&!selected)return;const previous=selected||select.value||'regular';select.innerHTML='<option value="custom">Custom command</option><optgroup label="Built-in presets">'+Object.entries(data.profiles).map(([id,p])=>`<option value="${id}">${esc(p.name)}</option>`).join('')+'</optgroup>'+(data.presets.length?'<optgroup label="Global presets">'+data.presets.map(p=>`<option value="preset:${p.id}">${esc(p.name)}</option>`).join('')+'</optgroup>':'');select.value=previous;select.dataset.signature=signature;}
  function applyPreset(){const id=el('preset').value;if(id==='custom')return;let tokens;
    if(id.startsWith('preset:'))tokens=tokenize(data.presets.find(p=>'preset:'+p.id===id).command.replaceAll('{target}',quote(el('target').value.trim())));
    else{
      tokens=[tool,...data.profiles[id].args];
      if(tool==='gobuster'&&config?.modes?.includes(tokens[1]))el('mode').value=tokens[1];
      if(tool==='tcpdump'&&!utility(tokens)&&!tokens.includes('-r'))tokens.push('-i',el('interface').value);
      appendTarget(tokens,el('target').value.trim());
    }
    if(tool==='gobuster'&&config?.modes?.includes(tokens[1]))el('mode').value=tokens[1];
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
  function markup(p){return `<div class="hakrawler-heading"><h1>${display()}</h1><span id="web-status">CONNECTING</span></div><div class="hakrawler-workbench"><div class="hakrawler-main"><form id="web-form" class="hakrawler-controls"><div class="hakrawler-top"><label>${esc(config?.target_label||'Target URL')}<span class="primary-input"><input id="web-target" value="${esc(initialTarget(p))}" placeholder="${config?.target_kind==='file'?'Choose an input file':config?.target_kind==='filter'?'host 127.0.0.1 and tcp':'Target'}">${config?.target_kind==='file'?'<button type="button" id="web-choose-input">File</button><input id="web-input-file" type="file" hidden>':''}</span></label>${tool==='gobuster'?`<label>Mode<select id="web-mode">${config.modes.map(m=>`<option>${m}</option>`).join('')}</select></label>`:''}${tool==='tcpdump'?`<label>Interface<select id="web-interface">${[...new Set([...(config.default_interface?[config.default_interface]:[]),...(config.interfaces||[])])].map(n=>`<option>${esc(n)}</option>`).join('')}</select></label>`:''}<label>Preset<select id="web-preset" aria-label="Preset"></select></label><div class="hakrawler-actions"><button class="primary" id="web-scan" disabled>${esc(config?.action||'Scan')}</button><button type="button" id="web-stop" disabled>Stop</button>${tool==='nuclei'?'<button type="button" id="web-batch-scan" class="batch-scan-btn">Batch Scan</button>':''}</div></div>${tool==='tcpdump'&&config.can_elevate?'<label class="capture-admin"><input type="checkbox" id="web-elevate">Use administrator permission for live capture</label>':''}<label class="command-label">Command<div class="command-field"><input id="web-command" aria-label="${display()} command" spellcheck="false"><button type="button" id="web-save-preset" aria-label="Save command as preset" title="Save command as preset">+</button></div></label></form><p id="web-notice" role="status">${config?esc(config.help):tool==='sqlmap'?'Use the full page URL with query parameters, POST data, or an HTTP request file.':'Enter the web service URL, including its protocol and port.'}</p><section class="web-results"><div class="hakrawler-tabs" role="tablist">${[['output','Output'],['details','Scan details'],['scans','Runs'],['files','Output files']].map(([id,name])=>`<button type="button" role="tab" data-web-tab="${id}" aria-selected="${id==='output'}">${name}</button>`).join('')}</div><div id="web-result" role="tabpanel"></div></section></div><aside class="hakrawler-parameters" aria-label="${display()} parameters"><div class="parameter-heading"><strong>Parameters</strong><span id="web-count"></span></div><input id="web-search" type="search" placeholder="Find a flag or name…" aria-label="Search ${display()} parameters"><div id="web-parameters"></div><a href="${config?config.reference:tool==='sqlmap'?'https://github.com/sqlmapproject/sqlmap/wiki/Usage':'https://github.com/sullo/nikto/wiki/Annotated-Option-List'}" target="_blank" rel="noopener">${display()} reference ↗</a></aside></div><dialog id="web-parameter-dialog"><form id="web-parameter-form"><h2 id="web-parameter-title"></h2><p id="web-description"></p><label>Value<input id="web-value" maxlength="8000"></label><div id="web-file-area"><label>Upload file<input type="file" id="web-file"></label><label>Upload directory<input type="file" webkitdirectory multiple id="web-directory"></label><small>Or enter an existing local path above.</small></div><p id="web-parameter-error" role="alert"></p><div class="form-actions"><button type="button" id="web-parameter-cancel">Cancel</button><button class="primary">Add parameter</button></div></form></dialog><dialog id="web-preset-dialog"><form id="web-preset-form"><h2>Save preset</h2><label>Preset name<input id="web-preset-name" maxlength="80" required></label><p class="muted">Presets are available in all projects. The target URL is replaced with each project’s target.</p><p id="web-preset-error" role="alert"></p><div class="form-actions"><button type="button" id="web-preset-cancel">Cancel</button><button class="primary">Save preset</button></div></form></dialog>
<dialog id="web-batch-dialog" class="batch-modal">
  <div class="batch-modal-card">
    <div class="batch-modal-header">
      <h2>Nuclei Batch Scan</h2>
      <button type="button" id="batch-close-btn" class="batch-close-btn" aria-label="Close dialog">✕</button>
    </div>
    <div class="batch-modal-body">
      <div class="batch-mode-switcher">
        <button type="button" class="batch-mode-btn active" id="batch-mode-start">Start New Batch Scan</button>
        <button type="button" class="batch-mode-btn" id="batch-mode-resume">Continue / Resume Scan</button>
      </div>

      <div class="batch-section">
        <label class="batch-section-title">Target list <span class="batch-hint">(CSV or TXT file, one URL per line, no header)</span></label>
        <div class="batch-file-dropzone" id="batch-dropzone">
          <input type="file" id="batch-file-input" accept=".csv,.txt" style="display:none">
          <button type="button" id="batch-browse-btn" class="batch-browse-btn">📁 Choose CSV or TXT file</button>
          <span class="batch-drop-text">Single column of URLs, no header</span>
          <div id="batch-file-status" class="batch-file-status">No file selected.</div>
        </div>
        <input type="text" id="batch-file-path" class="batch-text-input" placeholder="Or enter local file path (e.g. /home/user/targets.txt)">
        <details class="batch-paste-details">
          <summary>Or paste URLs directly</summary>
          <textarea id="batch-paste-targets" rows="4" placeholder="https://target1.example.com&#10;https://target2.example.com" class="batch-textarea"></textarea>
        </details>
      </div>

      <div class="batch-section" id="batch-resume-section" style="display:none">
        <label class="batch-section-title">Select Previous Session to Resume</label>
        <select id="batch-session-select" class="batch-select">
          <option value="">-- Choose previous session --</option>
        </select>
      </div>

      <details class="batch-config-details" open>
        <summary class="batch-section-title">Configuration Parameters</summary>
        <div class="batch-config-grid">
          <label>
            <span>MAX_WORKERS</span>
            <input type="number" id="batch-cfg-max-workers" value="7" min="1" max="64">
            <small>8GB RAM safe</small>
          </label>
          <label>
            <span>NUCLEI_TIMEOUT (s)</span>
            <input type="number" id="batch-cfg-nuclei-timeout" value="900" min="10">
            <small>15 min hard cap per target</small>
          </label>
          <label>
            <span>SIGTERM_GRACE (s)</span>
            <input type="number" id="batch-cfg-sigterm-grace" value="10" min="1">
          </label>
          <label>
            <span>RATE_LIMIT (RPS/worker)</span>
            <input type="number" id="batch-cfg-rate-limit" value="15" min="1">
            <small>WAF-safe</small>
          </label>
          <label>
            <span>NUCLEI_C (template concurrency)</span>
            <input type="number" id="batch-cfg-nuclei-c" value="5" min="1">
          </label>
          <label>
            <span>NUCLEI_BS (bulk size)</span>
            <input type="number" id="batch-cfg-nuclei-bs" value="5" min="1">
          </label>
          <label>
            <span>MAX_HOST_ERROR</span>
            <input type="number" id="batch-cfg-max-host-error" value="30" min="1">
            <small>abort scan after N errors</small>
          </label>
          <label>
            <span>STATS_INTERVAL (s)</span>
            <input type="number" id="batch-cfg-stats-interval" value="30" min="1">
          </label>
          <label class="grid-span-2">
            <span>TEMPLATE_TAGS</span>
            <input type="text" id="batch-cfg-template-tags" value="cve,tech,panel,exposure,misconfiguration,default-login">
          </label>
          <label class="grid-span-2">
            <span>SEVERITY</span>
            <input type="text" id="batch-cfg-severity" value="critical,high,medium">
          </label>
          <label>
            <span>STATE_FILE</span>
            <input type="text" id="batch-cfg-state-file" value=".progress.json">
          </label>
          <label>
            <span>STATE_SAVE_EVERY</span>
            <input type="number" id="batch-cfg-state-save-every" value="10" min="1">
          </label>
          <label>
            <span>LARGE_SCAN_WARN</span>
            <input type="number" id="batch-cfg-large-scan-warn" value="200" min="1">
          </label>
          <label>
            <span>CLEAN_COVERAGE_MIN (%)</span>
            <input type="number" id="batch-cfg-clean-coverage-min" value="70" min="1" max="100">
            <small>&gt;= 70% requests → trustworthy NO_FINDINGS</small>
          </label>
          <label class="grid-span-2">
            <span>WAF_ERROR_RATE</span>
            <input type="number" id="batch-cfg-waf-error-rate" value="0.10" step="0.01" min="0" max="1">
            <small>&gt;= 10% errors → suspect WAF blocking</small>
          </label>
        </div>
      </details>
      <p id="batch-dialog-error" class="batch-dialog-error" role="alert"></p>
    </div>
    <div class="batch-modal-actions">
      <button type="button" id="batch-cancel-btn">Cancel</button>
      <button type="button" id="batch-start-btn" class="primary">Start Batch Scan</button>
      <button type="button" id="batch-resume-btn" class="primary" style="display:none">Continue Batch Scan</button>
    </div>
  </div>
</dialog>
`;}
  function selected(){return (selectedId?[data?.current,...(data?.history||[])].find(r=>r?.id===selectedId):data?.current||data?.history?.[0])||null;}
  const isScanRunning = (r = selected()) => Boolean(data?.busy) || data?.current?.status === 'running' || (r?.status === 'running' && data?.current?.id === r?.id);
  function results(){const run=selected();
    const isBatch = tool === 'nuclei' && (run?.type === 'batch' || Boolean(run?.hosts));
    const isRunning = isScanRunning(run);
    const statusText = !data.installed ? 'NOT INSTALLED' : run?.status ? run.status.toUpperCase() : 'READY';
    const statusCls = !data.installed ? 'status-error' : isRunning ? 'status-running' : run?.status === 'cancelled' ? 'status-cancelled' : run?.status === 'completed' ? 'status-clean' : 'status-pending';
    el('status').textContent = (isRunning ? '⟳ ' : '') + statusText;
    el('status').className = 'batch-badge ' + statusCls;

    el('scan').disabled = !data.installed || isRunning;
    el('stop').disabled = !isRunning;
    el('stop').classList.toggle('stop-active', isRunning);

    const bBtn = document.getElementById('web-batch-scan');
    if (bBtn) {
      bBtn.disabled = !data.installed || isRunning;
      bBtn.textContent = isRunning && isBatch ? '⟳ Batch Running…' : 'Batch Scan';
    }

    if(!data.installed)el('notice').textContent=display()+' is not installed. Install it from the startscreen.';
    else if(run?.error)el('notice').textContent=run.error;
    else if(isBatch){
      const completed=(run.hosts||[]).filter(h=>!['pending','running'].includes(h.status)).length;
      const total=(run.hosts||[]).length;
      el('notice').textContent=run.status==='running'?`⟳ Batch scan running (${completed}/${total} completed). Live output streaming below.`:run.status==='cancelled'?'Batch scan stopped. Partial results saved in this project.':`Batch scan ${run.status}. Results saved in this project.`;
    }
    else if(run)el('notice').textContent=run.status==='running'?'⟳ Scan running. Results are saved automatically.':run.status==='cancelled'?'Scan stopped. Partial results saved.':'Run '+run.status+(run.outcome==='exhausted'?' (candidate list exhausted)':'')+'. Results saved in this project.';
    if(currentTab!=='files')delete el('result').dataset.filesKey;
    if(isBatch && ['output','details','files'].includes(currentTab)){renderBatchWorkspace(run);return;}
    if(currentTab==='files'){const gen=generation,key=run?`${gen}/${run.id}/${run.status}/${run.status==='running'?Math.floor(Date.now()/5000):''}`:'empty';if(el('result').dataset.filesKey===key)return;el('result').dataset.filesKey=key;el('result').innerHTML='<p class="muted">Loading output files…</p>';if(!run){el('result').innerHTML='<p class="muted">No run selected.</p>';return;}request(path()+`/history/${run.id}/files`).then(value=>{if(gen!==generation||currentTab!=='files'||selected()?.id!==run.id)return;el('result').innerHTML=value.files.map(f=>`<a class="output-file" href="${path()}/history/${run.id}/files/${f.token}" download><span>${esc(f.name)}<small>${Math.ceil(f.size/1024)} KB</small></span><span>↓</span></a>`).join('')||'<p class="muted">No output files saved yet.</p>';}).catch(e=>{if(gen===generation&&currentTab==='files'&&selected()?.id===run.id){el('result').textContent=e.message;delete el('result').dataset.filesKey;}});}
    else if(currentTab==='output'){const previous=el('result').querySelector('pre');const scroll=previous?.scrollTop||0;const atBottom=!previous||previous.scrollHeight-previous.clientHeight-previous.scrollTop<40;el('result').innerHTML=`<pre class="web-terminal">${esc(run?.output||'Prepare a command and click '+(config?.action||'Scan')+' to start.')}</pre>`;const terminal=el('result').querySelector('pre');terminal.scrollTop=atBottom?terminal.scrollHeight:scroll;}
    else if(currentTab==='details')el('result').innerHTML=run?`<dl><dt>Target</dt><dd>${esc(run.target)}</dd><dt>Status</dt><dd>${esc(run.status)}</dd><dt>Started</dt><dd>${esc(new Date(run.created_at).toLocaleString())}</dd><dt>Command</dt><dd><code>${esc(run.command)}</code></dd><dt>Executed command</dt><dd><code>${esc(run.executed_command||run.command)}</code></dd></dl><p class="muted">Reports, session data, and output stay inside projects/${esc(project.id)}/scans/${tool}/.</p>`:'<p class="muted">No scan selected.</p>';
    else el('result').innerHTML=(data.history||[]).map(r=>`<button class="saved-scan" type="button" data-web-run="${r.id}"><strong>${esc(r.title||r.command)}</strong><span>${esc(r.status)} · ${esc(new Date(r.created_at).toLocaleString())}</span></button>`).join('')||'<p class="muted">No saved scans yet.</p>';
  }
  
  function renderBatchWorkspace(run) {
    const isRunning = isScanRunning(run);
    const hosts = run.hosts || [];
    const query = batchSearchQuery.toLowerCase().trim();
    const completed = hosts.filter(h => !['pending', 'running'].includes(h.status)).length;
    const findings = hosts.filter(h => ['findings', 'findings_partial'].includes(h.status)).length;

    const hostItems = hosts.map((h, idx) => ({ h, idx }))
      .filter(({ h }) => !query || (h.label || '').toLowerCase().includes(query) || (h.url || '').toLowerCase().includes(query))
      .map(({ h, idx }) => `
        <button type="button" class="batch-host-row ${selectedHostIdx === idx ? 'active' : ''}" data-batch-host="${idx}">
          <div class="batch-host-row-main">
            <strong class="batch-host-title">${esc(h.label || h.url)}</strong>
            ${batchStatusBadge(h.status)}
          </div>
          <small class="batch-host-sub">${esc(h.url)}</small>
        </button>
      `).join('') || '<p class="muted" style="padding:14px;font-size:11px;">No targets match filter.</p>';

    const sidebarHtml = `
      <div class="batch-sidebar">
        <div class="batch-sidebar-header">
          <input type="search" id="batch-host-search" class="batch-host-search" placeholder="Filter host names…" value="${esc(batchSearchQuery)}">
          <div class="batch-sidebar-stats">
            <span>${completed}/${hosts.length} completed</span>
            ${findings ? `<span class="badge-findings-count">${findings} findings</span>` : ''}
          </div>
        </div>
        <div class="batch-hosts-list" id="batch-hosts-list" role="tablist">
          <button type="button" class="batch-host-row ${selectedHostIdx === -1 ? 'active' : ''}" data-batch-host="-1">
            <div class="batch-host-row-main">
              <strong class="batch-host-title">Batch Summary &amp; Log</strong>
              ${batchStatusBadge(run.status)}
            </div>
            <small class="batch-host-sub">Master pool log • ${hosts.length} targets</small>
          </button>
          ${hostItems}
        </div>
      </div>
    `;

    let mainHtml = '';
    const currentHost = (selectedHostIdx >= 0 && selectedHostIdx < hosts.length) ? hosts[selectedHostIdx] : null;

    if (currentTab === 'output') {
      if (selectedHostIdx === -1 || !currentHost) {
        mainHtml = `
          <div class="batch-host-header">
            <div class="batch-host-header-left">
              <h3 class="batch-host-heading">Batch Master Output Log</h3>
              <span class="batch-host-sub">${hosts.length} targets • ${completed} completed</span>
            </div>
            <div class="batch-host-header-right">
              ${batchStatusBadge(run.status)}
              ${isRunning ? `<button type="button" class="batch-stop-header-btn" id="batch-header-stop-btn" title="Stop batch scan">Stop Scan</button>` : ''}
            </div>
          </div>
          <pre class="web-terminal batch-terminal" id="batch-terminal">${esc(run.output || 'Batch scan starting…')}</pre>
        `;
      } else {
        const key = `${run.id}/${selectedHostIdx}/${run.status === 'running' ? Math.floor(Date.now() / 2500) : 'done'}`;
        if (activeBatchHostLogKey !== key) {
          activeBatchHostLogKey = key;
          request(`/api/projects/${project.id}/nuclei_batch/hostlog/${run.id}?idx=${selectedHostIdx}`)
            .then(res => {
              activeBatchHostLog = res.log || (currentHost.status === 'pending' ? 'Target pending in scan queue…' : 'No output recorded for this target.');
              const term = document.getElementById('batch-host-term');
              if (term) {
                const atBottom = term.scrollHeight - term.clientHeight - term.scrollTop < 40;
                term.textContent = activeBatchHostLog;
                if (atBottom) term.scrollTop = term.scrollHeight;
              }
            })
            .catch(() => { activeBatchHostLog = 'Unable to fetch host log.'; });
        }
        mainHtml = `
          <div class="batch-host-header">
            <div class="batch-host-header-left">
              <h3 class="batch-host-heading">${esc(currentHost.label || currentHost.url)}</h3>
              <a href="${esc(currentHost.url)}" target="_blank" rel="noopener" class="batch-host-link">${esc(currentHost.url)} ↗</a>
            </div>
            <div class="batch-host-header-right">
              ${batchStatusBadge(currentHost.status)}
              ${currentHost.detail ? `<span class="batch-host-detail">${esc(currentHost.detail)}</span>` : ''}
              ${isRunning ? `<button type="button" class="batch-stop-header-btn" id="batch-header-stop-btn" title="Stop batch scan">Stop Scan</button>` : ''}
            </div>
          </div>
          <pre class="web-terminal batch-terminal" id="batch-host-term">${esc(activeBatchHostLog || 'Loading host log…')}</pre>
        `;
      }
    } else if (currentTab === 'details') {
      if (selectedHostIdx === -1 || !currentHost) {
        const sum = run.summary || {};
        const cfg = run.config || {};
        const cleanCount = hosts.filter(h => ['clean', 'no_findings'].includes(h.status)).length;
        const wafCount = hosts.filter(h => ['incomplete_waf', 'waf'].includes(h.status)).length;
        const errCount = hosts.filter(h => h.status === 'error').length;
        const toCount = hosts.filter(h => h.status === 'timeout').length;

        mainHtml = `
          <div class="batch-details-dashboard">
            <h3>Batch Scan Overview</h3>
            <div class="batch-stats-grid">
              <div class="batch-stat-card"><div class="batch-stat-num">${hosts.length}</div><div class="batch-stat-label">Targets</div></div>
              <div class="batch-stat-card stat-findings"><div class="batch-stat-num">${sum.findings || findings}</div><div class="batch-stat-label">Findings</div></div>
              <div class="batch-stat-card stat-partial"><div class="batch-stat-num">${sum.findings_partial || 0}</div><div class="batch-stat-label">Partial (Timeout)</div></div>
              <div class="batch-stat-card stat-clean"><div class="batch-stat-num">${sum.no_findings !== undefined ? sum.no_findings : cleanCount}</div><div class="batch-stat-label">Trustworthy Clean</div></div>
              <div class="batch-stat-card stat-waf"><div class="batch-stat-num">${sum.waf !== undefined ? sum.waf : wafCount}</div><div class="batch-stat-label">WAF / Incomplete</div></div>
              <div class="batch-stat-card stat-timeout"><div class="batch-stat-num">${sum.timeout !== undefined ? sum.timeout : toCount}</div><div class="batch-stat-label">Timed Out</div></div>
              <div class="batch-stat-card stat-error"><div class="batch-stat-num">${sum.error !== undefined ? sum.error : errCount}</div><div class="batch-stat-label">Errors</div></div>
            </div>

            <h4>Configuration Parameters</h4>
            <dl class="batch-cfg-dl">
              <dt>Max Workers</dt><dd>${cfg.max_workers || 7}</dd>
              <dt>Target Timeout</dt><dd>${cfg.nuclei_timeout || 900}s</dd>
              <dt>Rate Limit</dt><dd>${cfg.rate_limit || 15} RPS/worker</dd>
              <dt>Template Tags</dt><dd><code>${esc(cfg.template_tags || '—')}</code></dd>
              <dt>Severity</dt><dd><code>${esc(cfg.severity || '—')}</code></dd>
              <dt>Concurrency (-c)</dt><dd>${cfg.nuclei_c || 5}</dd>
              <dt>Bulk Size (-bs)</dt><dd>${cfg.nuclei_bs || 5}</dd>
              <dt>Max Host Error</dt><dd>${cfg.max_host_error || 30}</dd>
              <dt>Coverage Min</dt><dd>${cfg.clean_coverage_min || 70}%</dd>
              <dt>WAF Error Rate</dt><dd>${cfg.waf_error_rate || 0.10}</dd>
              <dt>Started</dt><dd>${esc(new Date(run.created_at).toLocaleString())}</dd>
              ${run.finished_at ? `<dt>Finished</dt><dd>${esc(new Date(run.finished_at).toLocaleString())}</dd>` : ''}
            </dl>
          </div>
        `;
      } else {
        mainHtml = `
          <div class="batch-host-header">
            <div class="batch-host-header-left">
              <h3 class="batch-host-heading">${esc(currentHost.label || currentHost.url)}</h3>
              <a href="${esc(currentHost.url)}" target="_blank" rel="noopener" class="batch-host-link">${esc(currentHost.url)} ↗</a>
            </div>
            <div class="batch-host-header-right">
              ${batchStatusBadge(currentHost.status)}
            </div>
          </div>
          <div class="batch-host-details">
            <dl>
              <dt>Target URL</dt><dd><a href="${esc(currentHost.url)}" target="_blank" rel="noopener">${esc(currentHost.url)}</a></dd>
              <dt>Host / Domain</dt><dd><strong>${esc(currentHost.label || currentHost.url)}</strong></dd>
              <dt>Status</dt><dd>${batchStatusBadge(currentHost.status)}</dd>
              <dt>Classification Detail</dt><dd>${esc(currentHost.detail || '—')}</dd>
              <dt>Coverage</dt><dd>${currentHost.pct !== undefined ? `${currentHost.pct}%` : '—'}</dd>
              <dt>Raw Log Path</dt><dd><code>${esc(currentHost.log_path || '—')}</code></dd>
              <dt>JSONL Findings</dt><dd><code>${esc(currentHost.jsonl_path || '—')}</code></dd>
            </dl>
          </div>
        `;
      }
    } else if (currentTab === 'files') {
      const gen = generation;
      request(path() + `/history/${run.id}/files`).then(value => {
        if (gen !== generation || currentTab !== 'files' || selected()?.id !== run.id) return;
        const elContainer = document.getElementById('batch-files-container');
        if (!elContainer) return;
        let files = value.files || [];
        if (selectedHostIdx >= 0 && currentHost) {
          const safePrefix = currentHost.log_path ? currentHost.log_path.split('/').pop().replace(/\.log$/, '') : '';
          if (safePrefix) {
            files = files.filter(f => f.name.startsWith(safePrefix));
          }
        }
        elContainer.innerHTML = files.map(f => `
          <a class="output-file" href="${path()}/history/${run.id}/files/${f.token}" download>
            <span>${esc(f.name)}<small>${Math.ceil(f.size / 1024)} KB</small></span>
            <span>↓</span>
          </a>
        `).join('') || '<p class="muted" style="padding:14px;">No files generated yet for this target.</p>';
      }).catch(e => {
        const elContainer = document.getElementById('batch-files-container');
        if (elContainer) elContainer.textContent = e.message;
      });

      mainHtml = `
        <div class="batch-host-header">
          <div class="batch-host-header-left">
            <h3 class="batch-host-heading">${selectedHostIdx === -1 || !currentHost ? 'Batch Output Files' : esc(currentHost.label || currentHost.url) + ' Files'}</h3>
            <span class="batch-host-sub">Downloadable findings & logs</span>
          </div>
        </div>
        <div id="batch-files-container" style="padding:14px;overflow-y:auto;max-height:60vh;">
          <p class="muted">Loading files…</p>
        </div>
      `;
    }

    if (lastBatchRunId !== run.id) {
      lastBatchRunId = run.id;
      savedHostsListScroll = 0;
    }

    const prevTerm = document.getElementById('batch-terminal') || document.getElementById('batch-host-term');
    const prevScroll = prevTerm?.scrollTop || 0;
    const atBottom = !prevTerm || (prevTerm.scrollHeight - prevTerm.clientHeight - prevTerm.scrollTop < 40);

    const prevList = document.getElementById('batch-hosts-list') || document.querySelector('.batch-hosts-list');
    if (prevList && prevList.scrollTop > 0) {
      savedHostsListScroll = prevList.scrollTop;
    }

    const prevDetails = document.querySelector('.batch-host-details');
    const prevDetailsScroll = prevDetails ? prevDetails.scrollTop : 0;

    const prevFiles = document.getElementById('batch-files-container');
    const prevFilesScroll = prevFiles ? prevFiles.scrollTop : 0;

    const searchInput = document.getElementById('batch-host-search');
    const searchWasFocused = document.activeElement && document.activeElement.id === 'batch-host-search';
    const searchSelStart = searchWasFocused ? searchInput.selectionStart : null;
    const searchSelEnd = searchWasFocused ? searchInput.selectionEnd : null;

    el('result').innerHTML = `
      <div class="batch-layout">
        ${sidebarHtml}
        <div class="batch-main-content">
          ${mainHtml}
        </div>
      </div>
    `;

    const nextList = document.getElementById('batch-hosts-list') || document.querySelector('.batch-hosts-list');
    if (nextList) {
      if (savedHostsListScroll > 0) {
        nextList.scrollTop = savedHostsListScroll;
      }
      nextList.onscroll = () => {
        savedHostsListScroll = nextList.scrollTop;
      };
    }

    const term = document.getElementById('batch-terminal') || document.getElementById('batch-host-term');
    if (term) term.scrollTop = atBottom ? term.scrollHeight : prevScroll;

    if (prevDetailsScroll > 0) {
      const nextDetails = document.querySelector('.batch-host-details');
      if (nextDetails) nextDetails.scrollTop = prevDetailsScroll;
    }

    if (prevFilesScroll > 0) {
      const nextFiles = document.getElementById('batch-files-container');
      if (nextFiles) nextFiles.scrollTop = prevFilesScroll;
    }

    const nextSearch = document.getElementById('batch-host-search');
    if (nextSearch) {
      if (searchWasFocused) {
        nextSearch.focus();
        if (searchSelStart !== null && searchSelEnd !== null) {
          try { nextSearch.setSelectionRange(searchSelStart, searchSelEnd); } catch(_) {}
        }
      }
      nextSearch.oninput = () => {
        batchSearchQuery = nextSearch.value;
        savedHostsListScroll = 0;
        const curRun = selected();
        if (curRun) renderBatchWorkspace(curRun);
        const refocused = document.getElementById('batch-host-search');
        if (refocused) {
          refocused.focus();
          refocused.setSelectionRange(refocused.value.length, refocused.value.length);
        }
      };
    }

    requestAnimationFrame(() => {
      const l = document.getElementById('batch-hosts-list') || document.querySelector('.batch-hosts-list');
      if (l && savedHostsListScroll > 0 && l.scrollTop !== savedHostsListScroll) {
        l.scrollTop = savedHostsListScroll;
      }
    });
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
    const handleStop = async () => {
      const actionGeneration = generation;
      el('stop').disabled = true;
      document.querySelectorAll('.batch-stop-header-btn').forEach(b => { b.disabled = true; b.textContent = 'Stopping…'; });
      el('notice').textContent = 'Stopping scan…';
      try {
        await request(path() + '/cancel', {});
        if (tool === 'nuclei') {
          await request(`/api/projects/${project.id}/nuclei_batch/cancel`, {}).catch(() => {});
        }
        if (actionGeneration === generation) await poll();
      } catch (error) {
        if (actionGeneration === generation) {
          el('notice').textContent = error.message;
          await poll();
        }
      }
    };
    el('stop').onclick = handleStop;
    document.getElementById('webscan-workspace').onclick = e => {
    const bStop = e.target.closest('#batch-header-stop-btn, .batch-stop-header-btn');
    if (bStop) { handleStop(); return; }
    const bHost = e.target.closest('[data-batch-host]');
    if (bHost) {
      const list = document.getElementById('batch-hosts-list') || document.querySelector('.batch-hosts-list');
      if (list) savedHostsListScroll = list.scrollTop;
      selectedHostIdx = Number(bHost.dataset.batchHost);
      results();
      return;
    }const tab=e.target.closest('[data-web-tab]');if(tab){currentTab=tab.dataset.webTab;setTab();results();}const run=e.target.closest('[data-web-run]');if(run){selectedId=run.dataset.webRun;const saved=selected();el('command').value=saved.command;el('target').value=saved.target;el('preset').value='custom';targetFromCommand();currentTab='output';setTab();results();}};
    
    const batchDialog = document.getElementById('web-batch-dialog');
    const batchTrigger = document.getElementById('web-batch-scan');
    if (batchTrigger && batchDialog) {
      batchTrigger.onclick = () => {
        batchDialogMode = 'start';
        batchUploadedTargetsText = '';
        batchUploadedFileName = '';
        const elStatus = document.getElementById('batch-file-status');
        if (elStatus) elStatus.textContent = 'No file selected.';
        const elErr = document.getElementById('batch-dialog-error');
        if (elErr) elErr.textContent = '';
        const elPaste = document.getElementById('batch-paste-targets');
        if (elPaste) elPaste.value = '';
        const elPath = document.getElementById('batch-file-path');
        if (elPath) elPath.value = '';
        document.getElementById('batch-mode-start')?.classList.add('active');
        document.getElementById('batch-mode-resume')?.classList.remove('active');
        const resumeSec = document.getElementById('batch-resume-section');
        if (resumeSec) resumeSec.style.display = 'none';
        const startBtn = document.getElementById('batch-start-btn');
        if (startBtn) startBtn.style.display = '';
        const resumeBtn = document.getElementById('batch-resume-btn');
        if (resumeBtn) resumeBtn.style.display = 'none';
        batchDialog.showModal();
      };

      document.getElementById('batch-close-btn')?.addEventListener('click', () => batchDialog.close());
      document.getElementById('batch-cancel-btn')?.addEventListener('click', () => batchDialog.close());

      document.getElementById('batch-mode-start')?.addEventListener('click', () => {
        batchDialogMode = 'start';
        document.getElementById('batch-mode-start').classList.add('active');
        document.getElementById('batch-mode-resume').classList.remove('active');
        const resumeSec = document.getElementById('batch-resume-section');
        if (resumeSec) resumeSec.style.display = 'none';
        const startBtn = document.getElementById('batch-start-btn');
        if (startBtn) startBtn.style.display = '';
        const resumeBtn = document.getElementById('batch-resume-btn');
        if (resumeBtn) resumeBtn.style.display = 'none';
      });

      document.getElementById('batch-mode-resume')?.addEventListener('click', async () => {
        batchDialogMode = 'resume';
        document.getElementById('batch-mode-start').classList.remove('active');
        document.getElementById('batch-mode-resume').classList.add('active');
        const resumeSec = document.getElementById('batch-resume-section');
        if (resumeSec) resumeSec.style.display = '';
        const startBtn = document.getElementById('batch-start-btn');
        if (startBtn) startBtn.style.display = 'none';
        const resumeBtn = document.getElementById('batch-resume-btn');
        if (resumeBtn) resumeBtn.style.display = '';

        const sel = document.getElementById('batch-session-select');
        if (sel) {
          sel.innerHTML = '<option value="">Loading previous sessions…</option>';
          try {
            const data = await request(`/api/projects/${project.id}/nuclei_batch/sessions`);
            const sessions = data.sessions || [];
            if (!sessions.length) {
              sel.innerHTML = '<option value="">No previous sessions found</option>';
            } else {
              sel.innerHTML = '<option value="">-- Choose session to resume --</option>' + sessions.map(s => `
                <option value="${s.id}">Session ${s.id.slice(0, 8)} (${s.done} completed${s.total ? ' / ' + s.total : ''})</option>
              `).join('');
            }
          } catch (e) {
            sel.innerHTML = `<option value="">Error: ${esc(e.message)}</option>`;
          }
        }
      });

      const fileInput = document.getElementById('batch-file-input');
      const browseBtn = document.getElementById('batch-browse-btn');
      if (browseBtn && fileInput) {
        browseBtn.onclick = () => fileInput.click();
        fileInput.onchange = () => {
          const file = fileInput.files[0];
          if (!file) return;
          batchUploadedFileName = file.name;
          const reader = new FileReader();
          reader.onload = () => {
            batchUploadedTargetsText = reader.result;
            const lines = batchUploadedTargetsText.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
            const statusEl = document.getElementById('batch-file-status');
            if (statusEl) statusEl.textContent = `✔ Loaded ${file.name} (${lines.length} targets found)`;
          };
          reader.onerror = () => {
            const statusEl = document.getElementById('batch-file-status');
            if (statusEl) statusEl.textContent = '✕ Error reading file.';
          };
          reader.readAsText(file);
        };
      }

      function collectConfig() {
        return {
          max_workers: Number(document.getElementById('batch-cfg-max-workers')?.value || 7),
          nuclei_timeout: Number(document.getElementById('batch-cfg-nuclei-timeout')?.value || 900),
          sigterm_grace: Number(document.getElementById('batch-cfg-sigterm-grace')?.value || 10),
          rate_limit: Number(document.getElementById('batch-cfg-rate-limit')?.value || 15),
          nuclei_c: Number(document.getElementById('batch-cfg-nuclei-c')?.value || 5),
          nuclei_bs: Number(document.getElementById('batch-cfg-nuclei-bs')?.value || 5),
          max_host_error: Number(document.getElementById('batch-cfg-max-host-error')?.value || 30),
          stats_interval: Number(document.getElementById('batch-cfg-stats-interval')?.value || 30),
          template_tags: document.getElementById('batch-cfg-template-tags')?.value || '',
          severity: document.getElementById('batch-cfg-severity')?.value || '',
          state_file: document.getElementById('batch-cfg-state-file')?.value || '.progress.json',
          state_save_every: Number(document.getElementById('batch-cfg-state-save-every')?.value || 10),
          large_scan_warn: Number(document.getElementById('batch-cfg-large-scan-warn')?.value || 200),
          clean_coverage_min: Number(document.getElementById('batch-cfg-clean-coverage-min')?.value || 70),
          waf_error_rate: Number(document.getElementById('batch-cfg-waf-error-rate')?.value || 0.10),
        };
      }

      function getTargetsText() {
        const pasteVal = document.getElementById('batch-paste-targets')?.value?.trim();
        if (pasteVal) return pasteVal;
        if (batchUploadedTargetsText?.trim()) return batchUploadedTargetsText.trim();
        return '';
      }

      document.getElementById('batch-start-btn')?.addEventListener('click', async () => {
        const errEl = document.getElementById('batch-dialog-error');
        if (errEl) errEl.textContent = '';
        const targets = getTargetsText();
        const filePath = document.getElementById('batch-file-path')?.value?.trim();
        if (!targets && !filePath) {
          if (errEl) errEl.textContent = 'Please choose a CSV/TXT file, enter a file path, or paste target URLs.';
          return;
        }

        const lines = targets.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
        const cfg = collectConfig();
        if (lines.length > cfg.large_scan_warn) {
          if (!confirm(`Warning: Scanning ${lines.length} targets may take a long time. Do you want to continue?`)) {
            return;
          }
        }

        try {
          const payload = { targets, file_path: filePath, ...cfg };
          const res = await request(`/api/projects/${project.id}/nuclei_batch`, payload);
          selectedId = res.id;
          selectedHostIdx = -1;
          batchDialog.close();
          currentTab = 'output';
          setTab();
          await poll();
        } catch (e) {
          if (errEl) errEl.textContent = e.message;
        }
      });

      document.getElementById('batch-resume-btn')?.addEventListener('click', async () => {
        const errEl = document.getElementById('batch-dialog-error');
        if (errEl) errEl.textContent = '';
        const batchId = document.getElementById('batch-session-select')?.value;
        if (!batchId) {
          if (errEl) errEl.textContent = 'Please select a previous session to resume.';
          return;
        }
        const targets = getTargetsText();
        const filePath = document.getElementById('batch-file-path')?.value?.trim();
        const cfg = collectConfig();

        try {
          const payload = { batch_id: batchId, targets, file_path: filePath, ...cfg };
          const res = await request(`/api/projects/${project.id}/nuclei_batch/resume`, payload);
          selectedId = res.id;
          selectedHostIdx = -1;
          batchDialog.close();
          currentTab = 'output';
          setTab();
          await poll();
        } catch (e) {
          if (errEl) errEl.textContent = e.message;
        }
      });
    }

    timer=setInterval(poll,1500);
  }
  function unmount(){generation++;if(timer)clearInterval(timer);timer=null;project=null;polling=false;savedHostsListScroll=0;lastBatchRunId=null;}
  return {mount,unmount};
})();
