const projectUI = (() => {
  let duplicateDraft = null, historyQuery = '', historyStatus = '';
  let routeVersion=0, historyLoading=false, historyQueued=false, historyLoaded=false;
  const expandedTools = new Set();
  let toolsExpanded = true;
  let project = null, statuses = [], projects = [], view = 'overview', tool = null, saving = false;
  const esc = escapeHTML;
  const date = value => new Date(value).toLocaleString();
  async function api(path, data) {
    if (data !== undefined && !state) await refresh();
    const response = await fetch(path, data === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-App-Token':state?.token || ''}, body:JSON.stringify(data)});
    const body = await response.json();
    if (!response.ok) { const error=Error(body.error || 'Request failed'); error.duplicates=body.duplicates; throw error; }
    return body;
  }
  function options(selected) {return statuses.map(s=>`<option ${s===selected?'selected':''}>${esc(s)}</option>`).join('');}
  function message(text) {const element=document.getElementById('workspace-message'); if(element) element.textContent=text;}
  async function loadList() {
    const data = await api('/api/projects'); projects=data.projects; statuses=data.statuses;
  }
  function historyControls(){
    const host=$('home-projects');host.hidden=false;
    if($('project-list'))return;
    host.innerHTML=`<div class="history-filters"><input id="project-search" type="search" placeholder="Search projects…" aria-label="Search project history"><select id="project-status-filter" aria-label="Filter projects by status"><option value="">All statuses</option></select></div><div class="history-list-heading"><span id="history-count"></span><button id="history-clear" type="button" hidden>Clear filters</button><button id="history-refresh" type="button" aria-label="Refresh project history" title="Refresh project history">↻</button></div><p id="history-error" role="status" hidden></p><div id="project-list"></div>`;
    $('project-search').oninput=()=>{historyQuery=$('project-search').value;drawHistory();};
    $('project-status-filter').onchange=()=>{historyStatus=$('project-status-filter').value;drawHistory();};
    $('history-clear').onclick=()=>{historyQuery='';historyStatus='';drawHistory();};
    $('history-refresh').onclick=()=>history();
  }
  function drawHistory(){
    historyControls();
    const available=[...new Set([...statuses,...projects.map(p=>p.status)])];
    const filter=$('project-status-filter');
    if(filter.dataset.values!==JSON.stringify(available)){
      filter.innerHTML='<option value="">All statuses</option>'+available.map(s=>`<option value="${esc(s)}">${esc(s)}</option>`).join('');
      filter.dataset.values=JSON.stringify(available);
    }
    if(historyStatus&&!available.includes(historyStatus))historyStatus='';
    filter.value=historyStatus;
    if($('project-search').value!==historyQuery)$('project-search').value=historyQuery;
    const q=historyQuery.trim().toLowerCase();
    const shown=projects.filter(p=>`${p.name} ${p.host} ${p.ip} ${p.status}`.toLowerCase().includes(q)&&(!historyStatus||p.status===historyStatus));
    $('history-count').textContent=historyLoaded?`${shown.length} of ${projects.length} projects`:'Loading projects…';
    $('history-clear').hidden=!historyQuery&&!historyStatus;
    const markup=shown.map(p=>`<a class="project-card" href="#project/${p.id}/overview"><div><strong>${esc(p.name)}</strong><span class="badge">${esc(p.status)}</span></div><p>${esc(p.host||p.ip)}${p.host&&p.ip?` · ${esc(p.ip)}`:''}</p><small>Updated ${esc(date(p.updated_at))}</small></a>`).join('')||(historyLoaded?(projects.length?'<p class="muted">No projects match your filters. Use Clear filters to show all projects.</p>':'<p class="muted">No projects yet. Start a project to create your first workspace.</p>'):'<p class="muted">Loading saved projects…</p>');
    if($('project-list').innerHTML!==markup)$('project-list').innerHTML=markup;
  }
  async function history(){
    historyControls();
    if(historyLoading){historyQueued=true;return;}
    historyLoading=true;drawHistory();$('history-refresh').disabled=true;
    try{
      const response=await fetch('/api/projects',{cache:'no-store',signal:AbortSignal.timeout(10000)});
      if(!response.ok)throw Error('Project history could not be loaded.');
      const data=await response.json();projects=data.projects;statuses=data.statuses;historyLoaded=true;
      $('history-error').hidden=true;drawHistory();
    }catch(e){
      $('history-error').hidden=false;
      $('history-error').textContent='Unable to refresh history. '+(historyLoaded?'Your last loaded list is still shown. ':'')+'Retry with ↻; the app will also retry automatically.';
    }finally{
      historyLoading=false;$('history-refresh').disabled=false;
      if(historyQueued){historyQueued=false;history();}
    }
  }
  function sidebar() {
    const items=(state?.tools || []).filter(t=>!['macchanger','anonsurf'].includes(t.id));
    return `<aside class="project-sidebar"><a class="back-link" href="#">← Startscreen</a><div class="sidebar-project"><strong title="${esc(project.name)}">${esc(project.name)}</strong><select id="sidebar-project-status" aria-label="Project status">${options(project.status)}</select>${project.name!==(project.host||project.ip)?`<small title="${esc(project.host||project.ip)}">${esc(project.host||project.ip)}</small>`:''}</div><nav aria-label="Project navigation"><a class="nav-item ${view==='overview'?'selected':''}" href="#project/${project.id}/overview">Overview</a><section class="tools-nav"><div class="tools-heading"><span>Tools</span><button class="tool-toggle" data-tools-toggle aria-label="Toggle tools" aria-expanded="${toolsExpanded}">${toolsExpanded?'⌄':'›'}</button></div><div ${toolsExpanded?'':'hidden'}>${items.map(t=>`<div class="tool-nav"><div class="tool-nav-row"><a class="tool-link ${tool===t.id&&view==='tool'?'selected':''}" href="#project/${project.id}/tool/${t.id}">${esc(t.name)}</a><span class="availability ${t.installed?'yes':'no'}" title="${t.installed?'Installed':'Not installed'}">${t.installed?'✓':'×'}</span>${t.gui?'':`<button class="tool-toggle" data-toggle-tool="${t.id}" aria-label="Toggle ${esc(t.name)} menu" aria-expanded="${expandedTools.has(t.id)}">${expandedTools.has(t.id)?'⌄':'›'}</button></div><div class="tool-submenu" ${expandedTools.has(t.id)?'':'hidden'}><a class="${tool===t.id&&view==='history'?'selected':''}" href="#project/${project.id}/history/${t.id}">History <span>${(project.tool_history[t.id]||[]).length}</span></a>`}</div></div>`).join('')}</div></section><a class="nav-item ${view==='notes'?'selected':''}" href="#project/${project.id}/notes">Notes</a><a class="nav-item ${view==='docs'?'selected':''}" href="#project/${project.id}/docs">Saved docs <span>${project.documents.length}</span></a></nav></aside>`;
  }
  function overview() {
    return `<div class="content-heading"><div><p class="kicker">PROJECT WORKSPACE</p><h1>${esc(project.name)}</h1><p class="muted">Created ${esc(date(project.created_at))}</p></div><span class="badge">${esc(project.status)}</span></div><form id="edit-project" class="workspace-card"><h2>Project details</h2><label>Project name<input name="name" value="${esc(project.name)}" maxlength="140"></label><div class="field-pair"><label>IP address<input name="ip" value="${esc(project.ip)}" maxlength="100" placeholder="IPv4 or IPv6"></label><label>Host name<input name="host" value="${esc(project.host)}" maxlength="253" placeholder="example.com"></label></div><label>Others<textarea name="others" rows="5" maxlength="20000">${esc(project.others)}</textarea></label><label>Status<select name="status">${options(project.status)}</select></label><div class="custom-status"><input id="workspace-status" placeholder="New custom status" aria-label="New custom status" maxlength="60"><button type="button" id="workspace-add-status">Add status</button></div><div class="form-actions"><button class="primary" type="submit">Save changes</button></div></form><p class="storage-location">Stored inside this app: projects/${esc(project.id)}/</p>`;
  }
  function toolContent() {
    const selected=state?.tools.find(t=>t.id===tool);
    if(!selected) return '<h1>Tool not found</h1>';
    if(selected.gui) return `<div class="desktop-tool-page"><button type="button" class="primary" id="open-desktop-tool" ${selected.installed?'':'disabled'}>Open ${esc(selected.name)}</button>${selected.installed?'':`<p class="muted">${esc(selected.name)} is not installed.</p>`}</div>`;
    if(tool==='hakrawler' && view==='tool') return '<div id="hakrawler-workspace"></div>';
    if(tool==='nmap' && view==='tool') return '<div id="nmap-workspace"></div>';
    const entries=project.tool_history[tool] || [];
    if(view==='history') return `<div class="content-heading"><div><p class="kicker">TOOLS / ${esc(selected.name.toUpperCase())}</p><h1>${esc(selected.name)} history</h1><p class="muted">${entries.length} saved scan${entries.length===1?'':'s'} in this project</p></div></div><div class="workspace-card scan-history-list">${entries.length?entries.map(entry=>`<article class="scan-history-row"><a class="scan-history-open" href="#project/${project.id}/tool/${tool}/${entry.id}"><div><strong>${esc(entry.title||entry.command||entry.target||project.host||project.ip)}</strong><span class="badge">${esc(entry.status||'saved')}</span></div><small>${esc(entry.target||'')} · ${esc(date(entry.created_at))}</small></a><button class="scan-delete" data-delete-scan="${entry.id}" aria-label="Delete scan from ${esc(date(entry.created_at))}" title="Delete scan"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/></svg></button></article>`).join(''):'<div class="blank-state"><span>↳</span><h2>No runs saved yet</h2><p>Runs are saved here automatically.</p></div>'}</div>`;
    return `<div class="content-heading"><div><p class="kicker">TOOLS / ${esc(selected.name.toUpperCase())}</p><h1>${esc(selected.name)}${view==='history'?' history':''}</h1><p class="muted">${esc(project.host || project.ip)}</p></div></div>${view==='history' ? `<div class="workspace-card">${entries.length ? entries.map(entry=>`<article class="scan-history-entry"><p>${esc(date(entry.created_at))} · ${esc(entry.status||'saved')}</p><code>${esc(entry.command||'')}</code><p><a class="text-link" href="#project/${project.id}/tool/nmap/${entry.id}">Open scan results →</a></p><pre>${esc(entry.output)}</pre></article>`).join('') : '<div class="blank-state"><span>↳</span><h2>No runs saved yet</h2><p>This project has no history for this tool.</p></div>'}</div>` : `<div class="workspace-card"><h2>${esc(selected.category)}</h2><p class="muted">${selected.installed?'Installed on this computer.':'Not installed. Use the startscreen tool menu to install it.'}</p><dl><dt>Host</dt><dd>${esc(project.host || '—')}</dd><dt>IP address</dt><dd>${esc(project.ip || '—')}</dd><dt>Saved runs</dt><dd>${entries.length}</dd></dl><a class="text-link" href="#project/${project.id}/history/${tool}">View history →</a><p class="muted">Tool execution will be added in a later step.</p></div>`}`;
  }
  function renderProject() {
    let content;
    if(view==='overview') content=overview();
    else if(view==='notes') content=`<div class="content-heading"><div><p class="kicker">PROJECT / NOTES</p><h1>Notes</h1><p class="muted">Keep findings, context, and next steps with this project.</p></div></div><form id="notes-form" class="workspace-card"><label for="project-notes">Project notes</label><textarea id="project-notes" rows="18" maxlength="500000" placeholder="Write your notes here…">${esc(project.notes)}</textarea><div class="form-actions"><button type="submit" class="primary">Save notes</button></div></form>`;
    else if(view==='docs') content=`<div class="content-heading"><div><p class="kicker">PROJECT / FILES</p><h1>Saved docs</h1><p class="muted">Documents stay inside this project’s local folder.</p></div></div><form id="document-form" class="workspace-card"><label>Choose a document (up to 4 MB)<input id="document-file" type="file" required></label><button type="submit" class="primary">Save document</button></form><div class="workspace-card document-list">${project.documents.length ? project.documents.map(d=>`<a href="/api/projects/${project.id}/documents/${d.id}" download="${esc(d.name)}"><span>${esc(d.name)}<small>${Math.ceil(d.size/1024)} KB · ${esc(date(d.created_at))}</small></span><span>↓</span></a>`).join('') : '<p class="muted">No documents saved yet.</p>'}</div>`;
    else content=toolContent();
    $('workspace').innerHTML=sidebar()+`<div class="project-content"><p id="workspace-message" role="status"></p>${content}</div>`;
    $('workspace').querySelectorAll('[data-toggle-tool]').forEach(button=>button.onclick=()=>{
      const id=button.dataset.toggleTool;
      if(expandedTools.has(id))expandedTools.delete(id);else expandedTools.add(id);
      button.setAttribute('aria-expanded',expandedTools.has(id));button.textContent=expandedTools.has(id)?'⌄':'›';
      button.closest('.tool-nav').querySelector('.tool-submenu').hidden=!expandedTools.has(id);
    });
    const toolsToggle=$('workspace').querySelector('[data-tools-toggle]');
    if(toolsToggle)toolsToggle.onclick=()=>{toolsExpanded=!toolsExpanded;toolsToggle.setAttribute('aria-expanded',toolsExpanded);toolsToggle.textContent=toolsExpanded?'⌄':'›';toolsToggle.parentElement.nextElementSibling.hidden=!toolsExpanded;};
    if(tool==='hakrawler'&&view==='tool') HakrawlerWorkspace.mount(project,location.hash.split('/')[4]);
    if(tool==='nmap'&&view==='tool') NmapWorkspace.mount(project,location.hash.split('/')[4]);
    $('workspace').querySelectorAll('[data-delete-scan]').forEach(button=>button.onclick=()=>{
      const scan=project.tool_history[tool].find(entry=>entry.id===button.dataset.deleteScan);
      const dialog=$('delete-scan-dialog');
      dialog.dataset.project=project.id;dialog.dataset.scan=scan.id;dialog.dataset.tool=tool;
      $('delete-scan-text').textContent=`Delete the scan for ${scan.target||project.name} from ${date(scan.created_at)}? Its saved results and output files will be removed.`;
      $('delete-scan-error').textContent='';dialog.showModal();
    });
    const desktopButton=$('open-desktop-tool');
    if(desktopButton)desktopButton.onclick=async()=>{
      desktopButton.disabled=true;
      try{const result=await api(`/api/projects/${project.id}/gui/${tool}/open`,{});message(result.message);}
      catch(e){message(e.message);}finally{desktopButton.disabled=false;}
    };
    const sidebarStatus=$('sidebar-project-status');
    sidebarStatus.onchange=async()=>{
      const id=project.id,old=project.status;sidebarStatus.disabled=true;
      try{
        const updated=await api(`/api/projects/${id}/status`,{status:sidebarStatus.value});
        if(project?.id!==id)return;
        project.status=updated.status;project.updated_at=updated.updated_at;
        const overviewStatus=$('edit-project')?.querySelector('[name="status"]');if(overviewStatus)overviewStatus.value=updated.status;
        const badge=$('workspace').querySelector('.content-heading>.badge');if(badge)badge.textContent=updated.status;
        message('Project status saved.');
      }catch(e){sidebarStatus.value=old;message(e.message);}finally{sidebarStatus.disabled=false;}
    };
    const edit=$('edit-project'); if(edit) edit.onsubmit=async e=>{e.preventDefault();await saveAction(e.submitter,async()=>{project=await api(`/api/projects/${project.id}`,Object.fromEntries(new FormData(edit)));renderProject();message('Project saved.');});};
    const add=$('workspace-add-status'); if(add) add.onclick=async()=>{await saveAction(add,async()=>{const name=$('workspace-status').value.trim(); const result=await api('/api/statuses',{name});statuses=result.statuses; $('sidebar-project-status').innerHTML=options(project.status); const select=edit.querySelector('select');select.innerHTML=options(name);$('workspace-status').value='';message('Status added. Save changes to apply it.');});};
    const notes=$('notes-form'); if(notes) notes.onsubmit=async e=>{e.preventDefault();await saveAction(e.submitter,async()=>{project=await api(`/api/projects/${project.id}/notes`,{notes:$('project-notes').value});message('Notes saved.');});};
    const docs=$('document-form'); if(docs) docs.onsubmit=async e=>{e.preventDefault();await saveAction(e.submitter,async()=>{const file=$('document-file').files[0];if(!file) throw Error('Choose a document.');if(file.size>4*1024*1024) throw Error('Documents must be 4 MB or smaller.');const content=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(',')[1]);reader.onerror=()=>reject(Error('Could not read document.'));reader.readAsDataURL(file);});project=await api(`/api/projects/${project.id}/documents`,{name:file.name,content});renderProject();message('Document saved.');});};
  }
  async function saveAction(button, fn) {
    if(saving)return; saving=true;if(button)button.disabled=true;
    try {await fn();}catch(e){message(e.message);}finally{saving=false;if(button)button.disabled=false;}
  }
  async function route() {
    const version=++routeVersion;
    NmapWorkspace.unmount();
    HakrawlerWorkspace.unmount();
    const parts=location.hash.slice(1).split('/');
    if(parts[0]!=='project') {$('workspace').hidden=true;$('startscreen').hidden=false;document.title='Startscreen';project=null;historyQuery='';historyStatus='';window.scrollTo({top:0,left:0,behavior:'instant'});history();return;}
    $('startscreen').hidden=true;$('workspace').hidden=false;
    try {
      if(!state) await refresh();
      await loadList(); const loaded=await api(`/api/projects/${parts[1]}`);
      if(version!==routeVersion)return;
      project=loaded;
      view=['overview','notes','docs','tool','history'].includes(parts[2])?parts[2]:'overview';tool=parts[3]||null;
      document.title=project.name+' · Project';
      renderProject();
    } catch(e){if(version!==routeVersion)return;$('workspace').innerHTML=`<div class="project-content"><a class="back-link" href="#">← Startscreen</a><p>${esc(e.message)}</p></div>`;}
  }
  $('start-project').onclick=async()=>{try{await loadList();$('create-status').innerHTML=options('test');$('project-error').textContent='';$('project-dialog').showModal();}catch(e){$('project-start-error').textContent=e.message;}};
  $('cancel-project').onclick=()=>$('project-dialog').close();
  $('add-status').onclick=async()=>{try{const name=$('new-status').value.trim();const data=await api('/api/statuses',{name});statuses=data.statuses;$('create-status').innerHTML=options(name);$('new-status').value='';$('project-error').textContent='Status added.';}catch(e){$('project-error').textContent=e.message;}};
  async function openSaved(created) {
    project=created;
    $('project-dialog').close();
    $('duplicate-dialog').close();
    $('project-form').reset();
    duplicateDraft=null;
    await history();
    location.hash=`project/${project.id}/overview`;
  }
  $('project-form').onsubmit=async e=>{
    e.preventDefault();const button=e.submitter;button.disabled=true;
    const draft=Object.fromEntries(new FormData(e.target));
    try { await openSaved(await api('/api/projects',draft)); }
    catch(e){
      if(e.duplicates?.length){
        duplicateDraft=draft;
        $('duplicate-error').textContent='';
        $('duplicate-projects').innerHTML=e.duplicates.map(p=>`<div class="duplicate-row"><div><strong>${esc(p.name)}</strong><p>${esc(p.host||p.ip)} · ${esc(p.status)}</p><small>Updated ${esc(date(p.updated_at))}</small></div><button class="secondary" data-continue-project="${p.id}">Continue existing</button></div>`).join('');
        $('duplicate-dialog').showModal();
      } else $('project-error').textContent=e.message;
    } finally {button.disabled=false;}
  };
  $('duplicate-projects').onclick=e=>{
    const button=e.target.closest('[data-continue-project]');if(!button)return;
    $('duplicate-dialog').close();$('project-dialog').close();$('project-form').reset();duplicateDraft=null;
    location.hash=`project/${button.dataset.continueProject}/overview`;
  };
  $('duplicate-cancel').onclick=()=>$('duplicate-dialog').close();
  $('duplicate-copy').onclick=async()=>{
    if(!duplicateDraft)return;const button=$('duplicate-copy');button.disabled=true;
    try{await openSaved(await api('/api/projects',{...duplicateDraft,duplicate:'copy'}));}
    catch(e){$('duplicate-error').textContent=e.message;}finally{button.disabled=false;}
  };
  $('delete-scan-cancel').onclick=()=>$('delete-scan-dialog').close();
  $('delete-scan-confirm').onclick=async()=>{
    const dialog=$('delete-scan-dialog'),button=$('delete-scan-confirm');button.disabled=true;
    try{await api(`/api/projects/${dialog.dataset.project}/${dialog.dataset.tool}/history/${dialog.dataset.scan}/delete`,{});dialog.close();await route();message('Scan deleted.');}
    catch(e){$('delete-scan-error').textContent=e.message;}finally{button.disabled=false;}
  };
  const refreshHome=()=>{if(!$('startscreen').hidden&&!document.hidden&&!$('project-dialog').open)history();};
  setInterval(refreshHome,5000);
  window.addEventListener('focus',refreshHome);
  document.addEventListener('visibilitychange',refreshHome);
  window.addEventListener('hashchange',route);route();
  return {route};
})();
