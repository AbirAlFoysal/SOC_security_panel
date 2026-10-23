const projectUI = (() => {
  let selectedDocumentId=null, documentsProjectId=null, pendingDocumentFiles=[];
  let selectedNoteId = null, notesProjectId = null;
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
    return `<aside class="project-sidebar"><a class="back-link" href="#">← Startscreen</a><div class="sidebar-project"><strong title="${esc(project.name)}">${esc(project.name)}</strong><select id="sidebar-project-status" aria-label="Project status">${options(project.status)}</select>${project.name!==(project.host||project.ip)?`<small title="${esc(project.host||project.ip)}">${esc(project.host||project.ip)}</small>`:''}</div><nav aria-label="Project navigation"><a class="nav-item ${view==='overview'?'selected':''}" href="#project/${project.id}/overview">Overview</a><section class="tools-nav"><div class="tools-heading"><span>Tools</span><button class="tool-toggle" data-tools-toggle aria-label="Toggle tools" aria-expanded="${toolsExpanded}">${toolsExpanded?'⌄':'›'}</button></div><div ${toolsExpanded?'':'hidden'}>${items.map(t=>`<div class="tool-nav"><div class="tool-nav-row"><a class="tool-link ${tool===t.id&&view==='tool'?'selected':''}" href="#project/${project.id}/tool/${t.id}">${esc(t.name)}</a><span class="availability ${t.installed?'yes':'no'}" title="${t.installed?'Installed':'Not installed'}">${t.installed?'✓':'×'}</span>${t.gui?'':`<button class="tool-toggle" data-toggle-tool="${t.id}" aria-label="Toggle ${esc(t.name)} menu" aria-expanded="${expandedTools.has(t.id)}">${expandedTools.has(t.id)?'⌄':'›'}</button></div><div class="tool-submenu" ${expandedTools.has(t.id)?'':'hidden'}><a class="${tool===t.id&&view==='history'?'selected':''}" href="#project/${project.id}/history/${t.id}">History <span>${(project.tool_history[t.id]||[]).length}</span></a>`}</div></div>`).join('')}</div></section><a class="nav-item ${view==='notes'?'selected':''}" href="#project/${project.id}/notes">Notes</a><a class="nav-item ${view==='docs'?'selected':''}" href="#project/${project.id}/docs">Saved docs <span>${(project.document_entries||[]).length}</span></a></nav></aside>`;
  }
  function overview() {
    return `<div class="content-heading"><div><p class="kicker">PROJECT WORKSPACE</p><h1>${esc(project.name)}</h1><p class="muted">Created ${esc(date(project.created_at))}</p></div><span class="badge">${esc(project.status)}</span></div><form id="edit-project" class="workspace-card"><h2>Project details</h2><label>Project name<input name="name" value="${esc(project.name)}" maxlength="140"></label><div class="field-pair"><label>IP address<input name="ip" value="${esc(project.ip)}" maxlength="100" placeholder="IPv4 or IPv6"></label><label>Host name<input name="host" value="${esc(project.host)}" maxlength="253" placeholder="example.com"></label></div><label>Others<textarea name="others" rows="5" maxlength="20000">${esc(project.others)}</textarea></label><label>Status<select name="status">${options(project.status)}</select></label><div class="custom-status"><input id="workspace-status" placeholder="New custom status" aria-label="New custom status" maxlength="60"><button type="button" id="workspace-add-status">Add status</button></div><div class="form-actions"><button class="primary" type="submit">Save changes</button></div></form><p class="storage-location">Stored inside this app: projects/${esc(project.id)}/</p>`;
  }
  function toolContent() {
    const selected=state?.tools.find(t=>t.id===tool);
    if(!selected) return '<h1>Tool not found</h1>';
    if(selected.gui) return `<div class="desktop-tool-page"><button type="button" class="primary" id="open-desktop-tool" ${selected.installed?'':'disabled'}>Open ${esc(selected.name)}</button>${selected.installed?'':`<p class="muted">${esc(selected.name)} is not installed.</p>`}</div>`;
    if(['sqlmap','nikto','tcpdump','hydra','john','hashcat','gobuster','ffuf','aircrack-ng'].includes(tool) && view==='tool') return '<div id="webscan-workspace"></div>';
    if(tool==='hakrawler' && view==='tool') return '<div id="hakrawler-workspace"></div>';
    if(tool==='nmap' && view==='tool') return '<div id="nmap-workspace"></div>';
    const entries=project.tool_history[tool] || [];
    if(view==='history') return `<div class="content-heading"><div><p class="kicker">TOOLS / ${esc(selected.name.toUpperCase())}</p><h1>${esc(selected.name)} history</h1><p class="muted">${entries.length} saved scan${entries.length===1?'':'s'} in this project</p></div></div><div class="workspace-card scan-history-list">${entries.length?entries.map(entry=>`<article class="scan-history-row"><a class="scan-history-open" href="#project/${project.id}/tool/${tool}/${entry.id}"><div><strong>${esc(entry.title||entry.command||entry.target||project.host||project.ip)}</strong><span class="badge">${esc(entry.status||'saved')}</span></div><small>${esc(entry.target||'')} · ${esc(date(entry.created_at))}</small></a><button class="scan-delete" data-delete-scan="${entry.id}" aria-label="Delete scan from ${esc(date(entry.created_at))}" title="Delete scan"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7"/></svg></button></article>`).join(''):'<div class="blank-state"><span>↳</span><h2>No runs saved yet</h2><p>Runs are saved here automatically.</p></div>'}</div>`;
    return `<div class="content-heading"><div><p class="kicker">TOOLS / ${esc(selected.name.toUpperCase())}</p><h1>${esc(selected.name)}${view==='history'?' history':''}</h1><p class="muted">${esc(project.host || project.ip)}</p></div></div>${view==='history' ? `<div class="workspace-card">${entries.length ? entries.map(entry=>`<article class="scan-history-entry"><p>${esc(date(entry.created_at))} · ${esc(entry.status||'saved')}</p><code>${esc(entry.command||'')}</code><p><a class="text-link" href="#project/${project.id}/tool/nmap/${entry.id}">Open scan results →</a></p><pre>${esc(entry.output)}</pre></article>`).join('') : '<div class="blank-state"><span>↳</span><h2>No runs saved yet</h2><p>This project has no history for this tool.</p></div>'}</div>` : `<div class="workspace-card"><h2>${esc(selected.category)}</h2><p class="muted">${selected.installed?'Installed on this computer.':'Not installed. Use the startscreen tool menu to install it.'}</p><dl><dt>Host</dt><dd>${esc(project.host || '—')}</dd><dt>IP address</dt><dd>${esc(project.ip || '—')}</dd><dt>Saved runs</dt><dd>${entries.length}</dd></dl><a class="text-link" href="#project/${project.id}/history/${tool}">View history →</a><p class="muted">Tool execution will be added in a later step.</p></div>`}`;
  }
  function renderProject() {
    let content;
    if(view==='overview') content=overview();
    else if(view==='notes') {
      if(notesProjectId!==project.id){notesProjectId=project.id;selectedNoteId=project.saved_notes?.[0]?.id||null;}
      const entries=project.saved_notes||[], selected=entries.find(n=>n.id===selectedNoteId);
      content=`<div class="content-heading"><h1>Notes</h1></div><div class="notes-layout"><form id="notes-form" class="workspace-card"><label>Note name<input id="note-title" maxlength="140" value="${esc(selected?.title||'')}" placeholder="Untitled note"></label><label for="project-notes">Note</label><textarea id="project-notes" rows="18" maxlength="500000" placeholder="Write your notes here…">${esc(selected?.content||'')}</textarea><div class="form-actions"><button type="submit" class="primary">Save note</button></div></form><aside class="notes-list" aria-label="Saved notes"><div class="notes-list-heading"><strong>Saved notes (${entries.length})</strong><button type="button" id="new-note">+ New</button></div>${entries.map(n=>`<article class="note-row ${n.id===selectedNoteId?'selected':''}"><button type="button" class="note-open" data-open-note="${n.id}"><strong>${esc(n.title)}</strong><small>${esc(date(n.updated_at))}</small></button><details class="note-actions"><summary aria-label="Options for ${esc(n.title)}">⋮</summary><div><button type="button" data-rename-note="${n.id}">Rename</button><button type="button" data-delete-note="${n.id}">Delete</button></div></details></article>`).join('')||'<p class="muted">No saved notes yet.</p>'}</aside></div><dialog id="note-action-dialog"><form id="note-action-form"><h2 id="note-action-heading"></h2><label id="note-rename-label">Note name<input id="note-rename-title" maxlength="140"></label><p id="note-action-description"></p><p id="note-action-error" role="alert"></p><div class="form-actions"><button type="button" id="cancel-note-action">Cancel</button><button type="submit" id="confirm-note-action" class="primary">Save</button></div></form></dialog>`;
    }
    else if(view==='docs') {
      if(documentsProjectId!==project.id){documentsProjectId=project.id;selectedDocumentId=project.document_entries?.[0]?.id||null;pendingDocumentFiles=[];}
      const entries=project.document_entries||[], selected=entries.find(d=>d.id===selectedDocumentId);
      const attachments=(selected?.attachments||[]).map(id=>project.documents.find(d=>d.id===id)).filter(Boolean);
      content=`<div class="content-heading"><h1>Saved docs</h1></div><div class="notes-layout"><form id="document-form" class="workspace-card"><label>Document name<input id="document-title" maxlength="140" value="${esc(selected?.title||'')}" placeholder="Untitled document"></label><label>Text<textarea id="document-text" rows="12" maxlength="500000" placeholder="Write findings or describe these files…">${esc(selected?.text||'')}</textarea></label><div class="document-list">${attachments.map(d=>`<a href="/api/projects/${project.id}/documents/${d.id}" download="${esc(d.name)}"><span>${esc(d.name)}<small>${Math.ceil(d.size/1024)} KB</small></span><span>↓</span></a>`).join('')}</div><label>Add files (4 MB total per save)<input id="document-file" type="file" multiple></label><ul id="pending-document-files"></ul><div class="form-actions"><button type="submit" class="primary">Save document</button></div></form><aside class="notes-list" aria-label="Saved documents"><div class="notes-list-heading"><strong>Documents (${entries.length})</strong><button type="button" id="new-document">+ New</button></div>${entries.map(d=>`<article class="note-row ${d.id===selectedDocumentId?'selected':''}"><button type="button" class="note-open" data-open-document="${d.id}"><strong>${esc(d.title)}</strong><small>${d.attachments.length} files · ${esc(date(d.updated_at))}</small></button><details class="note-actions"><summary aria-label="Options for ${esc(d.title)}">⋮</summary><div><button type="button" data-rename-document="${d.id}">Rename</button><button type="button" data-delete-document="${d.id}">Delete</button></div></details></article>`).join('')||'<p class="muted">No saved documents yet.</p>'}</aside></div><dialog id="document-action-dialog"><form id="document-action-form"><h2 id="document-action-heading"></h2><label id="document-rename-label">Document name<input id="document-rename-title" maxlength="140"></label><p id="document-action-description"></p><p id="document-action-error" role="alert"></p><div class="form-actions"><button type="button" id="cancel-document-action">Cancel</button><button type="submit" id="confirm-document-action" class="primary">Save</button></div></form></dialog>`;
    }
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
    if(['sqlmap','nikto','tcpdump','hydra','john','hashcat','gobuster','ffuf','aircrack-ng'].includes(tool)&&view==='tool') WebScanWorkspace.mount(project,tool,location.hash.split('/')[4]);
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
    const notes=$('notes-form');
    if(notes){
      notes.onsubmit=async e=>{e.preventDefault();await saveAction(e.submitter,async()=>{
        project=await api(`/api/projects/${project.id}/notes`,{id:selectedNoteId,title:$('note-title').value.trim()||'Untitled note',notes:$('project-notes').value});
        selectedNoteId=project.selected_note_id;renderProject();message('Note saved.');
      });};
      $('new-note').onclick=()=>{selectedNoteId=null;renderProject();$('note-title').focus();};
      document.querySelectorAll('[data-open-note]').forEach(b=>b.onclick=()=>{selectedNoteId=b.dataset.openNote;renderProject();});
      const dialog=$('note-action-dialog');
      let action, noteId;
      const openAction=(id,kind)=>{
        const note=project.saved_notes.find(n=>n.id===id);noteId=id;action=kind;
        $('note-action-heading').textContent=kind==='rename'?'Rename note':'Delete note';
        $('note-rename-label').hidden=kind!=='rename';$('note-rename-title').value=note.title;
        $('note-action-description').textContent=kind==='delete'?`Delete “${note.title}”? This cannot be undone.`:'';
        $('note-action-error').textContent='';$('confirm-note-action').textContent=kind==='delete'?'Delete':'Save';
        dialog.showModal();
      };
      document.querySelectorAll('[data-rename-note]').forEach(b=>b.onclick=()=>openAction(b.dataset.renameNote,'rename'));
      document.querySelectorAll('[data-delete-note]').forEach(b=>b.onclick=()=>openAction(b.dataset.deleteNote,'delete'));
      $('cancel-note-action').onclick=()=>dialog.close();
      $('note-action-form').onsubmit=async e=>{
        e.preventDefault();const button=$('confirm-note-action');button.disabled=true;
        try{
          project=await api(`/api/projects/${project.id}/notes`,{action,id:noteId,title:$('note-rename-title').value});
          if(action==='delete'&&selectedNoteId===noteId)selectedNoteId=project.saved_notes[0]?.id||null;
          dialog.close();renderProject();message(action==='delete'?'Note deleted.':'Note renamed.');
        }catch(error){$('note-action-error').textContent=error.message;}finally{button.disabled=false;}
      };
    }
    const docs=$('document-form');
    if(docs){
      const drawPending=()=>{$('pending-document-files').innerHTML=pendingDocumentFiles.map((f,i)=>`<li>${esc(f.name)} <button type="button" data-remove-pending="${i}" aria-label="Remove ${esc(f.name)}">×</button></li>`).join('');document.querySelectorAll('[data-remove-pending]').forEach(b=>b.onclick=()=>{pendingDocumentFiles.splice(Number(b.dataset.removePending),1);drawPending();});};
      drawPending();
      $('document-file').onchange=()=>{pendingDocumentFiles.push(...$('document-file').files);$('document-file').value='';drawPending();};
      docs.onsubmit=async e=>{e.preventDefault();await saveAction(e.submitter,async()=>{
        if(pendingDocumentFiles.length>50||pendingDocumentFiles.reduce((sum,f)=>sum+f.size,0)>4*1024*1024)throw Error('Choose at most 50 files totaling 4 MB per save.');
        const files=await Promise.all(pendingDocumentFiles.map(async file=>({name:file.name,content:await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(',')[1]);reader.onerror=()=>reject(Error('Could not read '+file.name));reader.readAsDataURL(file);})})));
        project=await api(`/api/projects/${project.id}/documents`,{action:'save',id:selectedDocumentId,title:$('document-title').value,text:$('document-text').value,files});
        selectedDocumentId=project.selected_document_id;pendingDocumentFiles=[];renderProject();message('Document saved.');
      });};
      $('new-document').onclick=()=>{selectedDocumentId=null;pendingDocumentFiles=[];renderProject();$('document-title').focus();};
      document.querySelectorAll('[data-open-document]').forEach(b=>b.onclick=()=>{selectedDocumentId=b.dataset.openDocument;pendingDocumentFiles=[];renderProject();});
      const dialog=$('document-action-dialog');let action,documentId;
      const openAction=(id,kind)=>{const entry=project.document_entries.find(d=>d.id===id);documentId=id;action=kind;$('document-action-heading').textContent=kind==='rename'?'Rename document':'Delete document';$('document-rename-label').hidden=kind!=='rename';$('document-rename-title').value=entry.title;$('document-action-description').textContent=kind==='delete'?`Delete “${entry.title}” and its attached files? This cannot be undone.`:'';$('document-action-error').textContent='';$('confirm-document-action').textContent=kind==='delete'?'Delete':'Save';dialog.showModal();};
      document.querySelectorAll('[data-rename-document]').forEach(b=>b.onclick=()=>openAction(b.dataset.renameDocument,'rename'));
      document.querySelectorAll('[data-delete-document]').forEach(b=>b.onclick=()=>openAction(b.dataset.deleteDocument,'delete'));
      $('cancel-document-action').onclick=()=>dialog.close();
      $('document-action-form').onsubmit=async e=>{e.preventDefault();const button=$('confirm-document-action');button.disabled=true;try{project=await api(`/api/projects/${project.id}/documents`,{action,id:documentId,title:$('document-rename-title').value});if(action==='delete'&&selectedDocumentId===documentId){selectedDocumentId=project.document_entries[0]?.id||null;pendingDocumentFiles=[];}dialog.close();renderProject();message(action==='delete'?'Document deleted.':'Document renamed.');}catch(error){$('document-action-error').textContent=error.message;}finally{button.disabled=false;}};
    }
  }
  async function saveAction(button, fn) {
    if(saving)return; saving=true;if(button)button.disabled=true;
    try {await fn();}catch(e){message(e.message);}finally{saving=false;if(button)button.disabled=false;}
  }
  async function route() {
    const version=++routeVersion;
    NmapWorkspace.unmount();
    HakrawlerWorkspace.unmount();
    WebScanWorkspace.unmount();
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
