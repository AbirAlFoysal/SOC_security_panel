const $ = id => document.getElementById(id);
let state, openMenu = null, pending, polling = false;
const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function render() {
  const {tools, job} = state;
  const installed = tools.filter(t => t.installed).length;
  const query = $('search').value.trim().toLowerCase();
  const shown = tools.filter(t => `${t.name} ${t.id} ${t.category}`.toLowerCase().includes(query));
  $('tools').innerHTML = shown.map(t => `<div class="tool"><div class="tool-name" title="${escapeHTML(t.path || 'No executable found')}">${escapeHTML(t.name)}</div><span class="status ${t.installed ? 'yes' : 'no'}" role="img" aria-label="${t.installed ? 'Installed' : 'Not installed'}" title="${t.installed ? 'Installed' : 'Not installed'}"><b aria-hidden="true">${t.installed ? '✓' : '×'}</b></span><button class="menu-button" data-menu="${t.id}" aria-label="Actions for ${escapeHTML(t.name)}" aria-expanded="${openMenu === t.id}" ${job.running ? 'disabled' : ''}>⋮</button>${openMenu === t.id ? `<div class="dropdown">${['install','update','remove'].map(a=>`<button data-tool="${t.id}" data-action="${a}" ${job.running || (a==='install' ? t.installed : !t.installed) ? 'disabled' : ''}>${a[0].toUpperCase()+a.slice(1)}</button>`).join('')}</div>` : ''}</div>`).join('') || '<div class="empty">No modules match your filter.</div>';
  $('install-all').disabled = job.running || installed === tools.length;
  $('update-all').disabled = job.running || installed === 0;
  $('activity').hidden = !job.running && !job.log.length && !job.results.length;
  $('log').textContent = job.log.join('\n') || 'No operations yet.';
  $('results').innerHTML = job.results.map(r=>`<div class="result ${r.ok?'':'failed'}">${r.ok?'✓':'×'} ${escapeHTML(r.tool)}: ${escapeHTML(r.message)}</div>`).join('');
}
async function refresh() {
  if(polling) return;
  polling = true;
  try {
    const r = await fetch('/api/status');
    if(!r.ok) throw Error('Could not check local tools.');
    state = await r.json(); render();

  } catch(e) { $('activity').hidden=false; $('notice').textContent = `${e.message} Start or restart the app with make run.`; }
  finally {polling = false;}
}
async function act(tool, action) {
  openMenu = null;
  if(!state || state.job.running) return;
  try {
    const r = await fetch('/api/action', {method:'POST', headers:{'Content-Type':'application/json','X-App-Token':state.token}, body:JSON.stringify({tool,action})});
    const data = await r.json(); if(!r.ok) throw Error(data.error);
    $('notice').textContent = `${action[0].toUpperCase()+action.slice(1)} started. Output and any errors appear below.`;
    await refresh();
  } catch(e) { $('notice').textContent=e.message; }
}
$('tools').addEventListener('click', e => {
  const menu = e.target.closest('[data-menu]');
  if(menu) {openMenu = openMenu === menu.dataset.menu ? null : menu.dataset.menu; render(); return;}
  const button = e.target.closest('[data-action]');
  if(button) {
    const {tool,action} = button.dataset;
    if(action === 'remove') {
      pending = {tool,action};
      $('confirm-title').textContent = `Remove ${state.tools.find(t=>t.id===tool).name}?`;
      $('confirm-text').textContent = 'This removes the tool from this computer using its package manager. Other packages may depend on it; review the system prompt and operation log.';
      $('confirm').showModal();
    } else act(tool,action);
  }
});
document.addEventListener('click', e => {if(openMenu && !e.target.closest('.tool')) {openMenu=null; render();}});
document.addEventListener('keydown', e => {if(e.key === 'Escape' && openMenu) {openMenu=null; render();}});
$('cancel').onclick = () => $('confirm').close();
$('confirm-action').onclick = () => { $('confirm').close(); if(pending) act(pending.tool,pending.action); pending=null; };
$('search').addEventListener('input', () => { if(state) render(); });
$('install-all').onclick = () => act('all','install');
$('update-all').onclick = () => act('all','update');
refresh();
setInterval(()=> { if(!openMenu) refresh(); }, 2500);

// Check separately so open menus never pause development reloads.
let codeRevision = null, checkingRevision = false;
async function checkRevision() {
  if (checkingRevision) return;
  checkingRevision = true;
  try {
    const response = await fetch('/api/revision');
    if (!response.ok) return;
    const data = await response.json();
    if (codeRevision && codeRevision !== data.revision && !data.busy) {
      window.location.reload();
      return;
    }
    if (!codeRevision) codeRevision = data.revision;
  } catch (_) {
    // The server may be restarting. The next poll reconnects automatically.
  } finally { checkingRevision = false; }
}
checkRevision();
setInterval(checkRevision, 1000);
