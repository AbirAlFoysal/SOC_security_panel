(() => {
  let current = null, checking = false, sending = false, showOutput = false;
  function showMessage(text) { $('network-message').hidden=!text; $('network-message').textContent=text; }
  async function checkNetwork() {
    if(checking) return;
    checking=true;
    try {
      const response=await fetch('/api/network');
      if(!response.ok) throw Error('Network status is unavailable. Retrying…');
      current=await response.json();
      const {anonsurf:anon,macchanger:mac,job}=current;
      const busy=job.running||sending;
      const anonActive=anon.state==='active';
      $('anonsurf-control').textContent=anonActive?'Stop AnonSurf':'Start AnonSurf';
      $('anonsurf-control').disabled=busy||!anon.installed||current.system!=='Linux';
      $('anonsurf-state').textContent=!anon.installed?'Not installed':anonActive?'Active':anon.state==='inactive'?'Stopped':'Status unavailable';
      $('anonsurf-state').classList.toggle('active',anonActive);
      $('anonsurf-data').textContent=anon.installed ? (anon.error || `Tor: ${anon.tor===true?'running':anon.tor===false?'stopped':'unknown'} · DNS: ${anon.dns||'unknown'}`) : '';
      $('anonsurf-control').title=anon.error || (anonActive?'Stop system-wide Tor routing':'Start system-wide Tor routing');
      $('mac-control').textContent=mac.managed?'Restore MAC':'Start MAC changer';
      $('mac-control').disabled=busy||!mac.installed||Boolean(mac.reason)||anonActive;
      $('mac-control').title=anonActive?'Stop AnonSurf before changing the MAC.':mac.reason||'Randomize the active interface MAC. This briefly reconnects the network.';
      $('mac-state').textContent=!mac.installed?'Not installed':mac.managed?'Changed · session saved':mac.state==='changed'?'Changed externally':mac.state==='original'?'Original MAC':mac.interface?'Status unavailable':'No active interface';
      $('mac-state').classList.toggle('active',mac.state==='managed'||mac.state==='changed');
      $('mac-data').textContent=mac.interface ? `${mac.interface} · ${mac.current||'MAC unavailable'}` : mac.reason||'';
      $('mac-data').title=`Permanent MAC: ${mac.permanent||'unavailable'}${mac.error?' · '+mac.error:''}`;
      $('network-updated').textContent=`Live · ${new Date().toLocaleTimeString()}`;
      const networkJob=/^\[(anonsurf|macchanger)\] (start|stop)/.test(job.log?.[0]||'');
      if(networkJob||showOutput) {
        $('network-output').hidden=false;
        $('network-log').textContent=job.log.join('\n')||'Waiting for the system…';
        if(networkJob&&job.results.length) showMessage(job.results.map(r=>`${r.ok?'✓':'×'} ${r.message}`).join(' '));
      }
    } catch(e) {
      $('anonsurf-state').textContent='Disconnected';$('mac-state').textContent='Disconnected';
      $('anonsurf-control').disabled=true;$('mac-control').disabled=true;
      $('network-updated').textContent='Reconnecting…';
    } finally {checking=false;}
  }
  async function action(tool, action) {
    if(sending||!current||current.job.running)return;
    sending=true;showOutput=true;
    $('anonsurf-control').disabled=true;$('mac-control').disabled=true;
    showMessage(action==='start'&&tool==='macchanger'?'Waiting for authentication. The network will briefly reconnect.':'Waiting for system authentication…');
    $('network-output').hidden=false;$('network-output').open=true;
    try {
      // Refresh the request token so actions also work after a server restart.
      const info=await fetch('/api/status');if(!info.ok)throw Error('Unable to connect to the local server.');
      const auth=await info.json();
      const response=await fetch('/api/network/action',{method:'POST',headers:{'Content-Type':'application/json','X-App-Token':auth.token},body:JSON.stringify({tool,action})});
      const result=await response.json();if(!response.ok)throw Error(result.error);
      showMessage(result.message);
    }catch(e){showMessage(e.message);}finally{sending=false;await checkNetwork();}
  }
  $('anonsurf-control').onclick=()=>action('anonsurf',current.anonsurf.state==='active'?'stop':'start');
  $('mac-control').onclick=()=>action('macchanger',current.macchanger.managed?'stop':'start');
  const nav=document.querySelector('.network-nav');
  new ResizeObserver(()=>document.documentElement.style.setProperty('--network-nav-height',nav.getBoundingClientRect().height+'px')).observe(nav);
  checkNetwork();setInterval(checkNetwork,2000);
})();
