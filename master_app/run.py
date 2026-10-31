"""Local cybersecurity environment manager (Python standard library only)."""
import argparse
import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import threading
import webbrowser
from gui_apps import GUI_TOOLS, DesktopLauncher, locate_gui
from hakrawler_runner import HakrawlerRunner
from nmap_runner import NmapRunner
from webscan_runner import WebScanRunner
from nuclei_batch_runner import NucleiBatchRunner
from cli_runner import CliRunner, CONFIG as CLI_CONFIG
import network_manager
from project_store import ProjectStore, DuplicateProjectError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).parent
PROJECTS = ProjectStore(ROOT.parent / 'projects')
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()
JOB = {'running': False, 'log': [], 'results': []}
TOOLS = [
    ('nmap', 'Nmap', 'Network discovery', 'nmap', 'Insecure.Nmap'),
    ('hakrawler', 'Hakrawler', 'Web crawling', 'hakrawler', None),
    ('macchanger', 'MAC changer', 'Network identity', 'macchanger', None),
    ('anonsurf', 'AnonSurf', 'Network privacy', 'anonsurf', None),
    ('burpsuite', 'Burp Suite', 'Web application proxy', 'burpsuite', None),
    ('wireshark', 'Wireshark', 'Packet analysis', 'wireshark', 'WiresharkFoundation.Wireshark'),
    ('tcpdump', 'tcpdump', 'Packet capture', 'tcpdump', None),
    ('sqlmap', 'sqlmap', 'Database assessment', 'sqlmap', None),
    ('nikto', 'Nikto', 'Web server assessment', 'nikto', None),
    ('hydra', 'Hydra', 'Authentication testing', 'hydra', None),
    ('john', 'John the Ripper', 'Password auditing', 'john', None),
    ('hashcat', 'Hashcat', 'Password recovery', 'hashcat', None),
    ('gobuster', 'Gobuster', 'Content discovery', 'gobuster', None),
    ('ffuf', 'ffuf', 'Web fuzzing', 'ffuf', None),
    ('aircrack-ng', 'Aircrack-ng', 'Wireless assessment', 'aircrack-ng', None),
    ('nuclei', 'Nuclei', 'Vulnerability scanning', 'nuclei', None),
]
CATALOG = {t[0]: t for t in TOOLS}


def capture(args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return r.stdout.strip() if r.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def environment():
    system = platform.system()
    release = platform.freedesktop_os_release() if system == 'Linux' else {}
    manager = next((p for p in ('apt-get', 'dnf', 'pacman') if shutil.which(p)), None) if system == 'Linux' else ('winget' if system == 'Windows' and shutil.which('winget') else None)
    return {'system': system, 'name': release.get('PRETTY_NAME', platform.platform()), 'manager': manager, 'machine': platform.machine()}


def locate(tool):
    if tool in GUI_TOOLS:
        return locate_gui(tool)
    found = shutil.which(tool)
    if found:
        return found
    suffix = '.exe' if os.name == 'nt' else ''
    candidates = [Path.home() / '.local/bin' / (tool + suffix), Path.home() / 'go/bin' / (tool + suffix), Path('/usr/sbin') / tool]
    if os.name == 'nt':
        for base in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)')):
            if base and tool in ('nmap', 'wireshark'):
                candidates.append(Path(base) / ('Nmap' if tool == 'nmap' else 'Wireshark') / (tool + '.exe'))
    return next((str(p) for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)


def go_binary(tool):
    gobin = os.environ.get('GOBIN')
    if not gobin:
        gopath = capture(['go', 'env', 'GOPATH']) if shutil.which('go') else str(Path.home() / 'go')
        gobin = str(Path(gopath.split(os.pathsep)[0]) / 'bin')
    return Path(gobin) / (tool + ('.exe' if os.name == 'nt' else ''))


def plan(tool, action, env):
    t = CATALOG[tool]
    installed = locate(tool)
    if action == 'install' and installed:
        raise ValueError('Already installed. Use Update instead.')
    if action in ('update', 'remove') and not installed:
        raise ValueError('Tool is not installed.')
    manager = env['manager']
    if tool == 'nuclei' and (manager != 'apt-get' or not capture(['dpkg-query', '-W', '-f=${Status}', 'nuclei']).endswith(' installed')):
        if not shutil.which('go'):
            raise ValueError('Install Go first to manage Nuclei from its official Go module.')
        target = go_binary(tool)
        if installed and Path(installed).resolve() != target.resolve():
            local = Path.home() / '.local' / 'bin' / tool
            if Path(installed) == local and local.is_file() and not local.is_symlink() and local.stat().st_uid == os.getuid():
                target = local
            else:
                raise ValueError(f'Existing binary is outside the Go install directory ({target}). Manage its original installation manually.')
        if action == 'remove':
            return ('delete', str(target))
        return ('go', (['go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'], str(target.parent)))
    if tool == 'hakrawler' and (manager != 'apt-get' or not capture(['dpkg-query', '-W', '-f=${Status}', 'hakrawler']).endswith(' installed')):
        if not shutil.which('go'):
            raise ValueError('Install Go first to manage Hakrawler from its official Go module.')
        target = go_binary(tool)
        if installed and Path(installed).resolve() != target.resolve():
            local = Path.home() / '.local' / 'bin' / tool
            if Path(installed) == local and local.is_file() and not local.is_symlink() and local.stat().st_uid == os.getuid():
                target = local
            else:
                raise ValueError(f'Existing binary is outside the Go install directory ({target}). Manage its original installation manually.')
        if action == 'remove':
            return ('delete', str(target))
        return ('go', (['go', 'install', 'github.com/hakluke/hakrawler@latest'], str(target.parent)))
    if manager == 'apt-get':
        if action != 'remove':
            policy = capture(['apt-cache', 'policy', t[3]])
            candidate = next((line.split(':', 1)[1].strip() for line in policy.splitlines() if 'Candidate:' in line), '')
            if not candidate or candidate == '(none)':
                raise ValueError('No package candidate in configured APT repositories. This tool needs its official installer or a supported repository.')
        if action in ('update', 'remove'):
            owner = capture(['dpkg-query', '-S', installed])
            if not owner or t[3] not in owner.split(':', 1)[0].split(', '):
                raise ValueError('The detected binary is not owned by this APT package. Manage its original installation manually.')
        cmd = ['apt-get', 'remove' if action == 'remove' else 'install', '-y']
        if action == 'update':
            cmd.append('--only-upgrade')
        return ('admin', cmd + [t[3]])
    if manager == 'dnf':
        return ('admin', ['dnf', {'install': 'install', 'update': 'upgrade', 'remove': 'remove'}[action], '-y', t[3]])
    if manager == 'pacman':
        return ('admin', ['pacman', '-R' if action == 'remove' else '-S', '--noconfirm', t[3]])
    if manager == 'winget' and t[4]:
        cmd = ['winget', {'install': 'install', 'update': 'upgrade', 'remove': 'uninstall'}[action], '--id', t[4], '--exact', '--disable-interactivity']
        if action != 'remove':
            cmd += ['--accept-source-agreements', '--accept-package-agreements']
        return ('command', cmd)
    raise ValueError('No supported native installer for this tool on this OS. Use its official installation instructions (Linux tools may require WSL on Windows).')


NMAP = NmapRunner(PROJECTS, locate)
HAKRAWLER = HakrawlerRunner(PROJECTS, locate)
WEB_SCANS = {tool: WebScanRunner(PROJECTS, locate, tool) for tool in ('sqlmap', 'nikto', 'nuclei')}
WEB_SCANS.update({tool: CliRunner(PROJECTS, locate, tool) for tool in CLI_CONFIG})

NUCLEI_BATCH = NucleiBatchRunner(PROJECTS, locate)

def web_scans_busy():
    return any(r.running for r in WEB_SCANS.values()) or NUCLEI_BATCH.running
DESKTOP = DesktopLauncher(ROOT.parent / '.runtime' / 'desktop-tools')

def snapshot():
    env = environment()
    rows = []
    for tool, name, category, package, win in TOOLS:
        if tool in ('anonsurf', 'macchanger'):
            continue
        path = locate(tool)
        is_running = (
            (tool in WEB_SCANS and WEB_SCANS[tool].running) or
            (tool == 'nuclei' and NUCLEI_BATCH.running) or
            (tool == 'nmap' and NMAP.running) or
            (tool == 'hakrawler' and HAKRAWLER.running)
        )
        rows.append({'id': tool, 'name': name, 'category': category, 'installed': bool(path), 'path': path, 'gui': tool in GUI_TOOLS, 'running': is_running})
    with LOCK:
        job = {**JOB, 'log': list(JOB['log']), 'results': list(JOB['results'])}
    active_scan = None
    if NUCLEI_BATCH.running and NUCLEI_BATCH.current:
        active_scan = {'tool': 'nuclei', 'type': 'batch', 'project_id': NUCLEI_BATCH.current.get('project_id'), 'target': NUCLEI_BATCH.current.get('target')}
    elif any(r.running for r in WEB_SCANS.values()):
        for t, r in WEB_SCANS.items():
            if r.running and r.current:
                active_scan = {'tool': t, 'type': 'scan', 'project_id': r.current.get('project_id'), 'target': r.current.get('target')}
                break
    return {'environment': env, 'tools': rows, 'job': job, 'token': TOKEN, 'active_scan': active_scan}


def log(line):
    with LOCK:
        JOB['log'].append(line)
        JOB['log'] = JOB['log'][-800:]


def run_command(cmd, extra_env=None):
    log('$ ' + subprocess.list2cmdline(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', stdin=subprocess.DEVNULL, env={**os.environ, **(extra_env or {})})
    timeout = threading.Timer(1800, proc.kill)
    timeout.start()
    try:
        for line in proc.stdout:
            log(line.rstrip())
        code = proc.wait()
        if code:
            raise RuntimeError(f'Command exited with code {code}. See output above. Authentication can be retried from the menu.')
    finally:
        timeout.cancel()


def worker(ids, action):
    try:
        env = environment()
        for tool in ids:
            try:
                log(f'\n[{CATALOG[tool][1]}] {action}')
                kind, value = plan(tool, action, env)
                if kind == 'delete':
                    Path(value).unlink()
                    log('Removed Go binary.')
                else:
                    if kind == 'admin' and hasattr(os, 'geteuid') and os.geteuid() != 0:
                        if shutil.which('pkexec'):
                            value = ['pkexec', shutil.which(value[0])] + value[1:]
                            log('Approve the system authentication dialog to continue.')
                        else:
                            value = ['sudo', '-n'] + value
                            log('Using an existing sudo authorization; if unavailable, run sudo -v in the launch terminal and retry.')
                    if kind == 'go':
                        cmd, gobin = value
                        run_command(cmd, {'GOBIN': gobin})
                    else:
                        run_command(value)
                present = bool(locate(tool))
                if (action == 'remove' and present) or (action != 'remove' and not present):
                    raise RuntimeError('Command completed, but tool detection did not match the expected result. Restart the app if your PATH changed.')
                result = {'tool': tool, 'ok': True, 'message': f'{action.capitalize()} completed.'}
                log(result['message'])
            except Exception as exc:
                result = {'tool': tool, 'ok': False, 'message': str(exc)}
                log('FAILED: ' + str(exc))
            with LOCK:
                JOB['results'].append(result)
    finally:
        with LOCK:
            JOB['running'] = False
        log('\nFinished. Tool status refreshed.')


def network_worker(tool, action):
    try:
        log(f'[{tool}] {action}')
        cmd = network_manager.command(tool, action, network_manager.status())
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            if shutil.which('pkexec'):
                cmd = ['pkexec'] + cmd
                log('Approve the system authentication dialog on your desktop.')
            else:
                cmd = ['sudo', '-n'] + cmd
                log('Using an existing sudo authorization. If unavailable, run sudo -v and retry.')
        run_command(cmd)
        actual = network_manager.status()
        if tool == 'anonsurf':
            expected = 'active' if action == 'start' else 'inactive'
            if actual['anonsurf']['state'] != expected:
                raise RuntimeError('The command finished but AnonSurf status did not confirm the expected result.')
        elif action == 'start' and not actual['macchanger']['managed']:
            raise RuntimeError('MAC change was not confirmed. Check the operation log.')
        elif action == 'stop' and actual['macchanger']['managed']:
            raise RuntimeError('MAC restoration was not confirmed. Check the operation log.')
        result = {'tool': tool, 'ok': True, 'message': f'{action.capitalize()} completed.'}
        log(result['message'])
    except Exception as exc:
        result = {'tool': tool, 'ok': False, 'message': str(exc)}
        log('FAILED: ' + str(exc))
    finally:
        with LOCK:
            JOB['results'].append(result)
            JOB['running'] = False


class Handler(BaseHTTPRequestHandler):
    def valid_host(self):
        return self.headers.get('Host') in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}')

    def send(self, code, body, content='application/json'):
        raw = json.dumps(body).encode() if content == 'application/json' else body
        self.send_response(code)
        self.send_header('Content-Type', content)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not self.valid_host():
            return self.send(403, {'error': 'Local access only.'})
        if self.path == '/api/network':
            data = network_manager.status()
            with LOCK:
                data['job'] = {**JOB, 'log': list(JOB['log']), 'results': list(JOB['results'])}
            return self.send(200, data)
        if self.path == '/api/projects':
            return self.send(200, {'projects': PROJECTS.list(), 'statuses': PROJECTS.statuses()})
        if self.path.startswith('/api/projects/'):
            parts = self.path.strip('/').split('/')
            try:
                if len(parts) == 3:
                    return self.send(200, PROJECTS.get(parts[2]))
                if len(parts) == 4 and parts[3] == 'nmap':
                    return self.send(200, NMAP.status(parts[2]))
                if len(parts) == 4 and parts[3] in WEB_SCANS:
                    result = WEB_SCANS[parts[3]].status(parts[2])
                    if parts[3] == 'nuclei':
                        with NUCLEI_BATCH.lock:
                            if NUCLEI_BATCH.current and NUCLEI_BATCH.current.get('project_id') == parts[2]:
                                if NUCLEI_BATCH.running:
                                    result['current'] = deepcopy(NUCLEI_BATCH.current)
                                    result['busy'] = True
                                else:
                                    cur = deepcopy(NUCLEI_BATCH.current)
                                    h_list = result.setdefault('history', [])
                                    idx = next((i for i, r in enumerate(h_list) if r.get('id') == cur.get('id')), None)
                                    if idx is not None:
                                        h_list[idx] = cur
                                    else:
                                        h_list.insert(0, cur)
                            elif not NUCLEI_BATCH.running and not WEB_SCANS['nuclei'].running:
                                h_list = result.get('history', [])
                                changed = False
                                for r in h_list:
                                    if r.get('status') == 'running':
                                        r['status'] = 'cancelled'
                                        for h in r.get('hosts', []):
                                            if h.get('status') in ('pending', 'running'):
                                                h['status'] = 'cancelled'
                                                h['detail'] = 'cancelled by user'
                                        changed = True
                                if changed:
                                    try:
                                        p_data = PROJECTS.get(parts[2])
                                        p_data['tool_history']['nuclei'] = h_list
                                        p_data.pop('notes', None)
                                        p_data.pop('saved_notes', None)
                                        PROJECTS._write(PROJECTS._directory(parts[2]) / 'project.json', p_data)
                                    except Exception:
                                        pass
                    result['busy'] = JOB['running'] or NMAP.running or HAKRAWLER.running or web_scans_busy() or result.get('busy', False)
                    return self.send(200, result)
                if len(parts) == 4 and parts[3] == 'nuclei_batch':
                    return self.send(200, NUCLEI_BATCH.status(parts[2]))
                clean_path = self.path.split('?')[0]
                cparts = clean_path.strip('/').split('/')
                if len(cparts) == 6 and cparts[3] == 'nuclei_batch' and cparts[4] == 'hostlog':
                    try:
                        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                        idx = int(qs.get('idx', [0])[0])
                        return self.send(200, {'log': NUCLEI_BATCH.get_host_log(cparts[2], cparts[5], idx)})
                    except Exception as exc:
                        return self.send(400, {'error': str(exc)})
                if len(parts) == 5 and parts[3] == 'nuclei_batch' and parts[4] == 'sessions':
                    return self.send(200, {'sessions': NUCLEI_BATCH.list_sessions(parts[2])})
                if len(parts) == 4 and parts[3] == 'hakrawler':
                    return self.send(200, HAKRAWLER.status(parts[2]))
                if len(parts)>=7 and parts[3] in WEB_SCANS and parts[4]=='history' and parts[6]=='files':
                    runner=WEB_SCANS[parts[3]]
                    if len(parts)==7:
                        return self.send(200, {'files':runner.scan_files(parts[2],parts[5])})
                    if len(parts)==8:
                        file=runner.scan_file(parts[2],parts[5],parts[7])
                        with file.open('rb') as stream:
                            self.send_response(200)
                            self.send_header('Content-Type','application/octet-stream')
                            name=''.join(c if c.isascii() and (c.isalnum() or c in '._-') else '_' for c in file.name)
                            self.send_header('Content-Disposition','attachment; filename="'+name+'"')
                            self.send_header('X-Content-Type-Options','nosniff')
                            self.send_header('Content-Length',str(os.fstat(stream.fileno()).st_size))
                            self.end_headers()
                            return shutil.copyfileobj(stream,self.wfile)
                if len(parts) == 5 and parts[3] == 'documents':
                    raw = PROJECTS.download(parts[2], parts[4])
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', 'attachment; filename="document"')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    return self.wfile.write(raw)
            except FileNotFoundError as exc:
                return self.send(404, {'error': str(exc)})
            except ValueError as exc:
                return self.send(400, {'error': str(exc)})
            return self.send(404, {'error': 'Not found'})
        if self.path == '/api/revision':
            digest = hashlib.sha256(TOKEN.encode())
            for p in sorted(ROOT.iterdir()):
                if p.is_file() and p.suffix in ('.html', '.css', '.js', '.py', '.json'):
                    digest.update(p.name.encode())
                    digest.update(p.read_bytes())
            with LOCK:
                running = JOB['running'] or NMAP.running or HAKRAWLER.running or web_scans_busy()
            return self.send(200, {'revision': digest.hexdigest(), 'busy': running})
        if self.path == '/api/status':
            return self.send(200, snapshot())
        files = {'/webscan.js': ('webscan.js', 'text/javascript'), '/webscan.css': ('webscan.css', 'text/css'), '/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css'), '/projects.js': ('projects.js', 'text/javascript'), '/projects.css': ('projects.css', 'text/css'), '/network.js': ('network.js', 'text/javascript'), '/network.css': ('network.css', 'text/css'), '/nmap.js': ('nmap.js', 'text/javascript'), '/nmap.css': ('nmap.css', 'text/css'), '/hakrawler.js': ('hakrawler.js', 'text/javascript'), '/hakrawler.css': ('hakrawler.css', 'text/css')}
        if self.path not in files:
            return self.send(404, {'error': 'Not found'})
        file, mime = files[self.path]
        self.send(200, (ROOT / file).read_bytes(), mime)

    def do_POST(self):
        origin = self.headers.get('Origin')
        if not self.valid_host() or self.headers.get('X-App-Token') != TOKEN or origin not in (None, f'http://{self.headers.get("Host")}'):
            return self.send(403, {'error': 'Request must come from this app.'})
        if self.path.startswith('/api/') and self.path.endswith('/presets') and self.path.split('/')[2] in WEB_SCANS:
            return self.nmap_preset_post(WEB_SCANS[self.path.split('/')[2]])
        if self.path == '/api/hakrawler/presets':
            return self.nmap_preset_post(HAKRAWLER)
        if self.path == '/api/nmap/presets':
            return self.nmap_preset_post()
        if self.path == '/api/network/action':
            return self.network_post()
        if self.path.startswith('/api/projects') or self.path == '/api/statuses':
            return self.project_post()
        if self.path != '/api/action':
            return self.send(404, {'error': 'Not found'})
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 4096:
                raise ValueError('Invalid request size')
            body = json.loads(self.rfile.read(length))
            action, target = body.get('action'), body.get('tool')
            if action not in ('install', 'update', 'remove') or target not in (*CATALOG, 'all'):
                raise ValueError('Unknown tool or action')
            if target == 'all' and action == 'remove':
                raise ValueError('Bulk removal is not supported')
            ids = [t for t in CATALOG if t not in ('anonsurf','macchanger') and bool(locate(t)) == (action == 'update')] if target == 'all' else [target]
            with LOCK:
                if JOB['running'] or NMAP.running or HAKRAWLER.running or web_scans_busy():
                    return self.send(409, {'error': 'An operation is already running.'})
                JOB.update(running=True, log=[], results=[])
            threading.Thread(target=worker, args=(ids, action), daemon=True).start()
            self.send(202, {'message': 'Operation started'})
        except (ValueError, TypeError, AttributeError) as exc:
            self.send(400, {'error': str(exc)})

    def network_post(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 4096:
                raise ValueError('Invalid request size.')
            data = json.loads(self.rfile.read(length))
            tool, action = data.get('tool'), data.get('action')
            if tool not in ('anonsurf', 'macchanger') or action not in ('start', 'stop'):
                raise ValueError('Unknown network action.')
            with LOCK:
                if JOB['running'] or NMAP.running or HAKRAWLER.running or web_scans_busy():
                    return self.send(409, {'error': 'An operation is already running.'})
                JOB.update(running=True, log=[], results=[])
            threading.Thread(target=network_worker, args=(tool, action), daemon=True).start()
            self.send(202, {'message': 'Network action started. Approve the system authentication prompt.'})
        except (ValueError, TypeError, AttributeError) as exc:
            self.send(400, {'error': str(exc)})

    def nmap_preset_post(self, runner=None):
        runner = runner or NMAP
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 20000:
                raise ValueError('Invalid preset size.')
            data = json.loads(self.rfile.read(length))
            self.send(201, runner.save_preset(data))
        except (ValueError, TypeError, AttributeError) as exc:
            self.send(400, {'error': str(exc)})

    def project_post(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= 6 * 1024 * 1024:
                raise ValueError('Request must be at most 6 MB')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object')
            if self.path == '/api/statuses':
                return self.send(200, {'statuses': PROJECTS.add_status(data)})
            if self.path == '/api/projects':
                return self.send(201, PROJECTS.create(data))
            parts = self.path.strip('/').split('/')
            if len(parts) >= 4 and parts[3] == 'nuclei_batch':
                try:
                    if len(parts) == 4:
                        with LOCK:
                            if JOB['running'] or NMAP.running or HAKRAWLER.running or web_scans_busy():
                                return self.send(409, {'error': 'An operation is already running.'})
                        return self.send(202, NUCLEI_BATCH.start(parts[2], data))
                    if len(parts) == 5 and parts[4] == 'resume':
                        with LOCK:
                            if JOB['running'] or NMAP.running or HAKRAWLER.running or web_scans_busy():
                                return self.send(409, {'error': 'An operation is already running.'})
                        return self.send(202, NUCLEI_BATCH.resume(parts[2], data))
                    if len(parts) == 5 and parts[4] == 'cancel':
                        return self.send(200, NUCLEI_BATCH.cancel(parts[2]))
                except (ValueError, TypeError) as exc:
                    return self.send(400, {'error': str(exc)})
                return self.send(404, {'error': 'Not found'})
            if len(parts) >= 4 and parts[3] in WEB_SCANS:
                runner = WEB_SCANS[parts[3]]
                if len(parts) == 4:
                    with LOCK:
                        if JOB['running'] or NMAP.running or HAKRAWLER.running or web_scans_busy():
                            return self.send(409, {'error': 'An operation is already running.'})
                    return self.send(202, runner.start(parts[2], data))
                if len(parts) == 5 and parts[4] == 'cancel':
                    if parts[3] == 'nuclei':
                        res = None
                        if NUCLEI_BATCH.running:
                            res = NUCLEI_BATCH.cancel(parts[2])
                        elif runner.running:
                            res = runner.cancel(parts[2])
                        else:
                            try:
                                res = NUCLEI_BATCH.cancel(parts[2])
                            except Exception:
                                res = runner.cancel(parts[2])
                        return self.send(200, res or {'message': 'Scan stopped.'})
                    return self.send(200, runner.cancel(parts[2]))
                if len(parts) == 5 and parts[4] == 'files':
                    return self.send(201, runner.upload(parts[2], data))
                if len(parts) == 7 and parts[4] == 'history' and parts[6] == 'delete':
                    return self.send(200, runner.delete(parts[2], parts[5]))
                return self.send(404, {'error': 'Not found'})
            if len(parts) == 6 and parts[3] == 'gui' and parts[5] == 'open':
                PROJECTS.get(parts[2])
                return self.send(200, DESKTOP.open(parts[4]))
            if len(parts) >= 4 and parts[3] == 'hakrawler':
                if len(parts) == 4:
                    with LOCK:
                        if JOB['running'] or NMAP.running or web_scans_busy():
                            return self.send(409, {'error': 'Wait for the current operation to finish.'})
                        return self.send(202, HAKRAWLER.start(parts[2], data))
                if len(parts) == 5 and parts[4] == 'cancel':
                    return self.send(200, HAKRAWLER.cancel(parts[2]))
                if len(parts) == 7 and parts[4] == 'history' and parts[6] == 'delete':
                    return self.send(200, HAKRAWLER.delete(parts[2], parts[5]))
                return self.send(404, {'error': 'Not found'})
            if len(parts) == 5 and parts[3:] == ['nmap', 'files']:
                return self.send(201, NMAP.upload(parts[2], data))
            if len(parts) == 4 and parts[3] == 'nmap':
                with LOCK:
                    if JOB['running'] or HAKRAWLER.running or web_scans_busy():
                        return self.send(409, {'error': 'Wait for the current system operation to finish.'})
                    return self.send(202, NMAP.start(parts[2], data))
            if len(parts) == 7 and parts[3:5] == ['nmap', 'history'] and parts[6] == 'delete':
                return self.send(200, NMAP.delete(parts[2], parts[5]))
            if len(parts) == 5 and parts[3:] == ['nmap', 'cancel']:
                return self.send(200, NMAP.cancel(parts[2]))
            if len(parts) == 3:
                return self.send(200, PROJECTS.save(data, parts[2]))
            if len(parts) == 4 and parts[3] == 'status':
                return self.send(200, PROJECTS.set_status(parts[2], data))
            if len(parts) == 4 and parts[3] == 'notes':
                return self.send(200, PROJECTS.notes(parts[2], data))
            if len(parts) == 4 and parts[3] == 'documents':
                return self.send(201, PROJECTS.document(parts[2], data))
            return self.send(404, {'error': 'Not found'})
        except DuplicateProjectError as exc:
            self.send(409, {'error': str(exc), 'duplicates': exc.projects})
        except FileNotFoundError as exc:
            self.send(404, {'error': str(exc)})
        except (ValueError, TypeError, AttributeError) as exc:
            self.send(400, {'error': str(exc)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', choices=['127.0.0.1', 'localhost'])
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    with ThreadingHTTPServer((args.host, args.port), Handler) as server:
        url = f'http://127.0.0.1:{server.server_port}'
        print(f'Startscreen: {url} — Ctrl+C to stop.', flush=True)
        if not args.no_browser:
            timer = threading.Timer(0.3, webbrowser.open, args=(url,))
            timer.daemon = True
            timer.start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nApp stopped.')


if __name__ == '__main__':
    main()
