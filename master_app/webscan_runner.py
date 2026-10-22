"""SQLmap and Nikto workspaces, using argument arrays rather than a shell.

Catalog sources: sqlmapproject/sqlmap lib/parse/cmdline.py and
sullo/nikto wiki/Annotated-Option-List, retrieved 2026-10-23.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import signal
import shutil
import subprocess
import threading
import uuid
from urllib.parse import urlsplit
from nmap_runner import NmapRunner

CATALOG = json.loads(Path(__file__).with_name('webscan_options.json').read_text())
PROFILES = {
    'sqlmap': {
        'regular': {'name': 'Standard detection', 'args': ['--batch', '--level', '1', '--risk', '1']},
        'forms': {'name': 'Detect forms', 'args': ['--batch', '--forms', '--level', '1', '--risk', '1']},
        'post': {'name': 'POST parameter test', 'args': ['--batch', '--data', 'id=1', '--level', '1', '--risk', '1']},
        'fingerprint': {'name': 'DBMS fingerprint', 'args': ['--batch', '--fingerprint', '--level', '1', '--risk', '1']},
    },
    'nikto': {
        'regular': {'name': 'Standard web scan', 'args': ['-nointeractive', '-nocheck', '-ask', 'no']},
        'information': {'name': 'Information disclosure', 'args': ['-nointeractive', '-nocheck', '-ask', 'no', '-Tuning', '3']},
        'configuration': {'name': 'Configuration checks', 'args': ['-nointeractive', '-nocheck', '-ask', 'no', '-Tuning', '2']},
        'identification': {'name': 'Software identification', 'args': ['-nointeractive', '-nocheck', '-ask', 'no', '-Tuning', 'b']},
    },
}


def parse_command(tool, command):
    if not isinstance(command, str) or len(command) > 16000 or '\x00' in command:
        raise ValueError('Command must be text up to 16,000 characters.')
    tokens = shlex.split(command)
    if not tokens or tokens.pop(0) not in (tool, tool + '.exe'):
        raise ValueError(f'The command must begin with {tool}.')
    lookup = {alias.lower() if tool == 'nikto' else alias: o for o in CATALOG[tool] for alias in o['aliases']}
    result = []
    i = 0
    while i < len(tokens):
        flag, separator, value = tokens[i].partition('=')
        key = flag.lower() if tool == 'nikto' else flag
        option = lookup.get(key)
        if not option:
            raise ValueError(f'Unknown {tool} option: {flag}. Use the parameter list for supported spelling.')
        flag = option['flag']
        if option['kind'] == 'flag':
            if separator:
                raise ValueError(f'{flag} does not take a value.')
            result.append(flag)
        else:
            optional = option['kind'] == 'optional-value'
            if not separator:
                next_key = tokens[i + 1].split('=', 1)[0] if i + 1 < len(tokens) else ''
                if tool == 'nikto':
                    next_key = next_key.lower()
                if not optional and next_key in lookup:
                    raise ValueError(f'{flag} requires a value, not another option.')
                if i + 1 < len(tokens) and (not optional or not tokens[i + 1].startswith('-')):
                    i += 1
                    value = tokens[i]
                elif not optional:
                    raise ValueError(f'{flag} requires a value.')
            if not value and not optional:
                raise ValueError(f'{flag} requires a value.')
            result.append(flag)
            if value:
                # Nikto treats leading '-' values as new switches.
                if value.startswith('-') and tool == 'nikto':
                    raise ValueError(f'{flag} requires a value, not another option.')
                result.append(value)
        i += 1
    if tool == 'sqlmap':
        # These launch terminal/GUI sessions instead of producing a finite scan.
        interactive = {'--sql-shell', '--os-shell', '--shell', '--gui', '--tui', '--wizard'}
        if interactive.intersection(result):
            raise ValueError('Interactive shells and GUI modes require a terminal. Use a scan option in this workspace.')
    return result


def web_target(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 8000:
        raise ValueError('Enter a target HTTP or HTTPS URL.')
    value = value.strip()
    if '://' not in value:
        value = 'http://' + value
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError('Enter a valid HTTP or HTTPS URL, including its path and query parameters.')
    try:
        parsed.port
    except ValueError:
        raise ValueError('Enter a valid URL port.')
    return value


class WebScanRunner(NmapRunner):
    def __init__(self, store, locate, tool):
        super().__init__(store, locate)
        self.tool = tool
        self.profiles = PROFILES[tool]
        self.options = CATALOG[tool]
        self.validate_command = lambda command: parse_command(tool, command)

    def _prepare(self, args, directory, scanid):
        """Keep generated reports, sessions and caches inside this project."""
        lookup = {o['flag']: o for o in self.options}
        actual = []
        i = 0
        while i < len(args):
            flag = args[i]
            option = lookup[flag]
            actual.append(flag)
            i += 1
            takes_value = option['kind'] != 'flag' and i < len(args) and (option['kind'] != 'optional-value' or not args[i].startswith('-'))
            if takes_value:
                value = args[i]
                if self.tool == 'sqlmap' and flag == '-s':
                    destination = directory / (scanid + '-session.sqlite')
                    shutil.copyfile(value, destination)
                    value = str(destination.resolve())
                if option['kind'] in ('output', 'output-directory'):
                    name = re.sub(r'[^a-zA-Z0-9_.-]', '_', value.replace('\\', '/').split('/')[-1]).strip('.') or 'output'
                    path = directory / (scanid + '-' + name)
                    if option['kind'] == 'output-directory':
                        path.mkdir(exist_ok=True)
                    value = str(path.resolve())
                actual.append(value)
                i += 1
        if self.tool == 'sqlmap':
            if '--batch' not in actual:
                actual.append('--batch')
            if '--disable-coloring' not in actual:
                actual.append('--disable-coloring')
            if '--output-dir' not in actual:
                destination = directory / (scanid + '-output')
                destination.mkdir(exist_ok=True)
                actual += ['--output-dir', str(destination.resolve())]
            if '--tmp-dir' not in actual:
                destination = directory / (scanid + '-tmp')
                destination.mkdir(exist_ok=True)
                actual += ['--tmp-dir', str(destination.resolve())]
        else:
            for flag in ('-nointeractive', '-nocheck'):
                if flag not in actual:
                    actual.append(flag)
            if '-ask' not in actual:
                actual += ['-ask', 'no']
        return actual

    def start(self, ident, data):
        args = parse_command(self.tool, data.get('command', ''))
        target_flag = '--url' if self.tool == 'sqlmap' else '-host'
        if self.tool == 'nikto':
            # Nikto's URL alias has the same semantics as -host.
            args = [target_flag if a == '-url' else a for a in args]
        sources = {'--url', '-r', '-m', '-l', '-d', '-g', '--dork', '-c', '--openapi'} if self.tool == 'sqlmap' else {'-host'}
        source_flags = sources.intersection(args)
        utility = {'-h', '-hh', '--hh', '--help', '--version', '--list-tampers'} if self.tool == 'sqlmap' else {'-Help', '-Version', '-list-plugins', '-dbcheck'}
        if not source_flags and not utility.intersection(args):
            args += [target_flag, web_target(data.get('target', ''))]
        if args.count(target_flag) > 1:
            raise ValueError('Use one target URL option per scan, or a target list file.')
        if target_flag in args:
            position = args.index(target_flag) + 1
            value = args[position]
            if not (self.tool == 'nikto' and Path(value).is_file()):
                args[position] = web_target(value)
            target = args[position]
        else:
            source = next((f for f in args if f in sources), None)
            target = args[args.index(source) + 1] if source else 'Utility command'
        binary = self.locate(self.tool)
        if not binary:
            raise ValueError(f'{self.tool} is not installed. Install it from the startscreen.')
        self.store.get(ident)
        with self.lock:
            if self.running:
                raise ValueError('A scan is already running. Stop it or wait for completion.')
            scanid = uuid.uuid4().hex
            directory = self.store._directory(ident) / 'scans' / self.tool
            directory.mkdir(parents=True, exist_ok=True)
            actual = self._prepare(args, directory, scanid)
            self.current = {'id': scanid, 'project_id': ident, 'target': target, 'profile': str(data.get('profile', 'custom'))[:100],
                            'command': shlex.join([self.tool] + args), 'executed_command': shlex.join([self.tool] + actual),
                            'created_at': datetime.now(timezone.utc).isoformat(), 'status': 'running', 'output': '', 'error': None, 'admin': False}
            self.current = self.store.save_scan(ident, deepcopy(self.current), self.tool)
            self.cancelled = False
            self.process = None
            self._finishing = True
            threading.Thread(target=self._run_web, args=([binary] + actual, directory / (scanid + '.txt')), daemon=True).start()
            return deepcopy(self.current)

    def _signal(self, kill=False):
        proc = self.process
        if proc and proc.poll() is None:
            try:
                if os.name == 'posix':
                    os.killpg(proc.pid, signal.SIGKILL if kill else signal.SIGTERM)
                elif kill:
                    proc.kill()
                else:
                    proc.terminate()
            except ProcessLookupError:
                pass

    def cancel(self, ident):
        with self.lock:
            if not self.running or self.current['project_id'] != ident:
                raise ValueError('No running scan in this project.')
            self.cancelled = True
            self._signal()
            escalation = threading.Timer(3, self._force_cancel, args=(self.current['id'],))
            escalation.daemon = True
            escalation.start()
            return {'message': 'Stopping scan…'}

    def _force_cancel(self, scanid):
        with self.lock:
            if self.current and self.current['id'] == scanid and self.cancelled:
                self._signal(kill=True)

    def _run_web(self, command, output):
        timer = None
        timed_out = threading.Event()
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    text=True, errors='replace', start_new_session=os.name == 'posix', bufsize=1,
                                    env={**os.environ, 'PYTHONUNBUFFERED': '1'})
            with self.lock:
                self.process = proc
                if self.cancelled:
                    self._signal()
            def timeout():
                with self.lock:
                    timed_out.set()
                    self._signal(kill=True)
            timer = threading.Timer(1800, timeout)
            timer.start()
            with output.open('w', encoding='utf-8') as file:
                for line in proc.stdout:
                    file.write(line)
                    file.flush()
                    with self.lock:
                        self.current['output'] = (self.current['output'] + line)[-262144:]
            code = proc.wait()
            with self.lock:
                status = 'cancelled' if self.cancelled else 'failed' if timed_out.is_set() or code else 'completed'
                self.current.update(status=status, exit_code=code, finished_at=datetime.now(timezone.utc).isoformat())
                if timed_out.is_set():
                    self.current['error'] = 'Scan stopped after the 30-minute time limit. Partial output was saved.'
                elif code and not self.cancelled:
                    self.current['error'] = f'{self.tool} exited with code {code}. See output.'
        except Exception as exc:
            with self.lock:
                self.current.update(status='failed', error=str(exc), finished_at=datetime.now(timezone.utc).isoformat())
        finally:
            if timer:
                timer.cancel()
            with self.lock:
                self._signal(kill=True)
                if self.process:
                    self.process.wait()
                    if self.process.stdout:
                        self.process.stdout.close()
                try:
                    self.store.save_scan(self.current['project_id'], deepcopy(self.current), self.tool)
                except Exception as exc:
                    self.current['error'] = f'Unable to save scan: {exc}'
                self.process = None
                self._finishing = False
