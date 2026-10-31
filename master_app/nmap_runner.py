"""Run project-scoped Nmap scans and save their results locally."""
from pathlib import Path
from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import json
import base64
import binascii
import shlex
import os
import shutil
import re
import subprocess
import threading
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from nmap_options import OPTIONS, BY_FLAG, parse_command

PROFILES = {
    'regular': {'name': 'Regular scan', 'args': ['-sT']},
    'quick': {'name': 'Quick scan', 'args': ['-sT', '-F']},
    'service': {'name': 'Service detection', 'args': ['-sT', '-sV']},
    'full': {'name': 'All TCP ports', 'args': ['-sT', '-p-']},
    'discovery': {'name': 'Host discovery', 'args': ['-sn']},
}


def target(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Enter a target IP or host name.')
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if '://' in value:
        value = urlsplit(value).hostname or ''
    value = value.rstrip('.')
    if len(value) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in value.split('.')):
        raise ValueError('Enter one valid IP or host name, without command options.')
    return value.lower()


def arguments(data):
    host = target(data.get('target', ''))
    profile = data.get('profile', 'regular')
    if profile not in PROFILES:
        raise ValueError('Unknown scan profile.')
    args = list(PROFILES[profile]['args'])
    ports = data.get('ports', '')
    if not isinstance(ports, str) or len(ports) > 300:
        raise ValueError('Invalid ports.')
    ports = ports.strip()
    if ports:
        if profile == 'discovery':
            raise ValueError('Host discovery does not scan ports.')
        for part in ports.split(','):
            if not re.fullmatch(r'[0-9]{1,5}(?:-[0-9]{1,5})?', part):
                raise ValueError('Use ports like 22,80,443 or 1-1024.')
            bounds = [int(p) for p in part.split('-')]
            if not all(1 <= p <= 65535 for p in bounds) or bounds[0] > bounds[-1]:
                raise ValueError('Port numbers must be 1–65535, with ascending ranges.')
        args = [a for a in args if a != '-F' and a != '-p-'] + ['-p', ports]
    if data.get('skip_discovery') is True:
        if profile == 'discovery':
            raise ValueError('Host discovery cannot be skipped in the discovery profile.')
        args += ['-Pn']
    if ':' in host:
        args += ['-6']
    return host, profile, args + ['--reason', '-v', host]


def parse_xml(path):
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    hosts = []
    for node in root.findall('host'):
        state = node.find('status')
        addresses = [a.get('addr', '') for a in node.findall('address')]
        names = [a.get('name', '') for a in node.findall('hostnames/hostname')]
        ports = []
        for port in node.findall('ports/port'):
            status = port.find('state'); service = port.find('service')
            ports.append({'port': port.get('portid'), 'protocol': port.get('protocol'),
                          'state': status.get('state', 'unknown') if status is not None else 'unknown',
                          'reason': status.get('reason', '') if status is not None else '',
                          'service': service.get('name', '') if service is not None else '',
                          'version': ' '.join(service.get(k, '') for k in ('product', 'version', 'extrainfo')).strip() if service is not None else ''})
        hosts.append({'addresses': addresses, 'names': names, 'state': state.get('state', 'unknown') if state is not None else 'unknown', 'ports': ports})
    return hosts


class NmapRunner:
    tool = 'nmap'
    profiles = PROFILES
    options = OPTIONS
    validate_command = staticmethod(parse_command)
    def __init__(self, store, locate):
        self.store, self.locate = store, locate
        self.lock = threading.RLock()
        self.current = None
        self.process = None
        self.cancelled = False
        self._finishing = False
        self.stop_file = None

    @property
    def running(self):
        with self.lock:
            return self._finishing

    def status(self, ident):
        project = self.store.get(ident)
        with self.lock:
            current = deepcopy(self.current) if self.current and self.current['project_id'] == ident else None
            return {'current': current, 'history': project.get('tool_history', {}).get(self.tool, []),
                    'busy': self.running, 'installed': bool(self.locate(self.tool)), 'profiles': self.profiles, 'options': self.options, 'presets': self.presets()}

    def presets(self):
        with self.store.lock:
            path = self.store.root / (self.tool + '-presets.json')
            return json.loads(path.read_text(encoding='utf-8')) if path.exists() else []

    def save_preset(self, data):
        name = data.get('name', '')
        command = data.get('command', '')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ValueError('Give the preset a name (up to 80 characters).')
        self.validate_command(command.replace('{target}', '127.0.0.1'))
        with self.store.lock:
            presets = self.presets()
            if name.strip().casefold() in [p['name'].casefold() for p in presets] or name.strip().casefold() in [p['name'].casefold() for p in self.profiles.values()]:
                raise ValueError('A preset with this name already exists. Choose another name.')
            preset = {'id': uuid.uuid4().hex, 'name': name.strip(), 'command': command}
            presets.append(preset)
            self.store._write(self.store.root / (self.tool + '-presets.json'), presets)
            return preset

    def upload(self, ident, data):
        self.store.get(ident)
        files = data.get('files')
        if not isinstance(files, list) or not 1 <= len(files) <= 200:
            raise ValueError('Choose between 1 and 200 files (4 MB total).')
        decoded = []
        total = 0
        for item in files:
            name = item.get('path', '')
            parts = name.replace('\\', '/').split('/') if isinstance(name, str) else []
            if not parts or any(p in ('', '.', '..') or ':' in p or any(ord(c) < 32 for c in p) for p in parts) or len(name) > 500:
                raise ValueError('Invalid upload path.')
            try:
                raw = base64.b64decode(item.get('content', ''), validate=True)
            except (ValueError, TypeError, binascii.Error):
                raise ValueError('Invalid file content.')
            total += len(raw)
            if total > 4 * 1024 * 1024:
                raise ValueError('Uploaded files must total 4 MB or less. For larger datasets, enter an existing server directory.')
            decoded.append((parts, raw))
        directory = self.store._directory(ident) / (self.tool + '-inputs') / uuid.uuid4().hex
        for parts, raw in decoded:
            destination = directory.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        if data.get('directory'):
            roots = {parts[0] for parts, _ in decoded}
            selected = directory / next(iter(roots)) if len(roots) == 1 and all(len(parts) > 1 for parts, _ in decoded) else directory
        else:
            selected = directory.joinpath(*decoded[0][0])
        return {'path': str(selected.resolve()), 'files': len(decoded)}

    def _outputs(self, args, directory, scanid, xml):
        # All generated output is confined to this scan's project directory.
        result = []; i = 0; has_xml = False
        while i < len(args):
            flag = args[i]
            if flag in ('-oN', '-oX', '-oS', '-oG', '-oA'):
                name = args[i+1].replace('\\', '/').split('/')[-1]
                name = re.sub(r'[^a-zA-Z0-9_.-]', '_', name).strip('.') or 'output'
                destination = directory / (scanid + '-' + name)
                if flag == '-oX':
                    destination = xml; has_xml = True
                elif flag == '-oA':
                    xml = directory / (destination.name + '.xml'); has_xml = True
                result += [flag, str(destination)]; i += 2
            else:
                result.append(flag); i += 1
        if not has_xml:
            result += ['-oX', str(xml)]
        return result, xml

    def start(self, ident, data):
        if data.get('command') is not None:
            args, targets, admin = parse_command(data['command'])
            host = ', '.join(targets) or 'Targets from file / utility command'
            profile = str(data.get('profile', 'custom'))[:100]
        else:
            host, profile, args = arguments(data)
            admin = False
        binary = self.locate('nmap')
        if not binary:
            raise ValueError('Nmap is not installed. Install it from the startscreen.')
        self.store.get(ident)
        with self.lock:
            if self.running:
                raise ValueError('A scan is already running. Stop it or wait until it finishes.')
            scanid = uuid.uuid4().hex
            directory = self.store._directory(ident) / 'scans' / 'nmap'
            directory.mkdir(parents=True, exist_ok=True)
            xml = directory / (scanid + '.xml')
            command_text = shlex.join(['nmap'] + args)
            if '--resume' in args:
                # Resume files embed a command. Rewrite its output destinations before Nmap reads it.
                source = Path(args[args.index('--resume') + 1])
                content = source.read_text(encoding='utf-8')
                lines = content.splitlines(keepends=True)
                header = next((i for i,line in enumerate(lines[:10]) if ' as: ' in line), None)
                if header is None:
                    raise ValueError('Choose compatible normal or grepable Nmap output containing its original command header.')
                recovered, recovered_targets, raw = parse_command(lines[header].split(' as: ', 1)[1].strip())
                if '--resume' in recovered:
                    raise ValueError('Nested resume commands are not supported.')
                resumed, xml = self._outputs(recovered, directory, scanid, xml)
                lines[header] = lines[header].split(' as: ', 1)[0] + ' as: ' + shlex.join(['nmap'] + resumed) + '\n'
                resume_file = directory / (scanid + '-resume.nmap')
                resume_file.write_text(''.join(lines), encoding='utf-8')
                cmd = [binary, '--resume', str(resume_file)]
                admin = admin or raw
                host = ', '.join(recovered_targets) or 'Resumed scan'
            else:
                actual, xml = self._outputs(args, directory, scanid, xml)
                cmd = [binary] + actual
            self.stop_file = directory / (scanid + '.stop')
            if admin and hasattr(os, 'geteuid') and os.geteuid() != 0:
                cmd = ['/usr/bin/python3', str(Path(__file__).parent / 'nmap_privileged.py'), '--stop-file', str(self.stop_file), '--command', json.dumps(cmd)]
                if shutil.which('pkexec'):
                    cmd = ['pkexec'] + cmd
                else:
                    cmd = ['sudo', '-n'] + cmd
            self.current = {'id': scanid, 'project_id': ident, 'target': host, 'profile': profile,
                            'command': command_text, 'admin': admin, 'created_at': datetime.now(timezone.utc).isoformat(),
                            'status': 'running', 'output': '', 'hosts': [], 'error': None}
            self.current = self.store.save_scan(ident, deepcopy(self.current))
            self.cancelled = False
            self._finishing = True
            self.process = None
            threading.Thread(target=self._run, args=(cmd, xml, directory / (scanid + '.txt')), daemon=True).start()
            return deepcopy(self.current)

    def delete(self, ident, scanid):
        with self.lock:
            if self.running and self.current['id'] == scanid and self.current['project_id'] == ident:
                raise ValueError('Stop this scan before deleting it.')
            project = self.store.delete_scan(ident, scanid, self.tool)
            if self.current and self.current['id'] == scanid and self.current['project_id'] == ident:
                self.current = None
            return project

    def cancel(self, ident):
        with self.lock:
            if self.running:
                if self.current and self.current.get('project_id') == ident:
                    self.cancelled = True
                    if self.current.get('admin') and self.stop_file:
                        self.stop_file.touch()
                    elif self.process:
                        self.process.terminate()
                    return {'message': 'Stopping scan…'}
                raise ValueError('No running scan in this project.')
            project = self.store.get(ident)
            entries = project.get('tool_history', {}).get(self.tool, [])
            changed = False
            for entry in entries:
                if entry.get('status') == 'running':
                    entry['status'] = 'cancelled'
                    changed = True
            if changed:
                self.store._write(self.store._directory(ident) / 'project.json', project)
                return {'message': 'Scan stopped.'}
            raise ValueError('No running scan in this project.')

    def _run(self, cmd, xml, output):
        timer = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    errors='replace', stdin=subprocess.DEVNULL)
            with self.lock:
                self.process = proc
                if self.cancelled:
                    if self.current.get('admin') and self.stop_file:
                        self.stop_file.touch()
                    else:
                        proc.terminate()
            timer = threading.Timer(1830 if self.current.get('admin') else 1800, proc.kill)
            timer.start()
            with output.open('w', encoding='utf-8') as file:
                for line in proc.stdout:
                    file.write(line); file.flush()
                    with self.lock:
                        self.current['output'] = (self.current['output'] + line)[-262144:]
            code = proc.wait()
            hosts = parse_xml(xml)
            with self.lock:
                self.current.update(status='cancelled' if self.cancelled else 'completed' if code == 0 else 'failed', hosts=hosts,
                                    exit_code=code, finished_at=datetime.now(timezone.utc).isoformat())
                if code and not self.cancelled:
                    self.current['error'] = f'Nmap exited with code {code}. See Nmap output.'
        except Exception as exc:
            with self.lock:
                self.current.update(status='failed', error=str(exc), finished_at=datetime.now(timezone.utc).isoformat())
        finally:
            if timer:
                timer.cancel()
            with self.lock:
                record = deepcopy(self.current)
                try:
                    self.store.save_scan(record['project_id'], record)
                except Exception as exc:
                    self.current['error'] = f'Result could not be saved: {exc}'
                if self.process and self.process.stdout:
                    self.process.stdout.close()
                self.process = None
                self._finishing = False
