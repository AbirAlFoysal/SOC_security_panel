"""Read live local network state without changing the network."""
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
PUBLIC_STATE = Path('/run/desktop-anon-status.json')
MAC_PATTERN = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'


def find(name):
    path = shutil.which(name)
    if path:
        return path
    for directory in ('/usr/sbin', '/sbin', str(Path.home() / '.local/bin')):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def read_command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5,
                                env={**os.environ, 'LC_ALL': 'C'})
        return result.stdout.strip(), result.returncode, result.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return '', -1, str(exc)


def managed_interface():
    try:
        if PUBLIC_STATE.stat().st_uid == 0 and not PUBLIC_STATE.is_symlink():
            iface = json.loads(PUBLIC_STATE.read_text())['iface']
            if isinstance(iface, str) and re.fullmatch(r'[a-zA-Z0-9_.:-]+', iface):
                return iface
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def default_interface():
    ip = find('ip')
    if not ip:
        return None
    output, code, _ = read_command([ip, '-j', 'route', 'show', 'default'])
    try:
        routes = json.loads(output) if code == 0 else []
        iface = min(routes, key=lambda r: r.get('metric', 0))['dev'] if routes else None
        return iface if iface and re.fullmatch(r'[a-zA-Z0-9_.:-]+', iface) else None
    except (ValueError, KeyError, TypeError):
        return None


def status():
    linux = platform.system() == 'Linux'
    anon = find('anonsurf')
    mac = find('macchanger')
    anonsurf = {'installed': bool(anon), 'state': 'unknown' if anon else 'not-installed', 'tor': None, 'dns': None, 'error': None}
    if anon and linux:
        output, code, error = read_command([anon, 'status', '--json'])
        try:
            info = json.loads(output)
            active = info.get('anonsurf_active')
            if not isinstance(active, bool):
                raise ValueError('Installed AnonSurf did not report routing status.')
            anonsurf.update(state='active' if active else 'inactive', tor=info.get('tor_active'), dns=info.get('dns_state'))
        except (ValueError, TypeError, AttributeError):
            anonsurf['error'] = error or 'Unable to read AnonSurf JSON status.'
    elif anon:
        anonsurf['error'] = 'Network controls currently require Linux.'
    managed = managed_interface() if linux else None
    iface = managed or (default_interface() if linux else None)
    current = permanent = None
    error = None
    if iface:
        try:
            current = (Path('/sys/class/net') / iface / 'address').read_text().strip().lower()
        except OSError:
            pass
        if mac:
            output, code, stderr = read_command([mac, '--show', iface])
            if code == 0:
                match = re.search(r'Current MAC:\s*' + MAC_PATTERN, output)
                if match:
                    current = match[1].lower()
                match = re.search(r'Permanent MAC:\s*' + MAC_PATTERN, output)
                if match:
                    permanent = match[1].lower()
            else:
                error = stderr or 'Unable to read MAC address.'
    reason = None
    if not linux:
        reason = 'Network controls currently require Linux.'
    elif not mac:
        reason = 'MAC changer is not installed.'
    elif not iface:
        reason = 'No active default network interface found.'
    elif not all(find(p) for p in ('nmcli', 'ip', 'systemctl')):
        reason = 'MAC controls require NetworkManager, iproute2, and systemd.'
    elif not managed:
        kind, code, _ = read_command([find('nmcli'), '-g', 'GENERAL.TYPE', 'device', 'show', iface])
        if code or kind not in ('wifi', 'ethernet'):
            reason = 'The active interface must be managed by NetworkManager (Wi-Fi or Ethernet).'
    if not mac:
        macstate = 'not-installed'
    elif managed:
        macstate = 'managed'
    elif current and permanent:
        macstate = 'changed' if current != permanent else 'original'
    else:
        macstate = 'unknown'
    return {'anonsurf': anonsurf, 'macchanger': {'installed': bool(mac), 'state': macstate,
            'interface': iface, 'current': current, 'permanent': permanent, 'managed': bool(managed),
            'reason': reason, 'error': error}, 'system': platform.system()}


def command(tool, action, current):
    if platform.system() != 'Linux':
        raise ValueError('These network controls currently require Linux.')
    if tool not in ('anonsurf', 'macchanger') or action not in ('start', 'stop'):
        raise ValueError('Unknown network action.')
    binary = find(tool)
    if not binary:
        raise ValueError(f'{tool} is not installed.')
    if tool == 'anonsurf':
        if action == 'start' and current['anonsurf']['state'] == 'active':
            raise ValueError('AnonSurf is already active.')
        return [binary, action]
    mac = current['macchanger']
    if mac['reason']:
        raise ValueError(mac['reason'])
    if current['anonsurf']['state'] == 'active':
        raise ValueError('Stop AnonSurf before changing or restoring the MAC address.')
    if action == 'start' and mac['managed']:
        raise ValueError('A saved MAC session exists. Restore it before starting another.')
    if action == 'stop' and not mac['managed']:
        raise ValueError('No MAC session saved by this app to restore.')
    return ['/usr/bin/python3', str(ROOT.parent / 'anon-control.py'), 'mac-start' if action == 'start' else 'mac-stop', mac['interface']]
