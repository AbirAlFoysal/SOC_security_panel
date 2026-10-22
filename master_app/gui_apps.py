"""Launch an allowlisted desktop tool in the current user's desktop session."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import threading

GUI_TOOLS = {'wireshark': 'Wireshark', 'burpsuite': 'Burp Suite'}


def locate_gui(tool):
    if tool not in GUI_TOOLS:
        return None
    names = ['wireshark'] if tool == 'wireshark' else ['burpsuite', 'BurpSuiteCommunity', 'BurpSuiteProfessional', 'BurpSuitePro']
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    candidates = []
    if tool == 'burpsuite':
        for base in [Path('/opt'), Path.home(), Path.home()/'.local/share', Path('/usr/local')]:
            for edition in ['BurpSuiteCommunity', 'BurpSuiteProfessional', 'BurpSuitePro']:
                candidates.append(base/edition/edition)
    if os.name == 'nt':
        for base in [os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)'), os.environ.get('LOCALAPPDATA')]:
            if not base:
                continue
            if tool == 'wireshark':
                candidates.append(Path(base)/'Wireshark/wireshark.exe')
            else:
                for edition in ['BurpSuiteCommunity', 'BurpSuiteProfessional', 'BurpSuitePro']:
                    candidates.append(Path(base)/edition/(edition+'.exe'))
    return next((str(path) for path in candidates if path.is_file() and os.access(path, os.X_OK)), None)


class DesktopLauncher:
    def __init__(self, directory, locate=locate_gui):
        self.directory = Path(directory)
        self.locate = locate
        self.lock = threading.Lock()
        self.processes = {}

    def open(self, tool):
        if tool not in GUI_TOOLS:
            raise ValueError('Unknown desktop application.')
        binary = self.locate(tool)
        name = GUI_TOOLS[tool]
        if not binary:
            raise ValueError(f'{name} is not installed. Install it from the startscreen tool menu or its official installer.')
        if platform.system() == 'Linux' and not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            raise ValueError('No graphical desktop session is available. Start the app from your desktop terminal and retry.')
        with self.lock:
            previous = self.processes.get(tool)
            if previous is not None and previous.poll() is None:
                return {'message': f'{name} is already open. Switch to its desktop window.'}
            self.directory.mkdir(parents=True, exist_ok=True)
            log = self.directory/(tool+'.log')
            with log.open('wb') as output:
                try:
                    process = subprocess.Popen([binary], stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                               start_new_session=os.name != 'nt')
                except OSError as exc:
                    raise ValueError(f'{name} could not start: {exc}') from exc
            self.processes[tool] = process
            try:
                code = process.wait(timeout=.6)
            except subprocess.TimeoutExpired:
                code = None
            if code not in (None, 0):
                with log.open('rb') as output:
                    output.seek(0, 2);size=output.tell();output.seek(max(0,size-2000))
                    detail=output.read().decode('utf-8', errors='replace').strip()
                raise ValueError(f'{name} could not start (exit {code}). '+(detail or 'Check the desktop session and application installation.'))
            return {'message': f'Opening {name} on your desktop.'}
