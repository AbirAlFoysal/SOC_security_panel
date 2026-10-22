"""Project data stays under the repository's projects/ directory."""
import base64
import binascii
from datetime import datetime, timezone
import json
import ipaddress
from urllib.parse import urlsplit
from pathlib import Path
import re
import threading
import shutil
import uuid

DEFAULT_STATUSES = ['test', 'Planned', 'In progress', 'On hold', 'Completed']


class DuplicateProjectError(ValueError):
    def __init__(self, projects):
        super().__init__('This IP or domain already exists. Make a copy or continue an existing project.')
        self.projects = projects


def target_key(value):
    value = value.strip()
    if not value:
        return ''
    try:
        return 'ip:' + str(ipaddress.ip_address(value))
    except ValueError:
        try:
            host = urlsplit(value if '://' in value else '//' + value).hostname
            if host:
                host = host.rstrip('.').casefold()
                try:
                    return 'ip:' + str(ipaddress.ip_address(host))
                except ValueError:
                    return 'host:' + host.encode('idna').decode('ascii')
        except (ValueError, UnicodeError):
            pass
        return 'host:' + value.rstrip('.').casefold()


class ProjectStore:
    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.RLock()

    def _write(self, path, value):
        if path.name == 'project.json':
            value = {k: v for k, v in value.items() if k not in ('saved_notes', 'selected_note_id', 'selected_document_id')}
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(path.name + '.tmp')
        temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        temp.replace(path)

    def _directory(self, ident):
        if not isinstance(ident, str) or not re.fullmatch(r'[0-9a-f]{32}', ident):
            raise ValueError('Invalid project ID')
        directory = self.root / ident
        if directory.is_symlink():
            raise ValueError('Invalid project directory')
        return directory

    def _text(self, data, key, limit):
        value = data.get(key, '')
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError(f'{key} must be text up to {limit} characters')
        return value.strip()

    def statuses(self):
        with self.lock:
            p = self.root / 'statuses.json'
            saved = json.loads(p.read_text(encoding='utf-8')) if p.exists() else list(DEFAULT_STATUSES)
            return ['test'] + [status for status in saved if status != 'test']

    def add_status(self, data):
        name = self._text(data, 'name', 60)
        if not name:
            raise ValueError('Enter a status name')
        with self.lock:
            statuses = self.statuses()
            if name.casefold() not in [s.casefold() for s in statuses]:
                statuses.append(name)
                self._write(self.root / 'statuses.json', statuses)
            return statuses

    def list(self):
        with self.lock:
            if not self.root.exists():
                return []
            rows = [json.loads(p.read_text(encoding='utf-8')) for p in self.root.glob('*/project.json') if not p.parent.is_symlink()]
            return sorted(rows, key=lambda p: p['updated_at'], reverse=True)

    def get(self, ident):
        with self.lock:
            directory = self._directory(ident)
            p = directory / 'project.json'
            if not p.is_file():
                raise FileNotFoundError('Project not found')
            data = json.loads(p.read_text(encoding='utf-8'))
            changed = False
            for records in data.get('tool_history', {}).values():
                used = set()
                for entry in reversed(records):
                    base = entry.get('command') or entry.get('target') or 'Saved run'
                    title = entry.get('title') or base
                    suffix = 1
                    while title in used:
                        title = f'{base} ({suffix})'
                        suffix += 1
                    used.add(title)
                    if entry.get('title') != title:
                        entry['title'] = title
                        changed = True
            if 'document_entries' not in data:
                data['document_entries'] = [{'id': d['id'], 'title': d['name'], 'text': '', 'attachments': [d['id']], 'updated_at': d['created_at']} for d in data.get('documents', [])]
                changed = True
            if changed:
                self._write(p, data)
            data['notes'] = (directory / 'notes.md').read_text(encoding='utf-8')
            collection = directory / 'notes.json'
            if not collection.exists():
                legacy = data['notes']
                entries = [{'id': uuid.uuid4().hex, 'title': 'Project notes', 'content': legacy, 'updated_at': data['updated_at']}] if legacy else []
                self._write(collection, entries)
            data['saved_notes'] = json.loads(collection.read_text(encoding='utf-8'))
            return data

    def create(self, data):
        with self.lock:
            choice = data.get('duplicate')
            if choice not in (None, 'copy'):
                raise ValueError('Invalid duplicate choice')
            targets = {target_key(self._text(data, key, limit)) for key, limit in [('host', 253), ('ip', 100)]} - {''}
            matches = [p for p in self.list() if targets & ({target_key(p.get('host', '')), target_key(p.get('ip', ''))} - {''})]
            if matches and choice != 'copy':
                raise DuplicateProjectError(matches)
            return self.save(data)

    def save(self, data, ident=None):
        with self.lock:
            current = self.get(ident) if ident else {}
            host = self._text(data, 'host', 253)
            ip = self._text(data, 'ip', 100)
            if not host and not ip:
                raise ValueError('Enter a host name or IP address')
            if ip:
                import ipaddress
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    raise ValueError('Enter a valid IPv4 or IPv6 address')
            status = self._text(data, 'status', 60) or current.get('status', 'test')
            if status not in self.statuses():
                raise ValueError('Create the custom status before using it')
            ident = ident or uuid.uuid4().hex
            now = datetime.now(timezone.utc).isoformat()
            result = {**current, 'id': ident, 'name': self._text(data, 'name', 140) or host or ip,
                      'host': host, 'ip': ip, 'others': self._text(data, 'others', 20000),
                      'status': status, 'created_at': current.get('created_at', now), 'updated_at': now,
                      'documents': current.get('documents', []), 'tool_history': current.get('tool_history', {})}
            result.pop('notes', None)
            directory = self._directory(ident)
            if not current:
                directory.mkdir(parents=True, exist_ok=True)
                (directory / 'notes.md').write_text('', encoding='utf-8')
                (directory / 'docs').mkdir(exist_ok=True)
            self._write(directory / 'project.json', result)
            return self.get(ident)

    def set_status(self, ident, data):
        status = self._text(data, 'status', 60)
        with self.lock:
            if status not in self.statuses():
                raise ValueError('Choose an existing project status')
            project = self.get(ident)
            project.pop('notes')
            project['status'] = status
            project['updated_at'] = datetime.now(timezone.utc).isoformat()
            self._write(self._directory(ident) / 'project.json', project)
            return self.get(ident)

    def notes(self, ident, data):
        action = data.get('action', 'save')
        if action not in ('save', 'rename', 'delete'):
            raise ValueError('Invalid note action')
        with self.lock:
            project = self.get(ident)
            directory = self._directory(ident)
            entries = project['saved_notes']
            note_id = data.get('id')
            entry = next((n for n in entries if n['id'] == note_id), None)
            if note_id and entry is None:
                raise FileNotFoundError('Note not found')
            if action != 'save' and entry is None:
                raise ValueError('Choose a saved note')
            now = datetime.now(timezone.utc).isoformat()
            if action == 'delete':
                entries.remove(entry)
            elif action == 'rename':
                title = self._text(data, 'title', 140)
                if not title:
                    raise ValueError('Enter a note name')
                entry.update(title=title, updated_at=now)
            else:
                content = data.get('notes')
                if not isinstance(content, str) or len(content) > 500000:
                    raise ValueError('Notes must be text up to 500,000 characters')
                title = self._text(data, 'title', 140) or 'Project notes'
                # Preserve compatibility with the original single-note API.
                if 'title' not in data and not note_id:
                    entry = next((n for n in entries if n['title'] == 'Project notes'), None)
                if entry is None:
                    entry = {'id': uuid.uuid4().hex}
                    entries.insert(0, entry)
                entry.update(title=title, content=content, updated_at=now)
            self._write(directory / 'notes.json', entries)
            # Keep the legacy file in sync, including after deletion.
            legacy = entries[0]['content'] if entries else ''
            temp = directory / 'notes.md.tmp'
            temp.write_text(legacy, encoding='utf-8')
            temp.replace(directory / 'notes.md')
            project.pop('notes')
            project['updated_at'] = now
            self._write(directory / 'project.json', project)
            result = self.get(ident)
            result['selected_note_id'] = entry['id'] if action != 'delete' else None
            return result

    def document(self, ident, data):
        if 'action' in data:
            return self.document_entry(ident, data)
        name = self._text(data, 'name', 255)
        if not name or '/' in name or '\\' in name or any(ord(c) < 32 for c in name):
            raise ValueError('Enter a valid document name')
        try:
            raw = base64.b64decode(data.get('content', ''), validate=True)
        except (ValueError, TypeError, binascii.Error):
            raise ValueError('Invalid document content')
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('Documents must be 4 MB or smaller')
        with self.lock:
            project = self.get(ident)
            doc = {'id': uuid.uuid4().hex, 'name': name, 'size': len(raw), 'created_at': datetime.now(timezone.utc).isoformat()}
            (self._directory(ident) / 'docs' / doc['id']).write_bytes(raw)
            project.pop('notes')
            project['documents'].append(doc)
            project['document_entries'].insert(0, {'id': uuid.uuid4().hex, 'title': name, 'text': '', 'attachments': [doc['id']], 'updated_at': doc['created_at']})
            project['updated_at'] = doc['created_at']
            self._write(self._directory(ident) / 'project.json', project)
            return self.get(ident)

    def document_entry(self, ident, data):
        action = data.get('action')
        if action not in ('save', 'rename', 'delete'):
            raise ValueError('Invalid document action')
        title = self._text(data, 'title', 140)
        text = data.get('text', '')
        if not isinstance(text, str) or len(text) > 500000:
            raise ValueError('Document text must be at most 500,000 characters')
        files = data.get('files', [])
        if not isinstance(files, list) or len(files) > 50:
            raise ValueError('Choose at most 50 files per save')
        decoded = []
        for item in files:
            if not isinstance(item, dict):
                raise ValueError('Invalid attachment')
            name = self._text(item, 'name', 255)
            if not name or '/' in name or '\\' in name or any(ord(c) < 32 for c in name):
                raise ValueError('Invalid attachment name')
            try:
                raw = base64.b64decode(item.get('content', ''), validate=True)
            except (ValueError, TypeError, binascii.Error):
                raise ValueError('Invalid attachment content')
            decoded.append((name, raw))
        if sum(len(raw) for _, raw in decoded) > 4 * 1024 * 1024:
            raise ValueError('New attachments must total 4 MB or smaller per save')
        with self.lock:
            project = self.get(ident)
            entries = project['document_entries']
            entry = next((e for e in entries if e['id'] == data.get('id')), None)
            if (data.get('id') or action != 'save') and entry is None:
                raise FileNotFoundError('Document not found')
            now = datetime.now(timezone.utc).isoformat()
            removed = []
            if action == 'delete':
                removed = list(entry['attachments'])
                entries.remove(entry)
                project['documents'] = [d for d in project['documents'] if d['id'] not in removed]
            elif action == 'rename':
                if not title:
                    raise ValueError('Enter a document name')
                entry.update(title=title, updated_at=now)
            else:
                if entry is None:
                    entry = {'id': uuid.uuid4().hex, 'attachments': []}
                    entries.insert(0, entry)
                for name, raw in decoded:
                    attachment = {'id': uuid.uuid4().hex, 'name': name, 'size': len(raw), 'created_at': now}
                    (self._directory(ident) / 'docs' / attachment['id']).write_bytes(raw)
                    project['documents'].append(attachment)
                    entry['attachments'].append(attachment['id'])
                entry.update(title=title or 'Untitled document', text=text, updated_at=now)
            project.pop('notes')
            project['updated_at'] = now
            self._write(self._directory(ident) / 'project.json', project)
            for docid in removed:
                (self._directory(ident) / 'docs' / docid).unlink(missing_ok=True)
            result = self.get(ident)
            result['selected_document_id'] = entry['id'] if action != 'delete' else None
            return result

    def save_scan(self, ident, record, tool="nmap"):
        with self.lock:
            project = self.get(ident)
            project.pop('notes')
            entries = project.setdefault('tool_history', {}).setdefault(tool, [])
            existing = next((entry for entry in entries if entry['id'] == record['id']), None)
            record = dict(record)
            if existing:
                record['title'] = existing['title']
            else:
                base = record.get('command') or record.get('target') or 'Nmap scan'
                used = {entry['title'] for entry in entries}
                title = base
                suffix = 1
                while title in used:
                    title = f'{base} ({suffix})'
                    suffix += 1
                record['title'] = title
            entries[:] = [entry for entry in entries if entry['id'] != record['id']]
            entries.insert(0, record)
            project['updated_at'] = datetime.now(timezone.utc).isoformat()
            self._write(self._directory(ident) / 'project.json', project)
            return record

    def delete_scan(self, ident, scanid, tool="nmap"):
        if not isinstance(scanid, str) or not re.fullmatch(r'[0-9a-f]{32}', scanid):
            raise ValueError('Invalid scan ID')
        with self.lock:
            project = self.get(ident)
            entries = project.get('tool_history', {}).get(tool, [])
            if not any(entry['id'] == scanid for entry in entries):
                raise FileNotFoundError('Scan not found in this project')
            directory = self._directory(ident) / 'scans' / tool
            if directory.exists():
                if not directory.resolve().is_relative_to(self._directory(ident).resolve()):
                    raise ValueError('Invalid scan directory')
                for file in directory.iterdir():
                    if file.name.startswith((scanid + '.', scanid + '-')):
                        if file.is_symlink() or file.is_file():
                            file.unlink()
                        elif file.is_dir():
                            shutil.rmtree(file)
            project['tool_history'][tool] = [entry for entry in entries if entry['id'] != scanid]
            project.pop('notes')
            project['updated_at'] = datetime.now(timezone.utc).isoformat()
            self._write(self._directory(ident) / 'project.json', project)
            return self.get(ident)

    def download(self, ident, docid):
        with self.lock:
            project = self.get(ident)
            doc = next((d for d in project['documents'] if d['id'] == docid), None)
            if not doc:
                raise FileNotFoundError('Document not found')
            return (self._directory(ident) / 'docs' / doc['id']).read_bytes()
