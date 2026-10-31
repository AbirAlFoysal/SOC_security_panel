"""Nuclei batch scanner backend — multi-worker scanning matching nuclei_scan.py.

Each batch is saved as a scan record in project history under tool='nuclei' with type='batch'.
Per-host logs are streamed and saved individually so the UI can switch between them.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from urllib.parse import urlparse

# ── defaults (mirror nuclei_scan.py) ───────────────────────────────────────────
DEFAULT_CONFIG = {
    'max_workers': 7,
    'nuclei_timeout': 900,
    'sigterm_grace': 10,
    'template_tags': 'cve,tech,panel,exposure,misconfiguration,default-login',
    'severity': 'critical,high,medium',
    'rate_limit': 15,
    'nuclei_c': 5,
    'nuclei_bs': 5,
    'max_host_error': 30,
    'stats_interval': 30,
    'state_file': '.progress.json',
    'state_save_every': 10,
    'large_scan_warn': 200,
    'clean_coverage_min': 70,
    'waf_error_rate': 0.10,
}

STATUS_LABELS = {
    'FINDINGS': 'findings',
    'FINDINGS_PARTIAL': 'findings (partial)',
    'NO_FINDINGS': 'clean',
    'INCOMPLETE_WAF': 'WAF/incomplete',
    'TIMEOUT': 'timeout',
    'ERROR': 'error',
}


# ── helpers ─────────────────────────────────────────────────────────────────────

def normalize_url(u):
    u = u.strip()
    if not u or u.startswith('#'):
        return None
    if not u.lower().startswith(('http://', 'https://')):
        u = 'https://' + u
    p = urlparse(u)
    return u if p.netloc else None


def safe_name(u, i):
    p = urlparse(u)
    b = (p.netloc or p.path).replace(':', '_').replace('/', '_')
    b = ''.join(c for c in b if c.isalnum() or c in ('-', '_', '.'))
    return f'{i:04d}_{b or "target"}'


def host_label(u):
    try:
        p = urlparse(u)
        return p.netloc or u
    except Exception:
        return u


def parse_coverage(log_path):
    pct = errors = done = total = 0
    gave_up = False
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if 'max-host-error' in line.lower() or 'giving up' in line.lower():
                    gave_up = True
                if 'Requests:' not in line or 'Errors:' not in line:
                    continue
                try:
                    errors = int(line.split('Errors:')[1].split('|')[0].strip())
                    req_part = line.split('Requests:')[1].strip()
                    frac, pct_part = req_part.split('(')
                    done_s, total_s = frac.strip().split('/')
                    done = int(done_s.strip())
                    total = int(total_s.strip())
                    pct = int(pct_part.split('%')[0].strip())
                except Exception:
                    continue
    except Exception:
        pass
    return pct, errors, done, total, gave_up


def classify(jsonl_path, log_path, timed_out, timeout, rc, cfg):
    jsonl_ok = Path(jsonl_path).exists() and Path(jsonl_path).stat().st_size > 0
    log_ok   = Path(log_path).exists() and Path(log_path).stat().st_size > 0
    pct = errs = done_req = 0
    gave_up = False
    if log_ok:
        pct, errs, done_req, _, gave_up = parse_coverage(log_path)
    clean_min = cfg['clean_coverage_min']
    waf_rate  = cfg['waf_error_rate']
    error_rate = (errs / done_req) if done_req > 0 else 0.0

    if jsonl_ok and timed_out:
        status = 'FINDINGS_PARTIAL'
        detail = f'partial findings (timeout) | {pct}% coverage, {errs} errs'
    elif jsonl_ok:
        status = 'FINDINGS'
        detail = f'{pct}% coverage'
    elif timed_out:
        status = 'TIMEOUT'
        detail = f'exceeded {timeout}s | {pct}% coverage, {errs} errs'
    elif not log_ok:
        status = 'ERROR'
        detail = 'no output produced'
    elif gave_up and pct < clean_min:
        status = 'INCOMPLETE_WAF'
        detail = f'aborted by max-host-error | {pct}% coverage, {errs} errs'
    elif pct < clean_min:
        status = 'INCOMPLETE_WAF'
        detail = f'{pct}% coverage, {errs} errs'
    elif error_rate >= waf_rate:
        status = 'INCOMPLETE_WAF'
        detail = f'{pct}% coverage but {int(error_rate*100)}% error rate'
    else:
        status = 'NO_FINDINGS'
        detail = f'{pct}% coverage, {errs} errs'

    if rc not in (0, None) and status not in ('FINDINGS', 'FINDINGS_PARTIAL'):
        detail += f' | exit={rc}'
    return status, detail, pct


def run_one(nuclei_bin, url, jsonl_path, log_path, cfg, runner=None):
    """Run nuclei on a single URL. Returns (status, detail, pct)."""
    if runner and runner.cancelled:
        return 'ERROR', 'cancelled by user', 0
    timeout = int(cfg.get('nuclei_timeout', 900))
    grace   = int(cfg.get('sigterm_grace', 10))
    cmd = [
        nuclei_bin, '-u', url,
        '-jsonl-export', jsonl_path,
        '-silent', '-nc', '-no-interactsh',
        '-timeout', '10', '-retries', '1',
        '-rate-limit', str(cfg.get('rate_limit', 15)),
        '-c', str(cfg.get('nuclei_c', 5)),
        '-bs', str(cfg.get('nuclei_bs', 5)),
        '-ss', 'host-spray',
        '-max-host-error', str(cfg.get('max_host_error', 30)),
        '-stats', '-stats-interval', str(cfg.get('stats_interval', 30)),
        '-duc',
    ]
    if cfg.get('template_tags'):
        cmd.extend(['-tags', str(cfg['template_tags'])])
    if cfg.get('severity'):
        cmd.extend(['-severity', str(cfg['severity'])])

    timed_out = False
    rc = None
    proc = None
    try:
        with open(log_path, 'wb') as lf:
            proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT,
                                    start_new_session=os.name == 'posix')
            if runner:
                with runner._proc_lock:
                    runner._active_procs.add(proc)
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    if os.name == 'posix':
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    else:
                        proc.terminate()
                except Exception:
                    pass
                try:
                    rc = proc.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    try:
                        if os.name == 'posix':
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        else:
                            proc.kill()
                    except Exception:
                        pass
                    try:
                        rc = proc.wait(timeout=5)
                    except Exception:
                        rc = -9
            finally:
                if runner and proc:
                    with runner._proc_lock:
                        runner._active_procs.discard(proc)
    except FileNotFoundError:
        return 'ERROR', 'nuclei binary not found', 0
    except Exception as e:
        return 'ERROR', f'{type(e).__name__}: {e}', 0

    if runner and runner.cancelled:
        return 'ERROR', 'cancelled by user', 0

    return classify(jsonl_path, log_path, timed_out, timeout, rc, cfg)


# ── NucleiBatchRunner ────────────────────────────────────────────────────────────

class NucleiBatchRunner:
    TOOL = 'nuclei'

    def __init__(self, store, locate):
        self.store  = store
        self.locate = locate
        self.lock   = threading.RLock()
        self.current   = None   # the active batch record
        self.cancelled = False
        self._finishing = False
        self._active_procs = set()
        self._proc_lock = threading.Lock()

    @property
    def running(self):
        with self.lock:
            return bool(self.current and self.current.get('status') == 'running') or self._finishing

    def _scan_dir(self, ident, batch_id):
        d = self.store._directory(ident) / 'scans' / 'nuclei' / batch_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _state_file(self, ident, batch_id):
        return self._scan_dir(ident, batch_id) / '.progress.json'

    def _load_state(self, ident, batch_id):
        sf = self._state_file(ident, batch_id)
        if sf.exists():
            try:
                return json.loads(sf.read_text(encoding='utf-8'))
            except Exception:
                pass
        return {'completed': {}, 'results': [], 'hosts': []}

    def _save_state(self, ident, batch_id, state):
        sf = self._state_file(ident, batch_id)
        tmp = sf.with_suffix('.tmp')
        with self.lock:
            if self.current and 'hosts' in self.current:
                state['hosts'] = deepcopy(self.current['hosts'])
                state['created_at'] = self.current.get('created_at', '')
                state['total'] = len(self.current.get('hosts', []))
        try:
            tmp.write_text(json.dumps(state, indent=2), encoding='utf-8')
            tmp.replace(sf)
        except Exception:
            pass

    def list_sessions(self, ident):
        """List all resumable batch sessions for this project."""
        base = self.store._directory(ident) / 'scans' / 'nuclei'
        if not base.exists():
            return []
        sessions = []
        for d in sorted(base.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            sf = d / '.progress.json'
            if not sf.exists():
                continue
            try:
                state = json.loads(sf.read_text(encoding='utf-8'))
                completed = state.get('completed', {})
                done = len(completed)
                total = state.get('total', len(state.get('hosts', [])) or done)
                sessions.append({
                    'id': d.name,
                    'done': done,
                    'total': total,
                    'created_at': state.get('created_at', ''),
                })
            except Exception:
                continue
        return sessions

    def status(self, ident):
        """Return current batch status for project."""
        project = self.store.get(ident)
        history = [r for r in project.get('tool_history', {}).get(self.TOOL, []) if r.get('type') == 'batch']
        with self.lock:
            current = deepcopy(self.current) if self.current and self.current.get('project_id') == ident else None
        if current:
            ids = {r['id'] for r in history}
            if current['id'] not in ids:
                history = [current] + history
            else:
                history = [current if r['id'] == current['id'] else r for r in history]
        return {
            'current': current,
            'history': history,
            'busy': self.running,
            'defaults': DEFAULT_CONFIG,
        }

    def start(self, ident, data):
        binary = self.locate('nuclei')
        if not binary:
            raise ValueError('Nuclei is not installed. Install it from the startscreen.')

        cfg = {k: data.get(k, v) for k, v in DEFAULT_CONFIG.items()}

        raw_list = data.get('targets', '')
        if not isinstance(raw_list, str) or not raw_list.strip():
            file_path = data.get('file_path', '')
            if file_path and os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        raw_list = f.read()
                except Exception as e:
                    raise ValueError(f'Cannot read target file: {e}')
            else:
                raise ValueError('No target list provided.')

        raw_urls = [line.strip() for line in raw_list.splitlines() if line.strip() and not line.strip().startswith('#')]
        valid_urls = [n for n in (normalize_url(u) for u in raw_urls) if n]
        if not valid_urls:
            raise ValueError('No valid URLs found in the target list.')

        self.store.get(ident)
        with self.lock:
            if self.running:
                raise ValueError('A batch scan is already running. Stop it first.')
            batch_id = uuid.uuid4().hex
            scan_dir = self._scan_dir(ident, batch_id)
            hosts = [{'url': u, 'label': host_label(u), 'status': 'pending', 'detail': '', 'pct': 0} for u in valid_urls]
            self.current = {
                'id': batch_id,
                'project_id': ident,
                'type': 'batch',
                'target': f'{len(valid_urls)} targets',
                'command': f'nuclei batch ({len(valid_urls)} targets)',
                'created_at': datetime.now(timezone.utc).isoformat(),
                'status': 'running',
                'output': '',
                'hosts': hosts,
                'config': cfg,
                'summary': None,
            }
            self.cancelled = False
            self._save_state(ident, batch_id, {'completed': {}, 'results': [], 'config': cfg, 'hosts': hosts})
            try:
                self.store.save_scan(ident, deepcopy(self.current), self.TOOL)
            except Exception:
                pass

        threading.Thread(target=self._run_batch,
                         args=(ident, batch_id, binary, valid_urls, scan_dir, cfg, None),
                         daemon=True).start()
        return deepcopy(self.current)

    def resume(self, ident, data):
        binary = self.locate('nuclei')
        if not binary:
            raise ValueError('Nuclei is not installed.')

        batch_id = data.get('batch_id', '').strip()
        if not re.fullmatch(r'[0-9a-f]{32}', batch_id):
            raise ValueError('Invalid batch ID.')

        self.store.get(ident)
        existing_state = self._load_state(ident, batch_id)
        completed = set(existing_state.get('completed', {}).keys())

        raw_list = data.get('targets', '')
        if not isinstance(raw_list, str) or not raw_list.strip():
            file_path = data.get('file_path', '')
            if file_path and os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        raw_list = f.read()
                except Exception as e:
                    raise ValueError(f'Cannot read target file: {e}')

        if raw_list and raw_list.strip():
            raw_urls = [line.strip() for line in raw_list.splitlines() if line.strip() and not line.strip().startswith('#')]
            valid_urls = [n for n in (normalize_url(u) for u in raw_urls) if n]
        else:
            prev_hosts = existing_state.get('hosts', [])
            valid_urls = [h['url'] for h in prev_hosts if h.get('url')]

        if not valid_urls:
            raise ValueError('No targets found to scan.')

        remaining = [u for u in valid_urls if u not in completed]
        if not remaining:
            raise ValueError(f'All {len(valid_urls)} targets in this list were already completed.')

        cfg = existing_state.get('config', DEFAULT_CONFIG.copy())
        for k in DEFAULT_CONFIG:
            if k in data:
                cfg[k] = data[k]

        scan_dir = self._scan_dir(ident, batch_id)
        with self.lock:
            if self.running:
                raise ValueError('A batch scan is already running.')
            hosts = []
            for u in valid_urls:
                if u in completed:
                    cinfo = existing_state['completed'][u]
                    hosts.append({'url': u, 'label': host_label(u), 'status': cinfo['status'].lower(),
                                  'detail': cinfo.get('detail', ''), 'pct': cinfo.get('pct', 100),
                                  'log_path': cinfo.get('log_path', ''), 'jsonl_path': cinfo.get('jsonl_path', '')})
                else:
                    hosts.append({'url': u, 'label': host_label(u), 'status': 'pending', 'detail': '', 'pct': 0})
            self.current = {
                'id': batch_id,
                'project_id': ident,
                'type': 'batch',
                'target': f'{len(valid_urls)} targets (resumed: {len(remaining)} left)',
                'command': f'nuclei batch resume ({len(remaining)}/{len(valid_urls)} remaining)',
                'created_at': existing_state.get('created_at', datetime.now(timezone.utc).isoformat()),
                'status': 'running',
                'output': f'[*] Resuming batch scan ({len(completed)} already done, {len(remaining)} remaining)...\n',
                'hosts': hosts,
                'config': cfg,
                'summary': None,
            }
            self.cancelled = False
            try:
                self.store.save_scan(ident, deepcopy(self.current), self.TOOL)
            except Exception:
                pass

        threading.Thread(target=self._run_batch,
                         args=(ident, batch_id, binary, remaining, scan_dir, cfg, existing_state),
                         daemon=True).start()
        return deepcopy(self.current)

    def cancel(self, ident=None):
        with self.lock:
            self.cancelled = True
            self._finishing = False
            with self._proc_lock:
                procs = list(self._active_procs)
            for p in procs:
                try:
                    if os.name == 'posix':
                        try:
                            pgid = os.getpgid(p.pid)
                            os.killpg(pgid, signal.SIGTERM)
                        except Exception:
                            p.terminate()
                    else:
                        p.terminate()
                except Exception:
                    pass

            def _kill_lingering(to_kill):
                time.sleep(0.5)
                for p in to_kill:
                    try:
                        if p.poll() is None:
                            if os.name == 'posix':
                                try:
                                    pgid = os.getpgid(p.pid)
                                    os.killpg(pgid, signal.SIGKILL)
                                except Exception:
                                    p.kill()
                            else:
                                p.kill()
                    except Exception:
                        pass
            threading.Thread(target=_kill_lingering, args=(procs,), daemon=True).start()

            if self.current and (not ident or self.current.get('project_id') == ident):
                self.current['status'] = 'cancelled'
                for h in self.current.get('hosts', []):
                    if h.get('status') in ('pending', 'running'):
                        h['status'] = 'cancelled'
                        h['detail'] = 'cancelled by user'
                self._append_log('\n[*] Batch scan stopped by user.\n')
                pid = self.current.get('project_id') or ident
                if pid:
                    try:
                        self.store.save_scan(pid, deepcopy(self.current), self.TOOL)
                    except Exception:
                        pass
                return {'message': 'Batch scan cancelled.'}

            if ident:
                try:
                    project = self.store.get(ident)
                    entries = project.get('tool_history', {}).get(self.TOOL, [])
                    changed = False
                    for entry in entries:
                        if entry.get('status') == 'running':
                            entry['status'] = 'cancelled'
                            for h in entry.get('hosts', []):
                                if h.get('status') in ('pending', 'running'):
                                    h['status'] = 'cancelled'
                                    h['detail'] = 'cancelled by user'
                            changed = True
                    if changed:
                        self.store._write(self.store._directory(ident) / 'project.json', project)
                        return {'message': 'Batch scan stopped.'}
                except Exception:
                    pass
        return {'message': 'Batch scan cancelled.'}

    def _update_host(self, ident, batch_id, url, update):
        with self.lock:
            if self.current and self.current['id'] == batch_id:
                for h in self.current['hosts']:
                    if h['url'] == url:
                        h.update(update)
                        break

    def _append_log(self, line):
        with self.lock:
            if self.current:
                self.current['output'] = (self.current['output'] + line)[-262144:]

    def _run_batch(self, ident, batch_id, binary, urls, scan_dir, cfg, existing_state):
        state = existing_state if existing_state else {'completed': {}, 'results': []}
        completed = state.get('completed', {})
        results = state.get('results', [])
        max_workers = int(cfg.get('max_workers', 7))
        save_every  = int(cfg.get('state_save_every', 10))
        semaphore   = threading.Semaphore(max_workers)
        done_count  = [len(completed)]
        total       = len(urls) + len(completed)
        save_counter = [0]
        start_time   = time.time()
        lock         = threading.Lock()

        def log(msg):
            self._append_log(msg + '\n')

        log(f'[*] Batch pool started — {len(urls)} targets remaining, {max_workers} workers')
        log(f'[*] Tags: {cfg.get("template_tags", "")} | Severity: {cfg.get("severity", "")}')

        def scan_one(url, i):
            if self.cancelled:
                self._update_host(ident, batch_id, url, {'status': 'cancelled', 'detail': 'cancelled by user'})
                return
            acquired = False
            try:
                while not self.cancelled:
                    if semaphore.acquire(timeout=0.2):
                        acquired = True
                        break
                if self.cancelled or not acquired:
                    self._update_host(ident, batch_id, url, {'status': 'cancelled', 'detail': 'cancelled by user'})
                    return
                name = safe_name(url, i)
                jsonl_path = str(scan_dir / f'{name}.jsonl')
                log_path   = str(scan_dir / f'{name}.log')
                self._update_host(ident, batch_id, url, {'status': 'running', 'jsonl_path': jsonl_path, 'log_path': log_path})
                status, detail, pct = run_one(binary, url, jsonl_path, log_path, cfg, runner=self)
            except Exception as e:
                status, detail, pct = 'ERROR', str(e), 0
            finally:
                if acquired:
                    semaphore.release()

            with lock:
                done_count[0] += 1
                elapsed = time.time() - start_time
                tp = done_count[0] / elapsed if elapsed > 0 else 0
                rem = (total - done_count[0]) / tp if tp > 0 else 0
                eta = f'{int(rem // 60)}m{int(rem % 60):02d}s' if rem > 0 else '0s'
                log(f'[{done_count[0]}/{total}] {status:<18} {url}  ({detail}) | ETA {eta}')

                self._update_host(ident, batch_id, url, {
                    'status': status.lower(), 'detail': detail, 'pct': pct,
                    'jsonl_path': jsonl_path, 'log_path': log_path,
                })
                completed[url] = {'status': status, 'detail': detail, 'pct': pct,
                                  'jsonl_path': jsonl_path, 'log_path': log_path}
                results.append({'url': url, 'status': status, 'detail': detail, 'pct': pct,
                                'jsonl_path': jsonl_path, 'log_path': log_path})
                save_counter[0] += 1
                if save_counter[0] >= save_every or done_count[0] >= total:
                    self._save_state(ident, batch_id, {'completed': completed, 'results': results, 'config': cfg})
                    save_counter[0] = 0
                    with self.lock:
                        if self.current:
                            try:
                                self.store.save_scan(ident, deepcopy(self.current), self.TOOL)
                            except Exception:
                                pass

        threads = []
        for i, url in enumerate(urls, start=len(completed) + 1):
            t = threading.Thread(target=scan_one, args=(url, i), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Build summary
        counts = {}
        for r in results:
            counts[r['status']] = counts.get(r['status'], 0) + 1
        summary = {
            'total': total,
            'scanned': len(results),
            'findings': counts.get('FINDINGS', 0),
            'findings_partial': counts.get('FINDINGS_PARTIAL', 0),
            'no_findings': counts.get('NO_FINDINGS', 0),
            'waf': counts.get('INCOMPLETE_WAF', 0),
            'timeout': counts.get('TIMEOUT', 0),
            'error': counts.get('ERROR', 0),
        }

        final_status = 'cancelled' if self.cancelled else 'completed'
        log('\n===== BATCH COMPLETE =====')
        log(f'Total: {total} | Scanned: {len(results)}')
        log(f'Findings: {summary["findings"]} | Partial: {summary["findings_partial"]}')
        log(f'Clean: {summary["no_findings"]} | WAF: {summary["waf"]}')
        log(f'Timeout: {summary["timeout"]} | Error: {summary["error"]}')

        # Write summary.txt
        try:
            summary_path = scan_dir / 'summary.txt'
            lines = [
                f'Nuclei batch scan — {datetime.now().isoformat()}',
                f'Tags: {cfg.get("template_tags", "")} | Severity: {cfg.get("severity", "")}',
                f'Workers: {cfg.get("max_workers", 7)} | Timeout: {cfg.get("nuclei_timeout", 900)}s',
                '', 'STATUS\tURL\tDETAIL',
            ]
            for r in sorted(results, key=lambda x: x['status']):
                lines.append(f'{r["status"]}\t{r["url"]}\t{r["detail"]}')
            summary_path.write_text('\n'.join(lines), encoding='utf-8')
        except Exception:
            pass

        self._save_state(ident, batch_id, {'completed': completed, 'results': results, 'config': cfg})
        with self.lock:
            if self.current and self.current['id'] == batch_id:
                self.current.update(
                    status=final_status,
                    summary=summary,
                    finished_at=datetime.now(timezone.utc).isoformat(),
                )
                try:
                    self.store.save_scan(ident, deepcopy(self.current), self.TOOL)
                except Exception:
                    pass
            self._finishing = False

    def get_host_log(self, ident, batch_id, url_index):
        """Return live or saved log for a specific host."""
        with self.lock:
            if self.current and self.current.get('id') == batch_id:
                hosts = self.current.get('hosts', [])
                if 0 <= url_index < len(hosts):
                    log_path = hosts[url_index].get('log_path', '')
                    if log_path and Path(log_path).exists():
                        try:
                            return Path(log_path).read_text(encoding='utf-8', errors='replace')[-65536:]
                        except Exception:
                            return ''
                    if hosts[url_index].get('status') == 'running':
                        return '[*] Scanning host...\n'
                    return f'[*] Status: {hosts[url_index].get("status", "pending")}\n'

        scan_dir = self.store._directory(ident) / 'scans' / 'nuclei' / batch_id
        if scan_dir.exists():
            try:
                project = self.store.get(ident)
                entries = project.get('tool_history', {}).get(self.TOOL, [])
                scan_rec = next((e for e in entries if e.get('id') == batch_id), None)
                if scan_rec and 'hosts' in scan_rec and 0 <= url_index < len(scan_rec['hosts']):
                    lp = scan_rec['hosts'][url_index].get('log_path', '')
                    if lp and Path(lp).exists():
                        return Path(lp).read_text(encoding='utf-8', errors='replace')[-65536:]
            except Exception:
                pass
            sf = scan_dir / '.progress.json'
            if sf.exists():
                try:
                    state = json.loads(sf.read_text(encoding='utf-8'))
                    hosts = state.get('hosts', [])
                    if 0 <= url_index < len(hosts):
                        lp = hosts[url_index].get('log_path', '')
                        if lp and Path(lp).exists():
                            return Path(lp).read_text(encoding='utf-8', errors='replace')[-65536:]
                except Exception:
                    pass
            log_files = sorted(scan_dir.glob('*.log'))
            if 0 <= url_index < len(log_files):
                try:
                    return log_files[url_index].read_text(encoding='utf-8', errors='replace')[-65536:]
                except Exception:
                    pass
        return ''
