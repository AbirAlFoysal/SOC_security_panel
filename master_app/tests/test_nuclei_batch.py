import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.path.insert(0, str(Path(__file__).parents[1]))
from project_store import ProjectStore
from nuclei_batch_runner import (
    NucleiBatchRunner, normalize_url, safe_name, host_label,
    classify, DEFAULT_CONFIG
)


class NucleiBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = ProjectStore(self.root / 'projects')
        self.project = self.store.save({'host': 'example.com'})

        # Mock nuclei binary script
        self.binary = self.root / 'fake-nuclei'
        self.binary.write_text(
            '#!' + sys.executable + '\n'
            'import sys\n'
            'for i, arg in enumerate(sys.argv):\n'
            '    if arg == "-jsonl-export" and i + 1 < len(sys.argv):\n'
            '        with open(sys.argv[i+1], "w") as jf:\n'
            '            jf.write(\'{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"}}\\n\')\n'
            'print("[INF] Requests: 100/100 (100%) | Errors: 0", flush=True)\n'
        )
        self.binary.chmod(0o755)
        self.runner = NucleiBatchRunner(self.store, lambda t: str(self.binary) if t == 'nuclei' else None)

    def tearDown(self):
        if self.runner.running:
            try:
                self.runner.cancel(self.project['id'])
            except Exception:
                pass
        self.temp.cleanup()

    def test_helpers(self):
        self.assertEqual(normalize_url('example.com'), 'https://example.com')
        self.assertEqual(normalize_url('http://test.com/path'), 'http://test.com/path')
        self.assertIsNone(normalize_url(''))
        self.assertIsNone(normalize_url('#comment'))

        self.assertEqual(host_label('https://api.test.com/v1'), 'api.test.com')
        self.assertTrue(safe_name('https://test.com:8080/path', 1).startswith('0001_'))

    def test_classify(self):
        cfg = DEFAULT_CONFIG.copy()
        jf = self.root / 'test.jsonl'
        lf = self.root / 'test.log'

        jf.write_text('{"finding": true}\n')
        lf.write_text('Requests: 100/100 (100%) | Errors: 0\n')
        status, detail, pct = classify(str(jf), str(lf), False, 900, 0, cfg)
        self.assertEqual(status, 'FINDINGS')

        jf.write_text('')
        lf.write_text('Requests: 100/100 (100%) | Errors: 0\n')
        status, detail, pct = classify(str(jf), str(lf), False, 900, 0, cfg)
        self.assertEqual(status, 'NO_FINDINGS')

    def test_cancel_batch(self):
        # Create a slow fake nuclei
        slow_bin = self.root / 'slow-nuclei'
        slow_bin.write_text(
            '#!' + sys.executable + '\n'
            'import time\n'
            'time.sleep(30)\n'
        )
        slow_bin.chmod(0o755)
        runner = NucleiBatchRunner(self.store, lambda t: str(slow_bin))
        res = runner.start(self.project['id'], {'targets': 'https://s1.example.com\nhttps://s2.example.com', 'max_workers': 2})
        time.sleep(0.3)
        self.assertTrue(runner.running)
        runner.cancel(self.project['id'])
        deadline = time.time() + 5
        while runner.running and time.time() < deadline:
            time.sleep(0.05)
        self.assertFalse(runner.running)
        self.assertEqual(runner.current['status'], 'cancelled')

    def test_start_batch_and_get_log(self):
        data = {
            'targets': 'https://target1.example.com\nhttps://target2.example.com',
            'max_workers': 2,
            'nuclei_timeout': 30,
        }
        res = self.runner.start(self.project['id'], data)
        self.assertEqual(res['type'], 'batch')
        self.assertEqual(len(res['hosts']), 2)

        deadline = time.time() + 10
        while self.runner.running and time.time() < deadline:
            time.sleep(0.05)
        self.assertFalse(self.runner.running)

        st = self.runner.status(self.project['id'])
        self.assertEqual(len(st['history']), 1)
        self.assertEqual(st['history'][0]['status'], 'completed')

        log0 = self.runner.get_host_log(self.project['id'], res['id'], 0)
        self.assertIn('Requests:', log0)

        sessions = self.runner.list_sessions(self.project['id'])
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]['id'], res['id'])
        self.assertEqual(sessions[0]['done'], 2)


    def test_cancel_orphan_running_scan_cleans_history(self):
        # Simulate an orphan running batch scan left in project.json after server restart
        orphan_scan = {
            'id': 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
            'project_id': self.project['id'],
            'type': 'batch',
            'command': 'nuclei batch (2 targets)',
            'status': 'running',
            'hosts': [
                {'url': 'https://s1.example.com', 'status': 'running', 'detail': ''},
                {'url': 'https://s2.example.com', 'status': 'pending', 'detail': ''},
            ],
            'output': 'Initial logs...',
        }
        self.store.save_scan(self.project['id'], orphan_scan, 'nuclei')
        
        # Verify it was saved as running
        proj = self.store.get(self.project['id'])
        self.assertEqual(proj['tool_history']['nuclei'][0]['status'], 'running')
        
        # Now call cancel while runner is NOT actively running in memory
        self.assertFalse(self.runner.running)
        res = self.runner.cancel(self.project['id'])
        self.assertTrue(any(w in res['message'].lower() for w in ('stopped', 'cancelled')))
        
        # Verify the orphan scan and its hosts are now marked cancelled
        proj_after = self.store.get(self.project['id'])
        history_run = proj_after['tool_history']['nuclei'][0]
        self.assertEqual(history_run['status'], 'cancelled')
        for h in history_run['hosts']:
            self.assertEqual(h['status'], 'cancelled')
            self.assertEqual(h['detail'], 'cancelled by user')

    def test_cancel_via_api_routes(self):
        import json
        import threading
        import urllib.request
        from http.server import ThreadingHTTPServer
        from unittest.mock import patch
        import run
        
        class QuietHandler(run.Handler):
            def log_message(self, *args):
                pass
                
        with patch.object(run, 'PROJECTS', self.store), patch.object(run, 'NUCLEI_BATCH', self.runner):
            server = ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = f'http://127.0.0.1:{server.server_port}'
            
            def call(path, data=None):
                req = urllib.request.Request(
                    base + path,
                    data=b'{}' if data is None else json.dumps(data).encode(),
                    headers={'Content-Type': 'application/json', 'X-App-Token': run.TOKEN}
                )
                with urllib.request.urlopen(req, timeout=4) as response:
                    return json.load(response)
                    
            try:
                # 1. Test nuclei_batch/cancel when not running
                res1 = call(f"/api/projects/{self.project['id']}/nuclei_batch/cancel", {})
                self.assertIn('message', res1)
                
                # 2. Test nuclei/cancel when not running
                res2 = call(f"/api/projects/{self.project['id']}/nuclei/cancel", {})
                self.assertIn('message', res2)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
if __name__ == '__main__':
    unittest.main()
