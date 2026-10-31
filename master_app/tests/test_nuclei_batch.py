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


if __name__ == '__main__':
    unittest.main()
