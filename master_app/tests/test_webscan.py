import base64
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.path.insert(0, str(Path(__file__).parents[1]))
from project_store import ProjectStore
from webscan_runner import CATALOG, WebScanRunner, parse_command, web_target


class WebScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = ProjectStore(self.root / 'projects')
        self.project = self.store.save({'host': 'localhost'})
        self.binary = self.root / 'fixture-scanner'
        self.binary.write_text('#!' + sys.executable + '\nimport json,sys,time\nprint(json.dumps(sys.argv[1:]),flush=True)\nif "slow" in sys.argv: time.sleep(30)\nprint("fixture scan completed",flush=True)\n')
        self.binary.chmod(0o700)
        self.runners = []

    def tearDown(self):
        for runner in self.runners:
            if runner.running:
                runner.cancel(self.project['id'])
                self.wait(runner)
        self.temp.cleanup()

    def runner(self, tool, installed=True):
        runner = WebScanRunner(self.store, lambda _: str(self.binary) if installed else None, tool)
        self.runners.append(runner)
        return runner

    def wait(self, runner):
        deadline = time.monotonic() + 8
        while runner.running and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(runner.running, 'Fixture scan did not finish')
        return runner.status(self.project['id'])['history'][0]

    def test_catalogs_and_command_validation(self):
        self.assertGreater(len(CATALOG['sqlmap']), 200)
        self.assertGreater(len(CATALOG['nikto']), 40)
        self.assertEqual(parse_command('sqlmap', "sqlmap -u 'http://127.0.0.1/?id=1' --level=2 --batch"), ['--url', 'http://127.0.0.1/?id=1', '--level', '2', '--batch'])
        self.assertEqual(parse_command('nikto', 'nikto -h http://127.0.0.1 -p 8080 -Tuning 23'), ['-host', 'http://127.0.0.1', '-port', '8080', '-Tuning', '23'])
        for command in ('bash -c whoami', 'sqlmap --bogus', 'sqlmap --risk', 'sqlmap --risk --batch', 'sqlmap --batch=foo', 'sqlmap --sql-shell'):
            with self.assertRaises(ValueError):
                parse_command('sqlmap', command)
        self.assertEqual(web_target('127.0.0.1:8080/path?id=1'), 'http://127.0.0.1:8080/path?id=1')
        for value in ('file:///tmp/test', 'http://', 'http://x:wrong', 'http://x/ bad'):
            with self.assertRaises(ValueError):
                web_target(value)

    def test_both_tools_persist_output_and_duplicate_command_titles(self):
        for tool in ('sqlmap', 'nikto'):
            runner = self.runner(tool)
            for _ in range(2):
                runner.start(self.project['id'], {'command': tool, 'target': 'http://127.0.0.1:8080/?id=1'})
                record = self.wait(runner)
                self.assertEqual(record['status'], 'completed')
                self.assertIn('fixture scan completed', record['output'])
            history = ProjectStore(self.store.root).get(self.project['id'])['tool_history'][tool]
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]['title'], history[1]['title'] + ' (1)')
            other = self.store.save({'host': 'other.test'})
            self.assertEqual(runner.status(other['id'])['history'], [])
            self.assertIsNone(runner.status(other['id'])['current'])

    def test_stop_saves_partial_output_and_refuses_running_delete(self):
        runner = self.runner('sqlmap')
        run = runner.start(self.project['id'], {'command': 'sqlmap --data slow', 'target': '127.0.0.1'})
        deadline = time.monotonic() + 3
        while not runner.current['output'] and time.monotonic() < deadline:
            time.sleep(0.01)
        with self.assertRaises(ValueError):
            runner.delete(self.project['id'], run['id'])
        runner.cancel(self.project['id'])
        record = self.wait(runner)
        self.assertEqual(record['status'], 'cancelled')
        self.assertIn('slow', record['output'])

    def test_global_presets_and_input_upload(self):
        runner = self.runner('sqlmap')
        preset = runner.save_preset({'name': 'Request test', 'command': 'sqlmap --url {target} --batch'})
        self.assertEqual(WebScanRunner(self.store, lambda _: None, 'sqlmap').presets()[0]['id'], preset['id'])
        self.assertEqual(self.runner('nikto').presets(), [])
        uploaded = runner.upload(self.project['id'], {'files': [{'path': 'request.txt', 'content': base64.b64encode(b'GET /?id=1 HTTP/1.1\nHost: localhost\n').decode()}]})
        runner.start(self.project['id'], {'command': 'sqlmap -r ' + uploaded['path']})
        record = self.wait(runner)
        self.assertNotIn('--url', json.loads(record['output'].splitlines()[0]))

    def test_outputs_confined_and_delete_cleans_generated_directories(self):
        runner = self.runner('sqlmap')
        run = runner.start(self.project['id'], {'command': 'sqlmap --url http://127.0.0.1 --output-dir /tmp/outside --har /tmp/traffic.har'})
        record = self.wait(runner)
        args = json.loads(record['output'].splitlines()[0])
        directory = self.store._directory(self.project['id']) / 'scans' / 'sqlmap'
        for flag in ('--output-dir', '--tmp-dir', '--har'):
            self.assertTrue(Path(args[args.index(flag) + 1]).is_relative_to(directory))
        runner.delete(self.project['id'], run['id'])
        self.assertEqual(runner.status(self.project['id'])['history'], [])
        self.assertFalse(any(p.name.startswith(run['id']) for p in directory.iterdir()))

    def test_missing_binary_and_failed_launch(self):
        with self.assertRaisesRegex(ValueError, 'not installed'):
            self.runner('sqlmap', False).start(self.project['id'], {'command': 'sqlmap', 'target': '127.0.0.1'})
        runner = self.runner('nikto')
        self.binary.unlink()
        runner.start(self.project['id'], {'command': 'nikto', 'target': '127.0.0.1'})
        self.assertEqual(self.wait(runner)['status'], 'failed')

    def test_session_file_copied_and_nikto_output_confined(self):
        session = self.root / 'existing.sqlite'
        session.write_bytes(b'fixture session')
        runner = self.runner('sqlmap')
        runner.start(self.project['id'], {'command': f'sqlmap -s {session}', 'target': 'localhost'})
        record = self.wait(runner)
        args = json.loads(record['output'].splitlines()[0])
        copied = Path(args[args.index('-s') + 1])
        self.assertEqual(copied.read_bytes(), b'fixture session')
        self.assertNotEqual(copied, session)
        runner = self.runner('nikto')
        runner.start(self.project['id'], {'command': 'nikto -host http://localhost -output /tmp/report.txt -Save /tmp/responses'})
        args = json.loads(self.wait(runner)['output'].splitlines()[0])
        self.assertIn('-nointeractive', args)
        self.assertEqual(args[args.index('-ask')+1], 'no')
        for flag in ('-output', '-Save'):
            self.assertTrue(Path(args[args.index(flag)+1]).is_relative_to(self.store._directory(self.project['id'])))

    def test_api_status_presets_upload_start_stop_and_delete(self):
        import threading
        import urllib.request
        import urllib.error
        from http.server import ThreadingHTTPServer
        from unittest.mock import patch
        import run
        runners = {tool: self.runner(tool) for tool in ('sqlmap', 'nikto')}
        class QuietHandler(run.Handler):
            def log_message(self, *args):
                pass
        with patch.object(run, 'PROJECTS', self.store), patch.object(run, 'WEB_SCANS', runners):
            server = ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = f'http://127.0.0.1:{server.server_port}'
            def call(path, data=None):
                request = urllib.request.Request(base + path, None if data is None else json.dumps(data).encode(), headers={'Content-Type':'application/json', 'X-App-Token':run.TOKEN})
                with urllib.request.urlopen(request, timeout=4) as response:
                    return json.load(response)
            try:
                ident = self.project['id']
                for tool in runners:
                    endpoint = f'/api/projects/{ident}/{tool}'
                    self.assertTrue(call(endpoint)['installed'])
                    preset = call(f'/api/{tool}/presets', {'name':'API preset', 'command':tool})
                    self.assertEqual(call(endpoint)['presets'][0]['id'], preset['id'])
                    uploaded = call(endpoint+'/files', {'files':[{'path':'targets.txt', 'content':base64.b64encode(b'http://127.0.0.1\n').decode()}]})
                    self.assertTrue(Path(uploaded['path']).is_file())
                    command = 'sqlmap --data slow' if tool=='sqlmap' else 'nikto -useragent slow'
                    record = call(endpoint, {'command':command, 'target':'http://127.0.0.1'})
                    with self.assertRaises(urllib.error.HTTPError) as conflict:
                        call(f'/api/projects/{ident}/'+('nikto' if tool=='sqlmap' else 'sqlmap'), {'command': 'nikto' if tool=='sqlmap' else 'sqlmap', 'target':'http://127.0.0.1'})
                    self.assertEqual(conflict.exception.code, 409)
                    conflict.exception.close()
                    self.assertTrue(call('/api/revision')['busy'])
                    call(endpoint+'/cancel', {})
                    self.wait(runners[tool])
                    self.assertEqual(call(endpoint)['history'][0]['status'], 'cancelled')
                    call(endpoint+f"/history/{record['id']}/delete", {})
                    self.assertEqual(call(endpoint)['history'], [])
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
