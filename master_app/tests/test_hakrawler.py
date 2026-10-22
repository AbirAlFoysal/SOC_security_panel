from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]))
from hakrawler_runner import HakrawlerRunner, parse_command, targets
from project_store import ProjectStore


def locate(tool):
    return shutil.which(tool) or (str(Path.home()/'.local/bin'/tool) if (Path.home()/'.local/bin'/tool).exists() else None)


class HakrawlerTests(unittest.TestCase):
    def test_supported_flags_and_header_quoting(self):
        args=parse_command('hakrawler -d 2 -u -json -h "Cookie: one=two;;Referer: https://example.test/"')
        self.assertIn('Cookie: one=two;;Referer: https://example.test/',args)
        for command in ['sh -c id','hakrawler -not-real','hakrawler -t 0','hakrawler -d x']:
            with self.subTest(command=command),self.assertRaises(ValueError):parse_command(command)

    def test_target_list_validation(self):
        self.assertEqual(targets('example.test\n# comment\nhttps://example.test\n'),['https://example.test'])
        with self.assertRaises(ValueError):targets('file:///etc/passwd')
        with self.assertRaises(ValueError):targets('https://user:secret@example.test')

    def test_ip_targets_use_http_and_keep_explicit_protocol_and_port(self):
        self.assertEqual(targets('127.0.0.1'),['http://127.0.0.1'])
        self.assertEqual(targets('127.0.0.1:8000'),['http://127.0.0.1:8000'])
        self.assertEqual(targets('127.0.0.1:8443'),['https://127.0.0.1:8443'])
        self.assertEqual(targets('::1'),['http://[::1]'])
        self.assertEqual(targets('https://127.0.0.1:9443/path'),['https://127.0.0.1:9443/path'])

    def test_global_presets_and_separate_tool_histories(self):
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects');runner=HakrawlerRunner(store,locate)
            first=store.create({'host':'one.test'});second=store.create({'host':'two.test'})
            preset=runner.save_preset({'name':'Depth three','command':'hakrawler -d 3 -u -json'})
            self.assertEqual(runner.status(first['id'])['presets'],runner.status(second['id'])['presets'])
            self.assertEqual(runner.presets(),[preset])
            store.save_scan(first['id'],{'id':'a'*32,'command':'printf target | hakrawler -u'},'hakrawler')
            store.save_scan(first['id'],{'id':'b'*32,'command':'nmap one.test'})
            runner.delete(first['id'],'a'*32)
            self.assertEqual(len(store.get(first['id'])['tool_history']['nmap']),1)
            self.assertEqual(runner.status(first['id'])['history'],[])
            self.assertEqual(runner.presets(),[preset])

    @unittest.skipUnless(locate('hakrawler'),'Hakrawler not installed')
    def test_real_local_crawl_saves_structured_urls(self):
        class Page(BaseHTTPRequestHandler):
            def do_GET(self):
                content=b'<html><a href="/found">Found</a><script src="/asset.js"></script></html>' if self.path=='/' else b'<html>Local fixture</html>'
                self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content)
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Page)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                store=ProjectStore(Path(temp)/'projects');project=store.create({'ip':'127.0.0.1'});runner=HakrawlerRunner(store,locate)
                url=f'http://127.0.0.1:{server.server_port}/'
                scan=runner.start(project['id'],{'target':url,'command':'hakrawler -d 2 -u -json -timeout 5'})
                for _ in range(200):
                    if not runner.running:break
                    time.sleep(.1)
                if runner.running:runner.cancel(project['id']);self.fail('Local crawl did not finish')
                result=store.get(project['id'])['tool_history']['hakrawler'][0]
                self.assertEqual(result['status'],'completed',result.get('output'))
                self.assertTrue(any(row['url'].endswith('/found') for row in result['urls']),result['output'])
                self.assertEqual(result['id'],scan['id'])
                self.assertTrue((store.root/project['id']/'scans/hakrawler'/(scan['id']+'.txt')).exists())
                self.assertTrue((store.root/project['id']/'scans/hakrawler'/(scan['id']+'-targets.txt')).exists())
        finally:server.shutdown();server.server_close()


if __name__=='__main__':unittest.main()
