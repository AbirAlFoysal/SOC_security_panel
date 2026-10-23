import base64
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]))
from project_store import ProjectStore
from cli_runner import CliRunner, CONFIG, OPTIONS, parse_parts, tokens_from_parts


def tiny_capture(path):
    # One Ethernet/IPv4/UDP packet containing a local fixture string; no traffic is sent.
    payload=b'fixture'
    ethernet=b'\x00'*12+b'\x08\x00'
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+8+len(payload),1,0,64,17,0,b'\x7f\x00\x00\x01',b'\x7f\x00\x00\x01')
    udp=struct.pack('!HHHH',12345,9999,8+len(payload),0)
    packet=ethernet+ip+udp+payload
    path.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',1,0,len(packet),len(packet))+packet)


class CliToolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.store=ProjectStore(self.root/'projects');self.project=self.store.save({'host':'localhost'})
        self.binary=self.root/'fixture-tool'
        self.binary.write_text('#!'+sys.executable+'\nimport json,sys,time,os\nprint(json.dumps(sys.argv[1:]),flush=True)\nprint("CWD="+os.getcwd(),flush=True)\nif "slow" in sys.argv: time.sleep(20)\nif "exhaust" in sys.argv: sys.exit(1)\nprint("fixture complete",flush=True)\n')
        self.binary.chmod(0o700);self.runners=[]
        self.hashes=self.root/'hashes.txt';self.hashes.write_text('fixture hash\n')
        self.words=self.root/'words.txt';self.words.write_text('fixture\n')
        self.capture=self.root/'capture.pcap';tiny_capture(self.capture)

    def tearDown(self):
        for r in self.runners:
            if r.running:r.cancel(self.project['id']);self.wait(r)
        self.temp.cleanup()

    def runner(self,tool,installed=True):
        r=CliRunner(self.store,lambda _:str(self.binary) if installed else None,tool);self.runners.append(r);return r

    def wait(self,r):
        deadline=time.monotonic()+8
        while r.running and time.monotonic()<deadline:time.sleep(.01)
        self.assertFalse(r.running)
        return r.status(self.project['id'])['history'][0]

    def command(self,tool):
        q=shlex.quote
        return {
         'tcpdump':f'tcpdump -nn -r {q(str(self.capture))} udp',
         'hydra':f'hydra -l fixture -P {q(str(self.words))} -t 1 ssh://127.0.0.1',
         'john':f'john --wordlist={q(str(self.words))} --format=raw-md5 {q(str(self.hashes))}',
         'hashcat':f'hashcat -m 0 -a 0 {q(str(self.hashes))} {q(str(self.words))}',
         'gobuster':f'gobuster dir -u http://127.0.0.1 -w {q(str(self.words))}',
         'ffuf':f'ffuf -u http://127.0.0.1/FUZZ -w {q(str(self.words))}',
         'aircrack-ng':f'aircrack-ng -a 2 -b 00:11:22:33:44:55 -w {q(str(self.words))} {q(str(self.capture))}',
        }[tool]

    def test_every_remaining_tool_runs_and_persists_separate_history(self):
        for tool in CONFIG:
            with self.subTest(tool=tool):
                r=self.runner(tool);run=r.start(self.project['id'],{'command':self.command(tool)})
                record=self.wait(r)
                self.assertEqual(record['status'],'completed')
                self.assertIn('fixture complete',record['output'])
                self.assertEqual(record['id'],run['id'])
                self.assertTrue(r.status(self.project['id'])['workspace']['name'])
                self.assertGreater(len(r.options),20)
                self.assertTrue(Path(r.execution_cwd).is_relative_to(self.store._directory(self.project['id'])))
                reopened=ProjectStore(self.store.root).get(self.project['id'])
                self.assertEqual(reopened['tool_history'][tool][0]['id'],run['id'])

    def test_native_spelling_and_optional_john_values(self):
        _,parts=parse_parts('john',f'john --single {self.hashes}')
        self.assertEqual(parts[0]['value'],None)
        self.assertEqual(parts[1]['positional'],str(self.hashes))
        r=self.runner('john');r.start(self.project['id'],{'command':self.command('john')});record=self.wait(r)
        args=json.loads(record['output'].splitlines()[0])
        self.assertIn('--wordlist='+str(self.words),args)
        self.assertIn('--format=raw-md5',args)
        self.assertTrue(any(v.startswith('--pot='+str(self.store._directory(self.project['id']))) for v in args))
        for tool,command in [('john','john --bad'),('hydra','hydra -P -l test'),('gobuster','gobuster nonsense'),('ffuf','ffuf -t'),('tcpdump','tcpdump -i')]:
            with self.subTest(command=command),self.assertRaises(ValueError):parse_parts(tool,command)

    def test_required_input_validation_prevents_broken_jobs(self):
        commands={
         'tcpdump':'tcpdump -c 1', 'hydra':'hydra ssh://127.0.0.1',
         'john':'john --wordlist '+str(self.words), 'hashcat':'hashcat -a 0 '+str(self.hashes),
         'gobuster':'gobuster dir -u http://127.0.0.1', 'ffuf':'ffuf -u http://127.0.0.1/FUZZ',
         'aircrack-ng':'aircrack-ng -a 2 '+str(self.capture),
        }
        for tool,command in commands.items():
            with self.subTest(tool=tool),self.assertRaises(ValueError):self.runner(tool).start(self.project['id'],{'command':command})
        self.assertEqual(self.store.get(self.project['id'])['tool_history'],{})

    def test_gobuster_modes_and_ffuf_named_wordlists(self):
        for mode in ('dir','dns','vhost','fuzz','s3','gcs','tftp'):
            flag='--domain example.test' if mode=='dns' else '--server 127.0.0.1' if mode=='tftp' else '' if mode in ('s3','gcs') else '--url http://127.0.0.1'
            r=self.runner('gobuster');r.start(self.project['id'],{'command':f'gobuster {mode} {flag} --wordlist {self.words}'})
            args=json.loads(self.wait(r)['output'].splitlines()[0]);self.assertEqual(args[0],mode)
        r=self.runner('ffuf');r.start(self.project['id'],{'command':f'ffuf -u http://127.0.0.1/NAME -w {self.words}:NAME -H "X-Fixture: test"'})
        args=json.loads(self.wait(r)['output'].splitlines()[0]);self.assertIn(str(self.words)+':NAME',args);self.assertIn('-noninteractive',args)

    def test_presets_are_global_per_tool_and_targets_not_required_for_help(self):
        for tool in CONFIG:
            with self.subTest(tool=tool):
                r=self.runner(tool);preset=r.save_preset({'name':'Fixture preset','command':self.command(tool)})
                self.assertEqual(self.runner(tool).presets()[0]['id'],preset['id'])
                utility={'tcpdump':'tcpdump -D','hydra':'hydra -h','john':'john --list=formats','hashcat':'hashcat --backend-info','gobuster':'gobuster --help','ffuf':'ffuf -h','aircrack-ng':'aircrack-ng --help'}[tool]
                r.start(self.project['id'],{'command':utility});self.assertEqual(self.wait(r)['status'],'completed')

    def test_cancel_persists_partial_output_and_protects_other_project(self):
        r=self.runner('hydra');run=r.start(self.project['id'],{'command':self.command('hydra')+' -m slow'})
        deadline=time.monotonic()+3
        while not r.current['output'] and time.monotonic()<deadline:time.sleep(.01)
        other=self.store.save({'host':'other.test'})
        with self.assertRaises(ValueError):r.cancel(other['id'])
        with self.assertRaises(ValueError):r.delete(self.project['id'],run['id'])
        r.cancel(self.project['id']);record=self.wait(r);self.assertEqual(record['status'],'cancelled');self.assertIn('slow',record['output'])
        self.assertEqual(r.status(other['id'])['history'],[])

    def test_output_files_and_deletion_are_project_scoped(self):
        r=self.runner('ffuf');run=r.start(self.project['id'],{'command':self.command('ffuf')+' -o /tmp/outside.json -od /tmp/responses'})
        args=json.loads(self.wait(r)['output'].splitlines()[0])
        for flag in ('-o','-od'):self.assertTrue(Path(args[args.index(flag)+1]).is_relative_to(self.store._directory(self.project['id'])))
        out=Path(args[args.index('-o')+1]);out.write_text('fixture report')
        files=r.scan_files(self.project['id'],run['id']);saved=next(f for f in files if f['name'].endswith('outside.json'))
        self.assertEqual(r.scan_file(self.project['id'],run['id'],saved['token']).read_text(),'fixture report')
        with self.assertRaises(FileNotFoundError):r.scan_file(self.project['id'],run['id'],'../escape')
        outside=self.root/'private.txt';outside.write_text('private');link=out.with_name(run['id']+'-link');link.symlink_to(outside)
        self.assertFalse(any(f['name'].endswith('-link') for f in r.scan_files(self.project['id'],run['id'])))
        r.delete(self.project['id'],run['id']);self.assertFalse(out.exists());self.assertTrue(outside.exists())

    def test_hashcat_exhaustion_is_completion_and_state_is_local(self):
        r=self.runner('hashcat');r.start(self.project['id'],{'command':self.command('hashcat')+' --session exhaust'})
        # The fixture sees a scoped path for session; use a value that is passed literally to simulate exit 1.
        self.wait(r)
        r.start(self.project['id'],{'command':self.command('hashcat')+' --rule-left exhaust'})
        record=self.wait(r);self.assertEqual(record['status'],'completed');self.assertEqual(record['outcome'],'exhausted')
        args=json.loads(record['output'].splitlines()[0])
        for flag in ('--potfile-path','--restore-file-path'):self.assertTrue(Path(args[args.index(flag)+1]).is_relative_to(self.store._directory(self.project['id'])))

    @unittest.skipUnless(shutil.which('tcpdump'),'tcpdump not installed')
    def test_real_tcpdump_offline_capture_needs_no_admin(self):
        r=CliRunner(self.store,lambda _:shutil.which('tcpdump'),'tcpdump');self.runners.append(r)
        r.start(self.project['id'],{'command':f'tcpdump -nn -i any -r {self.capture} udp','elevate':True})
        record=self.wait(r);self.assertEqual(record['status'],'completed');self.assertFalse(record['admin'])
        self.assertIn('9999',record['output']);self.assertNotIn('-i any',record['executed_command'])

    def test_missing_installation_and_capture_wrapper_validation(self):
        with self.assertRaisesRegex(ValueError,'not installed'):self.runner('gobuster',False).start(self.project['id'],{'command':self.command('gobuster')})
        from capture_privileged import validate_command
        for command in (['/bin/sh','-c','true'],[],['/tmp/tcpdump','-D']):
            with self.assertRaises(ValueError):validate_command(command)

    def test_http_routes_for_every_tool_and_output_download(self):
        import threading
        import urllib.request
        import urllib.error
        from http.server import ThreadingHTTPServer
        import run
        runners={tool:self.runner(tool) for tool in CONFIG}
        class QuietHandler(run.Handler):
            def log_message(self,*args):pass
        with patch.object(run,'PROJECTS',self.store),patch.object(run,'WEB_SCANS',runners):
            server=ThreadingHTTPServer(('127.0.0.1',0),QuietHandler)
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            base=f'http://127.0.0.1:{server.server_port}'
            def request(path,data=None,raw=False):
                req=urllib.request.Request(base+path,None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json','X-App-Token':run.TOKEN})
                with urllib.request.urlopen(req,timeout=5) as response:
                    return response.read() if raw else json.load(response)
            try:
                for tool,r in runners.items():
                    with self.subTest(tool=tool):
                        endpoint=f'/api/projects/{self.project["id"]}/{tool}'
                        self.assertTrue(request(endpoint)['installed'])
                        self.assertEqual(request(endpoint)['workspace']['name'],CONFIG[tool]['name'])
                        preset=request('/api/'+tool+'/presets',{'name':'HTTP preset','command':self.command(tool)})
                        self.assertEqual(request(endpoint)['presets'][0]['id'],preset['id'])
                        uploaded=request(endpoint+'/files',{'files':[{'path':'fixture.txt','content':base64.b64encode(b'fixture').decode()}]})
                        self.assertTrue(Path(uploaded['path']).is_file())
                        record=request(endpoint,{'command':self.command(tool)});self.wait(r)
                        files=request(endpoint+'/history/'+record['id']+'/files')['files']
                        self.assertTrue(files)
                        content=request(endpoint+'/history/'+record['id']+'/files/'+files[0]['token'],raw=True)
                        self.assertIn(b'fixture complete',content)
                        with self.assertRaises(urllib.error.HTTPError) as error:
                            request(endpoint+'/history/'+record['id']+'/files/not-a-file',raw=True)
                        self.assertEqual(error.exception.code,404);error.exception.close()
                        request(endpoint+'/history/'+record['id']+'/delete',{})
                        self.assertEqual(request(endpoint)['history'],[])
            finally:
                server.shutdown();server.server_close();worker.join(timeout=3)

    def test_native_short_forms_and_empty_gobuster_blacklist(self):
        mode,parts=parse_parts('tcpdump',f'tcpdump -c10 -r {self.capture} udp')
        self.assertEqual(tokens_from_parts('tcpdump',mode,parts)[:2],['-c','10'])
        mode,parts=parse_parts('hydra','hydra -Vf -t4 -h')
        self.assertEqual(tokens_from_parts('hydra',mode,parts),['-V','-f','-t','4','-h'])
        mode,parts=parse_parts('gobuster',f'gobuster dir -u http://127.0.0.1 -w {self.words} -s 200 -b ""')
        tokens=tokens_from_parts('gobuster',mode,parts)
        self.assertEqual(tokens[tokens.index('--status-codes-blacklist')+1],'')


    def test_aircrack_optional_x_does_not_consume_capture(self):
        mode,parts=parse_parts('aircrack-ng',f'aircrack-ng -a 1 -x {self.capture}')
        self.assertEqual(parts[-1]['positional'],str(self.capture))
        self.assertIsNone(parts[-2]['value'])
        mode,parts=parse_parts('aircrack-ng',f'aircrack-ng -a 1 -x 2 {self.capture}')
        self.assertIn('-x2',tokens_from_parts('aircrack-ng',mode,parts))

    def test_capture_filter_tokens_are_not_rewritten_as_file_paths(self):
        # A working-directory file whose name matches a BPF token must not alter the filter.
        r=self.runner('tcpdump')
        scanid='a'*32
        directory=self.store._directory(self.project['id'])/'scans'/'tcpdump'
        directory.mkdir(parents=True)
        mode,parts=parse_parts('tcpdump',f'tcpdump -r {self.capture} udp')
        with patch('cli_runner.Path.is_file',return_value=True):
            native=r._native_command(self.project['id'],mode,parts,directory,scanid)
        self.assertEqual(native[-1],'udp')
