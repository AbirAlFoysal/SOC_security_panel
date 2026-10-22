from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
import shutil
sys.path.insert(0,str(Path(__file__).parents[1]))
from project_store import ProjectStore
from nmap_runner import NmapRunner, arguments


class NmapTests(unittest.TestCase):
    def test_rejects_options_and_shell_input_as_target(self):
        for host in ['--script=anything','127.0.0.1;whoami','a b','$(id)']:
            with self.subTest(host=host), self.assertRaises(ValueError):
                arguments({'target':host})

    def test_validates_ports_and_builds_ipv6(self):
        host,profile,args=arguments({'target':'::1','ports':'22,80-90','skip_discovery':True})
        self.assertEqual(host,'::1')
        self.assertIn('-6',args)
        self.assertIn('-Pn',args)
        for ports in ['0','65536','20-10','22;id']:
            with self.subTest(ports=ports),self.assertRaises(ValueError):
                arguments({'target':'localhost','ports':ports})

    def test_url_target_extracts_host(self):
        self.assertEqual(arguments({'target':'https://Example.test/path'})[0],'example.test')

    @unittest.skipUnless(shutil.which('nmap'),'Nmap not installed')
    def test_localhost_scan_persists_output_and_structured_results(self):
        with tempfile.TemporaryDirectory() as temp, socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen()
            port=listener.getsockname()[1]
            store=ProjectStore(Path(temp)/'projects')
            project=store.create({'ip':'127.0.0.1'})
            runner=NmapRunner(store,shutil.which)
            run=runner.start(project['id'],{'target':'127.0.0.1','profile':'regular','ports':str(port),'skip_discovery':True})
            for _ in range(150):
                if not runner.running:break
                time.sleep(.1)
            if runner.running:
                runner.cancel(project['id'])
                self.fail('Localhost scan did not finish')
            result=store.get(project['id'])['tool_history']['nmap'][0]
            self.assertEqual(result['id'],run['id'])
            self.assertEqual(result['status'],'completed',result.get('error'))
            self.assertTrue(any(p['port']==str(port) and p['state']=='open' for h in result['hosts'] for p in h['ports']))
            directory=store.root/project['id']/'scans'/'nmap'
            self.assertTrue((directory/(run['id']+'.xml')).is_file())
            self.assertIn('Nmap',(directory/(run['id']+'.txt')).read_text())


if __name__=='__main__':unittest.main()

class CommandBuilderTests(unittest.TestCase):
    def test_catalog_covers_installed_help_flags(self):
        from nmap_options import BY_FLAG
        for flag in ['-sS','-sT','-iL','--excludefile','--script-args-file','--datadir','--resume','-oX','-T5','--nsock-engine']:
            self.assertIn(flag, BY_FLAG)
            self.assertTrue(BY_FLAG[flag]['name'])
            self.assertTrue(BY_FLAG[flag]['description'])

    def test_custom_parser_supports_values_and_privilege_detection(self):
        from nmap_options import parse_command
        args,targets,admin=parse_command('nmap -sS -p80,443 --script=default -T4 example.test')
        self.assertTrue(admin)
        self.assertIn('default',args)
        self.assertEqual(targets,['example.test'])
        self.assertFalse(parse_command('nmap -sT -p 80 localhost')[2])
        with self.assertRaises(ValueError): parse_command('sh -c id')
        with self.assertRaises(ValueError): parse_command('nmap --unknown localhost')
        with self.assertRaises(ValueError): parse_command('nmap --max-rate')

    def test_presets_survive_restart_and_names_are_unique(self):
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects');runner=NmapRunner(store,shutil.which)
            saved=runner.save_preset({'name':'Web ports','command':'nmap -sT -p 80,443 {target}'})
            self.assertEqual(NmapRunner(ProjectStore(store.root),shutil.which).presets()[0],saved)
            with self.assertRaises(ValueError):
                runner.save_preset({'name':'web ports','command':'nmap -sT {target}'})

    def test_file_upload_preserves_directory_and_blocks_traversal(self):
        import base64
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects');runner=NmapRunner(store,shutil.which)
            project=store.create({'ip':'127.0.0.1'})
            content=base64.b64encode(b'127.0.0.1\n').decode()
            upload=runner.upload(project['id'],{'files':[{'path':'data/targets.txt','content':content}],'directory':True})
            self.assertEqual((Path(upload['path'])/'targets.txt').read_text(),'127.0.0.1\n')
            self.assertTrue(Path(upload['path']).is_relative_to(store.root))
            with self.assertRaises(ValueError):runner.upload(project['id'],{'files':[{'path':'../escape','content':content}]})

    @unittest.skipUnless(shutil.which('nmap'),'Nmap not installed')
    def test_command_scan_uses_uploaded_list_and_project_local_output(self):
        import base64
        with tempfile.TemporaryDirectory() as temp, socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
            store=ProjectStore(Path(temp)/'projects');runner=NmapRunner(store,shutil.which)
            project=store.create({'ip':'127.0.0.1'})
            upload=runner.upload(project['id'],{'files':[{'path':'targets.txt','content':base64.b64encode(b'127.0.0.1\n').decode()}]})
            import shlex
            command=shlex.join(['nmap','-sT','-Pn','-p',str(port),'-iL',upload['path'],'-oX','/outside/should-not-write.xml'])
            run=runner.start(project['id'],{'command':command})
            for _ in range(150):
                if not runner.running:break
                time.sleep(.1)
            if runner.running:runner.cancel(project['id']);self.fail('Localhost scan timed out')
            result=store.get(project['id'])['tool_history']['nmap'][0]
            self.assertEqual(result['status'],'completed',result.get('error'))
            self.assertTrue((store.root/project['id']/'scans/nmap'/(run['id']+'.xml')).is_file())
            self.assertTrue(result['hosts'])


class PrivilegedCancellationTests(unittest.TestCase):
    def test_stop_request_uses_marker_for_privileged_process(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects');runner=NmapRunner(store,shutil.which)
            project=store.create({'ip':'127.0.0.1'})
            runner.current={'project_id':project['id'],'status':'running','admin':True}
            runner._finishing=True;runner.process=Mock();runner.stop_file=Path(temp)/'scan.stop'
            runner.cancel(project['id'])
            self.assertTrue(runner.stop_file.exists())
            runner.process.terminate.assert_not_called()

class HistoryManagementTests(unittest.TestCase):
    def test_scan_is_saved_as_soon_as_it_starts_and_updates_in_place(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects');project=store.create({'ip':'127.0.0.1'})
            runner=NmapRunner(store,lambda tool:'/usr/bin/nmap')
            with patch('nmap_runner.threading.Thread.start'):
                scan=runner.start(project['id'],{'command':'nmap -sT 127.0.0.1'})
            entries=store.get(project['id'])['tool_history']['nmap']
            self.assertEqual(entries[0]['status'],'running')
            self.assertEqual(entries[0]['id'],scan['id'])
            store.save_scan(project['id'],{**scan,'status':'completed'})
            self.assertEqual(len(store.get(project['id'])['tool_history']['nmap']),1)

    def test_deletion_is_project_scoped_and_keeps_global_presets(self):
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects');runner=NmapRunner(store,shutil.which)
            first=store.create({'ip':'127.0.0.1'});second=store.create({'host':'example.test'})
            saved=runner.save_preset({'name':'Global test','command':'nmap -sT {target}'})
            scanid='a'*32;otherid='b'*32
            store.save_scan(first['id'],{'id':scanid,'status':'completed'})
            store.save_scan(first['id'],{'id':otherid,'status':'completed'})
            directory=store.root/first['id']/'scans/nmap';directory.mkdir(parents=True)
            for name in [scanid+'.txt',scanid+'.xml',scanid+'-output.gnmap',otherid+'.txt']:(directory/name).write_text('output')
            with self.assertRaises(FileNotFoundError):runner.delete(second['id'],scanid)
            runner.current={'id':scanid,'project_id':first['id'],'status':'completed'}
            runner.delete(first['id'],scanid)
            self.assertIsNone(runner.current)
            self.assertEqual([p.name for p in directory.iterdir()],[otherid+'.txt'])
            self.assertEqual(len(store.get(first['id'])['tool_history']['nmap']),1)
            self.assertEqual(runner.presets(),[saved])

    def test_running_scan_cannot_be_deleted(self):
        with tempfile.TemporaryDirectory() as temp:
            runner=NmapRunner(ProjectStore(Path(temp)/'projects'),shutil.which)
            runner.current={'id':'a'*32,'project_id':'b'*32,'status':'running'};runner._finishing=True
            with self.assertRaisesRegex(ValueError,'Stop this scan'):
                runner.delete('b'*32,'a'*32)

class ScanTitleTests(unittest.TestCase):
    def test_duplicate_commands_receive_stable_project_local_titles(self):
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects')
            project=store.create({'host':'example.test'});other=store.create({'host':'other.test'})
            command='nmap -sT example.test'
            for i in range(3):store.save_scan(project['id'],{'id':str(i),'command':command,'status':'running'})
            entries=store.get(project['id'])['tool_history']['nmap']
            self.assertEqual([e['title'] for e in reversed(entries)],[command,command+' (1)',command+' (2)'])
            store.save_scan(project['id'],{'id':'1','command':command,'status':'completed'})
            self.assertEqual(next(e for e in store.get(project['id'])['tool_history']['nmap'] if e['id']=='1')['title'],command+' (1)')
            self.assertEqual(store.save_scan(other['id'],{'id':'other','command':command})['title'],command)

    def test_older_saved_history_gets_command_titles(self):
        with tempfile.TemporaryDirectory() as temp:
            store=ProjectStore(Path(temp)/'projects');project=store.create({'host':'example.test'})
            path=store.root/project['id']/'project.json'
            import json
            raw=json.loads(path.read_text());raw['tool_history']['nmap']=[{'id':'new','command':'nmap example.test'},{'id':'old','command':'nmap example.test'}]
            store._write(path,raw)
            entries=store.get(project['id'])['tool_history']['nmap']
            self.assertEqual([e['title'] for e in entries],['nmap example.test (1)','nmap example.test'])
            self.assertEqual(json.loads(path.read_text())['tool_history']['nmap'],entries)
