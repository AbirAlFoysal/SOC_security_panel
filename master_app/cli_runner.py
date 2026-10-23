"""Native workspaces for remaining command-line tools. No shell interpolation.

Bundled flag references: tcpdump(1), THC Hydra help, John Jumbo options.c,
Hashcat usage.c, Gobuster cli/*.go, ffuf README help, Aircrack-ng native help.
See cli_references.json for upstream sources and retrieval date.
"""
from copy import deepcopy
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import sys
import threading
import uuid
from urllib.parse import urlsplit
from nmap_runner import NmapRunner, target as network_target
from webscan_runner import WebScanRunner, web_target

OPTIONS = json.loads(Path(__file__).with_name('cli_options.json').read_text())
REFERENCES = {
    'tcpdump':'https://www.tcpdump.org/manpages/tcpdump.1.html',
    'hydra':'https://github.com/vanhauser-thc/thc-hydra',
    'john':'https://www.openwall.com/john/doc/OPTIONS.shtml',
    'hashcat':'https://hashcat.net/wiki/doku.php?id=hashcat',
    'gobuster':'https://github.com/OJ/gobuster',
    'ffuf':'https://github.com/ffuf/ffuf',
    'aircrack-ng':'https://www.aircrack-ng.org/doku.php?id=aircrack-ng',
}
CONFIG = {
 'tcpdump': dict(name='tcpdump', target_kind='filter', target_option='$filter', target_label='Capture filter', action='Capture',
   help='Choose an interface and a packet filter, or use -r to read an existing capture. Live capture may need administrator permission.',
   profiles={'regular':{'name':'Live packet summary','args':['-nn','-l','-c','100']},'payload':{'name':'Packet payloads','args':['-nn','-l','-X','-c','100']},'save':{'name':'Save packet capture','args':['-nn','-U','-c','100','-w','capture.pcap']},'interfaces':{'name':'List interfaces','args':['-D']}},
   utility=['-D','-L','-J','--version','--help','-d','-dd','-ddd']),
 'hydra': dict(name='Hydra', target_kind='service', target_option='$target', target_label='Target service URL', action='Run',
   help='Use a service URL such as ssh://host. Add a login (-l/-L) and password (-p/-P), or a login:password file (-C). Module-specific options use -m.',
   profiles={'regular':{'name':'Single host, stop on success','args':['-t','4','-f']},'serial':{'name':'One connection at a time','args':['-t','1','-f']},'verbose':{'name':'Show attempts','args':['-t','4','-f','-V']},'help':{'name':'Command help','args':['-h']}}, utility=['-h','-U','-R']),
 'john': dict(name='John the Ripper', target_kind='file', target_option='$input', target_label='Hash file', action='Run',
   help='Choose a hash file, then add a wordlist or a cracking mode. Choose --format when auto-detection is ambiguous. Potfiles and sessions are kept in this project.',
   profiles={'regular':{'name':'Wordlist / default recovery','args':[]},'single':{'name':'Single crack','args':['--single']},'incremental':{'name':'Incremental mode','args':['--incremental']},'show':{'name':'Show recovered passwords','args':['--show']},'formats':{'name':'List supported formats','args':['--list=formats']}},utility=['--help','--list','--test','--stress-test','--restore','--status','--stdout']),
 'hashcat': dict(name='Hashcat', target_kind='file', target_option='$input', target_label='Hash file', action='Run',
   help='Choose a hash file, hash type (-m), and attack mode (-a). Add a wordlist or mask from Input files and masks. Potfiles and restore state stay in this project.',
   profiles={'regular':{'name':'Dictionary attack','args':['--attack-mode','0']},'mask':{'name':'Mask attack','args':['--attack-mode','3']},'combination':{'name':'Combinator attack','args':['--attack-mode','1']},'hybrid':{'name':'Wordlist + mask','args':['--attack-mode','6']},'devices':{'name':'List compute devices','args':['--backend-info']}},utility=['--help','--version','--backend-info','--benchmark','--benchmark-pure','--hash-info','--example-hashes','--restore','--stdout']),
 'gobuster': dict(name='Gobuster', target_kind='url', target_option='--url', target_label='Target URL / domain', action='Scan',
   help='Choose a mode and target, then upload or select a wordlist (-w). DNS mode uses a domain; cloud bucket modes use only a wordlist.',
   modes=['dir','dns','vhost','fuzz','s3','gcs','tftp'],
   profiles={'regular':{'name':'Directory discovery','args':['dir','--threads','10']},'dns':{'name':'DNS subdomains','args':['dns','--threads','10']},'vhost':{'name':'Virtual hosts','args':['vhost','--append-domain','--threads','10']},'fuzz':{'name':'URL fuzzing','args':['fuzz','--threads','10']},'s3':{'name':'S3 buckets','args':['s3','--threads','10']},'gcs':{'name':'GCS buckets','args':['gcs','--threads','10']},'tftp':{'name':'TFTP files','args':['tftp','--threads','10']}}, utility=['--help','--version']),
 'ffuf': dict(name='ffuf', target_kind='fuzz-url', target_option='-u', target_label='Target URL (use FUZZ)', action='Scan',
   help='Place FUZZ in the URL, header, or POST data, and add a wordlist (-w). Multiple wordlists can use custom keywords (file:KEYWORD).',
   profiles={'regular':{'name':'Path discovery','args':['-noninteractive','-t','10']},'calibrated':{'name':'Auto-calibrated discovery','args':['-noninteractive','-ac','-t','10']},'recursive':{'name':'Recursive discovery','args':['-noninteractive','-recursion','-recursion-depth','2','-t','10']},'json':{'name':'JSON result stream','args':['-noninteractive','-json','-t','10']}},utility=['-h','-V','-search']),
 'aircrack-ng': dict(name='Aircrack-ng', target_kind='file', target_option='$input', target_label='Wireless capture file', action='Run',
   help='Choose an existing .cap/.pcap/.ivs capture. Select a BSSID (-b) or ESSID (-e), then a wordlist (-w) for WPA. This page audits saved captures; it does not configure monitor mode or capture handshakes.',
   profiles={'regular':{'name':'WPA/WPA2 wordlist audit','args':['-a','2']},'wep':{'name':'WEP capture audit','args':['-a','1']},'simd':{'name':'List SIMD support','args':['--simd-list']},'help':{'name':'Command help','args':['--help']}},utility=['--help','--simd-list','-u','-S']),
}


def mode_options(tool, mode=None):
    return [o for o in OPTIONS[tool] if not o.get('modes') or mode in o['modes']]


def parse_parts(tool, command):
    if not isinstance(command, str) or not command.strip() or len(command)>16000 or '\x00' in command:
        raise ValueError('Enter a command up to 16,000 characters.')
    tokens=shlex.split(command)
    if not tokens or tokens.pop(0) not in (tool, tool+'.exe'):
        raise ValueError(f'The command must begin with {tool}.')
    mode=None
    if tool=='gobuster' and tokens and not tokens[0].startswith('-'):
        mode=tokens.pop(0)
        if mode not in CONFIG[tool]['modes']+['help','version','completion']:
            raise ValueError('Choose a supported Gobuster mode.')
    lookup={alias:o for o in mode_options(tool,mode) for alias in o['aliases'] if not o['flag'].startswith('$')}
    parts=[];i=0
    while i<len(tokens):
        token=tokens[i]
        if token=='--':
            parts.extend({'positional':v} for v in tokens[i+1:]);break
        flag,sep,value=token.partition('=')
        option=lookup.get(flag)
        # Native getopt short options can bundle switches or attach a value (-c10).
        if option is None and token.startswith('-') and not token.startswith('--') and len(token)>2:
            first=lookup.get(token[:2])
            if first and first['kind'] not in ('flag','optional-value'):
                option=first;flag=first['flag'];sep='=';value=token[2:]
            elif all('-'+c in lookup and lookup['-'+c]['kind']=='flag' for c in token[1:]):
                parts.extend({'option':lookup['-'+c], 'value':None} for c in token[1:]);i+=1;continue
        if option is None:
            if token.startswith('-'):
                raise ValueError(f'Unknown {tool} option: {flag}. Choose an option from the parameter sidebar.')
            if tool=='tcpdump':
                parts.extend({'positional':v} for v in tokens[i:]);break
            parts.append({'positional':token});i+=1;continue
        kind=option['kind']
        if kind=='flag':
            if sep:raise ValueError(f'{flag} does not take a value.')
            value=None
        elif not sep:
            optional=kind=='optional-value'
            # John optional arguments must use =; otherwise the next token is a hash file.
            consume=i+1<len(tokens) and (not optional or (tool!='john' and not tokens[i+1].startswith('-')))
            if tool=='aircrack-ng' and flag=='-x' and optional:
                consume=i+1<len(tokens) and tokens[i+1].isdigit()
            if consume:
                if tokens[i+1].split('=',1)[0] in lookup:raise ValueError(f'{flag} requires a value.')
                i+=1;value=tokens[i]
            elif optional:value=None
            else:raise ValueError(f'{flag} requires a value.')
        if kind!='flag' and value=='' and option['flag']!='--status-codes-blacklist':raise ValueError(f'{flag} requires a value.')
        parts.append({'option':option,'value':value});i+=1
    return mode,parts


def tokens_from_parts(tool,mode,parts):
    result=[mode] if mode else []
    for part in parts:
        if 'positional' in part:result.append(part['positional']);continue
        flag=part['option']['flag'];value=part['value']
        if tool=='john' and value is not None:result.append(flag+'='+value)
        elif tool=='aircrack-ng' and flag=='-x' and value is not None:result.append(flag+value)
        else:
            result.append(flag)
            if value is not None:result.append(value)
    return result


class CliRunner(WebScanRunner):
    def __init__(self,store,locate,tool):
        NmapRunner.__init__(self,store,locate)
        self.tool=tool;self.options=OPTIONS[tool];self.profiles=CONFIG[tool]['profiles']
        self.validate_command=lambda command:tokens_from_parts(tool,*parse_parts(tool,command))
        self.execution_cwd=None;self.execution_env={};self.stop_file=None
        self.success_codes={0,1} if tool=='hashcat' else {0}

    def status(self,ident):
        result=super().status(ident)
        result['workspace']={**CONFIG[self.tool],'reference':REFERENCES[self.tool]}
        if self.tool=='tcpdump':
            try:result['workspace']['interfaces']=[name for _,name in socket.if_nameindex()]
            except OSError:result['workspace']['interfaces']=[]
            names=result['workspace']['interfaces']
            result['workspace']['default_interface']='any' if sys.platform.startswith('linux') else names[0] if names else '1'
            result['workspace']['can_elevate']=os.name=='posix' and bool(shutil.which('pkexec') or shutil.which('sudo'))
        return result

    def _validate_inputs(self,mode,parts):
        flags={p['option']['flag']:p['value'] for p in parts if 'option' in p}
        positional=[p['positional'] for p in parts if 'positional' in p]
        utility=bool(set(flags)&set(CONFIG[self.tool]['utility'])) or (self.tool=='gobuster' and mode in ('help','version','completion'))
        # Check file paths before registering a job. ffuf permits a :KEYWORD suffix.
        for part in parts:
            option=part.get('option');value=part.get('value')
            if not option or not value or option['kind'] not in ('file','file-or-value'):continue
            path=value
            if self.tool=='ffuf' and option['flag']=='-w' and not Path(path).is_file() and ':' in path:path=path.rsplit(':',1)[0]
            if self.tool=='aircrack-ng' and option['flag']=='-w':
                if not all(Path(p).is_file() for p in path.split(',')):raise ValueError('Choose existing wordlist files for -w.')
            elif option['kind']=='file' and not Path(path).is_file():raise ValueError(f"Choose an existing file for {option['flag']} or upload it.")
        if utility:
            if self.tool=='hydra' and '-U' in flags and not positional:
                raise ValueError('Add a service module name, for example hydra -U ssh.')
            return flags,positional,utility
        if self.tool=='tcpdump':
            if not ('-r' in flags or '-V' in flags or flags.get('-i')):raise ValueError('Choose a capture interface or an input capture (-r).')
        elif self.tool=='hydra':
            if not ('-C' in flags or ('-l' in flags or '-L' in flags) and ('-p' in flags or '-P' in flags or '-x' in flags or '-e' in flags)):
                raise ValueError('Choose a login (-l/-L) and password source (-p/-P), or a login:password file (-C).')
            if not positional:raise ValueError('Enter a service URL or service name for the server list.')
            if '://' in positional[0]:
                parsed=urlsplit(positional[0])
                if not parsed.scheme or not parsed.hostname or any(c.isspace() for c in positional[0]):raise ValueError('Enter a valid service URL such as ssh://host.')
        elif self.tool in ('john','hashcat','aircrack-ng'):
            if not positional or not Path(positional[0]).is_file():raise ValueError('Choose an existing hash file.' if self.tool!='aircrack-ng' else 'Choose an existing wireless capture file.')
            if self.tool=='hashcat' and not any(f in flags for f in ('--show','--left','--identify')):
                attack=flags.get('--attack-mode','0');extra=positional[1:]
                if attack in ('0','1','6','7','9') and not extra:raise ValueError('Add the wordlist or candidate input required by this attack mode.')
                if attack=='1' and len(extra)<2:raise ValueError('Combinator mode requires two wordlists.')
                if attack in ('6','7') and len(extra)<2:raise ValueError('Hybrid mode requires a wordlist and a mask.')
                if attack=='3' and not extra:raise ValueError('Add a mask or mask file for mask mode.')
                if attack in ('0','1') and not all(Path(f).is_file() for f in extra):raise ValueError('Choose existing candidate wordlists.')
            if self.tool=='aircrack-ng' and flags.get('-a','2')=='2' and '-w' not in flags and '-r' not in flags:raise ValueError('Choose a WPA wordlist (-w) or airolib database (-r).')
        elif self.tool=='gobuster':
            if not mode:raise ValueError('Choose a Gobuster mode.')
            if '--wordlist' not in flags:raise ValueError('Choose a wordlist (-w).')
            target_flag='--domain' if mode=='dns' else '--server' if mode=='tftp' else '--url'
            if mode not in ('s3','gcs') and not flags.get(target_flag):raise ValueError('Enter the target for this Gobuster mode.')
            if mode in ('dir','vhost','fuzz'):web_target(flags[target_flag])
            if mode=='dns':network_target(flags[target_flag])
        elif self.tool=='ffuf':
            if not flags.get('-u') and '-request' not in flags:raise ValueError('Enter a target URL or choose an HTTP request file (-request).')
            if flags.get('-u'):web_target(flags['-u'])
            if '-w' not in flags and '-input-cmd' not in flags:raise ValueError('Choose a wordlist (-w) or an input command.')
            # Named keywords may appear in the URL, headers or body; ffuf validates them.
        return flags,positional,utility

    def _native_command(self,ident,mode,parts,directory,scanid):
        state=self.store._directory(ident)/(self.tool+'-state');state.mkdir(exist_ok=True)
        self.execution_cwd=str(state.resolve());self.execution_env={'XDG_CACHE_HOME':str((state/'cache').resolve())}
        scoped=deepcopy(parts)
        existing={p['option']['flag'] for p in scoped if 'option' in p}
        def append(flag,value=None):
            option=next(o for o in self.options if o['flag']==flag)
            scoped.append({'option':option,'value':value});existing.add(flag)
        for part in scoped:
            option=part.get('option');value=part.get('value')
            if not option or value is None:
                if self.tool in ('john','hashcat','aircrack-ng') and 'positional' in part and Path(part['positional']).is_file():part['positional']=str(Path(part['positional']).resolve())
                continue
            kind=option['kind'];flag=option['flag']
            if kind.startswith('output'):
                name=re.sub(r'[^a-zA-Z0-9_.-]','_',Path(value.replace('\\','/')).name).strip('.') or 'output'
                destination=directory/(scanid+'-'+name)
                if kind=='output-directory':destination.mkdir(exist_ok=True)
                part['value']=str(destination.resolve())
            elif kind.startswith('state-') or (self.tool=='john' and flag in ('--restore','--status')):
                name=re.sub(r'[^a-zA-Z0-9_.-]','_',Path(value.replace('\\','/')).name).strip('.') or 'default'
                destination=state/name
                if kind=='state-directory':destination.mkdir(exist_ok=True)
                elif kind=='state-file' and Path(value).is_file() and Path(value).resolve()!=destination.resolve():
                    shutil.copyfile(value,destination)
                part['value']=str(destination.resolve())
            elif kind in ('file','file-or-value'):
                suffix='';filename=value
                if self.tool=='ffuf' and flag=='-w' and not Path(filename).is_file() and ':' in filename:
                    filename,key=filename.rsplit(':',1);suffix=':'+key
                if Path(filename).is_file():part['value']=str(Path(filename).resolve())+suffix
                elif self.tool=='aircrack-ng' and flag=='-w':part['value']=','.join(str(Path(f).resolve()) for f in filename.split(','))
        if self.tool=='tcpdump':
            # Offline reads must not request a live interface.
            if '-r' in existing or '-V' in existing:scoped=[p for p in scoped if p.get('option',{}).get('flag')!='-i']
            if '-l' not in existing and '-w' not in existing:append('-l')
        elif self.tool=='hydra':
            if '-U' in existing or '-M' in existing:
                for p in scoped:
                    if 'positional' in p and '://' in p['positional']:
                        p['positional']=urlsplit(p['positional']).scheme
            if '-I' not in existing and '-R' not in existing:append('-I')
        elif self.tool=='john':
            if '--pot' not in existing:append('--pot',str((state/'john.pot').resolve()))
            if not existing&{'--restore','--status','--session','--help','--list'}:append('--session',str((state/'default').resolve()))
            for p in scoped:
                if p.get('option',{}).get('flag') in ('--restore','--status') and p['value'] is None:p['value']=str((state/'default').resolve())
        elif self.tool=='hashcat':
            if '--potfile-path' not in existing:append('--potfile-path',str((state/'hashcat.pot').resolve()))
            if '--restore-file-path' not in existing:append('--restore-file-path',str((state/'hashcat.restore').resolve()))
            if '--logfile-disable' not in existing:append('--logfile-disable')
            if '--status' not in existing:append('--status')
        elif self.tool=='gobuster' and not (existing&set(CONFIG[self.tool]['utility']) or mode in ('help','version','completion')):
            if '--no-progress' not in existing:append('--no-progress')
            if '--no-color' not in existing:append('--no-color')
        elif self.tool=='ffuf':
            if '-noninteractive' not in existing:append('-noninteractive')
        # Flags must precede positional arguments (in particular tcpdump's BPF filter).
        scoped=[p for p in scoped if 'option' in p]+[p for p in scoped if 'positional' in p]
        return tokens_from_parts(self.tool,mode,scoped)

    def start(self,ident,data):
        mode,parts=parse_parts(self.tool,data.get('command',''))
        flags,positional,utility=self._validate_inputs(mode,parts)
        binary=self.locate(self.tool)
        if not binary:raise ValueError(f'{CONFIG[self.tool]["name"]} is not installed. Install it from the startscreen.')
        self.store.get(ident)
        with self.lock:
            if self.running:raise ValueError('A run is already active. Stop it or wait for completion.')
            scanid=uuid.uuid4().hex;directory=self.store._directory(ident)/'scans'/self.tool
            directory.mkdir(parents=True,exist_ok=True)
            native=self._native_command(ident,mode,parts,directory,scanid)
            args=tokens_from_parts(self.tool,mode,parts)
            admin=self.tool=='tcpdump' and not utility and '-r' not in flags and '-V' not in flags and data.get('elevate') is True and os.name=='posix' and os.geteuid()!=0
            command=[binary]+native;self.stop_file=directory/(scanid+'.stop')
            if admin:
                if '-Z' not in native:command=[binary,'-Z',getpass.getuser()]+native
                wrapper=[sys.executable,str(Path(__file__).with_name('capture_privileged.py').resolve()),'--stop-file',str(self.stop_file.resolve()),'--command',json.dumps(command)]
                if shutil.which('pkexec'):command=['pkexec']+wrapper
                elif shutil.which('sudo'):command=['sudo','-n']+wrapper
                else:raise ValueError('No administrator authentication helper is available. Configure capture permissions or use offline capture files.')
            target=next((flags.get(f) for f in ('--url','-u','--domain','--server','-r','-i') if flags.get(f)),None)
            if positional:target=' '.join(positional)
            self.current={'id':scanid,'project_id':ident,'target':target or 'Utility command','profile':str(data.get('profile','custom'))[:100],
                          'command':shlex.join([self.tool]+args),'executed_command':shlex.join([self.tool]+native),'created_at':datetime.now(timezone.utc).isoformat(),
                          'status':'running','output':'','error':None,'admin':admin}
            self.current=self.store.save_scan(ident,deepcopy(self.current),self.tool)
            self.cancelled=False;self.process=None;self._finishing=True
            threading.Thread(target=self._run_web,args=(command,directory/(scanid+'.txt')),daemon=True).start()
            return deepcopy(self.current)

    def _signal(self,kill=False):
        if self.current and self.current.get('admin') and self.stop_file:
            self.stop_file.touch()
            return
        return super()._signal(kill)
