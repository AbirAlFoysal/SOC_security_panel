"""Project-scoped Hakrawler with stdin URL input and global presets."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import ipaddress
import shlex
import subprocess
import threading
import uuid
from urllib.parse import urlsplit
from nmap_runner import NmapRunner

OPTIONS = [
    ('-d','Crawl depth','value','2','Maximum link depth to follow. Default: 2.'),
    ('-dr','Do not follow redirects','flag','','Keep requests from following HTTP redirects.'),
    ('-h','Custom HTTP headers','value','Cookie: foo=bar;;Referer: https://example.com/','Separate multiple request headers with two semicolons.'),
    ('-i','Stay inside target path','flag','','Only crawl pages inside the initial URL path.'),
    ('-insecure','Skip TLS verification','flag','','Allow HTTPS connections without verifying the server certificate.'),
    ('-json','JSON output','flag','','Return structured JSON results including source information.'),
    ('-proxy','Proxy URL','value','http://127.0.0.1:8080','Send requests through this proxy.'),
    ('-s','Show source type','flag','','Show whether a URL came from a link, form, script, or another source.'),
    ('-size','Maximum page size','value','1024','Page size limit in KB. Use -1 for no limit.'),
    ('-subs','Include subdomains','flag','','Include subdomains of the target in crawl scope.'),
    ('-t','Worker threads','value','8','Concurrent crawl workers. Default: 8.'),
    ('-timeout','Timeout per target','value','30','Maximum seconds to crawl each URL. Use -1 for no per-URL limit.'),
    ('-u','Unique URLs only','flag','','Filter duplicate URLs from output.'),
    ('-w','Show referring page','flag','','Show the page where each URL was discovered.'),
]
CATALOG=[{'flag':f,'name':n,'kind':k,'hint':h,'description':d,'group':'Crawler options','admin':False,'exclusive':None} for f,n,k,h,d in OPTIONS]
BY_FLAG={o['flag']:o for o in CATALOG}
PROFILES={
    'regular':{'name':'Regular crawl','args':['-d','2','-u','-json']},
    'shallow':{'name':'Shallow crawl','args':['-d','1','-u','-json']},
    'deep':{'name':'Deep crawl','args':['-d','4','-u','-json']},
    'subdomains':{'name':'Include subdomains','args':['-d','2','-subs','-u','-json']},
}


def parse_command(command):
    if not isinstance(command,str) or len(command)>16000:
        raise ValueError('Command must be text up to 16,000 characters.')
    tokens=shlex.split(command)
    if not tokens or tokens.pop(0) not in ('hakrawler','hakrawler.exe'):
        raise ValueError('The command must start with hakrawler. Enter target URLs in the Target field; they are supplied through stdin.')
    args=[];i=0
    while i<len(tokens):
        flag=tokens[i];value=None
        if '=' in flag:flag,value=flag.split('=',1)
        if flag not in BY_FLAG:raise ValueError(f'Unknown Hakrawler option: {flag}')
        option=BY_FLAG[flag]
        if option['kind']=='value':
            if value is None:
                i+=1
                if i>=len(tokens):raise ValueError(f'{flag} requires a value.')
                value=tokens[i]
            if not value or '\x00' in value:raise ValueError(f'{flag} requires a value.')
            if flag in ('-d','-t','-size','-timeout'):
                try:number=int(value)
                except ValueError:raise ValueError(f'{flag} requires a whole number.')
                if number<1 and not (number==-1 and flag in ('-size','-timeout')):
                    raise ValueError(f'{flag} requires a positive number'+(' or -1.' if flag in ('-size','-timeout') else '.'))
            if flag=='-proxy' and urlsplit(value).scheme not in ('http','https','socks5','socks4'):
                raise ValueError('Enter a supported proxy URL.')
            args.extend([flag,value])
        else:
            if value is not None:
                if value not in ('true','false'):raise ValueError(f'{flag} takes true or false.')
                args.append(flag+'='+value)
            else:args.append(flag)
        i+=1
    return args


def targets(text):
    if not isinstance(text,str) or len(text)>262144:raise ValueError('Provide up to 256 KB of target URLs.')
    result=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        if '://' not in line:
            try:
                address=ipaddress.ip_address(line)
                line='http://'+('['+str(address)+']' if address.version==6 else str(address))
            except ValueError:
                candidate=urlsplit('//'+line)
                try:ipaddress.ip_address(candidate.hostname or '')
                except ValueError:line='https://'+line
                else:line=('https://' if candidate.port in (443,8443) else 'http://')+line
        parsed=urlsplit(line)
        if parsed.scheme not in ('http','https') or not parsed.hostname or any(c.isspace() for c in line) or parsed.username or parsed.password:
            raise ValueError('Targets must be HTTP or HTTPS URLs, one per line.')
        if line not in result:result.append(line)
    if not result:raise ValueError('Enter at least one URL or load a URL list.')
    if len(result)>5000:raise ValueError('Use at most 5,000 target URLs per crawl.')
    return result


class HakrawlerRunner(NmapRunner):
    tool='hakrawler'
    profiles=PROFILES
    options=CATALOG
    validate_command=staticmethod(parse_command)

    def start(self,ident,data):
        urls=targets(data.get('target',''))
        args=parse_command(data.get('command','hakrawler -d 2 -u -json'))
        binary=self.locate(self.tool)
        if not binary:raise ValueError('Hakrawler is not installed. Install it from the startscreen.')
        self.store.get(ident)
        with self.lock:
            if self.running:raise ValueError('A crawl is already running. Stop it or wait for it to finish.')
            scanid=uuid.uuid4().hex
            directory=self.store._directory(ident)/'scans'/self.tool;directory.mkdir(parents=True,exist_ok=True)
            (directory/(scanid+'-targets.txt')).write_text('\n'.join(urls)+'\n',encoding='utf-8')
            command=shlex.join(['hakrawler']+args)
            title=shlex.join(['printf','%s\\n']+urls)+' | '+command
            self.current={'id':scanid,'project_id':ident,'target':'\n'.join(urls),'profile':str(data.get('profile','custom'))[:100],
                          'command':title,'options_command':command,'created_at':datetime.now(timezone.utc).isoformat(),
                          'status':'running','output':'','urls':[],'error':None,'admin':False}
            self.current=self.store.save_scan(ident,self.current,self.tool)
            self._finishing=True;self.cancelled=False;self.process=None
            threading.Thread(target=self._crawl,args=([binary]+args,urls,directory/(scanid+'.txt')),daemon=True).start()
            return deepcopy(self.current)

    def _crawl(self,command,urls,output):
        timer=None;writer=None;writer_errors=[]
        try:
            proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace')
            with self.lock:
                self.process=proc
                if self.cancelled:proc.terminate()
            timer=threading.Timer(1800,proc.kill);timer.start()
            def feed():
                try:proc.stdin.write('\n'.join(urls)+'\n');proc.stdin.close()
                except (BrokenPipeError,OSError) as exc:writer_errors.append(str(exc))
            writer=threading.Thread(target=feed,daemon=True);writer.start()
            seen=set()
            with output.open('w',encoding='utf-8') as file:
                for line in proc.stdout:
                    file.write(line);file.flush()
                    row=None
                    try:
                        item=json.loads(line)
                        if isinstance(item,dict):
                            normalized={k.lower():v for k,v in item.items()}
                            url=normalized.get('url')
                            if isinstance(url,str):row={'url':url,'source':str(normalized.get('source','')),'where':str(normalized.get('where',''))}
                    except ValueError:pass
                    if row is None:
                        # Non-JSON modes remain supported; preserve the full line in raw output.
                        for value in line.split():
                            if value.startswith(('http://','https://')):
                                row={'url':value,'source':'','where':''};break
                    with self.lock:
                        self.current['output']=(self.current['output']+line)[-262144:]
                        if row and row['url'] not in seen and len(seen)<10000:
                            seen.add(row['url']);self.current['urls'].append(row)
            code=proc.wait();writer.join(timeout=2)
            with self.lock:
                self.current.update(status='cancelled' if self.cancelled else 'completed' if code==0 else 'failed',exit_code=code,finished_at=datetime.now(timezone.utc).isoformat())
                if code==0 and not self.cancelled and not self.current['urls']:
                    self.current['warning']='No links were discovered. IP addresses are supported: check the web service protocol (HTTP/HTTPS), port, path, and any redirects. Some sites require their domain name for virtual hosting.'
                if code and not self.cancelled:self.current['error']=f'Hakrawler exited with code {code}. See output.'
        except Exception as exc:
            with self.lock:self.current.update(status='failed',error=str(exc),finished_at=datetime.now(timezone.utc).isoformat())
        finally:
            if timer:timer.cancel()
            with self.lock:
                try:self.store.save_scan(self.current['project_id'],deepcopy(self.current),self.tool)
                except Exception as exc:self.current['error']=f'Unable to save crawl results: {exc}'
                if self.process:
                    if self.process.poll() is None:
                        self.process.kill();self.process.wait()
                    try:
                        if self.process.stdin and not self.process.stdin.closed:self.process.stdin.close()
                    except OSError:
                        pass
                    if self.process.stdout:self.process.stdout.close()
                self.process=None;self._finishing=False
