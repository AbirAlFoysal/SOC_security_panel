"""Nmap reference options, matching the local 7.98 help and manual."""
import shlex
import re
from pathlib import Path

OPTIONS = []
def group(name, rows):
    for row in rows.strip().splitlines():
        flag, title, kind, hint, description = row.split('|')
        OPTIONS.append({'flag':flag, 'name':title, 'kind':kind or 'flag', 'hint':hint,
                        'description':description, 'group':name})

group('Scan techniques', '''
-sT|TCP connect scan|||Complete TCP connections using the operating system.
-sS|TCP SYN scan|||Probe TCP ports using SYN packets; requires raw-packet privileges.
-sU|UDP scan|||Probe UDP services; usually requires administrator privileges.
-sA|TCP ACK scan|||Examine firewall filtering with TCP ACK probes.
-sW|TCP window scan|||Use TCP response windows to distinguish port states.
-sM|TCP Maimon scan|||Send FIN/ACK probes to assess TCP ports.
-sN|TCP NULL scan|||Send TCP probes with no flags set.
-sF|TCP FIN scan|||Probe TCP ports using the FIN flag.
-sX|TCP Xmas scan|||Probe with FIN, PSH, and URG flags set.
-sY|SCTP INIT scan|||Discover SCTP services with INIT probes.
-sZ|SCTP COOKIE ECHO scan|||Probe SCTP ports using COOKIE ECHO packets.
-sO|IP protocol scan|||Discover supported IP protocols instead of TCP/UDP ports.
-sI|Idle scan|value|host[:port]|Use the specified idle host for an idle scan.
-b|FTP bounce scan|value|relay host|Use an FTP relay for a bounce scan.
--scanflags|Custom TCP flags|value|SYN,ACK|Specify the TCP flag combination for probes.
''')
group('Targets', '''
-iL|Targets from file|file|targets.txt|Read hosts and networks from an uploaded or local file.
-iR|Random targets|value|number of hosts|Generate the specified number of random target addresses.
--exclude|Exclude targets|value|host1,host2|Leave the listed hosts or networks out of the scan.
--excludefile|Exclusions from file|file|exclude.txt|Read excluded targets from a file.
--resolve-all|Scan every resolved address|||Scan all addresses returned for each host name.
--unique|Scan each address once|||Remove duplicate addresses from the target set.
--randomize-hosts|Randomize host order|||Shuffle target host order before scanning.
''')
group('Host discovery', '''
-sL|List targets only|||List target addresses without performing a port scan.
-sn|Host discovery only|||Discover hosts without scanning their ports.
-Pn|Skip host discovery|||Treat targets as online and proceed to scanning.
-PS|TCP SYN discovery|optional|80,443|Use SYN probes to discover hosts; an omitted list uses Nmap defaults.
-PA|TCP ACK discovery|optional|80|Use ACK probes for host discovery.
-PU|UDP discovery|optional|53|Use UDP probes for host discovery.
-PY|SCTP INIT discovery|optional|80|Use SCTP INIT probes for host discovery.
-PE|ICMP echo discovery|||Use ICMP echo requests to discover hosts.
-PP|ICMP timestamp discovery|||Send ICMP timestamp requests during discovery.
-PM|ICMP netmask discovery|||Send ICMP address mask requests during discovery.
-PO|IP protocol discovery|optional|1,2,4|Probe the listed IP protocols for host discovery.
-PR|ARP discovery|||Use ARP probes for local Ethernet discovery.
--disable-arp-ping|Disable ARP discovery|||Avoid automatic ARP or IPv6 neighbor discovery.
--discovery-ignore-rst|Ignore discovery resets|||Do not treat TCP resets as evidence that a host is online.
-n|Disable reverse DNS|||Skip reverse DNS lookups.
-R|Always resolve DNS|||Perform reverse DNS lookups for all target addresses.
--dns-servers|Custom DNS servers|value|192.0.2.53,192.0.2.54|Send DNS queries to the specified resolvers.
--system-dns|System DNS resolver|||Use the operating system resolver.
--traceroute|Trace route|||Estimate the network path to discovered hosts.
''')
group('Ports and order', '''
-p|Specify ports|value|22,80,443 or 1-1024|Select port numbers or ranges; protocol prefixes are supported.
-p-|All ports|||Scan the full port range, 1 through 65535.
--exclude-ports|Exclude ports|value|135,139,445|Skip these ports in scanning and discovery.
-F|Fast scan|||Scan a smaller set of frequently used ports.
-r|Sequential port order|||Scan ports in numerical order instead of shuffling them.
--top-ports|Most common ports|value|100|Scan this many ports ranked by frequency.
--port-ratio|Port frequency threshold|value|0.01|Scan ports whose frequency exceeds this ratio.
''')
group('Service detection', '''
-sV|Detect service versions|||Probe discovered services to identify software and versions.
--allports|Probe every port|||Do not skip ports normally excluded from version detection.
--version-intensity|Version probe intensity|value|0–9|Choose how extensively to probe services.
--version-light|Light version detection|||Use a reduced set of version probes.
--version-all|All version probes|||Try every available version probe.
--version-trace|Trace version probes|||Display detailed version-detection activity.
''')
group('Nmap scripts', '''
-sC|Default scripts|||Run Nmap's default script selection.
--script|Select scripts|script|default or script selection|Choose installed script names, categories, expressions, or an uploaded script/directory.
--script-args|Script arguments|value|key=value,key2=value2|Provide named arguments to NSE scripts.
--script-args-file|Script arguments file|file|arguments.txt|Read NSE arguments from a file.
--script-timeout|Script time limit|value|30s|Limit how long each script may run.
--script-trace|Trace script traffic|||Display communications sent and received by NSE scripts.
--script-updatedb|Rebuild script index|||Rebuild the installed NSE script index; this may require write permissions.
--script-help|Script help|script|default or script name|Display documentation for the selected scripts.
''')
group('Operating system', '''
-O|Detect operating system|||Fingerprint the target operating system; requires raw-packet privileges.
--osscan-limit|Limit OS detection|||Only fingerprint hosts with suitable open and closed ports.
--osscan-guess|Aggressive OS guesses|||Show less certain operating-system matches.
--fuzzy|Fuzzy OS matching|||Alias for aggressive operating-system guesses.
--max-os-tries|OS detection attempts|value|number|Limit OS fingerprinting retries per host.
-A|Advanced detection|||Enable OS detection, service versions, default scripts, and traceroute.
''')
group('Timing and performance', '''
-T|Timing template|value|0–5|Choose a numeric Nmap timing template.
-T0|Paranoid timing|||Use timing template 0.
-T1|Sneaky timing|||Use timing template 1.
-T2|Polite timing|||Use timing template 2.
-T3|Normal timing|||Use timing template 3.
-T4|Aggressive timing|||Use timing template 4.
-T5|Insane timing|||Use timing template 5.
--min-hostgroup|Minimum host group|value|number|Set the minimum number of hosts scanned together.
--max-hostgroup|Maximum host group|value|number|Set the maximum number of hosts scanned together.
--min-parallelism|Minimum parallel probes|value|number|Set a lower bound on outstanding probes.
--max-parallelism|Maximum parallel probes|value|number|Limit outstanding probes.
--min-rtt-timeout|Minimum RTT timeout|value|100ms|Set the minimum probe response timeout.
--max-rtt-timeout|Maximum RTT timeout|value|1s|Set the maximum probe response timeout.
--initial-rtt-timeout|Initial RTT timeout|value|1s|Set the initial response timeout estimate.
--max-retries|Probe retries|value|number|Limit retransmissions of individual probes.
--host-timeout|Host time limit|value|5m|Stop scanning a host after this time.
--scan-delay|Delay between probes|value|100ms|Wait between probes sent to the same host.
--max-scan-delay|Maximum probe delay|value|1s|Limit adaptive delays between probes.
--min-rate|Minimum packet rate|value|packets per second|Request a minimum outgoing packet rate.
--max-rate|Maximum packet rate|value|packets per second|Limit outgoing packets per second.
--defeat-rst-ratelimit|Ignore RST rate limits|||Prioritize speed over distinguishing closed ports behind reset rate limits.
--defeat-icmp-ratelimit|Ignore ICMP rate limits|||Prioritize UDP scanning speed when ICMP errors are rate-limited.
--nsock-engine|Socket engine|value|epoll, poll, or select|Choose an available Nsock I/O engine.
''')
group('Packet and network options', '''
-f|Fragment packets|||Split suitable raw probes into small IP fragments.
--mtu|Custom fragment size|value|multiple of 8|Set the fragment size for applicable raw probes.
-D|Decoy addresses|value|address1,ME,address2|Include decoy source addresses in supported scans.
-S|Source IP address|value|source IP|Specify the source address for applicable probes.
-e|Network interface|value|interface name|Choose the network interface Nmap uses.
-g|Source port|value|port number|Choose a source port for supported probes.
--source-port|Source port (long form)|value|port number|Long-form source-port selection.
--proxies|Proxy servers|value|http://host:port|Use supported HTTP/SOCKS proxies for compatible connections.
--data|Hexadecimal payload|value|hex bytes|Append hexadecimal payload bytes to probes.
--data-string|Text payload|value|text|Append text payload to probes.
--data-length|Random payload length|value|bytes|Append random payload bytes of this length.
--ip-options|IP header options|value|options|Specify IP header options for applicable probes.
--ttl|IP time to live|value|number|Set the IP TTL for applicable probes.
--spoof-mac|Probe source MAC|value|MAC, prefix, or vendor|Set source MAC bytes in raw Ethernet probes; does not change the adapter setting.
--badsum|Invalid checksums|||Send deliberately incorrect transport checksums.
--adler32|SCTP Adler32 checksum|||Use the legacy Adler32 checksum for SCTP probes.
--send-eth|Send Ethernet frames|||Send raw probes using Ethernet frames.
--send-ip|Send IP packets|||Send raw probes at the IP layer.
''')
group('Output and diagnostics', '''
-oN|Normal output file|output|scan.txt|Write normal-format output inside the project's scan folder.
-oX|XML output file|output|scan.xml|Write structured XML inside the project's scan folder.
-oS|Stylized output file|output|scan.txt|Write Nmap's stylized output format inside the project.
-oG|Grepable output file|output|scan.gnmap|Write grepable-format output inside the project.
-oA|All output formats|output|scan|Write normal, XML, and grepable files with this project-local basename.
-v|Verbose output|||Increase the amount of progress and scan information.
-vv|More verbose output|||Use two levels of verbosity.
-d|Debug output|||Enable debugging output.
-dd|Detailed debug output|||Use two levels of debugging output.
--reason|Explain port states|||Show why Nmap assigned each host or port state.
--open|Show open ports only|||Restrict port output to open or possibly open ports.
--packet-trace|Trace packets|||Display packet-level send and receive activity.
--iflist|List interfaces|||Print detected network interfaces and routes.
--append-output|Append scan output|||Append rather than replace requested output files.
--resume|Resume saved scan|file|scan output file|Resume a scan from compatible normal or grepable output; Nmap controls resumed options.
--noninteractive|Disable keyboard controls|||Turn off interactive runtime keyboard commands.
--stats-every|Progress interval|value|5s|Print progress statistics at the requested interval.
--log-errors|Log warnings to output|||Include warnings and errors in normal-format output where supported.
--stylesheet|XML stylesheet|file|stylesheet.xsl|Associate an uploaded or local stylesheet with XML output.
--webxml|Online XML stylesheet|||Reference the Nmap-hosted XML stylesheet.
--no-stylesheet|No XML stylesheet|||Do not reference a stylesheet in XML output.
''')
group('Miscellaneous', '''
-6|IPv6 scanning|||Use IPv6 addresses and probes.
--datadir|Nmap data directory|directory|directory path|Choose a local or uploaded directory containing Nmap data files.
--servicedb|Service database file|file|nmap-services|Use a custom service-name and frequency database.
--versiondb|Version probe database|file|nmap-service-probes|Use a custom service-probe database.
--privileged|Assume raw privileges|||Tell Nmap that raw-packet privileges are available.
--unprivileged|Assume no raw privileges|||Tell Nmap not to assume raw-packet privileges.
--release-memory|Release memory before exit|||Perform additional memory cleanup before exiting.
-V|Version information|||Print the installed Nmap version.
--version|Version information (long)|||Print the installed Nmap version.
-h|Nmap help|||Print the installed Nmap help summary.
--help|Nmap help (long)|||Print the installed Nmap help summary.
''')

RAW_FLAGS = {'-PE','-PP','-PM','-PR','-PO','-PS','-PA','-PU','-PY','-sS','-sU','-sA','-sW','-sM','-sN','-sF','-sX','-sY','-sZ','-sO','-sI','-O','-A','-f','--mtu','-D','-S','--spoof-mac','--send-eth','--send-ip','--privileged'}
TCP_FLAGS = {'-sT','-sS','-sA','-sW','-sM','-sN','-sF','-sX'}
for option in OPTIONS:
    option['admin'] = option['flag'] in RAW_FLAGS
    option['exclusive'] = 'tcp' if option['flag'] in TCP_FLAGS else 'timing' if re.fullmatch('-T[0-5]?',option['flag']) else 'ports' if option['flag'] in ('-p','-p-','-F','--top-ports','--port-ratio') else None
BY_FLAG = {option['flag']:option for option in OPTIONS}


def parse_command(command):
    if not isinstance(command,str) or len(command)>16000:
        raise ValueError('Command must be text up to 16,000 characters.')
    try:
        tokens=shlex.split(command)
    except ValueError as exc:
        raise ValueError(f'Invalid command quoting: {exc}')
    if not tokens or tokens.pop(0) not in ('nmap','nmap.exe'):
        raise ValueError('The command must begin with nmap.')
    normalized=[]; targets=[]; admin=False; i=0
    while i<len(tokens):
        token=tokens[i]
        if not token.startswith('-'):
            targets.append(token); normalized.append(token); i+=1; continue
        flag=token; attached=None
        if '=' in token and token.startswith('--'):
            flag,attached=token.split('=',1)
        option=BY_FLAG.get(flag)
        if not option:
            # Support Nmap's compact short options: -p80, -PS443, -d3, -v2.
            if re.fullmatch(r'-(?:[vd][0-9]+|v{3,}|d{3,})',token):
                normalized.append(token);i+=1;continue
            for short in sorted((k for k in BY_FLAG if k.startswith('-') and not k.startswith('--')),key=len,reverse=True):
                if token.startswith(short) and len(token)>len(short) and BY_FLAG[short]['kind'] in ('value','optional','file','output','script','directory'):
                    flag=short;attached=token[len(short):];option=BY_FLAG[short];break
        if not option:
            # Combined scan selectors, e.g. -sSU.
            if token.startswith('-s') and len(token)>3 and all('-s'+c in BY_FLAG for c in token[2:]):
                admin=admin or any('-s'+c in RAW_FLAGS for c in token[2:]);normalized.append(token);i+=1;continue
            raise ValueError(f'Unknown Nmap option: {token}. Use a listed parameter.')
        admin=admin or option['admin']
        kind=option['kind']; value=attached
        if kind in ('value','file','output','script','directory') and value is None:
            i+=1
            if i>=len(tokens) or tokens[i].startswith('-'):
                raise ValueError(f'{flag} needs a value.')
            value=tokens[i]
        if kind=='flag' and attached is not None:
            raise ValueError(f'{flag} does not take a value.')
        normalized.append(flag)
        if value is not None:
            if not value or '\x00' in value:
                raise ValueError(f'{flag} needs a nonempty value.')
            if kind=='optional':
                normalized[-1]=flag+value
            else:
                normalized.append(value)
        i+=1
    if not targets and not any(f in normalized for f in ('-iL','-iR','--resume','--iflist','-h','--help','-V','--version','--script-help','--script-updatedb')):
        raise ValueError('Enter a target or use a target-list parameter.')
    for item in targets:
        if any(c in item for c in (';', '|', '&', '$', '`','\n','\r')):
            raise ValueError('Targets must be host names, IPs, ranges, or networks.')
    return normalized, targets, admin
