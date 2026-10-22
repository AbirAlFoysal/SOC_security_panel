#!/usr/bin/python3
"""Desktop Makefile helper. Keeps restoration state across separate make calls."""
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

STATE_DIR = Path('/var/lib/desktop-anon')
STATE = STATE_DIR / 'state.json'
PUBLIC_STATE = Path('/run/desktop-anon-status.json')


def publish(saved):
    # Only expose the interface needed by the unprivileged web status reader.
    fd, name = tempfile.mkstemp(prefix='.desktop-anon-', dir='/run')
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump({'iface': saved['iface']}, handle)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o644)
        os.replace(name, PUBLIC_STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(*args, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check).stdout.strip()


def restore(saved):
    iface, uuid = saved['iface'], saved['uuid']
    run('nmcli', '--wait', '20', 'device', 'disconnect', iface, check=False)
    run('ip', 'link', 'set', 'dev', iface, 'down')
    print(run('macchanger', '--mac', saved['mac'], iface), flush=True)
    run('nmcli', 'connection', 'modify', '--temporary', 'uuid', uuid,
        saved['property'], saved['setting'])
    run('ip', 'link', 'set', 'dev', iface, 'up')
    run('nmcli', '--wait', '60', 'connection', 'up', 'uuid', uuid, 'ifname', iface)
    STATE.unlink()
    PUBLIC_STATE.unlink(missing_ok=True)
    print('Original connection settings restored.', flush=True)


def stop():
    # If Tor cleanup fails, retain the state and do not tear down the connection.
    print(run('anonsurf', 'stop'), flush=True)
    if STATE.exists():
        restore(json.loads(STATE.read_text()))
    else:
        print('No MAC change saved by this Makefile; nothing to restore.')


def start(iface, with_anonsurf=True):
    if STATE.exists():
        raise RuntimeError('A saved session exists. Run make stop anon first.')
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'anonsurfd.service']).returncode == 0:
        raise RuntimeError('Anonsurf is already active. Stop it before changing the MAC.')
    if not iface:
        routes = json.loads(run('ip', '-j', 'route', 'show', 'default'))
        if not routes:
            raise RuntimeError('No default route. Connect first or set IFACE=your_interface.')
        iface = min(routes, key=lambda route: route.get('metric', 0))['dev']
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]+', iface):
        raise RuntimeError('Invalid interface name.')
    kind = run('nmcli', '-g', 'GENERAL.TYPE', 'device', 'show', iface)
    properties = {'wifi': '802-11-wireless.cloned-mac-address',
                  'ethernet': '802-3-ethernet.cloned-mac-address'}
    if kind not in properties:
        raise RuntimeError('Select a NetworkManager Wi-Fi or Ethernet interface with IFACE=...')
    uuid = run('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', iface)
    if not uuid or uuid == '--':
        raise RuntimeError('The selected interface must have an active connection.')
    prop = properties[kind]
    saved = {'iface': iface, 'uuid': uuid, 'property': prop,
             'mac': Path('/sys/class/net', iface, 'address').read_text().strip(),
             'setting': run('nmcli', '-g', prop, 'connection', 'show', 'uuid', uuid)}
    # Persist before the first network change so a failed start can be recovered.
    with STATE.open('x') as handle:
        json.dump(saved, handle)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        publish(saved)
        print(f'Changing MAC on {iface}; the connection will briefly disconnect.', flush=True)
        run('nmcli', '--wait', '20', 'device', 'disconnect', iface)
        run('ip', 'link', 'set', 'dev', iface, 'down')
        print(run('macchanger', '--random', iface), flush=True)
        new_mac = Path('/sys/class/net', iface, 'address').read_text().strip()
        if new_mac == saved['mac']:
            raise RuntimeError('MAC address did not change.')
        # Keep NetworkManager from overwriting the new MAC on reconnection.
        # --temporary leaves the on-disk connection profile unchanged.
        run('nmcli', 'connection', 'modify', '--temporary', 'uuid', uuid, prop, new_mac)
        run('ip', 'link', 'set', 'dev', iface, 'up')
        run('nmcli', '--wait', '60', 'connection', 'up', 'uuid', uuid, 'ifname', iface)
        actual = Path('/sys/class/net', iface, 'address').read_text().strip()
        if actual != new_mac:
            raise RuntimeError('NetworkManager did not retain the changed MAC.')
        if with_anonsurf:
            print(run('anonsurf', 'start'), flush=True)
            print('Anonsurf started. Restore with: make stop anon', flush=True)
        else:
            print('MAC changer started. Original connection settings are saved for restoration.', flush=True)
    except (Exception, KeyboardInterrupt):
        print('Start interrupted or failed; attempting to restore the connection.', file=sys.stderr)
        try:
            if with_anonsurf:
                stop()
            else:
                restore(saved)
        except Exception as recovery_error:
            print(f'Recovery incomplete: {recovery_error}. Run make stop anon again.', file=sys.stderr)
        raise


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run through the Desktop Makefile, which uses sudo.')
    os.umask(0o077)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE_DIR / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if sys.argv[1] == 'start':
            start(sys.argv[2] if len(sys.argv) > 2 else '')
        elif sys.argv[1] == 'mac-start':
            start(sys.argv[2] if len(sys.argv) > 2 else '', with_anonsurf=False)
        elif sys.argv[1] == 'mac-stop':
            if subprocess.run(['systemctl', 'is-active', '--quiet', 'anonsurfd.service']).returncode == 0:
                raise RuntimeError('Stop AnonSurf before restoring the MAC address.')
            if not STATE.exists():
                raise RuntimeError('No saved MAC session to restore.')
            restore(json.loads(STATE.read_text()))
        elif sys.argv[1] == 'stop':
            stop()
        else:
            raise RuntimeError('Expected start, stop, mac-start, or mac-stop.')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stderr.strip() or str(error), file=sys.stderr)
        sys.exit(1)
    except (RuntimeError, BlockingIOError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
