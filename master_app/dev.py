"""Development runner: restart the local server after Python edits."""
import argparse
import subprocess
import sys
import time
import urllib.request
import json
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def python_revision():
    return tuple((str(p), p.stat().st_mtime_ns, p.stat().st_size)
                 for p in sorted(ROOT.glob('*.py')) if p.is_file())


def busy(url):
    try:
        with urllib.request.urlopen(url + '/api/revision', timeout=1) as response:
            return json.load(response)['busy']
    except (OSError, ValueError):
        return False


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', choices=['127.0.0.1', 'localhost'])
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    url = f'http://127.0.0.1:{args.port}'
    command = [sys.executable, str(ROOT / 'run.py'), '--host', args.host, '--port', str(args.port), '--no-browser']
    revision = python_revision()
    child = subprocess.Popen(command)
    opened = args.no_browser
    print('Auto reload enabled: HTML / CSS / JavaScript refresh the browser; Python edits restart the server.', flush=True)
    try:
        while True:
            time.sleep(0.5)
            if not opened and child.poll() is None:
                try:
                    with urllib.request.urlopen(url + '/api/revision', timeout=1):
                        webbrowser.open(url)
                        opened = True
                except OSError:
                    pass
            current = python_revision()
            if current != revision and not busy(url):
                # Wait for the editor to finish writing before restarting.
                time.sleep(0.2)
                revision = python_revision()
                print('Python changed. Restarting server…', flush=True)
                stop(child)
                child = subprocess.Popen(command)
            # If edited Python has a syntax error, stay watching for the next fix.
    except KeyboardInterrupt:
        pass
    finally:
        stop(child)


if __name__ == '__main__':
    main()
