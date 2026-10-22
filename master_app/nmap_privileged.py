"""Keep privileged Nmap scans cancellable from the local application."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stop-file', required=True)
    parser.add_argument('--command', required=True)
    args = parser.parse_args()
    command = json.loads(args.command)
    if not isinstance(command, list) or not command or Path(command[0]).name not in ('nmap', 'nmap.exe') or not all(isinstance(x,str) for x in command):
        raise ValueError('Expected an Nmap argument list.')
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True)
    start = time.monotonic()
    try:
        while child.poll() is None:
            if Path(args.stop_file).exists() or time.monotonic()-start >= 1800:
                print('Stopping privileged Nmap scan.', flush=True)
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                break
            time.sleep(.25)
        return child.wait()
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()


if __name__ == '__main__':
    raise SystemExit(main())
