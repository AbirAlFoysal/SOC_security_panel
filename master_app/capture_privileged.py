"""Run a system tcpdump with a bounded lifetime and a user-owned stop signal."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def validate_command(command):
    if not isinstance(command,list) or not command or not all(isinstance(v,str) for v in command):
        raise ValueError('Expected a tcpdump argument list.')
    binary=Path(command[0]).resolve()
    trusted={Path(p).resolve() for p in ('/usr/bin/tcpdump','/usr/sbin/tcpdump','/sbin/tcpdump') if Path(p).exists()}
    if binary not in trusted or binary.stat().st_uid!=0:
        raise ValueError('Administrator capture requires the system tcpdump installation.')
    return command


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stop-file',required=True)
    parser.add_argument('--command',required=True)
    args=parser.parse_args();command=validate_command(json.loads(args.command))
    child=subprocess.Popen(command,stdin=subprocess.DEVNULL,start_new_session=True)
    started=time.monotonic()
    try:
        while child.poll() is None:
            if Path(args.stop_file).exists() or time.monotonic()-started>=1800:
                # SIGINT lets tcpdump flush pcap buffers and print packet statistics.
                os.killpg(child.pid,signal.SIGINT)
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL)
                break
            time.sleep(.2)
        return child.wait()
    finally:
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL);child.wait()


if __name__=='__main__':
    raise SystemExit(main())
