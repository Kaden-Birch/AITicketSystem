#!/usr/bin/env python3
"""Unprivileged outbound-only Linux telemetry agent; no shell or action execution."""
import argparse
import getpass
import json
import os
import signal
import ssl
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

VERSION = '0.1.0'


def endpoint(value):
    p = urlsplit(value)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ValueError('An authenticated, certificate-verified HTTPS endpoint is required.')
    return value.rstrip('/')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post(base, route, payload, ca=None, credential=None):
    context = ssl.create_default_context(cafile=ca)
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    headers = {'Content-Type': 'application/json'}
    if credential:
        headers['Authorization'] = 'Bearer ' + credential
    req = urllib.request.Request(base + route, data=json.dumps(payload).encode(), headers=headers, method='POST')
    with opener.open(req, timeout=10) as response:
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError('Server response exceeds size limit')
        return json.loads(body)


def write_state(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def telemetry():
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable'):
            memory[key] = int(value.strip().split()[0]) * 1024
    disk = os.statvfs('/')
    return {'uptime_seconds': float(Path('/proc/uptime').read_text().split()[0]),
            'load_1': os.getloadavg()[0], 'memory_total_bytes': memory['MemTotal'],
            'memory_available_bytes': memory['MemAvailable'],
            'disk_free_bytes': disk.f_bavail * disk.f_frsize, 'disk_total_bytes': disk.f_blocks * disk.f_frsize}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['enroll', 'run'])
    parser.add_argument('--state', default='/var/lib/aiticket-agent/identity.json')
    parser.add_argument('--server')
    parser.add_argument('--ca')
    args = parser.parse_args()
    path = Path(args.state)
    if args.command == 'enroll':
        if path.exists():
            raise SystemExit('Identity already exists. Revoke and remove it deliberately before re-enrollment.')
        base = endpoint(args.server or input('Application HTTPS endpoint: '))
        reply = post(base, '/api/agent/enroll', {'token': getpass.getpass('Single-use enrollment token: ')}, args.ca)
        write_state(path, {'server': base, 'ca': args.ca, **reply})
        print('Enrolled. Credentials saved with mode 0600; no agent IP configured.')
        return
    state = json.loads(path.read_text())
    base = endpoint(state['server'])
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    delay = 30
    while running:
        try:
            # Retain stable event identity after ambiguous delivery or process restart.
            pending = state.get('pending')
            if not pending:
                pending = {'event_id': str(uuid.uuid4()), 'version': VERSION, 'telemetry': telemetry()}
                state['pending'] = pending
                write_state(path, state)
            post(base, '/api/agent/heartbeat', pending, state.get('ca'), state['credential'])
            state.pop('pending', None)
            write_state(path, state)
            delay = 30
        except Exception as exc:
            print('Heartbeat unavailable: ' + type(exc).__name__, flush=True)
            delay = min(delay * 2, 300)
        for _ in range(delay):
            if not running:
                break
            time.sleep(1)


if __name__ == '__main__':
    main()
