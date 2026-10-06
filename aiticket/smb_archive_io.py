"""One bounded SMB operation per child process; credentials arrive only through stdin."""
import gzip
import hashlib
import json
import re
import sys
import time
import uuid
import math
import errno
import socket
from datetime import datetime, timezone
from pathlib import Path

# Names carry receipt/event time bounds and a checksum. Only our archive namespace is managed.
NAME = re.compile(r'^logs-(\d+)-(\d+)-(\d+)-([a-f0-9]{32})-([a-f0-9]{64})\.jsonl\.gz$')
MAX_FILE = 16 * 1048576
MAX_EXPANDED = 32 * 1048576


def metadata(name):
    match = NAME.fullmatch(name)
    if not match: return None
    received, start, end, identifier, checksum = match.groups()
    return {'name': name, 'received': int(received), 'start': int(start), 'end': int(end), 'checksum': checksum}


def execute(request):
    import smbclient
    cfg = request['connection']
    # No DFS referrals or implicit credential fallback to other servers.
    smbclient.ClientConfig(skip_dfs=True)
    username = (cfg['domain'] + '\\' if cfg.get('domain') else '') + cfg['username']
    smbclient.register_session(cfg['server'], username=username, password=cfg['password'],
                               port=445, connection_timeout=5, require_signing=True,
                               encrypt=bool(cfg.get('encrypt')))
    root = '\\\\' + cfg['server'] + '\\' + cfg['share']
    folder = cfg.get('folder', '').replace('/', '\\').strip('\\')
    root += ('\\' + folder if folder else '') + '\\aiticket-network-logs\\' + cfg['namespace']
    smbclient.makedirs(root, exist_ok=True)
    operation = request['operation']

    def remote(name):
        if not NAME.fullmatch(name): raise ValueError('Invalid archive filename.')
        day = datetime.fromtimestamp(metadata(name)['received'], timezone.utc).strftime('%Y-%m-%d')
        return root + '\\' + day + '\\' + name

    def read_bytes(name):
        with smbclient.open_file(remote(name), 'rb') as f:
            data = f.read(MAX_FILE + 1)
        if len(data) > MAX_FILE: raise ValueError('Archive exceeds size limit.')
        if hashlib.sha256(data).hexdigest() != metadata(name)['checksum']:
            raise ValueError('Archive checksum did not match.')
        return data

    if operation == 'test':
        probe = root + '\\connection-test-' + uuid.uuid4().hex
        renamed = probe + '-verified'
        try:
            with smbclient.open_file(probe, 'xb') as f: f.write(b'AITicketSystem SMB connection test\n')
            smbclient.rename(probe, renamed)
            with smbclient.open_file(renamed, 'rb') as f:
                if f.read(100) != b'AITicketSystem SMB connection test\n': raise ValueError('Read verification failed.')
            smbclient.remove(renamed)
        finally:
            for path in (probe, renamed):
                try: smbclient.remove(path)
                except FileNotFoundError: pass
        return {'message': 'Connection verified: create, write, rename, read and delete succeeded.'}

    if operation == 'upload':
        name = request['name']; target = remote(name)
        smbclient.makedirs(target.rsplit('\\',1)[0], exist_ok=True)
        data = Path(request['file']).read_bytes()
        if len(data) > MAX_FILE or hashlib.sha256(data).hexdigest() != metadata(name)['checksum']:
            raise ValueError('Invalid local archive.')
        try:
            if read_bytes(name) == data: return {'bytes': len(data)}
        except FileNotFoundError: pass
        partial = target + '.partial'
        with smbclient.open_file(partial, 'wb') as f:
            f.write(data); f.flush()
        with smbclient.open_file(partial, 'rb') as f:
            copied = f.read(MAX_FILE + 1)
        if hashlib.sha256(copied).hexdigest() != metadata(name)['checksum']:
            raise ValueError('Uploaded archive failed verification.')
        smbclient.rename(partial, target)
        return {'bytes': len(data)}

    if operation == 'catalog':
        files = []; directories = []; scanned = 0
        # Daily partitions let retention and monthly searches avoid enumerating every archived file.
        for entry in smbclient.scandir(root):
            if re.fullmatch(r'\d{4}-\d{2}-\d{2}', entry.name) and entry.is_dir(follow_symlinks=False):
                day = datetime.strptime(entry.name, '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp()
                if request.get('cutoff') and day > request['cutoff']: continue
                if request.get('start') is not None and day+86400 < request['start']-31*86400: continue
                if request.get('end') is not None and day > request['end']+31*86400: continue
                directories.append(entry.name)
                if len(directories)>10000: raise ValueError('Too many archive day partitions.')
        for day in sorted(directories, reverse=not bool(request.get('cutoff'))):
            for entry in smbclient.scandir(root+'\\'+day):
                scanned += 1
                item = metadata(entry.name)
                if item and entry.is_file(follow_symlinks=False):
                    if request.get('cutoff') and item['received'] >= request['cutoff']: continue
                    if request.get('start') is not None and item['end'] < request['start']: continue
                    if request.get('end') is not None and item['start'] > request['end']: continue
                    files.append(item)
                if (request.get('cutoff') and len(files)>=100) or len(files)>=50000 or scanned>=100000:
                    return {'files':files,'truncated':True}
        return {'files': files, 'truncated':False}

    if operation == 'delete':
        for name in request['names'][:100]:
            try: smbclient.remove(remote(name))
            except FileNotFoundError: pass
        return {'deleted': len(request['names'][:100])}

    if operation == 'search':
        params = request['params']; results = []; scanned = 0; truncated = False; seen = set()
        for name in request['names'][:100]:
            data = read_bytes(name)
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                expanded = f.read(MAX_EXPANDED + 1)
            if len(expanded) > MAX_EXPANDED: raise ValueError('Expanded archive exceeds size limit.')
            for line in expanded.splitlines():
                scanned += 1
                if scanned > 100000: truncated = True; break
                event = json.loads(line)
                if not isinstance(event, dict) or not isinstance(event.get('event_key'), str) or len(event['event_key']) > 100:
                    raise ValueError('Invalid archive event identity.')
                if event['event_key'] in seen: continue
                seen.add(event['event_key'])
                if not all(isinstance(event.get(key), (int, float)) and math.isfinite(event[key]) for key in ('at','received')):
                    raise ValueError('Invalid archive timestamps.')
                if not params['start'] <= event['at'] <= params['end']: continue
                if params.get('source') and event['source_id'] != params['source']: continue
                if params.get('severity') is not None and (event['severity'] is None or event['severity'] < params['severity']): continue
                if params.get('q') and params['q'].lower() not in ' '.join(str(event.get(k) or '') for k in ('message', 'name', 'client_ip', 'client_mac')).lower(): continue
                if params.get('machine'):
                    associations = json.loads(event['associations'])
                    binding = next((b['machine_id'] for b in params.get('bindings',[]) if b['source_id']==event['source_id'] and b['mac']==event.get('client_mac')), None)
                    if binding: associations = [a for a in associations if a['role']!='client'] + [{'machine_id':binding,'role':'client'}]
                    if not any(a['machine_id']==params['machine'] for a in associations): continue
                # Return a bounded result even for very broad historical searches.
                results.append(event)
                if len(results) >= 200: truncated = True; break
            if truncated: break
        Path(request['file']).write_text(json.dumps(results, separators=(',', ':'), allow_nan=False))
        return {'count': len(results), 'scanned': scanned, 'truncated': truncated}
    raise ValueError('Unknown SMB operation.')


def error_message(exc):
    """Classify wrapped failures without returning SMB exception text or secrets."""
    from smbprotocol.header import NtStatus
    from smbprotocol.exceptions import LogonFailure, WrongPassword, AccessDenied, BadNetworkName, SMBUnsupportedFeature
    chain = []; seen = set()
    while exc is not None and id(exc) not in seen and len(chain) < 8:
        seen.add(id(exc)); chain.append(exc)
        exc = exc.__cause__ or exc.__context__
    statuses = {getattr(item, 'ntstatus', getattr(item, 'status', None)) for item in chain
                if isinstance(getattr(item, 'ntstatus', getattr(item, 'status', None)), int)}
    if any(isinstance(item, (LogonFailure, WrongPassword)) for item in chain) or statuses & {NtStatus.STATUS_LOGON_FAILURE, NtStatus.STATUS_WRONG_PASSWORD}:
        return 'SMB login failed. Check the username, domain and password.'
    if any(isinstance(item, (PermissionError, AccessDenied)) for item in chain) or NtStatus.STATUS_ACCESS_DENIED in statuses:
        return 'SMB access denied. The archive folder requires read, write, rename and delete permissions.'
    if any(isinstance(item, BadNetworkName) for item in chain) or NtStatus.STATUS_BAD_NETWORK_NAME in statuses:
        return 'SMB share not found. Check the share name.'
    if any(isinstance(item, socket.gaierror) for item in chain):
        return 'SMB server hostname could not be resolved. Check DNS or use the server IP address.'
    if any(isinstance(item, TimeoutError) or getattr(item, 'errno', None) == errno.ETIMEDOUT for item in chain):
        return 'SMB connection timed out. Check routing and firewall access from the application server to the SMB server on TCP port 445.'
    if any(isinstance(item, ConnectionRefusedError) or getattr(item, 'errno', None) == errno.ECONNREFUSED for item in chain):
        return 'SMB connection refused on TCP port 445. Check that the SMB service is running and accepting connections on the selected server.'
    if any(getattr(item, 'errno', None) in (errno.ENETUNREACH, errno.EHOSTUNREACH) for item in chain):
        return 'SMB server is unreachable. Check routing and firewall access from the application server to TCP port 445.'
    if any(getattr(item, 'errno', None) in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE) for item in chain):
        return 'SMB server closed the connection. Check the SMB service and any intervening firewall.'
    if any(isinstance(item, SMBUnsupportedFeature) for item in chain):
        return 'SMB server does not support a required connection feature. Check SMB protocol, signing and encryption support.'
    if NtStatus.STATUS_DISK_FULL in statuses or any(getattr(item, 'errno', None) == errno.ENOSPC for item in chain):
        return 'SMB archive storage is full. Free space on the share before retrying.'
    return 'SMB operation failed. Check the server, share, permissions and available space; test the connection again.'


def main():
    try:
        request = json.load(sys.stdin)
        result = execute(request)
        print(json.dumps({'ok': True, **result}))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': error_message(exc)}))
        sys.exit(1)


if __name__ == '__main__': main()
