"""Independent UDP/TCP syslog receiver. No Vault, HTTP server or AI worker."""
import json
import selectors
import signal
import socket
import time
from . import network_logs as logs


class Framer:
    """RFC6587 octet counting and newline-delimited TCP; hard bounded buffering."""
    def __init__(self):
        self.buffer = b''

    def feed(self, data):
        self.buffer += data
        result = []
        while self.buffer:
            space = self.buffer.find(b' ')
            prefix = self.buffer[:space] if 0 <= space <= 6 else b''
            if prefix.isdigit():
                length = int(prefix)
                if not 1 <= length <= logs.MAX_MESSAGE:
                    raise ValueError('Invalid syslog frame size.')
                if len(self.buffer) < space + 1 + length: break
                result.append(self.buffer[space + 1:space + 1 + length])
                self.buffer = self.buffer[space + 1 + length:]
            else:
                newline = self.buffer.find(b'\n')
                if newline < 0: break
                if newline > logs.MAX_MESSAGE: raise ValueError('Syslog line exceeds 16 KiB.')
                result.append(self.buffer[:newline].rstrip(b'\r'))
                self.buffer = self.buffer[newline + 1:]
        if len(self.buffer) > logs.MAX_MESSAGE + 8: raise ValueError('Syslog buffer exceeds 16 KiB.')
        return result


class Collector:
    def __init__(self, store):
        self.store = store
        self.archive = logs.Archive(logs.database(store))
        self.pending = []
        self.sources = {}
        self.stats = {'received': 0, 'dropped': 0, 'unrecognized': 0, 'parse_errors': 0, 'oversize': 0, 'storage_errors': 0}
        self.last_source = {}
        self.buckets = {}
        self.refresh()

    def refresh(self):
        with self.store.connect() as c:
            self.sources = {r['sender_ip']: dict(r) for r in c.execute('SELECT * FROM log_sources WHERE enabled=1')}
            self.bindings = {(r['source_id'], r['mac']): r['machine_id'] for r in c.execute('SELECT * FROM log_host_bindings')}
            self.interfaces = [(r['machine_id'], r['at'], i) for r in c.execute('SELECT * FROM network_inventory') for i in json.loads(r['data']).get('interfaces', [])]
            self.devices = [(r['connection_id'], r['machine_id'], json.loads(r['data']).get('device', {})) for r in c.execute('SELECT * FROM unifi_devices WHERE deleted IS NULL')]
            self.consoles = {r['id']: r['machine_id'] for r in c.execute('SELECT id,machine_id FROM unifi_connections WHERE deleted IS NULL')}
        self.config = {**logs.DEFAULTS, **self.store.setting('network_log_retention', {})}
        self.mirror = self.store.setting('network_log_smb', {})
        self.config['buffer_mb'] = self.mirror.get('buffer_mb', 256)

    def match(self, event, source):
        result = []
        candidates = {machine for machine, at, i in self.interfaces if
                      event['client_mac'] and logs.mac(i.get('mac')) == event['client_mac'] or
                      not event['client_mac'] and event['client_ip'] and event['timestamp_kind'] == 'reported' and abs(at - event['at']) <= 180 and abs(event['received'] - event['at']) <= 180 and event['client_ip'] in i.get('addresses', [])}
        if len(candidates) == 1:
            result.append({'machine_id': next(iter(candidates)), 'role': 'client', 'method': 'Inventory MAC match' if event['client_mac'] else 'Unique recent IP observation (within 3 minutes)'})
        devices = {machine for connection, machine, device in self.devices if connection == source['connection_id'] and event['device_mac'] and logs.mac(device.get('macAddress')) == event['device_mac']}
        if len(devices) == 1:
            result.append({'machine_id': next(iter(devices)), 'role': 'infrastructure', 'method': 'UniFi device MAC match in this connection'})
        console = self.consoles.get(source['connection_id'])
        if console:
            result.append({'machine_id': console, 'role': 'console', 'method': 'Configured sending console'})
        return result

    def receive(self, data, ip, now=None):
        now = time.time() if now is None else now
        source = self.sources.get(logs.address(ip))
        if not source:
            self.stats['dropped'] += 1; return
        # Each permitted source gets 100 messages/sec with a 200-message burst.
        tokens, previous = self.buckets.get(source['id'], (200, now))
        tokens = min(200, tokens + max(0, now - previous) * 100)
        self.buckets[source['id']] = (max(0, tokens - 1), now)
        if tokens < 1 or len(self.pending) >= 500:
            self.stats['dropped'] += 1; return
        if len(data) > logs.MAX_MESSAGE:
            self.stats['oversize'] += 1; return
        event = logs.parse(data, now)
        event['source_id'] = source['id']
        event['associations'] = self.match(event, source)
        self.pending.append(event)
        self.stats['received'] += 1
        if event['format'] != 'CEF': self.stats['unrecognized'] += 1
        if event['format'] == 'unparsed CEF': self.stats['parse_errors'] += 1
        self.last_source[source['id']] = {'at': now, 'format': event['format']}

    def flush(self, now=None):
        now = time.time() if now is None else now
        try:
            self.archive.retain(self.config, now, mirrored=self.mirror.get('enabled', False))
            self.archive.append(self.pending, self.mirror if self.mirror.get('enabled') else None)
            self.pending.clear()
            self.archive.retain(self.config, now, mirrored=self.mirror.get('enabled', False))
            self.archive.status({**self.stats, 'heartbeat': now, 'sources': self.last_source})
        except (OSError, logs.sqlite3.Error):
            self.stats['storage_errors'] += 1
            self.stats['dropped'] += len(self.pending)
            self.pending.clear()
            # No packet contents/credentials are ever printed to container logs.
            print('Network log archive unavailable; batch dropped.', flush=True)


def run(store, host='0.0.0.0', port=5514):
    collector = Collector(store)
    selector = selectors.DefaultSelector()
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    udp = socket.socket(family, socket.SOCK_DGRAM)
    tcp = socket.socket(family, socket.SOCK_STREAM)
    clients = {}
    stopping = False
    listening = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, stop)
    def close(connection):
        selector.unregister(connection); clients.pop(connection, None); connection.close()
    try:
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for sock, kind in ((udp, 'udp'), (tcp, 'tcp')):
            sock.bind((host, port)); sock.setblocking(False); selector.register(sock, selectors.EVENT_READ, kind)
        tcp.listen(32)
        listening = True
        print('Network log receiver listening on UDP/TCP port '+str(port)+'. Only configured sender IPs are accepted.', flush=True)
        updated = flushed = time.monotonic()
        collector.flush()
        while not stopping:
            for key, _ in selector.select(0.25):
                sock = key.fileobj
                try:
                    if key.data == 'udp':
                        data, peer = sock.recvfrom(logs.MAX_MESSAGE + 1)
                        collector.receive(data, peer[0])
                    elif key.data == 'tcp':
                        connection, peer = sock.accept()
                        if len(clients) >= 32 or logs.address(peer[0]) not in collector.sources:
                            connection.close(); collector.stats['dropped'] += 1; continue
                        connection.setblocking(False)
                        clients[connection] = (peer[0], Framer(), time.monotonic())
                        selector.register(connection, selectors.EVENT_READ, 'client')
                    else:
                        ip, frame, _ = clients[sock]
                        data = sock.recv(32768)
                        if not data: close(sock); continue
                        clients[sock] = (ip, frame, time.monotonic())
                        for message in frame.feed(data): collector.receive(message, ip)
                except (OSError, ValueError):
                    collector.stats['oversize'] += 1
                    if sock in clients: close(sock)
            tick = time.monotonic()
            for connection, (_, _, active) in list(clients.items()):
                if tick - active > 30: close(connection)
            if tick - updated >= 5:
                collector.refresh(); updated = tick
                for connection, (ip, _, _) in list(clients.items()):
                    if logs.address(ip) not in collector.sources: close(connection)
            if tick - flushed >= 2 or len(collector.pending) >= 100:
                collector.flush(); flushed = tick
    finally:
        if listening: collector.flush()
        for connection in list(clients): close(connection)
        selector.close(); udp.close(); tcp.close()
