import hashlib
import hmac
import ipaddress
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit
from cryptography.fernet import Fernet


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Vault:
    def __init__(self, key_file):
        path = Path(key_file)
        if not path.exists():
            raise RuntimeError('Create a separately managed encryption key with python -m aiticket init.')
        self.box = Fernet(path.read_bytes().strip())

    def encrypt(self, value):
        return self.box.encrypt(value.encode()).decode()

    def decrypt(self, value):
        return self.box.decrypt(value.encode()).decode() if value else ''


def validate_url(url, schemes=('https', 'http')):
    p = urlsplit(url)
    if schemes==('https',) and os.environ.get('AITICKET_ALLOW_INSECURE_HTTP')=='1':
        schemes=('https','http')
    if p.scheme not in schemes or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError('Use a valid URL without embedded credentials or fragments.')
    if len(url) > 2048:
        raise ValueError('URL is too long.')
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError('Invalid port.')
    return url


def hermes_headers(secret, body, request_id, now=None):
    stamp = str(int(time.time() if now is None else now))
    signed = stamp.encode() + b'.' + body
    return {'Content-Type': 'application/json', 'X-Request-ID': request_id,
            'X-Webhook-Timestamp': stamp,
            'X-Webhook-Signature-V2': hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()}
