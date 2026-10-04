"""Windows host recognition and platform-specific check validation."""
import json,re


def is_windows(store,machine):
    rows=store.rows('SELECT host_info FROM agents WHERE machine_id=? AND revoked=0',(machine,))
    return bool(rows and json.loads(rows[0]['host_info']).get('os','').lower().startswith('windows'))


def valid_target(kind,target,windows=False):
    if not isinstance(target,str) or any(c in target for c in ('\0','\r','\n')):return False
    if kind=='smb':
        if windows:return bool(re.fullmatch(r'\\\\[^\\/]+\\[^\\/]+(?:\\[^\r\n]*)?',target)) and len(target)<=512
        return target.startswith('/') and len(target)<=512
    if kind=='process' and windows and target.lower().startswith('service:'):
        return bool(re.fullmatch(r'[A-Za-z0-9_.@ -]{1,100}',target[8:])) and not target[8:].startswith('-')
    return bool(re.fullmatch(r'[A-Za-z0-9_.@-]{1,100}',target)) and not target.startswith('-')
