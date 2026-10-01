import json
import socket
from urllib.parse import urlsplit
import requests
from .security import validate_url


def probe(kind, config, vault, store=None):
    if kind == 'proxmox_linked':
        from .proxmox import linked_probe
        return linked_probe(store,vault,config)
    if kind == 'tcp':
        with socket.create_connection((config['host'], int(config['port'])), timeout=5):
            return True, {'reason': 'TCP connection established'}
    if kind == 'http':
        validate_url(config['url'])
        r = requests.get(config['url'], timeout=(3, 5), allow_redirects=False, stream=True)
        try:
            return r.status_code == config.get('status', 200), {'status_code': r.status_code, 'expected_status': config.get('status', 200)}
        finally:
            r.close()
    if kind == 'proxmox':
        base = validate_url(config['url'].rstrip('/'), ('https',))
        headers = {'Authorization': 'PVEAPIToken=' + config['token_id'] + '=' + vault.decrypt(config['token_secret'])}
        r = requests.get(base + '/api2/json/cluster/resources', headers=headers, timeout=(3, 8), verify=config.get('ca', True), allow_redirects=False)
        r.raise_for_status()
        resources = r.json()['data']
        if len(resources) > 10000:
            raise ValueError('Inventory exceeds supported limit')
        selected = config.get('resource')
        if not selected:
            return True, {'reason': 'API authenticated; cluster resources readable', 'resource_count': len(resources)}
        item = next((x for x in resources if x['id'] == selected), None)
        if not item:
            return False, {'reason': 'Selected resource not present', 'resource': selected}
        expected = config.get('expected', 'running')
        return item.get('status') == expected, {'resource': selected, 'status': item.get('status'), 'expected': expected, 'node': item.get('node')}
    if kind == 'agent':
        agent = store.rows('SELECT last_seen FROM agents WHERE id=? AND revoked=0', (config['agent_id'],))
        import time
        age = time.time() - agent[0]['last_seen'] if agent and agent[0]['last_seen'] else None
        return age is not None and age < config.get('max_age', 180), {'heartbeat_age_seconds': age, 'reason': 'Agent heartbeat freshness; absence does not establish machine failure'}
    raise ValueError('Unsupported check type')
