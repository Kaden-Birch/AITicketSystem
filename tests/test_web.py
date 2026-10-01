import json
import re
from aiticket.security import digest
from aiticket.engine import observe
from test_core import seed


def test_authentication_csrf_headers(environment):
    app, _, _ = environment
    client = app.test_client()
    assert client.get('/').status_code == 302
    assert client.post('/login', data={'password': 'test-password-long'}).status_code == 403
    response = client.get('/login')
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    assert client.get('/health').json['ai_dispatch'] == 'disabled'


def test_dashboard_and_all_pages(signed_in):
    client, store, _, csrf = signed_in
    for path in ('/', '/hosts', '/queue', '/settings'):
        assert client.get(path).status_code == 200
    assert client.post('/hosts', data={'csrf': csrf, 'name': '<script>unsafe</script>'}).status_code == 302
    response = client.get('/hosts')
    assert b'&lt;script&gt;' in response.data
    assert b'<script>unsafe</script>' not in response.data


def test_invalid_targets_and_settings(signed_in):
    client, store, vault, csrf = signed_in
    seed(store)
    assert client.post('/checks', data={'csrf': csrf, 'machine_id':'m', 'kind':'http', 'url':'file:///etc/passwd'}).status_code == 400
    assert client.post('/settings', data={'csrf':csrf, 'section':'discord', 'webhook':'https://example.com/secret'}).status_code == 400
    assert client.post('/settings', data={'csrf':csrf, 'section':'discord', 'webhook':'https://discord.com/api/webhooks/123/topsecret', 'minimum':'high'}).status_code == 302
    assert 'topsecret' not in store.setting('discord_secret')
    assert b'topsecret' not in client.get('/settings').data


def test_dhcp_duplicate_revocation_and_reenroll(signed_in):
    client, store, _, csrf = signed_in
    seed(store)
    response = client.post('/enrollments', data={'csrf':csrf,'machine_id':'m'})
    token = re.search(rb'<pre>([^<]+)</pre>', response.data).group(1).decode()
    result = client.post('/api/agent/enroll', json={'token':token})
    assert result.status_code == 200
    identity = result.json
    assert client.post('/api/agent/enroll', json={'token':token}).status_code == 401
    bearer = {'Authorization': 'Bearer '+identity['credential']}
    payload = {'event_id':'first', 'version':'0.1.0', 'telemetry':{'load_1':1}}
    assert client.post('/api/agent/heartbeat', json=payload, headers=bearer, environ_overrides={'REMOTE_ADDR':'192.0.2.10'}).status_code == 200
    assert client.post('/api/agent/heartbeat', json=payload, headers=bearer).json['status'] == 'duplicate'
    payload['event_id'] = 'second'
    assert client.post('/api/agent/heartbeat', json=payload, headers=bearer, environ_overrides={'REMOTE_ADDR':'192.0.2.99'}).status_code == 200
    row = store.rows('SELECT * FROM agents')[0]
    assert row['id'] == identity['agent_id'] and row['address'] == '192.0.2.99'
    client.post('/agents/'+row['id']+'/revoke', data={'csrf':csrf})
    assert client.post('/api/agent/heartbeat', json=payload, headers=bearer).status_code == 401
    response = client.post('/enrollments', data={'csrf':csrf,'machine_id':'m'})
    token = re.search(rb'<pre>([^<]+)</pre>', response.data).group(1).decode()
    renewed = client.post('/api/agent/enroll', json={'token':token}).json
    assert renewed['agent_id'] == identity['agent_id']
    assert renewed['credential'] != identity['credential']


def test_manual_note_and_resolution_do_not_call_ai(signed_in):
    client, store, _, csrf = signed_in
    seed(store)
    for i in range(3):
        observe(store, 'c', False, {}, now=i+1)
    iid = store.rows('SELECT * FROM incidents')[0]['id']
    assert client.post(f'/incidents/{iid}/note', data={'csrf':csrf,'note':'','operation':'resolve'}).status_code == 400
    client.post(f'/incidents/{iid}/note', data={'csrf':csrf,'note':'Handled manually','operation':'resolve'})
    observe(store, 'c', False, {}, now=4)
    assert len(store.rows('SELECT * FROM incidents')) == 1
    assert b'check remains unhealthy' in client.get(f'/incidents/{iid}').data
    assert store.rows('SELECT * FROM incidents')[0]['status'] == 'Resolved'


def test_schema_limits_and_enrollment_expiry(signed_in):
    client,store,_,csrf = signed_in
    seed(store)
    with store.connect() as c:
        c.execute('INSERT INTO enrollments VALUES(?,?,?,NULL)',(digest('expired-token'),'m',1))
    assert client.post('/api/agent/enroll',json={'token':'expired-token'}).status_code==401
    assert client.post('/api/agent/enroll',json=['invalid']).status_code==400
    assert client.post('/api/agent/heartbeat',json=['invalid'],headers={'Authorization':'Bearer fake'}).status_code==400
    assert client.post('/settings',data={'csrf':csrf,'section':'ai','daily_cost':'nan'}).status_code==400


def test_login_throttling_and_secure_cookie(environment):
    app,_,_ = environment
    client = app.test_client()
    client.get('/login')
    with client.session_transaction() as s:
        csrf=s['csrf']
    for i in range(5):
        assert client.post('/login',data={'csrf':csrf,'password':'wrong'}).status_code==200
    assert client.post('/login',data={'csrf':csrf,'password':'wrong'}).status_code==429
