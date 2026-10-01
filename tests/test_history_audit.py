import json
from test_core import seed


def populate(store):
    seed(store)
    with store.connect() as c:
        for n in range(55):
            c.execute('INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?)',
                      (f'i{n}','m','c','high' if n%2 else 'low','Resolved',1704067200+n*86400,1704067201+n*86400,'{}',1704067202+n*86400))


def test_history_filters_and_pagination(signed_in):
    client,store,_,_=signed_in
    populate(store)
    response=client.get('/history')
    assert response.status_code==200 and b'55 matching incidents' in response.data
    assert b'Next' in response.data
    response=client.get('/history?page=2')
    assert b'Previous' in response.data and b'Next' not in response.data
    response=client.get('/history?severity=high&status=Resolved&machine=m')
    assert b'27 matching incidents' in response.data
    response=client.get('/history?from=2024-01-01&to=2024-01-01')
    assert b'1 matching incidents' in response.data
    assert client.get('/history?from=2024-02-01&to=2024-01-01').status_code==400
    assert client.get('/history?severity=invalid').status_code==400
    assert client.get('/history?page=0').status_code==400
    assert client.get('/history?machine=unknown').status_code==200


def test_settings_validate_before_atomic_save_and_exclude_secrets(signed_in):
    client,store,_,csrf=signed_in
    store.save('discord_minimum','medium')
    response=client.post('/settings',data={'csrf':csrf,'section':'discord','webhook':'https://discord.com/api/webhooks/123/secret-value','minimum':'invalid'})
    assert response.status_code==400
    assert not store.setting('discord_secret')
    assert not store.rows('SELECT * FROM audit')
    client.post('/settings',data={'csrf':csrf,'section':'discord','webhook':'https://discord.com/api/webhooks/123/secret-value','minimum':'high'})
    records=store.rows('SELECT * FROM audit')
    assert len(records)==1 and records[0]['action']=='settings.updated'
    assert 'secret-value' not in json.dumps(records)
    response=client.get('/audit')
    assert response.status_code==200 and b'settings.updated' in response.data and b'secret-value' not in response.data


def test_machine_and_maintenance_audit(signed_in):
    client,store,_,csrf=signed_in
    client.post('/hosts',data={'csrf':csrf,'name':'New machine'})
    assert store.rows('SELECT * FROM audit')[0]['action']=='machine.created'
    assert client.post('/checks/missing/maintenance',data={'csrf':csrf,'minutes':60}).status_code==404
    assert len(store.rows('SELECT * FROM audit'))==1
