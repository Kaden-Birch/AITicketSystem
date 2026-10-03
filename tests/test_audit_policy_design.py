import time
from aiticket.db import uid
from test_core import seed


def test_audit_highlights_preserves_full_activity_and_pagination(signed_in):
    client,store,_,_=signed_in;seed(store)
    with store.connect() as c:
        for index in range(60):store.audit(c,'diagnostic.completed','m',actor='agent')
        store.audit(c,'proxmox.discovered','m')
        store.audit(c,'command.failed','m',actor='agent')
        store.audit(c,'check.disabled','m')
        c.execute('INSERT INTO audit VALUES(?,?,?,?,?,?)',(uid(),time.time()-700000,'user','machine.created','m','{}'))
    before=store.rows('SELECT count(*) count FROM audit')[0]['count']
    highlights=client.get('/audit').data.decode()
    assert 'command.failed' in highlights and 'check.disabled' in highlights
    assert 'proxmox.discovered' not in highlights
    assert 'diagnostic.completed' not in highlights and 'machine.created' not in highlights
    assert 'Machine' in highlights and '<summary>Event details</summary>' in highlights
    assert 'machine.created' in client.get('/audit?period=all').data.decode()
    first=client.get('/audit?view=all&period=all&q=diagnostic').data.decode()
    second=client.get('/audit?view=all&period=all&q=diagnostic&page=2').data.decode()
    assert first.count('class="audit-entry"')==25 and second.count('class="audit-entry"')==25
    assert 'q=diagnostic' in second and 'page=3' in second
    assert 'No matching activity' in client.get('/audit?q=%25').data.decode()
    assert store.rows('SELECT count(*) count FROM audit')[0]['count']==before
    for path in ('/audit?view=bad','/audit?period=bad','/audit?page=0'):
        assert client.get(path).status_code==400


def test_policy_sections_and_combined_target_keep_scope(signed_in):
    client,store,_,csrf=signed_in;seed(store)
    for view in ('maintenance','defaults','groups','effective'):
        response=client.get('/policies?view='+view)
        assert response.status_code==200
        assert b'<pre>' not in response.data
    assert client.get('/policies?view=bad').status_code==400
    values={'csrf':csrf,'operation':'override','scope_target':'machine:m','enabled':'yes','minimum':'high','recovery':'yes','reminder_seconds':'600','escalate_after_seconds':'3600','escalate_to':'critical'}
    response=client.post('/policies?view=groups',data=values)
    assert response.status_code==302 and 'view=groups' in response.location
    assert store.rows('SELECT scope_kind,scope_id FROM notification_overrides')==[{'scope_kind':'machine','scope_id':'m'}]
    page=client.get('/policies?view=groups').data.decode()
    assert 'Every 600 seconds' in page and 'Use inherited settings' in page
    assert client.post('/policies?view=groups',data={'csrf':csrf,'operation':'inherit','scope_kind':'machine','scope_id':'m'}).status_code==302
    assert not store.rows('SELECT * FROM notification_overrides')
