from aiticket.engine import observe
from test_core import seed


def test_delivery_categories_details_and_retry(signed_in):
    client,store,_,csrf=signed_in
    seed(store)
    for at in (1,2,3):observe(store,'c',False,{},now=at)
    original=store.rows('SELECT * FROM deliveries')[0]
    with store.connect() as c:
        c.execute("UPDATE deliveries SET state='failed',last_error='HTTP 403; review destination settings.'")
        for index,state in enumerate(('pending','leased','completed','superseded','expired')):
            c.execute('INSERT INTO deliveries VALUES(?,?,?,?,0,?,NULL,NULL,NULL,?,?)',(str(index),original['incident_id'],original['incident_id']+':reminder:'+str(index),state,10,10+index,100))
    page=client.get('/queue?view=attention').data.decode()
    assert 'App' in page and 'Machine' in page and 'Recorded error' in page
    assert 'Message reference' in page and '<summary>Delivery details</summary>' in page
    assert 'Retry notification' in page and 'Waiting &amp; sending' in page
    assert f'/queue/{original["id"]}/retry' in page
    sent=client.get('/queue?view=sent').data.decode()
    assert 'Delivered messages' in sent and '/queue/2/retry' not in sent
    assert client.get('/queue?view=invalid').status_code==400
    assert client.get('/queue?page=0').status_code==400
    assert client.post('/queue/'+original['id']+'/retry').status_code==403
    assert client.post('/queue/2/retry',data={'csrf':csrf}).status_code==409
    assert client.post('/queue/'+original['id']+'/retry',data={'csrf':csrf}).status_code==302
    updated=store.rows('SELECT state,last_error FROM deliveries WHERE id=?',(original['id'],))[0]
    assert updated['state']=='pending' and updated['last_error'] is None


def test_delivery_pagination(signed_in):
    client,store,_,_=signed_in;seed(store)
    for at in (1,2,3):observe(store,'c',False,{},now=at)
    incident=store.rows('SELECT id FROM incidents')[0]['id']
    with store.connect() as c:
        for index in range(52):
            c.execute('INSERT INTO deliveries VALUES(?,?,?,\'completed\',0,1,NULL,NULL,NULL,?,100)',(str(index),incident,incident+':reminder:'+str(index),10+index))
    first=client.get('/queue?view=sent').data.decode()
    second=client.get('/queue?view=sent&page=2').data.decode()
    assert first.count('class="delivery-item"')==50 and second.count('class="delivery-item"')==2
    assert 'view=sent&amp;page=2' in first and 'view=sent&amp;page=1' in second
