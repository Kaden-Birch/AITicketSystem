from unittest.mock import patch
import pytest
from aiticket.policies import group_create,group_assign,override,effective,notifications
from aiticket.engine import observe,claim
from aiticket.worker import deliver
from test_core import seed


def values(**changes):
    return {'enabled':True,'minimum':'medium','recovery':True,'reminder_seconds':0,'escalate_after_seconds':0,'escalate_to':'high',**changes}


def test_override_precedence_and_inheritance(environment):
    _,store,_=environment
    seed(store)
    group=group_create(store,'Applications')
    group_assign(store,'m',group)
    override(store,'group',group,values(minimum='critical',reminder_seconds=60))
    with store.connect() as c:
        assert effective(c,'m')['minimum']=='critical'
    override(store,'machine','m',values(minimum='info'))
    with store.connect() as c:
        policy=effective(c,'m')
        assert policy['minimum']=='info' and policy['reminder_seconds']==0
    override(store,'machine','m',None)
    group_assign(store,'m',None)
    with store.connect() as c:
        assert effective(c,'m')['scope']=='global'


def test_group_controls_enqueue_reminders_and_dispatch(environment):
    _,store,vault=environment
    seed(store,severity='medium')
    group=group_create(store,'Applications')
    group_assign(store,'m',group)
    override(store,'group',group,values(minimum='info',reminder_seconds=60))
    for n in range(3):
        observe(store,'c',False,{},now=100+n)
    notifications(store,now=160)
    assert len(store.rows('SELECT * FROM deliveries'))==2
    store.save('discord_secret',vault.encrypt('https://discord.com/api/webhooks/test'))
    job=claim(store,'deliveries',now=161)
    override(store,'group',group,values(enabled=False))
    with patch('aiticket.worker.requests.post') as post:
        deliver(store,vault,job)
        post.assert_not_called()
    assert store.rows('SELECT state FROM deliveries WHERE id=?',(job['id'],))[0]['state']=='superseded'
    observe(store,'c',False,{},now=162)
    notifications(store,now=220)
    assert len(store.rows('SELECT * FROM deliveries'))==2


def test_invalid_override_is_atomic(environment):
    _,store,_=environment
    seed(store)
    with pytest.raises(ValueError):
        override(store,'machine','m',values(reminder_seconds=-1))
    with pytest.raises(ValueError):
        override(store,'machine','unknown',values())
    assert not store.rows('SELECT * FROM notification_overrides')


def test_group_and_override_ui(signed_in):
    client,store,_,csrf=signed_in
    seed(store)
    assert client.post('/policies',data={'csrf':csrf,'operation':'group','name':'Apps'}).status_code==302
    group=store.rows('SELECT id FROM notification_groups')[0]['id']
    assert client.post('/policies',data={'csrf':csrf,'operation':'membership','machine_id':'m','group_id':group}).status_code==302
    data={'csrf':csrf,'operation':'override','scope_kind':'group','scope_id':group,'enabled':'yes','recovery':'yes','minimum':'high','escalate_to':'critical','reminder_seconds':'600','escalate_after_seconds':'3600'}
    assert client.post('/policies',data=data).status_code==302
    assert b'Effective policy per machine' in client.get('/policies').data
