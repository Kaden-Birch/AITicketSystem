from unittest.mock import patch
import pytest
from aiticket.proxmox import schedule,scheduled_refresh,Client,discover,link
from test_proxmox import setup,inventory


def test_schedule_refresh_review_and_visibility(environment):
    _,store,vault=environment
    setup(store,vault)
    schedule(store,'p1',60,now=100)
    with patch.object(Client,'get',return_value=inventory()):
        assert scheduled_refresh(store,vault,now=100)
        assert not scheduled_refresh(store,vault,now=159)
    guest=store.rows("SELECT * FROM proxmox_objects WHERE kind='qemu'")[0]
    assert guest['review_required'] and not store.rows('SELECT * FROM checks')
    link(store,guest['id'],None,'running','Guest')
    with patch.object(Client,'get',return_value=[]):
        scheduled_refresh(store,vault,now=160)
    current=store.rows('SELECT * FROM proxmox_objects WHERE id=?',(guest['id'],))[0]
    assert current['missing_since'] and current['present'] and not current['review_required']
    assert store.rows('SELECT enabled FROM checks')[0]['enabled']==1
    with patch.object(Client,'get',return_value=inventory('b')):
        scheduled_refresh(store,vault,now=220)
    current=store.rows('SELECT * FROM proxmox_objects WHERE id=?',(guest['id'],))[0]
    assert current['missing_since'] is None and current['node']=='b'


def test_failed_refresh_retains_inventory_and_lease_recovery(environment):
    _,store,vault=environment
    setup(store,vault)
    with patch.object(Client,'get',return_value=inventory()):
        discover(store,vault,'p1')
    schedule(store,'p1',60,now=100)
    with store.connect() as c:
        c.execute("UPDATE discovery_schedules SET lease_token='old',lease_until=150")
    with patch.object(Client,'get',side_effect=OSError('sensitive-upstream-secret')):
        assert not scheduled_refresh(store,vault,now=149)
        assert scheduled_refresh(store,vault,now=150)
    assert len(store.rows('SELECT * FROM proxmox_objects'))==5
    assert store.rows('SELECT last_error FROM discovery_schedules')[0]['last_error']=='OSError'
    assert 'sensitive' not in str(store.rows('SELECT * FROM audit'))


def test_disable_fences_inflight_refresh(environment):
    _,store,vault=environment
    setup(store,vault)
    schedule(store,'p1',60,now=100)
    def response(*args):
        schedule(store,'p1',0,now=101)
        return inventory()
    with patch.object(Client,'get',side_effect=response):
        scheduled_refresh(store,vault,now=100)
    assert not store.rows('SELECT * FROM proxmox_objects')
    with pytest.raises(ValueError):
        schedule(store,'p1',59)


def test_schedule_ui(signed_in):
    client,store,vault,csrf=signed_in
    setup(store,vault)
    assert client.post('/proxmox',data={'csrf':csrf,'operation':'schedule','connection_id':'p1','interval':'300'}).status_code==302
    assert b'Automatic refresh interval' in client.get('/proxmox').data
