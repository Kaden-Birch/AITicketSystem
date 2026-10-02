import json,time,uuid
from unittest.mock import patch
from aiticket.db import uid
from aiticket.security import digest
from aiticket.engine import claim
from aiticket.adapters import probe
from agent.monitoring import evaluate


def test_agent_failures_open_ticket_and_recovery_closes(signed_in):
    client,store,vault,csrf=signed_in
    machine=uid(); agent=uid(); token='monitor-test-token'
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Photos',time.time()))
        c.execute('INSERT INTO agents(id,machine_id,credential_digest) VALUES(?,?,?)',(agent,machine,digest(token)))
    response=client.post('/checks',data={'csrf':csrf,'machine_id':machine,'kind':'process','target':'immich.service','name':'Immich','interval':20,'fail_after':2,'recover_after':1,'severity':'high'})
    assert response.status_code==302
    check=store.rows("SELECT * FROM checks WHERE kind='process'")[0]
    assert claim(store,'checks') is None
    headers={'Authorization':'Bearer '+token}
    assert client.post('/api/agent/checks',json={}).status_code==401
    for healthy in (False,False,True):
        with store.connect() as c:c.execute('UPDATE checks SET next_run=0 WHERE id=?',(check['id'],))
        result={'id':check['id'],'config':{'target':'immich.service'},'healthy':healthy,'sampled_at':time.time()}
        assert client.post('/api/agent/checks',json={'results':[result]},headers=headers).status_code==200
    incident=store.rows('SELECT * FROM incidents')[0]
    assert incident['status']=='Resolved'
    assert len(store.rows('SELECT * FROM observations'))==3
    page=client.get('/hosts/'+machine)
    assert page.status_code==200 and b'check-item' in page.data


def test_ping_argv_and_timeout():
    with patch('subprocess.run') as run:
        run.return_value.returncode=0
        assert probe('ping',{'host':'10.0.0.1'},None)[0]
        assert run.call_args.args[0]==['ping','-n','-c','1','-W','1','10.0.0.1']
        assert run.call_args.kwargs['timeout']==2


def test_agent_service_and_smb_timeout():
    with patch('subprocess.run') as run:
        run.return_value.returncode=0
        assert evaluate({'id':'x','kind':'process','config':{'target':'immich.service'}})['healthy']
        assert run.call_args.args[0]==['systemctl','is-active','--quiet','immich.service']
        import subprocess
        run.side_effect=None
        with patch('agent.monitoring.mount_probe',return_value=False):
            assert not evaluate({'id':'x','kind':'smb','config':{'target':'/mnt/photos'}})['healthy']


def test_one_second_ping_configuration(signed_in):
    client,store,_,csrf=signed_in; machine=uid()
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'NAS',time.time()))
    response=client.post('/checks',data={'csrf':csrf,'machine_id':machine,'kind':'ping','host':'10.0.0.2','name':'NAS ping','interval':1})
    assert response.status_code==302
    from aiticket.inventory import export_inventory
    assert export_inventory(store)['tables']['checks'][0]['interval']==1


def test_smb_rejects_existing_local_directory(tmp_path):
    assert not evaluate({'id':'x','kind':'smb','config':{'target':str(tmp_path)}})['healthy']


def test_mount_timeout_never_waits_for_uninterruptible_child():
    import subprocess
    from agent import monitoring
    monitoring._children.clear()
    with patch('agent.monitoring.subprocess.Popen') as popen:
        child=popen.return_value
        child.wait.side_effect=subprocess.TimeoutExpired('mount',5)
        assert monitoring.mount_probe(['probe']) is False
        child.kill.assert_called_once()
        child.wait.assert_called_once_with(timeout=5)
    monitoring._children.clear()


def test_invalid_ping_rejected(signed_in):
    client,store,_,csrf=signed_in;machine=uid()
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'NAS',time.time()))
    response=client.post('/checks',data={'csrf':csrf,'machine_id':machine,'kind':'ping','host':'-f','name':'Flood','interval':1})
    assert response.status_code==400
