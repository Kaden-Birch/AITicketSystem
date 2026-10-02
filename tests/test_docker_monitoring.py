import json,time
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from agent.monitoring import docker_probe,DOCKER_FORMAT
from aiticket.db import uid
from aiticket.security import digest


@pytest.mark.parametrize('running,health,paused,restarting,expected',[(True,'healthy',False,False,True),(True,'not_configured',False,False,True),(False,'not_configured',False,False,False),(True,'unhealthy',False,False,False),(True,'starting',False,False,False),(True,'healthy',True,False,False),(True,'healthy',False,True,False)])
def test_container_state(running,health,paused,restarting,expected):
    data={'running':running,'health':health,'paused':paused,'restarting':restarting,'status':'running' if running else 'exited','exit_code':0,'restart_count':2,'oom_killed':False}
    with patch('agent.monitoring.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(data).encode(),stderr=b'')) as run:
        healthy,details=docker_probe('immich_server')
        assert healthy is expected and details['restart_count']==2
        assert run.call_args.args[0]==['docker','container','inspect','--format',DOCKER_FORMAT,'--','immich_server']
        assert '.Config' not in DOCKER_FORMAT and '.Log' not in DOCKER_FORMAT


def test_missing_and_inaccessible_are_distinct():
    with patch('agent.monitoring.subprocess.run') as run:
        run.return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b'No such container: immich')
        assert docker_probe('immich')[0] is False
        run.return_value.stderr=b'permission denied token=secret'
        healthy,details=docker_probe('immich')
        assert healthy is None and 'secret' not in json.dumps(details)
        run.side_effect=FileNotFoundError()
        assert docker_probe('immich')[0] is None


def test_required_healthcheck():
    with patch('agent.monitoring.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'{"running":true,"health":"not_configured"}',stderr=b'')) as run:
        assert docker_probe('immich',True)[0] is None
        run.return_value.stdout=b'{"running":false,"health":"not_configured"}'
        assert docker_probe('immich',True)[0] is False


def test_docker_failure_evidence_and_recovery(signed_in):
    client,store,vault,csrf=signed_in;machine=uid();token='docker-test-token'
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Docker host',time.time()))
        c.execute('INSERT INTO agents(id,machine_id,credential_digest) VALUES(?,?,?)',(uid(),machine,digest(token)))
    assert client.post('/checks',data={'csrf':csrf,'machine_id':machine,'kind':'docker','target':'immich_server','name':'Immich Docker','interval':20,'fail_after':1,'recover_after':1,'severity':'high','require_health':'yes'}).status_code==302
    check=store.rows("SELECT * FROM checks WHERE kind='docker'")[0];cfg=json.loads(check['config'])
    assert cfg['require_health'] is True
    headers={'Authorization':'Bearer '+token}
    reply=client.post('/api/agent/checks',headers=headers,json={}).get_json()
    assert reply['checks']==[]
    with store.connect() as c:c.execute('UPDATE agents SET version=? WHERE machine_id=?',('0.7.0',machine))
    assert client.post('/api/agent/checks',headers=headers,json={}).get_json()['checks'][0]['kind']=='docker'
    for healthy in (None,False,True):
        with store.connect() as c:c.execute('UPDATE checks SET next_run=0 WHERE id=?',(check['id'],))
        assert client.post('/api/agent/checks',headers=headers,json={'results':[{'id':check['id'],'config':cfg,'healthy':healthy,'sampled_at':time.time(),'details':{'status':'running' if healthy else 'exited','health':'healthy' if healthy else 'unhealthy','exit_code':137,'restart_count':2,'oom_killed':True}}]}).status_code==200
        if healthy is None:assert not store.rows('SELECT id FROM incidents')
    assert store.rows('SELECT status FROM incidents')[0]['status']=='Resolved'
    evidence=json.loads(store.rows('SELECT evidence FROM observations ORDER BY at DESC')[0]['evidence'])
    assert evidence['restart_count']==2 and evidence['target']=='immich_server'
    from aiticket.inventory import export_inventory
    assert export_inventory(store)['tables']['checks'][0]['kind']=='docker'
