import json,time
from aiticket.db import uid
from aiticket.security import digest


def test_edit_container_preserves_history_and_fences_old_results(signed_in):
    client,store,vault,csrf=signed_in;machine=uid();check=uid();token='edit-agent-token'
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'Planner',time.time()))
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,version) VALUES(?,?,?,?)',(uid(),machine,digest(token),'0.7.0'))
        c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after) VALUES(?,?,?,?,?,60,1,2)',(check,machine,'Planner Docker','docker',json.dumps({'target':'wrong','require_health':True})))
    headers={'Authorization':'Bearer '+token};old={'id':check,'config':{'target':'wrong','require_health':True},'healthy':False,'sampled_at':time.time()}
    client.post('/api/agent/checks',json={'results':[old]},headers=headers)
    incident=store.rows('SELECT id FROM incidents')[0]['id']
    page=client.get('/checks/'+check+'/edit')
    assert page.status_code==200 and b'value="wrong"' in page.data and b'Save changes' in page.data
    response=client.post('/checks/'+check+'/edit',data={'csrf':csrf,'name':'Planner container','target':'planner-app-1','require_health':'yes','interval':30,'fail_after':3,'recover_after':2,'severity':'high','machine_id':'other','kind':'http'})
    assert response.status_code==302
    updated=store.rows('SELECT * FROM checks WHERE id=?',(check,))[0]
    assert updated['machine_id']==machine and updated['kind']=='docker' and updated['failures']==0 and updated['health']=='unknown'
    cfg=json.loads(updated['config']);assert cfg['target']=='planner-app-1' and cfg['require_health']
    assert store.rows('SELECT id FROM incidents')[0]['id']==incident
    client.post('/api/agent/checks',json={'results':[old]},headers=headers)
    assert len(store.rows('SELECT id FROM observations'))==1
    assert client.get('/checks/missing/edit').status_code==404


def test_proxmox_edit_keeps_secret_private(signed_in):
    client,store,vault,csrf=signed_in;machine=uid();check=uid()
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(machine,'VM',time.time()))
        cfg={'url':'https://10.0.0.1:8006','token_id':'monitor@pve!read','token_secret':vault.encrypt('never-redisplay'),'resource':'qemu/1','expected':'running'}
        c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval) VALUES(?,?,?,?,?,60)',(check,machine,'VM API','proxmox',json.dumps(cfg)))
    assert b'never-redisplay' not in client.get('/checks/'+check+'/edit').data
    response=client.post('/checks/'+check+'/edit',data={'csrf':csrf,'name':'VM API','url':cfg['url'],'token_id':cfg['token_id'],'resource':'qemu/1','expected':'running','interval':60,'fail_after':3,'recover_after':2,'severity':'medium'})
    assert response.status_code==302
    assert json.loads(store.rows('SELECT config FROM checks WHERE id=?',(check,))[0]['config'])['token_secret']==cfg['token_secret']
