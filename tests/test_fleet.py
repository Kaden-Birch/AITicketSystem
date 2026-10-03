import base64,json,shlex,subprocess
import pytest
from cryptography.hazmat.primitives import serialization
from aiticket import fleet
from aiticket.db import uid


def host(store):
    identifier=uid()
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,0)',(identifier,'Fixture host'))
    return identifier


def test_private_key_download_and_forget(signed_in):
    client,store,vault,csrf=signed_in
    assert client.post('/fleet',data={'csrf':csrf,'operation':'key','label':'Laptop','passphrase':'test-secret'}).status_code==302
    row=store.rows('SELECT * FROM fleet_keys')[0]
    assert 'PRIVATE KEY' not in row['private']
    response=client.post('/fleet/keys/'+row['id']+'/download',data={'csrf':csrf})
    assert response.status_code==200
    key=serialization.load_ssh_private_key(response.data,password=b'test-secret')
    assert key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()==row['public']
    assert client.get('/fleet/keys/'+row['id']+'/download').status_code==405
    assert client.post('/fleet/keys/'+row['id']+'/download').status_code==403
    assert client.post('/fleet/keys/'+row['id']+'/forget',data={'csrf':csrf,'confirm':'yes'}).status_code==302
    assert client.post('/fleet/keys/'+row['id']+'/download',data={'csrf':csrf}).status_code==404
    assert store.rows('SELECT private FROM fleet_keys')[0]['private'] is None
    assert client.get('/fleet').status_code==200


def test_preview_and_blocked_hosts_no_dispatch(signed_in):
    client,store,vault,csrf=signed_in;identifier=host(store)
    values={'csrf':csrf,'label':'Install tools','kind':'packages','packages':'htop curl','targets':identifier}
    response=client.post('/fleet/preview',data=values)
    assert response.status_code==200 and b'apt-get' in response.data
    assert not store.rows('SELECT * FROM fleet_jobs')
    assert client.post('/fleet',data=values).status_code==400
    response=client.post('/fleet',data={**values,'confirm':'yes'})
    assert response.status_code==302
    assert client.get(response.location).status_code==200
    row=store.rows('SELECT * FROM fleet_targets')[0]
    assert row['state']=='blocked' and 'not enabled' in row['error']
    assert not store.rows('SELECT * FROM command_jobs')


def test_fleet_reuses_permission_queue_and_submission_uuid(environment,monkeypatch):
    _,store,vault=environment;machine=host(store);calls=[]
    monkeypatch.setattr('aiticket.commands.queue',lambda *args:calls.append(args))
    values={'kind':'script','script':'id','label':'Identity','fleet_id':uid()}
    identifier=fleet.launch(store,vault,values,[machine,machine])
    assert fleet.launch(store,vault,values,[machine])==identifier
    assert len(calls)==1 and calls[0][2]==machine
    with pytest.raises(ValueError):fleet.launch(store,vault,{**values,'script':'uptime'},[machine])
    with pytest.raises(ValueError):fleet.launch(store,vault,values,['unifi:test'])


def test_input_injection_rejected_and_key_code_compiles(environment):
    _,store,vault=environment
    for values in ({'kind':'packages','packages':'curl; reboot'},{'kind':'user','username':'x;id'},{'kind':'user','username':'safe','groups':'docker;id'}):
        with pytest.raises(ValueError):fleet.command(store,values)
    key=fleet.generate(store,vault,'Fixture')
    command=fleet.command(store,{'kind':'key','username':'safe','key_id':key})
    # Compile the generated remote script without executing host mutations.
    wrapper=shlex.split(command)[2]
    import ast
    tree=ast.parse(wrapper)
    encoded=tree.body[1].value.args[0].args[0].value
    source=base64.b64decode(encoded).decode()
    compile(source,'remote-script','exec')
    assert 'O_NOFOLLOW' in source and 'authorized_keys' in source

@pytest.mark.parametrize('mode,state',[('immediate','pending'),('guarded','awaiting'),('readonly','blocked')])
def test_real_host_permissions_apply(environment,mode,state):
    from aiticket.commands import configure
    from aiticket.security import digest
    import time
    _,store,vault=environment;machine=host(store)
    with store.connect() as c:c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES(?,?,?,?,?)',(uid(),machine,digest('fixture'),time.time(),json.dumps({'shell_commands':True})))
    configure(store,machine,{'enabled':'yes','approval':mode})
    identifier=fleet.launch(store,vault,{'label':'Install','kind':'packages','packages':'htop'},[machine])
    rows=store.rows('SELECT state FROM command_jobs')
    if state=='blocked':assert rows==[] and store.rows('SELECT state FROM fleet_targets')[0]['state']=='blocked'
    else:assert rows[0]['state']==state

def test_public_key_add_remove_preserves_other_keys(environment,tmp_path,monkeypatch):
    import ast,pwd,os
    from types import SimpleNamespace
    _,store,vault=environment;key=fleet.generate(store,vault,'Fixture')
    directory=tmp_path/'.ssh';directory.mkdir();path=directory/'authorized_keys'
    other='ssh-ed25519 OTHERKEY other-user';path.write_text(other+'\n')
    monkeypatch.setattr(pwd,'getpwnam',lambda user:SimpleNamespace(pw_dir=str(tmp_path),pw_uid=os.getuid(),pw_gid=os.getgid()))
    for kind in ('key','key','revoke'):
        command=fleet.command(store,{'kind':kind,'username':'fixture','key_id':key})
        tree=ast.parse(shlex.split(command)[2]);encoded=tree.body[1].value.args[0].args[0].value
        exec(compile(base64.b64decode(encoded),'fixture-key-script','exec'),{})
        text=path.read_text();public=store.rows('SELECT public FROM fleet_keys')[0]['public']
        assert other in text
        assert text.count(public)==(0 if kind=='revoke' else 1)
    assert path.stat().st_mode & 0o777==0o600
