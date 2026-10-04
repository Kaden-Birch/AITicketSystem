import json,time,uuid
import pytest
from aiticket.db import uid
from aiticket.security import digest
from aiticket.windows import valid_target
from aiticket.host_access import read_only


def enrolled(store):
    machine=uid();agent=uid();token='fixture-windows-token'
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,0)',(machine,'Windows host'))
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,host_info) VALUES(?,?,?,?)',(agent,machine,digest(token),json.dumps({'os':'Windows 11'})))
    return machine,agent,{'Authorization':'Bearer '+token}


def test_windows_heartbeat_network_services_and_signed_docker(environment):
    app,store,_=environment;machine,agent,headers=enrolled(store);client=app.test_client()
    network={'machine_type':'physical','interfaces':[{'name':name,'mac':'aa:bb:cc:dd:ee:ff','kind':'physical','state':'up','carrier':True,'addresses':['10.0.0.2'],'members':[],'master':''} for name in ('Ethernet 2','vEthernet (Default Switch)','Local Area Connection* 1','Connexion réseau')],'neighbors':[]}
    payload={'event_id':str(uuid.uuid4()),'version':'0.10.0+abcdefabcdef','sampled_at':time.time(),'telemetry':{'memory_total_bytes':1000,'memory_available_bytes':500},'host_info':{'os':'Windows 11'},'network':network,'capabilities':{'operations':['service_status'],'services':['print'],'shell_commands':True,'actions':['service_restart'],'action_services':{'print':'Spooler'}}}
    assert client.post('/api/agent/heartbeat',json=payload,headers=headers).status_code==200
    with store.connect() as c:c.execute('INSERT INTO checks(id,machine_id,name,kind,config,interval,fail_after,recover_after,severity,next_run) VALUES(?,?,?,?,?,60,3,2,?,0)',(uid(),machine,'Docker','docker',json.dumps({'target':'immich'}),'medium'))
    reply=client.post('/api/agent/checks',json={'results':[]},headers=headers)
    assert reply.status_code==200 and reply.json['checks'][0]['kind']=='docker'
    from aiticket.hostview import overview
    assert overview(store)[0]['sample']['source']=='Windows agent'
    from aiticket.machine_context import context
    with store.connect() as c:assert context(c,machine)['shell']['interpreter']=='powershell'


def test_windows_check_creation_and_export_validation(signed_in):
    client,store,_,csrf=signed_in;machine,_,_=enrolled(store)
    for kind,target in [('process','service:Spooler'),('process','notepad.exe'),('smb',r'\\nas\photos')]:
        reply=client.post('/checks',data={'csrf':csrf,'machine_id':machine,'name':kind,'kind':kind,'target':target,'interval':'60','fail_after':'3','recover_after':'2','severity':'medium'})
        assert reply.status_code==302,reply.data
    assert not valid_target('process','service:x;Remove-Item',True)
    assert not valid_target('smb',r'C:\photos',True)
    assert valid_target('smb',r'\\nas\photos',True)
    assert not valid_target('smb',r'\\nas\photos',False)


def test_windows_readonly_rejects_mutations():
    for text in ['Get-Service','Get-Service -Name Spooler','Get-NetIPAddress','Get-CimInstance -ClassName Win32_OperatingSystem','Get-Process -Name notepad']:
        assert read_only(text),text
    for text in ['Restart-Service Spooler','Get-Service; Restart-Service Spooler','Get-Service -ComputerName other','Get-CimInstance -ClassName EvilClass','Get-Process | Stop-Process','Get-Service $(Remove-Item x)','Get-Date -Date tomorrow','Get-Service -Name x #anything']:
        assert not read_only(text),text


def test_mixed_fleet_uses_correct_interpreter(environment,monkeypatch):
    _,store,vault=environment;machine,_,_=enrolled(store);linux=uid()
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,0)',(linux,'Linux'))
    from aiticket.fleet import plan,launch
    values={'kind':'packages','packages':'curl','label':'Packages'};text,commands=plan(store,values,[machine,linux])
    assert 'choco.exe' in commands[machine] and 'apt-get' in commands[linux]
    assert 'Windows' in text and 'Linux' in text
    calls=[];monkeypatch.setattr('aiticket.commands.queue',lambda *a:calls.append(a))
    launch(store,vault,values,[machine,linux]);assert {c[2]:c[3] for c in calls}==commands
    from aiticket.windows_fleet import command
    assert 'New-LocalUser' in command(store,{'kind':'user','username':'fixture','access':'administrator'})
    for values in ({'kind':'packages','packages':'x;Restart-Computer'},{'kind':'user','username':'x;evil'}):
        with pytest.raises(ValueError):command(store,values)


def test_windows_does_not_inherit_linux_only_health_alerts(environment):
    from aiticket import health_rules as health
    _,store,_=environment;machine,_,_=enrolled(store)
    linux=uid();linux_agent=uid()
    with store.connect() as c:
        c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,0)',(linux,'Linux'))
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,host_info) VALUES(?,?,?,?)',(linux_agent,linux,'linux-fixture',json.dumps({'os':'Ubuntu'})))
    for metric in ('memory_pressure_percent','inode_used_percent','cpu_percent'):
        cfg=health.defaults(metric)
        health.save(store,'*',{'metric':metric,'unit':'percent','threshold':str(cfg['threshold']),'recovery':str(cfg['recovery']),'sustain_seconds':'120','severity':'medium','enabled':'yes'})
    assert all(json.loads(c['config'])['metric']=='cpu_percent' for c in store.rows('SELECT config FROM checks WHERE machine_id=? AND enabled=1',(machine,)))
    assert len(store.rows('SELECT id FROM checks WHERE machine_id=? AND enabled=1',(linux,)))==3
    cards=health.cards(store,machine)
    assert {c['metric'] for c in cards if c['unsupported']}=={'memory_pressure_percent','inode_used_percent'}
