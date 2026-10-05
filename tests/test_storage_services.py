import json,time,ssl
from unittest.mock import patch,Mock
import pytest,requests
from aiticket import integrations,truenas,plex,discovery
from aiticket.security import digest
from aiticket.engine import observe

CFG={'url':'https://nas.example.com','ca':True,'interval':60,'username':'monitor'}
RAW={'system':{'hostname':'voyager','version':'TrueNAS-25.04.2.6','cores':8,'physmem':16*1024**3,'uptime_seconds':3600},'pools':[{'id':1,'name':'tank','healthy':True,'status':'ONLINE','topology':{'data':[{'type':'RAIDZ','parity':1}]}}], 'datasets':[{'id':'tank','used':{'parsed':1024**4},'available':{'parsed':2*1024**4},'mountpoint':{'value':'/mnt/tank'}}], 'apps':[{'name':'plex','state':'RUNNING','human_version':'1.2','active_workloads':{'container_details':[{'id':'abc','service_name':'plex','image':'plex/image','state':'running','environment':{'secret':'must-not-retain'}}],'volumes':[{'source':'/mnt/media','destination':'/media','password':'must-not-retain'}]}}],'alerts':[],'services':[{'service':'cifs','state':'RUNNING'}]}
EVENTS={'reporting.realtime':{'cpu':{'cpu':{'usage':12,'temp':48}},'memory':{'physical_memory_total':16*1024**3,'physical_memory_available':8*1024**3},'interfaces':{'eno1':{'link_state':'LINK_STATE_UP','speed':10000,'received_bytes_rate':1024,'sent_bytes_rate':2048}},'disks':{'busy':5,'read_bytes':1200}},'app.stats':[{'app_name':'plex','cpu_usage':5,'memory':1024**3,'networks':[{'rx_bytes':1024,'tx_bytes':2048}],'blkio':{'read':0,'write':1048576}}]}

def sample():return truenas.normalize(RAW,EVENTS)

def machine(store):
    with store.connect() as c:c.execute("INSERT INTO machines(id,name,created) VALUES('m','Media host',1)")

def test_normalization_multiple_sources_no_configuration_secrets():
    data=sample()
    assert data['pools'][0]['raid']=='RAIDZ1'
    assert data['metrics']['cpu_percent']==12 and data['metrics']['disk_free_bytes']==2*1024**4
    assert data['apps'][0]['metrics']['memory_gib']==1
    assert 'must-not-retain' not in json.dumps(data)
    assert truenas.normalize({'system':{}}, {})['metrics']=={}


def test_rpc_reads_only_tls_and_event_matching():
    ws=Mock();ws.recv.side_effect=[json.dumps({'method':'collection_update','params':{'collection':'app.stats:{"interval":2}','fields':[]}}),json.dumps({'id':1,'result':{'version':'25.04'}})]
    with patch('websocket.create_connection',return_value=ws) as connect:
        client=truenas.Client(CFG)
        assert client.call('system.info')['version']=='25.04'
        assert client.events['app.stats']==[]
        assert connect.call_args.args[0]=='wss://nas.example.com/api/current'
        assert connect.call_args.kwargs['sslopt']['cert_reqs']==ssl.CERT_REQUIRED
        assert connect.call_args.kwargs['redirect_limit']==0
        for method in ('app.stop','pool.delete','system.reboot','filesystem.put'):
            with pytest.raises(ValueError):client.call(method)
        with pytest.raises(ValueError):client.call('core.subscribe','app.container_log_follow')
        client.close();ws.close.assert_called_once()


def test_collection_optional_permission_failure_and_close():
    fake=Mock();fake.call.side_effect=[{'response_type':'SUCCESS'},RAW['system'],RAW['pools'],RAW['datasets'],truenas.RPCError('app.query'),[],[]];fake.statistics.return_value=EVENTS
    with patch('aiticket.truenas.Client',return_value=fake):data=truenas.collect(CFG,'fixture-secret')
    assert 'apps' not in data and data['warnings']
    fake.close.assert_called_once()
    assert fake.call.call_args_list[0].args==('auth.login_ex',{'mechanism':'API_KEY_PLAIN','username':'monitor','api_key':'fixture-secret'})


def test_add_host_test_inline_error_and_real_render(signed_in):
    client,store,vault,csrf=signed_in
    fields={'csrf':csrf,'name':'Voyager','host_kind':'truenas','url':'https://nas.example.com','username':'monitor','token':'fixture-key','interval':'60','operation':'test'}
    with patch('aiticket.integrations.read',return_value=sample()):
        response=client.post('/hosts',data=fields)
        assert response.status_code==200 and b'1 pools and 1 applications' in response.data
        assert not store.rows('SELECT * FROM machines')
        fields['url']='http://nas.example.com'
        response=client.post('/hosts',data=fields)
        assert response.status_code==400 and b'value="Voyager"' in response.data and b'role="alert"' in response.data
        fields.update(url='https://nas.example.com',operation='add')
        response=client.post('/hosts',data=fields);assert response.status_code==302
        assert len(store.rows('SELECT * FROM machines'))==1
        connection=store.rows('SELECT * FROM integrations')[0]
        assert connection['secret']!='fixture-key' and vault.decrypt(connection['secret'])=='fixture-key'
        page=client.get(response.location)
        assert page.status_code==200 and b'RAIDZ1' in page.data and b'NAS applications' in page.data and b'fixture-key' not in page.data
        assert client.get('/hosts/'+connection['machine_id']+'/settings').status_code==200
        assert client.get('/hosts').status_code==200
        assert client.post('/hosts',data={**fields,'parent':'does-not-exist'}).status_code==400
        assert len(store.rows('SELECT * FROM machines'))==1


def test_pool_and_app_checks_stale_unknown_failure_and_ticket(environment):
    _,store,vault=environment;machine(store)
    identifier=integrations.save(store,vault,'m','truenas','NAS',CFG,'fixture-key',snapshot=sample())
    appcheck=integrations.add_check(store,identifier,'app','plex')
    assert integrations.add_check(store,identifier,'app','plex')==appcheck
    cfg={'connection_id':identifier,'scope':'host'}
    assert integrations.probe(store,'truenas',cfg)[0] is True
    data=sample();data['pools'][0]['healthy']=None
    with store.connect() as c:c.execute('UPDATE integrations SET snapshot=?',(json.dumps(data),))
    assert integrations.probe(store,'truenas',cfg)[0] is None
    data['apps'][0]['state']='STOPPED'
    with store.connect() as c:c.execute('UPDATE integrations SET snapshot=?',(json.dumps(data),))
    for n in range(3):
        healthy,evidence=integrations.probe(store,'truenas',{'connection_id':identifier,'scope':'app','target':'plex'});observe(store,appcheck,healthy,evidence,now=time.time()+n)
    assert len(store.rows('SELECT * FROM incidents'))==1
    with store.connect() as c:c.execute('UPDATE integrations SET at=?',(time.time()-1000,))
    assert integrations.probe(store,'truenas',cfg)[0] is None
    with pytest.raises(ValueError,match='current'):integrations.add_check(store,identifier,'pool','1')


def test_poll_history_context_encrypted_key_retained_edit_and_deletion(environment):
    _,store,vault=environment;machine(store)
    identifier=integrations.save(store,vault,'m','truenas','NAS',CFG,'fixture-key',snapshot=sample())
    with patch('aiticket.integrations.read',return_value=sample()):assert integrations.tick(store,vault)
    assert store.rows("SELECT * FROM metric_samples WHERE source='truenas'")
    from aiticket.machine_context import context
    with store.connect() as c:data=context(c,'m')
    assert data['services'][0]['data']['apps'][0]['name']=='plex' and 'fixture-key' not in json.dumps(data)
    integrations.save(store,vault,'m','truenas','NAS renamed',CFG,'',identifier,sample())
    assert vault.decrypt(store.rows('SELECT secret FROM integrations')[0]['secret'])=='fixture-key'
    integrations.remove(store,identifier)
    assert not store.rows('SELECT * FROM integrations') and store.rows('SELECT enabled FROM checks')[0]['enabled']==0


def response(data=None,status=200,headers=None):
    r=Mock(status_code=status,headers=headers or {});r.iter_content.return_value=iter([json.dumps(data).encode()] if data is not None else [b'x']);return r


def test_plex_reads_one_byte_without_redirect_or_token_in_url():
    cfg={'url':'http://plex.example.com:32400','ca':True,'library_id':'1'}
    replies=[response({'MediaContainer':{'machineIdentifier':'fixture','version':'1.2'}}),response({'MediaContainer':{'Directory':[{'key':'1','title':'Movies','type':'movie'}]}}),response({'MediaContainer':{'size':1,'Metadata':[{'TranscodeSession':{},'User':{'title':'private-user'}}]}}),response({'MediaContainer':{'Metadata':[{'Media':[{'Part':[{'key':'/library/parts/12/123/file.mkv'}]}]}]}}),response(status=206,headers={'Content-Range':'bytes 0-0/100'})]
    with patch('aiticket.plex.requests.get',side_effect=replies) as get:
        data=plex.collect(cfg,'fixture-token')
    assert data['media_access'] is True and data['metrics']['transcoding_sessions']==1
    assert 'private-user' not in json.dumps(data)
    call=get.call_args;assert call.kwargs['headers']['Range']=='bytes=0-0' and not call.kwargs['allow_redirects']
    assert 'fixture-token' not in call.args[0] and call.kwargs['headers']['X-Plex-Token']=='fixture-token'
    assert all(r.close.called for r in replies)


def test_plex_media_200_unverified_auth_unknown_transport_down():
    cfg={'url':'http://plex.example.com','ca':True}
    with patch('aiticket.plex.requests.get',return_value=response(status=200)):
        with pytest.raises(plex.PlexError,match='unverified'):plex.get(cfg,'token','/library/parts/1/2/file.mkv',media=True)
    with patch('aiticket.plex.requests.get',return_value=response(status=401)):
        with pytest.raises(plex.PlexError,match='token'):plex.collect(cfg,'token')
    with patch('aiticket.plex.requests.get',side_effect=requests.exceptions.ConnectionError()):assert plex.collect(cfg,'token')['responsive'] is False
    with pytest.raises(ValueError):plex.get(cfg,'token','/library/parts/1/2/file/../../settings')


def test_plex_service_setup_test_edit_media_check_ui(signed_in):
    client,store,vault,csrf=signed_in;machine(store)
    data={'responsive':True,'version':'1.2','libraries':[{'id':'1','name':'Movies','type':'movie'}],'media_access':True,'media_reason':'Plex read a sample file successfully.','metrics':{'active_sessions':0},'warnings':[]}
    fields={'csrf':csrf,'name':'Plex','machine_id':'m','url':'http://plex.example.com:32400','token':'fixture-token','operation':'test'}
    with patch('aiticket.integrations.read',return_value=data):
        assert client.post('/services/new',data=fields).status_code==200
        assert not store.rows('SELECT * FROM integrations')
        result=client.post('/services/new',data={**fields,'operation':'save','library_id':'1'});assert result.status_code==302
        identifier=store.rows('SELECT id FROM integrations')[0]['id']
        page=client.get(result.location);assert page.status_code==200 and b'Media access' in page.data and b'fixture-token' not in page.data
        assert client.post(result.location,data={**fields,'token':'','operation':'save','library_id':'1'}).status_code==302
        assert client.post('/integrations/'+identifier+'/checks',data={'csrf':csrf,'scope':'media'}).status_code==302
        assert client.get('/applications').status_code==200
        assert client.get('/hosts/m').status_code==200
        with store.connect() as c:c.execute('UPDATE integrations SET at=? WHERE id=?',(time.time()-1000,identifier))
        stale=client.get(result.location).data
        assert b'Awaiting current readings' in stale and b'>Readable</span>' not in stale
        assert client.post('/integrations/'+identifier+'/delete',data={'csrf':csrf}).status_code==302
        assert all(not r['enabled'] for r in store.rows('SELECT enabled FROM checks'))


def test_discovery_freshness_revocation_opt_in_and_validation(signed_in):
    client,store,vault,csrf=signed_in;machine(store)
    with store.connect() as c:c.execute("INSERT INTO agents(id,machine_id,credential_digest) VALUES('a','m',?)",(digest('fixture-agent'),))
    inventory={'docker_installed':True,'containers':[{'name':'plex','target':'plex','state':'running','image':'plex'}],'processes':[{'name':'server','target':'server','pid':123,'memory_bytes':1024}]}
    reply=client.post('/api/agent/heartbeat',headers={'Authorization':'Bearer fixture-agent'},json={'event_id':'d1','sampled_at':time.time(),'discovery':inventory})
    assert reply.status_code==200
    assert len(store.rows('SELECT * FROM checks'))==0
    assert client.get('/hosts/m').status_code==200
    assert client.post('/hosts/m/discovery-check',data={'csrf':csrf,'kind':'docker','target':'plex'}).status_code==302
    assert discovery.add_check(store,'m','docker','plex')==store.rows('SELECT id FROM checks')[0]['id']
    with store.connect() as c:c.execute('UPDATE agents SET revoked=1')
    assert discovery.view(store,'m') is None
    with pytest.raises(ValueError):discovery.validate({'processes':[{'name':'x','target':'x','cpu_percent':float('nan')}]})


def test_poll_config_edit_race_does_not_overwrite_new_settings(environment):
    _,store,vault=environment;machine(store)
    identifier=integrations.save(store,vault,'m','truenas','NAS',CFG,'old-key',snapshot=sample())
    row=store.rows('SELECT * FROM integrations')[0]
    integrations.save(store,vault,'m','truenas','NAS',{**CFG,'url':'https://other.example.com'},'new-key',identifier,sample())
    with patch('aiticket.integrations.read',return_value={'error':'old result'}):integrations.refresh(store,vault,row)
    assert 'old result' not in store.rows('SELECT snapshot FROM integrations')[0]['snapshot']


def test_encrypted_integrations_survive_key_rotation(environment,tmp_path):
    _,store,vault=environment;machine(store)
    integrations.save(store,vault,'m','truenas','NAS',CFG,'fixture-key',snapshot=sample())
    from aiticket.administration import rotate_key
    new=rotate_key(store,vault,tmp_path/'new.key')
    assert new.decrypt(store.rows('SELECT secret FROM integrations')[0]['secret'])=='fixture-key'


def test_public_plex_identity_does_not_validate_bad_token():
    with patch('aiticket.plex.requests.get',side_effect=[response({'MediaContainer':{'machineIdentifier':'fixture','version':'1'}}),response(status=401)]):
        with pytest.raises(plex.PlexError,match='token'):plex.collect({'url':'http://plex.example.com'},'bad-token')


def test_linux_discovery_omits_arguments_and_process_delta(tmp_path,monkeypatch):
    import importlib.util
    from pathlib import Path
    spec=importlib.util.spec_from_file_location('fixture_monitoring',Path(__file__).resolve().parents[1]/'agent'/'monitoring.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    proc=tmp_path/'123';proc.mkdir();(proc/'comm').write_text('server');(proc/'cmdline').write_text('password=private-command')
    columns=['0']*25;columns[11]='100';columns[12]='0';columns[19]='123';columns[21]='100';(proc/'stat').write_text('123 (server) '+' '.join(columns))
    real=module.Path
    monkeypatch.setattr(module,'Path',lambda path:tmp_path if path=='/proc' else real(path))
    monkeypatch.setattr('shutil.which',lambda _:None)
    state={};first=module.discover(state)
    columns[11]='200';(proc/'stat').write_text('123 (server) '+' '.join(columns));state['discovery_at']-=2
    second=module.discover(state)
    assert first['processes'][0]['target']=='server' and second['processes'][0]['cpu_percent']>0
    assert 'private-command' not in json.dumps(second)


def test_truenas_explicit_skip_certificate_verification():
    form={'url':CFG['url'],'username':'monitor','interval':'60','ca':'/missing/old-ca.pem','skip_certificate_verification':'yes'}
    cfg=integrations.config(form,'truenas')
    assert cfg['verify_tls'] is False and cfg['ca']=='/missing/old-ca.pem'
    with patch('websocket.create_connection',return_value=Mock()) as connect:
        truenas.Client(cfg).close()
        assert connect.call_args.args[0].startswith('wss://')
        assert connect.call_args.kwargs['sslopt']=={'cert_reqs':ssl.CERT_NONE,'check_hostname':False}
        assert connect.call_args.kwargs['redirect_limit']==0
    with pytest.raises(ValueError,match='certificate file'):
        integrations.config({**form,'skip_certificate_verification':''},'truenas')
    with pytest.raises(ValueError):
        integrations.config({**form,'url':'http://nas.example.com'},'truenas')
    default=integrations.config({**form,'ca':'','skip_certificate_verification':''},'truenas')
    assert default['verify_tls'] is True
    # A string false is not an explicit boolean opt-out in saved configuration.
    with patch('websocket.create_connection',return_value=Mock()) as connect:
        truenas.Client({**CFG,'verify_tls':'false'}).close()
        assert connect.call_args.kwargs['sslopt']['cert_reqs']==ssl.CERT_REQUIRED


def test_truenas_tls_choice_add_edit_test_and_poll(signed_in):
    client,store,vault,csrf=signed_in
    fields={'csrf':csrf,'name':'Voyager','host_kind':'truenas','url':CFG['url'],'username':'monitor','token':'fixture-key','interval':'60','operation':'add','skip_certificate_verification':'yes','ca':'/missing/old-ca.pem'}
    with patch('aiticket.integrations.read',return_value=sample()) as read:
        response=client.post('/hosts',data=fields)
        assert response.status_code==302
        connection=store.rows('SELECT * FROM integrations')[0]
        assert json.loads(connection['config'])['verify_tls'] is False
        settings='/hosts/'+connection['machine_id']+'/settings'
        page=client.get(settings)
        assert b'aria-label="Skip certificate verification" checked' in page.data
        assert client.post(settings,data={**fields,'token':'','operation':'test'}).status_code==200
        assert read.call_args.args[1]['verify_tls'] is False
        assert integrations.tick(store,vault)
        assert read.call_args.args[1]['verify_tls'] is False
        # Unchecking restores verified TLS and leaves existing credentials intact.
        response=client.post(settings,data={**fields,'token':'','ca':'','skip_certificate_verification':'','operation':'save'})
        assert response.status_code in (200,302)
        connection=store.rows('SELECT * FROM integrations')[0]
        assert json.loads(connection['config'])['verify_tls'] is True
        assert vault.decrypt(connection['secret'])=='fixture-key'
        assert b'aria-label="Skip certificate verification" checked' not in client.get(settings).data
