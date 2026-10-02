import importlib.util,json,time,uuid
from pathlib import Path
from unittest.mock import patch,Mock
import pytest
from aiticket import commands
from aiticket.security import digest,hermes_headers


def setup(store,approval='immediate',external='yes',hermes='yes'):
    with store.connect() as c:
        c.execute("INSERT INTO machines(id,name,created) VALUES('shell-host','Shell host',?)",(time.time(),))
        c.execute("INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES('shell-agent','shell-host',?,?,?)",(digest('fixture-agent-credential'),time.time(),json.dumps({'shell_commands':True})))
    commands.configure(store,'shell-host',{'enabled':'yes','approval':approval,'external':external,'hermes':hermes})
    return 'shell-host'


def dispatch(store,vault,identifier):
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        jobs=commands.poll(c,store,vault,'shell-agent',time.time())
    assert jobs[0]['id']==identifier
    return jobs[0]


def test_command_queue_atomic_identity_approval_and_no_dispatch_replay(environment):
    _,store,vault=environment;mid=setup(store,approval='required');identifier=str(uuid.uuid4())
    commands.queue(store,vault,mid,'printf hello',identifier)
    assert commands.queue(store,vault,mid,'printf hello',identifier)==identifier
    with pytest.raises(ValueError): commands.queue(store,vault,mid,'printf changed',identifier)
    with store.connect() as c: assert commands.poll(c,store,vault,'shell-agent',time.time())==[]
    row=commands.view(store,vault,identifier)
    with pytest.raises(ValueError): commands.decide(store,identifier,'approve','wrong-hash')
    commands.decide(store,identifier,'approve',row['fingerprint']);job=dispatch(store,vault,identifier)
    with store.connect() as c: assert commands.poll(c,store,vault,'shell-agent',time.time())==[]
    assert commands.permission(store,'wrong-agent',job)=={'allowed':False}
    assert commands.permission(store,'shell-agent',job)=={'allowed':True}
    commands.decide(store,identifier,'cancel')
    assert commands.permission(store,'shell-agent',job)=={'allowed':False}
    result={**job,'result':{'state':'cancelled','exit_code':-9,'stdout':'','stderr':'cancelled','truncated':False}}
    assert commands.complete(store,'shell-agent',result)=={'status':'accepted'}
    assert commands.complete(store,'shell-agent',result)=={'status':'duplicate'}


def test_external_hmac_target_policy_and_agent_result_identity(environment):
    app,store,vault=environment;mid=setup(store);secret='fixture-operations-secret';store.save('hermes_secret',vault.encrypt(secret))
    client=app.test_client();identifier=str(uuid.uuid4())
    body=json.dumps({'action':'run','machine_id':mid,'command':'uptime','id':identifier}).encode()
    assert client.post('/api/operations/command',data=body,content_type='application/json').status_code==401
    assert client.post('/api/operations/command',data=body,headers=hermes_headers(secret,body,identifier)).status_code==200
    job=dispatch(store,vault,identifier)
    assert client.post('/api/agent/command-permission',json=job).status_code==401
    auth={'Authorization':'Bearer fixture-agent-credential'}
    assert client.post('/api/agent/command-permission',json=job,headers=auth).json=={'allowed':True}
    bad={**job,'dispatch_token':'wrong','result':{'state':'completed','exit_code':0,'stdout':'ok','stderr':'','truncated':False}}
    assert client.post('/api/agent/command-result',json=bad,headers=auth).status_code==400
    commands.configure(store,mid,{'enabled':'yes','external':'no'})
    assert client.post('/api/agent/command-permission',json=job,headers=auth).json=={'allowed':False}
    assert commands.view(store,vault,identifier)['state']=='cancelling'


def test_unknown_timeout_serializes_until_manual_reconciliation(environment):
    _,store,vault=environment;mid=setup(store);identifier=str(uuid.uuid4());commands.queue(store,vault,mid,'slow command',identifier);dispatch(store,vault,identifier)
    with store.connect() as c: commands.poll(c,store,vault,'shell-agent',time.time()+400)
    assert commands.view(store,vault,identifier)['state']=='unknown'
    with pytest.raises(ValueError): commands.queue(store,vault,mid,'do not overlap',str(uuid.uuid4()))
    commands.decide(store,identifier,'reconcile')
    commands.queue(store,vault,mid,'reviewed next command',str(uuid.uuid4()))


def agent_module():
    spec=importlib.util.spec_from_file_location('command_agent_fixture',Path(__file__).parents[1]/'agent/commands.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def test_agent_real_harmless_shell_exit_streams_bounds_and_cancellation():
    module=agent_module();policy=lambda:{'enabled':True,'timeout':5,'output_limit':1024,'sudo':False}
    result=module.execute({'command':'printf hello; printf error >&2; exit 7','timeout':5,'output_limit':1024},lambda:True,policy)
    assert result['state']=='failed' and result['exit_code']==7 and result['stdout']=='hello' and result['stderr']=='error'
    result=module.execute({'command':'yes x','timeout':1,'output_limit':1024},lambda:True,policy)
    assert result['state']=='unknown' and result['truncated'] and len(result['stdout'].encode())<=1024
    permission=iter([True,False])
    result=module.execute({'command':'sleep 30','timeout':5,'output_limit':1024},lambda:next(permission),policy)
    assert result['state']=='cancelled'
    with patch.object(module.subprocess,'Popen') as process:
        assert module.execute({'command':'never','timeout':5,'output_limit':1024},lambda:False,policy)['state']=='cancelled'
        process.assert_not_called()


def test_agent_restart_never_replays_and_policy_defaults_disabled(tmp_path):
    module=agent_module();state={'command_ledger':{'stable':{'state':'running','dispatch_token':'token'}}};module.recover(state)
    assert state['command_results'][0]['result']['state']=='unknown'
    module.recover(state);assert len(state['command_results'])==1
    assert module.policy_config(tmp_path/'missing')=={'enabled':False}
    p=tmp_path/'policy';p.write_text('{"commands":{"enabled":true}}');p.chmod(0o666)
    with pytest.raises(ValueError): module.policy_config(p)


def test_ai_command_tool_scoped_to_ticket_and_revoked_on_takeover(environment):
    from test_codex_mode import configure
    from aiticket import ai
    app,store,vault=environment;incident=configure(store,vault)
    mid=store.rows('SELECT machine_id FROM incidents WHERE id=?',(incident,))[0]['machine_id']
    with store.connect() as c:
        c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES(?,?,?,?,?)',('ai-shell',mid,'fake',time.time(),'{"shell_commands":true}'))
    commands.configure(store,mid,{'enabled':'yes','hermes':'yes','approval':'immediate'})
    bridge=store.setting('hermes_config');bridge['command_tools']=True;store.save('hermes_config',bridge)
    jobid=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(jobid,))
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(jobid,))[0];auth={'Authorization':'Bearer '+vault.decrypt(row['credential'])}
    response=app.test_client().post('/api/hermes/'+jobid+'/command',json={'action':'run','machine_id':'different-host','command':'uptime','id':str(uuid.uuid4())},headers=auth)
    assert response.status_code==200 and response.json['machine_id']==mid
    ai.cancel(store,jobid)
    assert app.test_client().post('/api/hermes/'+jobid+'/command',json={'action':'targets'},headers=auth).status_code==403


def test_gui_command_policy_requires_explicit_confirmation(signed_in):
    client,store,_,csrf=signed_in;setup(store)
    assert client.post('/hosts/shell-host/command-policy',data={'csrf':csrf,'enabled':'yes','approval':'immediate'}).status_code==400
    assert b'Remote commands' in client.get('/hosts/shell-host').data
    assert client.post('/hosts/shell-host/command',data={'csrf':csrf,'command':'uptime','request_id':str(uuid.uuid4())}).status_code==302


def test_operational_runner_exposes_only_compact_command_tool(monkeypatch):
    from aiticket.hermes_runner import execute
    from types import SimpleNamespace
    monkeypatch.setenv('AITICKET_EXECUTION_MODE','codex');monkeypatch.setenv('AITICKET_COMMAND_TOOLS','1')
    route={'provider':'openai-codex','api_mode':'codex_responses','base_url':'https://chatgpt.com/backend-api/codex','api_key':'fixture-oauth'}
    class Agent:
        def __init__(self,**kwargs):
            assert kwargs['enabled_toolsets']==['aiticket'] and kwargs['max_iterations']==12
            assert kwargs['request_overrides']=={} and kwargs['skip_memory'] and kwargs['skip_background_review']
            self.tools=[{'type':'function','function':{'name':'aiticket_host'}}];self.client=SimpleNamespace(base_url=route['base_url'])
        def run_conversation(self,prompt):
            assert prompt.startswith('CURRENT ADMINISTRATOR TASK (instruction for this run):\nRun id now')
            assert 'arbitrary shell commands' in prompt and 'Do not replay' in prompt
            return {'completed':True,'final_response':'Compact command results'}
    job={'execution_mode':'codex','command_tools':True,'model':'gpt-6.1-sol','reasoning':'low','execution_id':'job','credential':'fixture','max_calls':1,'evidence':json.dumps({'administrator_task':'Run id now','checkpoint':{'note':'historical only'}})}
    with patch('aiticket.hermes_runner.codex_runtime',return_value=route),patch('aiticket.command_tools.register') as register:
        assert execute(Agent,job,'http://192.0.2.10')['state']=='completed'
        register.assert_called_once()
    monkeypatch.delenv('AITICKET_COMMAND_TOOLS')
    with patch('aiticket.hermes_runner.codex_runtime',return_value=route),pytest.raises(RuntimeError):execute(Agent,job,'http://192.0.2.10')


def test_required_ai_proposal_can_be_approved_after_investigation_finishes(environment):
    from test_codex_mode import configure
    from aiticket import ai
    _,store,vault=environment;incident=configure(store,vault);mid=store.rows('SELECT machine_id FROM incidents WHERE id=?',(incident,))[0]['machine_id']
    with store.connect() as c:c.execute('INSERT INTO agents(id,machine_id,credential_digest,last_seen,capabilities) VALUES(?,?,?,?,?)',('shell-agent',mid,'fixture',time.time(),'{"shell_commands":true}'))
    commands.configure(store,mid,{'enabled':'yes','hermes':'yes','approval':'required'})
    bridge=store.setting('hermes_config');bridge['command_tools']=True;store.save('hermes_config',bridge)
    jobid=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(jobid,))
    identifier=str(uuid.uuid4());commands.queue(store,vault,mid,'uptime',identifier,incident,jobid)
    ai.cancel(store,jobid)
    commands.decide(store,identifier,'approve',commands.view(store,vault,identifier)['fingerprint'])
    assert dispatch(store,vault,identifier)['id']==identifier


def test_command_tool_ambiguous_delivery_preserves_uuid_and_mcp_handshake(tmp_path):
    import subprocess,os
    from aiticket.command_tools import invoke
    identifier=str(uuid.uuid4())
    with patch('aiticket.command_tools.requests.post',side_effect=TimeoutError):
        result=json.loads(invoke('http://192.0.2.10',{'action':'run','machine_id':'target','command':'uptime','id':identifier},secret='fixture-secret'))
        assert result['id']==identifier and 'Do not replay' in result['error']
    secret=tmp_path/'secret';secret.write_text('fixture-secret-at-least-sixteen')
    env={**os.environ,'AITICKET_ALLOW_INSECURE_HTTP':'1'}
    reply=subprocess.run([str(Path(__import__('sys').executable)),'-m','aiticket.command_tools','--server','http://192.0.2.10','--secret-file',str(secret),'--allow-http'],input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n',text=True,capture_output=True,env=env,timeout=10,check=True)
    docs=[json.loads(line) for line in reply.stdout.splitlines()]
    assert docs[0]['result']['capabilities']=={'tools':{}}
    assert docs[1]['result']['tools'][0]['name']=='aiticket_host'


def test_command_key_rotation_preserves_plaintext_and_immutability(environment,tmp_path):
    from aiticket.administration import rotate_key
    import sqlite3
    _,store,vault=environment;mid=setup(store);identifier=str(uuid.uuid4())
    commands.queue(store,vault,mid,'printf retained',identifier)
    replacement=rotate_key(store,vault,tmp_path/'rotated-command-key')
    assert commands.view(store,replacement,identifier)['command']=='printf retained'
    with pytest.raises(sqlite3.IntegrityError):
        with store.connect() as c:c.execute('UPDATE command_jobs SET command=? WHERE id=?',('changed',identifier))


def test_inventory_import_disables_command_authority_and_blocks_unknown(environment):
    from aiticket.inventory import export_inventory,import_inventory
    _,store,vault=environment;mid=setup(store)
    document=export_inventory(store);assert 'command_policies' not in document['tables']
    import_inventory(store,vault,document)
    assert store.rows('SELECT enabled FROM command_policies')[0]['enabled']==0
    commands.configure(store,mid,{'enabled':'yes','approval':'immediate'})
    identifier=str(uuid.uuid4());commands.queue(store,vault,mid,'uptime',identifier);dispatch(store,vault,identifier)
    with store.connect() as c:commands.poll(c,store,vault,'shell-agent',time.time()+400)
    with pytest.raises(ValueError):import_inventory(store,vault,document)


def test_bridge_compatibility_child_receives_direct_tool_profile(monkeypatch):
    from types import SimpleNamespace
    from aiticket import hermes_bridge
    monkeypatch.setenv('AITICKET_COMMAND_TOOLS','1')
    def child(command,**kwargs):
        config=json.loads((Path(kwargs['env']['HERMES_HOME'])/'config.yaml').read_text())
        assert kwargs['env']['AITICKET_COMMAND_TOOLS']=='1'
        assert config['model']['streaming'] is False
        return SimpleNamespace(returncode=0 if config['tools']['tool_search']['enabled']=='off' else 1)
    with patch('aiticket.hermes_bridge.subprocess.run',side_effect=child):
        assert hermes_bridge.check_adapter('/fixture/python','/fixture/hermes','http://192.0.2.10')
