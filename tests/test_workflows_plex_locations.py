import json,time,uuid
from unittest.mock import patch
import pytest
from aiticket import knowledge,knowledge_workflows as workflows,plex,integrations,ai
from aiticket.engine import resolve_verified
from test_codex_mode import configure
from test_storage_services import response,machine,RAW
from aiticket.truenas import normalize


def procedure(store,machine_id=None):
    folder=knowledge.root(store,'host' if machine_id else 'troubleshooting',machine=machine_id)
    article=knowledge.save(store,folder_id=folder,title='Restore media access',body='Check mount and read a file.',status='published')
    values={key:key+' steps' for key in workflows.PHASES}|{'enabled':'yes','version':'0'}
    workflows.save(store,article,values)
    return article,values


def test_workflow_version_scope_phases_and_independent_verification(environment):
    _,store,vault=environment;incident=configure(store,vault)
    target=store.rows('SELECT machine_id FROM incidents WHERE id=?',(incident,))[0]['machine_id']
    article,values=procedure(store,target)
    store.save('hermes_config',{**store.setting('hermes_config'),'command_tools':True})
    job=ai.request_job(store,vault,incident,workflow_article=article)
    with store.connect() as c:
        assert workflows.available(c,{target}) and not workflows.available(c,{'other'})
        run=c.execute('SELECT * FROM kb_workflow_runs').fetchone()
        with pytest.raises(ValueError,match='earlier'):workflows.tool(c,store,{'article_id':article,'phase':'fix','outcome':'passed','summary':'Fresh evidence'},target,incident,job)
        for phase in workflows.PHASES:workflows.tool(c,store,{'article_id':article,'phase':phase,'outcome':'passed','summary':'Current check '+phase},target,incident,job)
        assert c.execute('SELECT state FROM kb_workflow_runs').fetchone()[0]=='awaiting_verification'
        c.execute("UPDATE ai_jobs SET state='completed',resolution_summary='Procedure complete' WHERE id=?",(job,))
        resolve_verified(c,store,incident,'Independent checks healthy',time.time())
        assert c.execute('SELECT state FROM kb_workflow_runs').fetchone()[0]=='verified'
        with pytest.raises(ValueError,match='different'):workflows.start(c,store,article,'other',incident,job)
    old_plan=store.rows('SELECT plan FROM kb_workflow_runs')[0]['plan']
    knowledge.save(store,folder_id=knowledge.root(store,'host',machine=target),title='Changed fix',body='New procedure',status='published',identifier=article,expected=1)
    with store.connect() as c:
        assert not workflows.available(c,{target})
        with pytest.raises(ValueError,match='changed'):workflows.start(c,store,article,target,incident,job)
    workflows.save(store,article,{**values,'version':'1','fix':'New approved fix'})
    assert store.rows('SELECT plan FROM kb_workflow_runs')[0]['plan']==old_plan


def test_failed_and_readonly_workflows_never_count_as_verified(environment):
    _,store,vault=environment;incident=configure(store,vault);target=store.rows('SELECT machine_id FROM incidents')[0]['machine_id'];article,_=procedure(store)
    job=ai.request_job(store,vault,incident,read_only=True)
    with store.connect() as c:
        for phase in ('prerequisites','diagnostics'):workflows.tool(c,store,{'article_id':article,'phase':phase,'outcome':'passed','summary':'Read current facts'},target,incident,job)
        with pytest.raises(ValueError,match='Read-only'):workflows.tool(c,store,{'article_id':article,'phase':'fix','outcome':'passed','summary':'Attempt fix'},target,incident,job)
        workflows.tool(c,store,{'article_id':article,'phase':'diagnostics','outcome':'failed','summary':'Missing mount'},target,incident,job)
        resolve_verified(c,store,incident,'Other checks recovered',time.time())
        assert c.execute('SELECT state,phase FROM kb_workflow_runs').fetchone()[:]==('failed','diagnostics')


def test_workflow_ui_validation_and_start(signed_in):
    client,store,vault,csrf=signed_in;incident=configure(store,vault);target=store.rows('SELECT machine_id FROM incidents')[0]['machine_id'];article,values=procedure(store,target)
    page=client.get('/knowledge/articles/'+article+'/workflow');assert page.status_code==200 and b'Before you begin' in page.data
    bad=client.post(page.request.path,data={'csrf':csrf,'version':'1','fix':'Keep this input'})
    assert bad.status_code==200 and b'Keep this input' in bad.data and b'Fill in all four' in bad.data
    store.save('hermes_config',{**store.setting('hermes_config'),'command_tools':True})
    request_id=str(uuid.uuid4())
    fields={'csrf':csrf,'operation':'run','machine_id':target,'request_id':request_id}
    result=client.post(page.request.path,data=fields);assert result.status_code==302
    assert len(store.rows('SELECT * FROM kb_workflow_runs'))==1
    assert client.post(page.request.path,data=fields).location==result.location
    assert len(store.rows('SELECT * FROM kb_workflow_runs'))==1


def test_plex_partial_locations_and_error_privacy():
    section={'key':'1','title':'Movies','type':'movie','Location':[{'id':1,'path':'/media/Movies'},{'id':2,'path':'/backup/Movies'},{'id':3,'path':'/empty'}]}
    replies=[response({'MediaContainer':{'machineIdentifier':'fixture','version':'1'}}),response({'MediaContainer':{'Directory':[section]}}),response({'MediaContainer':{'Metadata':[{'User':{'title':'private'},'title':'secret-movie','TranscodeSession':{'error':'1','key':'private-key'}}]}}),response({'MediaContainer':{'Metadata':[{'Media':[{'Part':[{'file':'/media/Movies/secret.mkv','key':'/library/parts/1/2/file.mkv'},{'file':'/backup/Movies/secret.mkv','key':'/library/parts/2/2/file.mkv'}]}]}]}}),response(status=206,headers={'Content-Range':'bytes 0-0/100'}),response(status=404)]
    with patch('aiticket.plex.requests.get',side_effect=replies):data=plex.collect({'url':'http://plex','library_ids':['1'],'deep_monitoring':True},'secret-token')
    assert [x['readable'] for x in data['media_locations']]==[True,False,None]
    assert data['media_access'] is False and data['playback']['transcode_errors']==1
    assert all(x not in json.dumps(data) for x in ('secret.mkv','secret-movie','private-key','private','secret-token'))
    assert not plex.inside('/media/Movies-old/a','/media/Movies') and plex.inside('C:\\MEDIA\\Movies\\a.mkv','c:\\media\\movies')


def test_plex_cached_samples_and_unknown_locations():
    previous={'media_locations':[{'id':'1:1','path':'/media','sample_key':'/library/parts/1/2/file.mkv'}]}
    replies=[response({'MediaContainer':{'machineIdentifier':'fixture','version':'1'}}),response({'MediaContainer':{'Directory':[{'key':'1','title':'Movies','Location':[{'id':1,'path':'/media'}]}]}}),response({'MediaContainer':{'Metadata':[]}}),response(status=206,headers={'Content-Range':'bytes 0-0/100'})]
    with patch('aiticket.plex.requests.get',side_effect=replies) as request:data=plex.collect({'url':'http://plex','library_ids':['1'],'deep_monitoring':True,'_previous':previous},'token')
    assert data['media_access'] is True and request.call_count==4
    assert data['playback']['error_reporting_available'] and data['playback']['transcode_errors']==0
    assert plex.error_flag('unknown') is None and plex.error_flag('0') is False


def test_location_probes_and_dependencies(signed_in):
    client,store,vault,csrf=signed_in;machine(store)
    nas=integrations.save(store,vault,'m','truenas','Voyager',{'url':'https://nas','username':'monitor','interval':60},'key',snapshot=normalize(RAW,{}))
    pool=integrations.add_check(store,nas,'pool','1')
    snapshot={'responsive':True,'media_locations':[{'id':'1:2','library':'Movies','path':'/media','readable':False,'reason':'Sample unavailable'}],'playback':{'error_reporting_available':True,'transcode_errors':1}}
    cfg={'url':'http://plex','interval':60,'library_ids':['1'],'deep_monitoring':True,'nas_application':nas+'|plex','storage_checks':[pool]}
    service=integrations.save(store,vault,'m','plex','Plex',cfg,'token',snapshot=snapshot)
    location=integrations.add_check(store,service,'location','1:2');assert location==integrations.add_check(store,service,'location','1:2')
    assert integrations.probe(store,'plex',{'connection_id':service,'scope':'location','target':'1:2'})[0] is False
    assert integrations.probe(store,'plex',{'connection_id':service,'scope':'location','target':'gone'})[0] is None
    assert integrations.probe(store,'plex',{'connection_id':service,'scope':'transcode'})[0] is False
    assert len(store.rows('SELECT * FROM application_dependencies'))==4
    for path in ('/applications','/hosts/m','/services/new','/services/'+service):assert client.get(path).status_code==200
    assert b'+ Add application' in client.get('/hosts/m').data
    assert b'name="kind"' in client.get('/services/new').data
    assert b'Media locations' in client.get('/services/'+service).data
    bad=client.post('/services/new',data={'csrf':csrf,'kind':'unsupported','name':'Keep my name'})
    assert bad.status_code==200 and b'Keep my name' in bad.data and b'Choose a supported application' in bad.data


def test_workflow_tool_obeys_permissions_and_does_not_execute_saved_text(environment):
    app,store,vault=environment;incident=configure(store,vault);target=store.rows('SELECT machine_id FROM incidents')[0]['machine_id'];article,_=procedure(store,target)
    store.save('hermes_config',{**store.setting('hermes_config'),'command_tools':True})
    job=ai.request_job(store,vault,incident,workflow_article=article)
    from aiticket.maintenance_ai import check_change
    with store.connect() as c:
        with pytest.raises(ValueError,match='prerequisites'):check_change(c,job,target,command='touch /tmp/change')
        check_change(c,job,target,command='df -h')
        assert not c.execute('SELECT 1 FROM command_jobs').fetchone()
        for phase in ('prerequisites','diagnostics'):workflows.tool(c,store,{'article_id':article,'phase':phase,'outcome':'passed','summary':'Current observed evidence'},target,incident,job)
        check_change(c,job,target,command='touch /tmp/change')
        workflows.tool(c,store,{'article_id':article,'phase':'fix','outcome':'failed','summary':'Fix failed; stop'},target,incident,job)
        with pytest.raises(ValueError,match='ended'):check_change(c,job,target,method='POST')
        c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    credential=vault.decrypt(store.rows('SELECT credential FROM ai_jobs WHERE id=?',(job,))[0]['credential'])
    reply=app.test_client().post('/api/hermes/'+job+'/command',headers={'Authorization':'Bearer '+credential},json={'action':'workflow','article_id':article})
    assert reply.status_code==200 and reply.json['state']=='failed'
    assert app.test_client().post('/api/operations/command',json={'action':'workflow','article_id':article}).status_code!=200


def test_schema40_upgrades_existing_plex_connections(environment):
    _,store,vault=environment;machine(store)
    service=integrations.save(store,vault,'m','plex','Plex',{'url':'http://plex','interval':60,'library_id':'4'},'token')
    with store.connect() as c:
        for table in ('kb_workflow_events','kb_workflow_runs','kb_workflows'):c.execute('DROP TABLE '+table)
        c.execute('UPDATE schema_version SET version=39')
    from aiticket.db import Store
    upgraded=Store(store.path)
    cfg=json.loads(upgraded.rows('SELECT config FROM integrations WHERE id=?',(service,))[0]['config'])
    assert cfg['deep_monitoring'] is True and cfg['library_ids']==['4']


def test_workflow_maintenance_and_stale_verification(environment):
    _,store,vault=environment;incident=configure(store,vault);target=store.rows('SELECT machine_id FROM incidents')[0]['machine_id'];article,_=procedure(store,target)
    store.save('hermes_config',{**store.setting('hermes_config'),'command_tools':True})
    job=ai.request_job(store,vault,incident,workflow_article=article)
    from test_evidence_groups_maintenance import window
    window(store,target)
    from aiticket.maintenance_ai import check_change
    with store.connect() as c:
        for phase in ('prerequisites','diagnostics'):workflows.tool(c,store,{'article_id':article,'phase':phase,'outcome':'passed','summary':'Read current evidence'},target,incident,job)
        check_change(c,job,target,method='GET')
        with pytest.raises(ValueError,match='Maintenance'):check_change(c,job,target,method='POST')
        with pytest.raises(ValueError,match='maintenance'):workflows.tool(c,store,{'article_id':article,'phase':'fix','outcome':'passed','summary':'Fix applied'},target,incident,job)
        c.execute('DELETE FROM maintenance_windows')
        for phase in ('fix','verification'):workflows.tool(c,store,{'article_id':article,'phase':phase,'outcome':'passed','summary':'AI finding only'},target,incident,job)
        resolve_verified(c,store,incident,'Monitoring recovered while AI was still running',time.time())
        assert c.execute('SELECT state FROM kb_workflow_runs').fetchone()[0]=='awaiting_verification'
        workflows.job_ended(c,job,'expired','Expired before verification',time.time())
        assert c.execute('SELECT state FROM kb_workflow_runs').fetchone()[0]=='interrupted'


def test_plex_location_limit_cannot_imply_all_locations_readable():
    locations=[{'id':i,'path':'/location'+str(i)} for i in range(21)]
    previous={'media_locations':[{'id':'1:'+str(i),'path':'/location'+str(i),'sample_key':'/library/parts/1/2/file.mkv'} for i in range(20)]}
    def reading(cfg,token,path,params=None,media=False):
        if media:return True
        if path=='/identity':return {'MediaContainer':{'machineIdentifier':'fixture','version':'1'}}
        if path=='/library/sections':return {'MediaContainer':{'Directory':[{'key':'1','title':'Movies','type':'movie','Location':locations}]}}
        return {'MediaContainer':{'Metadata':[]}}
    with patch('aiticket.plex.get',side_effect=reading):data=plex.collect({'url':'http://plex','library_ids':['1'],'deep_monitoring':True,'_previous':previous},'token')
    assert len(data['media_locations'])==20 and all(x['readable'] is True for x in data['media_locations'])
    assert data['media_access'] is None and data['warnings']
