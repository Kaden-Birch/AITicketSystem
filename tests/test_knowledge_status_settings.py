from pathlib import Path

import json,time,uuid
from unittest.mock import patch
import pytest
from aiticket import knowledge,ai,telegram,changes
from aiticket.security import hermes_headers
from test_codex_mode import configure
from test_commands import setup


def host(store,identifier='h',name='Voyager'):
    with store.connect() as c:c.execute('INSERT INTO machines(id,name,created) VALUES(?,?,?)',(identifier,name,time.time()))
    return identifier


def test_articles_scope_revisions_redaction_and_optional_creation(signed_in):
    client,store,vault,csrf=signed_in
    host(store);host(store,'other','Other host')
    root=knowledge.root(store,'host',machine='h');other=knowledge.root(store,'host',machine='other')
    nested=knowledge.folder(store,'Plex storage',parent=root,kind='host',machine='h')
    assert nested==knowledge.folder(store,'Plex storage',parent=root,kind='host',machine='h')
    article=knowledge.save(store,folder_id=nested,title='Plex mount recovery',body='Check the mount. token=private-value',status='published')
    knowledge.save(store,folder_id=other,title='Private other host fix',body='Other evidence',status='published')
    with store.connect() as c:
        found=knowledge.search(c,{'h'})
        assert [r['id'] for r in found]==[article] and 'private-value' not in found[0]['body']
    with pytest.raises(ValueError,match='changed'):knowledge.save(store,folder_id=nested,title='Stale',body='Overwrite',identifier=article,expected=0)
    knowledge.save(store,folder_id=nested,title='Plex mount recovery',body='Verify a sample file',identifier=article,expected=1,status='published')
    assert len(store.rows('SELECT * FROM kb_versions WHERE article_id=?',(article,)))==2
    assert client.get('/knowledge?tab=hosts').status_code==200
    assert client.get('/knowledge/articles/'+article).status_code==200
    assert b'Knowledge' in client.get('/hosts/h').data
    response=client.post('/knowledge/articles/'+article,data={'csrf':csrf,'folder_id':nested,'title':'Keep this input','body':'My edited text','version':1})
    assert response.status_code==200 and b'My edited text' in response.data and b'This article changed' in response.data
    assert client.post('/knowledge/folders',data={'name':'No CSRF'}).status_code==403
    assert client.get('/knowledge/hosts/missing').status_code==404
    before=len(store.rows('SELECT * FROM kb_articles'))
    client.get('/knowledge/hosts/h')
    assert len(store.rows('SELECT * FROM kb_articles'))==before


def test_ai_draft_is_atomic_read_only_and_saved_on_completion(environment):
    app,store,vault=environment
    source=configure(store,vault)
    folder=knowledge.root(store,'host',machine=store.rows('SELECT machine_id FROM incidents WHERE id=?',(source,))[0]['machine_id'])
    incident=knowledge.request_draft(store,vault,folder,'Recurring storage issue','Explain the symptoms and verification.',source)
    job=store.rows('SELECT * FROM ai_jobs WHERE incident_id=?',(incident,))[0]
    assert json.loads(job['evidence'])['ticket_history']['source_ticket']['id']==source
    assert job['read_only']==1 and store.rows('SELECT * FROM kb_requests WHERE job_id=?',(job['id'],))
    assert not store.rows('SELECT * FROM kb_articles')
    ai.apply_status(store,job['id'],{'execution_id':job['id'],'state':'completed','summary':'Storage guide: verify the mount and read a sample file.','execution_mode':'codex','model':'gpt-6.1-sol','reasoning':'low'})
    article=store.rows('SELECT * FROM kb_articles')[0]
    assert article['status']=='draft' and article['source_incident']==source
    assert len(store.rows('SELECT * FROM kb_articles'))==1


def test_hermes_status_readonly_auth_and_feature_gate(environment):
    app,store,vault=environment;host(store)
    secret='fixture-status-shared-secret';store.save('hermes_secret',vault.encrypt(secret))
    client=app.test_client();body=json.dumps({'action':'query','query':'Voyager'}).encode()
    assert client.post('/api/operations/command',data=body,content_type='application/json').status_code==401
    def send():return client.post('/api/operations/command',data=body,headers=hermes_headers(secret,body,str(uuid.uuid4())))
    assert send().status_code==403
    store.save('hermes_queries_enabled',True)
    result=send()
    assert result.status_code==200 and result.json['hosts'][0]['name']=='Voyager'
    assert not store.rows('SELECT * FROM command_jobs')


def test_settings_preserve_routes_and_show_inline_setup_errors(signed_in):
    client,store,vault,csrf=signed_in
    for url in ('/settings','/settings?view=notifications','/settings?view=budgets','/settings/ai','/hermes','/settings/ai?view=usage','/settings/ai?view=activity','/settings/telegram','/knowledge/new'):
        r=client.get(url);assert r.status_code==200,(url,r.data)
    r=client.post('/settings/ai',data={'csrf':csrf,'operation':'save','url':'invalid','execution_mode':'codex','codex_model':'chosen-model'})
    assert r.status_code==200 and b'role="alert"' in r.data
    page=client.get('/').data
    assert b'>Knowledge Base</a>' in page and b'>Settings</a>' in page and b'>Hermes &amp; usage</a>' not in page


def test_change_history_initial_baseline_and_bounded_host_context(environment):
    _,store,vault=environment;host(store)
    old={'containers':[{'target':'plex','name':'Plex','image_id':'old','restart_count':0}]}
    with store.connect() as c:
        changes.agent(c,'h','v1',old,time.time())
        assert not c.execute('SELECT 1 FROM change_events').fetchone()
        c.execute('INSERT INTO agent_discovery VALUES(?,?,?)',('h',time.time(),json.dumps(old)))
        changes.agent(c,'h','v1',{'containers':[{'target':'plex','name':'Plex','image_id':'new','restart_count':1}]},time.time())
        assert len(changes.context(c,{'h'}))==2
        assert changes.context(c,{'other'})==[]


def test_read_only_job_refuses_changes_outside_maintenance(environment):
    _,store,vault=environment;incident=configure(store,vault)
    job=ai.request_job(store,vault,incident,read_only=True)
    from aiticket.maintenance_ai import check_change
    machine=store.rows('SELECT machine_id FROM incidents WHERE id=?',(incident,))[0]['machine_id']
    with store.connect() as c:
        with pytest.raises(ValueError,match='read-only'):check_change(c,job,machine,command='touch /tmp/example')
        check_change(c,job,machine,command='uptime')


def test_ai_knowledge_tools_are_scoped_and_history_is_retrievable(environment):
    app,store,vault=environment;incident=configure(store,vault)
    store.save('hermes_config',{**store.setting('hermes_config'),'command_tools':True})
    job=ai.request_job(store,vault,incident)
    with store.connect() as c:c.execute("UPDATE ai_jobs SET state='running' WHERE id=?",(job,))
    row=store.rows('SELECT * FROM ai_jobs WHERE id=?',(job,))[0];auth={'Authorization':'Bearer '+vault.decrypt(row['credential'])}
    def tool(fields):return app.test_client().post('/api/hermes/'+job+'/command',json=fields,headers=auth)
    response=tool({'action':'knowledge_write','category':'host','title':'Useful finding','body':'Verify with current monitoring.'})
    assert response.status_code==200,response.data
    article=store.rows('SELECT * FROM kb_articles')[0]
    assert article['status']=='published'
    assert tool({'action':'knowledge','article_id':article['id']}).status_code==200
    host(store,'outside','Outside')
    outside=knowledge.save(store,folder_id=knowledge.root(store,'host',machine='outside'),title='Other note',body='Private to another host',status='published')
    assert tool({'action':'knowledge','article_id':outside}).status_code==403
    assert tool({'action':'ticket_history'}).json['tickets']
    assert tool({'action':'changes'}).json['items']==[]


def test_article_formatter_escapes_html_and_formats_markdown():
    from aiticket.knowledge_render import render
    result=str(render('# Recovery\n\n**Verify** the `mount`.\n\n- Read a file\n- Check Plex\n\n<script>alert(1)</script>'))
    assert '<h2>Recovery</h2>' in result and '<strong>Verify</strong>' in result and '<ul>' in result
    assert '<script>' not in result and '&lt;script&gt;' in result


def test_normal_hermes_setup_preserves_configuration_and_private_backup(tmp_path):
    import sys
    from aiticket.hermes_status_setup import install
    root=Path(__file__).parents[1]
    config=tmp_path/'config.yaml';config.write_text(json.dumps({'model':{'default':'existing-model'},'mcp_servers':{'other':{'command':'existing'}}}))
    secret=tmp_path/'secret';secret.write_text('fixture-shared-connection-secret');secret.chmod(0o600)
    assert install(config,'https://192.0.2.10',secret,sys.executable,root)
    cfg=json.loads(config.read_text())
    assert cfg['model']['default']=='existing-model' and cfg['mcp_servers']['other']['command']=='existing'
    assert '--status-only' in cfg['mcp_servers']['aiticketsystem']['args']
    assert 'fixture-shared-connection-secret' not in config.read_text()
    assert list(tmp_path.glob('config.yaml.before-*'))
    assert config.stat().st_mode & 0o077==0
    assert install(config,'https://192.0.2.10',secret,sys.executable,root) is False


def test_related_host_history_scope_and_named_service_folders(environment):
    _,store,vault=environment;host(store);host(store,'vm','Plex VM');host(store,'outside','Unrelated')
    with store.connect() as c:
        c.execute('UPDATE machines SET parent_id=? WHERE id=?',('h','vm'))
        assert knowledge.related_scope(c,{'vm'})=={'h','vm'}
    identifier=knowledge.folder(store,'Plex deployment',kind='service',machine='vm')
    assert store.rows('SELECT * FROM kb_folders WHERE id=?',(identifier,))[0]['kind']=='service'


def test_change_retention_and_stored_credentials(environment):
    _,store,_=environment;host(store)
    with store.connect() as c:
        changes.event(c,'h','Plex','image','token=secret-before','token=secret-after')
        changes.event(c,'h','Plex','health','healthy','unhealthy',time.time()-31*86400)
        rows=changes.context(c,{'h'})
        assert len(rows)==1 and 'secret-before' not in json.dumps(rows) and 'secret-after' not in json.dumps(rows)


def test_gateway_setup_saves_the_visible_model(signed_in):
    client,store,vault,csrf=signed_in
    with patch('aiticket.ai_setup.check',return_value={}):
        response=client.post('/settings/ai',data={'csrf':csrf,'operation':'save','execution_mode':'gateway','url':'https://hermes.example','provider_url':'https://provider.example','codex_model':'fixture-model','provider_verified':'yes'})
    assert response.status_code==302
    assert store.setting('ai_config')['model']=='fixture-model'
    assert store.setting('ai_provider')['verified_model']=='fixture-model'
