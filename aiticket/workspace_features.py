"""Administrative knowledge and messaging workspaces, separated from host execution."""
import json
from flask import request,render_template,redirect,abort,flash,session
from . import knowledge,telegram

SETTINGS=[('General','/settings'),('AI & Hermes','/settings/ai'),('Notifications','/settings?view=notifications'),('Telegram','/settings/telegram'),('Network logs','/settings/network-logs'),('AI budgets','/settings?view=budgets'),('Policies','/policies'),('Agent health','/resources'),('Recovery','/recovery-policy'),('Administration','/administration')]


def register(app,store,vault,login_required):
    from .knowledge_render import render,excerpt
    app.add_template_filter(render,'knowledge_text')
    app.add_template_filter(excerpt,'knowledge_excerpt')
    @app.context_processor
    def settings_navigation():
        paths=('/settings','/hermes','/policies','/resources','/recovery-policy','/administration')
        return {'settings_sections':SETTINGS,'settings_workspace':request.path in paths or request.path.startswith('/settings/'),'settings_current':request.path+('?view='+request.args['view'] if request.path=='/settings' and request.args.get('view') else '')}

    @app.get('/knowledge')
    @login_required
    def knowledge_home():
        tab=request.args.get('tab','hosts');selected=request.args.get('folder');q=request.args.get('q','').strip()[:200]
        if tab not in ('hosts','services','troubleshooting','drafts'):tab='hosts'
        folders=store.rows('SELECT * FROM kb_folders ORDER BY name')
        chosen=next((f for f in folders if f['id']==selected),None)
        if selected and not chosen:abort(404)
        conditions=['a.status<>?'];args=['archived']
        if chosen:conditions.append('a.folder_id=?');args.append(selected)
        elif tab=='drafts':conditions.append("a.status='draft'")
        else:conditions.append('f.kind=?');args.append({'hosts':'host','services':'service','troubleshooting':'troubleshooting'}[tab])
        if q:conditions.append('(instr(lower(a.title),lower(?))>0 OR instr(lower(a.body),lower(?))>0 OR instr(lower(a.tags),lower(?))>0)');args.extend([q]*3)
        page=max(1,min(1000,int(request.args.get('page',1))))
        rows=store.rows('SELECT a.*,f.name folder FROM kb_articles a JOIN kb_folders f ON f.id=a.folder_id WHERE '+' AND '.join(conditions)+' ORDER BY a.updated DESC LIMIT 26 OFFSET ?',(*args,(page-1)*25))
        hosts=store.rows('SELECT id,name FROM machines ORDER BY name');services=store.rows('SELECT i.id,i.name,m.name host FROM integrations i JOIN machines m ON m.id=i.machine_id ORDER BY i.name')
        service_folders=[f for f in folders if f['kind']=='service' and not f['parent_id'] and not f['service_id']]
        return render_template('knowledge.html',tab=tab,folder=chosen,folders=folders,articles=rows[:25],more=len(rows)>25,page=page,q=q,hosts=hosts,services=services,service_folders=service_folders)

    @app.get('/knowledge/hosts/<machine>')
    @login_required
    def knowledge_host(machine):
        if not store.rows('SELECT 1 FROM machines WHERE id=?',(machine,)):abort(404)
        return redirect('/knowledge?tab=hosts&folder='+knowledge.root(store,'host',machine=machine))

    @app.get('/knowledge/services/<service>')
    @login_required
    def knowledge_service(service):
        if not store.rows('SELECT 1 FROM integrations WHERE id=?',(service,)):abort(404)
        return redirect('/knowledge?tab=services&folder='+knowledge.root(store,'service',service=service))

    @app.route('/knowledge/new',methods=['GET','POST'])
    @app.route('/knowledge/articles/<article>',methods=['GET','POST'])
    @login_required
    def knowledge_editor(article=None):
        existing=next(iter(store.rows('SELECT * FROM kb_articles WHERE id=?',(article,))),None) if article else None
        if article and not existing:abort(404)
        values=dict(existing or {'folder_id':request.args.get('folder',''),'status':'draft'});error=None
        if request.method=='POST':
            values.update(request.form)
            try:
                if request.form.get('operation')=='draft':
                    identifier=knowledge.request_draft(store,vault,values.get('folder_id'),values.get('title',''),values.get('instructions',''),values.get('source_incident') or None)
                    flash('AI is drafting the article. Its findings will appear here as a draft.')
                    return redirect('/incidents/'+identifier)
                identifier=knowledge.save(store,folder_id=values.get('folder_id'),title=values.get('title',''),body=values.get('body',''),tags=values.get('tags',''),status=values.get('status','draft'),source=values.get('source_incident') or None,identifier=article,expected=int(values.get('version',0)))
                flash('Article saved.');return redirect('/knowledge/articles/'+identifier)
            except (ValueError,TypeError) as e:error=str(e)
        # Create the global folder once, without creating articles.
        knowledge.root(store,'troubleshooting')
        for row in store.rows('SELECT id FROM machines'):knowledge.root(store,'host',machine=row['id'])
        for row in store.rows('SELECT id FROM integrations'):knowledge.root(store,'service',service=row['id'])
        return render_template('knowledge-editor.html',article=existing,values=values,error=error,folders=store.rows('SELECT * FROM kb_folders ORDER BY kind,name'),versions=store.rows('SELECT * FROM kb_versions WHERE article_id=? ORDER BY version DESC LIMIT 20',(article,)) if article else [])

    @app.route('/knowledge/articles/<article>/workflow',methods=['GET','POST'])
    @login_required
    def knowledge_workflow(article):
        from . import knowledge_workflows as workflows
        from .db import uid
        rows=store.rows('SELECT * FROM kb_articles WHERE id=?',(article,))
        if not rows:abort(404)
        with store.connect() as c:plan=workflows.definition(c,article)
        values={**(plan['steps'] if plan else {}),'version':str(plan['version']) if plan else '0','enabled':'yes' if not plan or plan['enabled'] else ''};error=None
        if request.method=='POST':
            values=dict(request.form)
            try:
                if values.get('operation')=='run':
                    machine=values.get('machine_id')
                    with store.connect() as c:
                        current=workflows.definition(c,article)
                        if not current or not current['enabled'] or current['status']!='published':raise ValueError('Publish the article and enable its workflow first.')
                        if current['article_version']!=rows[0]['version']:raise ValueError('Review and save the workflow after changing its article.')
                        if current['machine_id'] and current['machine_id']!=machine:raise ValueError('Choose this article’s host.')
                    import uuid
                    request_id=values.get('request_id','');uuid.UUID(request_id)
                    previous=store.rows('SELECT j.incident_id,r.article_id,r.machine_id FROM ai_jobs j LEFT JOIN kb_workflow_runs r ON r.job_id=j.id WHERE j.request_id=?',(request_id,))
                    if previous:
                        if previous[0]['article_id']!=article or previous[0]['machine_id']!=machine:raise ValueError('This request was already used for another procedure or host. Reload before starting.')
                        return redirect('/incidents/'+previous[0]['incident_id'])
                    from .host_admin import open_ticket
                    from .ai import request_job
                    ticket=open_ticket(store,machine,'Procedure: '+rows[0]['title'][:85],'Use the saved procedure '+rows[0]['title']+'. Check current prerequisites, record each step and independently verify the result.','medium',handling_mode='paused')
                    with store.connect() as c:c.execute("UPDATE incident_control SET owner='available',handling_mode='paused' WHERE incident_id=?",(ticket,))
                    try:request_job(store,vault,ticket,question='Use the saved workflow for article '+article+'. Retrieve it through knowledge and record prerequisites, diagnostics, fix and verification through workflow. Stop if it does not apply. Existing host permissions and maintenance restrictions apply.',request_id=request_id,workflow_article=article)
                    except ValueError as e:flash('Procedure ticket created. AI could not start: '+str(e))
                    return redirect('/incidents/'+ticket)
                workflows.save(store,article,values);flash('Workflow saved.');return redirect(request.path)
            except (ValueError,TypeError) as e:error=str(e)
        with store.connect() as c:statistics=workflows.stats(c,article)
        return render_template('knowledge-workflow.html',statistics=statistics,article=rows[0],plan=plan,values=values,error=error,runs=workflows.history(store,article),hosts=store.rows('SELECT id,name FROM machines ORDER BY name'),request_id=uid())

    @app.post('/knowledge/folders')
    @login_required
    def knowledge_folder():
        try:
            f=request.form;identifier=knowledge.folder(store,f.get('name',''),parent=f.get('parent') or None,kind=f.get('kind','troubleshooting'),machine=f.get('machine') or None,service=f.get('service') or None)
            kind=store.rows('SELECT kind FROM kb_folders WHERE id=?',(identifier,))[0]['kind']
            return redirect('/knowledge?tab='+{'host':'hosts','service':'services','troubleshooting':'troubleshooting'}[kind]+'&folder='+identifier)
        except ValueError as e:flash(str(e));return redirect('/knowledge')

    @app.route('/settings/telegram',methods=['GET','POST'])
    @login_required
    def telegram_settings():
        error=None;candidates=[];values={**telegram.DEFAULTS,**store.setting('telegram_config',{})}
        if request.method=='POST':
            try:
                operation=request.form.get('operation')
                if operation=='find':
                    if values['enabled']:raise ValueError('Pause Telegram before finding a new conversation, then enable it again.')
                    updates=telegram.api(vault,store.setting('telegram_secret'),'getUpdates',{'offset':values['offset'],'limit':50,'timeout':0,'allowed_updates':['message']})
                    found={}
                    for update in updates if isinstance(updates,list) else []:
                        message=update.get('message',{});user=message.get('from',{});chat=message.get('chat',{})
                        if type(user.get('id')) is not int or type(chat.get('id')) is not int or user.get('is_bot'):continue
                        key=str(chat['id'])+':'+str(user['id'])
                        found[key]={'key':key,'name':str(user.get('first_name') or user.get('username') or 'Telegram user')[:80],'chat':str(chat.get('title') or 'Private chat')[:80]}
                    candidates=list(found.values())[:20]
                    import time
                    session['telegram_candidates']={'at':time.time(),'keys':[x['key'] for x in candidates]}
                    if not candidates:flash('Send your bot a message, then click Find my chat again.')
                elif operation=='allow':
                    import time
                    saved=session.get('telegram_candidates',{})
                    key=request.form.get('conversation','')
                    if time.time()-saved.get('at',0)>300 or key not in saved.get('keys',[]):raise ValueError('Find your chat again before connecting it.')
                    chat,user=key.split(':')
                    telegram.configure(store,vault,{'enabled':'yes','chats':','.join(dict.fromkeys([*values['chats'],chat])),'users':','.join(dict.fromkeys([*values['users'],user])),'queries':'yes','notifications':'yes'})
                    session.pop('telegram_candidates',None);flash('Chat connected. Ask your bot for /status.');return redirect('/settings/telegram')
                elif operation=='test':
                    bot=telegram.api(vault,store.setting('telegram_secret'),'getMe',{})
                    flash('Connected to '+bot.get('username','your bot')+'. No message was sent.');return redirect('/settings/telegram')
                else:
                    telegram.configure(store,vault,request.form);flash('Telegram settings saved.');return redirect('/settings/telegram')
            except (ValueError,TypeError) as e:error=str(e);values={**values,**{k:request.form.get(k)=='yes' for k in ('enabled','queries','notifications')},'chats':request.form.get('chats','').split(','),'users':request.form.get('users','').split(',')}
        return render_template('telegram.html',candidates=candidates,values=values,error=error,configured=bool(store.setting('telegram_secret')),health=store.setting('telegram_health',{}),outcomes=store.rows('SELECT state,count(*) count FROM telegram_outbox GROUP BY state'))

    @app.post('/hosts/<machine>/container-logs')
    @login_required
    def host_container_logs(machine):
        from .host_admin import open_ticket
        from .diagnostics import request_job
        agents=store.rows('SELECT id FROM agents WHERE machine_id=? AND revoked=0',(machine,))
        if not agents:abort(404)
        target=request.form.get('target','')
        # Validate before creating the ticket; only currently discovered targets are accepted.
        discovery=store.rows('SELECT data,at FROM agent_discovery WHERE machine_id=?',(machine,))
        import time,re
        if not discovery or not 0<=time.time()-discovery[0]['at']<=180 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',target) or not any(x.get('target')==target for x in json.loads(discovery[0]['data']).get('containers',[])):
            flash('Refresh discovery before requesting logs for this container.');return redirect('/hosts/'+machine)
        incident=open_ticket(store,machine,'Container logs: '+target[:80],'Read the latest container logs for '+target+'.','low',handling_mode='paused')
        try:request_job(store,agents[0]['id'],incident,'container_logs',target)
        except ValueError as e:flash(str(e))
        return redirect('/incidents/'+incident)
