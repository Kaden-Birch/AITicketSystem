"""Authenticated, bounded local/SMB telemetry searches and stable references."""
import time
import json
from datetime import datetime,timezone
from flask import abort,redirect,render_template,request
from . import log_archive as archive,telemetry_archive as telemetry


def register(app,store,vault,login_required):
    @app.route('/telemetry-history',methods=['GET','POST'])
    @login_required
    def telemetry_history():
        now=time.time();error=None;items=[]
        values={'start':datetime.fromtimestamp(now-7*86400,timezone.utc).strftime('%Y-%m-%dT%H:%M'),'end':datetime.fromtimestamp(now+60,timezone.utc).strftime('%Y-%m-%dT%H:%M'),'machine':'','kind':'','q':'','tier':'local',**request.values.to_dict()}
        task=archive.job(store,request.args['job']) if request.args.get('job') else None
        if task and (task['kind']!='search' or task['params'].get('dataset')!='telemetry'):abort(404)
        if task:values.update(task['params'].get('display',{}));items=archive.search_results(store,task['id'])
        else:
            try:
                dates=[datetime.fromisoformat(values[k]) for k in ('start','end')]
                start,end=[(d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp() for d in dates]
                if not 0<=start<end<=now+120 or end-start>31*86400:raise ValueError('Choose a UTC interval of up to 31 days ending no later than now.')
                if values['kind'] and values['kind'] not in telemetry.KINDS:raise ValueError('Choose a supported record type.')
                if len(values['q'])>200 or values['tier'] not in ('local','smb'):raise ValueError('Choose a storage tier and a search phrase of at most 200 characters.')
                if values['machine'] and not store.rows('SELECT id FROM machines WHERE id=?',(values['machine'],)):raise ValueError('Choose an existing host.')
                params={'start':start,'end':end,'kind':values['kind'],'machine':values['machine'],'q':values['q'],'dataset':'telemetry','display':{k:values[k] for k in ('start','end','kind','machine','q','tier')}}
                if request.method=='POST':
                    if values['tier']!='smb':return redirect('/telemetry-history')
                    cfg=archive.connection(store,vault)
                    if not cfg.get('server'):raise ValueError('Configure an SMB archive in Network log settings first.')
                    identifier=archive.submit(store,vault,'search',cfg,params)
                    return redirect('/telemetry-history?job='+identifier)
                if values['tier']=='local':items=telemetry.local_search(store,params)
            except (ValueError,TypeError,OverflowError) as exc:error=str(exc)
        truncated=len(items)>200 or bool(task and task['result'].get('truncated'))
        for item in items[:200]:
            preview=json.dumps(item['data'],indent=2,ensure_ascii=False)
            item['preview']=preview[:2000]+('\n… Open the record for remaining fields.' if len(preview)>2000 else '')
        return render_template('telemetry-history.html',values=values,error=error,task=task,items=items[:200],truncated=truncated,kinds=telemetry.KINDS,coverage=telemetry.status(store),hosts=store.rows('SELECT id,name FROM machines ORDER BY name'))

    @app.get('/telemetry-history/records/<record_key>')
    @login_required
    def telemetry_record(record_key):
        identifier=request.args.get('job')
        if identifier:
            task=archive.job(store,identifier)
            if not task or task['params'].get('dataset')!='telemetry':abort(404)
            items=archive.search_results(store,identifier)
        else:items=[telemetry.document(r) for r in store.rows('SELECT * FROM telemetry_records WHERE id=?',(record_key,))]
        item=next((r for r in items if r['record_key']==record_key),None)
        if not item:abort(404)
        return render_template('telemetry-record.html',item=item,job=identifier)
