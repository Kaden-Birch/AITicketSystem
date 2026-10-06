"""Authenticated network evidence and collector configuration."""
import time
from datetime import datetime, timezone
from flask import abort, flash, redirect, render_template, request
from . import network_logs as logs
from . import log_archive as archive


def register(app, store, vault, login_required):
    @app.context_processor
    def log_helpers():
        def recent(machine):
            if not machine: return None
            with store.connect() as c:
                if not c.execute('SELECT 1 FROM log_sources LIMIT 1').fetchone(): return None
                return logs.query(c, machine=machine, limit=4)
        def troubleshooting(machine=None, incident=None):
            from .troubleshooting import build, scope
            now=time.time()
            with store.connect() as c:
                anchor=c.execute('SELECT first_seen,last_seen,closed FROM incidents WHERE id=?',(incident,)).fetchone() if incident else None
                end=(anchor['closed'] or anchor['last_seen'])+3600 if anchor else now+30
                end=min(end,now+30)
                start=max(0,anchor['first_seen']-3600) if anchor else now-86400
                start=max(start,end-31*86400)
                result=build(c,scope(c,machine,incident),start,end,limit=8)
            result['url']='/incidents/'+incident+'/troubleshooting' if incident else '/hosts/'+machine+'/troubleshooting'
            return result
        return {'recent_network_events': recent, 'troubleshooting_summary':troubleshooting,
                'network_event_host_names': {r['id']:r['name'] for r in store.rows('SELECT id,name FROM machines')} }

    @app.get('/hosts/<machine_id>/troubleshooting')
    @app.get('/incidents/<incident_id>/troubleshooting')
    @login_required
    def troubleshooting_timeline(machine_id=None,incident_id=None):
        from .troubleshooting import build, scope, KINDS
        now=time.time(); error=None; result=None
        with store.connect() as c:
            if incident_id:
                target=c.execute('SELECT i.*,m.name FROM incidents i JOIN machines m ON m.id=i.machine_id WHERE i.id=?',(incident_id,)).fetchone()
            else: target=c.execute('SELECT id,name FROM machines WHERE id=?',(machine_id,)).fetchone()
            if not target: abort(404)
            end=min((target['closed'] or target['last_seen'])+3600,now+30) if incident_id else now+30
            start=max(end-31*86400,max(0,target['first_seen']-3600)) if incident_id else now-86400
            values={'start':datetime.fromtimestamp(start,timezone.utc).strftime('%Y-%m-%dT%H:%M'),
                    'end':datetime.fromtimestamp(end+60,timezone.utc).strftime('%Y-%m-%dT%H:%M'), 'kind':'all'}
            values.update({k:request.args[k][:100] for k in values if k in request.args})
            try:
                start=datetime.fromisoformat(values['start']).replace(tzinfo=timezone.utc).timestamp()
                end=datetime.fromisoformat(values['end']).replace(tzinfo=timezone.utc).timestamp()
                result=build(c,scope(c,machine_id,incident_id),start,end,values['kind'])
            except (ValueError,TypeError) as exc: error=str(exc) or 'Choose valid dates.'
        return render_template('troubleshooting.html',result=result,values=values,error=error,kinds=KINDS,
                               name=target['name'],back='/incidents/'+incident_id if incident_id else '/hosts/'+machine_id,
                               incident_id=incident_id)

    @app.route('/network-events/problems',methods=['GET','POST'])
    @login_required
    def network_problems():
        from . import log_problems as problems
        values={};error=None
        if request.args.get('rule'):
            rule=next((r for r in problems.rules(store) if r['id']==request.args['rule']),None)
            if not rule:abort(404)
            values={**rule,**rule['config'],'minutes':rule['config']['window']//60,'event_names':'\n'.join(rule['config']['event_names']),'enabled':'yes' if rule['enabled'] else '', 'tickets':'yes' if rule['config']['tickets'] else ''}
        if request.method=='POST':
            values=dict(request.form)
            try:
                problems.save_rule(store,values);flash('Pattern rule saved. Evaluation runs in the application worker.');return redirect('/network-events/problems')
            except (ValueError,TypeError) as exc:error=str(exc)
        return render_template('network-log-problems.html',values=values,error=error,kinds=problems.KINDS,supported=problems.NAMES,rules=problems.rules(store),problems=problems.problems(store),scan=store.setting('network_problem_scan',{}),sources=store.rows('SELECT id,name FROM log_sources ORDER BY name'),host_names={r['id']:r['name'] for r in store.rows('SELECT id,name FROM machines')})

    @app.route('/network-events/coverage',methods=['GET','POST'])
    @login_required
    def network_log_coverage():
        from . import log_coverage as coverage
        cfg=store.setting('network_log_health',{});error=None
        values={'health_machine':cfg.get('machine'),'failure_minutes':cfg.get('delay',900)//60,'health_enabled':'yes' if cfg.get('enabled') else '', 'correlation':'yes' if store.setting('network_log_correlation',False) else ''}
        if request.method=='POST':
            values=dict(request.form)
            try:coverage.save(store,values);flash('Collection health and correlation settings saved.');return redirect('/network-events/coverage')
            except (ValueError,TypeError) as exc:error=str(exc)
        return render_template('network-log-coverage.html',coverage=coverage.view(store),values=values,error=error,hosts=store.rows('SELECT id,name FROM machines ORDER BY name'))

    @app.route('/settings/network-logs', methods=['GET', 'POST'])
    @login_required
    def network_log_settings():
        values = {'enabled': 'yes'}; error = None
        if request.args.get('source'):
            rows = store.rows('SELECT * FROM log_sources WHERE id=?', (request.args['source'],))
            if not rows: abort(404)
            values = {**rows[0], 'enabled': 'yes' if rows[0]['enabled'] else ''}
        retention = {**logs.DEFAULTS, **store.setting('network_log_retention', {})}
        smb = archive.config(store); smb_error = None
        if request.method == 'POST':
            values = dict(request.form)
            try:
                if values.get('operation') == 'retention':
                    retention = {k: values.get(k, '') for k in logs.DEFAULTS}
                    try:
                        validated = {k:int(v) for k,v in retention.items()}
                    except ValueError:
                        raise ValueError('Enter whole numbers for days, storage budget and maximum events.')
                    if not 0 <= validated['days'] <= 365 or not 10 <= validated['megabytes'] <= 2000 or not 1000 <= validated['rows'] <= 1000000:
                        raise ValueError('Choose 0–365 days (0 is indefinite), 10–2,000 MB and 1,000–1,000,000 events.')
                    store.save_many({'network_log_retention': validated}, actor='administrator')
                    flash('Retention saved. The collector applies it within a few seconds.')
                elif values.get('operation') in ('smb_save', 'smb_test'):
                    cfg = archive.validate(store, vault, values)
                    if values['operation'] == 'smb_test':
                        archive.save(store, cfg)
                        identifier = archive.submit(store, vault, 'test', cfg)
                        flash('SMB settings saved. Connection test queued; the result appears below.')
                        return redirect('/settings/network-logs?test='+identifier)
                    archive.save(store, cfg)
                    flash('SMB archive settings saved. Local collection continues independently; existing local history will be copied in batches.')
                elif values.get('operation') == 'smb_disable':
                    smb['enabled'] = False
                    store.save('network_log_smb', smb)
                    flash('SMB uploads paused. Local collection continues; pending copies remain queued.')
                else:
                    if not values.get('id') and len(store.rows('SELECT id FROM log_sources')) >= 32:
                        raise ValueError('Up to 32 sender sources are supported. Edit an existing source.')
                    logs.save_source(store, values)
                    flash('Log source saved. Configure UniFi to send CEF logs to this server on port 5514.')
                return redirect('/settings/network-logs')
            except (ValueError, TypeError) as exc:
                if values.get('operation', '').startswith('smb_'):
                    smb_error = str(exc) or 'Enter valid SMB settings.'
                    smb = {**smb, **{key: values.get('smb_'+key, '') for key in ('server','share','folder','username','domain','days','buffer_mb')}}
                    smb.update(enabled=values.get('smb_enabled')=='yes', encrypt=values.get('smb_encrypt')=='yes')
                else: error = str(exc) if str(exc) else 'Enter valid numbers.'
                values.pop('smb_password', None)
        return render_template('network-log-settings.html', values=values, error=error, retention=retention,
                               sources=store.rows('SELECT * FROM log_sources ORDER BY name'),
                               connections=store.rows('SELECT id,name FROM unifi_connections WHERE deleted IS NULL ORDER BY name'), collector=logs.status(store),
                               smb=smb, smb_error=smb_error, periods=archive.PERIODS, archive_status=archive.archive_status(store),
                               smb_test=archive.job(store, request.args['test']) if request.args.get('test') else None,
                               smb_password_saved=bool(store.setting('network_log_smb_secret')))

    @app.route('/network-events/archive', methods=['GET', 'POST'])
    @login_required
    def network_archive():
        now = time.time(); error = None
        values = {'start':datetime.fromtimestamp(now-30*86400,timezone.utc).strftime('%Y-%m-%dT%H:%M'),
                  'end':datetime.fromtimestamp(now+60,timezone.utc).strftime('%Y-%m-%dT%H:%M'), 'source':'', 'machine':'', 'q':'', 'severity':''}
        task = archive.job(store, request.args['job']) if request.args.get('job') else None
        if task and task['kind'] != 'search': abort(404)
        if request.method == 'POST':
            values = {**values, **dict(request.form)}
            try:
                if not archive.config(store)['server']: raise ValueError('Configure an SMB archive connection in Network logs first.')
                start = datetime.fromisoformat(values['start']).replace(tzinfo=timezone.utc).timestamp()
                end = datetime.fromisoformat(values['end']).replace(tzinfo=timezone.utc).timestamp()
                if not 0 < end-start <= 31*86400 or start < 0:
                    raise ValueError('Choose a time range of up to 31 days. You can search any month in the archive.')
                severity = int(values['severity']) if values.get('severity') else None
                if severity is not None and severity not in (4,7): raise ValueError('Choose a supported severity.')
                params = {**{k:values.get(k,'')[:200] for k in ('source','machine','q')}, 'start':start, 'end':end, 'severity':severity}
                params['display'] = {k:values[k] for k in ('start','end','source','machine','q','severity')}
                identifier = archive.submit(store, vault, 'search', archive.connection(store,vault), params)
                return redirect('/network-events/archive?job='+identifier)
            except (ValueError, TypeError) as exc: error = str(exc) or 'Enter a valid time range.'
        elif task: values.update(task['params'].get('display',{}))
        items = archive.search_results(store, task['id']) if task else []
        for item in items: item['archive_job'] = task['id']
        return render_template('network-log-archive.html', values=values, error=error, task=task, items=items, available=True,
                               sources=store.rows('SELECT id,name FROM log_sources ORDER BY name'),
                               hosts=store.rows('SELECT id,name FROM machines ORDER BY name'), archive_status=archive.archive_status(store))

    @app.get('/network-events/archive/<identifier>/<event_key>')
    @login_required
    def network_archive_event(identifier, event_key):
        items = archive.search_results(store, identifier)
        item = next((item for item in items if item.get('event_key') == event_key), None)
        if not item: abort(404)
        return render_template('network-event.html', event=item, error=None, selected=None, archived=True, archive_job=identifier,
                               hosts=store.rows('SELECT id,name FROM machines ORDER BY name'), sources=store.rows('SELECT id,name FROM log_sources'))

    @app.get('/network-events')
    @login_required
    def network_events():
        filters = {k: request.args.get(k, '').strip()[:200] for k in ('machine', 'source', 'device', 'port', 'category', 'q', 'severity')}
        error = None
        try:
            offset = max(0, min(10000, int(request.args.get('offset', 0))))
            hours = int(request.args.get('hours', 24))
            if hours not in (0, 1, 6, 24, 168, 720, 4320, 8760): hours = 24
            severity = int(filters['severity']) if filters['severity'] else None
            if severity is not None and severity not in (0, 4, 7): raise ValueError('Choose a supported severity.')
        except ValueError:
            offset, hours, severity = 0, 24, None
            error = 'Choose a valid time range, severity and page.'
        with store.connect() as c:
            result = logs.query(c, machine=filters['machine'], source=filters['source'], device=filters['device'], port=filters['port'], category=filters['category'], text=filters['q'], severity=severity, start=0 if hours==0 else time.time() - hours * 3600, offset=offset)
        return render_template('network-events.html', **result, filters=filters, hours=hours, offset=offset, error=error,
                               collector=logs.status(store), hosts=store.rows('SELECT id,name FROM machines ORDER BY name'),
                               sources=store.rows('SELECT id,name FROM log_sources ORDER BY name'))

    @app.route('/network-events/<int:identifier>', methods=['GET', 'POST'])
    @login_required
    def network_event(identifier):
        with store.connect() as c: item = logs.event(c, identifier)
        if not item or request.args.get('event_key') not in (None,item['event_key']): abort(404)
        error = None
        if request.method == 'POST':
            try:
                logs.bind(store, item['source_id'], item['client_mac'], request.form.get('machine_id') or None)
                flash('MAC association saved. It applies to retained history and future events from this source.')
                return redirect('/network-events/'+str(identifier))
            except ValueError as exc: error = str(exc)
        return render_template('network-event.html', event=item, error=error, selected=request.form.get('machine_id'),
                               hosts=store.rows('SELECT id,name FROM machines ORDER BY name'),
                               sources=store.rows('SELECT id,name FROM log_sources'))
