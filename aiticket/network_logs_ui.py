"""Authenticated network evidence and collector configuration."""
import time
from flask import abort, flash, redirect, render_template, request
from . import network_logs as logs


def register(app, store, login_required):
    @app.context_processor
    def log_helpers():
        def recent(machine):
            if not machine: return None
            with store.connect() as c:
                if not c.execute('SELECT 1 FROM log_sources LIMIT 1').fetchone(): return None
                return logs.query(c, machine=machine, limit=4)
        return {'recent_network_events': recent, 'network_event_host_names': {r['id']:r['name'] for r in store.rows('SELECT id,name FROM machines')} }

    @app.route('/settings/network-logs', methods=['GET', 'POST'])
    @login_required
    def network_log_settings():
        values = {'enabled': 'yes'}; error = None
        if request.args.get('source'):
            rows = store.rows('SELECT * FROM log_sources WHERE id=?', (request.args['source'],))
            if not rows: abort(404)
            values = {**rows[0], 'enabled': 'yes' if rows[0]['enabled'] else ''}
        retention = {**logs.DEFAULTS, **store.setting('network_log_retention', {})}
        if request.method == 'POST':
            values = dict(request.form)
            try:
                if values.get('operation') == 'retention':
                    retention = {k: values.get(k, '') for k in logs.DEFAULTS}
                    try:
                        validated = {k:int(v) for k,v in retention.items()}
                    except ValueError:
                        raise ValueError('Enter whole numbers for days, storage budget and maximum events.')
                    if not 1 <= validated['days'] <= 30 or not 10 <= validated['megabytes'] <= 2000 or not 1000 <= validated['rows'] <= 1000000:
                        raise ValueError('Choose 1–30 days, 10–2,000 MB and 1,000–1,000,000 events.')
                    store.save_many({'network_log_retention': validated}, actor='administrator')
                    flash('Retention saved. The collector applies it within a few seconds.')
                else:
                    if not values.get('id') and len(store.rows('SELECT id FROM log_sources')) >= 32:
                        raise ValueError('Up to 32 sender sources are supported. Edit an existing source.')
                    logs.save_source(store, values)
                    flash('Log source saved. Configure UniFi to send CEF logs to this server on port 5514.')
                return redirect('/settings/network-logs')
            except (ValueError, TypeError) as exc:
                error = str(exc) if str(exc) else 'Enter valid numbers.'
        return render_template('network-log-settings.html', values=values, error=error, retention=retention,
                               sources=store.rows('SELECT * FROM log_sources ORDER BY name'),
                               connections=store.rows('SELECT id,name FROM unifi_connections WHERE deleted IS NULL ORDER BY name'), collector=logs.status(store))

    @app.get('/network-events')
    @login_required
    def network_events():
        filters = {k: request.args.get(k, '').strip()[:200] for k in ('machine', 'source', 'device', 'port', 'category', 'q', 'severity')}
        error = None
        try:
            offset = max(0, min(10000, int(request.args.get('offset', 0))))
            hours = int(request.args.get('hours', 24))
            if hours not in (1, 6, 24, 168, 720): hours = 24
            severity = int(filters['severity']) if filters['severity'] else None
            if severity is not None and severity not in (0, 4, 7): raise ValueError('Choose a supported severity.')
        except ValueError:
            offset, hours, severity = 0, 24, None
            error = 'Choose a valid time range, severity and page.'
        with store.connect() as c:
            result = logs.query(c, machine=filters['machine'], source=filters['source'], device=filters['device'], port=filters['port'], category=filters['category'], text=filters['q'], severity=severity, start=time.time() - hours * 3600, offset=offset)
        return render_template('network-events.html', **result, filters=filters, hours=hours, offset=offset, error=error,
                               collector=logs.status(store), hosts=store.rows('SELECT id,name FROM machines ORDER BY name'),
                               sources=store.rows('SELECT id,name FROM log_sources ORDER BY name'))

    @app.route('/network-events/<int:identifier>', methods=['GET', 'POST'])
    @login_required
    def network_event(identifier):
        with store.connect() as c: item = logs.event(c, identifier)
        if not item: abort(404)
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
