"""Subscription runs: count/time limits, never pretend to enforce API spend."""
import time
from datetime import datetime,timezone

DEFAULTS={'reasoning':'low','incident_runs':3,'daily_runs':10,'monthly_runs':100,'timeout_seconds':90}


def options(values):
    result={**DEFAULTS,**{k:values[k] for k in DEFAULTS if k in values}}
    if result['reasoning'] not in ('low','medium','high'):
        raise ValueError('Choose low, medium or high reasoning.')
    for key in ('incident_runs','daily_runs','monthly_runs'):
        if type(result[key]) is not int or not 1<=result[key]<=10000:
            raise ValueError('Codex run limits must be 1–10000.')
    if type(result['timeout_seconds']) is not int or not 15<=result['timeout_seconds']<=180:
        raise ValueError('Codex elapsed-time limit must be 15–180 seconds.')
    return result


def admit(c,incident_id,bridge,now):
    cfg=options(bridge)
    at=datetime.fromtimestamp(now,timezone.utc)
    day=at.replace(hour=0,minute=0,second=0,microsecond=0).timestamp()
    month=at.replace(day=1,hour=0,minute=0,second=0,microsecond=0).timestamp()
    # Count queued, failed, cancelled and ambiguous runs as well: no replay/refund.
    for key,clause,args in (('incident_runs','incident_id=?',(incident_id,)),('daily_runs','created>=?',(day,)),('monthly_runs','created>=?',(month,))):
        count=c.execute("SELECT count(*) FROM ai_jobs WHERE execution_mode='codex' AND "+clause,args).fetchone()[0]
        if count>=cfg[key]: raise ValueError('Codex '+key.replace('_',' ')+' limit reached.')
    return cfg


def permission(c,job,now=None,admitted=False):
    import json
    now=time.time() if now is None else now
    setting=c.execute("SELECT value FROM settings WHERE key='hermes_config'").fetchone()
    config=json.loads(setting[0]) if setting else {}
    row=c.execute("SELECT value FROM settings WHERE key='ai_config'").fetchone()
    model=json.loads(row[0]).get('model') if row else None
    incident=c.execute('SELECT closed,status FROM incidents WHERE id=?',(job['incident_id'],)).fetchone()
    control=c.execute('SELECT owner,generation FROM incident_control WHERE incident_id=?',(job['incident_id'],)).fetchone()
    return bool((not job['command_tools'] or config.get('command_tools')) and model==job['model'] and job['execution_mode']=='codex' and (job['state'] in ('dispatching','running') or (admitted and job['state']=='completed')) and job['expires']>now and config.get('enabled') and config.get('execution_mode')=='codex' and config.get('runtime_verified') and incident and incident['closed'] is None and incident['status']!='Resolved' and control and (control['owner']=='ai' or (admitted and job['state']=='completed' and control['owner']=='available')) and control['generation']==job['control_generation'])
